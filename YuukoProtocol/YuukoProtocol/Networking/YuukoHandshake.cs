
// Challenge-response handshake that establishes a per-peer encrypted session over a
// single Zenoh "handshake topic". Reuses the Eclipse DLL crypto directly:
//   - Kyber-1024 KEM (Pariah EasyPQC.Keys)      -> proves identity + yields a shared secret
//   - Security.PrepareKeys (Eclipse, HKDF-SHA256) -> derives directional session keys
//   - Security.AeadChannel  (Eclipse, AES-256-GCM) -> the per-peer, sequenced channel
//
// Flow (provider = data owner "Eclipse role", requester = app wanting data):
//   1. Requester -> HELLO      { kyberPub, nonceC }
//   2. Provider runs an admission check (banned list for now)
//   3. Provider -> CHALLENGE   { kemCipher, nonceS, sessionId, enc(random challenge) }
//   4. Requester decapsulates, derives the same keys, decrypts the challenge and echoes it
//      back encrypted under its own direction -> RESPONSE { enc(challenge) }
//   5. On any failure the provider erases the pending handshake and -> REJECT
//   6. On success both sides hold a HandshakeSession and can exchange data encrypted
//
// v3 of this (Eclipse-secured Zenoh transport), i'm never touching this again LOL it's secure enough 

using System;
using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading;
using System.Threading.Tasks;
using EclipseProject;
using Pariah_Cybersecurity;

namespace YuukoProtocol
{
    // ── Identity ───────────────────────────────────────────────────────────────

    /// <summary>
    /// A peer's stable identity: a human-readable id plus a Kyber-1024 keypair. The
    /// public key is what other peers encapsulate to; possession of the private key is
    /// what the challenge-response proves.
    /// </summary>
    public sealed class YuukoIdentity
    {
        public string ClientId { get; }
        internal IReadOnlyDictionary<string, byte[]> KyberPublic { get; }
        internal IReadOnlyDictionary<string, byte[]> KyberPrivate { get; }

        private YuukoIdentity(string clientId,
            Dictionary<string, byte[]> pub, Dictionary<string, byte[]> priv)
        {
            ClientId = clientId;
            KyberPublic = pub;
            KyberPrivate = priv;
        }

        /// <summary>Generates a fresh Kyber-1024 identity for <paramref name="clientId"/>.</summary>
        public static YuukoIdentity Create(string clientId)
        {
            if (string.IsNullOrWhiteSpace(clientId))
                throw new ArgumentException("clientId must be non-empty.", nameof(clientId));

            var (pub, priv) = EasyPQC.Keys.Initiate();
            return new YuukoIdentity(clientId, pub, priv);
        }

        /// <summary>The public key as a plain dictionary, safe to hand to other peers.</summary>
        public Dictionary<string, byte[]> ExportPublicKey() =>
            new(KyberPublic as IDictionary<string, byte[]> ?? new Dictionary<string, byte[]>(KyberPublic));
    }

    // ── Options ────────────────────────────────────────────────────────────────

    public sealed class HandshakeOptions
    {
        /// <summary>Optional pre-shared key mixed into the HKDF salt. Empty = KEM-only trust.</summary>
        public byte[] PreSharedKey { get; set; } = Array.Empty<byte>();

        /// <summary>Client ids refused at admission (step 2). Replaceable with a richer policy later.</summary>
        public HashSet<string> BannedClients { get; } = new(StringComparer.Ordinal);

        /// <summary>Key expression the handshake traffic rides on.</summary>
        public string Topic { get; set; } = "yuuko/handshake";

        /// <summary>How long a requester waits for CHALLENGE/ACCEPT before giving up.</summary>
        public TimeSpan Timeout { get; set; } = TimeSpan.FromSeconds(10);

        /// <summary>
        /// Number of independent lanes (parallel AeadChannels) per established session, i.e.
        /// how many requests a requester may have in flight to one peer at once. Each lane
        /// keeps its own sequence, so lanes are ordered independently.
        /// </summary>
        public int MaxChannels { get; set; } = 8;
    }

    // ── Session ────────────────────────────────────────────────────────────────

    /// <summary>
    /// An established, mutually-derived encrypted session to one peer, multiplexed over a
    /// pool of independent lanes. Each lane is a pair of directional
    /// <see cref="Security.AeadChannel"/>s with its own sequence and a distinct nonce space
    /// (derived from the base session id), so lanes can be used concurrently and out of
    /// order relative to each other while each stays internally ordered.
    ///
    /// Both peers derive lane i identically from the shared key material + base session id,
    /// so a requester's lane i send channel pairs with the provider's lane i receive channel.
    /// The requester borrows a free lane per request (<see cref="AcquireLaneAsync"/>); the
    /// provider simply answers on whatever lane index the request arrived on.
    /// </summary>
    public sealed class HandshakeSession : IDisposable
    {
        public string LocalId { get; }
        public string RemoteId { get; }

        private readonly byte[] _sendKey;
        private readonly byte[] _recvKey;
        private readonly byte[] _baseSessionId;
        private readonly string _aadClientId;
        private readonly int _maxLanes;

        private readonly ConcurrentDictionary<int, Lane> _lanes = new();
        private readonly ConcurrentQueue<int> _freeLanes = new();
        private readonly SemaphoreSlim _laneAvailable;
        private int _disposed;

        internal HandshakeSession(string localId, string remoteId, string aadClientId,
            byte[] sendKey, byte[] recvKey, byte[] baseSessionId, int maxLanes)
        {
            LocalId = localId;
            RemoteId = remoteId;
            _aadClientId = aadClientId;
            _sendKey = sendKey;
            _recvKey = recvKey;
            _baseSessionId = baseSessionId;
            _maxLanes = Math.Max(1, maxLanes);

            for (int i = 0; i < _maxLanes; i++) _freeLanes.Enqueue(i);
            _laneAvailable = new SemaphoreSlim(_maxLanes, _maxLanes);
        }

        /// <summary>How many parallel lanes this session multiplexes over.</summary>
        public int MaxLanes => _maxLanes;

        /// <summary>
        /// Borrows a free lane for one request/response exchange, waiting if all lanes are
        /// busy. The caller MUST <see cref="ReleaseLane"/> it when the exchange completes.
        /// </summary>
        public async Task<int> AcquireLaneAsync(CancellationToken ct = default)
        {
            await _laneAvailable.WaitAsync(ct).ConfigureAwait(false);
            if (_freeLanes.TryDequeue(out var lane)) return lane;
            _laneAvailable.Release();
            throw new InvalidOperationException("HandshakeSession: lane pool inconsistent.");
        }

        /// <summary>Returns a borrowed lane to the pool.</summary>
        public void ReleaseLane(int lane)
        {
            _freeLanes.Enqueue(lane);
            _laneAvailable.Release();
        }

        /// <summary>Encrypts a payload on <paramref name="lane"/>; returns wire bytes.</summary>
        public byte[] EncryptOnLane(int lane, string method, byte[] plaintext) =>
            GetLane(lane).Encrypt(method, plaintext);

        /// <summary>Decrypts wire bytes received on <paramref name="lane"/>.</summary>
        public byte[] DecryptOnLane(int lane, byte[] wire) =>
            GetLane(lane).Decrypt(wire);

        private Lane GetLane(int index) =>
            _lanes.GetOrAdd(index, i => Lane.Build(_sendKey, _recvKey, _baseSessionId, i, _aadClientId));

        public void Dispose()
        {
            if (Interlocked.Exchange(ref _disposed, 1) != 0) return;
            foreach (var l in _lanes.Values) l.Dispose();
            _lanes.Clear();
            _laneAvailable.Dispose();
        }

        // One multiplexing lane: a send + receive AeadChannel sharing a per-lane nonce space.
        private sealed class Lane : IDisposable
        {
            private readonly Security.AeadChannel _send;
            private readonly Security.AeadChannel _recv;
            private readonly object _sendLock = new();
            private readonly object _recvLock = new();

            private Lane(Security.AeadChannel send, Security.AeadChannel recv)
            {
                _send = send;
                _recv = recv;
            }

            public static Lane Build(byte[] sendKey, byte[] recvKey, byte[] baseSessionId, int index, string aad)
            {
                byte[] laneId = DeriveLaneId(baseSessionId, index);
                var send = NewChannel(sendKey, laneId, aad, index, "s");
                var recv = NewChannel(recvKey, laneId, aad, index, "r");
                return new Lane(send, recv);
            }

            public byte[] Encrypt(string method, byte[] plaintext)
            {
                lock (_sendLock)
                    return HandshakeWire.EnvelopeToBytes(_send.Encrypt(method ?? "", plaintext));
            }

            public byte[] Decrypt(byte[] wire)
            {
                var env = HandshakeWire.EnvelopeFromBytes(wire);
                lock (_recvLock)
                    return _recv.Decrypt(env);
            }

            // Distinct 8-byte session id per lane => disjoint AES-GCM nonce space per lane,
            // so reusing the same key across lanes stays nonce-unique.
            private static byte[] DeriveLaneId(byte[] baseSessionId, int index)
            {
                byte[] seed = new byte[baseSessionId.Length + 4];
                Buffer.BlockCopy(baseSessionId, 0, seed, 0, baseSessionId.Length);
                BinaryPrimitives.WriteInt32BigEndian(seed.AsSpan(baseSessionId.Length), index);
                return SHA256.HashData(seed)[..8];
            }

            private static Security.AeadChannel NewChannel(
                byte[] key32, byte[] sessionId8, string aad, int index, string dir)
            {
                byte[] hash = SHA256.HashData(Encoding.UTF8.GetBytes($"{aad}:{index}:{dir}"));
                var transcript = new Security.Transcript(hash, $"{index}:{dir}");
                return new Security.AeadChannel(key32, sessionId8, aad, epoch: 0, transcript);
            }

            public void Dispose()
            {
                _send.Dispose();
                _recv.Dispose();
            }
        }
    }

    // ── Wire messages ──────────────────────────────────────────────────────────

    internal enum HandshakeType { Hello, Challenge, Response, Accept, Reject }

    internal sealed class HandshakeMessage
    {
        public HandshakeType Type { get; set; }
        public string FromId { get; set; } = "";
        public string ToId { get; set; } = "";
        public string HandshakeId { get; set; } = "";

        // HELLO
        public Dictionary<string, byte[]>? KyberPub { get; set; }
        public byte[]? NonceC { get; set; }

        // CHALLENGE
        public byte[]? KemCipher { get; set; }
        public byte[]? NonceS { get; set; }
        public byte[]? SessionId { get; set; }
        public byte[]? EncChallenge { get; set; }

        // RESPONSE
        public byte[]? EncResponse { get; set; }

        // REJECT
        public string? Reason { get; set; }
    }

    internal static class HandshakeWire
    {
        private static readonly JsonSerializerOptions Json = new()
        {
            DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        };

        public static byte[] Encode(HandshakeMessage m) =>
            JsonSerializer.SerializeToUtf8Bytes(m, Json);

        public static HandshakeMessage? Decode(byte[] data)
        {
            try { return JsonSerializer.Deserialize<HandshakeMessage>(data, Json); }
            catch { return null; }
        }

        // EncryptedEnvelope <-> bytes without pulling in MessagePack: the envelope's
        // fields are all public, so we round-trip them through a tiny DTO.
        private sealed class EnvDto
        {
            public string ClientId { get; set; } = "";
            public uint Epoch { get; set; }
            public uint Seq { get; set; }
            public string Method { get; set; } = "";
            public byte[] Ciphertext { get; set; } = Array.Empty<byte>();
            public byte[] Tag { get; set; } = Array.Empty<byte>();
        }

        public static byte[] EnvelopeToBytes(Security.EncryptedEnvelope env) =>
            JsonSerializer.SerializeToUtf8Bytes(new EnvDto
            {
                ClientId = env.ClientId,
                Epoch = env.Epoch,
                Seq = env.Seq,
                Method = env.Method,
                Ciphertext = env.Ciphertext,
                Tag = env.Tag,
            }, Json);

        public static Security.EncryptedEnvelope EnvelopeFromBytes(byte[] data)
        {
            var d = JsonSerializer.Deserialize<EnvDto>(data, Json)
                ?? throw new FormatException("Malformed encrypted envelope.");
            return new Security.EncryptedEnvelope
            {
                ClientId = d.ClientId,
                Epoch = d.Epoch,
                Seq = d.Seq,
                Method = d.Method,
                Ciphertext = d.Ciphertext,
                Tag = d.Tag,
            };
        }
    }

    // ── Handshake service ──────────────────────────────────────────────────────

    /// <summary>
    /// Drives both sides of the handshake over an <see cref="IYuukoApi"/> transport. A
    /// single instance can host (answer requesters) and request (open sessions to others).
    /// </summary>
    public sealed class YuukoHandshake : IDisposable
    {
        private readonly IYuukoApi _api;
        private readonly YuukoIdentity _id;
        private readonly HandshakeOptions _opts;

        // Provider side: handshakes awaiting a RESPONSE, keyed by handshakeId.
        private readonly ConcurrentDictionary<string, PendingHandshake> _pending = new();

        // Requester side: awaiting CHALLENGE / ACCEPT, keyed by handshakeId.
        private readonly ConcurrentDictionary<string, RequesterState> _inflight = new();

        // Established sessions, keyed by remote client id.
        private readonly ConcurrentDictionary<string, HandshakeSession> _sessions = new();

        // Single-flight: one in-progress handshake per provider, shared by concurrent callers.
        // Lazy guarantees the handshake body runs once even if GetOrAdd's factory races.
        private readonly ConcurrentDictionary<string, Lazy<Task<HandshakeSession?>>> _connecting = new();

        private Func<YuukoPacket, Task>? _subscription;
        private int _disposed;

        public YuukoHandshake(IYuukoApi api, YuukoIdentity identity, HandshakeOptions? options = null)
        {
            _api = api ?? throw new ArgumentNullException(nameof(api));
            _id = identity ?? throw new ArgumentNullException(nameof(identity));
            _opts = options ?? new HandshakeOptions();
        }

        /// <summary>Established session for a peer, if one exists.</summary>
        public bool TryGetSession(string remoteId, out HandshakeSession session) =>
            _sessions.TryGetValue(remoteId, out session!);

        /// <summary>
        /// Begins listening on the handshake topic so this peer can answer incoming
        /// handshake requests (the "provider"/Eclipse role). Idempotent.
        /// </summary>
        public async Task StartAsync(CancellationToken ct = default)
        {
            if (_subscription is not null) return;
            _subscription = pkt => OnMessageAsync(pkt);
            await _api.SubscribeAsync(_opts.Topic, _subscription, ct);
        }

        /// <summary>
        /// Requester role: performs a handshake with <paramref name="providerId"/> and
        /// returns the established session, or null on rejection/timeout.
        /// </summary>
        public async Task<HandshakeSession?> RequestSessionAsync(string providerId, CancellationToken ct = default)
        {
            ThrowIfDisposed();
            if (_sessions.TryGetValue(providerId, out var existing)) return existing;

            // Make sure we are subscribed so we can hear CHALLENGE/ACCEPT/REJECT.
            await StartAsync(ct);

            // Collapse concurrent requests to the same provider onto one handshake, so a burst
            // of first-time requests doesn't launch (and overwrite) many parallel sessions.
            var lazy = _connecting.GetOrAdd(providerId,
                id => new Lazy<Task<HandshakeSession?>>(() => DoHandshakeAsync(id)));
            try
            {
                return await lazy.Value.WaitAsync(ct).ConfigureAwait(false);
            }
            finally
            {
                _connecting.TryRemove(new KeyValuePair<string, Lazy<Task<HandshakeSession?>>>(providerId, lazy));
            }
        }

        private async Task<HandshakeSession?> DoHandshakeAsync(string providerId)
        {
            var handshakeId = Guid.NewGuid().ToString("N");
            var state = new RequesterState
            {
                ProviderId = providerId,
                NonceC = RandomNumberGenerator.GetBytes(16),
            };
            _inflight[handshakeId] = state;

            try
            {
                await SendAsync(new HandshakeMessage
                {
                    Type = HandshakeType.Hello,
                    FromId = _id.ClientId,
                    ToId = providerId,
                    HandshakeId = handshakeId,
                    KyberPub = _id.ExportPublicKey(),
                    NonceC = state.NonceC,
                });

                using var timeout = new CancellationTokenSource(_opts.Timeout);
                using (timeout.Token.Register(() => state.Completion.TrySetResult(null)))
                {
                    return await state.Completion.Task.ConfigureAwait(false);
                }
            }
            finally
            {
                _inflight.TryRemove(handshakeId, out _);
            }
        }

        // ── Message dispatch ────────────────────────────────────────────────────

        private async Task OnMessageAsync(YuukoPacket pkt)
        {
            var msg = HandshakeWire.Decode(pkt.Data);
            if (msg is null) return;
            if (!string.Equals(msg.ToId, _id.ClientId, StringComparison.Ordinal)) return; // not for us

            switch (msg.Type)
            {
                case HandshakeType.Hello:     await OnHelloAsync(msg); break;
                case HandshakeType.Challenge: await OnChallengeAsync(msg); break;
                case HandshakeType.Response:  await OnResponseAsync(msg); break;
                case HandshakeType.Accept:    OnAccept(msg); break;
                case HandshakeType.Reject:    OnReject(msg); break;
            }
        }

        // ── Provider role ─────────────────────────────────────────────────────

        private async Task OnHelloAsync(HandshakeMessage hello)
        {
            // Step 2: admission check.
            if (_opts.BannedClients.Contains(hello.FromId))
            {
                await SendAsync(Reject(hello, "banned"));
                return;
            }
            if (hello.KyberPub is null || hello.NonceC is null) return;

            // Kyber encapsulation to the requester's public key -> shared secret + cipher.
            var encap = EasyPQC.Keys.CreateSecret(hello.KyberPub);
            byte[] sharedSecret = encap.key;
            byte[] kemCipher = encap.text;

            byte[] nonceS = RandomNumberGenerator.GetBytes(16);
            byte[] sessionId = RandomNumberGenerator.GetBytes(8);

            var (kC2S, kS2C) = Security.PrepareKeys(_opts.PreSharedKey, hello.NonceC, nonceS, sharedSecret);

            // Provider sends on s2c, receives on c2s. AAD clientId is the requester's id on
            // both sides so both parties compute identical associated data. Lane 0 carries
            // the handshake itself and then serves as a normal data lane.
            var session = new HandshakeSession(_id.ClientId, hello.FromId, aadClientId: hello.FromId,
                sendKey: kS2C, recvKey: kC2S, baseSessionId: sessionId, _opts.MaxChannels);

            byte[] challenge = RandomNumberGenerator.GetBytes(32);
            byte[] encChallenge = session.EncryptOnLane(0, "CHALLENGE", challenge);

            _pending[hello.HandshakeId] = new PendingHandshake
            {
                RemoteId = hello.FromId,
                Challenge = challenge,
                Session = session,
                ExpiresAt = DateTimeOffset.UtcNow + _opts.Timeout,
            };

            await SendAsync(new HandshakeMessage
            {
                Type = HandshakeType.Challenge,
                FromId = _id.ClientId,
                ToId = hello.FromId,
                HandshakeId = hello.HandshakeId,
                KemCipher = kemCipher,
                NonceS = nonceS,
                SessionId = sessionId,
                EncChallenge = encChallenge,
            });
        }

        private async Task OnResponseAsync(HandshakeMessage resp)
        {
            if (!_pending.TryRemove(resp.HandshakeId, out var pending)) return;

            bool ok = false;
            try
            {
                if (resp.EncResponse is not null && !IsExpired(pending.ExpiresAt))
                {
                    byte[] echoed = pending.Session.DecryptOnLane(0, resp.EncResponse);
                    ok = CryptographicOperations.FixedTimeEquals(echoed, pending.Challenge);
                }
            }
            catch { ok = false; } // decrypt failure => authentication failure

            if (!ok)
            {
                // Step 5: erase handshake data on failure.
                pending.Session.Dispose();
                await SendAsync(new HandshakeMessage
                {
                    Type = HandshakeType.Reject,
                    FromId = _id.ClientId,
                    ToId = pending.RemoteId,
                    HandshakeId = resp.HandshakeId,
                    Reason = "challenge mismatch",
                });
                return;
            }

            // Step 6: promote to an established session.
            RegisterSession(pending.Session);

            await SendAsync(new HandshakeMessage
            {
                Type = HandshakeType.Accept,
                FromId = _id.ClientId,
                ToId = pending.RemoteId,
                HandshakeId = resp.HandshakeId,
            });
        }

        // ── Requester role ────────────────────────────────────────────────────

        private async Task OnChallengeAsync(HandshakeMessage ch)
        {
            if (!_inflight.TryGetValue(ch.HandshakeId, out var state)) return;
            if (ch.KemCipher is null || ch.NonceS is null || ch.SessionId is null || ch.EncChallenge is null)
                return;

            try
            {
                byte[] sharedSecret = EasyPQC.Keys.CreateSecretTwo(
                    new Dictionary<string, byte[]>(_id.KyberPrivate), ch.KemCipher);

                var (kC2S, kS2C) = Security.PrepareKeys(_opts.PreSharedKey, state.NonceC, ch.NonceS, sharedSecret);

                // Requester sends on c2s, receives on s2c. Same AAD clientId (our own id).
                var session = new HandshakeSession(_id.ClientId, ch.FromId, aadClientId: _id.ClientId,
                    sendKey: kC2S, recvKey: kS2C, baseSessionId: ch.SessionId, _opts.MaxChannels);

                // Decrypt the challenge on lane 0, then echo it back encrypted on the same lane.
                byte[] challenge = session.DecryptOnLane(0, ch.EncChallenge);
                byte[] encResponse = session.EncryptOnLane(0, "RESPONSE", challenge);

                state.Session = session;

                await SendAsync(new HandshakeMessage
                {
                    Type = HandshakeType.Response,
                    FromId = _id.ClientId,
                    ToId = ch.FromId,
                    HandshakeId = ch.HandshakeId,
                    EncResponse = encResponse,
                });
            }
            catch
            {
                state.Session?.Dispose();
                state.Session = null;
                state.Completion.TrySetResult(null);
            }
        }

        private void OnAccept(HandshakeMessage acc)
        {
            if (!_inflight.TryGetValue(acc.HandshakeId, out var state)) return;
            if (state.Session is null) { state.Completion.TrySetResult(null); return; }

            RegisterSession(state.Session);
            state.Completion.TrySetResult(state.Session);
        }

        private void OnReject(HandshakeMessage rej)
        {
            if (!_inflight.TryGetValue(rej.HandshakeId, out var state)) return;
            state.Session?.Dispose();
            state.Session = null;
            state.Completion.TrySetResult(null);
        }

        // ── Helpers ─────────────────────────────────────────────────────────────

        private void RegisterSession(HandshakeSession session)
        {
            if (_sessions.TryGetValue(session.RemoteId, out var old) && !ReferenceEquals(old, session))
                old.Dispose();
            _sessions[session.RemoteId] = session;
        }

        private static bool IsExpired(DateTimeOffset at) => DateTimeOffset.UtcNow > at;

        private HandshakeMessage Reject(HandshakeMessage src, string reason) => new()
        {
            Type = HandshakeType.Reject,
            FromId = _id.ClientId,
            ToId = src.FromId,
            HandshakeId = src.HandshakeId,
            Reason = reason,
        };

        private Task SendAsync(HandshakeMessage msg, CancellationToken ct = default)
        {
            var packet = YuukoPacket.Ephemeral(
                name: msg.Type + ":" + msg.HandshakeId,
                data: HandshakeWire.Encode(msg));
            return _api.PublishAsync(_opts.Topic, packet, ct);
        }

        private void ThrowIfDisposed()
        {
            if (Volatile.Read(ref _disposed) != 0)
                throw new ObjectDisposedException(nameof(YuukoHandshake));
        }

        public void Dispose()
        {
            if (Interlocked.Exchange(ref _disposed, 1) != 0) return;

            if (_subscription is not null)
                _ = _api.UnsubscribeAsync(_opts.Topic, _subscription);

            foreach (var s in _sessions.Values) s.Dispose();
            foreach (var p in _pending.Values) p.Session.Dispose();
            _sessions.Clear();
            _pending.Clear();
        }

        // ── Per-role state ───────────────────────────────────────────────────────

        private sealed class PendingHandshake
        {
            public string RemoteId = "";
            public byte[] Challenge = Array.Empty<byte>();
            public HandshakeSession Session = null!;
            public DateTimeOffset ExpiresAt;
        }

        private sealed class RequesterState
        {
            public string ProviderId = "";
            public byte[] NonceC = Array.Empty<byte>();
            public HandshakeSession? Session;
            public readonly TaskCompletionSource<HandshakeSession?> Completion =
                new(TaskCreationOptions.RunContinuationsAsynchronously);
        }
    }
}
