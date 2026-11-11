// EclipseBroker.cs
// Secure overlay over any IYuukoApi transport (ZenohBroker in production, LocalBroker for
// tests). Replaces the old HTTP+WebSocket-to-Eclipse-server design: instead of a central
// Eclipse RPC hub, each node handshakes peer-to-peer via YuukoHandshake and talks to each
// peer over its own encrypted session.
//
// What a node can do (a node can be all of these at once):
//   Serve / RequestAsync      pull-style data: put packets out, fetch another device's packets
//   On / SendCommandAsync     push-style commands: ask another device to run something, get an ack
//   Peers / KickAsync         who is connected, and throw one out
//   Device("name")            talk to a device by its local nickname (see DeviceDirectory)
//
// All crypto runs through the Eclipse DLL (EclipseProject.Security.AeadChannel) via the
// per-peer HandshakeSession. Only handshake + ciphertext ever touch the transport.
//
// Walker Industries R&D — YuukoProtocol v1.3 (Eclipse-secured, Zenoh-transported)

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading;
using System.Threading.Tasks;

namespace YuukoProtocol
{
    public sealed class EclipseBrokerOptions
    {
        /// <summary>Key expression carrying the encrypted data/command traffic.</summary>
        public string DataTopic { get; set; } = "yuuko/eclipse/data";

        /// <summary>How long RequestAsync waits for a reply on each attempt.</summary>
        public TimeSpan RequestTimeout { get; set; } = TimeSpan.FromSeconds(10);

        /// <summary>Extra RequestAsync attempts after a timeout (reads are safe to repeat).</summary>
        public int RequestRetries { get; set; } = 1;

        /// <summary>Handshake tuning (banned list, pinned devices, PSK, handshake topic, timeout).</summary>
        public HandshakeOptions Handshake { get; } = new();

        // ── commands ──────────────────────────────────────────────────────────

        /// <summary>Default time to wait for a command's ack on each attempt.</summary>
        public TimeSpan CommandTimeout { get; set; } = TimeSpan.FromSeconds(10);

        /// <summary>Default extra attempts after a timeout. Retries are safe: the receiver runs a command at most once.</summary>
        public int CommandRetries { get; set; } = 1;

        /// <summary>How many commands this device runs at the same time; more are answered "Busy".</summary>
        public int MaxConcurrentCommands { get; set; } = 64;

        /// <summary>Largest command payload accepted, in bytes.</summary>
        public int MaxCommandBytes { get; set; } = 1 << 20;

        /// <summary>How long a handler may run before it is cancelled.</summary>
        public TimeSpan CommandHandlerTimeout { get; set; } = TimeSpan.FromSeconds(30);

        /// <summary>How long a finished command's answer is remembered, so a retry gets the same answer instead of a second run.</summary>
        public TimeSpan CommandDedupeWindow { get; set; } = TimeSpan.FromMinutes(5);

        /// <summary>
        /// Decides whether peer X (first argument) may run command Y (second argument). Return false to
        /// answer "Denied" without running the handler. Null allows every connected peer. Built-in
        /// "yuuko.*" commands (ping) are not subject to it. If this throws, the command is denied.
        /// </summary>
        public Func<string, string, bool>? CommandAuthorizer { get; set; }

        // ── relay (broadcast) ─────────────────────────────────────────────────

        /// <summary>
        /// How many devices a broadcast may be passed along through. A change is dropped once it has been relayed this many
        /// times, so it cannot wander forever even if something is wrong. A receiver also clamps larger values it is sent.
        /// </summary>
        public int RelayMaxHops { get; set; } = 8;

        /// <summary>How long a broadcast's id is remembered. A broadcast that comes back within this window is ignored (that is what stops loops).</summary>
        public TimeSpan RelayDedupeWindow { get; set; } = TimeSpan.FromMinutes(10);

        /// <summary>Most broadcast ids remembered at once. When full, new relayed broadcasts are answered "Busy" (never the old ones forgotten early).</summary>
        public int RelayMaxRemembered { get; set; } = 50_000;

        /// <summary>A broadcast signed longer ago than this is refused (a replay). Needs the devices' clocks to roughly agree.</summary>
        public TimeSpan RelayMaxAge { get; set; } = TimeSpan.FromMinutes(5);

        /// <summary>How far ahead of our own clock a broadcast's signing time may be.</summary>
        public TimeSpan RelayClockSkew { get; set; } = TimeSpan.FromMinutes(2);

        /// <summary>
        /// Devices whose broadcasts we accept even when we hold no session with them, by key fingerprint. Every broadcast
        /// is signed by the device that started it; a signature only counts if the signing key is one we know here, is a
        /// device we are connected to right now, or is a pinned device (<see cref="HandshakeOptions.TrustDevice"/> / the
        /// device directory). Trusting an origin does NOT let that device connect to us.
        /// </summary>
        public ConcurrentDictionary<string, string> TrustedOrigins { get; } = new(StringComparer.Ordinal);

        /// <summary>Accept broadcasts started by <paramref name="clientId"/> when they are signed with the key that has this <paramref name="fingerprint"/>.</summary>
        public void TrustOrigin(string clientId, string fingerprint)
        {
            if (string.IsNullOrWhiteSpace(clientId))
                throw new ArgumentException("clientId must be non-empty.", nameof(clientId));
            var fp = (fingerprint ?? "").Trim().ToLowerInvariant();
            if (fp.Length != 64 || !fp.All(Uri.IsHexDigit))
                throw new ArgumentException("fingerprint must be 64 hex characters (YuukoIdentity.Fingerprint).", nameof(fingerprint));
            TrustedOrigins[clientId] = fp;
        }

        public bool UntrustOrigin(string clientId) => TrustedOrigins.TryRemove(clientId, out _);

        // ── presence ──────────────────────────────────────────────────────────

        /// <summary>How long a ping waits for its answer.</summary>
        public TimeSpan PingTimeout { get; set; } = TimeSpan.FromSeconds(3);

        /// <summary>If above zero, ping every connected peer this often. Peers that stay silent are dropped once their lanes run out.</summary>
        public TimeSpan HeartbeatInterval { get; set; } = TimeSpan.Zero;

        /// <summary>A peer counts as online if we heard from it within this window. Zero = three heartbeats, or 60 s without a heartbeat.</summary>
        public TimeSpan PresenceTimeout { get; set; } = TimeSpan.Zero;

        // ── devices ───────────────────────────────────────────────────────────

        /// <summary>
        /// Your list of paired devices. If you supply one, ONLY the devices in it may connect to this
        /// node (an empty directory means nobody can), and this node only opens sessions with them.
        /// </summary>
        public DeviceDirectory? Directory { get; set; }

        /// <summary>
        /// The Yuuko TLS certificate this device's transport uses. Found automatically when the transport is a
        /// <see cref="ZenohBroker"/> that made one; set it yourself only if you open the transport another way.
        /// </summary>
        public YuukoCertificate? TlsCertificate { get; set; }

        // ── group changes ─────────────────────────────────────────────────────

        /// <summary>
        /// Decides whether this device accepts a change to who is in the group that another device announces
        /// (<see cref="EclipseBroker.IntroduceAsync"/> / <see cref="EclipseBroker.RevokeAsync"/>). It is told WHO is announcing
        /// (checked, not claimed) and what they want, and returns true to allow it. This is where you ask the user
        /// ("Phone wants you to trust Headset. Allow?"). <b>Null (the default) refuses every change.</b> A change can
        /// take as long as <see cref="CommandHandlerTimeout"/>; the announcing device does not wait for the answer.
        /// If it throws, the change is refused.
        /// </summary>
        public Func<GroupChange, Task<bool>>? GroupChangePolicy { get; set; }
    }

    public enum GroupChangeKind { Introduce, Revoke }

    /// <summary>One device telling another "trust this device" or "stop trusting this device".</summary>
    /// <param name="IntroducedBy">The device that announced it. For a relayed announcement this was verified from its signature.</param>
    /// <param name="Endpoint">Where the new device can be reached, if the announcer said (informational: connecting is up to you).</param>
    public sealed record GroupChange(GroupChangeKind Kind, string DeviceId, string Fingerprint, string? Endpoint, string IntroducedBy, bool ViaRelay);

    /// <summary>What <see cref="EclipseBroker.PairWithAsync(string,string?,System.Threading.CancellationToken)"/> returned.</summary>
    /// <param name="RestartTransport">
    /// True if this device joined the other device's TLS group while pairing. Its new certificate is on disk, but the
    /// transport still uses the temporary one from the code: open the transport again (restart the app) soon, because
    /// the temporary certificate is only good for a few minutes.
    /// </param>
    public sealed record PairResult(bool Success, string? Failure, string? DeviceId, string? Moniker, bool RestartTransport = false)
    {
        internal static PairResult Fail(string why) => new(false, why, null, null);
    }

    /// <summary>A pairing window that is open: show <see cref="Code"/> (as text or a QR code) to the person pairing.</summary>
    public sealed record PairingOffer(string Code, PairingCode Details)
    {
        public DateTimeOffset ExpiresUtc => Details.ExpiresUtc;
    }

    public sealed class EclipseBroker : IDisposable
    {
        private const int MaxHeals = 2;
        private const int MaxCommandNameLength = 128;

        private readonly IYuukoApi _transport;
        private readonly YuukoIdentity _identity;
        private readonly YuukoHandshake _handshake;
        private readonly EclipseBrokerOptions _opts;

        // Provider: retained packets per data topic (name -> packet), tombstone/ephemeral aware.
        private readonly ConcurrentDictionary<string, ConcurrentDictionary<string, YuukoPacket>> _store = new();

        // Exchanges we started and are waiting on, keyed by request id.
        private readonly ConcurrentDictionary<string, Pending> _pending = new(StringComparer.Ordinal);

        // Commands other devices can run here.
        private readonly ConcurrentDictionary<string, CommandHandler> _handlers = new(StringComparer.Ordinal);

        // Commands we have already seen, so a retry is answered instead of run a second time.
        private readonly ConcurrentDictionary<string, RecentCommand> _recent = new(StringComparer.Ordinal);

        // Broadcasts we have already handled (origin/changeId -> forget-after), so one that comes back around is ignored.
        private readonly ConcurrentDictionary<string, DateTimeOffset> _relaySeen = new(StringComparer.Ordinal);
        private const string RelayCommand = "yuuko.relay";

        private readonly ConcurrentDictionary<string, DateTimeOffset> _lastSeen = new(StringComparer.Ordinal);
        private readonly ConcurrentDictionary<string, long> _noSessionSentAt = new(StringComparer.Ordinal);
        private readonly SemaphoreSlim _commandGate;
        private readonly SemaphoreSlim _startLock = new(1, 1);
        private readonly HashSet<string> _directoryTrusted = new(StringComparer.Ordinal);
        private readonly object _directoryLock = new();

        private Func<YuukoPacket, Task>? _dataSub;
        private CancellationTokenSource? _heartbeatCts;
        private int _disposed;

        /// <summary>Raised when a peer finishes a handshake with us.</summary>
        public event Action<PeerInfo>? PeerConnected;

        /// <summary>Raised when we no longer hold any session with a peer: (peer id, reason).</summary>
        public event Action<string, string>? PeerDisconnected;

        /// <summary>The list of devices this node knows by nickname.</summary>
        public DeviceDirectory Devices { get; }

        private EclipseBroker(IYuukoApi transport, YuukoIdentity identity, EclipseBrokerOptions opts)
        {
            _transport = transport;
            _identity = identity;
            _opts = opts;
            _commandGate = new SemaphoreSlim(Math.Max(1, opts.MaxConcurrentCommands));

            Devices = opts.Directory ?? new DeviceDirectory();
            if (opts.Directory is not null) opts.Handshake.RequireKnownDevices = true;
            SyncTrustFromDirectory();
            Devices.Changed += SyncTrustFromDirectory;

            _handshake = new YuukoHandshake(transport, identity, opts.Handshake);
            _handshake.SessionEstablished += s =>
            {
                Touch(s.RemoteId);
                try { PeerConnected?.Invoke(InfoOf(s)); } catch { /* a subscriber's bug must not break the handshake */ }
                // A device we just paired is waiting for the group's TLS certificate authority: hand it over on this session.
                if (_shareGroupWith.TryRemove(s.RemoteId, out _)) _ = Task.Run(() => ShareGroupAsync(s.RemoteId));
            };
            _handshake.SessionEnded += (s, reason) =>
            {
                if (_handshake.TryGetSession(s.RemoteId, out _)) return;   // another session with that peer remains
                try { PeerDisconnected?.Invoke(s.RemoteId, reason); } catch { }
            };

            _handshake.DevicePaired += (id, fp) =>
            {
                AddToDirectory(id, fp, null);
                _shareGroupWith[id] = 0;
                try { DevicePaired?.Invoke(id, fp); } catch { }
            };

            _handshake.HandshakeRefused += (who, why) => Audit("handshake.refused", who, why);

            _handlers["yuuko.ping"] = (ctx, _) => Task.FromResult(CommandResult.Ok(ctx.Payload));
            _handlers[RelayCommand] = OnRelayAsync;
            _handlers[IntroduceCommand] = OnGroupChangeAsync;
            _handlers[RevokeCommand] = OnGroupChangeAsync;
            _handlers[TlsGroupCommand] = OnTlsGroupAsync;
        }

        private const string IntroduceCommand = "yuuko.introduce", RevokeCommand = "yuuko.revoke", TlsGroupCommand = "yuuko.tlsgroup";

        // Devices we have just paired that are owed the group's TLS authority, and who we are waiting to receive it from.
        private readonly ConcurrentDictionary<string, byte> _shareGroupWith = new(StringComparer.Ordinal);
        private readonly object _groupLock = new();
        private string? _expectGroupFrom;
        private long _expectGroupUntil;
        private TaskCompletionSource<bool>? _groupAdopted;

        private YuukoCertificate? MyCertificate => _opts.TlsCertificate ?? (_transport as ZenohBroker)?.Certificate;

        /// <summary>
        /// True after this device joined another device's TLS group while pairing: the transport must be opened again to use the
        /// new certificate, and until then this device cannot offer pairing codes (they would carry the old authority).
        /// </summary>
        public bool NeedsTransportRestart { get; private set; }

        // Built-in commands that may travel as a signed broadcast (everything else starting "yuuko." may not).
        private static bool IsRelayableBuiltIn(string name) => name is IntroduceCommand or RevokeCommand;

        /// <summary>Raised on the OFFERING device when a newcomer has paired using its code: (the newcomer's id, its key fingerprint). Its keys are already trusted.</summary>
        public event Action<string, string>? DevicePaired;

        /// <summary>
        /// Security-relevant decisions this node made, as (kind, subject, detail): refused connections, kicks and bans, pairing windows,
        /// group changes accepted or refused, commands denied. Feed it to an <see cref="AuditLog"/> (<see cref="AuditLog.Attach"/>).
        /// </summary>
        public event Action<string, string, string>? AuditEvent;

        private void Audit(string kind, string subject, string detail)
        {
            try { AuditEvent?.Invoke(kind, subject, detail); } catch { /* an audit subscriber's bug must never stop the node */ }
        }

        public string ClientId => _identity.ClientId;

        //For the sync layers that sign their own data (Cogitarium)
        internal YuukoIdentity LocalIdentity => _identity;

        /// <summary>This device's key fingerprint: what other devices pin to trust it.</summary>
        public string Fingerprint => _identity.Fingerprint;

        /// <summary>Wraps <paramref name="transport"/> with an Eclipse-secured overlay for <paramref name="identity"/>.</summary>
        public static EclipseBroker Create(IYuukoApi transport, YuukoIdentity identity, EclipseBrokerOptions? options = null)
        {
            if (transport is null) throw new ArgumentNullException(nameof(transport));
            if (identity is null) throw new ArgumentNullException(nameof(identity));
            return new EclipseBroker(transport, identity, options ?? new EclipseBrokerOptions());
        }

        /// <summary>Begins answering handshakes, data requests and commands. Idempotent.</summary>
        public async Task StartAsync(CancellationToken ct = default)
        {
            ThrowIfDisposed();
            if (Volatile.Read(ref _dataSub) is not null) return;

            await _startLock.WaitAsync(ct).ConfigureAwait(false);
            try
            {
                if (_dataSub is not null) return;
                await _handshake.StartAsync(ct).ConfigureAwait(false);

                Func<YuukoPacket, Task> sub = pkt => OnDataMessageAsync(pkt);
                await _transport.SubscribeAsync(_opts.DataTopic, sub, ct).ConfigureAwait(false);
                Volatile.Write(ref _dataSub, sub);

                if (_opts.HeartbeatInterval > TimeSpan.Zero) StartHeartbeat();
            }
            finally { _startLock.Release(); }
        }

        // ── Provider API ─────────────────────────────────────────────────────────

        /// <summary>Publishes a packet into the local store so connected peers can request it.</summary>
        public void Serve(string dataTopic, YuukoPacket packet)
        {
            ThrowIfDisposed();
            var store = _store.GetOrAdd(dataTopic, _ => new ConcurrentDictionary<string, YuukoPacket>());

            if (packet.IsTombstone) { store.TryRemove(packet.Name, out _); return; }
            if (packet.IsEphemeral) return; // never retained, matches LocalBroker
            store[packet.Name] = packet;
        }

        // ── Requester API ────────────────────────────────────────────────────────

        /// <summary>
        /// Ensures a session with <paramref name="providerId"/> (handshaking if needed), then
        /// requests all retained packets on <paramref name="dataTopic"/>, decrypted.
        /// Returns an empty list on rejection/timeout.
        /// </summary>
        public async Task<IReadOnlyList<YuukoPacket>> RequestAsync(
            string providerId, string dataTopic, CancellationToken ct = default)
        {
            ThrowIfDisposed();
            await StartAsync(ct).ConfigureAwait(false);

            var res = await ExchangeAsync(providerId, DataType.Req, DataType.Resp, "REQ", "RESP",
                Encoding.UTF8.GetBytes(dataTopic), Guid.NewGuid().ToString("N"),
                _opts.RequestTimeout, _opts.RequestRetries, ct).ConfigureAwait(false);

            if (res.Plain is null) return Array.Empty<YuukoPacket>();
            try { return DataWire.DecodePackets(res.Plain); }
            catch { return Array.Empty<YuukoPacket>(); }
        }

        // ── Commands ─────────────────────────────────────────────────────────────

        /// <summary>Registers (or replaces) the code that runs when another device sends <paramref name="command"/>.</summary>
        public void On(string command, CommandHandler handler)
        {
            ThrowIfDisposed();
            if (string.IsNullOrWhiteSpace(command) || command.Length > MaxCommandNameLength)
                throw new ArgumentException("A command name must be 1-" + MaxCommandNameLength + " characters.", nameof(command));
            if (command.StartsWith("yuuko.", StringComparison.Ordinal))
                throw new ArgumentException("Names starting with 'yuuko.' are reserved.", nameof(command));
            _handlers[command] = handler ?? throw new ArgumentNullException(nameof(handler));
        }

        /// <summary>Removes a command handler. Peers asking for it afterwards get "UnknownCommand".</summary>
        public bool Off(string command) => _handlers.TryRemove(command, out _);

        /// <summary>
        /// Asks <paramref name="peerId"/> to run <paramref name="command"/> and waits for its ack. Opens a
        /// session first if needed. Never throws for network trouble: check <see cref="CommandAck.Status"/>.
        /// </summary>
        public async Task<CommandAck> SendCommandAsync(string peerId, string command, byte[]? payload = null,
            CommandOptions? options = null, CancellationToken ct = default)
        {
            ThrowIfDisposed();
            if (string.IsNullOrWhiteSpace(command) || command.Length > MaxCommandNameLength)
                throw new ArgumentException("A command name must be 1-" + MaxCommandNameLength + " characters.", nameof(command));
            payload ??= Array.Empty<byte>();
            if (payload.Length > _opts.MaxCommandBytes)
                throw new ArgumentException($"Payload is {payload.Length} bytes; the limit is {_opts.MaxCommandBytes}.", nameof(payload));

            await StartAsync(ct).ConfigureAwait(false);

            var sw = Stopwatch.StartNew();
            var res = await ExchangeAsync(peerId, DataType.Cmd, DataType.Ack, "CMD", "ACK",
                DataWire.EncodeCommand(command, payload), Guid.NewGuid().ToString("N"),
                options?.Timeout ?? _opts.CommandTimeout, options?.Retries ?? _opts.CommandRetries, ct).ConfigureAwait(false);

            if (res.Plain is null)
                return new CommandAck(res.Unreachable ? AckStatus.Unreachable : AckStatus.TimedOut,
                    Array.Empty<byte>(), res.Failure, sw.Elapsed);

            var ack = DataWire.DecodeAck(res.Plain);
            return ack is null
                ? new CommandAck(AckStatus.Error, Array.Empty<byte>(), "malformed ack", sw.Elapsed)
                : new CommandAck(ack.Status, ack.Result, ack.Message, sw.Elapsed);
        }

        /// <summary>Round-trip check. The ack's <see cref="CommandAck.Elapsed"/> is the latency.</summary>
        public Task<CommandAck> PingAsync(string peerId, CancellationToken ct = default) =>
            SendCommandAsync(peerId, "yuuko.ping", Array.Empty<byte>(),
                new CommandOptions { Timeout = _opts.PingTimeout, Retries = 0 }, ct);

        // ── Broadcast (relay) ────────────────────────────────────────────────────

        /// <summary>
        /// Runs <paramref name="command"/> on every device in the group, including ones this device is not connected to:
        /// each device that receives it runs it, then passes it on to ITS other peers.
        /// <para>
        /// Each broadcast gets an id. A device that has already seen the id ignores it and does not pass it on again, so a
        /// group where everyone is connected to everyone, or one with loops, does not echo forever. It also is not run
        /// on THIS device: if you want it here too, run it yourself.
        /// </para>
        /// <para>
        /// Trust: the encryption is between neighbours, so a device that relays a broadcast CAN READ it. But it cannot
        /// forge or change one: this device signs every broadcast (Dilithium5), and a receiver only runs it if the
        /// signing key is one it already trusts for that origin (<see cref="EclipseBrokerOptions.TrustOrigin"/>, a pinned
        /// device, or a device it is connected to). A relay can still drop a broadcast or cut its reach short. Only relay
        /// through devices you are happy to show the content to.
        /// </para>
        /// Reaches only devices connected through sessions that already exist (<see cref="ConnectedPeers"/>).
        /// </summary>
        public async Task<BroadcastResult> BroadcastAsync(string command, byte[]? payload = null,
            CommandOptions? options = null, CancellationToken ct = default)
        {
            ThrowIfDisposed();
            if (string.IsNullOrWhiteSpace(command) || command.Length > MaxCommandNameLength)
                throw new ArgumentException("A command name must be 1-" + MaxCommandNameLength + " characters.", nameof(command));
            if (command.StartsWith("yuuko.", StringComparison.Ordinal))
                throw new ArgumentException("Names starting with 'yuuko.' are reserved and cannot be broadcast.", nameof(command));
            return await BroadcastCoreAsync(command, payload ?? Array.Empty<byte>(), options, ct).ConfigureAwait(false);
        }

        // Shared by BroadcastAsync and the built-in group-change broadcasts (which are the only "yuuko." names allowed).
        private async Task<BroadcastResult> BroadcastCoreAsync(string command, byte[] payload, CommandOptions? options, CancellationToken ct)
        {
            if (payload.Length > MaxBroadcastPayloadBytes)
                throw new ArgumentException($"Payload is {payload.Length} bytes; a broadcast is limited to {MaxBroadcastPayloadBytes}.", nameof(payload));

            await StartAsync(ct).ConfigureAwait(false);

            var (id, wire) = BuildBroadcast(command, payload);
            if (_relaySeen.Count >= _opts.RelayMaxRemembered) PurgeRelaySeen();
            _relaySeen[ClientId + "/" + id] = DateTimeOffset.UtcNow + RelayRememberFor;   // if it comes back to us, ignore it

            var peers = ConnectedPeers.ToList();
            var sent = await Task.WhenAll(peers.Select(async p =>
                (peer: p, ack: await SendCommandAsync(p, RelayCommand, wire, options, ct).ConfigureAwait(false)))).ConfigureAwait(false);

            return new BroadcastResult(id, sent.ToDictionary(s => s.peer, s => s.ack, StringComparer.Ordinal));
        }

        /// <summary>Accept broadcasts started by <paramref name="clientId"/> (signed with the key that has this fingerprint), without allowing it to connect. See <see cref="EclipseBrokerOptions.TrustedOrigins"/>.</summary>
        public void TrustOrigin(string clientId, string fingerprint) => _opts.TrustOrigin(clientId, fingerprint);

        public bool UntrustOrigin(string clientId) => _opts.UntrustOrigin(clientId);

        // The largest broadcast payload: it travels base64-encoded inside a command whose payload limit is MaxCommandBytes,
        // next to the origin's public keys (~6 KB) and its signature (~6 KB).
        private int MaxBroadcastPayloadBytes => Math.Max(0, (_opts.MaxCommandBytes - 24 * 1024) / 4 * 3);

        // How long a handled broadcast id must be remembered: longer than it could still pass the age check, or an old
        // signed copy could be replayed once the id was forgotten.
        private TimeSpan RelayRememberFor
        {
            get
            {
                var minimum = _opts.RelayMaxAge + _opts.RelayClockSkew + TimeSpan.FromMinutes(1);
                return _opts.RelayDedupeWindow > minimum ? _opts.RelayDedupeWindow : minimum;
            }
        }

        // What the origin signs: who, which broadcast, which command, when, and the data. NOT the hop count, which changes at every hand-over.
        private static byte[] BroadcastSigningBytes(string origin, string id, string name, long signedAtMs, byte[] data)
        {
            using var ms = new System.IO.MemoryStream();
            using (var w = new System.IO.BinaryWriter(ms, Encoding.UTF8, leaveOpen: true))
            {
                w.Write("yuuko-bc-v1");   // domain separation: a signature for something else can never pass as this
                w.Write(origin);
                w.Write(id);
                w.Write(name);
                w.Write(signedAtMs);
                w.Write(System.Security.Cryptography.SHA256.HashData(data));
            }
            return ms.ToArray();
        }

        // Makes a signed broadcast. Internal (with the time) so the self-test can build good and bad copies.
        internal (string id, byte[] wire) BuildBroadcast(string command, byte[] payload, DateTimeOffset? signedAt = null, string? claimOrigin = null)
        {
            string id = Guid.NewGuid().ToString("N");
            long at = (signedAt ?? DateTimeOffset.UtcNow).ToUnixTimeMilliseconds();
            string origin = claimOrigin ?? ClientId;   // claimOrigin: only for tests, to play an imposter that signs correctly with its OWN key
            var keys = _identity.ExportPublicKeys();
            byte[] sig = _identity.Sign(BroadcastSigningBytes(origin, id, command, at, payload));
            return (id, DataWire.EncodeRelay(new RelayEnvelope
            {
                Origin = origin, Id = id, Ttl = Math.Max(0, _opts.RelayMaxHops), Name = command, Data = payload,
                SignedAtMs = at, Keys = keys, Signature = sig,
            }));
        }

        // Is this broadcast really from the device it names? Null = yes; otherwise the reason it is not.
        private string? VerifyBroadcast(RelayEnvelope env)
        {
            if (env.Keys is null || env.Signature is null) return "unsigned broadcast";

            var now = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
            if (now - env.SignedAtMs > (long)_opts.RelayMaxAge.TotalMilliseconds) return "broadcast too old";
            if (env.SignedAtMs - now > (long)_opts.RelayClockSkew.TotalMilliseconds) return "broadcast dated in the future";

            // Whose key do we expect for this origin? Only things WE hold: a live authenticated session, or a pin.
            string? expected = null;
            if (_handshake.TryGetSession(env.Origin, out var live)) expected = live.RemoteFingerprint;
            else if (_opts.TrustedOrigins.TryGetValue(env.Origin, out var o)) expected = o;
            else if (_opts.Handshake.TrustedDevices.TryGetValue(env.Origin, out var d)) expected = d;
            if (expected is null) return "origin is not trusted here";

            string actual;
            try { actual = YuukoIdentity.FingerprintOf(env.Keys); }
            catch { return "malformed origin keys"; }
            if (!string.Equals(actual, expected, StringComparison.OrdinalIgnoreCase)) return "keys do not match the trusted origin";

            return YuukoIdentity.VerifySignature(env.Keys.Signing,
                BroadcastSigningBytes(env.Origin, env.Id, env.Name, env.SignedAtMs, env.Data), env.Signature)
                ? null : "bad signature";
        }

        // Built-in "yuuko.relay": someone handed us a broadcast. Run it here (if we have the command), then pass it on.
        private async Task<CommandResult> OnRelayAsync(CommandContext ctx, CancellationToken ct)
        {
            var env = DataWire.DecodeRelay(ctx.Payload);
            if (env is null || (object?)env.Data is null || (object?)env.Origin is null || (object?)env.Id is null || (object?)env.Name is null
                || string.IsNullOrWhiteSpace(env.Origin) || env.Origin.Length > MaxCommandNameLength
                || string.IsNullOrWhiteSpace(env.Id) || env.Id.Length > 64
                || string.IsNullOrWhiteSpace(env.Name) || env.Name.Length > MaxCommandNameLength
                || (env.Name.StartsWith("yuuko.", StringComparison.Ordinal) && !IsRelayableBuiltIn(env.Name)))
                return CommandResult.Error("malformed broadcast");
            if (env.Data.Length > _opts.MaxCommandBytes) return CommandResult.Error("payload too large");

            if (string.Equals(env.Origin, ClientId, StringComparison.Ordinal))
                return new CommandResult(AckStatus.Ok, Array.Empty<byte>(), "duplicate");   // our own broadcast came back

            // Already handled? Cheap check first, before the signature work. Only VERIFIED broadcasts are ever remembered,
            // so nobody can use this list to block a real broadcast by sending its id early.
            string key = env.Origin + "/" + env.Id;
            if (_relaySeen.ContainsKey(key))
                return new CommandResult(AckStatus.Ok, Array.Empty<byte>(), "duplicate");

            // Did the device it names really start it, with exactly this content? The device that handed it to us
            // proves nothing: it could be lying or have changed the data.
            string? problem = VerifyBroadcast(env);
            if (problem is not null) return CommandResult.Denied(problem);

            // The origin is now known, so it is the origin that must be allowed to run this command.
            // (The built-in group-change commands are judged by GroupChangePolicy instead.)
            if (!IsRelayableBuiltIn(env.Name) && _opts.CommandAuthorizer is { } authorize)
            {
                bool allowed;
                try { allowed = authorize(env.Origin, env.Name); } catch { allowed = false; }
                if (!allowed) { Audit("command.denied", env.Origin, env.Name + " (relayed)"); return CommandResult.Denied("not allowed to run '" + env.Name + "'"); }
            }

            if (_relaySeen.Count >= _opts.RelayMaxRemembered)
            {
                PurgeRelaySeen();
                if (_relaySeen.Count >= _opts.RelayMaxRemembered)
                    return new CommandResult(AckStatus.Busy, Array.Empty<byte>(), "too many broadcasts remembered");
            }
            if (!_relaySeen.TryAdd(key, DateTimeOffset.UtcNow + RelayRememberFor))
                return new CommandResult(AckStatus.Ok, Array.Empty<byte>(), "duplicate");   // already handled: do nothing, pass nothing on

            // Pass it on first, so a slow handler here does not hold up the rest of the group.
            int ttl = Math.Min(env.Ttl, _opts.RelayMaxHops);
            if (ttl > 0)
            {
                var next = new RelayEnvelope
                {
                    Origin = env.Origin, Id = env.Id, Ttl = ttl - 1, Name = env.Name, Data = env.Data,
                    SignedAtMs = env.SignedAtMs, Keys = env.Keys, Signature = env.Signature,
                };
                string hop = ctx.FromId;
                _ = Task.Run(() => ForwardAsync(next, hop));
            }

            if (!_handlers.TryGetValue(env.Name, out var handler))
                return new CommandResult(AckStatus.Ok, Array.Empty<byte>(), "passed on only (no such command here)");

            // Already inside a command slot (the one carrying this relay), so no second slot is taken.
            try
            {
                return await RunHandlerAsync(handler,
                    new CommandContext(ctx.FromId, env.Name, env.Data, ctx.RequestId, env.Origin, env.Id), ct).ConfigureAwait(false);
            }
            catch (Exception ex) { return CommandResult.Error("handler failed (" + ex.GetType().Name + ")"); }
        }

        // Hand a broadcast to every connected peer except the one it came from and the one that started it.
        private async Task ForwardAsync(RelayEnvelope env, string cameFrom)
        {
            try
            {
                byte[] wire = DataWire.EncodeRelay(env);
                var targets = ConnectedPeers.Where(p =>
                    !string.Equals(p, cameFrom, StringComparison.Ordinal) && !string.Equals(p, env.Origin, StringComparison.Ordinal));
                await Task.WhenAll(targets.Select(p => SendCommandAsync(p, RelayCommand, wire))).ConfigureAwait(false);
            }
            catch { /* shutting down, or a peer vanished: the other peers' copies still go out */ }
        }

        private void PurgeRelaySeen()
        {
            var now = DateTimeOffset.UtcNow;
            foreach (var kv in _relaySeen)
                if (kv.Value <= now) _relaySeen.TryRemove(kv.Key, out _);
        }

        // ── Peers, presence, kick ────────────────────────────────────────────────

        /// <summary>Ids of every peer we hold a session with.</summary>
        public IReadOnlyCollection<string> ConnectedPeers => _handshake.ConnectedPeers;

        /// <summary>Every connected peer, with its key fingerprint and when we last heard from it.</summary>
        public IReadOnlyList<PeerInfo> Peers => _handshake.GetSessions().Select(InfoOf).ToList();

        public bool IsConnected(string peerId) => _handshake.TryGetSession(peerId, out _);

        // For the self-test: how many sessions we hold with a peer (an old one lingers briefly after a rekey).
        internal int SessionCountWith(string peerId) => _handshake.GetSessionsOf(peerId).Count;

        /// <summary>Connected, and we heard from it recently (see <see cref="EclipseBrokerOptions.PresenceTimeout"/>).</summary>
        public bool IsOnline(string peerId)
        {
            if (!IsConnected(peerId)) return false;
            return _lastSeen.TryGetValue(peerId, out var t) && DateTimeOffset.UtcNow - t <= PresenceWindow;
        }

        public DateTimeOffset? LastSeen(string peerId) => _lastSeen.TryGetValue(peerId, out var t) ? t : null;

        /// <summary>
        /// Ends every session with <paramref name="peerId"/> and tells it so (authenticated, so a bystander
        /// cannot fake it). With <paramref name="ban"/> it is also refused if it tries to reconnect, until
        /// <see cref="Unban"/>. Returns false if we had no session with it.
        /// </summary>
        public async Task<bool> KickAsync(string peerId, bool ban = true, string? reason = null, CancellationToken ct = default)
        {
            ThrowIfDisposed();
            if (ban) _opts.Handshake.BannedClients.Add(peerId);

            var sessions = _handshake.GetSessionsOf(peerId);
            if (ban || sessions.Count > 0) Audit(ban ? "peer.banned" : "peer.kicked", peerId, reason ?? "");
            if (sessions.Count == 0) return false;

            byte[] why = Encoding.UTF8.GetBytes(Truncate(reason ?? "kicked", 200));
            foreach (var s in sessions)
            {
                try
                {
                    var enc = s.EncryptOnLane(HandshakeSession.ControlLane, "CLOSE", why);
                    await SendAsync(DataType.Close, peerId, Guid.NewGuid().ToString("N"), s.Id, HandshakeSession.ControlLane, enc, ct)
                        .ConfigureAwait(false);
                }
                catch { /* best effort: they will find out the first time they use the session */ }
            }

            _handshake.DropPeer(peerId, ban ? "kicked and banned" : "kicked");
            return true;
        }

        /// <summary>Lets a previously banned peer connect again.</summary>
        public bool Unban(string peerId)
        {
            bool removed = _opts.Handshake.BannedClients.Remove(peerId);
            if (removed) Audit("peer.unbanned", peerId, "");
            return removed;
        }

        // ── Devices (nicknames) ──────────────────────────────────────────────────

        /// <summary>
        /// Adds a device to the directory and trusts exactly that key. <paramref name="moniker"/> is your
        /// local nickname for it; it never leaves this device.
        /// </summary>
        public DeviceRecord PairDevice(string moniker, string clientId, string fingerprint,
            string? displayName = null, params string[] groups) =>
            Devices.Add(moniker, clientId, fingerprint, displayName, groups);

        /// <summary>Removes a device from the directory (so it is no longer trusted) and, by default, kicks it.</summary>
        public async Task<bool> UnpairDeviceAsync(string moniker, bool kick = true, CancellationToken ct = default)
        {
            var rec = Devices.Find(moniker);
            if (rec is null) return false;
            Devices.Remove(rec.Moniker);
            if (kick) await KickAsync(rec.ClientId, ban: false, reason: "unpaired", ct).ConfigureAwait(false);
            return true;
        }

        /// <summary>A handle for talking to a paired device by nickname. Throws if there is no such nickname.</summary>
        public DeviceHandle Device(string moniker) =>
            new(this, Devices.Find(moniker) ?? throw new KeyNotFoundException($"No device is paired as '{moniker}'."));

        /// <summary>Every paired device.</summary>
        public DeviceSet AllDevices() => new(Devices.All().Select(r => new DeviceHandle(this, r)).ToList());

        /// <summary>Every paired device in the named group.</summary>
        public DeviceSet DeviceGroup(string group) => new(Devices.InGroup(group).Select(r => new DeviceHandle(this, r)).ToList());

        /// <summary>The directory joined with live connection state: the "list my devices" view.</summary>
        public IReadOnlyList<DeviceStatus> DeviceStatuses() => Devices.All().Select(r => new DeviceStatus(
            r.Moniker, r.ClientId, r.Fingerprint, r.DisplayName, r.Groups,
            IsConnected(r.ClientId), IsOnline(r.ClientId), LastSeen(r.ClientId))).ToList();

        // ── Pairing: adding a new device with a code ─────────────────────────────

        /// <summary>
        /// Opens a pairing window and returns the code to show (as text, or turn it into a QR code). For
        /// <paramref name="lifetime"/> (default 5 minutes) ONE new device that has the code may connect, even though
        /// it is not on the allowlist. When it succeeds its keys are pinned (and it is added to <see cref="Devices"/>)
        /// and the code stops working. <b>The code is a secret until then.</b> Show it only to the person pairing.
        /// <para>
        /// The code carries this device's key fingerprint, address and TLS certificate when it knows them (a
        /// <see cref="ZenohBroker"/> transport). Pass <paramref name="endpoint"/> to override the address in the code.
        /// </para>
        /// </summary>
        public PairingOffer BeginPairing(TimeSpan? lifetime = null, string? endpoint = null, int maxAttempts = 10)
        {
            ThrowIfDisposed();
            if (NeedsTransportRestart)
                throw new InvalidOperationException("This device joined another device's TLS group. Open the transport again before offering a pairing code.");
            var life = lifetime ?? TimeSpan.FromMinutes(5);
            byte[] token = _handshake.BeginPairing(life, maxAttempts);

            // With TLS the newcomer needs a way through our mutual TLS before it is trusted: a certificate for it alone, good for the window.
            string? tempCert = null, tempKey = null;
            var cert = MyCertificate;
            if (cert is not null) (tempCert, tempKey) = YuukoTls.IssueTemporary(cert, life + TimeSpan.FromMinutes(2));

            var details = new PairingCode(ClientId, Fingerprint, endpoint ?? DefaultEndpoint(),
                cert?.CaPem, token, DateTimeOffset.UtcNow + life, tempCert, tempKey);
            System.Security.Cryptography.CryptographicOperations.ZeroMemory(token);
            Audit("pairing.offered", ClientId, "valid until " + details.ExpiresUtc.ToString("O"));
            return new PairingOffer(details.Encode(), details);
        }

        /// <summary>Closes the pairing window now (the code stops working).</summary>
        public void CancelPairing()
        {
            if (_handshake.PairingOpen) Audit("pairing.cancelled", ClientId, "");
            _handshake.CancelPairing();
        }

        public bool PairingOpen => _handshake.PairingOpen;

        /// <summary>
        /// Joins the device that made <paramref name="code"/>. The transport must already be able to reach it: for a
        /// <see cref="ZenohBroker"/> that means opening it with <see cref="PairingCode.ToTransportOptions"/> first. On
        /// success the other device is pinned, added to <see cref="Devices"/> (as <paramref name="moniker"/>, or its own
        /// name), and the two are connected. Never throws for a bad or expired code: read <see cref="PairResult.Failure"/>.
        /// </summary>
        public async Task<PairResult> PairWithAsync(string code, string? moniker = null, CancellationToken ct = default)
        {
            ThrowIfDisposed();
            return PairingCode.TryParse(code, out var parsed, out var error)
                ? await PairWithAsync(parsed!, moniker, ct).ConfigureAwait(false)
                : PairResult.Fail(error!);
        }

        public async Task<PairResult> PairWithAsync(PairingCode code, string? moniker = null, CancellationToken ct = default)
        {
            ThrowIfDisposed();
            if (code is null) throw new ArgumentNullException(nameof(code));
            if (code.IsExpired) return PairResult.Fail("This pairing code has expired. Ask the other device for a new one.");
            if (string.Equals(code.DeviceId, ClientId, StringComparison.Ordinal) || code.Fingerprint == Fingerprint)
                return PairResult.Fail("That code was made by this device.");

            // Be listening BEFORE pairing: the other device sends us things (its TLS group) the moment we are paired.
            await StartAsync(ct).ConfigureAwait(false);

            // With TLS, the other device will hand us its group's certificate authority. Be ready for it (and ONLY from it, just now).
            bool expectGroup = false;
            if (MyCertificate is { } mine && code.CaCertificatePem is not null)
            {
                if (mine.CaFingerprint != YuukoTls.FingerprintOfPem(code.CaCertificatePem) && Devices.All().Count > 0)
                    return PairResult.Fail("This device already belongs to a group of its own (it has paired devices). Joining another group would cut it off from them.");
                ExpectGroupFrom(code.DeviceId, TimeSpan.FromSeconds(60));
                expectGroup = true;
            }

            HandshakeSession? session;
            try { session = await _handshake.PairAsync(code.DeviceId, code.Fingerprint, code.Token, ct).ConfigureAwait(false); }
            catch (InvalidOperationException e) { StopExpectingGroup(); return PairResult.Fail(e.Message); }
            catch { StopExpectingGroup(); throw; }

            if (session is null)
            {
                StopExpectingGroup();
                return PairResult.Fail("Could not pair. The code may have expired or already been used, the other device may be out of reach, or its pairing window is closed.");
            }

            string? name = AddToDirectory(code.DeviceId, code.Fingerprint, moniker);

            bool restart = false;
            if (expectGroup)
            {
                var done = _groupAdopted!.Task;
                if (await Task.WhenAny(done, Task.Delay(TimeSpan.FromSeconds(10), ct)).ConfigureAwait(false) == done) restart = done.Result;
                StopExpectingGroup();
            }
            return new PairResult(true, null, code.DeviceId, name, restart);
        }

        private void ExpectGroupFrom(string deviceId, TimeSpan window)
        {
            lock (_groupLock)
            {
                _expectGroupFrom = deviceId;
                _expectGroupUntil = Environment.TickCount64 + (long)window.TotalMilliseconds;
                _groupAdopted = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
            }
        }

        private void StopExpectingGroup()
        {
            lock (_groupLock) { _expectGroupFrom = null; _expectGroupUntil = 0; }
        }

        // Records a paired device in the directory under a nickname that is valid and unused. Returns the nickname, or null if it could not be added.
        private string? AddToDirectory(string clientId, string fingerprint, string? preferred)
        {
            try
            {
                if (Devices.FindByClientId(clientId) is { } existing) return existing.Moniker;
                string name = preferred ?? clientId;
                if (!DeviceDirectory.IsValidName(name))
                    name = new string(name.Select(c => char.IsAsciiLetterOrDigit(c) || c is '.' or '_' or '-' ? c : '-').ToArray());
                if (name.Length > 60) name = name[..60];
                if (name.Length == 0) name = "device";

                for (int i = 0; i < 50; i++)
                {
                    string candidate = i == 0 ? name : name + "-" + (i + 1);
                    try { Devices.Add(candidate, clientId, fingerprint); lock (_directoryLock) _directoryTrusted.Add(clientId); return candidate; }
                    catch (InvalidOperationException) { if (Devices.FindByClientId(clientId) is { } now) return now.Moniker; }
                }
            }
            catch { /* the directory is a convenience: the pin already exists either way */ }
            return null;
        }

        // The address to put in a code: our listening port on this machine's LAN address.
        private string? DefaultEndpoint()
        {
            if (_transport is not ZenohBroker zb) return null;
            string? ep = zb.ListenEndpoints.FirstOrDefault(e => e.StartsWith("tcp/", StringComparison.OrdinalIgnoreCase) || e.StartsWith("tls/", StringComparison.OrdinalIgnoreCase));
            if (ep is null) return null;
            string rest = ep[4..];
            int colon = rest.LastIndexOf(':');
            if (colon < 0) return ep;
            string host = rest[..colon], port = rest[(colon + 1)..];
            if (host is "0.0.0.0" or "[::]" or "::" or "" or "*") host = LocalAddress() ?? "127.0.0.1";
            return "tcp/" + host + ":" + port;
        }

        // This machine's most likely LAN address: a private IPv4 on an interface that is up.
        private static string? LocalAddress()
        {
            try
            {
                var candidates = System.Net.NetworkInformation.NetworkInterface.GetAllNetworkInterfaces()
                    .Where(n => n.OperationalStatus == System.Net.NetworkInformation.OperationalStatus.Up
                             && n.NetworkInterfaceType != System.Net.NetworkInformation.NetworkInterfaceType.Loopback)
                    .SelectMany(n => n.GetIPProperties().UnicastAddresses)
                    .Select(a => a.Address)
                    .Where(a => a.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
                    .ToList();
                static bool Private(System.Net.IPAddress a)
                {
                    var b = a.GetAddressBytes();
                    return b[0] == 10 || (b[0] == 172 && b[1] is >= 16 and <= 31) || (b[0] == 192 && b[1] == 168);
                }
                return (candidates.FirstOrDefault(Private) ?? candidates.FirstOrDefault())?.ToString();
            }
            catch { return null; }
        }

        // The offering side: give the device we just paired the group's TLS authority (certificate AND key), on the encrypted session.
        // Everything in the group then trusts one authority, so nobody has to be updated when a device joins.
        private async Task ShareGroupAsync(string peerId)
        {
            try
            {
                if (MyCertificate is not { } mine) return;
                byte[] payload = JsonSerializer.SerializeToUtf8Bytes(new TlsGroupWire
                {
                    CaPem = System.IO.File.ReadAllText(mine.CaCertPath),
                    CaKeyPem = System.IO.File.ReadAllText(System.IO.Path.Combine(mine.Directory, "ca.key")),
                });
                try { await SendCommandAsync(peerId, TlsGroupCommand, payload).ConfigureAwait(false); }
                finally { System.Security.Cryptography.CryptographicOperations.ZeroMemory(payload); }
            }
            catch { /* the pairing itself already succeeded; the newcomer can be paired again for its TLS group */ }
        }

        // Built-in "yuuko.tlsgroup": the device we just paired gives us its group's TLS authority. Accepted ONLY from the
        // device we asked to pair with, within a minute of asking: this carries a signing key, so nobody else may send it.
        private int _tlsGroupSeen;
        internal int TlsGroupMessagesSeen => Volatile.Read(ref _tlsGroupSeen);   // for the self-test: who was offered a group, and how often

        private Task<CommandResult> OnTlsGroupAsync(CommandContext ctx, CancellationToken ct)
        {
            Interlocked.Increment(ref _tlsGroupSeen);
            string? from;
            long until;
            lock (_groupLock) { from = _expectGroupFrom; until = _expectGroupUntil; }
            if (from is null || !string.Equals(from, ctx.FromId, StringComparison.Ordinal) || Environment.TickCount64 > until)
                return Task.FromResult(CommandResult.Denied("not expecting a TLS group from this device"));

            if (MyCertificate is not { } mine)
            {
                _groupAdopted?.TrySetResult(false);
                return Task.FromResult(new CommandResult(AckStatus.Ok, Array.Empty<byte>(), "this device does not use TLS"));
            }

            try
            {
                var wire = JsonSerializer.Deserialize<TlsGroupWire>(ctx.Payload);
                if (wire is null || string.IsNullOrWhiteSpace(wire.CaPem) || string.IsNullOrWhiteSpace(wire.CaKeyPem))
                    return Task.FromResult(CommandResult.Error("malformed TLS group"));

                if (YuukoTls.FingerprintOfPem(wire.CaPem) == mine.CaFingerprint)
                {
                    _groupAdopted?.TrySetResult(false);
                    return Task.FromResult(CommandResult.Ok("already in this group"));
                }

                YuukoTls.AdoptGroup(mine, wire.CaPem, wire.CaKeyPem);
                Audit("tls.group.joined", ctx.FromId, "adopted its TLS authority");
                NeedsTransportRestart = true;
                _groupAdopted?.TrySetResult(true);
                return Task.FromResult(CommandResult.Ok("joined"));
            }
            catch (Exception e) when (e is ArgumentException or System.Security.Cryptography.CryptographicException or JsonException or System.IO.IOException)
            {
                return Task.FromResult(CommandResult.Error("not a usable TLS group"));
            }
        }

        private sealed class TlsGroupWire
        {
            public string CaPem { get; set; } = "";
            public string CaKeyPem { get; set; } = "";
        }

        // ── Group changes: telling the rest of the group about a device ──────────

        /// <summary>
        /// Tells the rest of the group to trust <paramref name="deviceId"/> (a device THIS device already trusts), and tells
        /// that device about the other members. Each receiving device asks its own <see cref="EclipseBrokerOptions.GroupChangePolicy"/>
        /// before doing anything, and a device with no policy refuses. Returns what the broadcast reached directly.
        /// </summary>
        public async Task<BroadcastResult> IntroduceAsync(string deviceId, string? endpoint = null, CancellationToken ct = default)
        {
            ThrowIfDisposed();
            if (!_opts.Handshake.TrustedDevices.TryGetValue(deviceId, out var fp))
                throw new InvalidOperationException($"'{deviceId}' is not a device this one trusts, so it cannot be introduced to others.");

            var result = await BroadcastCoreAsync(IntroduceCommand, GroupChangeWire.Encode(deviceId, fp, endpoint), null, ct).ConfigureAwait(false);
            Audit("group.introduced", deviceId, "announced to the group");

            // The newcomer also needs to hear about everyone else (it may refuse them, by its own policy).
            foreach (var kv in _opts.Handshake.TrustedDevices.ToList())
            {
                if (kv.Key == deviceId || kv.Key == ClientId) continue;
                try { await SendCommandAsync(deviceId, IntroduceCommand, GroupChangeWire.Encode(kv.Key, kv.Value, null), ct: ct).ConfigureAwait(false); }
                catch { /* best effort */ }
            }
            return result;
        }

        /// <summary>
        /// Stops trusting <paramref name="deviceId"/> here (and disconnects it), and asks the rest of the group to do the
        /// same. Devices that are offline, or whose policy refuses, keep trusting it. <b>Revocation is a request, not a guarantee.</b>
        /// </summary>
        public async Task<BroadcastResult> RevokeAsync(string deviceId, CancellationToken ct = default)
        {
            ThrowIfDisposed();
            if (!_opts.Handshake.TrustedDevices.TryGetValue(deviceId, out var fp))
                throw new InvalidOperationException($"'{deviceId}' is not a device this one trusts.");

            // Ask the others first, while the link to them is still up, then act locally.
            var result = await BroadcastCoreAsync(RevokeCommand, GroupChangeWire.Encode(deviceId, fp, null), null, ct).ConfigureAwait(false);
            Audit("group.revoked", deviceId, "announced to the group, and removed here");
            ForgetDevice(deviceId, "revoked");
            return result;
        }

        private void ForgetDevice(string deviceId, string reason)
        {
            if (Devices.FindByClientId(deviceId) is { } rec) Devices.Remove(rec.Moniker);
            _opts.Handshake.UntrustDevice(deviceId);
            lock (_directoryLock) _directoryTrusted.Remove(deviceId);
            _ = KickAsync(deviceId, ban: false, reason: reason);
        }

        // Built-in "yuuko.introduce" / "yuuko.revoke". Reached by a direct command or by a signed broadcast; either way
        // ctx.Origin is the checked identity of whoever announced it.
        private async Task<CommandResult> OnGroupChangeAsync(CommandContext ctx, CancellationToken ct)
        {
            var wire = GroupChangeWire.Decode(ctx.Payload);
            if (wire is null) return CommandResult.Error("malformed group change");
            bool introduce = ctx.Name == IntroduceCommand;

            if (string.Equals(wire.Id, ClientId, StringComparison.Ordinal)) return CommandResult.Ok("that is this device");
            if (_opts.GroupChangePolicy is not { } policy)
            {
                Audit("group.refused", wire.Id, (introduce ? "introduce" : "revoke") + " announced by " + ctx.Origin + ": no policy set");
                return CommandResult.Denied("this device does not accept group changes");
            }

            var known = _opts.Handshake.TrustedDevices.TryGetValue(wire.Id, out var pinned) ? pinned : null;
            if (introduce)
            {
                if (known is not null)
                    return string.Equals(known, wire.Fingerprint, StringComparison.Ordinal)
                        ? CommandResult.Ok("already trusted")
                        : CommandResult.Denied("that name is already paired with different keys");
            }
            else
            {
                if (known is null) return CommandResult.Ok("not trusted here anyway");
                if (!string.Equals(known, wire.Fingerprint, StringComparison.Ordinal)) return CommandResult.Denied("those are not the keys trusted for that name");
            }

            // The policy usually asks a person. It gets CommandHandlerTimeout to answer: a prompt nobody answers is a
            // refusal, and must not hold this command's slot forever (the policy cannot be cancelled, so we stop waiting for it).
            bool allowed;
            try
            {
                var decision = policy(new GroupChange(introduce ? GroupChangeKind.Introduce : GroupChangeKind.Revoke,
                    wire.Id, wire.Fingerprint, wire.Endpoint, ctx.Origin, ctx.IsBroadcast));
                var timeout = Task.Delay(_opts.CommandHandlerTimeout);
                allowed = await Task.WhenAny(decision, timeout).ConfigureAwait(false) == decision
                          && await decision.ConfigureAwait(false);
            }
            catch { allowed = false; }
            Audit(allowed ? "group.accepted" : "group.refused", wire.Id, (introduce ? "introduce" : "revoke") + " announced by " + ctx.Origin);
            if (!allowed) return CommandResult.Denied("refused by this device's policy, or not answered in time");

            if (introduce)
            {
                _opts.Handshake.TrustDevice(wire.Id, wire.Fingerprint);
                AddToDirectory(wire.Id, wire.Fingerprint, null);
                return CommandResult.Ok("trusted");
            }
            ForgetDevice(wire.Id, "revoked by " + ctx.Origin);
            return CommandResult.Ok("revoked");
        }

        private sealed class GroupChangeWire
        {
            public string Id { get; set; } = "";
            public string Fingerprint { get; set; } = "";
            public string? Endpoint { get; set; }

            public static byte[] Encode(string id, string fingerprint, string? endpoint) =>
                JsonSerializer.SerializeToUtf8Bytes(new GroupChangeWire { Id = id, Fingerprint = fingerprint, Endpoint = endpoint });

            public static GroupChangeWire? Decode(byte[] data)
            {
                try
                {
                    var w = JsonSerializer.Deserialize<GroupChangeWire>(data);
                    if (w is null || string.IsNullOrWhiteSpace(w.Id) || w.Id.Length > 128) return null;
                    w.Fingerprint = (w.Fingerprint ?? "").Trim().ToLowerInvariant();
                    if (w.Fingerprint.Length != 64 || !w.Fingerprint.All(Uri.IsHexDigit)) return null;
                    if (w.Endpoint is { Length: > 512 }) return null;
                    return w;
                }
                catch { return null; }
            }
        }

        // ── Message handling ───────────────────────────────────────────────────────

        private async Task OnDataMessageAsync(YuukoPacket pkt)
        {
            var msg = DataWire.Decode(pkt.Data);
            if (msg is null) return;
            if (!string.Equals(msg.ToId, _identity.ClientId, StringComparison.Ordinal)) return;
            if (Volatile.Read(ref _disposed) != 0) return;

            try
            {
                switch (msg.Type)
                {
                    case DataType.Req: await OnRequestAsync(msg).ConfigureAwait(false); break;
                    case DataType.Cmd: await OnCommandAsync(msg).ConfigureAwait(false); break;
                    case DataType.Resp:
                    case DataType.Ack: OnReply(msg); break;
                    case DataType.NoSession: OnNoSession(msg); break;
                    case DataType.Close: OnClose(msg); break;
                }
            }
            catch (ObjectDisposedException) { /* session or broker closed while we were working */ }
        }

        private bool TryFindSession(DataMessage msg, out HandshakeSession session)
        {
            if (!string.IsNullOrEmpty(msg.SessionId) &&
                _handshake.TryGetSessionById(msg.SessionId, msg.FromId, out session))
                return true;
            session = null!;
            return false;
        }

        private async Task OnRequestAsync(DataMessage req)
        {
            // Only serve peers that have completed a handshake.
            if (!TryFindSession(req, out var session)) { await SendNoSessionAsync(req).ConfigureAwait(false); return; }
            if (req.Payload is null) return;

            IReadOnlyList<YuukoPacket> packets;
            try
            {
                string dataTopic = Encoding.UTF8.GetString(session.DecryptOnLane(req.Lane, req.Payload, "REQ"));
                packets = _store.TryGetValue(dataTopic, out var store)
                    ? store.Values.ToList()
                    : Array.Empty<YuukoPacket>();
            }
            catch { return; } // decrypt failed => not a valid peer message, drop
            Touch(session.RemoteId);

            // Answer on the same lane the request arrived on.
            byte[] enc = session.EncryptOnLane(req.Lane, "RESP", DataWire.EncodePackets(packets));
            await SendAsync(DataType.Resp, req.FromId, req.RequestId, session.Id, req.Lane, enc).ConfigureAwait(false);
        }

        // A reply (data response or command ack) to an exchange we started.
        private void OnReply(DataMessage msg)
        {
            if (!_pending.TryGetValue(msg.RequestId, out var p)) return;
            if (p.ReplyType != msg.Type || !string.Equals(p.PeerId, msg.FromId, StringComparison.Ordinal)) return;
            if (msg.Payload is null || !TryFindSession(msg, out var session)) return;

            byte[] plain;
            try { plain = session.DecryptOnLane(msg.Lane, msg.Payload, p.ReplyMethod); }
            catch { return; }

            Touch(msg.FromId);
            p.SetFinal(plain);
            p.Signal();
        }

        // The peer got our message but has no session by that id (it restarted, or dropped us).
        private void OnNoSession(DataMessage msg)
        {
            if (!_pending.TryGetValue(msg.RequestId, out var p)) return;
            if (!string.Equals(p.PeerId, msg.FromId, StringComparison.Ordinal)) return;

            // Only believe it if it names the session we are actually using with that peer.
            if (!_handshake.TryGetSession(msg.FromId, out var cur) || cur.Id != msg.SessionId) return;

            p.SawNoSession = true;
            p.Signal();
        }

        private void OnClose(DataMessage msg)
        {
            if (msg.Payload is null || !TryFindSession(msg, out var session)) return;

            string reason;
            try { reason = Encoding.UTF8.GetString(session.DecryptOnLane(HandshakeSession.ControlLane, msg.Payload, "CLOSE")); }
            catch { return; }   // not really from the peer

            _handshake.DropSession(session, "closed by peer: " + Truncate(reason, 200));
        }

        private async Task OnCommandAsync(DataMessage msg)
        {
            if (!TryFindSession(msg, out var session)) { await SendNoSessionAsync(msg).ConfigureAwait(false); return; }
            if (msg.Payload is null) return;

            byte[] plain;
            try { plain = session.DecryptOnLane(msg.Lane, msg.Payload, "CMD"); }
            catch { return; }
            Touch(session.RemoteId);

            // Have we seen this request id from this peer before? Then this is a retry.
            string key = session.RemoteId + "/" + msg.RequestId;
            var record = new RecentCommand(DateTimeOffset.UtcNow + _opts.CommandDedupeWindow);
            if (!_recent.TryAdd(key, record))
            {
                if (_recent.TryGetValue(key, out var seen) && seen.AckPlain is { } stored)
                    await SendAckAsync(session, msg, stored).ConfigureAwait(false);   // finished: repeat the answer
                return;                                                                // still running: it will answer itself
            }
            PurgeRecentIfLarge();

            _ = Task.Run(() => RunCommandAsync(session, msg, plain, record));
        }

        private async Task RunCommandAsync(HandshakeSession session, DataMessage msg, byte[] plain, RecentCommand record)
        {
            CommandResult result;
            try { result = await ExecuteAsync(session.RemoteId, msg.RequestId, plain).ConfigureAwait(false); }
            catch (Exception ex) { result = CommandResult.Error("handler failed (" + ex.GetType().Name + ")"); }

            byte[] ackPlain = DataWire.EncodeAck(result);
            record.AckPlain = ackPlain;
            try { await SendAckAsync(session, msg, ackPlain).ConfigureAwait(false); }
            catch { /* the peer or transport went away; a retry will be handed the stored answer */ }
        }

        private async Task<CommandResult> ExecuteAsync(string peerId, string requestId, byte[] plain)
        {
            if (plain.Length > (long)_opts.MaxCommandBytes * 2 + 1024) return CommandResult.Error("payload too large");

            var env = DataWire.DecodeCommand(plain);
            if (env is null || string.IsNullOrWhiteSpace(env.Name) || env.Name.Length > MaxCommandNameLength)
                return CommandResult.Error("malformed command");
            if (env.Data.Length > _opts.MaxCommandBytes) return CommandResult.Error("payload too large");

            bool builtIn = env.Name.StartsWith("yuuko.", StringComparison.Ordinal);
            if (!builtIn && _opts.CommandAuthorizer is { } authorize)
            {
                bool allowed;
                try { allowed = authorize(peerId, env.Name); } catch { allowed = false; }
                if (!allowed) { Audit("command.denied", peerId, env.Name); return CommandResult.Denied("not allowed to run '" + env.Name + "'"); }
            }

            if (!_handlers.TryGetValue(env.Name, out var handler))
                return new CommandResult(AckStatus.UnknownCommand, Array.Empty<byte>(), "no such command: " + env.Name);

            if (!_commandGate.Wait(0))
                return new CommandResult(AckStatus.Busy, Array.Empty<byte>(), "too many commands running");
            try { return await RunHandlerAsync(handler, new CommandContext(peerId, env.Name, env.Data, requestId), CancellationToken.None).ConfigureAwait(false); }
            finally { _commandGate.Release(); }
        }

        // Runs a handler with the time limit and the result checks. The caller holds a slot in _commandGate.
        private async Task<CommandResult> RunHandlerAsync(CommandHandler handler, CommandContext ctx, CancellationToken ct)
        {
            try
            {
                using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                cts.CancelAfter(_opts.CommandHandlerTimeout);
                var r = await handler(ctx, cts.Token).ConfigureAwait(false);
                if (r is null) return CommandResult.Error("handler returned nothing");
                return (int)r.Status >= 100 ? CommandResult.Error(r.Message ?? "handler failed") : r;
            }
            catch (OperationCanceledException) { return CommandResult.Error("handler timed out"); }
        }

        private Task SendAckAsync(HandshakeSession session, DataMessage msg, byte[] ackPlain)
        {
            byte[] enc = session.EncryptOnLane(msg.Lane, "ACK", ackPlain);
            return SendAsync(DataType.Ack, msg.FromId, msg.RequestId, session.Id, msg.Lane, enc);
        }

        // "I have no session by that id": lets a peer that is holding a stale session find out at
        // once instead of waiting out a timeout. Rate-limited so it cannot be used as a megaphone.
        private async Task SendNoSessionAsync(DataMessage msg)
        {
            long now = Environment.TickCount64;
            if (_noSessionSentAt.TryGetValue(msg.FromId, out var last) && now - last < 1000) return;
            if (_noSessionSentAt.Count > 1024) _noSessionSentAt.Clear();
            _noSessionSentAt[msg.FromId] = now;

            await SendAsync(DataType.NoSession, msg.FromId, msg.RequestId, msg.SessionId ?? "", 0, null).ConfigureAwait(false);
        }

        // ── The send/wait/heal loop ───────────────────────────────────────────────

        private sealed record ExchangeResult(byte[]? Plain, bool Unreachable, string? Failure);

        // Sends one message on a lane of the current session and waits for its reply, handling the ways
        // that goes wrong:
        //   timeout     the lane may now be out of step with the peer (a lost message leaves a strictly
        //               sequenced lane stuck), so retire it and retry on another; when every lane is
        //               retired, replace the session.
        //   NoSession   the peer restarted or dropped us; replace the session and try again.
        private async Task<ExchangeResult> ExchangeAsync(string peerId, DataType type, DataType replyType,
            string method, string replyMethod, byte[] plaintext, string requestId,
            TimeSpan timeout, int retries, CancellationToken ct)
        {
            var pending = new Pending(peerId, replyType, replyMethod);
            _pending[requestId] = pending;
            try
            {
                int timeouts = 0, heals = 0;
                while (true)
                {
                    ct.ThrowIfCancellationRequested();

                    var session = await _handshake.RequestSessionAsync(peerId, ct).ConfigureAwait(false);
                    if (session is null)
                        return new ExchangeResult(null, true, "could not establish a session (unreachable, not trusted, or refused)");
                    if (pending.Final is { } early) return new ExchangeResult(early, false, null);

                    if (session.IsExhausted)
                    {
                        if (++heals > MaxHeals) return new ExchangeResult(null, false, "no usable lanes");
                        _handshake.DropSession(session, "no usable lanes");
                        continue;
                    }

                    int lane;
                    try { lane = await session.AcquireLaneAsync(ct).ConfigureAwait(false); }
                    catch (SessionExhaustedException)
                    {
                        if (++heals > MaxHeals) return new ExchangeResult(null, false, "no usable lanes");
                        _handshake.DropSession(session, "no usable lanes");
                        continue;
                    }
                    catch (ObjectDisposedException)
                    {
                        if (++heals > MaxHeals) return new ExchangeResult(null, false, "session closed");
                        continue;
                    }

                    pending.Reset();
                    if (pending.Final is { } late) { Release(session, lane); return new ExchangeResult(late, false, null); }

                    try
                    {
                        byte[] enc = session.EncryptOnLane(lane, method, plaintext);
                        await SendAsync(type, peerId, requestId, session.Id, lane, enc, ct).ConfigureAwait(false);
                    }
                    catch (ObjectDisposedException)
                    {
                        if (++heals > MaxHeals) return new ExchangeResult(null, false, "session closed");
                        continue;
                    }
                    catch { Release(session, lane); throw; }

                    using var delayCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                    var delay = Task.Delay(timeout, delayCts.Token);
                    await Task.WhenAny(pending.Wait, delay).ConfigureAwait(false);
                    delayCts.Cancel();
                    ct.ThrowIfCancellationRequested();

                    if (pending.Final is { } final)
                    {
                        Release(session, lane);
                        return new ExchangeResult(final, false, null);
                    }

                    if (pending.SawNoSession)
                    {
                        Release(session, lane);
                        _handshake.DropPeer(peerId, "peer has no matching session");
                        if (++heals > MaxHeals) return new ExchangeResult(null, false, "peer keeps losing the session");
                        continue;
                    }

                    // Timed out.
                    Retire(session, lane);
                    if (++timeouts > retries) return new ExchangeResult(null, false, "timed out waiting for an answer");
                }
            }
            finally { _pending.TryRemove(requestId, out _); }
        }

        private static void Release(HandshakeSession s, int lane)
        {
            try { s.ReleaseLane(lane); } catch (ObjectDisposedException) { }
        }

        private void Retire(HandshakeSession s, int lane)
        {
            try
            {
                s.RetireLane(lane);
                if (s.IsExhausted) _handshake.DropSession(s, "every lane stopped answering");
            }
            catch (ObjectDisposedException) { }
        }

        private Task SendAsync(DataType type, string toId, string requestId, string sessionId, int lane, byte[]? payload, CancellationToken ct = default)
        {
            var msg = new DataMessage
            {
                Type = type,
                FromId = _identity.ClientId,
                ToId = toId,
                RequestId = requestId,
                SessionId = sessionId,
                Lane = lane,
                Payload = payload,
            };
            var packet = YuukoPacket.Ephemeral(type + ":" + requestId, DataWire.Encode(msg));
            return _transport.PublishAsync(_opts.DataTopic, packet, ct);
        }

        // ── Presence ─────────────────────────────────────────────────────────────

        private TimeSpan PresenceWindow =>
            _opts.PresenceTimeout > TimeSpan.Zero ? _opts.PresenceTimeout
            : _opts.HeartbeatInterval > TimeSpan.Zero ? _opts.HeartbeatInterval * 3
            : TimeSpan.FromSeconds(60);

        private void Touch(string peerId) => _lastSeen[peerId] = DateTimeOffset.UtcNow;

        private PeerInfo InfoOf(HandshakeSession s) => new(
            s.RemoteId, s.RemoteFingerprint, s.CreatedUtc,
            _lastSeen.TryGetValue(s.RemoteId, out var t) ? t : s.CreatedUtc,
            IsOnline(s.RemoteId));

        private void StartHeartbeat()
        {
            var cts = _heartbeatCts = new CancellationTokenSource();
            _ = Task.Run(async () =>
            {
                while (!cts.IsCancellationRequested)
                {
                    try { await Task.Delay(_opts.HeartbeatInterval, cts.Token).ConfigureAwait(false); }
                    catch (OperationCanceledException) { break; }

                    foreach (var peer in ConnectedPeers)
                        _ = PingQuietly(peer, cts.Token);
                }
            });
        }

        private async Task PingQuietly(string peer, CancellationToken ct)
        {
            try { await PingAsync(peer, ct).ConfigureAwait(false); } catch { }
        }

        // ── Housekeeping ─────────────────────────────────────────────────────────

        // Keep the handshake's trust list in step with the device directory. The directory is the
        // source of truth for anything it added; trust added by hand elsewhere is left alone.
        private void SyncTrustFromDirectory()
        {
            lock (_directoryLock)
            {
                var records = Devices.All();
                var present = new HashSet<string>(records.Select(r => r.ClientId), StringComparer.Ordinal);
                foreach (var r in records)
                {
                    _opts.Handshake.TrustDevice(r.ClientId, r.Fingerprint);
                    _directoryTrusted.Add(r.ClientId);
                }
                foreach (var gone in _directoryTrusted.Where(id => !present.Contains(id)).ToList())
                {
                    _opts.Handshake.UntrustDevice(gone);
                    _directoryTrusted.Remove(gone);
                }
            }
        }

        private void PurgeRecentIfLarge()
        {
            if (_recent.Count < 1024) return;
            var now = DateTimeOffset.UtcNow;
            foreach (var kv in _recent)
                if (kv.Value.ExpiresUtc < now) _recent.TryRemove(kv.Key, out _);
        }

        private static string Truncate(string s, int max) => s.Length <= max ? s : s[..max];

        private void ThrowIfDisposed()
        {
            if (Volatile.Read(ref _disposed) != 0)
                throw new ObjectDisposedException(nameof(EclipseBroker));
        }

        public void Dispose()
        {
            if (Interlocked.Exchange(ref _disposed, 1) != 0) return;

            Devices.Changed -= SyncTrustFromDirectory;
            try { _heartbeatCts?.Cancel(); } catch { }

            if (_dataSub is not null)
                _ = _transport.UnsubscribeAsync(_opts.DataTopic, _dataSub);

            _handshake.Dispose();
            _store.Clear();
            _handlers.Clear();
            _recent.Clear();
        }

        // ── Per-exchange state ───────────────────────────────────────────────────

        private sealed class Pending
        {
            public readonly string PeerId;
            public readonly DataType ReplyType;
            public readonly string ReplyMethod;

            private TaskCompletionSource<bool> _signal = NewSignal();
            private readonly object _lock = new();
            private byte[]? _final;

            public Pending(string peerId, DataType replyType, string replyMethod)
            {
                PeerId = peerId; ReplyType = replyType; ReplyMethod = replyMethod;
            }

            public volatile bool SawNoSession;
            public byte[]? Final { get { lock (_lock) return _final; } }
            public Task Wait => Volatile.Read(ref _signal).Task;

            public void SetFinal(byte[] plain) { lock (_lock) _final ??= plain; }
            public void Signal() => Volatile.Read(ref _signal).TrySetResult(true);
            public void Reset() { SawNoSession = false; Interlocked.Exchange(ref _signal, NewSignal()); }

            private static TaskCompletionSource<bool> NewSignal() => new(TaskCreationOptions.RunContinuationsAsynchronously);
        }

        private sealed class RecentCommand
        {
            public readonly DateTimeOffset ExpiresUtc;
            public volatile byte[]? AckPlain;
            public RecentCommand(DateTimeOffset expires) => ExpiresUtc = expires;
        }

        // ── Wire types ─────────────────────────────────────────────────────────────

        // The numbers are part of the wire format: do not renumber.
        private enum DataType { Req = 0, Resp = 1, Cmd = 2, Ack = 3, NoSession = 4, Close = 5 }

        private sealed class DataMessage
        {
            public DataType Type { get; set; }
            public string FromId { get; set; } = "";
            public string ToId { get; set; } = "";
            public string RequestId { get; set; } = "";
            public string? SessionId { get; set; }
            public int Lane { get; set; }
            public byte[]? Payload { get; set; } // AeadChannel-encrypted envelope bytes
        }

        private sealed class CommandEnvelope
        {
            public string Name { get; set; } = "";
            public byte[] Data { get; set; } = Array.Empty<byte>();
        }

        // A broadcast on its way through the group. Origin + Id identify it for good; Ttl counts down per hand-over.
        private sealed class RelayEnvelope
        {
            public string Origin { get; set; } = "";
            public string Id { get; set; } = "";
            public int Ttl { get; set; }          // NOT signed: a relay may lower it (shorter reach) but never forge the rest
            public string Name { get; set; } = "";
            public byte[] Data { get; set; } = Array.Empty<byte>();
            public long SignedAtMs { get; set; }
            public PublicKeys? Keys { get; set; } // the origin's public keys; must hash to a fingerprint we trust
            public byte[]? Signature { get; set; }
        }

        private sealed class AckEnvelope
        {
            public int Status { get; set; }
            public string? Message { get; set; }
            public byte[] Result { get; set; } = Array.Empty<byte>();
        }

        private static class DataWire
        {
            private static readonly JsonSerializerOptions Json = new()
            {
                DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
                PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
            };

            public static byte[] Encode(DataMessage m) => JsonSerializer.SerializeToUtf8Bytes(m, Json);

            public static DataMessage? Decode(byte[] data)
            {
                try { return JsonSerializer.Deserialize<DataMessage>(data, Json); }
                catch { return null; }
            }

            public static byte[] EncodePackets(IReadOnlyList<YuukoPacket> packets) =>
                JsonSerializer.SerializeToUtf8Bytes(packets, Json);

            public static IReadOnlyList<YuukoPacket> DecodePackets(byte[] data) =>
                JsonSerializer.Deserialize<List<YuukoPacket>>(data, Json) ?? new List<YuukoPacket>();

            public static byte[] EncodeCommand(string name, byte[] data) =>
                JsonSerializer.SerializeToUtf8Bytes(new CommandEnvelope { Name = name, Data = data }, Json);

            public static CommandEnvelope? DecodeCommand(byte[] data)
            {
                try { return JsonSerializer.Deserialize<CommandEnvelope>(data, Json); }
                catch { return null; }
            }

            public static byte[] EncodeRelay(RelayEnvelope e) => JsonSerializer.SerializeToUtf8Bytes(e, Json);

            public static RelayEnvelope? DecodeRelay(byte[] data)
            {
                try { return JsonSerializer.Deserialize<RelayEnvelope>(data, Json); }
                catch { return null; }
            }

            public static byte[] EncodeAck(CommandResult r) =>
                JsonSerializer.SerializeToUtf8Bytes(new AckEnvelope
                {
                    Status = (int)r.Status,
                    Message = r.Message is { Length: > 500 } m ? m[..500] : r.Message,
                    Result = r.Data,
                }, Json);

            public static CommandAck? DecodeAck(byte[] data)
            {
                try
                {
                    var a = JsonSerializer.Deserialize<AckEnvelope>(data, Json);
                    if (a is null) return null;
                    // Only statuses the other device is allowed to produce; anything else is an error.
                    var status = a.Status is >= 0 and < 100 && Enum.IsDefined(typeof(AckStatus), a.Status)
                        ? (AckStatus)a.Status : AckStatus.Error;
                    return new CommandAck(status, a.Result ?? Array.Empty<byte>(), a.Message, TimeSpan.Zero);
                }
                catch { return null; }
            }
        }
    }
}
