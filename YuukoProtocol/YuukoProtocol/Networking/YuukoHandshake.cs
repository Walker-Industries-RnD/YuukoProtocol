
// Challenge-response handshake that establishes a per-peer encrypted session over a
// single Zenoh "handshake topic". Reuses the Eclipse DLL crypto directly:
//   - Kyber-1024 KEM (Pariah EasyPQC.Keys)      -> proves the REQUESTER's identity + yields a shared secret
//   - Dilithium5 (Pariah EasyPQC.Signatures)    -> proves the PROVIDER's identity (signed transcript)
//   - Security.PrepareKeys (Eclipse, HKDF-SHA256) -> derives directional session keys
//   - Security.AeadChannel  (Eclipse, AES-256-GCM) -> the per-peer, sequenced channel
//
// Flow (provider = data owner "Eclipse role", requester = app wanting data):
//   1. Requester -> HELLO      { kyberPub, sigPub, throw-away kyberPub, nonceC }
//   2. Provider runs an admission check (banned list, allowlist/pinned key, pending cap)
//   3. Provider -> CHALLENGE   { two KEM ciphertexts (long-term key + throw-away key), nonceS, sessionId,
//                                enc(random challenge), its own public keys, signature over the whole exchange }
//                                Session keys = HKDF(secret from long-term key + secret from throw-away key,
//                                salted with the hash of the whole exchange), so a recording of this handshake
//                                cannot be opened later even with every long-term key in hand.
//   4. Requester checks the provider's signature (and pin, if it has one), decapsulates, derives
//      the same keys, decrypts the challenge and echoes it back encrypted -> RESPONSE { enc(challenge) }
//   5. On any failure the provider erases the pending handshake and -> REJECT
//   6. On success the provider sends ACCEPT (encrypted, so it cannot be forged) and both sides
//      hold a HandshakeSession and can exchange data encrypted
//
// v3 of this (Eclipse-secured Zenoh transport), i'm never touching this again LOL it's secure enough

using System;
using System.Buffers.Binary;
using System.Collections;
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
using Walker.Crypto;
using WISecureData;

namespace YuukoProtocol
{
    // ── Identity ───────────────────────────────────────────────────────────────

    /// <summary>The public halves of a device identity: what other devices pin and verify against.</summary>
    public sealed record PublicKeys(Dictionary<string, byte[]> Kyber, Dictionary<string, byte[]> Signing);

    /// <summary>
    /// A peer's stable identity: a human-readable id plus two keypairs. A Kyber-1024 keypair
    /// (others encapsulate to it; holding the private half is what proves a REQUESTER is who it
    /// says) and a Dilithium5 signing keypair (what proves a PROVIDER is who it says).
    /// </summary>
    public sealed class YuukoIdentity
    {
        public string ClientId { get; }
        internal IReadOnlyDictionary<string, byte[]> KyberPublic { get; }
        internal IReadOnlyDictionary<string, byte[]> KyberPrivate { get; }
        internal IReadOnlyDictionary<string, byte[]> SigningPublic { get; }
        internal IReadOnlyDictionary<string, byte[]> SigningPrivate { get; }

        /// <summary>
        /// SHA-256 over both public keys (lowercase hex, 64 chars). Pin THIS when you trust a
        /// device - not the ClientId, which anyone can claim.
        /// </summary>
        public string Fingerprint { get; }

        private YuukoIdentity(string clientId,
            Dictionary<string, byte[]> kyberPub, Dictionary<string, byte[]> kyberPriv,
            Dictionary<string, byte[]> sigPub, Dictionary<string, byte[]> sigPriv)
        {
            ClientId = clientId;
            KyberPublic = kyberPub;
            KyberPrivate = kyberPriv;
            SigningPublic = sigPub;
            SigningPrivate = sigPriv;
            Fingerprint = FingerprintOf(new PublicKeys(kyberPub, sigPub));
        }

        private const int MaxKeyPartBytes = 8192;

        /// <summary>Fingerprint of a device's public keys, as other devices compute it.</summary>
        public static string FingerprintOf(PublicKeys keys)
        {
            if (keys is null) throw new ArgumentNullException(nameof(keys));

            byte[][] parts =
            {
                Need(keys.Kyber, "t"), Need(keys.Kyber, "rho"),
                Need(keys.Signing, "rho"), Need(keys.Signing, "t1"),
            };

            using var h = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
            h.AppendData(Encoding.ASCII.GetBytes("yuuko-id-v2"));
            foreach (var part in parts)
            {
                Span<byte> len = stackalloc byte[4];
                BinaryPrimitives.WriteInt32BigEndian(len, part.Length);
                h.AppendData(len);
                h.AppendData(part);
            }
            return Convert.ToHexString(h.GetHashAndReset()).ToLowerInvariant();

            static byte[] Need(IReadOnlyDictionary<string, byte[]>? d, string key) =>
                d is not null && d.TryGetValue(key, out var v) && v is { Length: > 0 and <= MaxKeyPartBytes }
                    ? v
                    : throw new ArgumentException($"Not a valid public key (missing or oversized '{key}').");
        }

        /// <summary>A hash of one Kyber public key, used to bind a handshake's throw-away key into the signed transcript.</summary>
        internal static byte[] KyberPublicDigest(IReadOnlyDictionary<string, byte[]> kyberPublic)
        {
            byte[] t = Part(kyberPublic, "t"), rho = Part(kyberPublic, "rho");
            using var h = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
            h.AppendData(Encoding.ASCII.GetBytes("yuuko-eph-v1"));
            foreach (var part in new[] { t, rho })
            {
                Span<byte> len = stackalloc byte[4];
                BinaryPrimitives.WriteInt32BigEndian(len, part.Length);
                h.AppendData(len);
                h.AppendData(part);
            }
            return h.GetHashAndReset();

            static byte[] Part(IReadOnlyDictionary<string, byte[]>? d, string key) =>
                d is not null && d.TryGetValue(key, out var v) && v is { Length: > 0 and <= MaxKeyPartBytes }
                    ? v
                    : throw new ArgumentException($"Not a valid public key (missing or oversized '{key}').");
        }

        // The Kyber key generator fails ("Key Initialization Failed") when two run at once in the same process, and several handshakes start at once
        // when strangers call a device together (Nearby). So every Kyber call takes turns.
        private static readonly object KeyGate = new();
        internal static T OneAtATime<T>(Func<T> Make) { lock (KeyGate) return Make(); }

        /// <summary>Generates a fresh identity (Kyber-1024 + Dilithium5 keypairs) for <paramref name="clientId"/>.</summary>
        public static YuukoIdentity Create(string clientId)
        {
            if (string.IsNullOrWhiteSpace(clientId))
                throw new ArgumentException("clientId must be non-empty.", nameof(clientId));

            var (kPub, kPriv) = OneAtATime(() => EasyPQC.Keys.Initiate());
            var (sPub, sPriv) = EasyPQC.Signatures.CreateKeys().GetAwaiter().GetResult();
            return new YuukoIdentity(clientId, kPub, kPriv, sPub, sPriv);
        }

        /// <summary>The Kyber public key as a plain dictionary, safe to hand to other peers.</summary>
        public Dictionary<string, byte[]> ExportPublicKey() =>
            new(KyberPublic as IDictionary<string, byte[]> ?? new Dictionary<string, byte[]>(KyberPublic));

        /// <summary>Both public keys, safe to hand to other peers.</summary>
        public PublicKeys ExportPublicKeys() => new(
            new Dictionary<string, byte[]>(KyberPublic),
            new Dictionary<string, byte[]>(SigningPublic));

        // ── Signing (provider authentication) ──────────────────────────────────

        // Pariah signs a string, so both sides sign/verify the base64 text of the message bytes.
        internal byte[] Sign(byte[] message) =>
            EasyPQC.Signatures.CreateSignature(
                new Dictionary<string, byte[]>(SigningPrivate), Convert.ToBase64String(message))
                .GetAwaiter().GetResult();

        internal static bool VerifySignature(IReadOnlyDictionary<string, byte[]> signingPublic, byte[] message, byte[] signature)
        {
            if (signingPublic is null || signature is null || signature.Length == 0 || signature.Length > 16384) return false;
            try
            {
                byte[] input = Encoding.UTF8.GetBytes(Convert.ToBase64String(message));
                return EasyPQC.Signatures.VerifySignature(
                    new Dictionary<string, byte[]>(signingPublic), signature, input)
                    .GetAwaiter().GetResult();
            }
            catch { return false; }
        }

        // ── Persistence ────────────────────────────────────────────────────────
        // A new identity on every launch means every pinned fingerprint breaks on restart,
        // so identities must be saved. The file holds the PRIVATE keys: anyone who can read it
        // can impersonate this device. Keep it somewhere only this user can read (the file is
        // created 0600 on Unix; on Windows it inherits the folder's ACL) or encrypt it yourself.

        private sealed class IdentityFile
        {
            public int Version { get; set; } = 2;
            public string ClientId { get; set; } = "";
            public Dictionary<string, byte[]> KyberPublic { get; set; } = new();
            public Dictionary<string, byte[]> KyberPrivate { get; set; } = new();
            public Dictionary<string, byte[]> SigningPublic { get; set; } = new();
            public Dictionary<string, byte[]> SigningPrivate { get; set; } = new();
        }

        /// <summary>SECRET: serializes the identity including its private keys.</summary>
        public byte[] Export() => JsonSerializer.SerializeToUtf8Bytes(new IdentityFile
        {
            ClientId = ClientId,
            KyberPublic = new Dictionary<string, byte[]>(KyberPublic),
            KyberPrivate = new Dictionary<string, byte[]>(KyberPrivate),
            SigningPublic = new Dictionary<string, byte[]>(SigningPublic),
            SigningPrivate = new Dictionary<string, byte[]>(SigningPrivate),
        });

        private const string EncryptedPrefix = "yuuko-id-enc-v1:";
        private const int MinPasswordLength = 8;

        /// <summary>True if <paramref name="data"/> is a password-protected identity file.</summary>
        public static bool IsEncryptedIdentity(byte[] data) =>
            data.Length > EncryptedPrefix.Length &&
            string.Equals(Encoding.ASCII.GetString(data, 0, EncryptedPrefix.Length), EncryptedPrefix, StringComparison.Ordinal);

        /// <summary>
        /// Like <see cref="Export"/> but protected with a password: Pariah's SimpleAESEncryption (a key stretched
        /// from the password with Argon2id, then AES-256-GCM). The result is safe to leave on disk; without the
        /// password it is useless, and any change to it is detected.
        /// </summary>
        public byte[] ExportEncrypted(string password)
        {
            if (password is null || password.Length < MinPasswordLength)
                throw new ArgumentException($"An identity password must be at least {MinPasswordLength} characters.", nameof(password));

            byte[] plain = Export();
            var pw = new SecureData(Encoding.UTF8.GetBytes(password));
            try
            {
                var sealedText = SimpleAESEncryption.Encrypt(Encoding.UTF8.GetString(plain), pw);
                return Encoding.ASCII.GetBytes(EncryptedPrefix + sealedText.ToString());
            }
            finally
            {
                pw.Dispose();
                CryptographicOperations.ZeroMemory(plain);
            }
        }

        /// <summary>
        /// Restores an identity from <see cref="Export"/> or <see cref="ExportEncrypted"/> output, verifying both
        /// keypairs still match. A password is required exactly when the data is encrypted.
        /// </summary>
        public static YuukoIdentity Import(byte[] data, string? password = null)
        {
            if (IsEncryptedIdentity(data))
            {
                if (password is null)
                    throw new FormatException("This identity file is encrypted. Supply its password.");

                string text = Encoding.ASCII.GetString(data, EncryptedPrefix.Length, data.Length - EncryptedPrefix.Length).Trim();
                var pw = new SecureData(Encoding.UTF8.GetBytes(password));
                try
                {
                    var parts = SimpleAESEncryption.AESEncryptedText.FromString(text);
                    data = Encoding.UTF8.GetBytes(SimpleAESEncryption.Decrypt(parts.EncryptedText, parts.IV, parts.Salt, pw));
                }
                catch (Exception)
                {
                    // AES-GCM refuses to decrypt with the wrong password or a modified file; both look the same on purpose.
                    throw new FormatException("Wrong password, or the identity file is damaged.");
                }
                finally { pw.Dispose(); }
            }

            IdentityFile f;
            try { f = JsonSerializer.Deserialize<IdentityFile>(data) ?? throw new FormatException(); }
            catch (Exception e) when (e is JsonException or FormatException)
            { throw new FormatException("Not a Yuuko identity file.", e); }

            if (f.Version == 1)
                throw new FormatException(
                    "This identity file is from an older version (1) that had no signing key. " +
                    "Create a new identity and re-pin its (new) fingerprint on the devices that trust it.");
            if (f.Version != 2) throw new FormatException($"Unsupported identity file version {f.Version}.");
            if (string.IsNullOrWhiteSpace(f.ClientId)) throw new FormatException("Identity file has no ClientId.");

            RequireParts(f.KyberPrivate, "Kyber private key", "s", "t", "rho", "hpk", "nonce");
            RequireParts(f.SigningPrivate, "signing private key", "rho", "k", "tr", "s1", "s2", "t0", "t1");

            var id = new YuukoIdentity(f.ClientId, f.KyberPublic, f.KyberPrivate, f.SigningPublic, f.SigningPrivate);

            // Prove each pair belongs together before trusting the file.
            var encap = OneAtATime(() => EasyPQC.Keys.CreateSecret(f.KyberPublic));
            var back = OneAtATime(() => EasyPQC.Keys.CreateSecretTwo(f.KyberPrivate, encap.text));
            if (!CryptographicOperations.FixedTimeEquals(encap.key, back))
                throw new FormatException("Identity file is corrupt: Kyber public and private keys do not match.");

            byte[] probe = RandomNumberGenerator.GetBytes(32);
            if (!VerifySignature(id.SigningPublic, probe, id.Sign(probe)))
                throw new FormatException("Identity file is corrupt: signing public and private keys do not match.");

            return id;

            static void RequireParts(Dictionary<string, byte[]> d, string what, params string[] keys)
            {
                foreach (var k in keys)
                    if (!d.TryGetValue(k, out var v) || v is null || v.Length == 0)
                        throw new FormatException($"Identity file is missing part '{k}' of the {what}.");
            }
        }

        /// <summary>
        /// Writes the identity atomically. With a <paramref name="password"/> the file is encrypted (see
        /// <see cref="ExportEncrypted"/>); without one it holds the private keys in the clear (see the note above).
        /// </summary>
        public void Save(string path, string? password = null)
        {
            var full = Path.GetFullPath(path);
            Directory.CreateDirectory(Path.GetDirectoryName(full)!);
            var tmp = full + ".tmp";

            var opts = new FileStreamOptions { Mode = FileMode.Create, Access = FileAccess.Write, Share = FileShare.None };
            if (!OperatingSystem.IsWindows())
                opts.UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite;
            byte[] content = password is null ? Export() : ExportEncrypted(password);
            try
            {
                using var fs = new FileStream(tmp, opts);
                fs.Write(content);
            }
            finally { CryptographicOperations.ZeroMemory(content); }

            File.Move(tmp, full, overwrite: true);
        }

        /// <summary>
        /// Loads the identity at <paramref name="path"/>, or creates and saves a new one if the file does not exist.
        /// With a <paramref name="password"/> new files are written encrypted, and an existing plaintext file is
        /// encrypted in place the first time it is loaded this way.
        /// </summary>
        public static YuukoIdentity LoadOrCreate(string path, string clientId, string? password = null)
        {
            if (File.Exists(path))
            {
                byte[] bytes = File.ReadAllBytes(path);
                bool wasEncrypted = IsEncryptedIdentity(bytes);
                var existing = Import(bytes, password);
                if (!string.Equals(existing.ClientId, clientId, StringComparison.Ordinal))
                    throw new InvalidOperationException(
                        $"'{path}' holds identity '{existing.ClientId}', not '{clientId}'. Refusing to silently switch identities.");
                if (password is not null && !wasEncrypted) existing.Save(path, password);   // upgrade in place
                return existing;
            }
            var created = Create(clientId);
            created.Save(path, password);
            return created;
        }
    }

    // ── Options ────────────────────────────────────────────────────────────────

    /// <summary>A small thread-safe set of strings (ordinal comparison). Safe to change while handshakes are running.</summary>
    public sealed class StringSet : IEnumerable<string>
    {
        private readonly ConcurrentDictionary<string, byte> _items = new(StringComparer.Ordinal);
        public bool Add(string value) => _items.TryAdd(value, 0);
        public bool Remove(string value) => _items.TryRemove(value, out _);
        public bool Contains(string value) => value is not null && _items.ContainsKey(value);
        public void Clear() => _items.Clear();
        public int Count => _items.Count;
        public IEnumerator<string> GetEnumerator() => _items.Keys.GetEnumerator();
        IEnumerator IEnumerable.GetEnumerator() => GetEnumerator();
    }

    public sealed class HandshakeOptions
    {
        /// <summary>Optional pre-shared key mixed into the HKDF salt. Empty = KEM-only trust.</summary>
        public byte[] PreSharedKey { get; set; } = Array.Empty<byte>();

        /// <summary>Client ids refused at admission (step 2). Replaceable with a richer policy later.</summary>
        public StringSet BannedClients { get; } = new();

        /// <summary>Shortest PreSharedKey accepted when <see cref="RequirePreSharedKey"/> is on.</summary>
        public const int MinPreSharedKeyBytes = 16;

        /// <summary>
        /// When true, creating a YuukoHandshake throws unless <see cref="PreSharedKey"/> is at least
        /// <see cref="MinPreSharedKeyBytes"/> long. A peer without the key cannot complete a handshake.
        /// One key is shared by every device, so it gates the mesh; it does not identify a device.
        /// Use <see cref="TrustDevice"/> for that.
        /// </summary>
        public bool RequirePreSharedKey { get; set; }

        /// <summary>
        /// Allowlist mode. When true, this device only talks to devices registered with
        /// <see cref="TrustDevice"/>, and only with the exact keys that were pinned - in BOTH directions:
        /// it refuses unknown or wrong-key devices that connect to it, and it refuses to open a session
        /// with a provider whose signature does not match the pinned fingerprint.
        /// </summary>
        public bool RequireKnownDevices { get; set; }

        /// <summary>ClientId -> pinned key fingerprint (see <see cref="YuukoIdentity.Fingerprint"/>).</summary>
        public ConcurrentDictionary<string, string> TrustedDevices { get; } = new(StringComparer.Ordinal);

        /// <summary>
        /// Pins <paramref name="clientId"/> to <paramref name="fingerprint"/> and turns allowlist mode on.
        /// Removing a device later (<see cref="UntrustDevice"/>) stops new handshakes only; it does not
        /// end a session that already exists (use EclipseBroker.KickAsync for that).
        /// </summary>
        public void TrustDevice(string clientId, string fingerprint)
        {
            if (string.IsNullOrWhiteSpace(clientId))
                throw new ArgumentException("clientId must be non-empty.", nameof(clientId));
            var fp = (fingerprint ?? "").Trim().ToLowerInvariant();
            if (fp.Length != 64 || !fp.All(Uri.IsHexDigit))
                throw new ArgumentException("fingerprint must be 64 hex characters (YuukoIdentity.Fingerprint).", nameof(fingerprint));
            TrustedDevices[clientId] = fp;
            RequireKnownDevices = true;
        }

        public bool UntrustDevice(string clientId) => TrustedDevices.TryRemove(clientId, out _);

        /// <summary>Handshakes allowed in flight at once on the provider side; further HELLOs are dropped.</summary>
        public int MaxPendingHandshakes { get; set; } = 128;

        /// <summary>Sessions kept per peer (older ones are retired); a peer that reconnects gets a new one.</summary>
        public int MaxSessionsPerPeer { get; set; } = 4;

        /// <summary>
        /// A session older than this is replaced by a fresh handshake (new keys) the next time it is used.
        /// Zero turns rotation off.
        /// </summary>
        public TimeSpan MaxSessionAge { get; set; } = TimeSpan.FromHours(1);

        /// <summary>
        /// How long an old session keeps working after it has been replaced (so messages already in flight are not
        /// lost). Once a session is older than <see cref="MaxSessionAge"/> plus this, it is refused outright, so no
        /// set of keys lives longer than that.
        /// </summary>
        public TimeSpan RotationGrace { get; set; } = TimeSpan.FromMinutes(1);

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

    /// <summary>Thrown when every lane of a session has been retired; the session must be replaced.</summary>
    internal sealed class SessionExhaustedException : InvalidOperationException
    {
        public SessionExhaustedException() : base("Every lane of this session has been retired.") { }
    }

    /// <summary>
    /// An established, mutually-derived encrypted session to one peer, multiplexed over a
    /// pool of independent lanes. Each lane is a pair of directional
    /// <see cref="Security.AeadChannel"/>s with its own sequence and a distinct nonce space
    /// (derived from the base session id), so lanes can be used concurrently and out of
    /// order relative to each other while each stays internally ordered.
    ///
    /// Both peers derive lane i identically from the shared key material + base session id,
    /// so one side's lane i send channel pairs with the other side's lane i receive channel.
    /// Each side borrows lanes for the exchanges IT starts (<see cref="AcquireLaneAsync"/>) and
    /// answers on the lane index a request arrived on. The two sides draw from separate index
    /// ranges, so a side's answer to a peer's request never shares a send channel with an
    /// exchange that side started itself.
    /// </summary>
    public sealed class HandshakeSession : IDisposable
    {
        /// <summary>Lane used only for the handshake messages themselves; never handed out.</summary>
        public const int HandshakeLane = 0;

        /// <summary>Lane used only for session control (close notices); never handed out.</summary>
        public const int ControlLane = -1;

        private const int ResponderLaneBase = 1 << 20;
        private const int MaxInboundLaneOffset = 4096;
        private const int MaxLiveLanes = 1024;

        /// <summary>Random id (hex) both peers know this session by; it travels in the clear and is not secret.</summary>
        public string Id { get; }
        public string LocalId { get; }
        public string RemoteId { get; }

        /// <summary>Fingerprint of the remote device's keys, as established by the handshake.</summary>
        public string RemoteFingerprint { get; }

        /// <summary>True on the side that started the handshake.</summary>
        public bool IsInitiator { get; }
        public DateTimeOffset CreatedUtc { get; } = DateTimeOffset.UtcNow;

        private readonly byte[] _sendKey;
        private readonly byte[] _recvKey;
        private readonly byte[] _baseSessionId;
        private readonly string _aadClientId;
        private readonly int _maxLanes;

        private readonly ConcurrentDictionary<int, Lane> _lanes = new();
        private readonly ConcurrentQueue<int> _freeLanes = new();
        private readonly SemaphoreSlim _laneAvailable;
        private readonly object _laneBuildLock = new();
        private int _retired;
        private int _disposed;

        internal HandshakeSession(string localId, string remoteId, string aadClientId,
            byte[] sendKey, byte[] recvKey, byte[] baseSessionId, int maxLanes,
            bool isInitiator, string remoteFingerprint)
        {
            LocalId = localId;
            RemoteId = remoteId;
            RemoteFingerprint = remoteFingerprint;
            IsInitiator = isInitiator;
            _aadClientId = aadClientId;
            _sendKey = sendKey;
            _recvKey = recvKey;
            _baseSessionId = baseSessionId;
            _maxLanes = Math.Clamp(maxLanes, 1, MaxInboundLaneOffset - 1);
            Id = Convert.ToHexString(baseSessionId).ToLowerInvariant();

            int laneBase = isInitiator ? 0 : ResponderLaneBase;
            for (int i = 1; i <= _maxLanes; i++) _freeLanes.Enqueue(laneBase + i);
            _laneAvailable = new SemaphoreSlim(_maxLanes);
        }

        /// <summary>How many parallel lanes this side can start exchanges on.</summary>
        public int MaxLanes => _maxLanes;

        /// <summary>True once every lane has been retired; the session can no longer start exchanges.</summary>
        public bool IsExhausted => Volatile.Read(ref _retired) >= _maxLanes;

        /// <summary>
        /// Borrows a free lane for one exchange, waiting if all lanes are busy. The caller MUST
        /// <see cref="ReleaseLane"/> it when the exchange completes, or <see cref="RetireLane"/> it
        /// if the exchange failed in a way that may have left the lane out of step with the peer.
        /// </summary>
        public async Task<int> AcquireLaneAsync(CancellationToken ct = default)
        {
            while (true)
            {
                await _laneAvailable.WaitAsync(ct).ConfigureAwait(false);
                if (IsExhausted)
                {
                    _laneAvailable.Release();   // let any other waiter see it too
                    throw new SessionExhaustedException();
                }
                if (_freeLanes.TryDequeue(out var lane)) return lane;
                _laneAvailable.Release();
                await Task.Yield();
            }
        }

        /// <summary>Returns a borrowed lane to the pool.</summary>
        public void ReleaseLane(int lane)
        {
            _freeLanes.Enqueue(lane);
            _laneAvailable.Release();
        }

        /// <summary>
        /// Takes a borrowed lane out of service for good. Lanes are strictly sequenced, so a lost
        /// message leaves a lane permanently out of step with the peer; the safe response is to
        /// stop using it. When every lane has been retired the session is exhausted.
        /// </summary>
        public void RetireLane(int lane)
        {
            if (Interlocked.Increment(ref _retired) >= _maxLanes)
                _laneAvailable.Release(_maxLanes);   // wake anyone waiting so they can see IsExhausted
        }

        /// <summary>Encrypts a payload on <paramref name="lane"/>; returns wire bytes.</summary>
        public byte[] EncryptOnLane(int lane, string method, byte[] plaintext) =>
            GetLane(lane).Encrypt(method, plaintext);

        /// <summary>Decrypts wire bytes received on <paramref name="lane"/>.</summary>
        public byte[] DecryptOnLane(int lane, byte[] wire) => DecryptOnLane(lane, wire, null);

        /// <summary>
        /// Decrypts wire bytes received on <paramref name="lane"/>, first checking that the sender
        /// labelled them <paramref name="expectedMethod"/>. The label is authenticated, and the check
        /// happens before decryption so a message of the wrong kind does not use up a sequence number.
        /// </summary>
        public byte[] DecryptOnLane(int lane, byte[] wire, string? expectedMethod)
        {
            ValidateInboundLane(lane);
            if (_lanes.TryGetValue(lane, out var existing))
                return existing.Decrypt(wire, expectedMethod);

            // First message on a lane we have not built yet. Build it off to the side and only keep
            // it if the message really authenticates, so forged messages cannot make us hoard lanes.
            lock (_laneBuildLock)
            {
                if (_lanes.TryGetValue(lane, out existing))
                    return existing.Decrypt(wire, expectedMethod);
                if (_lanes.Count >= MaxLiveLanes) throw new InvalidOperationException("Too many lanes.");

                var fresh = Lane.Build(_sendKey, _recvKey, _baseSessionId, lane, _aadClientId);
                try
                {
                    var plain = fresh.Decrypt(wire, expectedMethod);
                    _lanes[lane] = fresh;
                    return plain;
                }
                catch
                {
                    fresh.Dispose();
                    throw;
                }
            }
        }

        private static void ValidateInboundLane(int lane)
        {
            bool ok = lane == ControlLane
                   || (lane >= 0 && lane <= MaxInboundLaneOffset)
                   || (lane >= ResponderLaneBase && lane <= ResponderLaneBase + MaxInboundLaneOffset);
            if (!ok) throw new ArgumentOutOfRangeException(nameof(lane), "Not a valid lane index.");
        }

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

            public byte[] Decrypt(byte[] wire, string? expectedMethod)
            {
                var env = HandshakeWire.EnvelopeFromBytes(wire);
                if (expectedMethod is not null && !string.Equals(env.Method, expectedMethod, StringComparison.Ordinal))
                    throw new FormatException("Unexpected message kind for this lane.");
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

        // HELLO (the requester's public keys)
        public Dictionary<string, byte[]>? KyberPub { get; set; }
        public Dictionary<string, byte[]>? SigPub { get; set; }
        public Dictionary<string, byte[]>? EphKyberPub { get; set; }   // throw-away key for THIS handshake (forward secrecy)
        public byte[]? NonceC { get; set; }
        public bool Pairing { get; set; }   // "I hold a pairing code's token": keys for this handshake also depend on it. The token itself is NEVER sent.

        // CHALLENGE
        public byte[]? KemCipher { get; set; }
        public byte[]? KemCipherEph { get; set; }
        public byte[]? NonceS { get; set; }
        public byte[]? SessionId { get; set; }
        public byte[]? EncChallenge { get; set; }
        public Dictionary<string, byte[]>? ProviderKyberPub { get; set; }
        public Dictionary<string, byte[]>? ProviderSigPub { get; set; }
        public byte[]? Signature { get; set; }

        // RESPONSE
        public byte[]? EncResponse { get; set; }

        // ACCEPT (encrypted, so a bystander cannot forge it)
        public byte[]? EncAccept { get; set; }

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

        // Established sessions. A peer can hold several at once (it reconnected, or both sides
        // started a handshake together), so sessions are found by id and the newest one per peer
        // is the one we send on.
        private readonly ConcurrentDictionary<string, HandshakeSession> _byId = new(StringComparer.Ordinal);
        private readonly ConcurrentDictionary<string, HandshakeSession> _current = new(StringComparer.Ordinal);
        private readonly object _registryLock = new();

        // Single-flight: one in-progress handshake per provider, shared by concurrent callers.
        // Lazy guarantees the handshake body runs once even if GetOrAdd's factory races.
        private readonly ConcurrentDictionary<string, Lazy<Task<HandshakeSession?>>> _connecting = new();

        private Func<YuukoPacket, Task>? _subscription;
        private int _disposed;

        /// <summary>Raised when a handshake completes and a session becomes usable.</summary>
        public event Action<HandshakeSession>? SessionEstablished;

        /// <summary>Raised when a session is dropped, with a short human-readable reason.</summary>
        public event Action<HandshakeSession, string>? SessionEnded;

        public YuukoHandshake(IYuukoApi api, YuukoIdentity identity, HandshakeOptions? options = null)
        {
            _api = api ?? throw new ArgumentNullException(nameof(api));
            _id = identity ?? throw new ArgumentNullException(nameof(identity));
            _opts = options ?? new HandshakeOptions();

            if (_opts.RequirePreSharedKey && _opts.PreSharedKey.Length < HandshakeOptions.MinPreSharedKeyBytes)
                throw new InvalidOperationException(
                    $"RequirePreSharedKey is on but PreSharedKey is {_opts.PreSharedKey.Length} bytes; " +
                    $"at least {HandshakeOptions.MinPreSharedKeyBytes} are required.");
        }

        /// <summary>Newest established session for a peer, if one exists.</summary>
        public bool TryGetSession(string remoteId, out HandshakeSession session)
        {
            if (_current.TryGetValue(remoteId, out session!))
            {
                if (!IsPastHardExpiry(session)) return true;
                DropSession(session, "session expired");
            }
            session = null!;
            return false;
        }

        // Old enough that the next use should start a fresh handshake.
        private bool IsTooOld(HandshakeSession s) =>
            _opts.MaxSessionAge > TimeSpan.Zero && DateTimeOffset.UtcNow - s.CreatedUtc > _opts.MaxSessionAge;

        // Old enough that it is refused outright: no keys live longer than MaxSessionAge + RotationGrace.
        private bool IsPastHardExpiry(HandshakeSession s) =>
            _opts.MaxSessionAge > TimeSpan.Zero && DateTimeOffset.UtcNow - s.CreatedUtc > _opts.MaxSessionAge + _opts.RotationGrace;

        private readonly ConcurrentDictionary<string, long> _rekeyBackoffUntil = new(StringComparer.Ordinal);

        private void RetireLater(HandshakeSession old) =>
            _ = Task.Delay(_opts.RotationGrace).ContinueWith(_ =>
            {
                if (Volatile.Read(ref _disposed) == 0) DropSession(old, "rotated");
            }, TaskScheduler.Default);

        /// <summary>Finds a specific session by its id, but only if it belongs to <paramref name="remoteId"/>.</summary>
        public bool TryGetSessionById(string sessionId, string remoteId, out HandshakeSession session)
        {
            if (sessionId is not null && _byId.TryGetValue(sessionId, out session!) &&
                string.Equals(session.RemoteId, remoteId, StringComparison.Ordinal))
            {
                if (!IsPastHardExpiry(session)) return true;
                DropSession(session, "session expired");
            }
            session = null!;
            return false;
        }

        /// <summary>Every session we hold with <paramref name="remoteId"/>, newest first.</summary>
        public IReadOnlyList<HandshakeSession> GetSessionsOf(string remoteId) =>
            _byId.Values.Where(s => string.Equals(s.RemoteId, remoteId, StringComparison.Ordinal))
                        .OrderByDescending(s => s.CreatedUtc).ToList();

        /// <summary>The newest session of every connected peer.</summary>
        public IReadOnlyList<HandshakeSession> GetSessions() => _current.Values.ToList();

        /// <summary>Ids of every peer we hold a session with.</summary>
        public IReadOnlyCollection<string> ConnectedPeers => _current.Keys.ToList();

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

        // ── Pairing (letting ONE new device in) ──────────────────────────────────

        private readonly object _pairLock = new();
        private byte[]? _pairToken;
        private DateTimeOffset _pairExpires;
        private int _pairAttemptsLeft;

        /// <summary>Raised on the offering side when a newcomer has been paired: (its id, its key fingerprint). Its keys are already pinned.</summary>
        public event Action<string, string>? DevicePaired;

        /// <summary>Raised when a connection attempt is turned away before any key work: (who it claimed to be, why). Can be raised by anyone on the network, so a consumer must not trust or amplify it.</summary>
        public event Action<string, string>? HandshakeRefused;

        private void RaiseRefused(string who, string why)
        {
            try { HandshakeRefused?.Invoke(who, why); } catch { /* a subscriber's bug must not break the handshake */ }
        }

        /// <summary>
        /// Opens a pairing window and returns its one-time token (put it in a <see cref="PairingCode"/>). For
        /// <paramref name="lifetime"/>, or until one newcomer finishes, or <see cref="CancelPairing"/>, a device that
        /// holds the token may connect even if it is not on the allowlist. Its keys are pinned when it succeeds, and the
        /// token is spent. Only one window is open at a time; opening another replaces the first.
        /// <paramref name="maxAttempts"/> limits how many connection attempts may use the window, so it cannot be
        /// guessed at forever (and, as a cost, a nuisance can use the attempts up to close it: just offer a new code).
        /// </summary>
        public byte[] BeginPairing(TimeSpan lifetime, int maxAttempts = 10)
        {
            ThrowIfDisposed();
            if (lifetime <= TimeSpan.Zero || lifetime > TimeSpan.FromHours(1))
                throw new ArgumentOutOfRangeException(nameof(lifetime), "A pairing window lasts between a moment and one hour.");
            if (maxAttempts < 1) throw new ArgumentOutOfRangeException(nameof(maxAttempts));
            lock (_pairLock)
            {
                if (_pairToken is not null) CryptographicOperations.ZeroMemory(_pairToken);
                _pairToken = RandomNumberGenerator.GetBytes(16);
                _pairExpires = DateTimeOffset.UtcNow + lifetime;
                _pairAttemptsLeft = maxAttempts;
                return (byte[])_pairToken.Clone();
            }
        }

        /// <summary>Closes the pairing window now.</summary>
        public void CancelPairing()
        {
            lock (_pairLock)
            {
                if (_pairToken is not null) CryptographicOperations.ZeroMemory(_pairToken);
                _pairToken = null;
            }
        }

        /// <summary>True while a pairing window is open.</summary>
        public bool PairingOpen
        {
            get { lock (_pairLock) return _pairToken is not null && DateTimeOffset.UtcNow < _pairExpires && _pairAttemptsLeft > 0; }
        }

        private bool TryUsePairingAttempt(out byte[]? token)
        {
            lock (_pairLock)
            {
                token = null;
                if (_pairToken is null || DateTimeOffset.UtcNow >= _pairExpires || _pairAttemptsLeft <= 0) return false;
                _pairAttemptsLeft--;
                token = (byte[])_pairToken.Clone();
                return true;
            }
        }

        // True exactly once per window.
        private bool SpendPairingToken()
        {
            lock (_pairLock)
            {
                if (_pairToken is null || DateTimeOffset.UtcNow >= _pairExpires) return false;
                CryptographicOperations.ZeroMemory(_pairToken);
                _pairToken = null;
                return true;
            }
        }

        // The token joins the pre-shared key as extra secret material for ONE handshake. Both sides must hold it to agree on keys.
        internal static byte[] CombinePsk(byte[] psk, byte[] token)
        {
            using var h = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
            h.AppendData(Encoding.ASCII.GetBytes("yuuko-pair-v1"));
            Span<byte> len = stackalloc byte[4];
            BinaryPrimitives.WriteInt32BigEndian(len, psk.Length);
            h.AppendData(len);
            h.AppendData(psk);
            h.AppendData(token);
            return h.GetHashAndReset();
        }

        /// <summary>
        /// Joining side: pins <paramref name="providerId"/> to <paramref name="providerFingerprint"/> (from the pairing
        /// code, so the provider has to prove those keys), then connects using the one-time <paramref name="token"/>.
        /// Returns the session, or null (and leaves nothing pinned that was not before) if it did not work: wrong or
        /// expired code, a window that is closed, unreachable, or the other device is not who the code said.
        /// </summary>
        public async Task<HandshakeSession?> PairAsync(string providerId, string providerFingerprint, byte[] token, CancellationToken ct = default)
        {
            ThrowIfDisposed();
            if (token is null || token.Length != 16) throw new ArgumentException("token must be 16 bytes.", nameof(token));
            var fp = (providerFingerprint ?? "").Trim().ToLowerInvariant();

            bool hadPin = _opts.TrustedDevices.TryGetValue(providerId, out var previous);
            if (hadPin && !string.Equals(previous, fp, StringComparison.Ordinal))
                throw new InvalidOperationException($"'{providerId}' is already paired with different keys. Unpair it first.");
            bool wasStrict = _opts.RequireKnownDevices;

            await StartAsync(ct).ConfigureAwait(false);
            _opts.TrustDevice(providerId, fp);

            HandshakeSession? session = null;
            try { session = await DoHandshakeAsync(providerId, token).WaitAsync(ct).ConfigureAwait(false); }
            finally
            {
                if (session is null)
                {
                    if (!hadPin) _opts.TrustedDevices.TryRemove(providerId, out _);
                    _opts.RequireKnownDevices = wasStrict;
                }
            }
            return session;
        }

        /// <summary>
        /// Requester role: performs a handshake with <paramref name="providerId"/> and
        /// returns the established session, or null on rejection/timeout.
        /// </summary>
        public async Task<HandshakeSession?> RequestSessionAsync(string providerId, CancellationToken ct = default)
        {
            ThrowIfDisposed();

            HandshakeSession? stale = null;
            if (TryGetSession(providerId, out var existing))
            {
                if (!IsTooOld(existing)) return existing;

                // Old enough to replace. If a replacement failed recently (the peer is busy or gone), keep using
                // the old session for a while instead of making every call wait out a handshake timeout.
                if (Environment.TickCount64 < _rekeyBackoffUntil.GetValueOrDefault(providerId)) return existing;
                stale = existing;
            }

            // Make sure we are subscribed so we can hear CHALLENGE/ACCEPT/REJECT.
            await StartAsync(ct);

            // Collapse concurrent requests to the same provider onto one handshake, so a burst
            // of first-time requests doesn't launch (and overwrite) many parallel sessions.
            var lazy = _connecting.GetOrAdd(providerId,
                id => new Lazy<Task<HandshakeSession?>>(() => DoHandshakeAsync(id)));
            HandshakeSession? fresh;
            try
            {
                fresh = await lazy.Value.WaitAsync(ct).ConfigureAwait(false);
            }
            finally
            {
                _connecting.TryRemove(new KeyValuePair<string, Lazy<Task<HandshakeSession?>>>(providerId, lazy));
            }

            if (stale is not null)
            {
                if (fresh is null)
                {
                    _rekeyBackoffUntil[providerId] = Environment.TickCount64 + 30_000;
                    return TryGetSession(providerId, out var still) ? still : null;
                }
                RetireLater(stale);   // the old session keeps working for RotationGrace, then goes
            }
            return fresh;
        }

        /// <summary>Ends every session with <paramref name="remoteId"/>. Returns how many were dropped.</summary>
        public int DropPeer(string remoteId, string reason = "dropped")
        {
            List<HandshakeSession> dead;
            lock (_registryLock)
            {
                dead = _byId.Values.Where(s => string.Equals(s.RemoteId, remoteId, StringComparison.Ordinal)).ToList();
                foreach (var s in dead) _byId.TryRemove(s.Id, out _);
                _current.TryRemove(remoteId, out _);
            }
            foreach (var s in dead) EndSession(s, reason);
            return dead.Count;
        }

        /// <summary>Ends one session. If it was the newest for its peer, the next newest takes over.</summary>
        public bool DropSession(HandshakeSession session, string reason = "dropped")
        {
            bool removed;
            lock (_registryLock)
            {
                removed = _byId.TryRemove(session.Id, out _);
                if (_current.TryGetValue(session.RemoteId, out var cur) && ReferenceEquals(cur, session))
                {
                    _current.TryRemove(session.RemoteId, out _);
                    var next = _byId.Values
                        .Where(s => string.Equals(s.RemoteId, session.RemoteId, StringComparison.Ordinal))
                        .OrderByDescending(s => s.CreatedUtc).FirstOrDefault();
                    if (next is not null) _current[session.RemoteId] = next;
                }
            }
            if (removed) EndSession(session, reason);
            return removed;
        }

        private async Task<HandshakeSession?> DoHandshakeAsync(string providerId, byte[]? pairingToken = null)
        {
            var handshakeId = Guid.NewGuid().ToString("N");
            // A throw-away Kyber key for THIS handshake only. The provider mixes a secret encapsulated to it into
            // the session keys, and we destroy the private half as soon as we have used it - which is what makes
            // the session safe even if this device's long-term identity file is stolen later.
            var (ephPub, ephPriv) = YuukoIdentity.OneAtATime(() => EasyPQC.Keys.Initiate());
            var state = new RequesterState
            {
                ProviderId = providerId,
                PairingToken = pairingToken,
                NonceC = RandomNumberGenerator.GetBytes(16),
                EphPub = ephPub,
                EphPriv = ephPriv,
            };
            _inflight[handshakeId] = state;

            try
            {
                var keys = _id.ExportPublicKeys();
                await SendAsync(new HandshakeMessage
                {
                    Type = HandshakeType.Hello,
                    FromId = _id.ClientId,
                    ToId = providerId,
                    HandshakeId = handshakeId,
                    KyberPub = keys.Kyber,
                    SigPub = keys.Signing,
                    EphKyberPub = ephPub,
                    NonceC = state.NonceC,
                    Pairing = pairingToken is not null,
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
                WipeKey(state.EphPriv);   // whatever happened, the throw-away private key does not outlive the handshake
                state.EphPriv = null;
            }
        }

        // ── Message dispatch ────────────────────────────────────────────────────

        private async Task OnMessageAsync(YuukoPacket pkt)
        {
            if (Volatile.Read(ref _disposed) != 0) return;
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
            PurgeExpiredPending();

            // Step 2: admission check. Everything up to the Kyber call is cheap on purpose, so a
            // stranger on the mesh cannot make us burn CPU or memory just by sending HELLOs.
            if (string.IsNullOrWhiteSpace(hello.FromId) || hello.FromId.Length > 128) return;

            if (_opts.BannedClients.Contains(hello.FromId))
            {
                RaiseRefused(hello.FromId, "banned");
                await SendAsync(Reject(hello, "banned"));
                return;
            }

            // A pairing window lets ONE unknown device in, but only one that proves it holds the code's token (its keys
            // are derived from it, so without it the handshake cannot finish). Each HELLO that asks for pairing uses
            // up one of the window's attempts.
            byte[]? pairToken = null;
            bool pairing = hello.Pairing && TryUsePairingAttempt(out pairToken);

            // A name that is already paired to different keys cannot be re-paired over the top, code or no code.
            if (pairing && _opts.TrustedDevices.ContainsKey(hello.FromId) && !IsPinnedDevice(hello))
            {
                RaiseRefused(hello.FromId, "this name is already paired with different keys");
                await SendAsync(Reject(hello, "this name is already paired with different keys"));
                return;
            }

            if (_opts.RequireKnownDevices && !pairing && !IsPinnedDevice(hello))
            {
                RaiseRefused(hello.FromId, "unknown device");
                await SendAsync(Reject(hello, "unknown device"));
                return;
            }

            if (hello.KyberPub is null || hello.SigPub is null || hello.EphKyberPub is null || hello.NonceC is null) return;
            if (_pending.Count >= _opts.MaxPendingHandshakes) return; // shed load

            string requesterFp;
            byte[] ephDigest;
            try
            {
                requesterFp = YuukoIdentity.FingerprintOf(new PublicKeys(hello.KyberPub, hello.SigPub));
                ephDigest = YuukoIdentity.KyberPublicDigest(hello.EphKyberPub);
            }
            catch (ArgumentException) { return; }

            // Two Kyber encapsulations: one to the requester's long-term key (only that device can open it) and one
            // to the throw-away key it made for this handshake (it destroys that key after use, so stealing the
            // long-term key later does not reveal this session).
            var encap = YuukoIdentity.OneAtATime(() => EasyPQC.Keys.CreateSecret(hello.KyberPub));
            var encapEph = YuukoIdentity.OneAtATime(() => EasyPQC.Keys.CreateSecret(hello.EphKyberPub));
            byte[] kemCipher = encap.text;
            byte[] kemCipherEph = encapEph.text;

            byte[] nonceS = RandomNumberGenerator.GetBytes(16);
            byte[] sessionId = RandomNumberGenerator.GetBytes(8);

            // The whole exchange is hashed (and signed below), and the keys are derived FROM that hash. If anything
            // on the wire was altered, the two sides simply end up with different keys.
            byte[] transcript = TranscriptHash(hello.HandshakeId, _id.ClientId, hello.FromId,
                _id.Fingerprint, requesterFp, hello.NonceC, nonceS, kemCipher, ephDigest, kemCipherEph, sessionId);

            var (kC2S, kS2C) = DeriveSessionKeys(
                pairing ? CombinePsk(_opts.PreSharedKey, pairToken!) : _opts.PreSharedKey,
                hello.NonceC, transcript, encap.key, encapEph.key);
            CryptographicOperations.ZeroMemory(encap.key);
            CryptographicOperations.ZeroMemory(encapEph.key);

            // Provider sends on s2c, receives on c2s. AAD clientId is the requester's id on
            // both sides so both parties compute identical associated data. The handshake lane
            // carries the handshake itself and is never reused for data.
            var session = new HandshakeSession(_id.ClientId, hello.FromId, aadClientId: hello.FromId,
                sendKey: kS2C, recvKey: kC2S, baseSessionId: sessionId, _opts.MaxChannels,
                isInitiator: false, remoteFingerprint: requesterFp);

            byte[] challenge = RandomNumberGenerator.GetBytes(32);
            byte[] encChallenge = session.EncryptOnLane(HandshakeSession.HandshakeLane, "CHALLENGE", challenge);

            // Prove who we are: sign this exact exchange. The requester's fresh nonce, its key
            // fingerprint, the KEM ciphertext and the session id are all inside the signature, so
            // it cannot be replayed into a different handshake or spliced onto different keys.
            byte[] signature = _id.Sign(transcript);
            var ours = _id.ExportPublicKeys();

            _pending[hello.HandshakeId] = new PendingHandshake
            {
                RemoteId = hello.FromId,
                Challenge = challenge,
                Session = session,
                Paired = pairing,
                ExpiresAt = DateTimeOffset.UtcNow + _opts.Timeout,
            };

            await SendAsync(new HandshakeMessage
            {
                Type = HandshakeType.Challenge,
                FromId = _id.ClientId,
                ToId = hello.FromId,
                HandshakeId = hello.HandshakeId,
                KemCipher = kemCipher,
                KemCipherEph = kemCipherEph,
                NonceS = nonceS,
                SessionId = sessionId,
                EncChallenge = encChallenge,
                ProviderKyberPub = ours.Kyber,
                ProviderSigPub = ours.Signing,
                Signature = signature,
            });
        }

        private async Task OnResponseAsync(HandshakeMessage resp)
        {
            // Only the device we are handshaking with may answer; anyone else is ignored (and, in
            // particular, cannot make us throw the pending handshake away).
            if (!_pending.TryGetValue(resp.HandshakeId, out var peek)) return;
            if (!string.Equals(resp.FromId, peek.RemoteId, StringComparison.Ordinal)) return;
            if (!_pending.TryRemove(resp.HandshakeId, out var pending)) return;

            bool ok = false;
            try
            {
                if (resp.EncResponse is not null && !IsExpired(pending.ExpiresAt))
                {
                    byte[] echoed = pending.Session.DecryptOnLane(HandshakeSession.HandshakeLane, resp.EncResponse);
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

            // A pairing handshake is allowed to finish only once: the token is spent by the first success, so a second
            // device that somehow also had it cannot follow. Pin the newcomer's keys BEFORE the session goes live.
            if (pending.Paired)
            {
                string fp = pending.Session.RemoteFingerprint;
                if (!SpendPairingToken())
                {
                    pending.Session.Dispose();
                    await SendAsync(new HandshakeMessage
                    {
                        Type = HandshakeType.Reject, FromId = _id.ClientId, ToId = pending.RemoteId,
                        HandshakeId = resp.HandshakeId, Reason = "pairing closed",
                    });
                    return;
                }
                _opts.TrustDevice(pending.RemoteId, fp);
                try { DevicePaired?.Invoke(pending.RemoteId, fp); } catch { /* a subscriber's bug must not break the handshake */ }
            }

            // Step 6: promote to an established session.
            RegisterSession(pending.Session);

            await SendAsync(new HandshakeMessage
            {
                Type = HandshakeType.Accept,
                FromId = _id.ClientId,
                ToId = pending.RemoteId,
                HandshakeId = resp.HandshakeId,
                EncAccept = pending.Session.EncryptOnLane(
                    HandshakeSession.HandshakeLane, "ACCEPT", Encoding.UTF8.GetBytes(resp.HandshakeId)),
            });
        }

        // ── Requester role ────────────────────────────────────────────────────

        private async Task OnChallengeAsync(HandshakeMessage ch)
        {
            if (!_inflight.TryGetValue(ch.HandshakeId, out var state)) return;

            // Only the provider we addressed may answer.
            if (!string.Equals(ch.FromId, state.ProviderId, StringComparison.Ordinal)) return;
            if (state.Session is not null) return; // already accepted a challenge for this handshake

            if (ch.KemCipher is null || ch.KemCipherEph is null || ch.NonceS is null || ch.SessionId is null ||
                ch.EncChallenge is null || ch.ProviderKyberPub is null || ch.ProviderSigPub is null || ch.Signature is null)
                return;
            if (state.EphPub is null || state.EphPriv is null) return;   // our throw-away key is already gone

            try
            {
                // 1. Who answered? Check the provider's keys against our pin (if we have one) and
                //    verify its signature over this exact exchange BEFORE trusting anything else.
                string providerFp = YuukoIdentity.FingerprintOf(new PublicKeys(ch.ProviderKyberPub, ch.ProviderSigPub));

                if (_opts.RequireKnownDevices)
                {
                    if (!_opts.TrustedDevices.TryGetValue(ch.FromId, out var pinned) ||
                        !CryptographicOperations.FixedTimeEquals(
                            Encoding.ASCII.GetBytes(providerFp), Encoding.ASCII.GetBytes(pinned)))
                        throw new CryptographicException("Provider is not the device we pinned.");
                }

                byte[] transcript = TranscriptHash(ch.HandshakeId, ch.FromId, _id.ClientId,
                    providerFp, _id.Fingerprint, state.NonceC, ch.NonceS, ch.KemCipher,
                    YuukoIdentity.KyberPublicDigest(state.EphPub), ch.KemCipherEph, ch.SessionId);
                if (!YuukoIdentity.VerifySignature(ch.ProviderSigPub, transcript, ch.Signature))
                    throw new CryptographicException("Provider signature is invalid.");

                // 2. Open both KEM ciphertexts: one with our long-term key, one with the throw-away key made for this
                //    handshake. Then destroy the throw-away private key - from here on, nothing we keep can rebuild
                //    this session's keys from a recording.
                byte[] secretLong = YuukoIdentity.OneAtATime(() => EasyPQC.Keys.CreateSecretTwo(
                    new Dictionary<string, byte[]>(_id.KyberPrivate), ch.KemCipher));
                byte[] secretEph = YuukoIdentity.OneAtATime(() => EasyPQC.Keys.CreateSecretTwo(state.EphPriv, ch.KemCipherEph));
                WipeKey(state.EphPriv);
                state.EphPriv = null;

                var (kC2S, kS2C) = DeriveSessionKeys(
                    state.PairingToken is null ? _opts.PreSharedKey : CombinePsk(_opts.PreSharedKey, state.PairingToken),
                    state.NonceC, transcript, secretLong, secretEph);
                CryptographicOperations.ZeroMemory(secretLong);
                CryptographicOperations.ZeroMemory(secretEph);

                // Requester sends on c2s, receives on s2c. Same AAD clientId (our own id).
                var session = new HandshakeSession(_id.ClientId, ch.FromId, aadClientId: _id.ClientId,
                    sendKey: kC2S, recvKey: kS2C, baseSessionId: ch.SessionId, _opts.MaxChannels,
                    isInitiator: true, remoteFingerprint: providerFp);

                // Decrypt the challenge, then echo it back encrypted on the same lane.
                byte[] challenge = session.DecryptOnLane(HandshakeSession.HandshakeLane, ch.EncChallenge);
                byte[] encResponse = session.EncryptOnLane(HandshakeSession.HandshakeLane, "RESPONSE", challenge);

                lock (state)
                {
                    if (state.Session is not null) { session.Dispose(); return; } // a duplicate beat us here
                    state.Session = session;
                }

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
                // A bad challenge (wrong provider, bad signature, wrong PSK...) ends this attempt.
                // We only get here before a session is stored, so nothing needs disposing.
                state.Completion.TrySetResult(null);
            }
        }

        private void OnAccept(HandshakeMessage acc)
        {
            if (!_inflight.TryGetValue(acc.HandshakeId, out var state)) return;
            if (!string.Equals(acc.FromId, state.ProviderId, StringComparison.Ordinal)) return;

            var session = state.Session;
            if (session is null || acc.EncAccept is null) return;

            // The ACCEPT is encrypted with the session keys, so only the real provider can make one.
            try
            {
                byte[] plain = session.DecryptOnLane(HandshakeSession.HandshakeLane, acc.EncAccept, "ACCEPT");
                if (!CryptographicOperations.FixedTimeEquals(plain, Encoding.UTF8.GetBytes(acc.HandshakeId))) return;
            }
            catch { return; }

            RegisterSession(session);
            state.Completion.TrySetResult(session);
        }

        private void OnReject(HandshakeMessage rej)
        {
            if (!_inflight.TryGetValue(rej.HandshakeId, out var state)) return;
            if (!string.Equals(rej.FromId, state.ProviderId, StringComparison.Ordinal)) return;
            state.Session?.Dispose();
            state.Session = null;
            state.Completion.TrySetResult(null);
        }

        // ── Helpers ─────────────────────────────────────────────────────────────

        private void RegisterSession(HandshakeSession session)
        {
            List<HandshakeSession> evicted = new();
            lock (_registryLock)
            {
                _byId[session.Id] = session;
                _current[session.RemoteId] = session;

                // Keep a bounded number of sessions per peer; retire the oldest extras.
                var mine = _byId.Values
                    .Where(s => string.Equals(s.RemoteId, session.RemoteId, StringComparison.Ordinal))
                    .OrderBy(s => s.CreatedUtc).ToList();
                while (mine.Count > Math.Max(1, _opts.MaxSessionsPerPeer))
                {
                    var oldest = mine[0];
                    mine.RemoveAt(0);
                    if (ReferenceEquals(oldest, session)) continue;
                    _byId.TryRemove(oldest.Id, out _);
                    evicted.Add(oldest);
                }
            }

            foreach (var s in evicted) EndSession(s, "replaced by a newer session");
            foreach (var dead in _byId.Values.Where(IsPastHardExpiry).ToList()) DropSession(dead, "session expired");
            try { SessionEstablished?.Invoke(session); } catch { /* a subscriber's bug must not break the handshake */ }
        }

        private void EndSession(HandshakeSession session, string reason)
        {
            try { session.Dispose(); } catch { }
            try { SessionEnded?.Invoke(session, reason); } catch { }
        }

        private static bool IsExpired(DateTimeOffset at) => DateTimeOffset.UtcNow > at;

        // The signed summary of one handshake. Every field is length-prefixed so two different
        // sets of values can never hash to the same bytes.
        internal static byte[] TranscriptHash(string handshakeId, string providerId, string requesterId,
            string providerFingerprint, string requesterFingerprint,
            byte[] nonceC, byte[] nonceS, byte[] kemCipher, byte[] ephemeralKeyDigest, byte[] kemCipherEph, byte[] sessionId)
        {
            using var h = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
            Part(h, Encoding.ASCII.GetBytes("yuuko-hs-v3"));
            Part(h, Encoding.UTF8.GetBytes(handshakeId));
            Part(h, Encoding.UTF8.GetBytes(providerId));
            Part(h, Encoding.UTF8.GetBytes(requesterId));
            Part(h, Encoding.ASCII.GetBytes(providerFingerprint));
            Part(h, Encoding.ASCII.GetBytes(requesterFingerprint));
            Part(h, nonceC);
            Part(h, nonceS);
            Part(h, kemCipher);
            Part(h, ephemeralKeyDigest);
            Part(h, kemCipherEph);
            Part(h, sessionId);
            return h.GetHashAndReset();

            static void Part(IncrementalHash hash, byte[] bytes)
            {
                Span<byte> len = stackalloc byte[4];
                BinaryPrimitives.WriteInt32BigEndian(len, bytes.Length);
                hash.AppendData(len);
                hash.AppendData(bytes);
            }
        }

        // The session key schedule. Both sides call this with the same inputs:
        //   - the pre-shared key (if any) and the requester's nonce,
        //   - the TRANSCRIPT HASH (so the keys depend on every field of the exchange: any difference in what the
        //     two sides saw produces different keys, and the handshake fails),
        //   - the secret from the long-term key and the secret from the throw-away key. Without the second one the
        //     keys cannot be rebuilt, which is what gives forward secrecy.
        // Pass null for the throw-away secret only to model an attacker who does not have it (the tests do).
        internal static (byte[] c2s, byte[] s2c) DeriveSessionKeys(byte[] psk, byte[] nonceC, byte[] transcript,
            byte[] secretLongTerm, byte[]? secretEphemeral)
        {
            byte[] ikm = new byte[secretLongTerm.Length + (secretEphemeral?.Length ?? 0)];
            Buffer.BlockCopy(secretLongTerm, 0, ikm, 0, secretLongTerm.Length);
            if (secretEphemeral is not null)
                Buffer.BlockCopy(secretEphemeral, 0, ikm, secretLongTerm.Length, secretEphemeral.Length);
            try { return Security.PrepareKeys(psk, nonceC, transcript, ikm); }
            finally { CryptographicOperations.ZeroMemory(ikm); }
        }

        private static void WipeKey(Dictionary<string, byte[]>? key)
        {
            if (key is null) return;
            foreach (var part in key.Values) CryptographicOperations.ZeroMemory(part);
        }

        // True only if hello.FromId is pinned AND the keys it presented hash to the pinned fingerprint.
        private bool IsPinnedDevice(HandshakeMessage hello)
        {
            if (hello.KyberPub is null || hello.SigPub is null) return false;
            if (!_opts.TrustedDevices.TryGetValue(hello.FromId, out var pinned)) return false;

            string actual;
            try { actual = YuukoIdentity.FingerprintOf(new PublicKeys(hello.KyberPub, hello.SigPub)); }
            catch (ArgumentException) { return false; }

            return CryptographicOperations.FixedTimeEquals(
                Encoding.ASCII.GetBytes(actual), Encoding.ASCII.GetBytes(pinned));
        }

        // Handshakes that never finished would otherwise sit in _pending forever.
        private void PurgeExpiredPending()
        {
            foreach (var kv in _pending)
                if (IsExpired(kv.Value.ExpiresAt) && _pending.TryRemove(kv.Key, out var dead))
                    dead.Session.Dispose();
        }

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

            foreach (var s in _byId.Values) { try { s.Dispose(); } catch { } }
            foreach (var p in _pending.Values) { try { p.Session.Dispose(); } catch { } }
            _byId.Clear();
            _current.Clear();
            _pending.Clear();
        }

        // ── Per-role state ───────────────────────────────────────────────────────

        private sealed class PendingHandshake
        {
            public bool Paired;   // opened under a pairing token: success pins the requester, and uses up the token
            public string RemoteId = "";
            public byte[] Challenge = Array.Empty<byte>();
            public HandshakeSession Session = null!;
            public DateTimeOffset ExpiresAt;
        }

        private sealed class RequesterState
        {
            public string ProviderId = "";
            public byte[]? PairingToken;
            public byte[] NonceC = Array.Empty<byte>();
            public Dictionary<string, byte[]>? EphPub;
            public Dictionary<string, byte[]>? EphPriv;
            public HandshakeSession? Session;
            public readonly TaskCompletionSource<HandshakeSession?> Completion =
                new(TaskCreationOptions.RunContinuationsAsynchronously);
        }
    }
}
