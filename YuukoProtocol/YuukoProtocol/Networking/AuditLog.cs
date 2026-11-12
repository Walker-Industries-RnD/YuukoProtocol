// AuditLog.cs
// A small, append-only, tamper-evident audit log kept in one file.
//
//   using var audit = AuditLog.Open("audit.log", key);        // read + append. One writer at a time.
//   audit.Attach(node);                                        // records connects, kicks, refused devices, pairing, group changes...
//   audit.Append("report.opened", subject: "q3.pdf");          // or record your own events
//
//   using var viewer = AuditLog.OpenReadOnly("audit.log", key);   // can read and verify, can NOT write; works while the writer is running
//   var result = viewer.Verify();                                  // result.Ok, or the first bad entry and why
//
//   audit.Seal();                                              // finished: close it and mark the FILE read-only at the OS level
//
// Every entry holds the hash of the entry before it, so removing, editing, inserting or reordering an entry breaks the chain
// from that point on. WITHOUT a key that is the whole protection, and someone who can write the file can simply recompute every
// hash after their edit: it catches accidents and clumsy edits only. WITH a key (SecureData) each hash is an HMAC, which
// cannot be recomputed without the key, so an edit is detected even by someone who understands the format.
//
// Someone who holds the key can still write a convincing log, UNLESS the log is signed: Open(path, key, signer) signs every entry with the device's
// own private key (Dilithium5), and Verify(expectedHead, expectedSigner) then refuses a log that wasn't written by that device. The key only protects
// from edits, the signature protects from being forged by anyone who isn't the device.
//
// What a chain can NOT see by itself: entries cut off the END of the log (what remains is still a valid chain). AnchorTo(node) sends the newest head to
// the devices you are connected to after every entry (they keep it with an AuditWitness), and VerifyWithWitnessesAsync(node) asks them: a log with
// entries missing, or rewritten, doesn't match what they saw. Or keep a copy of <see cref="Head"/> yourself and pass it to Verify(expectedHead).
//
// Walker Industries R&D - YuukoProtocol

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.Json.Serialization;
using System.Threading;
using System.Threading.Tasks;
using WISecureData;

namespace YuukoProtocol
{
    //One line of the audit log.
    public sealed record AuditEntry(long Seq, DateTimeOffset TimeUtc, string Kind, string? Actor, string? Subject, string? Detail, string Prev, string Hash, string? By = null, string? Sig = null);

    //The newest entry of a log: keep a copy elsewhere to detect entries being cut off the end.
    public readonly record struct AuditHead(long Seq, string Hash);

    //The result of Verify.
    public sealed record AuditVerification(bool Ok, long Entries, long? BadSeq, string? Problem, AuditHead Head)
    {
        //How many other devices were asked by VerifyWithWitnessesAsync and had seen this log.
        public int Witnesses { get; init; }
    }

    public sealed class AuditLog : IDisposable
    {
        //The "previous hash" of the first entry.
        public static readonly string Genesis = new('0', 64);

        private const int MaxKind = 64, MaxActor = 256, MaxSubject = 256, MaxDetail = 1024;

        //The first entry of a signed log: it holds the public keys of the device that signs it.
        public const string SignerKind = "log.signer";
        private const int RefusedWindowSeconds = 60;

        private static readonly JsonSerializerOptions Json = new()
        {
            DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
            UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
        };

        private sealed class Line
        {
            [JsonPropertyName("seq")] public long Seq { get; set; }
            [JsonPropertyName("time")] public DateTimeOffset Time { get; set; }
            [JsonPropertyName("kind")] public string Kind { get; set; } = "";
            [JsonPropertyName("actor")] public string? Actor { get; set; }
            [JsonPropertyName("subject")] public string? Subject { get; set; }
            [JsonPropertyName("detail")] public string? Detail { get; set; }
            [JsonPropertyName("prev")] public string Prev { get; set; } = "";
            [JsonPropertyName("hash")] public string Hash { get; set; } = "";
            [JsonPropertyName("by")] public string? By { get; set; }
            [JsonPropertyName("sig")] public string? Sig { get; set; }
        }

        private readonly object _lock = new();
        private readonly byte[]? _macKey;
        private readonly YuukoIdentity? _signer;
        private FileStream? _writer;
        private long _lastSeq;
        private string _lastHash = Genesis;
        private int _disposed;

        //The full path of the log file.
        public string Path { get; }

        //True if this object can only read: Append throws.
        public bool IsReadOnly { get; private set; }

        //True if entries are HMAC'd with a key (edits are detected even by someone who knows the format).
        public bool IsKeyed => _macKey is not null;

        //How many appends failed (disk full, file removed...). A failure never throws out of Attach'd events.
        public int Failures => Volatile.Read(ref _failures);
        private int _failures;

        //Raised when recording an event from an attached node failed.
        public event Action<Exception>? AppendFailed;

        // Raised after every entry, with the new head (AnchorTo sends it on)
        private event Action<AuditHead>? Appended;

        private AuditLog(string path, SecureData? key, bool readOnly, YuukoIdentity? signer = null)
        {
            Path = System.IO.Path.GetFullPath(path);
            IsReadOnly = readOnly;
            _signer = signer;

            if (key is { } k)
            {
                byte[] raw = k.ConvertToBytes();
                try
                {
                    if (raw.Length == 0) throw new ArgumentException("The audit key is empty.", nameof(key));
                    _macKey = (byte[])raw.Clone();
                }
                finally { CryptographicOperations.ZeroMemory(raw); }
            }

            if (readOnly)
            {
                if (!File.Exists(Path)) throw new FileNotFoundException($"There is no audit log at '{Path}'.", Path);
                return;
            }

            Directory.CreateDirectory(System.IO.Path.GetDirectoryName(Path)!);

            // Carry on from the last entry, but only if that entry is intact: never append to a log that is already damaged.
            if (File.Exists(Path))
            {
                var tail = ReadTail();
                if (tail is not null) { _lastSeq = tail.Seq; _lastHash = tail.Hash; }
            }

            try { _writer = new FileStream(Path, FileMode.Append, FileAccess.Write, FileShare.Read); }
            catch (UnauthorizedAccessException e)
            {
                throw new UnauthorizedAccessException(
                    $"'{Path}' cannot be written. If it was sealed (see AuditLog.Seal) it is read-only on purpose: use OpenReadOnly, or Unseal it first.", e);
            }

            // A signed log starts with the signer's public keys, and only that device can carry on writing it
            if (_signer is not null)
            {
                var tail = _lastSeq == 0 ? null : ReadTail();
                if (tail is null) Append(SignerKind, detail: JsonSerializer.Serialize(_signer.ExportPublicKeys()));
                else if (tail.By != _signer.Fingerprint) throw new InvalidOperationException("This log is not signed by this device (or not signed at all). Start a new log.");
            }
        }

        //Opens (or creates) a log you can append to. Only one writer can have it open at a time; others can read it meanwhile.
        //Throws FormatException if the existing log ends in a damaged entry, rather than add to it.
        public static AuditLog Open(string path, SecureData? key = null, YuukoIdentity? signer = null) => new(path, key, readOnly: false, signer);

        //Opens an existing log for reading and verifying only. Append throws. Safe to use while a writer is running.
        public static AuditLog OpenReadOnly(string path, SecureData? key = null) => new(path, key, readOnly: true);

        //Writing

        //Adds an entry and returns it. kind is a short dotted name such as peer.kicked (letters, digits, '.', '_', '-').
        //The entry is on disk before this returns. Text longer than the limits is cut.
        public AuditEntry Append(string kind, string? subject = null, string? detail = null, string? actor = null)
        {
            ThrowIfDisposed();
            if (IsReadOnly || _writer is null) throw new InvalidOperationException("This audit log was opened read-only.");
            if (string.IsNullOrEmpty(kind) || kind.Length > MaxKind || !kind.All(c => char.IsAsciiLetterOrDigit(c) || c is '.' or '_' or '-'))
                throw new ArgumentException($"An audit kind is 1-{MaxKind} characters: letters, digits, '.', '_' or '-'.", nameof(kind));

            lock (_lock)
            {
                var time = DateTimeOffset.UtcNow;
                long seq = _lastSeq + 1;
                string? a = Cut(actor, MaxActor), s = Cut(subject, MaxSubject), d = kind == SignerKind ? detail : Cut(detail, MaxDetail);
                string? by = _signer?.Fingerprint;
                string hash = ComputeHash(seq, time.UtcTicks, kind, a, s, d, _lastHash, by);

                var line = new Line { Seq = seq, Time = time, Kind = kind, Actor = a, Subject = s, Detail = d, Prev = _lastHash, Hash = hash, By = by };
                if (_signer is not null) line.Sig = Convert.ToBase64String(_signer.Sign(Encoding.ASCII.GetBytes(hash)));
                byte[] bytes = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(line, Json) + "\n");
                _writer.Write(bytes, 0, bytes.Length);
                _writer.Flush(flushToDisk: true);

                _lastSeq = seq;
                _lastHash = hash;

                var entry = new AuditEntry(seq, time, kind, a, s, d, line.Prev, hash, by, line.Sig);
                try { Appended?.Invoke(new AuditHead(seq, hash)); } catch { /* telling others must never stop the log */ }
                return entry;
            }
        }

        private static string? Cut(string? text, int max) =>
            text is null ? null : text.Length <= max ? text : text[..(max - 1)] + "…";

        //Reading

        //The entries, oldest first, optionally filtered. last keeps only the newest N after filtering.
        //Throws FormatException naming the line if one cannot be read: run Verify for details.
        public IReadOnlyList<AuditEntry> Read(string? kind = null, string? subject = null, DateTimeOffset? since = null, int? last = null)
        {
            ThrowIfDisposed();
            var all = new List<AuditEntry>();
            long lineNo = 0;
            foreach (var raw in ReadLines())
            {
                lineNo++;
                if (raw.Length == 0) continue;
                var e = Parse(raw) ?? throw new FormatException($"Line {lineNo} of '{Path}' is damaged. Run Verify() to see what is wrong.");
                if (kind is not null && !string.Equals(e.Kind, kind, StringComparison.Ordinal)) continue;
                if (subject is not null && !string.Equals(e.Subject, subject, StringComparison.Ordinal)) continue;
                if (since is { } t && e.TimeUtc < t) continue;
                all.Add(e);
            }
            return last is { } n && n < all.Count ? all.Skip(all.Count - Math.Max(0, n)).ToList() : all;
        }

        //The newest entry (seq 0 and the genesis hash for an empty log).
        public AuditHead Head
        {
            get
            {
                ThrowIfDisposed();
                if (!IsReadOnly) { lock (_lock) return new AuditHead(_lastSeq, _lastHash); }
                var tail = ReadTail();
                return tail is null ? new AuditHead(0, Genesis) : new AuditHead(tail.Seq, tail.Hash);
            }
        }

        //Verifying

        //Checks every entry: numbering, the link to the one before, and its own hash (an HMAC when the log is keyed, so the wrong
        //key fails here at the first entry). Pass expectedHead (a copy of Head you kept
        //elsewhere) to also catch entries having been cut off the end.
        public AuditVerification Verify(AuditHead? expectedHead = null, string? expectedSigner = null)
        {
            ThrowIfDisposed();
            long count = 0, expectedSeq = 1;
            string prev = Genesis;
            long lineNo = 0;
            PublicKeys? signerKeys = null;

            AuditVerification Bad(long? seq, string problem) => new(false, count, seq, problem, new AuditHead(expectedSeq - 1, prev));

            if (!File.Exists(Path)) return Bad(null, "The log file is missing.");

            foreach (var raw in ReadLines(out bool endsWithNewline))
            {
                lineNo++;
                if (raw.Length == 0) return Bad(null, $"Line {lineNo} is empty (a blank line was inserted).");

                var e = Parse(raw);
                if (e is null) return Bad(null, $"Line {lineNo} is not a valid audit entry.");
                if (e.Seq != expectedSeq) return Bad(e.Seq, $"Entry {e.Seq} is where entry {expectedSeq} should be (an entry was removed, added or moved).");
                if (!string.Equals(e.Prev, prev, StringComparison.Ordinal)) return Bad(e.Seq, $"Entry {e.Seq} does not follow the entry before it (the chain is broken).");

                string expected = ComputeHash(e.Seq, e.TimeUtc.UtcTicks, e.Kind, e.Actor, e.Subject, e.Detail, e.Prev, e.By);
                if (!CryptographicOperations.FixedTimeEquals(Encoding.ASCII.GetBytes(expected), Encoding.ASCII.GetBytes(e.Hash)))
                    return Bad(e.Seq, IsKeyed
                        ? $"Entry {e.Seq} fails its check: it was changed, or the key is wrong."
                        : $"Entry {e.Seq} fails its check: it was changed.");

                // The signer's keys come from the log itself, and they only count if they are the ones the caller expects
                if (e.Kind == SignerKind && signerKeys is null && e.By is not null)
                {
                    try { signerKeys = JsonSerializer.Deserialize<PublicKeys>(e.Detail ?? ""); } catch (JsonException) { }
                    if (signerKeys is null || YuukoIdentity.FingerprintOf(signerKeys) != e.By) return Bad(e.Seq, $"Entry {e.Seq} does not hold the keys of the device that signed it.");
                    if (expectedSigner is not null && !string.Equals(expectedSigner, e.By, StringComparison.OrdinalIgnoreCase)) return Bad(e.Seq, "This log is signed by another device than the one expected.");
                }

                if (expectedSigner is not null || e.By is not null)
                {
                    if (e.By is null || e.Sig is null || signerKeys is null || !string.Equals(e.By, YuukoIdentity.FingerprintOf(signerKeys), StringComparison.Ordinal))
                        return Bad(e.Seq, $"Entry {e.Seq} is not signed by the device that signed the log.");

                    bool signedRight;
                    try { signedRight = YuukoIdentity.VerifySignature(signerKeys.Signing, Encoding.ASCII.GetBytes(e.Hash), Convert.FromBase64String(e.Sig)); }
                    catch (FormatException) { signedRight = false; }
                    if (!signedRight) return Bad(e.Seq, $"Entry {e.Seq} has a signature that is not the signer's.");
                }

                prev = e.Hash;
                expectedSeq = e.Seq + 1;
                count++;
            }

            if (count > 0 && !EndsWithNewline()) return Bad(null, "The log ends in a partly written entry.");
            if (expectedSigner is not null && count == 0) return Bad(null, "The log is empty, so nothing in it is signed.");

            var head = new AuditHead(expectedSeq - 1, prev);
            if (expectedHead is { } want && (want.Seq != head.Seq || !string.Equals(want.Hash, head.Hash, StringComparison.Ordinal)))
                return new AuditVerification(false, count, null,
                    want.Seq > head.Seq ? $"The log has {head.Seq} entries but {want.Seq} were expected: entries were cut off the end."
                                        : "The newest entry is not the one expected.", head);

            return new AuditVerification(true, count, null, null, head);
        }

        //Verify, and then ask the devices node is connected to what they saw of this log (they keep it with an AuditWitness
        //after AnchorTo). A log with entries cut off the end, or an earlier entry rewritten, doesn't match them. The answer says how many
        //devices had seen the log (Witnesses): none means nothing was compared.
        public async Task<AuditVerification> VerifyWithWitnessesAsync(EclipseBroker node, string name = "audit", string? expectedSigner = null, CancellationToken ct = default)
        {
            var local = Verify(null, expectedSigner);
            if (!local.Ok) return local;

            int answered = 0;
            AuditVerification Wrong(string problem) => local with { Ok = false, Problem = problem, Witnesses = answered };

            foreach (var peer in node.ConnectedPeers.ToList())
            {
                var ack = await node.SendCommandAsync(peer, "audit.gethead", Encoding.UTF8.GetBytes(new JsonObject { ["n"] = name }.ToJsonString()), ct: ct).ConfigureAwait(false);
                if (!ack.IsOk) continue;     // not a witness of this log

                long seq; string hash; bool conflict;
                try
                {
                    var body = JsonNode.Parse(ack.Result)!;
                    seq = (long?)body["s"] ?? -1; hash = (string?)body["h"] ?? ""; conflict = (bool?)body["c"] ?? false;
                }
                catch (Exception e) when (e is JsonException or InvalidCastException or InvalidOperationException) { continue; }
                if (seq < 1 || hash.Length != 64) continue;
                answered++;

                if (conflict) return Wrong($"{peer} was told two different versions of entry {seq}: the log was rewritten.");
                if (seq > local.Head.Seq) return Wrong($"The log has {local.Head.Seq} entries but {peer} saw entry {seq}: entries were cut off the end.");

                var mine = seq == local.Head.Seq ? local.Head.Hash : Read().FirstOrDefault(x => x.Seq == seq)?.Hash;
                if (!string.Equals(mine, hash, StringComparison.Ordinal)) return Wrong($"Entry {seq} is not the one {peer} saw: the log was rewritten.");
            }

            return local with { Witnesses = answered };
        }

        //Sends the newest head of this log to every device node is connected to, now and after every entry, and to each device that
        //connects later. Those devices keep it with an AuditWitness. name tells your logs apart. Returns an object that stops when disposed.
        public IDisposable AnchorTo(EclipseBroker node, string name = "audit")
        {
            ThrowIfDisposed();
            if (node is null) throw new ArgumentNullException(nameof(node));
            if (!AuditWitness.SafeName(name)) throw new ArgumentException("A log name is 1-64 letters, digits, '.', '_' or '-'.", nameof(name));

            void Tell(string peer, AuditHead head)
            {
                var body = new JsonObject { ["n"] = name, ["s"] = head.Seq, ["h"] = head.Hash };
                _ = Task.Run(async () => { try { await node.SendCommandAsync(peer, "audit.head", Encoding.UTF8.GetBytes(body.ToJsonString()), new CommandOptions { Timeout = TimeSpan.FromSeconds(3), Retries = 1 }).ConfigureAwait(false); } catch { } });
            }

            void Everyone(AuditHead head) { foreach (var peer in node.ConnectedPeers) Tell(peer, head); }
            void Joined(PeerInfo peer) => Tell(peer.Id, Head);

            Appended += Everyone;
            node.PeerConnected += Joined;
            if (Head.Seq > 0) Everyone(Head);

            return new Detach(() => { Appended -= Everyone; node.PeerConnected -= Joined; });
        }

        //Sealing

        //Finishes with this log: stops writing, and marks the FILE read-only at the operating-system level, so it cannot be
        //edited without a deliberate Unseal(string). This object becomes read-only too.
        public void Seal()
        {
            ThrowIfDisposed();
            lock (_lock)
            {
                _writer?.Dispose();
                _writer = null;
                IsReadOnly = true;
            }
            Seal(Path);
        }

        //Marks a log file read-only (the file attribute, and 0444 permissions on Unix). It is a guard against accidents and casual edits, not against someone with the rights to undo it.
        public static void Seal(string path)
        {
            File.SetAttributes(path, File.GetAttributes(path) | FileAttributes.ReadOnly);
            if (!OperatingSystem.IsWindows())
                File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.GroupRead | UnixFileMode.OtherRead);
        }

        //Lets a sealed log be written again.
        public static void Unseal(string path)
        {
            File.SetAttributes(path, File.GetAttributes(path) & ~FileAttributes.ReadOnly);
            if (!OperatingSystem.IsWindows())
                File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.GroupRead);
        }

        //Is this log file marked read-only?
        public static bool IsSealed(string path) => (File.GetAttributes(path) & FileAttributes.ReadOnly) != 0;

        //Recording a node

        private readonly Dictionary<string, (long At, int Suppressed)> _refused = new();

        //Records what node does: devices connecting and leaving, pairing, kicks and bans, group changes accepted or
        //refused, commands denied, and connection attempts turned away. Refused attempts can come from anybody, so repeats of the
        //same (who, why) within a minute are counted into one entry instead of filling the disk. Returns an object that stops recording
        //when disposed. A failure to write never reaches the node: see Failures and AppendFailed.
        public IDisposable Attach(EclipseBroker node)
        {
            ThrowIfDisposed();
            if (node is null) throw new ArgumentNullException(nameof(node));
            if (IsReadOnly) throw new InvalidOperationException("This audit log was opened read-only.");

            string me = node.ClientId;
            void Connected(PeerInfo p) => Record("peer.connected", p.Id, "fingerprint " + p.Fingerprint, me);
            void Disconnected(string id, string why) => Record("peer.disconnected", id, why, me);
            void Paired(string id, string fp) => Record("device.paired", id, "fingerprint " + fp, me);
            void Event(string kind, string subject, string detail)
            {
                if (kind == "handshake.refused")
                {
                    if (!ShouldRecordRefused(subject, detail, out int more)) return;
                    if (more > 0) detail += $" (+{more} more in the last minute)";
                }
                Record(kind, subject, detail, me);
            }

            node.PeerConnected += Connected;
            node.PeerDisconnected += Disconnected;
            node.DevicePaired += Paired;
            node.AuditEvent += Event;
            return new Detach(() =>
            {
                node.PeerConnected -= Connected;
                node.PeerDisconnected -= Disconnected;
                node.DevicePaired -= Paired;
                node.AuditEvent -= Event;
            });
        }

        private sealed class Detach : IDisposable
        {
            private Action? _undo;
            public Detach(Action undo) => _undo = undo;
            public void Dispose() => Interlocked.Exchange(ref _undo, null)?.Invoke();
        }

        private void Record(string kind, string subject, string detail, string actor)
        {
            if (Volatile.Read(ref _disposed) != 0) return;
            try { Append(kind, subject, detail, actor); }
            catch (Exception e)
            {
                Interlocked.Increment(ref _failures);
                try { AppendFailed?.Invoke(e); } catch { }
            }
        }

        private bool ShouldRecordRefused(string who, string why, out int suppressedBefore)
        {
            suppressedBefore = 0;
            string key = who + "|" + why;
            long now = Environment.TickCount64;
            lock (_refused)
            {
                if (_refused.Count > 4096) _refused.Clear();   // bounded no matter how many names an attacker invents
                if (_refused.TryGetValue(key, out var seen) && now - seen.At < RefusedWindowSeconds * 1000L)
                {
                    _refused[key] = (seen.At, seen.Suppressed + 1);
                    return false;
                }
                suppressedBefore = _refused.TryGetValue(key, out var old) ? old.Suppressed : 0;
                _refused[key] = (now, 0);
                return true;
            }
        }

        //Internals

        internal string ComputeHash(long seq, long ticks, string kind, string? actor, string? subject, string? detail, string prev, string? by = null)
        {
            using var ms = new MemoryStream();
            using (var w = new BinaryWriter(ms, Encoding.UTF8, leaveOpen: true))
            {
                w.Write("yuuko-audit-v1");   // domain separation
                w.Write(seq);
                w.Write(ticks);
                w.Write(kind);
                foreach (var field in new[] { actor, subject, detail })
                {
                    w.Write(field is not null);   // null and "" must hash differently
                    w.Write(field ?? "");
                }
                w.Write(prev);
                if (by is not null) { w.Write("by"); w.Write(by); }   // a signed entry can't be turned into an unsigned one, or signed by someone else
            }
            byte[] payload = ms.ToArray();
            byte[] digest;
            if (_macKey is null) digest = SHA256.HashData(payload);
            else
            {
                using var mac = new HMACSHA256(_macKey);
                digest = mac.ComputeHash(payload);
            }
            return Convert.ToHexString(digest).ToLowerInvariant();
        }

        private static AuditEntry? Parse(string line)
        {
            try
            {
                var l = JsonSerializer.Deserialize<Line>(line, Json);
                if (l is null || l.Seq < 1 || string.IsNullOrEmpty(l.Kind) || l.Prev.Length != 64 || l.Hash.Length != 64) return null;
                return new AuditEntry(l.Seq, l.Time.ToUniversalTime(), l.Kind, l.Actor, l.Subject, l.Detail, l.Prev, l.Hash, l.By, l.Sig);
            }
            catch (JsonException) { return null; }
        }

        private IEnumerable<string> ReadLines() => ReadLines(out _);

        // Reads the file as it is now, line by line, without blocking a writer.
        private IEnumerable<string> ReadLines(out bool endsWithNewline)
        {
            endsWithNewline = EndsWithNewline();
            return ReadAllLinesShared();
        }

        private IEnumerable<string> ReadAllLinesShared()
        {
            using var fs = new FileStream(Path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            using var reader = new StreamReader(fs, Encoding.UTF8);
            var lines = new List<string>();
            string? l;
            while ((l = reader.ReadLine()) is not null) lines.Add(l);
            return lines;
        }

        private bool EndsWithNewline()
        {
            using var fs = new FileStream(Path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            if (fs.Length == 0) return true;
            fs.Seek(-1, SeekOrigin.End);
            return fs.ReadByte() == '\n';
        }

        // The newest entry, checked on its own (cheap). Null for an empty file. Throws if the end of the file is damaged.
        private AuditEntry? ReadTail()
        {
            if (!File.Exists(Path)) return null;
            if (new FileInfo(Path).Length == 0) return null;
            if (!EndsWithNewline())
                throw new FormatException($"'{Path}' ends in a partly written entry. It will not be added to; check it with Verify() first.");

            string? lastLine = null;
            using (var fs = new FileStream(Path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
            {
                long start = Math.Max(0, fs.Length - 64 * 1024);
                fs.Seek(start, SeekOrigin.Begin);
                using var reader = new StreamReader(fs, Encoding.UTF8);
                string? l;
                while ((l = reader.ReadLine()) is not null) if (l.Length > 0) lastLine = l;
            }

            var e = lastLine is null ? null : Parse(lastLine);
            if (e is null)
                throw new FormatException($"The last entry of '{Path}' cannot be read. It will not be added to; check it with Verify() first.");
            string expected = ComputeHash(e.Seq, e.TimeUtc.UtcTicks, e.Kind, e.Actor, e.Subject, e.Detail, e.Prev, e.By);
            if (!CryptographicOperations.FixedTimeEquals(Encoding.ASCII.GetBytes(expected), Encoding.ASCII.GetBytes(e.Hash)))
                throw new FormatException($"The last entry of '{Path}' fails its check (it was changed, or the key is wrong). It will not be added to.");
            return e;
        }

        private void ThrowIfDisposed()
        {
            if (Volatile.Read(ref _disposed) != 0) throw new ObjectDisposedException(nameof(AuditLog));
        }

        public void Dispose()
        {
            if (Interlocked.Exchange(ref _disposed, 1) != 0) return;
            lock (_lock)
            {
                _writer?.Dispose();
                _writer = null;
            }
            if (_macKey is not null) CryptographicOperations.ZeroMemory(_macKey);
        }
    }
}
