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
// What a chain can NOT see: entries cut off the END of the log (what remains is still a valid chain). To catch that, keep the
// latest <see cref="Head"/> somewhere else and pass it to Verify(expectedHead).
//
// Walker Industries R&D - YuukoProtocol

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using WISecureData;

namespace YuukoProtocol
{
    /// <summary>One line of the audit log.</summary>
    public sealed record AuditEntry(long Seq, DateTimeOffset TimeUtc, string Kind, string? Actor, string? Subject, string? Detail, string Prev, string Hash);

    /// <summary>The newest entry of a log: keep a copy elsewhere to detect entries being cut off the end.</summary>
    public readonly record struct AuditHead(long Seq, string Hash);

    /// <summary>The result of <see cref="AuditLog.Verify"/>.</summary>
    public sealed record AuditVerification(bool Ok, long Entries, long? BadSeq, string? Problem, AuditHead Head);

    public sealed class AuditLog : IDisposable
    {
        /// <summary>The "previous hash" of the first entry.</summary>
        public static readonly string Genesis = new('0', 64);

        private const int MaxKind = 64, MaxActor = 256, MaxSubject = 256, MaxDetail = 1024;
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
        }

        private readonly object _lock = new();
        private readonly byte[]? _macKey;
        private FileStream? _writer;
        private long _lastSeq;
        private string _lastHash = Genesis;
        private int _disposed;

        /// <summary>The full path of the log file.</summary>
        public string Path { get; }

        /// <summary>True if this object can only read: <see cref="Append"/> throws.</summary>
        public bool IsReadOnly { get; private set; }

        /// <summary>True if entries are HMAC'd with a key (edits are detected even by someone who knows the format).</summary>
        public bool IsKeyed => _macKey is not null;

        /// <summary>How many appends failed (disk full, file removed...). A failure never throws out of <see cref="Attach"/>'d events.</summary>
        public int Failures => Volatile.Read(ref _failures);
        private int _failures;

        /// <summary>Raised when recording an event from an attached node failed.</summary>
        public event Action<Exception>? AppendFailed;

        private AuditLog(string path, SecureData? key, bool readOnly)
        {
            Path = System.IO.Path.GetFullPath(path);
            IsReadOnly = readOnly;

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
        }

        /// <summary>
        /// Opens (or creates) a log you can append to. Only one writer can have it open at a time; others can read it meanwhile.
        /// Throws <see cref="FormatException"/> if the existing log ends in a damaged entry, rather than add to it.
        /// </summary>
        public static AuditLog Open(string path, SecureData? key = null) => new(path, key, readOnly: false);

        /// <summary>Opens an existing log for reading and verifying only. <see cref="Append"/> throws. Safe to use while a writer is running.</summary>
        public static AuditLog OpenReadOnly(string path, SecureData? key = null) => new(path, key, readOnly: true);

        // ── writing ──────────────────────────────────────────────────────────────

        /// <summary>
        /// Adds an entry and returns it. <paramref name="kind"/> is a short dotted name such as <c>peer.kicked</c> (letters, digits, '.', '_', '-').
        /// The entry is on disk before this returns. Text longer than the limits is cut.
        /// </summary>
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
                string? a = Cut(actor, MaxActor), s = Cut(subject, MaxSubject), d = Cut(detail, MaxDetail);
                string hash = ComputeHash(seq, time.UtcTicks, kind, a, s, d, _lastHash);

                var line = new Line { Seq = seq, Time = time, Kind = kind, Actor = a, Subject = s, Detail = d, Prev = _lastHash, Hash = hash };
                byte[] bytes = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(line, Json) + "\n");
                _writer.Write(bytes, 0, bytes.Length);
                _writer.Flush(flushToDisk: true);

                _lastSeq = seq;
                _lastHash = hash;
                return new AuditEntry(seq, time, kind, a, s, d, line.Prev, hash);
            }
        }

        private static string? Cut(string? text, int max) =>
            text is null ? null : text.Length <= max ? text : text[..(max - 1)] + "…";

        // ── reading ──────────────────────────────────────────────────────────────

        /// <summary>
        /// The entries, oldest first, optionally filtered. <paramref name="last"/> keeps only the newest N after filtering.
        /// Throws <see cref="FormatException"/> naming the line if one cannot be read: run <see cref="Verify"/> for details.
        /// </summary>
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

        /// <summary>The newest entry (seq 0 and the genesis hash for an empty log).</summary>
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

        // ── verifying ────────────────────────────────────────────────────────────

        /// <summary>
        /// Checks every entry: numbering, the link to the one before, and its own hash (an HMAC when the log is keyed, so the wrong
        /// key fails here at the first entry). Pass <paramref name="expectedHead"/> (a copy of <see cref="Head"/> you kept
        /// elsewhere) to also catch entries having been cut off the end.
        /// </summary>
        public AuditVerification Verify(AuditHead? expectedHead = null)
        {
            ThrowIfDisposed();
            long count = 0, expectedSeq = 1;
            string prev = Genesis;
            long lineNo = 0;

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

                string expected = ComputeHash(e.Seq, e.TimeUtc.UtcTicks, e.Kind, e.Actor, e.Subject, e.Detail, e.Prev);
                if (!CryptographicOperations.FixedTimeEquals(Encoding.ASCII.GetBytes(expected), Encoding.ASCII.GetBytes(e.Hash)))
                    return Bad(e.Seq, IsKeyed
                        ? $"Entry {e.Seq} fails its check: it was changed, or the key is wrong."
                        : $"Entry {e.Seq} fails its check: it was changed.");

                prev = e.Hash;
                expectedSeq = e.Seq + 1;
                count++;
            }

            if (count > 0 && !EndsWithNewline()) return Bad(null, "The log ends in a partly written entry.");

            var head = new AuditHead(expectedSeq - 1, prev);
            if (expectedHead is { } want && (want.Seq != head.Seq || !string.Equals(want.Hash, head.Hash, StringComparison.Ordinal)))
                return new AuditVerification(false, count, null,
                    want.Seq > head.Seq ? $"The log has {head.Seq} entries but {want.Seq} were expected: entries were cut off the end."
                                        : "The newest entry is not the one expected.", head);

            return new AuditVerification(true, count, null, null, head);
        }

        // ── sealing ──────────────────────────────────────────────────────────────

        /// <summary>
        /// Finishes with this log: stops writing, and marks the FILE read-only at the operating-system level, so it cannot be
        /// edited without a deliberate <see cref="Unseal(string)"/>. This object becomes read-only too.
        /// </summary>
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

        /// <summary>Marks a log file read-only (the file attribute, and 0444 permissions on Unix). It is a guard against accidents and casual edits, not against someone with the rights to undo it.</summary>
        public static void Seal(string path)
        {
            File.SetAttributes(path, File.GetAttributes(path) | FileAttributes.ReadOnly);
            if (!OperatingSystem.IsWindows())
                File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.GroupRead | UnixFileMode.OtherRead);
        }

        /// <summary>Lets a sealed log be written again.</summary>
        public static void Unseal(string path)
        {
            File.SetAttributes(path, File.GetAttributes(path) & ~FileAttributes.ReadOnly);
            if (!OperatingSystem.IsWindows())
                File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.GroupRead);
        }

        /// <summary>Is this log file marked read-only?</summary>
        public static bool IsSealed(string path) => (File.GetAttributes(path) & FileAttributes.ReadOnly) != 0;

        // ── recording a node ─────────────────────────────────────────────────────

        private readonly Dictionary<string, (long At, int Suppressed)> _refused = new();

        /// <summary>
        /// Records what <paramref name="node"/> does: devices connecting and leaving, pairing, kicks and bans, group changes accepted or
        /// refused, commands denied, and connection attempts turned away. Refused attempts can come from anybody, so repeats of the
        /// same (who, why) within a minute are counted into one entry instead of filling the disk. Returns an object that stops recording
        /// when disposed. A failure to write never reaches the node: see <see cref="Failures"/> and <see cref="AppendFailed"/>.
        /// </summary>
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

        // ── internals ────────────────────────────────────────────────────────────

        internal string ComputeHash(long seq, long ticks, string kind, string? actor, string? subject, string? detail, string prev)
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
                return new AuditEntry(l.Seq, l.Time.ToUniversalTime(), l.Kind, l.Actor, l.Subject, l.Detail, l.Prev, l.Hash);
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
            string expected = ComputeHash(e.Seq, e.TimeUtc.UtcTicks, e.Kind, e.Actor, e.Subject, e.Detail, e.Prev);
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
