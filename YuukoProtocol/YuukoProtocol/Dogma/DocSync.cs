// DocSync.cs - the engine behind SimpleCRDT: keeps Yjs documents in step between your devices.
//
//   using var sync = new DocSync(node);                     // registers the "crdt.*" commands on the node
//   await sync.ShareAsync(doc);                             // announce a document and send its changes from now on
//   await sync.SyncWithAsync("phone");                      // compare notes with one device (also happens by itself on connect)
//   sync.DocReceived += d => ...;                           // another device shared one with us
//   sync.DocUpdated += (d, from) => ...;                    // a document changed because of another device
//
// Messages (all end-to-end encrypted by the node):
//   crdt.announce   a device shares a document (its whole state)
//   crdt.update     a change to a document you already have
//   crdt.remove     a document was removed
//   crdt.sync       "here is what I have: send me what I am missing" (the answer carries it); then we push what THEY are missing (crdt.push)
//   crdt.tombstones the removed documents, a page at a time
//   crdt.chunk      one piece of a message that was too big for one message (announce, update or push): the other side puts it back together
//
// Nothing has a size that fits in "one message": a message bigger than ChunkBytes is sent in pieces, and the comparing of notes is done in pages, so one
// document can be any size (up to MaxChunkedBytes, so another device can't fill your memory) and a device can have any number of documents (MaxDocs is off
// unless you set it).
//
// Nothing here decides whose copy is "newest": merging is the same in any order. What is checked: the sender is a device of this group
// (the node only talks to those), names and counts are bounded, a document cannot be re-added after it was removed, and only the
// device that created a document may remove it (set AnyMemberMayRemove to allow everyone).

using System;
using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;
using static YuukoProtocol.Dogma.SimpleCRDT;

namespace YuukoProtocol.Dogma
{
    public sealed class DocSync : IDisposable
    {
        //How many documents this device keeps. Nothing, unless you set it (A document from another device is refused once you are there)
        private static int _maxDocs = int.MaxValue;
        public static int MaxDocs
        {
            get => _maxDocs;
            set => _maxDocs = value >= 1 ? value : throw new ArgumentOutOfRangeException(nameof(value), "At least 1 document.");
        }

        //How many labels (text fields) a document may have, and how long a name is
        private static int _maxLabels = 256;
        public static int MaxLabels
        {
            get => _maxLabels;
            set => _maxLabels = value >= 1 ? value : throw new ArgumentOutOfRangeException(nameof(value), "At least 1 label.");
        }
        public const int MaxNameChars = 128;

        //A message bigger than this is sent in pieces of this size (Bytes) and put back together on the other side
        private static int _chunkBytes = 500_000;
        public static int ChunkBytes
        {
            get => _chunkBytes;
            set => _chunkBytes = value is >= 1_000 and <= 700_000 ? value : throw new ArgumentOutOfRangeException(nameof(value), "1000 to 700000 bytes: a piece has to fit in one message.");
        }

        //The biggest message that is put back together (Bytes), so one device can't fill another device's memory by promising a huge one
        private static long _maxChunked = 128L << 20;
        public static long MaxChunkedBytes
        {
            get => _maxChunked;
            set => _maxChunked = value >= 1_000 ? value : throw new ArgumentOutOfRangeException(nameof(value));
        }

        //How much of the list of documents goes in one message when comparing notes, and how many removed documents (Tests make these small)
        internal static int SyncPageBytes = 200_000;
        internal static int TombstonePage = 2000;

        private const int MaxFrameBytes = 700_000;
        internal static int ReplyMetaBudget = 300_000;      //How much naming of documents fits in one answer (Tests make it small)
        private const int MaxTransfersPerDevice = 4;

        private readonly EclipseBroker _node;
        private readonly ConcurrentDictionary<string, SharedDocs> _docs = new(StringComparer.Ordinal);
        private readonly ConcurrentDictionary<string, DateTime> _removed = new(StringComparer.Ordinal);
        private int _disposed;
        private int _updatesSent;
        private readonly ConcurrentDictionary<string, Assembly> _assemblies = new(StringComparer.Ordinal);
        private readonly ConcurrentDictionary<string, SyncSession> _sessions = new(StringComparer.Ordinal);
        private int _syncing;
        private Timer? _timer;
        private TimeSpan _interval = TimeSpan.FromSeconds(20);

        //The documents this node has, by UUID.
        public IReadOnlyDictionary<string, SharedDocs> Docs => _docs;

        //If true, any device of the group may remove any document. By default only the device that created it may.
        public bool AnyMemberMayRemove { get; set; }

        //How often this node compares notes with every connected device, on top of doing it whenever a device connects. This is the safety
        //Net: if a single change message is ever lost (a timeout, a busy device), the next comparison brings the copies back together.
        //Default 20 seconds; Zero turns it off.
        public TimeSpan AntiEntropyInterval
        {
            get => _interval;
            set
            {
                if (value < TimeSpan.Zero) throw new ArgumentOutOfRangeException(nameof(value));
                _interval = value;
                _timer?.Dispose();
                _timer = value == TimeSpan.Zero || Volatile.Read(ref _disposed) != 0 ? null
                    : new Timer(_ => PeriodicSync(), null, value, value);
            }
        }

        private void PeriodicSync()
        {
            if (Volatile.Read(ref _disposed) != 0 || Interlocked.Exchange(ref _syncing, 1) != 0) return;
            _ = Task.Run(async () =>
            {
                try { await SyncAllAsync().ConfigureAwait(false); }
                catch { /* the next round tries again */ }
                finally { Volatile.Write(ref _syncing, 0); }
            });
        }

        //How many change messages this node has sent (for diagnostics and tests).
        public int UpdatesSent => Volatile.Read(ref _updatesSent);

        //Another device shared a document we did not have.
        public event Action<SharedDocs>? DocReceived;

        //A document we have changed because of another device: (the document, the device).
        public event Action<SharedDocs, string>? DocUpdated;

        //A document was removed because another device removed it.
        public event Action<string, string>? DocRemoved;

        //Something could not be sent or merged: (what, why). Never thrown at you from the background.
        public event Action<string, string>? Problem;

        public DocSync(EclipseBroker node)
        {
            _node = node ?? throw new ArgumentNullException(nameof(node));
            node.On("crdt.announce", (c, _) => Task.FromResult(HandleIncoming(c, mayCreate: true)));
            node.On("crdt.update", (c, _) => Task.FromResult(HandleIncoming(c, mayCreate: false)));
            node.On("crdt.push", (c, _) => Task.FromResult(HandlePush(c)));
            node.On("crdt.remove", (c, _) => Task.FromResult(HandleRemove(c)));
            node.On("crdt.sync", (c, _) => Task.FromResult(HandleSync(c)));
            node.On("crdt.tombstones", (c, _) => Task.FromResult(HandleTombstones(c)));
            node.On("crdt.chunk", (c, _) => Task.FromResult(HandleChunk(c)));
            node.PeerConnected += OnPeerConnected;
            AntiEntropyInterval = _interval;   // starts the timer
        }

        //Sharing and removing

        //Starts keeping doc in step with every connected device: sends it to them now, and every later change as it happens.
        public async Task ShareAsync(SharedDocs doc)
        {
            ThrowIfDisposed();
            if (doc is null) throw new ArgumentNullException(nameof(doc));
            CheckName(doc.UUID, 64, "UUID");
            if (_docs.Count >= MaxDocs && !_docs.ContainsKey(doc.UUID)) throw new InvalidOperationException($"At most {MaxDocs} documents.");
            if (_removed.ContainsKey(doc.UUID)) throw new InvalidOperationException("That document was removed.");

            _docs[doc.UUID] = doc;
            Watch(doc);
            await _node.StartAsync().ConfigureAwait(false);

            var frame = Frame(MetaOf(doc), doc.StateDiff(null));
            await TryBroadcast("crdt.announce", frame, doc.UUID).ConfigureAwait(false);
        }

        //Removes a document here, and asks the other devices to. Throws if this device did not create it (unless AnyMemberMayRemove).
        public async Task RemoveAsync(string uuid)
        {
            ThrowIfDisposed();
            if (!_docs.TryGetValue(uuid, out var doc)) throw new InvalidOperationException("No Log With This UUID Exists.");
            if (!AnyMemberMayRemove && doc.DeviceName != _node.ClientId)
                throw new InvalidOperationException("Only the device that created a document may remove it.");

            Forget(uuid);
            await TryBroadcast("crdt.remove", Frame(new JsonObject { ["uuid"] = uuid }, Array.Empty<byte>()), uuid).ConfigureAwait(false);
        }

        private void Forget(string uuid)
        {
            _removed[uuid] = DateTime.UtcNow;
            if (_docs.TryRemove(uuid, out var d)) d.StopWatching();
        }

        private void Watch(SharedDocs doc)
        {
            string uuid = doc.UUID;
            doc.Watch(update =>
            {
                // A change made on THIS device (changes merged in from others are not reported here): send it to everyone.
                if (Volatile.Read(ref _disposed) != 0) return;
                var frame = Frame(MetaOf(doc), update);
                Interlocked.Increment(ref _updatesSent);
                _ = TryBroadcast("crdt.update", frame, uuid);
            });
        }

        private async Task TryBroadcast(string command, byte[] frame, string uuid)
        {
            try
            {
                if (frame.Length <= ChunkBytes) { await _node.BroadcastAsync(command, frame).ConfigureAwait(false); return; }

                //Too big for one message: every device we are connected to gets it in pieces, and passes on what is new to it
                await Task.WhenAll(_node.ConnectedPeers.ToList().Select(p => SendBigAsync(p, command, frame))).ConfigureAwait(false);
            }
            catch (ArgumentException) { Raise(uuid, "could not be sent; devices will get it when they next compare notes"); }
            catch (Exception e) when (e is not OutOfMemoryException) { Raise(uuid, e.Message); }
        }

        //Big messages: sent in pieces, put back together

        //Sends a message to one device. If it is bigger than ChunkBytes it goes in pieces ("crdt.chunk") and the other side puts it back together
        //And handles it as if it had come in one message. Comes back with false (and a Problem) if a piece did not get through.
        private async Task<bool> SendBigAsync(string peer, string command, byte[] frame, CancellationToken ct = default)
        {
            if (frame.Length <= ChunkBytes)
            {
                var one = await _node.SendCommandAsync(peer, command, frame, ct: ct).ConfigureAwait(false);
                if (!one.IsOk) Raise(peer, command + " failed: " + one.Status);
                return one.IsOk;
            }

            string id = Convert.ToHexString(RandomNumberGenerator.GetBytes(8)).ToLowerInvariant();
            string hash = Convert.ToHexString(SHA256.HashData(frame)).ToLowerInvariant();
            int size = ChunkBytes, count = (frame.Length + size - 1) / size;

            for (int i = 0; i < count; i++)
            {
                int from = i * size, len = Math.Min(size, frame.Length - from);
                var head = new JsonObject { ["t"] = id, ["i"] = i, ["n"] = count, ["c"] = command, ["h"] = hash, ["len"] = frame.Length };
                var ack = await _node.SendCommandAsync(peer, "crdt.chunk", Frame(head, frame.AsSpan(from, len).ToArray()), ct: ct).ConfigureAwait(false);
                Interlocked.Increment(ref _pieces);

                if (!ack.IsOk) { Raise(peer, $"piece {i + 1} of {count} of {command} failed: {ack.Status}"); return false; }
            }

            return true;
        }

        //A message being put back together
        private sealed class Assembly
        {
            public string Origin = "", Command = "", Hash = "";
            public int Count, Got;
            public long Length, Bytes;
            public byte[]?[] Parts = Array.Empty<byte[]?>();
            public DateTime Last = DateTime.UtcNow;
        }

        //For tests: pieces sent, sync pages sent, transfers being put together, removed documents known
        internal int OpenTransfers => _assemblies.Count;
        internal int PiecesSent => Volatile.Read(ref _pieces);
        internal int PagesSent => Volatile.Read(ref _pages);
        internal int RemovedCount => _removed.Count;
        private int _pieces, _pages;

        private CommandResult HandleChunk(CommandContext ctx)
        {
            if (!TryUnframe(ctx.Payload, out var h, out var piece)) return CommandResult.Error("malformed");

            try
            {
                string t = h["t"]?.GetValue<string>() ?? "", command = h["c"]?.GetValue<string>() ?? "", hash = h["h"]?.GetValue<string>() ?? "";
                int i = (int?)h["i"] ?? -1, n = (int?)h["n"] ?? 0;
                long len = (long?)h["len"] ?? -1;

                if (t.Length is 0 or > 32 || !t.All(Uri.IsHexDigit) || hash.Length != 64 || !hash.All(Uri.IsHexDigit)) return CommandResult.Error("malformed");
                if (command is not ("crdt.announce" or "crdt.update" or "crdt.push")) return CommandResult.Error("not a message that can be sent in pieces");
                if (n < 2 || n > 100_000 || i < 0 || i >= n || len <= 0 || piece.Length == 0 || piece.Length > len) return CommandResult.Error("malformed");
                if (len > MaxChunkedBytes) return CommandResult.Error("too big");

                //Forget the ones that stopped coming
                var cutoff = DateTime.UtcNow.AddMinutes(-2);
                foreach (var old in _assemblies.Where(a => a.Value.Last < cutoff).Select(a => a.Key).ToList()) _assemblies.TryRemove(old, out _);

                string key = ctx.Origin + "/" + t;
                if (!_assemblies.TryGetValue(key, out var a))
                {
                    if (_assemblies.Values.Count(x => x.Origin == ctx.Origin) >= MaxTransfersPerDevice) return CommandResult.Error("busy");
                    a = _assemblies.GetOrAdd(key, _ => new Assembly { Origin = ctx.Origin, Command = command, Hash = hash, Count = n, Length = len, Parts = new byte[]?[n] });
                }

                lock (a)
                {
                    if (a.Command != command || a.Count != n || a.Length != len || a.Hash != hash) return CommandResult.Error("pieces that don't belong together");

                    if (a.Parts[i] is null)
                    {
                        a.Parts[i] = piece.ToArray();
                        a.Bytes += piece.Length;
                        a.Got++;

                        if (a.Bytes > a.Length) { _assemblies.TryRemove(key, out _); return CommandResult.Error("more than it said"); }
                    }

                    a.Last = DateTime.UtcNow;
                    if (a.Got < a.Count) return CommandResult.Ok();
                }

                //Every piece is here
                _assemblies.TryRemove(key, out _);

                if (a.Bytes != a.Length) return CommandResult.Error("less than it said");
                var whole = new byte[a.Length];
                long at = 0;
                foreach (var part in a.Parts) { part!.CopyTo(whole, at); at += part.Length; }

                if (!string.Equals(Convert.ToHexString(SHA256.HashData(whole)), hash, StringComparison.OrdinalIgnoreCase)) return CommandResult.Error("damaged");

                //Handled as if it had come whole. What reached us this way was never broadcast on to the rest, so we pass on what is new to us
                return command == "crdt.push"
                    ? Push(whole, ctx.Origin, big: true)
                    : Incoming(whole, ctx.Origin, mayCreate: command == "crdt.announce", relay: true, big: true);
            }
            catch (Exception e) when (BadInput.Is(e))
            {
                return CommandResult.Error("malformed");
            }
        }

        //Comparing notes

        //Compares notes with every connected device. Returns how many were reachable.
        public async Task<int> SyncAllAsync()
        {
            int ok = 0;
            foreach (var peer in _node.ConnectedPeers.ToList())
                if (await SyncWithAsync(peer).ConfigureAwait(false)) ok++;
            return ok;
        }

        //Swaps what is missing with one device, in both directions: we send what we have (as a short summary, in pages if there are many), it answers
        //With what we lack, then we send what it lacks. Anything too big for an answer comes after it in pieces. Returns false if the device could not be
        //Reached or answered badly.
        public async Task<bool> SyncWithAsync(string peerId, CancellationToken ct = default)
        {
            ThrowIfDisposed();
            await _node.StartAsync(ct).ConfigureAwait(false);

            var pages = SyncPages();
            string session = Convert.ToHexString(RandomNumberGenerator.GetBytes(6)).ToLowerInvariant();
            var theirVectors = new Dictionary<string, byte[]>(StringComparer.Ordinal);
            var wants = new HashSet<string>(StringComparer.Ordinal);

            try
            {
                for (int k = 0; k < pages.Count; k++)
                {
                    Interlocked.Increment(ref _pages);
                    var request = new JsonObject { ["docs"] = pages[k].Docs, ["removed"] = pages[k].Removed, ["page"] = k, ["pages"] = pages.Count, ["session"] = session };
                    var ack = await _node.SendCommandAsync(peerId, "crdt.sync", Frame(request, Array.Empty<byte>()), ct: ct).ConfigureAwait(false);
                    if (!ack.IsOk) { Raise(peerId, "sync failed: " + ack.Status); return false; }

                    if (!TryUnframe(ack.Result, out var reply, out var payload) || !TakeReply(reply, payload, peerId, theirVectors, wants)) { Raise(peerId, "sync answer was malformed"); return false; }
                }

                //Now send them what THEY are missing: documents they asked about that they lack, and the difference for those we both have
                var send = new List<(SharedDocs Doc, byte[] Diff)>();
                foreach (var doc in _docs.Values.ToList())
                {
                    byte[] diff;
                    if (wants.Contains(doc.UUID)) diff = doc.StateDiff(null);
                    else if (theirVectors.TryGetValue(doc.UUID, out var theirs)) diff = doc.StateDiff(theirs);
                    else continue;
                    if (diff.Length > 0) send.Add((doc, diff));
                }
                if (!await PushAsync(peerId, send, ct).ConfigureAwait(false)) return false;

                return await FetchTombstones(peerId, ct).ConfigureAwait(false);
            }
            catch (Exception e) when (BadInput.Is(e))
            {
                Raise(peerId, "sync answer was malformed: " + e.Message);
                return false;
            }
        }

        //Our list of documents cut into pages that each fit in one message, with our removed documents spread over the pages
        private List<(JsonArray Docs, JsonArray Removed)> SyncPages()
        {
            var pages = new List<(JsonArray Docs, JsonArray Removed)>();
            var docs = new JsonArray(); int bytes = 0;

            foreach (var doc in _docs.Values.ToList())
            {
                var m = MetaOf(doc);
                m["sv"] = Convert.ToBase64String(doc.StateVector());
                int size = Encoding.UTF8.GetByteCount(m.ToJsonString());

                if (docs.Count > 0 && bytes + size > SyncPageBytes) { pages.Add((docs, new JsonArray())); docs = new JsonArray(); bytes = 0; }
                docs.Add(m); bytes += size;
            }
            pages.Add((docs, new JsonArray()));

            var removed = _removed.Keys.OrderBy(x => x, StringComparer.Ordinal).ToList();
            for (int i = 0; i * TombstonePage < removed.Count; i++)
            {
                if (i >= pages.Count) pages.Add((new JsonArray(), new JsonArray()));
                foreach (var uuid in removed.Skip(i * TombstonePage).Take(TombstonePage)) pages[i].Removed.Add(uuid);
            }

            return pages;
        }

        //What the other device answered for one page: merge what it had that we lacked, remember what it has and what it wants
        private bool TakeReply(JsonObject reply, ReadOnlyMemory<byte> payload, string peerId, Dictionary<string, byte[]> theirVectors, HashSet<string> wants)
        {
            int offset = 0;
            foreach (var node in reply["docs"] as JsonArray ?? new JsonArray())
            {
                if (node is not JsonObject entry) continue;
                int len = (int?)entry["len"] ?? 0;
                if (len < 0 || offset + len > payload.Length) return false;
                var diff = payload.Slice(offset, len).ToArray(); offset += len;

                if (!ReadMeta(entry, out var meta, out _)) continue;
                if (entry["sv"]?.GetValue<string>() is { } sv) theirVectors[meta.Uuid] = Convert.FromBase64String(sv);
                if (_removed.ContainsKey(meta.Uuid)) continue;
                Merge(meta, diff, peerId, mayCreate: true, relay: true);
            }

            foreach (var w in reply["wants"] as JsonArray ?? new JsonArray())
            {
                var uuid = w?.GetValue<string>();
                if (!string.IsNullOrEmpty(uuid)) wants.Add(uuid);
            }

            return true;
        }

        //Sends documents' changes to one device, several to a message, and a big one alone (in pieces if it needs them)
        private async Task<bool> PushAsync(string peer, List<(SharedDocs Doc, byte[] Diff)> items, CancellationToken ct = default)
        {
            var entries = new JsonArray(); var body = new List<byte>();

            async Task<bool> Flush()
            {
                if (entries.Count == 0) return true;
                var frame = Frame(new JsonObject { ["docs"] = entries }, body.ToArray());
                entries = new JsonArray(); body = new List<byte>();
                return await SendBigAsync(peer, "crdt.push", frame, ct).ConfigureAwait(false);
            }

            foreach (var (doc, diff) in items)
            {
                if (body.Count > 0 && body.Count + diff.Length > MaxFrameBytes && !await Flush().ConfigureAwait(false)) return false;
                var meta = MetaOf(doc); meta["len"] = diff.Length;
                entries.Add(meta); body.AddRange(diff);
            }

            return await Flush().ConfigureAwait(false);
        }

        //The other device's list of removed documents, a page at a time
        private async Task<bool> FetchTombstones(string peerId, CancellationToken ct)
        {
            string after = "";
            for (int round = 0; round < 100_000; round++)
            {
                var ack = await _node.SendCommandAsync(peerId, "crdt.tombstones", Frame(new JsonObject { ["after"] = after }, Array.Empty<byte>()), ct: ct).ConfigureAwait(false);
                if (!ack.IsOk) { Raise(peerId, "sync failed: " + ack.Status); return false; }
                if (!TryUnframe(ack.Result, out var reply, out _)) { Raise(peerId, "sync answer was malformed"); return false; }

                ApplyRemovals(reply["items"] as JsonArray, peerId);

                string? next = reply["next"]?.GetValue<string>();
                if (string.IsNullOrEmpty(next)) return true;
                after = next;
            }

            return true;
        }

        private void OnPeerConnected(PeerInfo p)
        {
            if (Volatile.Read(ref _disposed) != 0) return;
            _ = Task.Run(async () => { try { await SyncWithAsync(p.Id).ConfigureAwait(false); } catch { } });
        }

        //Handling what other devices send

        private CommandResult HandleIncoming(CommandContext ctx, bool mayCreate) => Incoming(ctx.Payload, ctx.Origin, mayCreate, relay: false, big: false);

        //relay: pass what is new to us on to the others. A message that came in one piece was broadcast to everybody by whoever made it, so no
        //Need. One that came in pieces was sent to the devices connected to its maker only
        private CommandResult Incoming(byte[] data, string origin, bool mayCreate, bool relay, bool big)
        {
            if (!TryUnframe(data, out var meta, out var payload, big)) return CommandResult.Error("malformed");
            if (!ReadMeta(meta, out var m, out var why)) return CommandResult.Error(why!);
            if (_removed.ContainsKey(m.Uuid)) return CommandResult.Ok("removed here");
            if (!mayCreate && !_docs.ContainsKey(m.Uuid))
            {
                // an update for a document we have never seen (we missed its announcement): ask the sender for it
                _ = Task.Run(async () => { try { await SyncWithAsync(origin).ConfigureAwait(false); } catch { } });
                return CommandResult.Ok("unknown document; syncing");
            }
            try { Merge(m, payload.ToArray(), origin, mayCreate, relay); }
            catch (Exception e) when (BadInput.Is(e)) { return CommandResult.Error("rejected: " + e.Message); }
            return CommandResult.Ok();
        }

        private CommandResult HandlePush(CommandContext ctx) => Push(ctx.Payload, ctx.Origin, big: false);

        private CommandResult Push(byte[] data, string origin, bool big)
        {
            if (!TryUnframe(data, out var meta, out var payload, big)) return CommandResult.Error("malformed");
            try
            {
                int offset = 0;
                foreach (var node in meta["docs"] as JsonArray ?? new JsonArray())
                {
                    if (node is not JsonObject entry || !ReadMeta(entry, out var m, out _)) continue;
                    int len = (int?)entry["len"] ?? 0;
                    if (len < 0 || offset + len > payload.Length) return CommandResult.Error("malformed");
                    var diff = payload.Slice(offset, len).ToArray(); offset += len;
                    if (_removed.ContainsKey(m.Uuid)) continue;
                    Merge(m, diff, origin, mayCreate: true, relay: true);
                }
            }
            catch (Exception e) when (BadInput.Is(e))
            {
                return CommandResult.Error("rejected: " + e.Message);
            }
            return CommandResult.Ok();
        }

        private CommandResult HandleRemove(CommandContext ctx)
        {
            if (!TryUnframe(ctx.Payload, out var meta, out _)) return CommandResult.Error("malformed");
            string? uuid = meta["uuid"]?.GetValue<string>();
            if (uuid is null || uuid.Length > 64) return CommandResult.Error("malformed");
            //We can't check who made a document we never saw, so we don't remember the claim (Anyone could block a real doc that way)
            if (!_docs.TryGetValue(uuid, out var doc)) return CommandResult.Ok();
            if (!AnyMemberMayRemove && doc.DeviceName != ctx.Origin) return CommandResult.Denied("only the device that created a document may remove it");
            Forget(uuid);
            try { DocRemoved?.Invoke(uuid, ctx.Origin); } catch { }
            return CommandResult.Ok();
        }

        //The devices comparing notes with us: which documents each one listed over all its pages, so the last page knows which ones it has not got at all
        private sealed class SyncSession
        {
            public readonly HashSet<string> Listed = new(StringComparer.Ordinal);
            public DateTime At = DateTime.UtcNow;
        }

        private SyncSession SessionFor(string origin, string id)
        {
            var cutoff = DateTime.UtcNow.AddMinutes(-2);
            foreach (var old in _sessions.Where(x => x.Value.At < cutoff).Select(x => x.Key).ToList()) _sessions.TryRemove(old, out _);

            string key = origin + "/" + id;
            if (_sessions.Count >= 256 && !_sessions.ContainsKey(key)) throw new InvalidOperationException("too many devices comparing notes at once");

            var session = _sessions.GetOrAdd(key, _ => new SyncSession());
            session.At = DateTime.UtcNow;
            return session;
        }

        // "Here is what I have." (one page of it) Answers with what the asker is missing of the documents it listed, who has what, and which documents we would like.
        // On the last page it also answers for the documents the asker did not list on any page, because it has none of them. What does not fit in one answer is
        // Sent afterwards.
        private CommandResult HandleSync(CommandContext ctx)
        {
            if (!TryUnframe(ctx.Payload, out var req, out _)) return CommandResult.Error("malformed");
            try
            {
                ApplyRemovals(req["removed"] as JsonArray, ctx.Origin);

                int page = (int?)req["page"] ?? 0, pages = (int?)req["pages"] ?? 1;
                string id = req["session"]?.GetValue<string>() ?? "";
                if (pages < 1 || pages > 100_000 || page < 0 || page >= pages || id.Length > 32) return CommandResult.Error("malformed");
                bool last = page == pages - 1;

                var theirs = new Dictionary<string, byte[]>(StringComparer.Ordinal);
                var wants = new JsonArray();
                foreach (var node in req["docs"] as JsonArray ?? new JsonArray())
                {
                    if (node is not JsonObject entry || !ReadMeta(entry, out var m, out _)) continue;
                    if (_removed.ContainsKey(m.Uuid)) continue;
                    var sv = entry["sv"]?.GetValue<string>();
                    theirs[m.Uuid] = sv is null ? Array.Empty<byte>() : Convert.FromBase64String(sv);
                    if (!_docs.ContainsKey(m.Uuid) && _docs.Count < MaxDocs) wants.Add(m.Uuid);
                }

                var session = SessionFor(ctx.Origin, id);
                lock (session.Listed) foreach (var uuid in theirs.Keys) session.Listed.Add(uuid);

                var entries = new JsonArray(); var body = new List<byte>(); var later = new List<(SharedDocs Doc, byte[] Diff)>();
                int metaBytes = 0;

                foreach (var doc in _docs.Values.ToList())
                {
                    bool listed = theirs.TryGetValue(doc.UUID, out var sv);
                    if (!listed)
                    {
                        if (!last) continue;      // it may be on another page
                        bool elsewhere; lock (session.Listed) elsewhere = session.Listed.Contains(doc.UUID);
                        if (elsewhere) continue;
                    }

                    byte[] diff = doc.StateDiff(listed ? sv : null);   // they lack the whole document if they did not list it
                    var meta = MetaOf(doc);
                    meta["sv"] = Convert.ToBase64String(doc.StateVector());
                    int size = Encoding.UTF8.GetByteCount(meta.ToJsonString());

                    //Too many to name in one answer: they are sent afterwards
                    if (!listed && metaBytes + size > ReplyMetaBudget) { if (diff.Length > 0) later.Add((doc, diff)); continue; }
                    metaBytes += size;

                    //Their copy is named (so they can send us what we lack) but the data does not fit: it is sent afterwards
                    if (body.Count + diff.Length > MaxFrameBytes)
                    {
                        meta["len"] = 0; entries.Add(meta);
                        if (diff.Length > 0) later.Add((doc, diff));
                        continue;
                    }

                    meta["len"] = diff.Length;
                    entries.Add(meta); body.AddRange(diff);
                }

                if (last) _sessions.TryRemove(ctx.Origin + "/" + id, out _);
                if (later.Count > 0) { string to = ctx.Origin; _ = Task.Run(async () => { try { await PushAsync(to, later).ConfigureAwait(false); } catch { } }); }

                return CommandResult.Ok(Frame(new JsonObject { ["docs"] = entries, ["wants"] = wants }, body.ToArray()));
            }
            catch (Exception e) when (BadInput.Is(e))
            {
                return CommandResult.Error("rejected: " + e.Message);
            }
        }

        //Our removed documents after one UUID, a page of them, and where the next page starts (Nothing if that was the last)
        private CommandResult HandleTombstones(CommandContext ctx)
        {
            if (!TryUnframe(ctx.Payload, out var req, out _)) return CommandResult.Error("malformed");
            try
            {
                string after = req["after"]?.GetValue<string>() ?? "";
                if (after.Length > 64) return CommandResult.Error("malformed");

                var items = _removed.Keys.Where(k => string.CompareOrdinal(k, after) > 0).OrderBy(k => k, StringComparer.Ordinal).Take(TombstonePage + 1).ToList();
                bool more = items.Count > TombstonePage;
                if (more) items.RemoveAt(items.Count - 1);

                var reply = new JsonObject { ["items"] = new JsonArray(items.Select(x => (JsonNode)x).ToArray()), ["next"] = more ? items[^1] : null };
                return CommandResult.Ok(Frame(reply, Array.Empty<byte>()));
            }
            catch (Exception e) when (BadInput.Is(e))
            {
                return CommandResult.Error("malformed");
            }
        }

        private void ApplyRemovals(JsonArray? removed, string fromDevice)
        {
            if (removed is null) return;
            foreach (var n in removed.Take(TombstonePage * 2))
            {
                string? uuid = n?.GetValue<string>();
                if (uuid is null || uuid.Length > 64) continue;
                if (_docs.TryGetValue(uuid, out var doc))
                {
                    if (!AnyMemberMayRemove && doc.DeviceName != fromDevice) continue;   // only the creator's word counts
                    Forget(uuid);
                    try { DocRemoved?.Invoke(uuid, fromDevice); } catch { }
                }
                //Same here: a claim about a document we don't have can't be checked, so it's ignored
            }
        }

        // Merges bytes into a document, creating it if allowed. Throws FormatException for bytes that are not a valid update.
        // relay: pass what we learned on to our other devices. True for changes that reached us by catching up (they were never broadcast
        // from here), false for changes that were broadcast to every device by whoever made them (everyone already has them).
        private void Merge(DocMeta m, byte[] update, string fromDevice, bool mayCreate, bool relay)
        {
            bool created = false;
            byte[]? before = relay && _docs.TryGetValue(m.Uuid, out var existing) ? existing.StateVector() : null;
            if (!_docs.TryGetValue(m.Uuid, out var doc))
            {
                if (!mayCreate) return;
                if (_docs.Count >= MaxDocs) throw new InvalidOperationException("too many documents");
                doc = new SharedDocs { UUID = m.Uuid, DeviceName = m.Owner, LabelName = m.Name, LastUpdated = DateTime.UtcNow };
                foreach (var label in m.Labels) doc.AddLabelFromRemote(label);
                if (update.Length > 0) doc.ApplyUpdate(update);   // a bad update stops here, before the document is kept
                created = _docs.TryAdd(m.Uuid, doc);
                if (!created) { _docs.TryGetValue(m.Uuid, out doc); }   // another message created it first
            }
            if (!created && doc is not null)
            {
                foreach (var label in m.Labels) doc.AddLabelFromRemote(label);
                if (update.Length > 0) doc.ApplyUpdate(update);
            }

            if (relay && doc is not null && update.Length > 0)
            {
                if (created) _ = TryBroadcast("crdt.announce", Frame(MetaOf(doc), doc.StateDiff(null)), m.Uuid);
                else if (before is not null && !before.AsSpan().SequenceEqual(doc.StateVector()))
                    _ = TryBroadcast("crdt.update", Frame(MetaOf(doc), doc.StateDiff(before)), m.Uuid);   // only what was new to us
            }

            if (created)
            {
                Watch(doc!);
                try { DocReceived?.Invoke(doc!); } catch { }
            }
            else if (update.Length > 0) { try { DocUpdated?.Invoke(doc!, fromDevice); } catch { } }
        }

        //Wire format: [4-byte length][JSON header][raw bytes]

        private readonly record struct DocMeta(string Uuid, string Name, string Owner, string[] Labels);

        private static JsonObject MetaOf(SharedDocs d) => new()
        {
            ["uuid"] = d.UUID, ["name"] = d.LabelName, ["owner"] = d.DeviceName,
            ["labels"] = new JsonArray(d.TextLabels.OrderBy(x => x, StringComparer.Ordinal).Select(x => (JsonNode)x).ToArray()),
        };

        private static bool ReadMeta(JsonObject o, out DocMeta m, out string? why)
        {
            m = default; why = null;
            try
            {
                string uuid = o["uuid"]?.GetValue<string>() ?? "", name = o["name"]?.GetValue<string>() ?? "", owner = o["owner"]?.GetValue<string>() ?? "";
                if (uuid.Length is 0 or > 64 || uuid.Any(char.IsControl)) { why = "bad document id"; return false; }
                if (name.Length > MaxNameChars || owner.Length > MaxNameChars || name.Any(char.IsControl) || owner.Any(char.IsControl)) { why = "bad name"; return false; }
                var labelsNode = o["labels"] as JsonArray ?? new JsonArray();
                if (labelsNode.Count > MaxLabels) { why = "too many labels"; return false; }
                var labels = new List<string>();
                foreach (var l in labelsNode)
                {
                    string s = l?.GetValue<string>() ?? "";
                    if (s.Length is 0 or > MaxNameChars) { why = "bad label"; return false; }
                    labels.Add(s);
                }
                m = new DocMeta(uuid, name, owner, labels.ToArray());
                return true;
            }
            catch (Exception e) when (BadInput.Is(e)) { why = "malformed"; return false; }
        }

        private static byte[] Frame(JsonObject meta, byte[] payload)
        {
            byte[] header = Encoding.UTF8.GetBytes(meta.ToJsonString());
            var all = new byte[4 + header.Length + payload.Length];
            BinaryPrimitives.WriteInt32BigEndian(all, header.Length);
            header.CopyTo(all, 4);
            payload.CopyTo(all, 4 + header.Length);
            return all;
        }

        private static bool TryUnframe(byte[] data, out JsonObject meta, out ReadOnlyMemory<byte> payload, bool big = false)
        {
            meta = new JsonObject(); payload = default;
            if (data is null || data.Length < 4 || (!big && data.Length > MaxFrameBytes * 2)) return false;
            int n = BinaryPrimitives.ReadInt32BigEndian(data);
            if (n < 2 || n > data.Length - 4) return false;
            try
            {
                if (JsonNode.Parse(data.AsSpan(4, n), documentOptions: new JsonDocumentOptions { MaxDepth = 8 }) is not JsonObject o) return false;
                meta = o;
                payload = new ReadOnlyMemory<byte>(data, 4 + n, data.Length - 4 - n);
                return true;
            }
            catch (JsonException) { return false; }
        }

        private static void CheckName(string value, int max, string what)
        {
            if (string.IsNullOrEmpty(value) || value.Length > max || value.Any(char.IsControl))
                throw new ArgumentException($"A document's {what} is 1-{max} characters with no control characters.");
        }

        private void Raise(string what, string why) { try { Problem?.Invoke(what, why); } catch { } }

        private void ThrowIfDisposed()
        {
            if (Volatile.Read(ref _disposed) != 0) throw new ObjectDisposedException(nameof(DocSync));
        }

        public void Dispose()
        {
            if (Interlocked.Exchange(ref _disposed, 1) != 0) return;
            _node.PeerConnected -= OnPeerConnected;
            _timer?.Dispose();
            foreach (var n in new[] { "crdt.announce", "crdt.update", "crdt.push", "crdt.remove", "crdt.sync", "crdt.tombstones", "crdt.chunk" }) _node.Off(n);
            foreach (var d in _docs.Values) d.StopWatching();
        }
    }
}
