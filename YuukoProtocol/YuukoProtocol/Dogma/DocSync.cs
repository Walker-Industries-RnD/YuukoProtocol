// DocSync.cs - the engine behind SimpleCRDT: keeps Yjs documents in step between your devices.
//
//   using var sync = new DocSync(node);                     // registers the "crdt.*" commands on the node
//   await sync.ShareAsync(doc);                             // announce a document and send its changes from now on
//   await sync.SyncWithAsync("phone");                      // compare notes with one device (also happens by itself on connect)
//   sync.DocReceived += d => ...;                           // another device shared one with us
//   sync.DocUpdated += (d, from) => ...;                    // a document changed because of another device
//
// Messages (all end-to-end encrypted by the node; sizes are limited by one message, about 700 KB per document update):
//   crdt.announce   a device shares a document (its whole state)
//   crdt.update     a change to a document you already have
//   crdt.remove     a document was removed
//   crdt.sync       "here is what I have: send me what I am missing" (the answer carries it); then we push what THEY are missing (crdt.push)
//
// Nothing here decides whose copy is "newest": merging is the same in any order. What is checked: the sender is a device of this group
// (the node only talks to those), names and counts are bounded, a document cannot be re-added after it was removed, and only the
// device that created a document may remove it (set AnyMemberMayRemove to allow everyone).

using System;
using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
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
        public const int MaxDocs = 1000, MaxLabels = 256, MaxNameChars = 128;
        private const int MaxFrameBytes = 700_000;

        private readonly EclipseBroker _node;
        private readonly ConcurrentDictionary<string, SharedDocs> _docs = new(StringComparer.Ordinal);
        private readonly ConcurrentDictionary<string, DateTime> _removed = new(StringComparer.Ordinal);
        private int _disposed;
        private int _updatesSent;
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
            node.PeerConnected += OnPeerConnected;
            AntiEntropyInterval = _interval;   // starts the timer
        }

        // ── sharing and removing ─────────────────────────────────────────────────

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
            try { await _node.BroadcastAsync(command, frame).ConfigureAwait(false); }
            catch (ArgumentException) { Raise(uuid, "too large to send in one message; devices will fetch it when they next connect"); }
            catch (Exception e) when (e is not OutOfMemoryException) { Raise(uuid, e.Message); }
        }

        // ── comparing notes ──────────────────────────────────────────────────────

        //Compares notes with every connected device. Returns how many were reachable.
        public async Task<int> SyncAllAsync()
        {
            int ok = 0;
            foreach (var peer in _node.ConnectedPeers.ToList())
                if (await SyncWithAsync(peer).ConfigureAwait(false)) ok++;
            return ok;
        }

        //Swaps what is missing with one device, in both directions: we send what we have (as a short summary), it answers with what we lack,
        //Then we send what it lacks. Returns false if the device could not be reached or answered badly.
        public async Task<bool> SyncWithAsync(string peerId, CancellationToken ct = default)
        {
            ThrowIfDisposed();
            await _node.StartAsync(ct).ConfigureAwait(false);

            var request = new JsonObject { ["docs"] = DocsSummary(), ["removed"] = new JsonArray(_removed.Keys.Select(k => (JsonNode)k).ToArray()) };
            var ack = await _node.SendCommandAsync(peerId, "crdt.sync", Frame(request, Array.Empty<byte>()), ct: ct).ConfigureAwait(false);
            if (!ack.IsOk) { Raise(peerId, "sync failed: " + ack.Status); return false; }

            JsonObject reply; ReadOnlyMemory<byte> payload;
            if (!TryUnframe(ack.Result, out reply, out payload)) { Raise(peerId, "sync answer was malformed"); return false; }

            var theirVectors = new Dictionary<string, byte[]>(StringComparer.Ordinal);
            try
            {
                ApplyRemovals(reply["removed"] as JsonArray, peerId);
                int offset = 0;
                foreach (var node in reply["docs"] as JsonArray ?? new JsonArray())
                {
                    if (node is not JsonObject entry) continue;
                    int len = (int?)entry["len"] ?? 0;
                    if (len < 0 || offset + len > payload.Length) { Raise(peerId, "sync answer was malformed"); return false; }
                    var diff = payload.Slice(offset, len).ToArray(); offset += len;

                    if (!ReadMeta(entry, out var meta, out _)) continue;
                    if (entry["sv"]?.GetValue<string>() is { } sv) theirVectors[meta.Uuid] = Convert.FromBase64String(sv);
                    Merge(meta, diff, peerId, mayCreate: true, relay: true);
                }

                // Now send them what THEY are missing: documents they asked about that they lack, and the difference for those we both have.
                var wants = new HashSet<string>((reply["wants"] as JsonArray ?? new JsonArray()).Select(n => n?.GetValue<string>() ?? "").Where(s => s.Length > 0), StringComparer.Ordinal);
                var entries = new JsonArray(); var body = new List<byte>();
                foreach (var doc in _docs.Values.ToList())
                {
                    byte[] diff;
                    if (wants.Contains(doc.UUID)) diff = doc.StateDiff(null);
                    else if (theirVectors.TryGetValue(doc.UUID, out var theirs)) diff = doc.StateDiff(theirs);
                    else continue;
                    if (diff.Length == 0 || body.Count + diff.Length > MaxFrameBytes) continue;
                    var meta = MetaOf(doc); meta["len"] = diff.Length;
                    entries.Add(meta); body.AddRange(diff);
                }
                if (entries.Count > 0)
                {
                    var pushAck = await _node.SendCommandAsync(peerId, "crdt.push", Frame(new JsonObject { ["docs"] = entries }, body.ToArray()), ct: ct).ConfigureAwait(false);
                    if (!pushAck.IsOk) { Raise(peerId, "push failed: " + pushAck.Status); return false; }
                }
                return true;
            }
            catch (Exception e) when (e is FormatException or JsonException or InvalidOperationException or InvalidCastException or ArgumentException)
            {
                Raise(peerId, "sync answer was malformed: " + e.Message);
                return false;
            }
        }

        private JsonArray DocsSummary()
        {
            var arr = new JsonArray();
            foreach (var doc in _docs.Values.ToList())
            {
                var m = MetaOf(doc);
                m["sv"] = Convert.ToBase64String(doc.StateVector());
                arr.Add(m);
            }
            return arr;
        }

        private void OnPeerConnected(PeerInfo p)
        {
            if (Volatile.Read(ref _disposed) != 0) return;
            _ = Task.Run(async () => { try { await SyncWithAsync(p.Id).ConfigureAwait(false); } catch { } });
        }

        // ── handling what other devices send ─────────────────────────────────────

        private CommandResult HandleIncoming(CommandContext ctx, bool mayCreate)
        {
            if (!TryUnframe(ctx.Payload, out var meta, out var payload)) return CommandResult.Error("malformed");
            if (!ReadMeta(meta, out var m, out var why)) return CommandResult.Error(why!);
            if (_removed.ContainsKey(m.Uuid)) return CommandResult.Ok("removed here");
            if (!mayCreate && !_docs.ContainsKey(m.Uuid))
            {
                // an update for a document we have never seen (we missed its announcement): ask the sender for it
                _ = Task.Run(async () => { try { await SyncWithAsync(ctx.Origin).ConfigureAwait(false); } catch { } });
                return CommandResult.Ok("unknown document; syncing");
            }
            try { Merge(m, payload.ToArray(), ctx.Origin, mayCreate, relay: false); }   // already sent to everybody by whoever made it
            catch (Exception e) when (e is FormatException or InvalidOperationException or ArgumentException) { return CommandResult.Error("rejected: " + e.Message); }
            return CommandResult.Ok();
        }

        private CommandResult HandlePush(CommandContext ctx)
        {
            if (!TryUnframe(ctx.Payload, out var meta, out var payload)) return CommandResult.Error("malformed");
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
                    Merge(m, diff, ctx.Origin, mayCreate: true, relay: true);
                }
            }
            catch (Exception e) when (e is FormatException or JsonException or InvalidOperationException or InvalidCastException or ArgumentException)
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

        // "Here is what I have." Answers with what the asker is missing, who has what, and which documents we would like.
        private CommandResult HandleSync(CommandContext ctx)
        {
            if (!TryUnframe(ctx.Payload, out var req, out _)) return CommandResult.Error("malformed");
            try
            {
                ApplyRemovals(req["removed"] as JsonArray, ctx.Origin);

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

                var entries = new JsonArray(); var body = new List<byte>();
                foreach (var doc in _docs.Values.ToList())
                {
                    byte[] diff = doc.StateDiff(theirs.TryGetValue(doc.UUID, out var sv) ? sv : null);   // they lack the whole document if they did not list it
                    if (body.Count + diff.Length > MaxFrameBytes) continue;
                    var meta = MetaOf(doc);
                    meta["sv"] = Convert.ToBase64String(doc.StateVector());
                    meta["len"] = diff.Length;
                    entries.Add(meta); body.AddRange(diff);
                }

                var reply = new JsonObject
                {
                    ["docs"] = entries, ["wants"] = wants,
                    ["removed"] = new JsonArray(_removed.Keys.Select(k => (JsonNode)k).ToArray()),
                };
                return CommandResult.Ok(Frame(reply, body.ToArray()));
            }
            catch (Exception e) when (e is FormatException or JsonException or InvalidOperationException or InvalidCastException or ArgumentException)
            {
                return CommandResult.Error("rejected: " + e.Message);
            }
        }

        private void ApplyRemovals(JsonArray? removed, string fromDevice)
        {
            if (removed is null) return;
            foreach (var n in removed.Take(MaxDocs))
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

        // ── wire format: [4-byte length][JSON header][raw bytes] ─────────────────

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
            catch (Exception e) when (e is InvalidOperationException or FormatException or JsonException or InvalidCastException) { why = "malformed"; return false; }
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

        private static bool TryUnframe(byte[] data, out JsonObject meta, out ReadOnlyMemory<byte> payload)
        {
            meta = new JsonObject(); payload = default;
            if (data is null || data.Length < 4 || data.Length > MaxFrameBytes * 2) return false;
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
            foreach (var n in new[] { "crdt.announce", "crdt.update", "crdt.push", "crdt.remove", "crdt.sync" }) _node.Off(n);
            foreach (var d in _docs.Values) d.StopWatching();
        }
    }
}
