// OtSession.cs - DOGMA II over the network: shared plain-text documents between your devices.
//
//   var ot = new OtSession(node);                       // once per node: registers the "ot.*" commands
//
//   // On the device that owns the document (it puts everyone's edits in order):
//   var doc = ot.Create("notes", "hello");
//
//   // On every other device:
//   var doc = await ot.JoinAsync("pc", "notes");        // "pc" is the owner's id
//
//   // On any of them:
//   doc.Insert(5, " world");                            // or Delete / Replace / SetText / Apply(yourOwnOperation)
//   doc.Changed += c => ui.Show(c.Text);                // c.Remote tells you whether it came from another device
//   await doc.WaitUntilSyncedAsync(TimeSpan.FromSeconds(5));
//
// How it works: the owner is the single authority. A device sends each edit to the owner (command "ot.op"), the owner transforms it over
// whatever it accepted in the meantime, applies it, and sends the accepted edit to every device that joined (command "ot.apply"). A
// device that was offline, or missed a message, asks the owner for what it missed ("ot.fetch"). A retry never applies an edit twice: the
// owner remembers the last edit it took from each device.
//
// What it does NOT do: if the owner is offline, nobody's edits are confirmed (devices keep their own edits and send them when the owner
// returns). There is no election of a new owner. Only devices that are paired and connected to the owner take part. Every device that
// joins can read the whole document; who may write can be limited with `writers` in Create.

using System;
using System.Buffers;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace YuukoProtocol.Dogma
{
    //Something changed in a document.
    //False for an edit made on this device, true for one that came from another.
    //The device that made the edit (null if unknown).
    internal sealed record OtChange(string DocumentId, string Text, TextOperation Operation, bool Remote, string? Author);

    //A shared text document. Get one from Create or JoinAsync.
    internal sealed class OtDocument
    {
        internal readonly record struct OwnerBroadcast(int Rev, OtSession.Meta Meta, TextOperation Op, string[] To);

        internal readonly object Gate = new();
        internal readonly OtSession Session;
        internal OtServer? Server;                       // owner only
        internal OtClient? Client;                       // everyone else
        internal readonly Dictionary<int, OtSession.Meta> MetaByRevision = new();    // owner: who made each revision
        internal readonly Dictionary<string, (int Seq, int Rev)> LastFrom = new();   // owner: last edit taken from each (device, run)
        internal readonly HashSet<string> Subscribers = new(StringComparer.Ordinal); // owner: who gets edits
        internal HashSet<string>? Writers;               // owner: null = any device connected to the owner may write
        internal readonly SortedDictionary<int, OtSession.Incoming> Future = new(); // member: edits that arrived early
        internal readonly string SessionId = Guid.NewGuid().ToString("N")[..16];     // member: tells one run of this document from another
        internal int Seq;                                // member: number of edits started
        internal int OutstandingSeq;                     // member: the edit currently in flight
        internal bool PumpRunning;
        internal volatile bool Closed;
        internal readonly SemaphoreSlim FetchLock = new(1, 1);

        public string Id { get; }
        public string OwnerId { get; }
        public bool IsOwner { get; }

        internal OtDocument(OtSession session, string id, string ownerId, bool isOwner)
        {
            Session = session; Id = id; OwnerId = ownerId; IsOwner = isOwner;
        }

        //The text as this device sees it, including its own edits that the owner has not confirmed yet.
        public string Text { get { lock (Gate) return IsOwner ? Server!.Document : Client!.Text; } }

        //The newest revision of the owner's text this device has taken in.
        public int Revision { get { lock (Gate) return IsOwner ? Server!.Revision : Client!.Revision; } }

        //True while one of this device's edits is waiting for the owner to confirm it.
        public bool HasPending { get { lock (Gate) return !IsOwner && Client!.HasPending; } }

        //The text changed, by this device or another.
        public event Action<OtChange>? Changed;

        //The owner refused this device's edit (for example because the device may not write): the reason is given, and the text is reset to the owner's.
        public event Action<string>? Rejected;

        //This device's text was replaced by the owner's (it fell too far behind, or an edit was rejected). Edits that were not confirmed are gone.
        public event Action<string>? Resynced;

        // ── editing ──────────────────────────────────────────────────────────────

        //Make an edit built against the current Text. Throws OtException if it does not fit.
        public void Apply(TextOperation operation) => Session.LocalEdit(this, _ => operation);

        public void Insert(int index, string text) =>
            Session.LocalEdit(this, doc => new TextOperation().Retain(Check(index, doc.Length)).Insert(text).Retain(doc.Length - index));

        public void Delete(int index, int length) =>
            Session.LocalEdit(this, doc => new TextOperation().Retain(Check(index, doc.Length)).Delete(CheckLen(index, length, doc.Length)).Retain(doc.Length - index - length));

        public void Replace(int index, int length, string text) =>
            Session.LocalEdit(this, doc => new TextOperation().Retain(Check(index, doc.Length)).Insert(text).Delete(CheckLen(index, length, doc.Length)).Retain(doc.Length - index - length));

        //Make the text exactly newText, with the smallest edit that does it (handy when all you have is the new contents of a text box).
        public void SetText(string newText) => Session.LocalEdit(this, doc => TextOperation.FromDiff(doc, newText));

        private static int Check(int index, int length)
        {
            if (index < 0 || index > length) throw new ArgumentOutOfRangeException(nameof(index));
            return index;
        }

        private static int CheckLen(int index, int length, int docLength)
        {
            if (length < 0 || index + length > docLength) throw new ArgumentOutOfRangeException(nameof(length));
            return length;
        }

        //Waits until every edit made here has been confirmed by the owner. Returns false if that took longer than timeout.
        public async Task<bool> WaitUntilSyncedAsync(TimeSpan timeout, CancellationToken ct = default)
        {
            var until = DateTime.UtcNow + timeout;
            while (HasPending)
            {
                if (DateTime.UtcNow >= until) return false;
                await Task.Delay(15, ct).ConfigureAwait(false);
            }
            return true;
        }

        internal void RaiseChanged(OtChange c) { try { Changed?.Invoke(c); } catch { /* a subscriber's bug must not break syncing */ } }
        internal void RaiseRejected(string why) { try { Rejected?.Invoke(why); } catch { } }
        internal void RaiseResynced(string text) { try { Resynced?.Invoke(text); } catch { } }
    }

    //Shared text documents over an EclipseBroker. One per node.
    internal sealed class OtSession : IDisposable
    {
        //The longest document, in characters. (A new device receives the whole text in one message when it joins.)
        public const int MaxDocumentChars = 200_000;

        private const int MaxPayloadBytes = 700_000, MaxSubscribers = 64, MaxFuture = 2_000, MaxRemembered = 2_048;
        private const int FetchBatchChars = 150_000;

        internal readonly record struct Meta(string Author, string Sid, int Seq);
        internal readonly record struct Incoming(int Rev, string Author, string Sid, int Seq, TextOperation Op);

        private static readonly JsonWriterOptions WriterOptions = new() { Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping };

        private readonly EclipseBroker _node;
        private readonly ConcurrentDictionary<string, OtDocument> _docs = new(StringComparer.Ordinal);
        private int _disposed;

        public OtSession(EclipseBroker node)
        {
            _node = node ?? throw new ArgumentNullException(nameof(node));
            node.On("ot.join", (c, _) => Task.FromResult(HandleJoin(c)));
            node.On("ot.op", (c, _) => Task.FromResult(HandleOp(c)));
            node.On("ot.apply", (c, _) => Task.FromResult(HandleApply(c)));
            node.On("ot.fetch", (c, _) => Task.FromResult(HandleFetch(c)));
            node.PeerConnected += OnPeerConnected;
        }

        //The documents this node has created or joined.
        public IReadOnlyCollection<OtDocument> Documents => _docs.Values.ToList();

        public OtDocument? Get(string id) => _docs.TryGetValue(id, out var d) ? d : null;

        // ── creating and joining ─────────────────────────────────────────────────

        //Starts a document that THIS device owns: it puts everyone's edits in order. Only devices in writers may edit
        //(null = any device connected to this one); the owner always may.
        public OtDocument Create(string id, string initialText = "", IEnumerable<string>? writers = null)
        {
            ThrowIfDisposed();
            ValidateId(id);
            if (initialText is null) throw new ArgumentNullException(nameof(initialText));
            if (initialText.Length > MaxDocumentChars) throw new OtException($"A document can hold at most {MaxDocumentChars} characters.");
            if (TextOperation.HasUnpairedSurrogate(initialText)) throw new OtException("The text contains half of an emoji (an unpaired surrogate), which cannot be sent.");

            var doc = new OtDocument(this, id, _node.ClientId, isOwner: true) { Server = new OtServer(initialText) };
            if (writers is not null) doc.Writers = new HashSet<string>(writers, StringComparer.Ordinal);
            if (!_docs.TryAdd(id, doc)) throw new InvalidOperationException($"This device already has a document called '{id}'.");
            return doc;
        }

        //Joins the document id owned by device ownerId, and returns it with the text up to date.
        public async Task<OtDocument> JoinAsync(string ownerId, string id, CancellationToken ct = default)
        {
            ThrowIfDisposed();
            ValidateId(id);
            if (string.IsNullOrWhiteSpace(ownerId)) throw new ArgumentException("ownerId must be non-empty.", nameof(ownerId));
            if (_docs.TryGetValue(id, out var existing)) return existing;
            if (ownerId == _node.ClientId) throw new InvalidOperationException($"This device owns no document called '{id}'.");

            await _node.StartAsync(ct).ConfigureAwait(false);
            var ack = await _node.SendCommandAsync(ownerId, "ot.join", Write(w => w.WriteString("doc", id)), ct: ct).ConfigureAwait(false);
            if (!ack.IsOk)
                throw new InvalidOperationException($"Could not join '{id}' on '{ownerId}': {ack.Status}{(string.IsNullOrEmpty(ack.Message) ? "" : " (" + ack.Message + ")")}.");

            int rev; string text;
            try
            {
                using var json = JsonDocument.Parse(ack.Result);
                rev = json.RootElement.GetProperty("rev").GetInt32();
                text = json.RootElement.GetProperty("text").GetString() ?? "";
                if (rev < 0 || text.Length > MaxDocumentChars || TextOperation.HasUnpairedSurrogate(text)) throw new FormatException();
            }
            catch (Exception e) when (e is JsonException or KeyNotFoundException or FormatException or InvalidOperationException)
            {
                throw new InvalidOperationException($"'{ownerId}' sent something that is not a document.");
            }

            var doc = new OtDocument(this, id, ownerId, isOwner: false) { Client = new OtClient(text, rev) };
            doc.Client!.Send = (_, __) => { doc.OutstandingSeq = ++doc.Seq; EnsurePump(doc); };   // called with the gate held
            if (!_docs.TryAdd(id, doc)) return _docs[id];

            await FetchAsync(doc, ct).ConfigureAwait(false);   // anything that happened between the snapshot and now
            return doc;
        }

        //Stops taking part in a document on this device (an owned document is dropped too: its other members can no longer reach it).
        public void Close(string id)
        {
            if (_docs.TryRemove(id, out var d)) d.Closed = true;
        }

        // ── editing (called by OtDocument) ───────────────────────────────────────

        internal void LocalEdit(OtDocument d, Func<string, TextOperation> build)
        {
            ThrowIfDisposed();
            OtChange change;
            OtDocument.OwnerBroadcast? send = null;
            lock (d.Gate)
            {
                if (d.Closed) throw new InvalidOperationException("That document is closed.");
                string text = d.IsOwner ? d.Server!.Document : d.Client!.Text;
                var op = build(text);
                if (op.BaseLength != text.Length) throw new OtException("The edit was made for a different text than the current one.");
                if (op.IsNoop) return;
                if (op.TargetLength > MaxDocumentChars) throw new OtException($"A document can hold at most {MaxDocumentChars} characters.");

                if (d.IsOwner)
                {
                    var applied = d.Server!.Receive(d.Server.Revision, op);
                    int rev = d.Server.Revision - 1;
                    var meta = new Meta(_node.ClientId, "", 0);
                    d.MetaByRevision[rev] = meta;
                    PruneMeta(d);
                    send = new OtDocument.OwnerBroadcast(rev, meta, applied, d.Subscribers.ToArray());
                    change = new OtChange(d.Id, d.Server.Document, applied, Remote: false, _node.ClientId);
                }
                else
                {
                    d.Client!.ApplyClient(op);
                    change = new OtChange(d.Id, d.Client.Text, op, Remote: false, _node.ClientId);
                }
            }
            d.RaiseChanged(change);
            if (send is { } s) FanOut(d, s);
        }

        private static void PruneMeta(OtDocument d)
        {
            int oldest = d.Server!.OldestRevision;
            if (d.MetaByRevision.Count <= d.Server.Revision - oldest + 8) return;
            foreach (var k in d.MetaByRevision.Keys.Where(k => k < oldest).ToList()) d.MetaByRevision.Remove(k);
        }

        // ── owner side: commands from other devices ──────────────────────────────

        private CommandResult HandleJoin(CommandContext ctx)
        {
            var id = ReadString(ctx.Payload, "doc");
            if (id is null || !_docs.TryGetValue(id, out var d) || !d.IsOwner) return CommandResult.Error("no such document");

            lock (d.Gate)
            {
                if (d.Subscribers.Count >= MaxSubscribers && !d.Subscribers.Contains(ctx.FromId)) return CommandResult.Error("too many devices have joined");
                d.Subscribers.Add(ctx.FromId);   // from now on this device gets every edit, starting after the snapshot below
                int rev = d.Server!.Revision;
                string text = d.Server.Document;
                return CommandResult.Ok(Write(w => { w.WriteNumber("rev", rev); w.WriteString("text", text); }));
            }
        }

        private CommandResult HandleOp(CommandContext ctx)
        {
            if (ctx.Payload.Length > MaxPayloadBytes) return Reject("the edit is too large");

            string? docId, sid; int rev, seq; string opJson;
            try
            {
                using var json = JsonDocument.Parse(ctx.Payload, new JsonDocumentOptions { MaxDepth = 8 });
                var root = json.RootElement;
                docId = root.GetProperty("doc").GetString();
                sid = root.GetProperty("sid").GetString();
                rev = root.GetProperty("rev").GetInt32();
                seq = root.GetProperty("seq").GetInt32();
                opJson = root.GetProperty("op").GetRawText();
            }
            catch (Exception e) when (e is JsonException or KeyNotFoundException or InvalidOperationException or FormatException)
            {
                return Reject("malformed edit");
            }
            if (docId is null || !_docs.TryGetValue(docId, out var d) || !d.IsOwner) return Reject("no such document");
            if (string.IsNullOrEmpty(sid) || sid.Length > 64 || seq < 1) return Reject("malformed edit");
            if (!TextOperation.TryFromJson(opJson, out var op, out var opError)) return Reject(opError ?? "malformed edit");

            string author = ctx.FromId;
            OtDocument.OwnerBroadcast send;
            OtChange change;
            int newRev;
            lock (d.Gate)
            {
                if (d.Writers is not null && !d.Writers.Contains(author)) return CommandResult.Denied("this device may not edit that document");

                string key = author + "|" + sid;
                if (d.LastFrom.TryGetValue(key, out var last))
                {
                    // a retry of an edit we already took (or an older one): answer as before, do nothing
                    if (seq <= last.Seq) return CommandResult.Ok(Write(w => w.WriteNumber("rev", last.Rev)));
                    if (seq != last.Seq + 1) return Reject("edits arrived out of order");
                }
                else if (seq != 1) return Reject("edits arrived out of order");

                if (op!.TargetLength - op.BaseLength + d.Server!.Document.Length > MaxDocumentChars) return Reject("the document would be too large");

                TextOperation applied;
                try { applied = d.Server.Receive(rev, op); }
                catch (OtResyncRequiredException) { return CommandResult.Error("resync: reload the document"); }
                catch (OtException e) { return Reject(e.Message); }

                newRev = d.Server.Revision - 1;
                var meta = new Meta(author, sid, seq);
                d.MetaByRevision[newRev] = meta;
                PruneMeta(d);
                if (d.LastFrom.Count >= MaxRemembered && !d.LastFrom.ContainsKey(key)) d.LastFrom.Clear();   // bounded; a forgotten device just resyncs
                d.LastFrom[key] = (seq, newRev);
                if (d.Subscribers.Count < MaxSubscribers) d.Subscribers.Add(author);

                send = new OtDocument.OwnerBroadcast(newRev, meta, applied, d.Subscribers.ToArray());
                change = new OtChange(d.Id, d.Server.Document, applied, Remote: true, author);
            }
            d.RaiseChanged(change);
            FanOut(d, send);
            return CommandResult.Ok(Write(w => w.WriteNumber("rev", newRev)));
        }

        private CommandResult HandleFetch(CommandContext ctx)
        {
            string? docId; int from;
            try
            {
                using var json = JsonDocument.Parse(ctx.Payload, new JsonDocumentOptions { MaxDepth = 4 });
                docId = json.RootElement.GetProperty("doc").GetString();
                from = json.RootElement.GetProperty("from").GetInt32();
            }
            catch (Exception e) when (e is JsonException or KeyNotFoundException or InvalidOperationException or FormatException)
            {
                return CommandResult.Error("malformed request");
            }
            if (docId is null || !_docs.TryGetValue(docId, out var d) || !d.IsOwner) return CommandResult.Error("no such document");

            lock (d.Gate)
            {
                var s = d.Server!;
                if (from > s.Revision || from < 0) return CommandResult.Error("that revision does not exist");
                if (from < s.OldestRevision)
                    return CommandResult.Ok(Write(w => { w.WriteBoolean("resync", true); w.WriteNumber("rev", s.Revision); w.WriteString("text", s.Document); }));

                var ops = s.OperationsFrom(from);
                return CommandResult.Ok(Write(w =>
                {
                    w.WriteBoolean("resync", false);
                    w.WriteNumber("rev", s.Revision);
                    w.WriteStartArray("ops");
                    int budget = FetchBatchChars;
                    for (int i = 0; i < ops.Count && budget > 0; i++)
                    {
                        d.MetaByRevision.TryGetValue(from + i, out var meta);
                        w.WriteStartObject();
                        WriteOpProperties(w, from + i, meta, ops[i], null);
                        w.WriteEndObject();
                        budget -= ops[i].TargetLength + ops[i].BaseLength / 8 + 64;
                    }
                    w.WriteEndArray();
                }));
            }
        }

        private void FanOut(OtDocument d, OtDocument.OwnerBroadcast b)
        {
            byte[] payload = Write(w => WriteOpProperties(w, b.Rev, b.Meta, b.Op, d.Id));
            foreach (var peer in b.To)
            {
                if (peer == _node.ClientId) continue;
                _ = Task.Run(async () =>
                {
                    // One quick try. A device that misses this, or is offline, catches up with "ot.fetch" the next time it hears from us.
                    try { await _node.SendCommandAsync(peer, "ot.apply", payload, new CommandOptions { Timeout = TimeSpan.FromSeconds(3), Retries = 0 }).ConfigureAwait(false); }
                    catch { }
                });
            }
        }

        // ── member side: edits arriving from the owner ───────────────────────────

        private CommandResult HandleApply(CommandContext ctx)
        {
            OtDocument? d = null;
            Incoming msg;
            try
            {
                using var json = JsonDocument.Parse(ctx.Payload, new JsonDocumentOptions { MaxDepth = 8 });
                var root = json.RootElement;
                var docId = root.GetProperty("doc").GetString();
                // Not one of our documents, or not sent by its owner: ignore quietly. Only the owner may order edits.
                if (docId is null || !_docs.TryGetValue(docId, out d) || d.IsOwner || d.OwnerId != ctx.FromId) return CommandResult.Ok();
                msg = ReadIncoming(root);
            }
            catch (Exception e) when (e is JsonException or KeyNotFoundException or InvalidOperationException or FormatException or OtException)
            {
                return CommandResult.Error("malformed edit");
            }

            ProcessIncoming(d!, new[] { msg });
            return CommandResult.Ok();
        }

        private static Incoming ReadIncoming(JsonElement el)
        {
            int rev = el.GetProperty("rev").GetInt32();
            string author = el.TryGetProperty("author", out var a) ? a.GetString() ?? "" : "";
            string sid = el.TryGetProperty("sid", out var s) ? s.GetString() ?? "" : "";
            int seq = el.TryGetProperty("seq", out var q) ? q.GetInt32() : 0;
            var op = TextOperation.FromJson(el.GetProperty("op").GetRawText());
            return new Incoming(rev, author, sid, seq, op);
        }

        // Applies edits in order; keeps early ones until their turn comes.
        private void ProcessIncoming(OtDocument d, IEnumerable<Incoming> batch)
        {
            var events = new List<OtChange>();
            bool needFetch = false, needResync = false;
            lock (d.Gate)
            {
                var c = d.Client!;
                foreach (var m in batch)
                {
                    if (m.Rev < c.Revision) continue;   // already have it
                    if (m.Rev > c.Revision)
                    {
                        if (d.Future.Count < MaxFuture) d.Future[m.Rev] = m;
                        needFetch = true;
                        continue;
                    }
                    if (!ApplyOne(d, m, events)) { needResync = true; break; }
                }
                // anything that arrived early and can go in now
                while (!needResync && d.Future.Count > 0)
                {
                    int first = d.Future.Keys.First();
                    if (first < c.Revision) { d.Future.Remove(first); continue; }
                    if (first > c.Revision) { needFetch = true; break; }
                    var m = d.Future[first]; d.Future.Remove(first);
                    if (!ApplyOne(d, m, events)) needResync = true;
                }
            }
            foreach (var e in events) d.RaiseChanged(e);
            if (needResync) _ = Task.Run(() => ResyncAsync(d, "the owner's edits could not be applied"));
            else if (needFetch) _ = Task.Run(() => FetchAsync(d, CancellationToken.None));
        }

        // Called with the gate held. False if the edit does not fit (this device's state cannot be reconciled).
        private bool ApplyOne(OtDocument d, Incoming m, List<OtChange> events)
        {
            var c = d.Client!;
            try
            {
                bool mine = m.Author == _node.ClientId && m.Sid == d.SessionId && c.HasPending && m.Seq == d.OutstandingSeq;
                if (mine) { c.ServerAck(); return true; }
                var applied = c.ApplyServer(m.Op);
                events.Add(new OtChange(d.Id, c.Text, applied, Remote: true, m.Author));
                return true;
            }
            catch (OtException) { return false; }
        }

        // ── catching up ──────────────────────────────────────────────────────────

        private async Task FetchAsync(OtDocument d, CancellationToken ct)
        {
            if (d.IsOwner || d.Closed) return;
            await d.FetchLock.WaitAsync(ct).ConfigureAwait(false);
            try
            {
                for (int round = 0; round < 50 && !d.Closed; round++)
                {
                    int from;
                    lock (d.Gate) from = d.Client!.Revision;
                    var ack = await _node.SendCommandAsync(d.OwnerId, "ot.fetch",
                        Write(w => { w.WriteString("doc", d.Id); w.WriteNumber("from", from); }), ct: ct).ConfigureAwait(false);
                    if (!ack.IsOk) return;   // owner unreachable: we try again the next time we hear from it

                    var ops = new List<Incoming>();
                    int ownerRev; bool resync; string? snapshot = null;
                    try
                    {
                        using var json = JsonDocument.Parse(ack.Result);
                        var root = json.RootElement;
                        ownerRev = root.GetProperty("rev").GetInt32();
                        resync = root.GetProperty("resync").GetBoolean();
                        if (resync) snapshot = root.GetProperty("text").GetString() ?? "";
                        else foreach (var el in root.GetProperty("ops").EnumerateArray()) ops.Add(ReadIncoming(el));
                    }
                    catch (Exception e) when (e is JsonException or KeyNotFoundException or InvalidOperationException or FormatException or OtException)
                    {
                        return;
                    }

                    if (resync) { ApplySnapshot(d, snapshot!, ownerRev); return; }

                    ProcessIncoming(d, ops);
                    lock (d.Gate) { if (d.Client!.Revision >= ownerRev || ops.Count == 0) return; }
                }
            }
            finally { d.FetchLock.Release(); }
        }

        // Replaces this device's text with the owner's. False if the owner could not be reached.
        private async Task<bool> ResyncAsync(OtDocument d, string why)
        {
            if (d.Closed) return false;
            var ack = await _node.SendCommandAsync(d.OwnerId, "ot.join", Write(w => w.WriteString("doc", d.Id))).ConfigureAwait(false);
            if (!ack.IsOk) return false;
            try
            {
                using var json = JsonDocument.Parse(ack.Result);
                return ApplySnapshot(d, json.RootElement.GetProperty("text").GetString() ?? "", json.RootElement.GetProperty("rev").GetInt32());
            }
            catch (Exception e) when (e is JsonException or KeyNotFoundException or InvalidOperationException) { return false; }
        }

        private static bool ApplySnapshot(OtDocument d, string text, int rev)
        {
            if (text.Length > MaxDocumentChars || TextOperation.HasUnpairedSurrogate(text)) return false;
            lock (d.Gate)
            {
                d.Client!.ResetTo(text, rev);
                d.Future.Clear();
            }
            d.RaiseResynced(text);
            d.RaiseChanged(new OtChange(d.Id, text, new TextOperation().Retain(text.Length), Remote: true, d.OwnerId));
            return true;
        }

        private void OnPeerConnected(PeerInfo p)
        {
            foreach (var d in _docs.Values.Where(x => !x.IsOwner && x.OwnerId == p.Id))
            {
                var doc = d;
                _ = Task.Run(async () =>
                {
                    await FetchAsync(doc, CancellationToken.None).ConfigureAwait(false);
                    EnsurePump(doc);   // resend an edit that was waiting for the owner to come back
                });
            }
        }

        // ── sending our edits to the owner ───────────────────────────────────────

        // Safe to call with or without the gate held (it is re-entrant). Starts the sender if an edit is waiting and none is running.
        private void EnsurePump(OtDocument d)
        {
            bool start;
            lock (d.Gate)
            {
                start = !d.PumpRunning && !d.Closed && d.Client!.Outstanding is not null;
                if (start) d.PumpRunning = true;
            }
            if (start) _ = Task.Run(() => PumpAsync(d));
        }

        private async Task PumpAsync(OtDocument d)
        {
            var delay = TimeSpan.FromMilliseconds(150);
            try
            {
                while (!d.Closed && Volatile.Read(ref _disposed) == 0)
                {
                    int rev, seq; TextOperation op;
                    lock (d.Gate)
                    {
                        var o = d.Client!.Outstanding;
                        if (o is null) return;
                        (rev, op) = o.Value;
                        seq = d.OutstandingSeq;
                    }

                    byte[] payload = Write(w =>
                    {
                        w.WriteString("doc", d.Id); w.WriteString("sid", d.SessionId);
                        w.WriteNumber("rev", rev); w.WriteNumber("seq", seq);
                        w.WritePropertyName("op"); w.WriteRawValue(op.ToJson());
                    });

                    var ack = await _node.SendCommandAsync(d.OwnerId, "ot.op", payload).ConfigureAwait(false);

                    if (ack.IsOk)
                    {
                        await FetchAsync(d, CancellationToken.None).ConfigureAwait(false);   // brings back our own edit (as its confirmation) and anything we missed
                        bool stillWaiting;
                        lock (d.Gate) stillWaiting = d.Client!.Outstanding is not null && d.OutstandingSeq == seq;
                        if (!stillWaiting) { delay = TimeSpan.FromMilliseconds(150); continue; }
                    }
                    else if (ack.Status == AckStatus.Denied || (ack.Status == AckStatus.Error && (ack.Message ?? "").StartsWith("rejected", StringComparison.Ordinal)))
                    {
                        // The owner will never take this edit: tell the app, then show the owner's text instead of ours.
                        d.RaiseRejected(ack.Message ?? "the owner refused the edit");
                        for (int attempt = 0; attempt < 20 && !d.Closed; attempt++)
                        {
                            if (await ResyncAsync(d, "an edit was rejected").ConfigureAwait(false)) break;
                            await Task.Delay(500).ConfigureAwait(false);
                        }
                        return;
                    }
                    else if (ack.Status == AckStatus.Error && (ack.Message ?? "").StartsWith("resync", StringComparison.Ordinal))
                    {
                        await ResyncAsync(d, "the owner asked this device to reload").ConfigureAwait(false);
                        continue;
                    }

                    // the owner is away, busy, or slow: wait and send the same edit again (it cannot be applied twice)
                    await Task.Delay(delay).ConfigureAwait(false);
                    delay = TimeSpan.FromMilliseconds(Math.Min(delay.TotalMilliseconds * 2, 5_000));
                }
            }
            catch (ObjectDisposedException) { }
            finally
            {
                lock (d.Gate) d.PumpRunning = false;
                EnsurePump(d);   // an edit may have arrived just as we were finishing
            }
        }

        // ── small helpers ────────────────────────────────────────────────────────

        // The properties of one accepted edit: where it sits in the order, who made it, and the edit itself.
        private static void WriteOpProperties(Utf8JsonWriter w, int rev, Meta meta, TextOperation op, string? docId)
        {
            if (docId is not null) w.WriteString("doc", docId);
            w.WriteNumber("rev", rev);
            w.WriteString("author", meta.Author ?? "");
            w.WriteString("sid", meta.Sid ?? "");
            w.WriteNumber("seq", meta.Seq);
            w.WritePropertyName("op");
            w.WriteRawValue(op.ToJson());
        }

        // One JSON object: the callback writes its properties.
        private static byte[] Write(Action<Utf8JsonWriter> properties)
        {
            var buffer = new ArrayBufferWriter<byte>();
            using (var w = new Utf8JsonWriter(buffer, WriterOptions))
            {
                w.WriteStartObject();
                properties(w);
                w.WriteEndObject();
            }
            return buffer.WrittenSpan.ToArray();
        }

        private static string? ReadString(byte[] payload, string name)
        {
            try
            {
                using var json = JsonDocument.Parse(payload, new JsonDocumentOptions { MaxDepth = 4 });
                return json.RootElement.GetProperty(name).GetString();
            }
            catch (Exception e) when (e is JsonException or KeyNotFoundException or InvalidOperationException) { return null; }
        }

        private static CommandResult Reject(string why) => CommandResult.Error("rejected: " + why);

        private static void ValidateId(string id)
        {
            if (string.IsNullOrWhiteSpace(id) || id.Length > 128 || id.Any(char.IsControl))
                throw new ArgumentException("A document id is 1-128 characters with no control characters.", nameof(id));
        }

        private void ThrowIfDisposed()
        {
            if (Volatile.Read(ref _disposed) != 0) throw new ObjectDisposedException(nameof(OtSession));
        }

        public void Dispose()
        {
            if (Interlocked.Exchange(ref _disposed, 1) != 0) return;
            _node.PeerConnected -= OnPeerConnected;
            foreach (var n in new[] { "ot.join", "ot.op", "ot.apply", "ot.fetch" }) _node.Off(n);
            foreach (var d in _docs.Values) d.Closed = true;
            _docs.Clear();
        }
    }
}
