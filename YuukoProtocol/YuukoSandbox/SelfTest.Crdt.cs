using System.Text;
using YuukoProtocol;
using YuukoProtocol.Dogma;
using static YuukoProtocol.Dogma.SimpleCRDT;

namespace YuukoSandbox;

public static partial class SelfTest
{
    private static byte[] CrdtFrame(string metaJson, byte[]? payload = null)
    {
        byte[] header = Encoding.UTF8.GetBytes(metaJson);
        var all = new byte[4 + header.Length + (payload?.Length ?? 0)];
        System.Buffers.Binary.BinaryPrimitives.WriteInt32BigEndian(all, header.Length);
        header.CopyTo(all, 4);
        payload?.CopyTo(all, 4 + header.Length);
        return all;
    }

    private static async Task CrdtTests()
    {
        Section("shared documents that merge by themselves (CRDT, YDotNet)");
        using var bus = new LocalBroker();
        var (n, _) = await Group(bus, new[] { "a", "b", "c" }, new[] { ("a", "b"), ("a", "c"), ("b", "c") });
        using var sa = new DocSync(n["a"]);
        using var sb = new DocSync(n["b"]);
        using var sc = new DocSync(n["c"]);
        sa.AntiEntropyInterval = sb.AntiEntropyInterval = sc.AntiEntropyInterval = TimeSpan.FromSeconds(1);   // quick safety net, so a lost message heals within seconds
        try
        {
            var received = new List<string>();
            sb.DocReceived += d => { lock (received) received.Add(d.UUID); };

            var doc = new SharedDocs("a", "Shopping list", DateTime.UtcNow, null);
            doc.CreateLabel("items", "milk\n");
            doc.CreateLabel("notes", null);
            ulong hashBefore = doc.ContentHash;
            doc.AddToLabel("items", "eggs\n");
            Check("the content hash is kept and changes with the content", doc.ContentHash != 0 && doc.ContentHash != hashBefore);

            await sa.ShareAsync(doc);
            Check("sharing a document gives it to every connected device", await Eventually(() => sb.Docs.ContainsKey(doc.UUID) && sc.Docs.ContainsKey(doc.UUID), 5000));
            var onB = sb.Docs[doc.UUID]; var onC = sc.Docs[doc.UUID];
            Check("...with the same name, owner, labels and text", onB.LabelName == "Shopping list" && onB.DeviceName == "a" && onB.TextLabels.SetEquals(new[] { "items", "notes" })
                && onB.ReadLabel("items") == "milk\neggs\n" && onC.ReadLabel("items") == "milk\neggs\n");
            Check("...and the other devices were told", received.Contains(doc.UUID));
            Check("the copies have the same fingerprint", onB.ContentHash == doc.ContentHash && onC.ContentHash == doc.ContentHash);

            // Changes travel by themselves.
            onB.AddToLabel("items", "bread\n");
            Check("a change made on one device reaches the others without anyone sending it", await Eventually(() => doc.ReadLabel("items") == "milk\neggs\nbread\n" && onC.ReadLabel("items") == "milk\neggs\nbread\n", 5000));
            int sentByA = sa.UpdatesSent, sentByC = sc.UpdatesSent;
            await Task.Delay(300);
            Check("a change that was merged in is not sent on again (no echo)", sa.UpdatesSent == sentByA && sc.UpdatesSent == sentByC && sb.UpdatesSent == 1);

            // Everybody at once, no coordination.
            await Task.WhenAll(
                Task.Run(() => { for (int i = 0; i < 20; i++) doc.AddToLabel("notes", $"A{i};"); }),
                Task.Run(() => { for (int i = 0; i < 20; i++) onB.AddToLabel("notes", $"B{i};"); }),
                Task.Run(() => { for (int i = 0; i < 20; i++) onC.AddToLabel("notes", $"C{i};"); }));
            Check("three devices editing the same text at once end with identical text", await Eventually(() =>
                doc.ReadLabel("notes") == onB.ReadLabel("notes") && onB.ReadLabel("notes") == onC.ReadLabel("notes") && doc.ReadLabel("notes").Length > 100, 10000));
            string merged = doc.ReadLabel("notes");
            Check("...and nothing anyone typed is missing", Enumerable.Range(0, 20).All(i => merged.Contains($"A{i};") && merged.Contains($"B{i};") && merged.Contains($"C{i};")));
            Check("...and the fingerprints match", await Eventually(() => doc.ContentHash == onB.ContentHash && onB.ContentHash == onC.ContentHash, 3000));

            // Documents made at the same instant must never share an internal id (YDotNet's default does, about 6 times in 100).
            var ids = new HashSet<ulong>();
            int clashes = 0;
            for (int i = 0; i < 3_000; i++)
            {
                using var x = SimpleCRDT.NewDoc();
                if (!ids.Add(x.Id)) clashes++;
            }
            Check($"documents made back to back never share an internal id ({clashes} clashes in 3000)", clashes == 0);
            Check("a document made through SharedDocs gets such an id too", new SharedDocs("a", "x", DateTime.UtcNow, null).Data.Id != new SharedDocs("a", "x", DateTime.UtcNow, null).Data.Id);

            // A device that was away (and edited while away) catches up, and so does everyone else.
            // The periodic comparison is switched off here: only comparing on reconnect, and passing on what was learned, can do the work.
            sa.AntiEntropyInterval = sb.AntiEntropyInterval = sc.AntiEntropyInterval = TimeSpan.Zero;
            await GoAway(n["a"], "a", n["b"], "b");
            await GoAway(n["c"], "c", n["b"], "b");   // c cannot relay for it either
            doc.AddToLabel("items", "while-b-was-away\n");
            onB.AddToLabel("items", "b-edited-offline\n");
            await Task.Delay(300);
            Check("(setup) the absent device has not seen the edit", !onB.ReadLabel("items").Contains("while-b-was-away"));
            ComeBack(n["a"], "a", n["b"], "b");
            ComeBack(n["c"], "c", n["b"], "b");
            await n["b"].PingAsync("a");   // reconnecting is what starts the catch-up
            Check("when it reconnects both sides get what they were missing", await Eventually(() =>
                doc.ReadLabel("items").Contains("b-edited-offline") && onB.ReadLabel("items").Contains("while-b-was-away") && doc.ReadLabel("items") == onB.ReadLabel("items"), 10000));
            Check("...and the third device gets it too", await Eventually(() => onC.ReadLabel("items") == doc.ReadLabel("items"), 10000));

            sa.AntiEntropyInterval = sb.AntiEntropyInterval = sc.AntiEntropyInterval = TimeSpan.FromSeconds(1);

            // A document only one device had (shared while the other was away).
            await GoAway(n["a"], "a", n["c"], "c");
            await GoAway(n["b"], "b", n["c"], "c");
            var late = new SharedDocs("a", "Made while c was away", DateTime.UtcNow, null);
            late.CreateLabel("body", "written offline");
            await sa.ShareAsync(late);
            await Task.Delay(300);
            Check("(setup) the absent device does not have the new document", !sc.Docs.ContainsKey(late.UUID));
            ComeBack(n["a"], "a", n["c"], "c");
            ComeBack(n["b"], "b", n["c"], "c");
            await n["c"].PingAsync("a");
            Check("a document made while a device was away arrives when it returns", await Eventually(() => sc.Docs.ContainsKey(late.UUID) && sc.Docs[late.UUID].ReadLabel("body") == "written offline", 10000));

            // Comparing notes on demand.
            Check("SyncWithAsync reports success", await sb.SyncWithAsync("a") && await sa.SyncWithAsync("c"));
            Check("SyncAllAsync reaches every connected device", await sa.SyncAllAsync() == 2);

            // Removal.
            Check("only the creator may remove a document", await Throws2<InvalidOperationException>(() => sb.RemoveAsync(doc.UUID)));
            var forgedRemove = await n["b"].SendCommandAsync("a", "crdt.remove", CrdtFrame($"{{\"uuid\":\"{doc.UUID.Replace("\\", "\\\\").Replace("\"", "\\\"")}\"}}"));
            Check("...and a removal forged by another device is refused", forgedRemove.Status == AckStatus.Denied && sa.Docs.ContainsKey(doc.UUID));
            var gone = new List<string>();
            sb.DocRemoved += (u, by) => gone.Add(u + "/" + by);
            await sa.RemoveAsync(late.UUID);
            Check("removing a document removes it on every device", await Eventually(() => !sa.Docs.ContainsKey(late.UUID) && !sb.Docs.ContainsKey(late.UUID) && !sc.Docs.ContainsKey(late.UUID), 5000));
            Check("...and the others are told who removed it", gone.Any(g => g.EndsWith("/a")));
            await sb.SyncWithAsync("a"); await sc.SyncWithAsync("a");
            Check("a removed document does not come back when devices compare notes", !sa.Docs.ContainsKey(late.UUID) && !sb.Docs.ContainsKey(late.UUID));
            Check("a removed document cannot be shared again", await Throws2<InvalidOperationException>(() => sa.ShareAsync(late)));

            // A removal claim about a document nobody here has seen can't be checked, so it must not be remembered (or anyone could block a real document before it exists).
            var unseen = new SharedDocs("a", "Not made yet", DateTime.UtcNow, null);
            var claimed = await n["b"].SendCommandAsync("a", "crdt.remove", CrdtFrame($"{{\"uuid\":\"{unseen.UUID.Replace("\\", "\\\\").Replace("\"", "\\\"")}\"}}"));
            Check("a removal claim about an unknown document is not an error", claimed.IsOk);
            bool shared = true;
            try { await sa.ShareAsync(unseen); } catch (InvalidOperationException) { shared = false; }
            Check("...but it does not stop the real owner from sharing that document later", shared && sa.Docs.ContainsKey(unseen.UUID));
            await sa.RemoveAsync(unseen.UUID);

            // Bad input: refused, never a crash, never changes a document.
            string uuid = doc.UUID.Replace("\\", "\\\\").Replace("\"", "\\\"");
            string itemsBefore = doc.ReadLabel("items");
            string meta = $"{{\"uuid\":\"{uuid}\",\"name\":\"x\",\"owner\":\"a\",\"labels\":[\"items\"]}}";
            var garbageUpdate = await n["b"].SendCommandAsync("a", "crdt.update", CrdtFrame(meta, new byte[] { 1, 2, 3, 4, 5, 250, 251 }));
            Check("random bytes sent as a document update are refused", garbageUpdate.Status == AckStatus.Error && doc.ReadLabel("items") == itemsBefore);
            foreach (var command in new[] { "crdt.announce", "crdt.update", "crdt.push", "crdt.remove", "crdt.sync" })
            {
                var junk = await n["b"].SendCommandAsync("a", command, Encoding.UTF8.GetBytes("junk"));
                var lie = await n["b"].SendCommandAsync("a", command, new byte[] { 0x7f, 0xff, 0xff, 0xff, 1, 2, 3 });
                if (junk.Status != AckStatus.Error || lie.Status != AckStatus.Error) { Check($"{command} refuses junk", false); }
            }
            Check("junk sent to every sync command is refused with an error, never a crash", true);
            var tooMany = "[" + string.Join(",", Enumerable.Range(0, DocSync.MaxLabels + 5).Select(i => $"\"l{i}\"")) + "]";
            var flood = await n["b"].SendCommandAsync("a", "crdt.announce", CrdtFrame($"{{\"uuid\":\"flood\",\"name\":\"x\",\"owner\":\"b\",\"labels\":{tooMany}}}"));
            Check("a document with too many labels is refused", flood.Status == AckStatus.Error && !sa.Docs.ContainsKey("flood"));
            var badName = await n["b"].SendCommandAsync("a", "crdt.announce", CrdtFrame($"{{\"uuid\":\"{new string('u', 70)}\",\"name\":\"x\",\"owner\":\"b\",\"labels\":[]}}"));
            Check("an over-long document id is refused", badName.Status == AckStatus.Error);
            var ghost = await n["b"].SendCommandAsync("a", "crdt.update", CrdtFrame("{\"uuid\":\"never-heard-of\",\"name\":\"x\",\"owner\":\"b\",\"labels\":[]}"));
            Check("an update for a document we have never seen does not create one", ghost.IsOk && !sa.Docs.ContainsKey("never-heard-of"));
            Check("sharing a document with no id is refused", await Throws2<ArgumentException>(() => sa.ShareAsync(new SharedDocs { UUID = "" })));
        }
        finally { foreach (var x in n.Values) x.Dispose(); }
    }
}
