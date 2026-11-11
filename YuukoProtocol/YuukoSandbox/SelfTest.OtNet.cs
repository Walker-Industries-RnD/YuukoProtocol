using System.Text;
using YuukoProtocol;
using YuukoProtocol.Dogma;

namespace YuukoSandbox;

// Tests for shared text documents (OtSession) and shared Yjs documents (DocSync) between real nodes.
public static partial class SelfTest
{
    private static int CountOf(string text, string token)
    {
        int n = 0, at = 0;
        while ((at = text.IndexOf(token, at, StringComparison.Ordinal)) >= 0) { n++; at += token.Length; }
        return n;
    }

    private static async Task OtNetworkTests()
    {
        Section("shared text documents over the network (operational transform)");
        using var bus = new LocalBroker();
        var (n, _) = await Group(bus, new[] { "pc", "phone", "tablet" }, new[] { ("pc", "phone"), ("pc", "tablet"), ("phone", "tablet") });
        using var spc = new OtSession(n["pc"]);
        using var sph = new OtSession(n["phone"]);
        using var stb = new OtSession(n["tablet"]);
        try
        {
            var owner = spc.Create("notes", "hello");
            var phone = await sph.JoinAsync("pc", "notes");
            var tablet = await stb.JoinAsync("pc", "notes");
            Check("devices that join get the owner's text and revision", phone.Text == "hello" && tablet.Text == "hello" && phone.Revision == 0 && owner.IsOwner && !phone.IsOwner);
            Check("joining the same document again returns the same one", await sph.JoinAsync("pc", "notes") == phone);

            phone.Insert(5, " world");
            Check("an edit is confirmed by the owner", await phone.WaitUntilSyncedAsync(TimeSpan.FromSeconds(5)));
            Check("...and reaches every device", await Eventually(() => owner.Text == "hello world" && tablet.Text == "hello world" && phone.Text == "hello world", 5000));
            Check("every device agrees on the revision", await Eventually(() => owner.Revision == 1 && phone.Revision == 1 && tablet.Revision == 1, 5000));

            // The simple public API (OpTransform.SharedText) over the same documents.
            var simpleOwner = OpTransform.Wrap(owner);
            var simplePhone = OpTransform.Wrap(phone);
            var simpleSeen = new List<string>();
            simplePhone.Changed += (text, remote, author) => { lock (simpleSeen) simpleSeen.Add(remote + "/" + author); };
            Check("the simple API shows the same text, name and sync state", simpleOwner.Text == owner.Text && simplePhone.Name == "notes" && simplePhone.IsSynced);
            Check("wrapping a document twice gives the same object", OpTransform.Wrap(phone) == simplePhone);
            simpleOwner.Replace(0, 5, "HELLO");
            Check("an edit through the simple API reaches the others and fires Changed once per wrapper", await Eventually(() => simplePhone.Text.StartsWith("HELLO"), 5000) && simpleSeen.Count == 1 && simpleSeen[0] == "True/pc");
            simplePhone.SetText(simplePhone.Text + "!");
            Check("SetText and WaitUntilSynced work through the simple API", await simplePhone.WaitUntilSynced(TimeSpan.FromSeconds(5)) && await Eventually(() => owner.Text.EndsWith("!"), 5000));
            simpleOwner.Replace(0, 5, "hello");
            simplePhone.SetText(simplePhone.Text.TrimEnd('!'));
            Check("(setup) text put back as it was", await Eventually(() => owner.Text == "hello world" && tablet.Text == "hello world" && phone.Text == "hello world", 5000));

            // The owner edits too.
            var seen = new List<OtChange>();
            tablet.Changed += c => { lock (seen) seen.Add(c); };
            owner.Insert(0, ">> ");
            Check("an edit by the owner reaches the others, marked as remote", await Eventually(() => tablet.Text == ">> hello world" && seen.Any(c => c.Remote && c.Author == "pc"), 5000));

            // Everybody typing at once.
            var rnd = new Random(2026);
            string[] who = { "P", "T", "O" };
            var docs = new[] { phone, tablet, owner };
            var tokens = new List<string>();
            var work = docs.Select((doc, i) => Task.Run(() =>
            {
                for (int k = 0; k < 25; k++)
                {
                    string token = $"[{who[i]}{k}]";
                    lock (tokens) tokens.Add(token);
                    int at; lock (rnd) at = rnd.Next(doc.Text.Length + 1);
                    doc.Insert(Math.Min(at, doc.Text.Length), token);
                    Thread.Sleep(2);
                }
            })).ToArray();
            await Task.WhenAll(work);
            Check("(setup) everybody finished typing", await phone.WaitUntilSyncedAsync(TimeSpan.FromSeconds(10)) && await tablet.WaitUntilSyncedAsync(TimeSpan.FromSeconds(10)));
            Check("three devices typing at once end with exactly the same text", await Eventually(() => phone.Text == owner.Text && tablet.Text == owner.Text, 8000));
            string final = owner.Text;
            // (A later insert can land INSIDE an earlier token, so compare the characters, not the tokens.)
            string expectedChars = new string((">> hello world" + string.Concat(tokens)).OrderBy(c => c).ToArray());
            Check("...and nothing anyone typed was lost or doubled (every character is there exactly once)", tokens.Count == 75 && new string(final.OrderBy(c => c).ToArray()) == expectedChars);
            bool InOrder(string text, string sub) { int at = 0; foreach (var ch in text) if (at < sub.Length && ch == sub[at]) at++; return at == sub.Length; }
            Check("...and the older text is still there, in order", InOrder(final, ">> hello world"));

            // Typing and deleting at once.
            var mixed = docs.Select((doc, i) => Task.Run(() =>
            {
                var r = new Random(100 + i);
                for (int k = 0; k < 30; k++)
                {
                    try
                    {
                        int len = doc.Text.Length;
                        if (r.Next(3) == 0 && len > 3) doc.Delete(r.Next(len - 2), r.Next(1, 3));
                        else doc.Insert(r.Next(len + 1), "·" + i);
                    }
                    catch (ArgumentOutOfRangeException) { /* the text changed under us; try the next one */ }
                    Thread.Sleep(1);
                }
            })).ToArray();
            await Task.WhenAll(mixed);
            await phone.WaitUntilSyncedAsync(TimeSpan.FromSeconds(10)); await tablet.WaitUntilSyncedAsync(TimeSpan.FromSeconds(10));
            Check("typing and deleting at once also ends the same everywhere", await Eventually(() => phone.Text == owner.Text && tablet.Text == owner.Text, 8000));

            // SetText: all a text box gives you is the new contents.
            phone.SetText("a brand new text");
            await phone.WaitUntilSyncedAsync(TimeSpan.FromSeconds(5));
            bool setOk = await Eventually(() => owner.Text == "a brand new text" && tablet.Text == "a brand new text", 5000);
            if (!setOk) Console.WriteLine($"   DEBUG owner='{owner.Text}' rev={owner.Revision} | tablet='{tablet.Text}' rev={tablet.Revision} pending={tablet.HasPending} | phone='{phone.Text}' rev={phone.Revision} pending={phone.HasPending}");
            Check("SetText works out the smallest edit itself", setOk);

            // Retries never apply an edit twice, and bad edits are refused.
            owner.SetText("");
            await Eventually(() => phone.Text == "" && tablet.Text == "", 3000);
            var dedupe = spc.Create("d2", "");
            byte[] Op(string doc, string sid, int rev, int seq, string op) =>
                Encoding.UTF8.GetBytes($"{{\"doc\":\"{doc}\",\"sid\":\"{sid}\",\"rev\":{rev},\"seq\":{seq},\"op\":{op}}}");
            var first = await n["phone"].SendCommandAsync("pc", "ot.op", Op("d2", "s1", 0, 1, "[\"abc\"]"));
            var again = await n["phone"].SendCommandAsync("pc", "ot.op", Op("d2", "s1", 0, 1, "[\"abc\"]"));
            Check("the same edit sent twice (a retry after a lost reply) is applied once", first.IsOk && again.IsOk && dedupe.Text == "abc" && dedupe.Revision == 1);
            Check("...and both answers name the same revision", first.ResultAsString() == again.ResultAsString());
            Check("an edit that skips a number is refused", (await n["phone"].SendCommandAsync("pc", "ot.op", Op("d2", "s1", 1, 3, "[3,\"x\"]"))).Status == AckStatus.Error && dedupe.Text == "abc");
            Check("an edit for the wrong text length is refused", (await n["phone"].SendCommandAsync("pc", "ot.op", Op("d2", "s1", 1, 2, "[9,\"x\"]"))).Status == AckStatus.Error && dedupe.Text == "abc");
            Check("a malformed edit is refused", (await n["phone"].SendCommandAsync("pc", "ot.op", Op("d2", "s1", 1, 2, "[0]"))).Status == AckStatus.Error);
            Check("an edit for a document that does not exist is refused", (await n["phone"].SendCommandAsync("pc", "ot.op", Op("nope", "s1", 0, 1, "[\"x\"]"))).Status == AckStatus.Error);
            Check("garbage instead of an edit is refused, not a crash", (await n["phone"].SendCommandAsync("pc", "ot.op", Encoding.UTF8.GetBytes("not json"))).Status == AckStatus.Error);
            Check("an edit that would make the document too large is refused",
                (await n["phone"].SendCommandAsync("pc", "ot.op", Op("d2", "s2", 1, 1, "[3,\"" + new string('x', OtSession.MaxDocumentChars) + "\"]"))).Status == AckStatus.Error && dedupe.Text == "abc");
            Check("joining a document that does not exist is an error", await Throws2<InvalidOperationException>(() => sph.JoinAsync("pc", "missing")));
            Check("a document cannot be created twice", Catch(() => spc.Create("notes")) is InvalidOperationException);
            Check("a document cannot start with half an emoji", Catch(() => spc.Create("bad", "\ud83d")) is OtException);
            Check("a document id must be sensible", Catch(() => spc.Create("")) is ArgumentException && Catch(() => spc.Create("bad\nid")) is ArgumentException);
            Check("a text longer than the limit is refused", Catch(() => spc.Create("big", new string('x', OtSession.MaxDocumentChars + 1))) is OtException);

            // Only the owner may order edits.
            string before = tablet.Text;
            string forged = $"{{\"doc\":\"notes\",\"rev\":{tablet.Revision},\"author\":\"pc\",\"sid\":\"\",\"seq\":0,\"op\":[{before.Length},\"EVIL\"]}}";
            await n["phone"].SendCommandAsync("tablet", "ot.apply", Encoding.UTF8.GetBytes(forged));
            await Task.Delay(200);
            Check("an edit that claims to come from the owner but was sent by another device is ignored", tablet.Text == before);
            Check("garbage sent as an owner edit is refused, not a crash", (await n["phone"].SendCommandAsync("tablet", "ot.apply", Encoding.UTF8.GetBytes("{\"doc\":"))).Status == AckStatus.Error);
            Check("the forged edit really was delivered (and ignored), not lost on the way", (await n["phone"].SendCommandAsync("tablet", "ot.apply", Encoding.UTF8.GetBytes(forged))).IsOk);

            // Emoji across the wire.
            var emo = spc.Create("emo", "a😀b");
            var emoPhone = await sph.JoinAsync("pc", "emo");
            emoPhone.Insert(1, "👍🏽");
            await emoPhone.WaitUntilSyncedAsync(TimeSpan.FromSeconds(5));
            Check("emoji go through intact", await Eventually(() => emo.Text == "a👍🏽😀b", 5000));
            Check("an edit that would cut an emoji in half is refused on the device, before it is sent", Catch(() => emoPhone.Delete(1, 1)) is OtException && emoPhone.Text == "a👍🏽😀b");
            Check("an edit past the end of the text is refused", Catch(() => emoPhone.Insert(999, "x")) is ArgumentOutOfRangeException);

            // Who may write.
            var locked = spc.Create("locked", "owner's text", writers: new[] { "phone" });
            var lockedPhone = await sph.JoinAsync("pc", "locked");
            var lockedTablet = await stb.JoinAsync("pc", "locked");
            string? rejectedWhy = null; bool resynced = false;
            lockedTablet.Rejected += why => rejectedWhy = why;
            lockedTablet.Resynced += _ => resynced = true;
            lockedTablet.Insert(0, "sneaky ");
            Check("a device that may not write sees its edit refused...", await Eventually(() => rejectedWhy is not null, 5000));
            Check("...and its text goes back to the owner's", await Eventually(() => lockedTablet.Text == "owner's text" && resynced, 5000));
            lockedPhone.Insert(0, "ok ");
            Check("a device that may write can", await Eventually(() => locked.Text == "ok owner's text" && lockedTablet.Text == "ok owner's text", 5000));
            locked.Insert(0, "!");
            Check("the owner never needs to be listed", await Eventually(() => lockedPhone.Text.StartsWith("!"), 5000));

            // A device that was away catches up when it is back.
            var away = spc.Create("away", "start");
            var awayTablet = await stb.JoinAsync("pc", "away");
            await GoAway(n["pc"], "pc", n["tablet"], "tablet");
            for (int i = 0; i < 4; i++) away.Insert(away.Text.Length, $" e{i}");
            await Task.Delay(300);
            Check("(setup) the absent device has not seen the edits", awayTablet.Text == "start");
            ComeBack(n["pc"], "pc", n["tablet"], "tablet");
            awayTablet.Insert(0, "[tablet was away] ");          // and it edits while away: this must not be lost
            await n["tablet"].PingAsync("pc");                    // reconnecting is what makes it catch up
            Check("when it reconnects it catches up on everything it missed", await Eventually(() => awayTablet.Text.Contains("e3") && away.Text.Contains("e3"), 10000));
            await awayTablet.WaitUntilSyncedAsync(TimeSpan.FromSeconds(10));
            Check("...and the edit it made while away is kept and sent", await Eventually(() => away.Text == awayTablet.Text && away.Text.Contains("[tablet was away]"), 10000));

            // Closing.
            sph.Close("notes");
            Check("a closed document refuses edits", Catch(() => phone.Insert(0, "x")) is InvalidOperationException && sph.Get("notes") is null);
        }
        finally { foreach (var x in n.Values) x.Dispose(); }
    }

    // Two devices that cannot reach each other: each refuses the other (one side alone is not enough, a device can connect either way).
    private static async Task GoAway(EclipseBroker a, string aId, EclipseBroker b, string bId)
    {
        await a.KickAsync(bId, ban: true, reason: "away");
        await b.KickAsync(aId, ban: true, reason: "away");
    }

    private static void ComeBack(EclipseBroker a, string aId, EclipseBroker b, string bId)
    {
        a.Unban(bId);
        b.Unban(aId);
    }

    private static async Task<bool> Throws2<T>(Func<Task> f) where T : Exception
    {
        try { await f(); return false; } catch (T) { return true; } catch { return false; }
    }
}
