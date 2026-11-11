using YuukoProtocol;
using YuukoProtocol.Dogma;

namespace YuukoSandbox;

// Tests for Operational Transformation: the algebra (randomized), the server, the client state machine, and whole sessions
// simulated with messages arriving in random orders.
public static partial class SelfTest
{
    // Whole characters, never half of an emoji (an emoji is two UTF-16 units, and JSON cannot carry half of one).
    private static readonly string[] OtTokens = { "a", "b", "c", " ", "X", "Y", "Z", "é", "\n", "😀", "👍🏽" };

    private static string RandomOtText(Random r, int maxChars)
    {
        int n = r.Next(0, maxChars + 1);
        var sb = new System.Text.StringBuilder();
        for (int i = 0; i < n; i++) sb.Append(OtTokens[r.Next(OtTokens.Length)]);
        return sb.ToString();
    }

    // Positions in `doc` where an edit may start or stop: everywhere except between the two halves of an emoji.
    private static List<int> OtCutPoints(string doc)
    {
        var cuts = new List<int> { 0 };
        for (int i = 1; i <= doc.Length; i++)
            if (!(i < doc.Length && char.IsLowSurrogate(doc[i]) && char.IsHighSurrogate(doc[i - 1]))) cuts.Add(i);
        return cuts;
    }

    // A random edit that covers the whole of `doc`.
    private static TextOperation RandomOtOp(Random r, string doc)
    {
        var cuts = OtCutPoints(doc);
        var op = new TextOperation();
        int at = 0;   // index into `cuts`
        while (cuts[at] < doc.Length)
        {
            int next = Math.Min(at + r.Next(1, 7), cuts.Count - 1);
            int k = cuts[next] - cuts[at];
            switch (r.Next(3))
            {
                case 0: op.Retain(k); at = next; break;
                case 1: op.Delete(k); at = next; break;
                default: op.Insert(RandomOtText(r, 3)); break;
            }
        }
        if (r.Next(3) == 0) op.Insert(RandomOtText(r, 2));
        return op;
    }

    private static void OtAlgebra()
    {
        Section("operational transform: the algebra (randomized)");
        var r = new Random(20260108);

        int tp1Bad = 0, composeBad = 0, invertBad = 0;
        const int cases = 20_000;
        for (int i = 0; i < cases; i++)
        {
            string doc = RandomOtText(r, 30);
            var a = RandomOtOp(r, doc);
            var b = RandomOtOp(r, doc);

            var (a1, b1) = TextOperation.Transform(a, b);
            if (b1.Apply(a.Apply(doc)) != a1.Apply(b.Apply(doc))) tp1Bad++;

            var next = RandomOtOp(r, a.Apply(doc));
            if (TextOperation.Compose(a, next).Apply(doc) != next.Apply(a.Apply(doc))) composeBad++;

            if (a.Invert(doc).Apply(a.Apply(doc)) != doc) invertBad++;
        }
        Check($"two edits made at the same time end in the same text either way round ({cases} random cases, {tp1Bad} wrong)", tp1Bad == 0);
        Check($"composing two edits equals making them one after the other ({cases} random cases, {composeBad} wrong)", composeBad == 0);
        Check($"an edit's inverse puts the text back ({cases} random cases, {invertBad} wrong)", invertBad == 0);

        // Composition and transformation keep working across three edits.
        int threeBad = 0;
        for (int i = 0; i < 5_000; i++)
        {
            string doc = RandomOtText(r, 20);
            var a = RandomOtOp(r, doc); var b = RandomOtOp(r, doc); var c = RandomOtOp(r, doc);
            var (ab, ba) = TextOperation.Transform(a, b);
            // (a then b') then c'' must equal a path where c is transformed against the composed pair: compare via both orders of combining
            var left = TextOperation.Compose(a, b1x(a, b));
            var (l1, c1) = TextOperation.Transform(left, c);
            var viaLeft = c1.Apply(left.Apply(doc));
            var right = TextOperation.Compose(c, l1);
            if (viaLeft != right.Apply(doc)) threeBad++;
        }
        Check($"three edits at once also converge ({5000} random cases, {threeBad} wrong)", threeBad == 0);
        static TextOperation b1x(TextOperation a, TextOperation b) => TextOperation.Transform(a, b).B1;

        // Specific, readable cases.
        var abDoc = "ab";
        var insX = new TextOperation().Retain(1).Insert("X").Retain(1);
        var insY = new TextOperation().Retain(1).Insert("Y").Retain(1);
        var (xA, yA) = TextOperation.Transform(insX, insY);
        Check("two inserts at the same spot: the first operation's text goes first, whichever side computes it",
            yA.Apply(insX.Apply(abDoc)) == "aXYb" && xA.Apply(insY.Apply(abDoc)) == "aXYb");

        var del = new TextOperation().Retain(1).Delete(3).Retain(1);                 // "abcde" -> "ae"
        var del2 = new TextOperation().Retain(2).Delete(3);                           // "abcde" -> "ab"
        var (d1, d2) = TextOperation.Transform(del, del2);
        Check("overlapping deletes remove each character once", d2.Apply(del.Apply("abcde")) == "a" && d1.Apply(del2.Apply("abcde")) == "a");

        var insInsideDelete = new TextOperation().Retain(3).Insert("!").Retain(2);   // "abcde" -> "abc!de"
        var (i1, i2) = TextOperation.Transform(insInsideDelete, del);
        Check("an insert inside a range somebody else deleted survives", i2.Apply(insInsideDelete.Apply("abcde")) == "a!e" && i1.Apply(del.Apply("abcde")) == "a!e");

        var built = new TextOperation().Retain(2).Delete(1).Insert("Z").Retain(1);
        Check("an insert written after a delete is stored before it, so equal edits compare equal",
            built.Equals(new TextOperation().Retain(2).Insert("Z").Delete(1).Retain(1)) && built.ToJson() == "[2,\"Z\",-1,1]");
        Check("adjacent parts of the same kind merge", new TextOperation().Retain(1).Retain(2).Insert("a").Insert("b").ToJson() == "[3,\"ab\"]");
        Check("a no-op is recognised", new TextOperation().Retain(5).IsNoop && new TextOperation().IsNoop && !new TextOperation().Insert("x").IsNoop);

        // Emoji (two UTF-16 units each).
        Check("whole emoji can be inserted, kept and deleted", new TextOperation().Retain(1).Insert("😀").Retain(1).Apply("ab") == "a😀b"
            && new TextOperation().Retain(1).Delete(2).Retain(1).Apply("a😀b") == "ab");
        Check("half of an emoji cannot be inserted", Catch(() => new TextOperation().Insert("\ud83d")) is OtException && Catch(() => new TextOperation().Insert("x\ude00")) is OtException);
        Check("an edit that would cut an emoji in half is refused (kept half)", Catch(() => new TextOperation().Retain(2).Insert("X").Retain(2).Apply("a😀b")) is OtException);
        Check("...and so is one that deletes only half", Catch(() => new TextOperation().Retain(2).Delete(1).Retain(1).Apply("a😀b")) is OtException);
        Check("...and one that starts in the middle of a pair", Catch(() => new TextOperation().Retain(1).Delete(1).Retain(2).Apply("😀ab")) is OtException);
        Check("emoji survive the JSON form", TextOperation.FromJson(new TextOperation().Retain(1).Insert("😀👍🏽").Retain(1).ToJson()).Apply("ab") == "a😀👍🏽b");
        Check("FromDiff does not cut an emoji when two emoji share their first half", TextOperation.FromDiff("😀", "😁").Apply("😀") == "😁" && TextOperation.FromDiff("a😀", "a😁").Apply("a😀") == "a😁" && TextOperation.FromDiff("😀b", "😁b").Apply("😀b") == "😁b");
        Check("a JSON text with a lone surrogate escape is refused, not crashed on", !TextOperation.TryFromJson("[\"\\ud83d\"]", out _, out _) && !TextOperation.TryFromJson("[\"\\ude00x\"]", out _, out _));
        Check("a server will not take an edit that cuts an emoji", Catch(() => new OtServer("a😀b").Receive(0, new TextOperation().Retain(2).Delete(1).Retain(1))) is OtException);

        // Errors.
        Check("an edit for a text of another length is refused", Catch(() => new TextOperation().Retain(3).Apply("ab")) is OtException);
        Check("transforming edits from different starting lengths is refused", Catch(() => TextOperation.Transform(new TextOperation().Retain(2), new TextOperation().Retain(3))) is OtException);
        Check("composing edits that do not line up is refused", Catch(() => TextOperation.Compose(new TextOperation().Retain(2), new TextOperation().Retain(3))) is OtException);
        Check("negative sizes are refused", Catch(() => new TextOperation().Retain(-1)) is ArgumentOutOfRangeException && Catch(() => new TextOperation().Delete(-1)) is ArgumentOutOfRangeException);

        // The diff helper, for when all you have is the new text of a text box.
        int diffBad = 0;
        for (int i = 0; i < 5_000; i++)
        {
            string before = RandomOtText(r, 25), after = RandomOtText(r, 25);
            var op = TextOperation.FromDiff(before, after);
            if (op.Apply(before) != after) diffBad++;
        }
        Check($"FromDiff turns any text into any other ({5000} random cases, {diffBad} wrong)", diffBad == 0);
        Check("...and is a no-op when nothing changed", TextOperation.FromDiff("same", "same").IsNoop);
        Check("...and keeps the common start and end", TextOperation.FromDiff("hello world", "hello brave world").ToJson() == "[6,\"brave \",5]");

        // JSON.
        int jsonBad = 0;
        for (int i = 0; i < 5_000; i++)
        {
            string doc = RandomOtText(r, 20);
            var op = RandomOtOp(r, doc);
            if (!TextOperation.FromJson(op.ToJson()).Equals(op)) jsonBad++;
        }
        Check($"an operation survives being written as JSON and read back ({5000} random cases, {jsonBad} wrong)", jsonBad == 0);
        Check("text that needs escaping survives too", TextOperation.FromJson(new TextOperation().Insert("quote\" slash\\ nl\n tab\t 😀").ToJson()).Apply("") == "quote\" slash\\ nl\n tab\t 😀");

        foreach (var bad in new[] { "", "null", "{}", "[0]", "[1.5]", "[true]", "[null]", "[[1]]", "[\"a\", {\"x\":1}]", "[99999999999]", "not json", "[1,", "[\"" + new string('a', TextOperation.MaxLength + 1) + "\"]" })
        {
            bool ok = TextOperation.TryFromJson(bad, out var parsed, out var error);
            if (ok || parsed is not null || string.IsNullOrEmpty(error)) { Check("malformed operation text is refused: " + (bad.Length > 30 ? bad[..30] + "..." : bad), false); }
        }
        Check("malformed operations (empty, objects, zeros, fractions, huge numbers, junk, oversized) are all refused with a reason", true);
        Check("an operation with far too many parts is refused",
            !TextOperation.TryFromJson("[" + string.Join(",", Enumerable.Range(0, TextOperation.MaxComponents + 5).Select(i => i % 2 == 0 ? "1" : "\"a\"")) + "]", out _, out _));
        Check("deeply nested junk is refused without crashing", !TextOperation.TryFromJson(new string('[', 200) + new string(']', 200), out _, out _));
    }

    private static void OtServerAndClient()
    {
        Section("operational transform: server and client");

        // The server.
        var server = new OtServer("hello");
        var e1 = server.Receive(0, new TextOperation().Retain(5).Insert(" world"));
        Check("an edit based on the current revision is applied as it is", server.Document == "hello world" && server.Revision == 1 && e1.ToJson() == "[5,\" world\"]");
        var late = server.Receive(0, new TextOperation().Insert(">> ").Retain(5));   // made against "hello", but a newer edit already exists
        Check("an edit based on an older revision is transformed over what happened since", server.Document == ">> hello world" && server.Revision == 2);
        Check("an edit for a revision that does not exist yet is refused", Catch(() => server.Receive(99, new TextOperation().Retain(server.Document.Length))) is OtException);
        string before = server.Document; int revBefore = server.Revision;
        Check("an edit that does not fit the text is refused", Catch(() => server.Receive(server.Revision, new TextOperation().Retain(3))) is OtException);
        Check("...and the document and revision stay exactly as they were", server.Document == before && server.Revision == revBefore);
        Check("the stored edits can be replayed to catch a client up", server.OperationsFrom(0).Count == 2 && server.OperationsFrom(2).Count == 0);

        var small = new OtServer("", historyLimit: 3);
        for (int i = 0; i < 10; i++) small.Receive(small.Revision, new TextOperation().Retain(small.Document.Length).Insert("x"));
        Check("the history is capped", small.OldestRevision == 7 && small.Revision == 10 && small.OperationsFrom(7).Count == 3);
        Check("a client older than the history must reload", Catch(() => small.Receive(2, new TextOperation().Retain(2))) is OtResyncRequiredException
            && Catch(() => small.OperationsFrom(2)) is OtResyncRequiredException);

        // The client state machine, step by step.
        var sent = new List<(int Rev, string Op)>();
        var c = new OtClient("abc", 0) { Send = (rev, op) => sent.Add((rev, op.ToJson())) };
        Check("a new client has nothing pending", !c.HasPending && c.Outstanding is null);
        c.ApplyClient(new TextOperation().Retain(3).Insert("d"));
        Check("the first local edit is sent at once", c.Text == "abcd" && c.HasPending && sent.Count == 1 && sent[0].Rev == 0);
        c.ApplyClient(new TextOperation().Retain(4).Insert("e"));
        c.ApplyClient(new TextOperation().Retain(5).Insert("f"));
        Check("further edits wait (and are folded together) while one is in flight", c.Text == "abcdef" && sent.Count == 1);
        var seen = c.ApplyServer(new TextOperation().Insert("<").Retain(3));
        Check("an edit from the server is transformed over the local ones and the text keeps everything", c.Text == "<abcdef" && c.Revision == 1 && seen.TargetLength == 7);
        c.ServerAck();
        Check("when the first edit is confirmed the buffered one is sent, based on the new revision", sent.Count == 2 && sent[1].Rev == 2 && c.HasPending);
        c.ServerAck();
        Check("when that is confirmed too the client is back in sync", !c.HasPending && c.Revision == 3);
        Check("a confirmation nobody is waiting for is an error", Catch(() => c.ServerAck()) is OtException);

        // A bad edit from the server must leave the client exactly as it was.
        var s2 = new List<string>();
        var c2 = new OtClient("abc", 0) { Send = (rev, op) => s2.Add(op.ToJson()) };
        c2.ApplyClient(new TextOperation().Retain(3).Insert("!"));
        c2.ApplyClient(new TextOperation().Retain(4).Insert("?"));
        string textBefore = c2.Text; int revBefore2 = c2.Revision;
        Check("a server edit that does not fit is refused", Catch(() => c2.ApplyServer(new TextOperation().Retain(99))) is OtException);
        Check("...and nothing about the client changed (text, revision, pending edits)", c2.Text == textBefore && c2.Revision == revBefore2 && c2.HasPending);
        c2.ServerAck(); c2.ServerAck();
        Check("...so the normal flow still works afterwards", !c2.HasPending && c2.Revision == 2);

        c2.ApplyClient(new TextOperation().Retain(c2.Text.Length).Insert("lost"));
        c2.ResetTo("fresh", 40);
        Check("a reset takes the server's text and drops unconfirmed edits", c2.Text == "fresh" && c2.Revision == 40 && !c2.HasPending && c2.Outstanding is null);

        // Sending an unconfirmed edit again must send it in its CURRENT form, or the server transforms it twice.
        var sv = new OtServer("abc");
        var lone = new OtClient("abc", 0);
        lone.ApplyClient(new TextOperation().Retain(3).Insert("!"));                       // in flight: "abc!"  (based on revision 0)
        var theirs = sv.Receive(0, new TextOperation().Insert(">").Retain(3));             // meanwhile the server took another edit: ">abc"
        lone.ApplyServer(theirs);                                                          // the client moves to ">abc!", revision 1
        var resend = lone.Outstanding!.Value;
        Check("an edit sent again carries the revision the client is at now, not the one it was first sent at", resend.Revision == 1 && lone.Revision == 1);
        sv.Receive(resend.Revision, resend.Operation);
        Check("...so the server ends up with exactly what the client shows", sv.Document == ">abc!" && lone.Text == ">abc!");

        // Whole sessions, with messages arriving in random orders (each direction stays in order, like a real connection).
        int sessions = 1_500, mismatches = 0, stuck = 0;
        var r = new Random(77);
        for (int run = 0; run < sessions; run++)
        {
            string start = RandomOtText(r, 12);
            var srv = new OtServer(start);
            int clientCount = r.Next(2, 5);
            var clients = new OtClient[clientCount];
            var toServer = new Queue<(int Client, int Rev, TextOperation Op, int Seq)>[clientCount];
            var seqOf = new int[clientCount];          // the number of the edit each client has in flight
            var lastTaken = new int[clientCount];      // the server remembers the last edit number it took from each client
            var toClient = new Queue<(bool Ack, TextOperation? Op)>[clientCount];
            for (int i = 0; i < clientCount; i++)
            {
                int me = i;
                toServer[i] = new(); toClient[i] = new();
                clients[i] = new OtClient(start, 0) { Send = (rev, op) => toServer[me].Enqueue((me, rev, op, ++seqOf[me])) };
            }

            void DeliverToServer(int i)
            {
                var (cl, rev, op, seq) = toServer[i].Dequeue();
                if (seq <= lastTaken[cl]) return;   // a resend of an edit already taken: nothing to do
                lastTaken[cl] = seq;
                var applied = srv.Receive(rev, op);
                for (int j = 0; j < clientCount; j++) toClient[j].Enqueue(j == cl ? (true, null) : (false, applied));
            }
            void DeliverToClient(int i)
            {
                var (ack, op) = toClient[i].Dequeue();
                if (ack) clients[i].ServerAck(); else clients[i].ApplyServer(op!);
            }

            int steps = r.Next(20, 80);
            for (int step = 0; step < steps; step++)
            {
                int i = r.Next(clientCount);
                switch (r.Next(4))
                {
                    case 0: clients[i].ApplyClient(RandomOtOp(r, clients[i].Text)); break;
                    case 1: if (toServer[i].Count > 0) DeliverToServer(i); break;
                    case 2: if (toClient[i].Count > 0) DeliverToClient(i); break;
                    default:
                        // The client did not hear back and sends its in-flight edit again, in the form it is in NOW.
                        if (clients[i].Outstanding is { } o) toServer[i].Enqueue((i, o.Revision, o.Operation, seqOf[i]));
                        break;
                }
            }
            // let everything settle
            bool progress = true;
            while (progress)
            {
                progress = false;
                for (int i = 0; i < clientCount; i++)
                {
                    while (toServer[i].Count > 0) { DeliverToServer(i); progress = true; }
                    while (toClient[i].Count > 0) { DeliverToClient(i); progress = true; }
                }
            }
            if (clients.Any(x => x.HasPending)) stuck++;
            if (clients.Any(x => x.Text != srv.Document || x.Revision != srv.Revision)) mismatches++;
        }
        Check($"{sessions} sessions of 2-4 devices editing at once, delivered in random order, with edits sent again when unanswered, all end with the same text ({mismatches} differed)", mismatches == 0);
        Check($"...and none is left waiting for a confirmation ({stuck} stuck)", stuck == 0);
    }
}
