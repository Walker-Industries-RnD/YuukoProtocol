using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using WISecureData;
using YuukoProtocol;
using YuukoProtocol.Dogma;

namespace YuukoSandbox;

//The checks for the most important parts, all in one program (No network needed)
//dotnet run --project YuukoSandbox -- selftest
public static class SelfTest
{
    static int Failed, Total;

    static void Check(string Name, bool Ok)
    {
        Total++;
        if (!Ok) Failed++;
        Console.WriteLine($"[{(Ok ? "PASS" : "FAIL")}] {Name}");
    }

    static async Task<bool> Eventually(Func<bool> Condition, int Ms = 5000)
    {
        var Until = DateTime.UtcNow.AddMilliseconds(Ms);
        while (DateTime.UtcNow < Until)
        {
            if (Condition()) return true;
            await Task.Delay(20);
        }
        return Condition();
    }

    static async Task<bool> Throws(Func<Task> Work)
    {
        try { await Work(); return false; }
        catch { return true; }
    }

    static byte[] Bytes(int Length, int Seed)
    {
        var Data = new byte[Length];
        new Random(Seed).NextBytes(Data);
        return Data;
    }

    static string Folder(string Name)
    {
        var Path_ = Path.Combine(Path.GetTempPath(), "yuuko-test-" + Guid.NewGuid().ToString("N")[..8], Name);
        Directory.CreateDirectory(Path_);
        return Path_;
    }

    //Devices that know each other by name and key, but only talk over the links given
    static async Task<Dictionary<string, EclipseBroker>> Group(LocalBroker Bus, string[] Names, (string, string)[] Links)
    {
        var Ids = Names.ToDictionary(n => n, n => YuukoIdentity.Create(n));
        var Nodes = new Dictionary<string, EclipseBroker>();

        foreach (var Name in Names)
        {
            var Options = new EclipseBrokerOptions { CommandTimeout = TimeSpan.FromSeconds(3), RequestTimeout = TimeSpan.FromSeconds(3) };

            foreach (var (A, B) in Links)
            {
                var Other = A == Name ? B : B == Name ? A : null;
                if (Other is null) continue;
                Options.Handshake.TrustDevice(Other, Ids[Other].Fingerprint);
                Options.TrustOrigin(Other, Ids[Other].Fingerprint);
            }

            Nodes[Name] = EclipseBroker.Create(Bus, Ids[Name], Options);
            await Nodes[Name].StartAsync();
        }

        foreach (var (A, B) in Links) await Nodes[A].PingAsync(B);
        return Nodes;
    }

    public static async Task<int> RunAsync()
    {
        await Connecting();
        await Documents();
        await Folders();
        await Streams();
        await AuditLogs();

        Console.WriteLine(Failed == 0 ? $"\nALL PASS ({Total} checks)" : $"\n{Failed} FAILED of {Total}");
        return Failed;
    }

    #region Connecting

    static async Task Connecting()
    {
        Console.WriteLine("\n-- connecting");
        using var Bus = new LocalBroker();
        var N = await Group(Bus, new[] { "pc", "phone", "tablet" }, new[] { ("pc", "phone") });
        N["phone"].On("echo", (c, _) => Task.FromResult(CommandResult.Ok(c.Payload)));

        var Sent = Bytes(1000, 1);
        var Ack = await N["pc"].SendCommandAsync("phone", "echo", Sent);
        Check("a command is answered by the other device", Ack.IsOk && Ack.Result.SequenceEqual(Sent));
        Check("a command nobody answers says so", (await N["pc"].SendCommandAsync("phone", "nothing")).Status == AckStatus.UnknownCommand);
        Check("a device that isn't paired is refused", !(await N["tablet"].PingAsync("pc")).IsOk);

        //The group key is the same on every device or they don't connect
        using var Bus2 = new LocalBroker();
        EclipseBroker Open(string Name, string Key)
        {
            var Options = new EclipseBrokerOptions { RequestTimeout = TimeSpan.FromSeconds(2), CommandTimeout = TimeSpan.FromSeconds(2) };
            Options.Handshake.PreSharedKey = Encoding.UTF8.GetBytes(Key);
            Options.Handshake.RequirePreSharedKey = true;
            return EclipseBroker.Create(Bus2, YuukoIdentity.Create(Name), Options);
        }

        using var One = Open("one", "the-group-key-1234"); using var Same = Open("same", "the-group-key-1234"); using var Other = Open("other", "another-group-key-9");
        await One.StartAsync();
        Check("devices with the same group key connect", (await Same.PingAsync("one")).IsOk);
        Check("a device with another group key doesn't", !(await Other.PingAsync("one")).IsOk);
    }

    #endregion

    #region Documents

    static async Task Documents()
    {
        Console.WriteLine("\n-- shared documents");
        using var Bus = new LocalBroker();
        var N = await Group(Bus, new[] { "a", "b" }, new[] { ("a", "b") });
        using var A = new DocSync(N["a"]); using var B = new DocSync(N["b"]);
        A.AntiEntropyInterval = B.AntiEntropyInterval = TimeSpan.Zero;

        var Doc = new SimpleCRDT.SharedDocs("a", "Shopping list", DateTime.UtcNow, null);
        Doc.CreateLabel("items", "milk\n");
        await A.ShareAsync(Doc);
        Check("a shared document arrives on the other device", await Eventually(() => B.Docs.ContainsKey(Doc.UUID)));

        var Copy = B.Docs[Doc.UUID];
        await Task.WhenAll(Task.Run(() => Doc.AddToLabel("items", "eggs\n")), Task.Run(() => Copy.AddToLabel("items", "bread\n")));
        Check("two edits at the same time end up the same on both, and nothing is lost",
            await Eventually(() => Doc.ReadLabel("items") == Copy.ReadLabel("items") && new[] { "milk", "eggs", "bread" }.All(Doc.ReadLabel("items").Contains)));

        Check("only the device that made a document can remove it", await Throws(() => B.RemoveAsync(Doc.UUID)));
        await A.RemoveAsync(Doc.UUID);
        Check("a removed document goes from every device", await Eventually(() => !B.Docs.ContainsKey(Doc.UUID)));

        var Big = new SimpleCRDT.SharedDocs("a", "Big", DateTime.UtcNow, null);
        Big.CreateLabel("text", new string('x', 1_500_000) + Convert.ToBase64String(Bytes(750_000, 2)));
        await A.ShareAsync(Big);
        Check("a document of 3 MB arrives whole (it is sent in pieces)", await Eventually(() => B.Docs.TryGetValue(Big.UUID, out var D) && D.ContentHash == Big.ContentHash, 60000));

        var Empty = new SimpleCRDT.SharedDocs("a", "Empty", DateTime.UtcNow, null);
        Empty.CreateLabel("text", "");
        Check("a document with no text is fine", Empty.ReadLabel("text") == "");
    }

    #endregion

    #region Folders

    static bool Same(string A, string B)
    {
        Dictionary<string, string> Look(string Root) => Directory.EnumerateFiles(Root, "*", SearchOption.AllDirectories)
            .Where(f => !Path.GetRelativePath(Root, f).StartsWith(".yuuko"))
            .ToDictionary(f => Path.GetRelativePath(Root, f), f => Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(f))));

        var X = Look(A); var Y = Look(B);
        return X.Count == Y.Count && X.All(p => Y.TryGetValue(p.Key, out var H) && H == p.Value);
    }

    static async Task Folders()
    {
        Console.WriteLine("\n-- folder sync");
        var Root = Folder("dag");
        string ADir = Path.Combine(Root, "a"), BDir = Path.Combine(Root, "b");
        Directory.CreateDirectory(Path.Combine(ADir, "notes"));
        File.WriteAllText(Path.Combine(ADir, "readme.txt"), "hello");
        File.WriteAllText(Path.Combine(ADir, "notes", "one.txt"), "one");
        File.WriteAllBytes(Path.Combine(ADir, "big.bin"), Bytes(700_000, 3));

        using var Bus = new LocalBroker();
        var N = await Group(Bus, new[] { "a", "b" }, new[] { ("a", "b") });
        var A = new DAG.Syncer(N["a"], null); var B = new DAG.Syncer(N["b"], null);

        try
        {
            var Shared = await A.Share(ADir, new List<string> { "b" });
            await B.Join(Shared.UUID, BDir, new List<string> { "a" });

            var First = await B.Sync("a", Shared.UUID);
            Check("a new folder arrives whole", First.Downloaded == 3 && First.Errors.Count == 0 && Same(ADir, BDir));

            File.WriteAllText(Path.Combine(ADir, "readme.txt"), "hello again");
            File.SetLastWriteTimeUtc(Path.Combine(ADir, "readme.txt"), DateTime.UtcNow.AddMinutes(1));
            File.Delete(Path.Combine(ADir, "notes", "one.txt"));
            var Second = await B.Sync("a", Shared.UUID);
            Check("a change and a delete arrive", Second.Downloaded == 1 && Second.Deleted == 1 && Same(ADir, BDir));
            Check("syncing again changes nothing", (await B.Sync("a", Shared.UUID)).AlreadyInSync);

            Check("a path that climbs out of the folder is refused", !DAG.SafeRelative("../x") && !DAG.SafeRelative("/etc/x") && !DAG.SafeRelative(".yuuko/x"));

            //A file that can't be written stops that file, not the sync, and the developer pushes it on
            File.WriteAllBytes(Path.Combine(ADir, "late.bin"), Bytes(300_000, 4));
            string Hash = DAG.Scan(ADir, null)["late.bin"].Hash;
            Directory.CreateDirectory(Path.Combine(BDir, ".yuuko", "partial"));
            var Held = new FileStream(Path.Combine(BDir, ".yuuko", "partial", Hash), FileMode.Create, FileAccess.Write, FileShare.None);

            var Stopped = await B.Sync("a", Shared.UUID);
            Check("a file that can't be written is reported and the sync goes on", Stopped.Errors.Count == 1 && !File.Exists(Path.Combine(BDir, "late.bin")));

            Held.Dispose();
            var Pushed = await B.Resume("a", Shared.UUID, 3);
            Check("syncing again (ResumeFolder) finishes it", Pushed.Errors.Count == 0 && Same(ADir, BDir));
        }
        finally
        {
            A.Dispose(); B.Dispose();
            foreach (var Node in N.Values) Node.Dispose();
        }
    }

    #endregion

    #region Streams

    static async Task Streams()
    {
        Console.WriteLine("\n-- streams (The Cogitarium)");
        using var Bus = new LocalBroker();

        //The source only talks to the middle one, who passes it on. x is no mesh, it just talks
        var N = await Group(Bus, new[] { "s", "m", "r", "x" }, new[] { ("s", "m"), ("m", "r"), ("m", "x") });
        var S = new Cogitarium.Mesh(N["s"]); var M = new Cogitarium.Mesh(N["m"]); var R = new Cogitarium.Mesh(N["r"]);
        var Got = new List<byte[]>();
        R.SegmentReceived += (Info, Piece) => { lock (Got) Got.Add(Piece.Data); };

        try
        {
            foreach (var Mesh in new[] { S, M, R }) Mesh.JoinChunk("room");
            M.AcceptSource(S.MyFingerprint);
            R.AcceptSource(S.MyFingerprint);
            await Eventually(() => S.Neighbors("room").Count == 1 && M.Neighbors("room").Count == 2);

            var Stream = S.StartStream("room", "Cafe");
            Check("a stream is announced to devices that accepted its source, through the middle one", await Eventually(() => R.Streams().Count == 1));

            var Piece = Bytes(5000, 5);
            await Stream.Send(Piece, Cogitarium.Full);
            Check("a piece reaches a device the source isn't connected to, unchanged", await Eventually(() => Got.Count == 1) && Got[0].SequenceEqual(Piece));

            await Task.Delay(300);
            Check("...once", Got.Count == 1);

            //A device passing on a piece that isn't what the source signed
            await N["x"].SendCommandAsync("m", "sccn.hello", Encoding.UTF8.GetBytes(new JsonObject { ["c"] = new JsonObject { ["room"] = 31 } }.ToJsonString()));
            var Header = new JsonObject { ["id"] = M.Streams()[0].ID, ["seq"] = 9, ["lv"] = 0, ["h"] = 0, ["m"] = "", ["sig"] = Convert.ToBase64String(Bytes(64, 6)) };
            await N["x"].SendCommandAsync("m", "sccn.segment", Cogitarium.Mesh.Frame(Header, Bytes(100, 7)));
            Check("a piece with a signature that isn't the source's is refused, and the device that sent it is distrusted", M.IsDistrusted("x") && !M.IsDistrusted("s"));
        }
        finally
        {
            S.Dispose(); M.Dispose(); R.Dispose();
            foreach (var Node in N.Values) Node.Dispose();
        }
    }

    #endregion

    #region Audit logs

    static async Task AuditLogs()
    {
        Console.WriteLine("\n-- audit log");
        var Dir = Folder("audit");
        var Key = new SecureData(Encoding.UTF8.GetBytes("audit file key 123"));
        string File_ = Path.Combine(Dir, "a.log");

        using (var Log = AuditLog.Open(File_, Key))
        {
            Log.Append("report.opened", "q3.pdf");
            Log.Append("peer.banned", "phone");
            Log.Append("report.closed", "q3.pdf");
        }

        using var Viewer = AuditLog.OpenReadOnly(File_, Key);
        var Head = Viewer.Head;
        Check("a log checks out", Viewer.Verify().Ok && Head.Seq == 3);

        var Lines = File.ReadAllLines(File_);
        string Edited = Path.Combine(Dir, "edited.log"), Cut = Path.Combine(Dir, "cut.log");
        Lines[1] = Lines[1].Replace("phone", "tablet");
        File.WriteAllLines(Edited, Lines);
        using (var Changed = AuditLog.OpenReadOnly(Edited, Key)) Check("an entry that was edited is found", !Changed.Verify().Ok);

        File.WriteAllLines(Cut, File.ReadAllLines(File_).Take(2));
        using (var Short = AuditLog.OpenReadOnly(Cut, Key))
        {
            Check("a log with its last entries cut off still looks fine on its own", Short.Verify().Ok);
            Check("...but not when you kept the newest entry somewhere else", !Short.Verify(Head).Ok);
        }

        using (var WrongKey = AuditLog.OpenReadOnly(File_, new SecureData(Encoding.UTF8.GetBytes("another key at all")))) Check("the wrong key can't check it", !WrongKey.Verify().Ok);

        //Signed by the device: someone who only has the key can't write a log that passes
        var Me = YuukoIdentity.Create("pc"); var Other = YuukoIdentity.Create("other");
        string Mine = Path.Combine(Dir, "mine.log"), Theirs = Path.Combine(Dir, "theirs.log");
        using (var Log = AuditLog.Open(Mine, Key, Me)) Log.Append("report.opened", "q3.pdf");
        using (var Log = AuditLog.Open(Theirs, Key, Other)) Log.Append("report.opened", "q3.pdf");

        using (var Own = AuditLog.OpenReadOnly(Mine, Key)) Check("a log signed by the device checks out", Own.Verify(null, Me.Fingerprint).Ok);
        using (var Forged = AuditLog.OpenReadOnly(Theirs, Key)) Check("a log written with the key by another device is refused", !Forged.Verify(null, Me.Fingerprint).Ok);

        await Task.CompletedTask;
    }

    #endregion
}
