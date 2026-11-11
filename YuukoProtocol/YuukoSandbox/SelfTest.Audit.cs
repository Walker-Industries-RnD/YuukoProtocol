using System.Collections.Concurrent;
using System.Globalization;
using System.Text;
using System.Text.Json.Nodes;
using WISecureData;
using YuukoProtocol;

namespace YuukoSandbox;

// Tests for the audit log: chained entries, tamper detection (keyed and unkeyed), read-only mode, sealing, and recording a node.
public static partial class SelfTest
{
    // Reads the lines even while a writer has the file open (File.ReadAllLines would refuse).
    private static string[] LinesOf(string file)
    {
        using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
        using var r = new StreamReader(fs, Encoding.UTF8);
        var lines = new List<string>();
        string? l;
        while ((l = r.ReadLine()) is not null) lines.Add(l);
        return lines.ToArray();
    }

    private static string WriteCopy(string[] lines, bool trailingNewline = true)
    {
        string f = Path.Combine(TempDir("auditcopy"), "audit.log");
        File.WriteAllText(f, string.Join("\n", lines) + (trailingNewline ? "\n" : ""));
        return f;
    }

    private static AuditVerification VerifyFile(string file, SecureData? key = null, AuditHead? head = null)
    {
        using var viewer = AuditLog.OpenReadOnly(file, key);
        return viewer.Verify(head);
    }

    private static async Task AuditLogTests()
    {
        Section("audit log (append-only, tamper-evident, read-only mode)");
        var key = DirKey("an-audit-key-that-is-long-enough");
        string file = Path.Combine(TempDir("audit"), "audit.log");

        AuditEntry e1, e2, e3;
        AuditHead headAfterThree;
        using (var log = AuditLog.Open(file, key))
        {
            Check("a new log is empty, writable and keyed", log.Head.Seq == 0 && log.Head.Hash == AuditLog.Genesis && !log.IsReadOnly && log.IsKeyed);
            e1 = log.Append("peer.connected", "phone", "fingerprint abc", "pc");
            e2 = log.Append("peer.kicked", "phone", "lost device");
            e3 = log.Append("note");
            headAfterThree = log.Head;
            Check("entries are numbered from 1 and each holds the hash of the one before",
                e1.Seq == 1 && e2.Seq == 2 && e3.Seq == 3 && e1.Prev == AuditLog.Genesis && e2.Prev == e1.Hash && e3.Prev == e2.Hash);
            Check("the entry is on disk before Append returns", LinesOf(file).Length == 3);

            var all = log.Read();
            Check("Read gives them back in order, with every field", all.Count == 3 && all[0].Kind == "peer.connected" && all[0].Subject == "phone"
                && all[0].Detail == "fingerprint abc" && all[0].Actor == "pc" && all[2].Subject is null && all[1].Hash == e2.Hash);
            Check("...and can filter by kind, subject, and newest-N",
                log.Read(kind: "peer.kicked").Count == 1 && log.Read(subject: "phone").Count == 2 && log.Read(last: 1).Single().Seq == 3
                && log.Read(since: DateTimeOffset.UtcNow.AddMinutes(1)).Count == 0);
            Check("a clean log verifies", log.Verify().Ok && log.Verify().Entries == 3);

            Check("a bad kind is refused", Catch(() => log.Append("bad kind!")) is ArgumentException && Catch(() => log.Append("")) is ArgumentException);
            var big = log.Append("big", new string('s', 5000), new string('d', 5000));
            Check("over-long text is cut, not refused", big.Subject!.Length <= 256 && big.Detail!.Length <= 1024 && log.Verify().Ok);
            headAfterThree = new AuditHead(3, e3.Hash);
        }

        using (var again = AuditLog.Open(file, key))
        {
            var e5 = again.Append("after.restart");
            Check("reopening carries on the chain from the last entry", e5.Seq == 5 && e5.Prev == again.Read()[3].Hash && again.Verify().Ok);
        }

        // ---- tampering ----------------------------------------------------------------------------------------
        string[] good = LinesOf(file);

        string Change(string line, string from, string to) { Assert(line.Contains(from)); return line.Replace(from, to); }
        static void Assert(bool c) { if (!c) throw new InvalidOperationException("test setup is wrong"); }

        var edited = (string[])good.Clone();
        edited[1] = Change(edited[1], "lost device", "lost deviCe");
        var r = VerifyFile(WriteCopy(edited), key);
        Check("an edited entry is detected, and the first bad one is named", !r.Ok && r.BadSeq == 2);

        var removedMiddle = good.Where((_, i) => i != 1).ToArray();
        Check("an entry removed from the middle is detected", !VerifyFile(WriteCopy(removedMiddle), key).Ok);

        var swapped = (string[])good.Clone();
        (swapped[1], swapped[2]) = (swapped[2], swapped[1]);
        Check("two entries swapped are detected", !VerifyFile(WriteCopy(swapped), key).Ok);

        var duplicated = good.Take(2).Concat(new[] { good[1] }).Concat(good.Skip(2)).ToArray();
        Check("an entry repeated is detected", !VerifyFile(WriteCopy(duplicated), key).Ok);

        var blank = good.Take(2).Concat(new[] { "" }).Concat(good.Skip(2)).ToArray();
        Check("a blank line slipped in is detected", !VerifyFile(WriteCopy(blank), key).Ok);

        var extraField = (string[])good.Clone();
        extraField[0] = extraField[0].Replace("}", ",\"admin\":true}");
        Check("an unknown field added to an entry is detected", !VerifyFile(WriteCopy(extraField), key).Ok);

        // A rewritten entry whose own hash was recomputed correctly (no key needed on an unkeyed log), with the rest left alone: only the
        // link from the NEXT entry back to this one gives it away.
        string forgeFile = Path.Combine(TempDir("forge"), "audit.log");
        using (var w = AuditLog.Open(forgeFile)) { w.Append("a"); w.Append("peer.kicked", "phone", "stole data"); w.Append("c"); }
        var forgeLines = LinesOf(forgeFile);
        using (var helper = AuditLog.OpenReadOnly(forgeFile))
        {
            var obj = JsonNode.Parse(forgeLines[1])!.AsObject();
            var when = DateTimeOffset.Parse(obj["time"]!.GetValue<string>(), CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind);
            obj["detail"] = "lost device";
            obj["hash"] = helper.ComputeHash(2, when.UtcTicks, "peer.kicked", null, "phone", "lost device", obj["prev"]!.GetValue<string>());
            forgeLines[1] = obj.ToJsonString();
        }
        var forgedLink = VerifyFile(WriteCopy(forgeLines), null);
        Check("an entry rewritten with its OWN hash recomputed is still caught: the next entry no longer follows it", !forgedLink.Ok && forgedLink.BadSeq == 3);

        var torn = (string[])good.Clone();
        torn[^1] = torn[^1][..(torn[^1].Length / 2)];
        Check("a half-written last entry is detected", !VerifyFile(WriteCopy(torn, trailingNewline: false), key).Ok);

        var cut = good.Take(good.Length - 2).ToArray();
        string cutFile = WriteCopy(cut);
        Check("entries cut off the END still form a valid chain (a chain alone cannot see this)", VerifyFile(cutFile, key).Ok);
        var finalHead = new AuditHead(5, AuditLogHeadOf(file, key));
        var cutResult = VerifyFile(cutFile, key, finalHead);
        Check("...but they are caught when you kept the newest head elsewhere", !cutResult.Ok && cutResult.Problem!.Contains("cut off"));
        Check("a log that is exactly as expected passes the head check", VerifyFile(file, key, finalHead).Ok);

        var wrongKey = VerifyFile(file, DirKey("a-completely-different-audit-key"));
        Check("the wrong key fails at the very first entry", !wrongKey.Ok && wrongKey.BadSeq == 1);
        Check("a keyed log read without a key fails too", !VerifyFile(file, null).Ok);

        // The reason to use a key: without one, anyone who can write the file can rewrite history and recompute every hash.
        string plain = Path.Combine(TempDir("plain"), "audit.log");
        using (var unkeyed = AuditLog.Open(plain))
        {
            unkeyed.Append("peer.connected", "phone");
            unkeyed.Append("peer.kicked", "phone", "stole data");
        }
        string forgedPlain = Path.Combine(TempDir("forged"), "audit.log");
        using (var forger = AuditLog.Open(forgedPlain))   // the attacker replays a "cleaned" history through the same code
        {
            forger.Append("peer.connected", "phone");
            forger.Append("peer.kicked", "phone", "lost device");
        }
        Check("WITHOUT a key a rewritten history verifies perfectly (this is why the key matters)", VerifyFile(forgedPlain, null).Ok);
        Check("WITH a key the same rewrite is rejected: the attacker cannot produce valid hashes", !VerifyFile(forgedPlain, key).Ok);

        // ---- read-only mode ------------------------------------------------------------------------------------
        using (var viewer = AuditLog.OpenReadOnly(file, key))
        {
            Check("a read-only log says so", viewer.IsReadOnly);
            Check("it cannot be written to", Catch(() => viewer.Append("x")) is InvalidOperationException);
            Check("it cannot be attached to a node", Catch(() => viewer.Attach(Node(new LocalBroker(), YuukoIdentity.Create("x")))) is InvalidOperationException);
            Check("it reads and verifies", viewer.Read().Count == 5 && viewer.Verify().Ok && viewer.Head.Seq == 5);
        }
        Check("opening a log that does not exist read-only is an error, not an empty log",
            Catch(() => AuditLog.OpenReadOnly(Path.Combine(TempDir("none"), "nope.log"), key)) is FileNotFoundException);

        using (var writer = AuditLog.Open(file, key))
        using (var watcher = AuditLog.OpenReadOnly(file, key))
        {
            int before = watcher.Read().Count;
            writer.Append("while.watching");
            Check("a read-only viewer sees new entries while the writer is running", watcher.Read().Count == before + 1 && watcher.Verify().Ok);
            Check("only one writer can have a log open", Catch(() => AuditLog.Open(file, key)) is IOException);
        }

        // ---- never append to damage ----------------------------------------------------------------------------
        string damaged = WriteCopy(torn, trailingNewline: false);
        Check("a log that ends in a half-written entry is not added to", Catch(() => AuditLog.Open(damaged, key)) is FormatException);
        Check("a log whose last entry is complete but is missing its newline is not added to (the next entry would be glued onto it)",
            Catch(() => AuditLog.Open(WriteCopy(good, trailingNewline: false), key)) is FormatException);
        var tamperedTail = (string[])good.Clone();
        tamperedTail[^1] = Change(tamperedTail[^1], "after.restart", "after.restarT");
        Check("a log whose newest entry was changed is not added to", Catch(() => AuditLog.Open(WriteCopy(tamperedTail), key)) is FormatException);
        Check("opening a keyed log with the wrong key for writing is refused", Catch(() => AuditLog.Open(file, DirKey("a-completely-different-audit-key"))) is FormatException);

        // ---- sealing -------------------------------------------------------------------------------------------
        string sealedFile = Path.Combine(TempDir("seal"), "audit.log");
        using (var s = AuditLog.Open(sealedFile, key))
        {
            s.Append("one"); s.Append("two");
            s.Seal();
            Check("sealing marks the file read-only at the OS level", AuditLog.IsSealed(sealedFile));
            Check("...and the log object becomes read-only", s.IsReadOnly && Catch(() => s.Append("three")) is InvalidOperationException);
            Check("...and the data is still readable", s.Read().Count == 2 && s.Verify().Ok);
        }
        Check("a sealed file cannot be edited by ordinary means", Catch(() => File.AppendAllText(sealedFile, "x")) is UnauthorizedAccessException);
        var sealedErr = Catch(() => AuditLog.Open(sealedFile, key));
        Check("a sealed log refuses to open for writing, and says why", sealedErr is UnauthorizedAccessException && sealedErr.Message.Contains("sealed"));
        Check("...but opens read-only", AuditLog.OpenReadOnly(sealedFile, key).Verify().Ok);
        AuditLog.Unseal(sealedFile);
        using (var reopened = AuditLog.Open(sealedFile, key))
            Check("after Unseal it can be written again, continuing the chain", !AuditLog.IsSealed(sealedFile) && reopened.Append("three").Seq == 3);

        // ---- many writers --------------------------------------------------------------------------------------
        string busy = Path.Combine(TempDir("busy"), "audit.log");
        using (var b = AuditLog.Open(busy, key))
        {
            await Task.WhenAll(Enumerable.Range(0, 16).Select(t => Task.Run(() => { for (int i = 0; i < 25; i++) b.Append("busy", "t" + t, i.ToString()); })));
            var v = b.Verify();
            Check("16 threads appending 25 entries each: all 400 are there, in one unbroken chain", v.Ok && v.Entries == 400 && b.Read().Select(x => x.Seq).Distinct().Count() == 400);
        }

        await AuditAttachTests(key);
    }

    private static string AuditLogHeadOf(string file, SecureData key)
    {
        using var v = AuditLog.OpenReadOnly(file, key);
        return v.Head.Hash;
    }

    private static async Task AuditAttachTests(SecureData key)
    {
        Section("audit log recording a node");
        using var bus = new LocalBroker();
        string file = Path.Combine(TempDir("attach"), "audit.log");
        var aid = YuukoIdentity.Create("anchor");
        var pid = YuukoIdentity.Create("phone");

        using var log = AuditLog.Open(file, key);
        EclipseBrokerOptions? aopts = null;
        using var a = Node(bus, aid, o => { o.Handshake.RequireKnownDevices = true; aopts = o; o.CommandAuthorizer = (peer, cmd) => cmd != "forbidden"; });
        using var phone = Node(bus, pid);
        using var stranger = Node(bus, YuukoIdentity.Create("stranger"));
        var detach = log.Attach(a);
        await a.StartAsync(); await phone.StartAsync(); await stranger.StartAsync();

        // a stranger knocks repeatedly
        for (int i = 0; i < 5; i++) await stranger.PingAsync("anchor");
        await Task.Delay(200);
        var refused = log.Read(kind: "handshake.refused");
        Check("a refused connection attempt is recorded, naming who tried and why", refused.Count >= 1 && refused[0].Subject == "stranger" && refused[0].Detail!.Contains("unknown device"));
        Check("...but repeats within a minute are not written again (a flood cannot fill the disk)", refused.Count == 1);

        // pairing
        var offer = a.BeginPairing();
        Check("opening a pairing window is recorded", log.Read(kind: "pairing.offered").Count == 1);
        var paired = await phone.PairWithAsync(offer.Code);
        await Task.Delay(300);
        Check("a successful pairing is recorded (who, and which keys)", paired.Success && log.Read(kind: "device.paired").Single().Detail!.Contains(pid.Fingerprint));
        Check("...and so is the connection", log.Read(kind: "peer.connected").Any(e => e.Subject == "phone"));
        a.BeginPairing(); a.CancelPairing();
        Check("cancelling a pairing window is recorded", log.Read(kind: "pairing.cancelled").Count == 1);

        // a command the authorizer refuses
        phone.On("noop", (c, _) => Task.FromResult(CommandResult.Ok()));
        a.On("forbidden", (c, _) => Task.FromResult(CommandResult.Ok()));
        await phone.SendCommandAsync("anchor", "forbidden");
        await Task.Delay(100);
        var denied = log.Read(kind: "command.denied");
        Check("a command refused by the authorizer is recorded with who asked and what", denied.Count == 1 && denied[0].Subject == "phone" && denied[0].Detail == "forbidden");

        // kicks and bans
        await a.KickAsync("phone", ban: false, reason: "testing");
        await Task.Delay(100);
        Check("a kick is recorded with its reason", log.Read(kind: "peer.kicked").Single().Detail == "testing");
        Check("...and the disconnect that follows", log.Read(kind: "peer.disconnected").Any(e => e.Subject == "phone"));
        await a.KickAsync("phone", ban: true, reason: "bad");
        Check("a ban is recorded", log.Read(kind: "peer.banned").Single().Subject == "phone");
        a.Unban("phone");
        Check("an unban is recorded", log.Read(kind: "peer.unbanned").Count == 1);
        Check("unbanning someone who was not banned records nothing", !a.Unban("never-banned") && log.Read(kind: "peer.unbanned").Count == 1);

        // stop recording
        detach.Dispose();
        int count = log.Read().Count;
        a.BeginPairing(); a.CancelPairing();
        Check("after Detach nothing more is recorded", log.Read().Count == count);

        var result = log.Verify();
        Check("the whole log still verifies", result.Ok && result.Entries == count);
        Check("recording never failed", log.Failures == 0);

        // group changes: one device with no policy refuses, and both sides record it
        using var bus2 = new LocalBroker();
        string f2 = Path.Combine(TempDir("attach2"), "audit.log");
        string f3 = Path.Combine(TempDir("attach3"), "audit.log");
        var (n, _) = await Group(bus2, new[] { "a", "b", "c" }, new[] { ("a", "b"), ("a", "c") }, (name, o) => { if (name == "c") o.GroupChangePolicy = _ => Task.FromResult(true); });
        try
        {
            using var logA = AuditLog.Open(f2, key);
            using var logB = AuditLog.Open(f3, key);
            using var d1 = logA.Attach(n["a"]);
            using var d2 = logB.Attach(n["b"]);
            await n["a"].IntroduceAsync("c");
            await Task.Delay(300);
            Check("the announcing device records that it announced", logA.Read(kind: "group.introduced").Single().Subject == "c");
            Check("a device with no policy records that it refused, and who asked", logB.Read(kind: "group.refused").Single().Detail!.Contains("announced by a"));
        }
        finally { foreach (var x in n.Values) x.Dispose(); }
    }
}
