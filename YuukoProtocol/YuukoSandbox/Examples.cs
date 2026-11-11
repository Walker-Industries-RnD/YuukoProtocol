using System.Text;
using WISecureData;
using YuukoProtocol;
using YuukoProtocol.Dogma;
using static YuukoProtocol.Dogma.SimpleCRDT;

namespace YuukoSandbox;

// Runnable examples. Each one sets up a few devices inside this one process (no network, no certificates needed) and narrates what happens.
//
//   dotnet run --project YuukoSandbox -- example ot       shared text: three devices type into the same document at once
//   dotnet run --project YuukoSandbox -- example crdt     shared documents that merge by themselves, even after a device was away
//   dotnet run --project YuukoSandbox -- example audit    a tamper-evident log of what a device did, readable but not writable by a viewer
//   dotnet run --project YuukoSandbox -- example holy     the apps installed on THIS machine (Steam, WalkerWorks, apps menu) and which are running
//
// The code here is meant to be read and copied: it is the same API you would call with real devices (see 1 - Getting Started/7 - Examples in the wiki).
public static class Examples
{
    public static async Task<int> RunAsync(string[] args)
    {
        string which = args.Length > 1 ? args[1].ToLowerInvariant() : "";
        switch (which)
        {
            case "ot": await OtExample(); return 0;
            case "crdt": await CrdtExample(); return 0;
            case "audit": await AuditExample(); return 0;
            case "holy": HolyExample(); return 0;
            default:
                Console.WriteLine("usage: example <ot | crdt | audit | holy>");
                return 1;
        }
    }

    // ── helpers ──────────────────────────────────────────────────────────────

    private static void Say(string text) => Console.WriteLine(text);
    private static string Show(string text) => "\"" + text.Replace("\n", "⏎") + "\"";

    // Devices that all know and trust each other, already connected (the same thing pairing gives you with real devices).
    private static async Task<Dictionary<string, EclipseBroker>> Devices(IYuukoApi bus, params string[] names)
    {
        var ids = names.ToDictionary(n => n, n => YuukoIdentity.Create(n));
        var nodes = new Dictionary<string, EclipseBroker>();
        foreach (var n in names)
        {
            var options = new EclipseBrokerOptions { CommandTimeout = TimeSpan.FromSeconds(3) };
            foreach (var other in names.Where(x => x != n))
            {
                options.Handshake.TrustDevice(other, ids[other].Fingerprint);   // pinned: only this exact device
                options.TrustOrigin(other, ids[other].Fingerprint);             // and its signed broadcasts are accepted
            }
            nodes[n] = EclipseBroker.Create(bus, ids[n], options);
        }
        foreach (var node in nodes.Values) await node.StartAsync();
        foreach (var a in names)
            foreach (var b in names.Where(x => string.CompareOrdinal(x, a) > 0))
                await nodes[a].PingAsync(b);   // the first message between two devices opens their encrypted session
        return nodes;
    }

    private static async Task<bool> Wait(Func<bool> condition, int milliseconds = 8000)
    {
        var until = DateTime.UtcNow.AddMilliseconds(milliseconds);
        while (DateTime.UtcNow < until) { if (condition()) return true; await Task.Delay(25); }
        return condition();
    }

    // ── OT: three devices type into the same text at once ────────────────────

    private static async Task OtExample()
    {
        Say("== Shared text (operational transform) ==");
        Say("A document has ONE owner that puts everybody's edits in order. Everyone else sends edits to it and gets the result back.\n");

        using var bus = new LocalBroker();
        var nodes = await Devices(bus, "pc", "phone", "tablet");
        using var pcOt = new OtSession(nodes["pc"]);
        using var phoneOt = new OtSession(nodes["phone"]);
        using var tabletOt = new OtSession(nodes["tablet"]);

        // In a real app you call OpTransform.Start() once, then OpTransform.CreateText / JoinText (they use Identity.YuukoNode).
        // Here three nodes live in one process, so each gets its own session and we wrap the documents the same way Start() does.
        // The PC owns the text. The others join it by the owner's device name.
        var onPc = OpTransform.Wrap(pcOt.Create("shopping", "Shopping list:\n"));
        var onPhone = OpTransform.Wrap(await phoneOt.JoinAsync("pc", "shopping"));
        var onTablet = OpTransform.Wrap(await tabletOt.JoinAsync("pc", "shopping"));
        Say($"All three start from {Show(onPc.Text)}\n");

        // Hear about changes that come from other devices.
        onPhone.Changed += (text, remote, author) => { if (remote) Say($"   phone: {author} changed it -> {Show(text)}"); };

        Say("Now all three type at the very same moment, each at the end of the list:");
        await Task.WhenAll(
            Task.Run(() => onPhone.Insert(onPhone.Text.Length, "- milk\n")),
            Task.Run(() => onTablet.Insert(onTablet.Text.Length, "- eggs\n")),
            Task.Run(() => onPc.Insert(onPc.Text.Length, "- bread\n")));

        await onPhone.WaitUntilSynced(TimeSpan.FromSeconds(5));   // "my edits have been confirmed by the owner"
        await onTablet.WaitUntilSynced(TimeSpan.FromSeconds(5));
        await Wait(() => onPc.Text == onPhone.Text && onPc.Text == onTablet.Text);

        Say("\nAfter a moment every device shows the SAME text, with nothing lost:");
        Say($"   pc     : {Show(onPc.Text)}");
        Say($"   phone  : {Show(onPhone.Text)}");
        Say($"   tablet : {Show(onTablet.Text)}");

        Say("\nA text box gives you the whole new text, not an edit. SetText works out the smallest edit for you:");
        onTablet.SetText(onTablet.Text.Replace("- eggs", "- a dozen eggs"));
        await onTablet.WaitUntilSynced(TimeSpan.FromSeconds(5));
        await Wait(() => onPc.Text == onTablet.Text && onPhone.Text == onTablet.Text);
        Say($"   everyone: {Show(onPc.Text)}");

        Say("\nOnly some devices may write? Say so when you create the document:");
        var locked = OpTransform.Wrap(pcOt.Create("rules", "House rules\n", writers: new[] { "phone" }));
        var rulesOnTablet = OpTransform.Wrap(await tabletOt.JoinAsync("pc", "rules"));
        rulesOnTablet.Rejected += why => Say($"   tablet: the owner said no ({why}) and put the text back");
        rulesOnTablet.Insert(0, "my own rule\n");
        await Wait(() => rulesOnTablet.Text == "House rules\n");
        Say($"   tablet's text is again {Show(rulesOnTablet.Text)}");

        foreach (var n in nodes.Values) n.Dispose();
    }

    // ── CRDT: documents that merge by themselves ─────────────────────────────

    private static async Task CrdtExample()
    {
        Say("== Shared documents that merge by themselves (CRDT) ==");
        Say("No owner, no server. Any device edits any time; copies merge to the same result.\n");

        using var bus = new LocalBroker();
        var nodes = await Devices(bus, "pc", "phone", "tablet");
        using var pcSync = new DocSync(nodes["pc"]);
        using var phoneSync = new DocSync(nodes["phone"]);
        using var tabletSync = new DocSync(nodes["tablet"]);
        pcSync.AntiEntropyInterval = phoneSync.AntiEntropyInterval = tabletSync.AntiEntropyInterval = TimeSpan.FromSeconds(2);

        // A document has named text fields ("labels"). The PC makes one and shares it.
        var doc = new SharedDocs("pc", "Party plan", DateTime.UtcNow, null);
        doc.CreateLabel("guests", "Ana\n");
        doc.CreateLabel("food", "pizza\n");
        await pcSync.ShareAsync(doc);
        await Wait(() => phoneSync.Docs.ContainsKey(doc.UUID) && tabletSync.Docs.ContainsKey(doc.UUID));
        var onPhone = phoneSync.Docs[doc.UUID];
        var onTablet = tabletSync.Docs[doc.UUID];
        Say($"The phone and the tablet received it. guests = {Show(onPhone.ReadLabel("guests"))}, food = {Show(onTablet.ReadLabel("food"))}\n");

        Say("All three add to the guest list at the same moment, with no coordination:");
        await Task.WhenAll(
            Task.Run(() => doc.AddToLabel("guests", "Ben\n")),
            Task.Run(() => onPhone.AddToLabel("guests", "Cleo\n")),
            Task.Run(() => onTablet.AddToLabel("guests", "Dev\n")));
        await Wait(() => doc.ReadLabel("guests") == onPhone.ReadLabel("guests") && doc.ReadLabel("guests") == onTablet.ReadLabel("guests") && doc.ReadLabel("guests").Length >= 17);
        Say($"   every device: {Show(doc.ReadLabel("guests"))}   (same order everywhere, nobody lost)\n");

        Say("The tablet goes out of range. Both sides keep editing:");
        foreach (var other in new[] { "pc", "phone" })
        {
            await nodes[other].KickAsync("tablet", ban: true, reason: "out of range");
            await nodes["tablet"].KickAsync(other, ban: true, reason: "out of range");
        }
        doc.AddToLabel("food", "salad\n");
        onTablet.AddToLabel("food", "cake (made on the tablet, offline)\n");
        await Task.Delay(300);
        Say($"   pc:     food = {Show(doc.ReadLabel("food"))}");
        Say($"   tablet: food = {Show(onTablet.ReadLabel("food"))}");

        Say("\nThe tablet comes back. Connecting is all it takes: the devices compare notes and swap what each is missing:");
        foreach (var other in new[] { "pc", "phone" })
        {
            nodes[other].Unban("tablet");
            nodes["tablet"].Unban(other);
        }
        await nodes["tablet"].PingAsync("pc");
        await Wait(() => doc.ReadLabel("food") == onTablet.ReadLabel("food") && doc.ReadLabel("food") == onPhone.ReadLabel("food") && doc.ReadLabel("food").Contains("cake") && doc.ReadLabel("food").Contains("salad"), 15000);
        Say($"   pc:     food = {Show(doc.ReadLabel("food"))}");
        Say($"   phone:  food = {Show(onPhone.ReadLabel("food"))}   (it never talked to the tablet directly while it was away)");
        Say($"   tablet: food = {Show(onTablet.ReadLabel("food"))}");

        Say("\nOnly the device that made a document may remove it:");
        try { await tabletSync.RemoveAsync(doc.UUID); } catch (InvalidOperationException e) { Say($"   tablet tried: {e.Message}"); }
        await pcSync.RemoveAsync(doc.UUID);
        await Wait(() => !phoneSync.Docs.ContainsKey(doc.UUID) && !tabletSync.Docs.ContainsKey(doc.UUID));
        Say($"   pc removed it; the phone still has it? {phoneSync.Docs.ContainsKey(doc.UUID)}, the tablet? {tabletSync.Docs.ContainsKey(doc.UUID)}");

        foreach (var n in nodes.Values) n.Dispose();
    }

    // ── holy: the apps on this machine ───────────────────────────────────────

    private static void HolyExample()
    {
        Say("== Apps on this device (HolyMother) ==");
        Say("Other devices ask for this list, and start / stop apps by ID. Here is what THIS machine would show them:");
        Say("");

        var apps = HolyMother.LocalApps();
        foreach (var group in apps.GroupBy(a => a.Source))
            Say($"   {group.Key}: {group.Count()} apps, {group.Count(a => a.Running)} running");

        Say("");
        var Pictures = HolyMother.LocalIcons(apps.Take(40).Select(a => a.Name));
        Say($"Pictures: {Pictures.Count} of the first 40 apps have one ({Pictures.Values.Sum(p => p.Length) / 1024} KB in all), asked for by name.");

        Say("Running right now:");
        foreach (var app in HolyMother.LocalRunning().Take(15)) Say($"   {app.Name}  [{app.ID}]");
    }

    // ── audit: a log you can show but not edit ───────────────────────────────

    private static async Task AuditExample()
    {
        Say("== Audit log ==");
        Say("Every entry holds the hash of the one before it, so changing, removing, adding or reordering one is detected.\n");

        string folder = Path.Combine(Path.GetTempPath(), "yuuko-audit-demo-" + Guid.NewGuid().ToString("N")[..6]);
        Directory.CreateDirectory(folder);
        string file = Path.Combine(folder, "audit.log");
        var key = new SecureData(Encoding.UTF8.GetBytes("an-audit-key-only-the-owner-knows"));   // NOT SecureData.FromString: that wipes the string you pass it

        using var bus = new LocalBroker();
        var ids = new[] { "pc", "phone", "stranger" }.ToDictionary(n => n, n => YuukoIdentity.Create(n));
        var pcOptions = new EclipseBrokerOptions { CommandTimeout = TimeSpan.FromSeconds(3) };
        pcOptions.Handshake.RequireKnownDevices = true;   // only devices that were paired may connect
        using var pc = EclipseBroker.Create(bus, ids["pc"], pcOptions);
        using var phone = EclipseBroker.Create(bus, ids["phone"], new EclipseBrokerOptions { CommandTimeout = TimeSpan.FromSeconds(3) });
        using var stranger = EclipseBroker.Create(bus, ids["stranger"], new EclipseBrokerOptions { CommandTimeout = TimeSpan.FromSeconds(3) });

        using var audit = AuditLog.Open(file, key);       // read + append; one writer at a time
        using var recording = audit.Attach(pc);            // now the PC's security-relevant decisions are written down by themselves
        await pc.StartAsync(); await phone.StartAsync(); await stranger.StartAsync();

        Say("A stranger knocks (it was never paired), then the phone pairs with a code, then the PC bans the phone:");
        for (int i = 0; i < 3; i++) await stranger.PingAsync("pc");
        var offer = pc.BeginPairing();
        await phone.PairWithAsync(offer.Code);
        await pc.KickAsync("phone", ban: true, reason: "lost device");
        audit.Append("report.opened", subject: "q3.pdf", detail: "you can record your own events too", actor: "pc");
        await Task.Delay(300);

        Say("\nWhat the log says:");
        foreach (var e in audit.Read()) Say($"   #{e.Seq,-2} {e.TimeUtc:HH:mm:ss}  {e.Kind,-20} {e.Subject,-10} {e.Detail}");
        var result = audit.Verify();
        Say($"\nVerify: ok={result.Ok}, entries={result.Entries}");
        Say("   (three knocks from the same stranger were written as ONE entry: a flood cannot fill the disk)\n");

        string copy = Path.Combine(folder, "tampered.log");
        // (File.ReadAllLines would refuse: the log is open for writing right now, which is exactly what a read-only viewer is for.)
        string[] lines;
        using (var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
        using (var reader = new StreamReader(fs))
            lines = reader.ReadToEnd().Split(new[] { '\n' }, StringSplitOptions.RemoveEmptyEntries);
        lines[1] = lines[1].Replace("pairing.offered", "pairing.offerad");
        File.WriteAllLines(copy, lines);
        using (var checkCopy = AuditLog.OpenReadOnly(copy, key))
        {
            var bad = checkCopy.Verify();
            Say($"Someone edits one word of entry 2 in a copy... Verify: ok={bad.Ok}. {bad.Problem}");
        }

        using (var viewer = AuditLog.OpenReadOnly(file, key))
        {
            Say($"\nA viewer opened READ-ONLY sees {viewer.Read().Count} entries and can verify them (ok={viewer.Verify().Ok}),");
            try { viewer.Append("x"); } catch (InvalidOperationException e) { Say($"but cannot write: {e.Message}"); }
        }

        var head = audit.Head;
        Say($"\nKeep the newest head somewhere else (seq {head.Seq}, hash {head.Hash[..12]}...): it is the only way to notice entries cut off the END.");
        audit.Seal();
        Say($"Sealed: the file is now read-only at the operating-system level (sealed={AuditLog.IsSealed(file)}). Unseal it deliberately to write again.");

        Say($"\n(the demo files are in {folder})");
    }
}
