using System.Security.Cryptography;
using System.Text;
using WISecureData;
using YuukoProtocol;

namespace YuukoSandbox;

// Tests for the device list file: it survives a restart, is unreadable and tamper-evident without the key,
// refuses (never "forgets") anything it cannot open, and a failed or interrupted save loses nothing.
public static partial class SelfTest
{
    private static SecureData DirKey(string password = "a-test-key-for-the-device-list-file") =>
        new SecureData(Encoding.UTF8.GetBytes(password));

    private static string RandomFingerprint() => Convert.ToHexString(RandomNumberGenerator.GetBytes(32)).ToLowerInvariant();

    private static Exception? Catch(Action a)
    {
        try { a(); return null; } catch (Exception e) { return e; }
    }

    private static async Task DeviceDirectoryFile()
    {
        Section("device list file (encrypted, tamper-evident, crash-safe)");
        var key = DirKey();
        string folder = TempDir("devlist");
        string file = Path.Combine(folder, "devices.json");
        string fpA = RandomFingerprint(), fpB = RandomFingerprint();

        var d = new DeviceDirectory(key, file);
        Check("a new path starts empty and writes nothing yet", d.All().Count == 0 && !File.Exists(file));
        d.Add("alpha", "a-id", fpA, "Device A", new[] { "g1", "g2" });
        d.Add("beta", "b-id", fpB);
        Check("the file exists after the first change", File.Exists(file));
        Check("...and no temporary file is left behind", !Directory.GetFiles(folder).Any(f => f.Contains(".saving")));

        var back = new DeviceDirectory(key, file);
        Check("a saved list comes back after a restart, exactly",
            back.All().Count == 2 && back.Find("alpha")?.Fingerprint == fpA && back.Find("alpha")!.Groups.SequenceEqual(new[] { "g1", "g2" })
            && back.Find("alpha")!.DisplayName == "Device A" && back.Find("beta")?.ClientId == "b-id");
        Check("the same key object can be used again and again (nothing consumes it)", new DeviceDirectory(key, file).All().Count == 2);

        string raw = Encoding.Latin1.GetString(File.ReadAllBytes(file));
        Check("the file shows no names, ids or fingerprints", !raw.Contains("a-id") && !raw.Contains(fpA) && !raw.Contains("Device A") && !raw.Contains("alpha"));

        d.Rename("beta", "gamma");
        d.SetGroups("alpha", new[] { "only" });
        d.Remove("gamma");
        var back2 = new DeviceDirectory(key, file);
        Check("renames, regrouping and removal are saved too", back2.All().Count == 1 && back2.Find("alpha")!.Groups.SequenceEqual(new[] { "only" }));

        // The previous version is kept.
        string bak = file + ".bak";
        Check("the previous version is kept as a backup", File.Exists(bak));
        string bakFolder = TempDir("bak");
        File.Copy(bak, Path.Combine(bakFolder, "devices.json"));
        Check("...and it is the version from just before the last change (it can be opened with the key)",
            new DeviceDirectory(key, Path.Combine(bakFolder, "devices.json")).All().Count == 2);

        // The wrong key.
        byte[] good = File.ReadAllBytes(file);
        var wrong = Catch(() => new DeviceDirectory(DirKey("a-different-key-entirely-not-the-same"), file));
        Check("the wrong key is refused, and says so", wrong is FormatException && wrong.Message.Contains("wrong key"));
        Check("...and mentions the backup so a person can decide", wrong!.Message.Contains(".bak"));
        Check("...and the file is left exactly as it was", File.ReadAllBytes(file).SequenceEqual(good));

        // Tampering, damage, truncation, junk: all refused, none treated as an empty list.
        int refused = 0, tried = 0;
        foreach (double where in new[] { 0.05, 0.2, 0.35, 0.5, 0.65, 0.8, 0.95 })
        {
            string tf = Path.Combine(TempDir("tamper"), "devices.json");
            var copy = (byte[])good.Clone();
            copy[(int)(copy.Length * where)] ^= 0x01;
            File.WriteAllBytes(tf, copy);
            tried++;
            if (Catch(() => new DeviceDirectory(key, tf)) is FormatException) refused++;
        }
        Check($"one flipped bit anywhere in the file is noticed and refused ({refused}/{tried} places tried)", refused == tried);

        string TryFile(byte[] content)
        {
            string tf = Path.Combine(TempDir("bad"), "devices.json");
            File.WriteAllBytes(tf, content);
            return tf;
        }
        Check("a half-written file (a crash mid-save) is refused, not read as empty",
            Catch(() => new DeviceDirectory(key, TryFile(good[..(good.Length / 2)]))) is FormatException);
        Check("an empty file is refused, not read as empty", Catch(() => new DeviceDirectory(key, TryFile(Array.Empty<byte>()))) is FormatException);
        Check("a text file is refused", Catch(() => new DeviceDirectory(key, TryFile(Encoding.UTF8.GetBytes("not a device list")))) is FormatException);
        Check("a plain (unencrypted) JSON list is refused: it would let anyone write one",
            Catch(() => new DeviceDirectory(key, TryFile(Encoding.UTF8.GetBytes("{\"Version\":1,\"Devices\":[]}")))) is FormatException);

        // Correctly encrypted, but with contents we would never write.
        string crafted = Path.Combine(TempDir("crafted"), "devices.json");
        async Task<Exception?> Crafted(string json)
        {
            await DeviceDirectory.WriteFileAsync(crafted, key, json);
            return Catch(() => new DeviceDirectory(key, crafted));
        }
        string Entry(string moniker, string id, string fp) =>
            $"{{\"Moniker\":\"{moniker}\",\"ClientId\":\"{id}\",\"Fingerprint\":\"{fp}\",\"DisplayName\":null,\"Groups\":[]}}";
        Check("(control) a crafted file that is valid loads", (await Crafted("{\"Version\":1,\"Devices\":[" + Entry("ok", "ok-id", fpA) + "]}")) is null);
        Check("a file from a newer version is refused", (await Crafted("{\"Version\":2,\"Devices\":[]}")) is FormatException);
        Check("a file that lists a device twice is refused",
            (await Crafted("{\"Version\":1,\"Devices\":[" + Entry("a", "a-id", fpA) + "," + Entry("b", "b-id", fpA) + "]}")) is FormatException);
        Check("a file with a malformed fingerprint is refused", (await Crafted("{\"Version\":1,\"Devices\":[" + Entry("a", "a-id", "nope") + "]}")) is FormatException);
        Check("a file with an invalid nickname is refused", (await Crafted("{\"Version\":1,\"Devices\":[" + Entry("bad name!", "a-id", fpA) + "]}")) is FormatException);

        // A save that fails must be reported and undone.
        string blocker = Path.Combine(TempDir("block"), "iamafile");
        File.WriteAllText(blocker, "x");
        var bad = new DeviceDirectory(key, Path.Combine(blocker, "sub", "devices.json"));
        int raised = 0;
        bad.Changed += () => raised++;
        Check("a save that fails is reported to the caller", Catch(() => bad.Add("x", "x-id", RandomFingerprint())) is not null);
        Check("...the change is undone and nothing is announced", bad.All().Count == 0 && raised == 0);

        // Many changes at once.
        string cf = Path.Combine(TempDir("conc"), "devices.json");
        var cd = new DeviceDirectory(key, cf);
        await Task.WhenAll(Enumerable.Range(0, 24).Select(i => Task.Run(() => cd.Add("dev" + i, "id" + i, RandomFingerprint()))));
        Check("24 devices added at the same moment are all saved", cd.All().Count == 24 && new DeviceDirectory(key, cf).All().Count == 24);

        // A leftover from a crash.
        string leftover = Path.Combine(folder, "devices.saving.json");
        File.WriteAllText(leftover, "left over from a crash");
        var clock = System.Diagnostics.Stopwatch.StartNew();
        d.Add("delta", "d-id", RandomFingerprint());
        long saveMs = clock.ElapsedMilliseconds;
        clock.Restart();
        var reopened = new DeviceDirectory(key, file);
        long loadMs = clock.ElapsedMilliseconds;
        Check($"a temporary file left by a crash does not get in the way and is cleaned up (one save took {saveMs} ms, one load {loadMs} ms)",
            reopened.Find("delta") is not null && !File.Exists(leftover));

        // Paths and arguments.
        Check("a path with another extension is refused", Catch(() => new DeviceDirectory(key, Path.Combine(folder, "devices.dat"))) is ArgumentException);
        string noExt = Path.Combine(TempDir("noext"), "list");
        new DeviceDirectory(key, noExt).Add("n", "n-id", RandomFingerprint());
        Check("a path with no extension is stored as .json", File.Exists(noExt + ".json"));
        string memFolder = TempDir("mem");
        new DeviceDirectory(key).Add("m", "m-id", RandomFingerprint());
        Check("a directory with a key but no path stays in memory and writes nothing", Directory.GetFiles(memFolder).Length == 0);

        // The real thing: a paired device is still trusted after the node restarts.
        {
            using var bus = new LocalBroker();
            string pf = Path.Combine(TempDir("restart"), "devices.json");
            var anchorId = YuukoIdentity.Create("anchor");
            var phoneId = YuukoIdentity.Create("phone");

            using (var a1 = Node(bus, anchorId, o => o.Directory = new DeviceDirectory(key, pf)))
            using (var b1 = Node(bus, phoneId))
            {
                await a1.StartAsync(); await b1.StartAsync();
                var paired = await b1.PairWithAsync(a1.BeginPairing().Code, moniker: "main");
                Check("(setup) a device pairs with a node that keeps its list in a file", paired.Success && File.Exists(pf));
            }

            using var a2 = Node(bus, anchorId, o => o.Directory = new DeviceDirectory(key, pf));
            using var b2 = Node(bus, phoneId, o => o.Handshake.TrustDevice("anchor", anchorId.Fingerprint));
            using var stranger = Node(bus, YuukoIdentity.Create("stranger"));
            await a2.StartAsync(); await b2.StartAsync(); await stranger.StartAsync();
            Check("after a restart the node still knows the paired device (no new pairing)", a2.Devices.FindByClientId("phone")?.Moniker == "phone");
            Check("...so that device can connect straight away", (await b2.PingAsync("anchor")).IsOk);
            Check("...and a stranger still cannot", !(await stranger.PingAsync("anchor")).IsOk);
        }
    }
}
