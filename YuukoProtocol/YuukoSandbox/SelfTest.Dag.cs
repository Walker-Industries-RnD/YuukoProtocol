using System.Text;
using WISecureData;
using YuukoProtocol;
using YuukoProtocol.Dogma;

namespace YuukoSandbox;

// Tests for folder sync (DAG): paths that can't be trusted, hashing, and real syncs between devices (new files, changes, deletes, conflicts, resumed and corrupted downloads).
public static partial class SelfTest
{
    private static void Put(string folder, string relative, byte[] content, int secondsAgo = 0)
    {
        string full = Path.Combine(folder, relative.Replace('/', Path.DirectorySeparatorChar));
        Directory.CreateDirectory(Path.GetDirectoryName(full)!);
        File.WriteAllBytes(full, content);
        File.SetLastWriteTimeUtc(full, DateTime.UtcNow.AddSeconds(-secondsAgo));
    }

    private static void Put(string folder, string relative, string text, int secondsAgo = 0) => Put(folder, relative, Encoding.UTF8.GetBytes(text), secondsAgo);

    private static byte[] Bytes(int length, int seed)
    {
        var data = new byte[length];
        new Random(seed).NextBytes(data);
        return data;
    }

    // Every file in a folder (not .yuuko) with its content, so two folders can be compared
    private static Dictionary<string, string> Snapshot(string folder) =>
        Directory.EnumerateFiles(folder, "*", SearchOption.AllDirectories)
            .Where(f => !Path.GetRelativePath(folder, f).StartsWith(".yuuko"))
            .ToDictionary(f => Path.GetRelativePath(folder, f).Replace('\\', '/'), f => Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(File.ReadAllBytes(f))));

    private static bool SameFolders(string a, string b)
    {
        try
        {
            var x = Snapshot(a); var y = Snapshot(b);
            return x.Count == y.Count && x.All(p => y.TryGetValue(p.Key, out var h) && h == p.Value);
        }
        catch (IOException) { return false; }     // a file was being moved while we looked, so they aren't the same yet
    }

    private static async Task<bool> ThrowsAny(Func<Task> action)
    {
        try { await action(); return false; }
        catch { return true; }
    }

    private static async Task DagTests()
    {
        Section("folder sync (DAG)");

        // ---- paths another device sends are never trusted ----
        Check("normal relative paths are accepted", DAG.SafeRelative("a.txt") && DAG.SafeRelative("notes/2026/a b.txt"));
        Check("paths that climb out, start at a root or use a drive are refused", !DAG.SafeRelative("../x") && !DAG.SafeRelative("a/../../x") && !DAG.SafeRelative("/etc/passwd") && !DAG.SafeRelative("C:/x") && !DAG.SafeRelative("a\\b"));
        Check("empty parts, dots and the .yuuko folder are refused", !DAG.SafeRelative("a//b") && !DAG.SafeRelative("./a") && !DAG.SafeRelative(".yuuko/trash/x") && !DAG.SafeRelative(".YUUKO/x") && !DAG.SafeRelative("") && !DAG.SafeRelative("a/"));
        Check("names Windows would treat differently are refused", !DAG.SafeRelative("a.") && !DAG.SafeRelative("a ") && !DAG.SafeRelative("a/b?c"));

        string root = TempDir("dag");
        string shop = Path.Combine(root, "shop"); Directory.CreateDirectory(shop);
        Check("a safe path lands inside the folder", DAG.SafePath(shop, "x/y.txt").StartsWith(Path.GetFullPath(shop)));
        Check("a path that would leave the folder throws", Catch(() => DAG.SafePath(shop, "../out.txt")) is InvalidDataException);
        Check("conflict names are made from the content, so every device makes the same one", DAG.ConflictPath("notes/a.txt", "1a2b3c4d5e6f") == "notes/a (conflict 1a2b3c4d).txt" && DAG.ConflictPath("b", "ffffffff00") == "b (conflict ffffffff)");

        // ---- hashing ----
        Put(shop, "same.bin", Bytes(600_000, 1)); Put(shop, "copy/same.bin", Bytes(600_000, 1)); Put(shop, "other.bin", Bytes(600_000, 2));
        Put(shop, "empty.txt", ""); Put(shop, "exact.bin", Bytes(DAG.ChunkSize, 3)); Put(shop, "one-more.bin", Bytes(DAG.ChunkSize + 1, 4));
        Put(Path.Combine(shop, ".yuuko"), "ignored.txt", "x");
        var scan = DAG.Scan(shop, null);
        Check("the same content has the same hash wherever it is, different content doesn't", scan["same.bin"].Hash == scan["copy/same.bin"].Hash && scan["same.bin"].Hash != scan["other.bin"].Hash);
        Check("files exactly one chunk long and one byte over work, and so do empty ones", scan["exact.bin"].Size == DAG.ChunkSize && scan["one-more.bin"].Hash != scan["exact.bin"].Hash && scan["empty.txt"].Size == 0);
        Check("the .yuuko folder isn't part of the folder", !scan.Keys.Any(k => k.StartsWith(".yuuko")));
        var fake = new Dictionary<string, DAG.FileState> { ["same.bin"] = new("f".PadRight(64, 'f'), scan["same.bin"].Size, scan["same.bin"].Modified) };
        Check("a file whose size and time didn't change isn't read again", DAG.Scan(shop, fake)["same.bin"].Hash == fake["same.bin"].Hash);
        Check("the folder's hash doesn't depend on the order", DAG.RootHash(scan) == DAG.RootHash(scan.Reverse().ToDictionary(p => p.Key, p => p.Value)));

        // ---- between devices ----
        using var bus = new LocalBroker();
        var (n, _) = await Group(bus, new[] { "pc", "phone", "stranger", "evil" }, new[] { ("pc", "phone"), ("pc", "stranger"), ("phone", "evil") });
        var pc = new DAG.Syncer(n["pc"], null);
        var phone = new DAG.Syncer(n["phone"], null);
        var stranger = new DAG.Syncer(n["stranger"], null);
        string pcDir = Path.Combine(root, "pc-docs"), phoneDir = Path.Combine(root, "phone-docs");
        Directory.CreateDirectory(pcDir);
        try
        {
            Put(pcDir, "readme.txt", "hello", 100); Put(pcDir, "notes/2026/big.bin", Bytes(700_000, 5), 90); Put(pcDir, "notes/empty.txt", "", 80); Put(pcDir, "keep.txt", "keep", 70);
            var entry = await pc.Share(pcDir, new List<string> { "phone" });
            Check("sharing a folder gives it a UUID and its folder hash", entry.UUID.Length > 8 && entry.Hash == DAG.RootHash(DAG.Scan(pcDir, null)) && entry.Baseline.Count == 0);
            Check("the same folder can't be shared twice", await ThrowsAny(() => pc.Share(pcDir, new List<string> { "phone" })));

            await phone.Join(entry.UUID, phoneDir, new List<string> { "pc" });
            Check("the other device can see the folder is shared with it", await phone.Exists("pc", entry.UUID));
            Check("a device that isn't on the list can't even tell whether it exists", !await stranger.Exists("pc", entry.UUID));
            Check("...and can't ask for its files", await ThrowsAny(async () => { await stranger.Join(entry.UUID, Path.Combine(root, "stranger"), new List<string> { "pc" }); await stranger.Sync("pc", entry.UUID); }));
            Check("before syncing, the device knows there is something to get", await phone.HasUpdate("pc", entry.UUID));

            var progress = new List<string>();
            DAG.Progress += (u, p, done, total) => { if (p == "notes/2026/big.bin") lock (progress) progress.Add(done + "/" + total); };
            var first = await phone.Sync("pc", entry.UUID);
            Check("the first sync gets every file", first.Downloaded == 4 && first.Errors.Count == 0 && SameFolders(pcDir, phoneDir));
            Check("...with the same times, so nothing looks changed afterwards", File.GetLastWriteTimeUtc(Path.Combine(phoneDir, "readme.txt")) == File.GetLastWriteTimeUtc(Path.Combine(pcDir, "readme.txt")));
            lock (progress) Check("a big file is sent in chunks and progress is reported", progress.Count == 3 && progress.Last() == "700000/700000");
            var again = await phone.Sync("pc", entry.UUID);
            Check("syncing again changes nothing", again.AlreadyInSync && again.Downloaded == 0);
            Check("...and there is nothing new to get", !await phone.HasUpdate("pc", entry.UUID));
            Check("the folder hash is the same on both devices", DAG.RootHash(DAG.Scan(pcDir, null)) == DAG.RootHash(DAG.Scan(phoneDir, null)));

            // changes: new, edited, deleted
            Put(pcDir, "readme.txt", "hello, edited", 5); Put(pcDir, "new/file.txt", "new", 5); File.Delete(Path.Combine(pcDir, "keep.txt"));
            var second = await phone.Sync("pc", entry.UUID);
            Check("an edit, a new file and a delete all arrive", second.Downloaded == 2 && second.Deleted == 1 && SameFolders(pcDir, phoneDir));
            Check("a deleted file is moved to .yuuko/trash, not erased", Directory.EnumerateFiles(Path.Combine(phoneDir, ".yuuko", "trash"), "keep.txt", SearchOption.AllDirectories).Any());

            // a device that was changed only on its side doesn't lose it, and the other device gets it
            Put(phoneDir, "from-phone.txt", "phone made this", 2);
            var pushed = await phone.Sync("pc", entry.UUID);
            Check("something only this device changed isn't touched, and is flagged for the other device", pushed.LocalChanges && pushed.Downloaded == 0 && pushed.Errors.Count == 0);
            Check("...which then comes and gets it by itself (it was told)", await Eventually(() => File.Exists(Path.Combine(pcDir, "from-phone.txt")), 8000));

            // both changed the same file: newest wins on BOTH, the other is kept beside it, and both end up the same
            Put(pcDir, "readme.txt", "pc version", 20); Put(phoneDir, "readme.txt", "phone version, newer", 1);
            var conflict = await pc.Sync("phone", entry.UUID);
            Check("a file both changed is reported as a conflict", conflict.Conflicts.Contains("readme.txt"));
            Check("the newest version wins", File.ReadAllText(Path.Combine(pcDir, "readme.txt")) == "phone version, newer");
            Check("the other one is kept beside it", Directory.GetFiles(pcDir, "readme (conflict *).txt").Length == 1 && File.ReadAllText(Directory.GetFiles(pcDir, "readme (conflict *).txt")[0]) == "pc version");
            Check("both devices end up with exactly the same files (the other one syncs by itself)", await Eventually(() => SameFolders(pcDir, phoneDir), 8000));
            Check("...and exactly one conflict copy on each, not a new one every sync", Directory.GetFiles(phoneDir, "readme (conflict *).txt").Length == 1 && Directory.GetFiles(pcDir, "readme (conflict *).txt").Length == 1);

            // ...and when OUR version is the newest, it stays and theirs is kept beside it
            Put(pcDir, "mine.txt", "base", 60);
            await phone.Sync("pc", entry.UUID);
            Put(pcDir, "mine.txt", "pc is newest", 1); Put(phoneDir, "mine.txt", "phone is older", 30);
            await pc.Sync("phone", entry.UUID);
            Check("our version stays when it's the newest", File.ReadAllText(Path.Combine(pcDir, "mine.txt")) == "pc is newest");
            Check("...and theirs is kept beside it", Directory.GetFiles(pcDir, "mine (conflict *).txt").Length == 1 && File.ReadAllText(Directory.GetFiles(pcDir, "mine (conflict *).txt")[0]) == "phone is older");
            Check("...and both devices end up the same", await Eventually(() => SameFolders(pcDir, phoneDir) && File.Exists(Path.Combine(phoneDir, "mine.txt")) && File.ReadAllText(Path.Combine(phoneDir, "mine.txt")) == "pc is newest", 8000));

            // a download that stopped half way continues, one that arrived wrong is thrown away
            byte[] resumable = Bytes(700_000, 9);
            Put(pcDir, "resume.bin", resumable, 3);
            string hash = DAG.Scan(pcDir, null)["resume.bin"].Hash;
            string partials = Path.Combine(phoneDir, ".yuuko", "partial"); Directory.CreateDirectory(partials);
            File.WriteAllBytes(Path.Combine(partials, hash), resumable.Take(DAG.ChunkSize + 1000).ToArray());   // one whole chunk plus a bit: the bit is dropped and fetched again
            lock (progress) progress.Clear();
            DAG.Progress += (u, p, done, total) => { if (p == "resume.bin") lock (progress) progress.Add(done + "/" + total); };
            var resumed = await phone.Sync("pc", entry.UUID);
            Check("a stopped download is finished and the file is right", resumed.Errors.Count == 0 && File.ReadAllBytes(Path.Combine(phoneDir, "resume.bin")).SequenceEqual(resumable));
            lock (progress) Check("...by asking only for the chunks it was missing", progress.Count == 2);

            byte[] wrong = Bytes(700_000, 10);
            Put(pcDir, "wrong.bin", wrong, 3);
            string wrongHash = DAG.Scan(pcDir, null)["wrong.bin"].Hash;
            File.WriteAllBytes(Path.Combine(partials, wrongHash), Bytes(DAG.ChunkSize, 99));   // the first chunk is garbage
            var bad = await phone.Sync("pc", entry.UUID);
            Check("a file that arrives wrong is refused and not put in the folder", bad.Errors.Count == 1 && !File.Exists(Path.Combine(phoneDir, "wrong.bin")) && !File.Exists(Path.Combine(partials, wrongHash)));
            var healed = await phone.Sync("pc", entry.UUID);
            Check("...and the next sync gets it right", healed.Errors.Count == 0 && File.ReadAllBytes(Path.Combine(phoneDir, "wrong.bin")).SequenceEqual(wrong));

            // other devices can only ask for what is in the folder
            string Chunk(string path) => "{\"u\":\"" + entry.UUID + "\",\"p\":\"" + path + "\",\"i\":0}";
            File.WriteAllText(Path.Combine(root, "secret.txt"), "secret");
            Put(pcDir, ".yuuko/hidden.txt", "hidden");
            var climb = await n["phone"].SendCommandAsync("pc", "dag.chunk", Encoding.UTF8.GetBytes(Chunk("../secret.txt")));
            var hidden = await n["phone"].SendCommandAsync("pc", "dag.chunk", Encoding.UTF8.GetBytes(Chunk(".yuuko/hidden.txt")));
            var unknown = await n["phone"].SendCommandAsync("pc", "dag.chunk", Encoding.UTF8.GetBytes(Chunk("not-in-the-list.txt")));
            var real = await n["phone"].SendCommandAsync("pc", "dag.chunk", Encoding.UTF8.GetBytes(Chunk("readme.txt")));
            var wrongFolder = await n["phone"].SendCommandAsync("pc", "dag.chunk", Encoding.UTF8.GetBytes(Chunk("readme.txt").Replace(entry.UUID, "nope")));
            Check("a file outside the folder, one in .yuuko and one that isn't listed are refused", climb.Status == AckStatus.Error && hidden.Status == AckStatus.Error && unknown.Status == AckStatus.Error);
            Check("a file in the list is sent, and a folder that isn't shared isn't", real.IsOk && real.Result.Length > 0 && wrongFolder.Status == AckStatus.Denied);
            Check("a device not on the list gets nothing even for a real file", (await n["stranger"].SendCommandAsync("pc", "dag.chunk", Encoding.UTF8.GetBytes(Chunk("readme.txt")))).Status == AckStatus.Denied);

            // a device that lies about its files can't write outside the folder
            n["evil"].On("dag.manifest", (c, _) => Task.FromResult(CommandResult.Ok(
                "{\"../escaped.txt\":{\"h\":\"" + new string('a', 64) + "\",\"s\":1,\"t\":1}}")));
            Check("a file list with a path that climbs out is refused as a whole", await ThrowsAny(() => phone.Sync("evil", entry.UUID)) && !File.Exists(Path.Combine(Path.GetDirectoryName(phoneDir)!, "escaped.txt")));

            // stop sharing
            await pc.Stop(entry.UUID);
            Check("a folder that is no longer shared can't be synced from", await ThrowsAny(() => phone.Sync("pc", entry.UUID)) && !await phone.Exists("pc", entry.UUID));
            Check("stopping doesn't touch the files", File.Exists(Path.Combine(pcDir, "readme.txt")));
        }
        finally
        {
            pc.Dispose(); phone.Dispose(); stranger.Dispose();
            foreach (var node in n.Values) node.Dispose();
        }

        // ---- things that must never happen ----
        using var bus2 = new LocalBroker();
        var (m, _) = await Group(bus2, new[] { "a", "b" }, new[] { ("a", "b") });
        var a = new DAG.Syncer(m["a"], null); var b = new DAG.Syncer(m["b"], null);
        string aDir = Path.Combine(root, "a-files"), bDir = Path.Combine(root, "b-files");
        Directory.CreateDirectory(aDir);
        try
        {
            for (int i = 0; i < 12; i++) Put(aDir, $"f{i}.txt", "file " + i, 50);
            var shared = await a.Share(aDir, new List<string> { "b" });
            await b.Join(shared.UUID, bDir, new List<string> { "a" });
            await b.Sync("a", shared.UUID);
            Check("(setup) twelve files are on both devices", Directory.GetFiles(bDir).Length == 12);

            foreach (var f in Directory.GetFiles(aDir)) File.Delete(f);
            var guarded = await b.Sync("a", shared.UUID);
            Check("when a sync would delete nearly everything, nothing is deleted", guarded.Errors.Count == 1 && guarded.Deleted == 0 && Directory.GetFiles(bDir).Length == 12);

            DAG.AllowMassDelete = true;
            try { var allowed = await b.Sync("a", shared.UUID); Check("...unless that was allowed", allowed.Deleted == 12 && Directory.GetFiles(bDir).Length == 0); }
            finally { DAG.AllowMassDelete = false; }

            Directory.Delete(aDir, true);
            Check("a folder that isn't there (an unplugged drive) is an error, not an empty folder", await ThrowsAny(() => a.Sync("b", shared.UUID)));
        }
        finally { a.Dispose(); b.Dispose(); foreach (var node in m.Values) node.Dispose(); }

        // ---- the repository is saved encrypted and comes back ----
        using var bus3 = new LocalBroker();
        var (r, _) = await Group(bus3, new[] { "x" }, Array.Empty<(string, string)>());
        string oldRepo = DAG.RepoPath;
        DAG.RepoPath = TempDir("dag-repo");
        var key = new SecureData(Encoding.UTF8.GetBytes("a-repository-key-for-the-tests"));   // NOT SecureData.FromString: that wipes the string you pass it
        try
        {
            string saved = Path.Combine(root, "saved"); Put(saved, "a.txt", "a", 10);
            var one = new DAG.Syncer(r["x"], key);
            await one.Load();
            var kept = await one.Share(saved, new List<string> { "y" });
            one.Dispose();

            var two = new DAG.Syncer(r["x"], key);
            await two.Load();
            Check("a shared folder is still shared after the repository is loaded again", (await DAG.GetSpecificEntry(kept.UUID, key))?.ParentPath == Path.GetFullPath(saved));
            await two.Stop(kept.UUID);
            Check("stopping removes it from the repository", (await DAG.GetAllEntries(null, key)).Count == 0);
            two.Dispose();
        }
        finally { DAG.RepoPath = oldRepo; foreach (var node in r.Values) node.Dispose(); }
    }
}
