// DAG.Sync.cs - DOGMA IV: the file sync. DAG.cs has the repository and the explanation, this is what talks to the other devices.
//
// Commands between devices (All of them are checked against the folder's device list first):
//   dag.exists   Do you share this folder?
//   dag.manifest Send me your list of files (path, hash, size, time)
//   dag.chunk    Send me chunk number N of this file
//   dag.notice   This folder changed here, come and get it

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.Json.Serialization;
using System.Threading;
using System.Threading.Tasks;
using WISecureData;

namespace YuukoProtocol.Dogma
{
    public static partial class DAG
    {
        public record FileState
        {
            [JsonPropertyName("h")] public string Hash { get; set; } = "";
            [JsonPropertyName("s")] public long Size { get; set; }
            [JsonPropertyName("t")] public long Modified { get; set; }       //UTC ticks

            public FileState() { }

            public FileState(string hash, long size, long modified)
            {
                Hash = hash;
                Size = size;
                Modified = modified;
            }
        }

        public class SyncResult
        {
            public int Downloaded;
            public int Deleted;
            public bool AlreadyInSync;
            public bool LocalChanges;                                     //We have things they don't (They'll be told to come and get them)
            public List<string> Conflicts = new();                        //Both changed it, the newest won and the other is next to it
            public List<string> Errors = new();
        }

        //Fires when a sync changed something on this device (UUID, the device it came from, what happened), apps use it to say "This was updated thanks to something elsewhere"
        public static event Action<string, string, SyncResult>? FolderUpdated;

        //Something went wrong in the background (A notice we couldn't act on)
        public static event Action<string>? Problem;

        //Download progress (UUID, path, bytes done, bytes total)
        public static event Action<string, string, long, long>? Progress;

        //If more than this many files, and more than half, would be deleted in one sync, nothing is deleted (They are only moved to .yuuko/trash anyway)
        public static bool AllowMassDelete { get; set; } = false;

        //Sync by itself when a device says a folder changed, or when a listed device connects
        public static bool AutoSync { get; set; } = true;

        public const int ChunkSize = 256 * 1024;
        public const int MaxFiles = 4000;
        public const long MaxFileBytes = 4L * 1024 * 1024 * 1024;

        internal static EclipseBroker? Node;
        static Syncer? _Default;

        static Syncer Default => _Default ?? throw new InvalidOperationException("Call DAG.Start(key) first.");

        //What the last sync with each folder did
        public static readonly ConcurrentDictionary<string, SyncResult> LastSync = new();

        //Loads the repository and starts listening for other devices, call it once after Identity.CreateNode
        public static async Task Start(SecureData Key)
        {
            var Net = Node ?? Identity.YuukoNode ?? throw new InvalidOperationException("Create the node first (Identity.CreateNode).");

            Directory.CreateDirectory(RepoPath);
            _Default?.Dispose();
            _Default = new Syncer(Net, Key);
            await _Default.Load();
        }

        //The node was built again, call Start() again
        internal static void Reset()
        {
            _Default?.Dispose();
            _Default = null;
        }

        #region Create

        //Share a folder from this device with the listed devices, comes back with the UUID the other devices join with
        public static Task<RepositoryEntry> ShareFolder(string DirectoryPath, List<string> Devices) => Default.Share(DirectoryPath, Devices);

        //Join a folder another device shared, same UUID but YOUR path for it (Files already there are kept)
        public static Task<RepositoryEntry> JoinFolder(string UUID, string DirectoryPath, List<string> Devices) => Default.Join(UUID, DirectoryPath, Devices);

        #endregion

        #region Read

        //Does another device share this folder with us?
        public static Task<bool> CheckIfFolderExists(string DeviceToAsk, string UUID) => Default.Exists(DeviceToAsk, UUID);

        //Does another device have something different from us? (Doesn't change anything)
        public static Task<bool> CheckForUpdate(string DeviceToAsk, string UUID) => Default.HasUpdate(DeviceToAsk, UUID);

        #endregion

        #region Update

        //Get what another device has (Continues by itself if an earlier one stopped)
        public static Task<SyncResult> SyncFolder(string DeviceToSyncFrom, string UUID) => Default.Sync(DeviceToSyncFrom, UUID);

        //Tell every connected device this folder changed here, the ones that share it come and get it
        public static Task BroadcastUpdate(string UUID) => Default.Broadcast(UUID);

        #endregion

        #region Delete

        //Stop sharing a folder on this device (The files stay where they are)
        public static Task StopSharing(string UUID) => Default.Stop(UUID);

        #endregion


        internal sealed class Syncer : IDisposable
        {
            readonly EclipseBroker Net;
            readonly SecureData? Key;                                       //Null means nothing is saved (Tests)
            readonly ConcurrentDictionary<string, RepositoryEntry> Folders = new();
            readonly ConcurrentDictionary<string, SemaphoreSlim> Gates = new();
            readonly ConcurrentDictionary<string, bool> Busy = new();
            readonly ConcurrentDictionary<string, string> Again = new();
            readonly ConcurrentDictionary<string, Dictionary<string, FileState>> Last = new();   //The newest scan, so files that didn't change aren't read again
            readonly SemaphoreSlim RepoLock = new(1, 1);
            int _Disposed;

            public Syncer(EclipseBroker Node, SecureData? Key)
            {
                Net = Node;
                this.Key = Key;

                Net.On("dag.exists", (c, _) => Task.FromResult(HandleExists(c)));
                Net.On("dag.manifest", (c, _) => HandleManifest(c));
                Net.On("dag.chunk", (c, _) => HandleChunk(c));
                Net.On("dag.notice", (c, _) => Task.FromResult(HandleNotice(c)));
                Net.PeerConnected += OnPeerConnected;
            }

            public async Task Load()
            {
                if (Key is null) return;

                HashSet<RepositoryEntry> Saved;

                try { Saved = await GetAllEntries(null, Key.Value); }
                catch { await SetupRepo(Key.Value); Saved = new HashSet<RepositoryEntry>(); }

                foreach (var Entry in Saved) Folders[Entry.UUID] = Entry;
            }

            public void Dispose()
            {
                if (Interlocked.Exchange(ref _Disposed, 1) != 0) return;

                Net.PeerConnected -= OnPeerConnected;
                foreach (var Command in new[] { "dag.exists", "dag.manifest", "dag.chunk", "dag.notice" }) Net.Off(Command);
            }

            async Task Save(RepositoryEntry Entry)
            {
                if (Key is null) return;

                await RepoLock.WaitAsync();
                try { await UpdateVariable(Entry.UUID, Entry, Key.Value); }
                finally { RepoLock.Release(); }
            }

            RepositoryEntry Get(string UUID) =>
                Folders.TryGetValue(UUID, out var Entry) ? Entry : throw new KeyNotFoundException("This device doesn't share a folder with that UUID.");

            #region Create

            public async Task<RepositoryEntry> Share(string DirectoryPath, List<string> Devices)
            {
                var Full = Path.GetFullPath(DirectoryPath);
                if (!Directory.Exists(Full)) throw new DirectoryNotFoundException("That folder doesn't exist.");
                if (Folders.Values.Any(f => SamePath(f.ParentPath, Full))) throw new InvalidOperationException("That folder is already shared.");

                //The baseline starts empty on every device, so a device that has nothing yet never looks like it deleted everything
                var Entry = new RepositoryEntry("", DateTime.UtcNow, "Sitting", new List<string>(Devices), Full);
                Entry.Hash = RootHash(await Task.Run(() => Scan(Full, null)));

                Folders[Entry.UUID] = Entry;
                await Save(Entry);
                return Entry;
            }

            public async Task<RepositoryEntry> Join(string UUID, string DirectoryPath, List<string> Devices)
            {
                if (!SafeName(UUID)) throw new ArgumentException("That isn't a folder UUID.");
                if (Folders.ContainsKey(UUID)) throw new InvalidOperationException("That folder is already shared on this device.");

                var Full = Path.GetFullPath(DirectoryPath);
                Directory.CreateDirectory(Full);
                if (Folders.Values.Any(f => SamePath(f.ParentPath, Full))) throw new InvalidOperationException("That folder is already shared.");

                var Entry = new RepositoryEntry("", DateTime.UtcNow, "Sitting", new List<string>(Devices), Full) { UUID = UUID };

                Folders[UUID] = Entry;
                await Save(Entry);
                return Entry;
            }

            #endregion

            #region Read

            public async Task<bool> Exists(string Device, string UUID)
            {
                var Reply = await Net.SendCommandAsync(Device, "dag.exists", Encoding.UTF8.GetBytes(UUID));
                return Reply.IsOk;
            }

            public async Task<bool> HasUpdate(string Device, string UUID)
            {
                var Entry = Get(UUID);
                var Remote = await RemoteFiles(Device, UUID);
                var Local = await Task.Run(() => Scan(Entry.ParentPath, Known(Entry)));

                return RootHash(Remote) != RootHash(Local);
            }

            async Task<Dictionary<string, FileState>> RemoteFiles(string Device, string UUID)
            {
                var Reply = await Net.SendCommandAsync(Device, "dag.manifest", Encoding.UTF8.GetBytes(UUID));
                if (!Reply.IsOk) throw new InvalidOperationException($"{Device} said {Reply.Status}: {Reply.Message}");

                //Whatever they sent is checked before it's trusted, a path from another device is never used as it is
                var Files = JsonSerializer.Deserialize<Dictionary<string, FileState>>(Reply.Result) ?? new();
                if (Files.Count > MaxFiles) throw new InvalidDataException("That device's folder has too many files.");

                foreach (var (Path_, State) in Files)
                {
                    if (!SafeRelative(Path_) || State.Size < 0 || State.Size > MaxFileBytes || !IsHash(State.Hash))
                        throw new InvalidDataException("That device sent a file list we can't trust.");
                }

                return Files;
            }

            Dictionary<string, FileState> Known(RepositoryEntry Entry) =>
                Last.TryGetValue(Entry.UUID, out var Scanned) ? Scanned : Entry.Baseline;

            #endregion

            #region Update

            public async Task<SyncResult> Sync(string Device, string UUID)
            {
                var Entry = Get(UUID);
                var Gate = Gates.GetOrAdd(UUID, _ => new SemaphoreSlim(1, 1));

                //One sync per folder at a time, so lots of devices asking for the same thing can't pile up
                await Gate.WaitAsync();
                try { return await SyncNow(Device, Entry); }
                finally { Gate.Release(); }
            }

            async Task<SyncResult> SyncNow(string Device, RepositoryEntry Entry)
            {
                var Result = new SyncResult();
                var Root = Path.GetFullPath(Entry.ParentPath);

                //A missing folder isn't an empty folder (An unplugged drive must never look like everything was deleted)
                if (!Directory.Exists(Root)) throw new DirectoryNotFoundException("This device's folder isn't there right now.");

                Entry.Status = "Update Pending";
                var Remote = await RemoteFiles(Device, Entry.UUID);
                var Local = await Task.Run(() => Scan(Root, Known(Entry)));
                Entry.Status = "Completing";

                var Deletes = new List<string>();
                var Moves = new List<(string From, string To)>();
                var Downloads = new Dictionary<string, (string Source, FileState State)>();   //Where it goes, where it comes from

                #region Work out who changed what

                foreach (var Path_ in Remote.Keys.Union(Local.Keys).Union(Entry.Baseline.Keys).OrderBy(p => p, StringComparer.Ordinal))
                {
                    Local.TryGetValue(Path_, out var L);
                    Remote.TryGetValue(Path_, out var R);
                    Entry.Baseline.TryGetValue(Path_, out var B);

                    if (Same(L, R)) continue;

                    //Only they changed it
                    if (Same(L, B))
                    {
                        if (R is null) Deletes.Add(Path_);
                        else Downloads[Path_] = (Path_, R);
                    }

                    //Only we changed it, they'll come and get it
                    else if (Same(R, B)) continue;

                    //They deleted it and we changed it, ours stays
                    else if (R is null) continue;

                    //We deleted it and they changed it, theirs comes back
                    else if (L is null) Downloads[Path_] = (Path_, R);

                    //Both changed it: the newest wins on BOTH devices, the other is kept next to it with a name made from its own content, so both devices make the same name
                    else
                    {
                        Result.Conflicts.Add(Path_);

                        if (IsNewer(R, L))
                        {
                            Moves.Add((Path_, ConflictPath(Path_, L.Hash)));
                            Downloads[Path_] = (Path_, R);
                        }
                        else Downloads[ConflictPath(Path_, R.Hash)] = (Path_, R);
                    }
                }

                #endregion

                if (Deletes.Count > 10 && Deletes.Count * 2 > Local.Count && !AllowMassDelete)
                {
                    Result.Errors.Add($"Not deleting {Deletes.Count} of {Local.Count} files, that looks like a mistake (Set DAG.AllowMassDelete if it isn't).");
                    Deletes.Clear();
                }

                foreach (var Path_ in Deletes)
                {
                    try { Trash(Root, Path_); Result.Deleted++; }
                    catch (Exception ex) { Result.Errors.Add($"{Path_}: {ex.Message}"); }
                }

                foreach (var (From, To) in Moves)
                {
                    try { MoveAside(Root, From, To); }
                    catch (Exception ex) { Result.Errors.Add($"{From}: {ex.Message}"); Downloads.Remove(From); }
                }

                //A file we already have under another name doesn't need to be downloaded again
                var HaveHere = new Dictionary<string, string>();
                foreach (var (Path_, State) in Local) HaveHere.TryAdd(State.Hash, Path_);

                foreach (var (Path_, (Source, State)) in Downloads.OrderBy(d => d.Key, StringComparer.Ordinal))
                {
                    try
                    {
                        await Download(Device, Entry.UUID, Root, Source, Path_, State, HaveHere.GetValueOrDefault(State.Hash));
                        Result.Downloaded++;
                    }
                    catch (Exception ex) { Result.Errors.Add($"{Path_}: {ex.Message}"); }
                }

                //What it looks like now, and what the two of us agree on
                var After = await Task.Run(() => Scan(Root, Known(Entry)));
                Last[Entry.UUID] = After;

                foreach (var Path_ in After.Keys.Union(Remote.Keys).Union(Entry.Baseline.Keys))
                {
                    After.TryGetValue(Path_, out var Now);
                    Remote.TryGetValue(Path_, out var Theirs);

                    if (!Same(Now, Theirs)) { Result.LocalChanges = true; continue; }

                    if (Now is null) Entry.Baseline.Remove(Path_);
                    else Entry.Baseline[Path_] = Now;
                }

                Result.AlreadyInSync = !Result.LocalChanges && Result.Downloaded == 0 && Result.Deleted == 0 && Result.Conflicts.Count == 0 && Result.Errors.Count == 0;

                Entry.Hash = RootHash(After);
                Entry.LastUpdated = DateTime.UtcNow;
                Entry.Status = "Sitting";
                await Save(Entry);

                LastSync[Entry.UUID] = Result;
                if (Result.Downloaded + Result.Deleted + Result.Conflicts.Count > 0) FolderUpdated?.Invoke(Entry.UUID, Device, Result);

                //We have things they don't, so they come and get them (Not when something failed, or two devices that can't agree would keep asking each other)
                if (Result.LocalChanges && Result.Errors.Count == 0)
                {
                    try { await Net.SendCommandAsync(Device, "dag.notice", Encoding.UTF8.GetBytes(Entry.UUID)); }
                    catch { }
                }

                return Result;
            }

            public async Task Broadcast(string UUID)
            {
                Get(UUID);
                await Net.BroadcastAsync("dag.notice", Encoding.UTF8.GetBytes(UUID));
            }

            //A device said this folder changed. If we're already syncing it we go once more after, so a lot of notices become one sync
            async Task Notified(string UUID, string Device)
            {
                if (!Busy.TryAdd(UUID, true)) { Again[UUID] = Device; return; }

                try
                {
                    string? Next = Device;

                    while (Next is not null)
                    {
                        Again.TryRemove(UUID, out _);

                        try { await Sync(Next, UUID); }
                        catch (Exception ex) { Problem?.Invoke($"{UUID} from {Next}: {ex.Message}"); }

                        Next = Again.TryGetValue(UUID, out var More) ? More : null;
                    }
                }
                finally { Busy.TryRemove(UUID, out _); }
            }

            void OnPeerConnected(PeerInfo Peer)
            {
                if (!AutoSync || Volatile.Read(ref _Disposed) != 0) return;

                foreach (var Entry in Folders.Values.Where(f => f.Devices.Contains(Peer.Id, StringComparer.OrdinalIgnoreCase)))
                    _ = Task.Run(() => Notified(Entry.UUID, Peer.Id));
            }

            #endregion

            #region Delete

            public async Task Stop(string UUID)
            {
                Get(UUID);
                Folders.TryRemove(UUID, out _);
                Last.TryRemove(UUID, out _);

                if (Key is null) return;

                await RepoLock.WaitAsync();
                try { await DeleteVariable(UUID, Key.Value); }
                finally { RepoLock.Release(); }
            }

            #endregion

            #region What other devices ask us

            bool Allowed(CommandContext Context, string UUID, out RepositoryEntry Entry) =>
                Folders.TryGetValue(UUID, out Entry!) && Entry.Devices.Contains(Context.Origin, StringComparer.OrdinalIgnoreCase);

            CommandResult HandleExists(CommandContext Context) =>
                Allowed(Context, Context.PayloadAsString(), out _) ? CommandResult.Ok() : CommandResult.Denied("not shared with you");

            async Task<CommandResult> HandleManifest(CommandContext Context)
            {
                if (!Allowed(Context, Context.PayloadAsString(), out var Entry)) return CommandResult.Denied("not shared with you");

                try
                {
                    var Files = await Task.Run(() => Scan(Entry.ParentPath, Known(Entry)));
                    Last[Entry.UUID] = Files;

                    var Json = JsonSerializer.SerializeToUtf8Bytes(Files);
                    return Json.Length > 900_000 ? CommandResult.Error("the file list is too big") : CommandResult.Ok(Json);
                }
                catch (Exception ex) { return CommandResult.Error(ex.Message); }
            }

            async Task<CommandResult> HandleChunk(CommandContext Context)
            {
                try
                {
                    var Request = JsonNode.Parse(Context.Payload)!;
                    var UUID = (string?)Request["u"] ?? "";
                    var Relative = (string?)Request["p"] ?? "";
                    var Index = (long?)Request["i"] ?? -1;

                    if (!Allowed(Context, UUID, out var Entry)) return CommandResult.Denied("not shared with you");
                    if (Index < 0 || !SafeRelative(Relative)) return CommandResult.Error("malformed");

                    //Only files that are in the folder's own list, not whatever path they asked for
                    if (!Last.TryGetValue(UUID, out var Files) || !Files.ContainsKey(Relative))
                    {
                        Files = await Task.Run(() => Scan(Entry.ParentPath, Known(Entry)));
                        Last[UUID] = Files;
                    }

                    if (!Files.TryGetValue(Relative, out var State)) return CommandResult.Error("no such file");

                    var Full = SafePath(Entry.ParentPath, Relative);
                    using var Stream = new FileStream(Full, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);

                    Stream.Seek(Index * ChunkSize, SeekOrigin.Begin);
                    var Buffer = new byte[ChunkSize];
                    var Read = ReadFull(Stream, Buffer);

                    return CommandResult.Ok(Buffer.AsSpan(0, Read).ToArray());
                }
                catch (Exception ex) when (ex is JsonException or InvalidCastException or IOException or InvalidDataException or FormatException)
                {
                    return CommandResult.Error("couldn't read that");
                }
            }

            CommandResult HandleNotice(CommandContext Context)
            {
                var UUID = Context.PayloadAsString();

                if (AutoSync && Allowed(Context, UUID, out _))
                {
                    var Origin = Context.Origin;
                    _ = Task.Run(() => Notified(UUID, Origin));
                }

                return CommandResult.Ok();
            }

            #endregion

            #region Getting a file

            async Task Download(string Device, string UUID, string Root, string Source, string Relative, FileState Remote, string? CopyFrom)
            {
                var Target = SafePath(Root, Relative);
                var PartDirectory = Path.Combine(Root, ".yuuko", "partial");
                Directory.CreateDirectory(PartDirectory);

                //Named after the content, so a download that stopped continues even in a later sync
                var Part = Path.Combine(PartDirectory, Remote.Hash);

                long Have = File.Exists(Part) ? new FileInfo(Part).Length : 0;
                Have -= Have % ChunkSize;
                if (Have > Remote.Size) Have = 0;

                if (CopyFrom is not null && Have == 0 && File.Exists(SafePath(Root, CopyFrom)))
                {
                    File.Copy(SafePath(Root, CopyFrom), Part, true);
                    Have = Remote.Size;
                }

                using (var Out = new FileStream(Part, FileMode.OpenOrCreate, FileAccess.Write, FileShare.None))
                {
                    Out.SetLength(Have);
                    Out.Seek(Have, SeekOrigin.Begin);

                    for (long Index = Have / ChunkSize; Index * ChunkSize < Remote.Size; Index++)
                    {
                        var Request = new JsonObject { ["u"] = UUID, ["p"] = Source, ["i"] = Index };
                        var Reply = await Net.SendCommandAsync(Device, "dag.chunk", Encoding.UTF8.GetBytes(Request.ToJsonString()));

                        if (!Reply.IsOk) throw new IOException($"{Device} said {Reply.Status}: {Reply.Message}");
                        if (Reply.Result.Length == 0 || Reply.Result.Length > ChunkSize) throw new InvalidDataException("A chunk was the wrong size.");

                        Out.Write(Reply.Result);
                        Progress?.Invoke(UUID, Relative, Math.Min(Out.Length, Remote.Size), Remote.Size);
                    }
                }

                //Nothing is put in place until it's the file we were promised
                if (new FileInfo(Part).Length != Remote.Size || HashFile(Part) != Remote.Hash)
                {
                    File.Delete(Part);
                    throw new InvalidDataException("It changed while we were getting it, or didn't arrive right. It'll be tried again next time.");
                }

                Directory.CreateDirectory(Path.GetDirectoryName(Target)!);
                File.SetLastWriteTimeUtc(Part, new DateTime(Remote.Modified, DateTimeKind.Utc));
                File.Move(Part, Target, true);
            }

            #endregion
        }


        #region Looking at a folder

        //Every file in the folder (Not .yuuko, not shortcuts or symlinks), with hashes that are only worked out again if the size or time changed
        internal static Dictionary<string, FileState> Scan(string Root, Dictionary<string, FileState>? Known)
        {
            var RootFull = Path.GetFullPath(Root).TrimEnd(Path.DirectorySeparatorChar);
            var Files = new Dictionary<string, FileState>(StringComparer.Ordinal);

            foreach (var Full in Walk(RootFull, RootFull))
            {
                var Relative = Path.GetRelativePath(RootFull, Full).Replace('\\', '/');
                if (!SafeRelative(Relative)) continue;

                var Info = new FileInfo(Full);
                if (Info.Length > MaxFileBytes) continue;
                if (Files.Count >= MaxFiles) throw new InvalidDataException($"A shared folder can have at most {MaxFiles} files.");

                var Modified = Info.LastWriteTimeUtc.Ticks;

                //A file we can't read right now stops the whole scan: leaving it out would look like it was deleted
                var Hash = Known != null && Known.TryGetValue(Relative, out var Old) && Old.Size == Info.Length && Old.Modified == Modified
                    ? Old.Hash
                    : HashFile(Full);

                Files[Relative] = new FileState(Hash, Info.Length, Modified);
            }

            return Files;
        }

        static IEnumerable<string> Walk(string Directory_, string RootFull)
        {
            foreach (var Item in new DirectoryInfo(Directory_).EnumerateFileSystemInfos())
            {
                if (Item.Attributes.HasFlag(FileAttributes.ReparsePoint)) continue;

                if (Item is DirectoryInfo Sub)
                {
                    if (Directory_ == RootFull && Sub.Name == ".yuuko") continue;
                    foreach (var File_ in Walk(Sub.FullName, RootFull)) yield return File_;
                }
                else yield return Item.FullName;
            }
        }

        //A file is cut in chunks and each is hashed, the file's hash is the hash of those hashes
        internal static string HashFile(string Path_)
        {
            using var Stream = new FileStream(Path_, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            using var Outer = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);

            var Buffer = new byte[ChunkSize];
            int Read;

            while ((Read = ReadFull(Stream, Buffer)) > 0)
                Outer.AppendData(SHA256.HashData(Buffer.AsSpan(0, Read)));

            return Convert.ToHexString(Outer.GetHashAndReset()).ToLowerInvariant();
        }

        static int ReadFull(Stream Stream_, byte[] Buffer)
        {
            var Total = 0;
            int Read;

            while (Total < Buffer.Length && (Read = Stream_.Read(Buffer, Total, Buffer.Length - Total)) > 0) Total += Read;

            return Total;
        }

        //One hash for the whole folder, the same on every device that has the same files
        internal static string RootHash(Dictionary<string, FileState> Files)
        {
            using var Outer = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);

            foreach (var (Path_, State) in Files.OrderBy(f => f.Key, StringComparer.Ordinal))
                Outer.AppendData(Encoding.UTF8.GetBytes(Path_ + "\n" + State.Hash + "\n"));

            return Convert.ToHexString(Outer.GetHashAndReset()).ToLowerInvariant();
        }

        static bool Same(FileState? A, FileState? B) => (A is null && B is null) || (A is not null && B is not null && A.Hash == B.Hash);

        //Newest time wins, and if the times are the same the bigger hash does, so both devices pick the same one
        static bool IsNewer(FileState A, FileState B) =>
            A.Modified != B.Modified ? A.Modified > B.Modified : string.CompareOrdinal(A.Hash, B.Hash) > 0;

        static bool IsHash(string Text) => Text.Length == 64 && Text.All(c => Uri.IsHexDigit(c) && !char.IsUpper(c));

        static bool SamePath(string A, string B) =>
            string.Equals(Path.GetFullPath(A).TrimEnd(Path.DirectorySeparatorChar), Path.GetFullPath(B).TrimEnd(Path.DirectorySeparatorChar),
                OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal);

        static bool SafeName(string Text) => Text.Length is > 0 and <= 64 && Text.All(c => char.IsLetterOrDigit(c) || c is '-' or '_');

        #endregion

        #region Keeping paths inside the folder

        //A path another device sent is only ever used if it passes this (A folder-relative path with / between parts, nothing that climbs out or hides in .yuuko)
        internal static bool SafeRelative(string Relative)
        {
            if (string.IsNullOrEmpty(Relative) || Relative.Length > 240) return false;
            if (Relative.Contains('\\') || Relative.Contains(':') || Relative.StartsWith('/') || Relative.EndsWith('/')) return false;

            var Bad = Path.GetInvalidFileNameChars();
            var Parts = Relative.Split('/');

            foreach (var Part in Parts)
            {
                if (Part.Length == 0 || Part == "." || Part == "..") return false;
                if (Part.IndexOfAny(Bad) >= 0 || Part.EndsWith(' ') || Part.EndsWith('.')) return false;
            }

            return !Parts[0].Equals(".yuuko", StringComparison.OrdinalIgnoreCase);
        }

        //The full path for a relative one, or an exception if it would land outside the folder or go through a shortcut
        internal static string SafePath(string Root, string Relative)
        {
            if (!SafeRelative(Relative)) throw new InvalidDataException("That path isn't allowed.");

            var RootFull = Path.GetFullPath(Root).TrimEnd(Path.DirectorySeparatorChar);
            var Full = Path.GetFullPath(Path.Combine(RootFull, Relative.Replace('/', Path.DirectorySeparatorChar)));

            if (!Full.StartsWith(RootFull + Path.DirectorySeparatorChar, OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal))
                throw new InvalidDataException("That path is outside the folder.");

            var Directory_ = Path.GetDirectoryName(Full)!;

            while (Directory_.Length > RootFull.Length)
            {
                if (Directory.Exists(Directory_) && File.GetAttributes(Directory_).HasFlag(FileAttributes.ReparsePoint))
                    throw new InvalidDataException("That path goes through a shortcut.");

                Directory_ = Path.GetDirectoryName(Directory_)!;
            }

            if (File.Exists(Full) && File.GetAttributes(Full).HasFlag(FileAttributes.ReparsePoint)) throw new InvalidDataException("That file is a shortcut.");

            return Full;
        }

        //"notes/a.txt" and the first 8 letters of a hash become "notes/a (conflict 1a2b3c4d).txt"
        internal static string ConflictPath(string Relative, string Hash)
        {
            var Directory_ = Relative.Contains('/') ? Relative[..(Relative.LastIndexOf('/') + 1)] : "";
            var Name = Path.GetFileNameWithoutExtension(Relative);
            var Extension = Path.GetExtension(Relative);

            if (Name.Length > 100) Name = Name[..100];
            return $"{Directory_}{Name} (conflict {Hash[..8]}){Extension}";
        }

        //Deleted files are moved here, not erased
        static void Trash(string Root, string Relative)
        {
            var From = SafePath(Root, Relative);
            if (!File.Exists(From)) return;

            var To = Path.Combine(Root, ".yuuko", "trash", DateTime.UtcNow.ToString("yyyyMMdd-HHmmss-fff"), Relative.Replace('/', Path.DirectorySeparatorChar));
            Directory.CreateDirectory(Path.GetDirectoryName(To)!);
            File.Move(From, To, true);
        }

        //Keeps our version of a file next to the one that won (If it's already there, the same content is already saved)
        static void MoveAside(string Root, string From, string To)
        {
            var Source = SafePath(Root, From);
            var Destination = SafePath(Root, To);

            if (File.Exists(Destination)) { Trash(Root, From); return; }

            Directory.CreateDirectory(Path.GetDirectoryName(Destination)!);
            File.Move(Source, Destination);
        }

        #endregion
    }
}
