using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;

namespace YuukoProtocol.Dogma
{
    //DOGMA V: see the apps on another device, start them, stop them, and see what is running
    //Apps come from Steam, the WalkerWorks directory and the big apps menu (Start Menu on Windows, .desktop files on Linux)
    //Other devices only ever send an app ID, never a command, so they can only start what this device listed itself
    public static class HolyMother
    {
        public class AppEntry
        {
            public string ID { get; set; } = "";
            public string Name { get; set; } = "";

            //Steam, WalkerWorks, StartMenu or Desktop
            public string Source { get; set; } = "";
            public bool Running { get; set; }

            //Everything below stays on the device that owns the app
            [JsonIgnore] public string Launch = "";           //What we start (steam:// link, .lnk, exe, or the Exec line)
            [JsonIgnore] public string Args = "";
            [JsonIgnore] public string? ExePath;              //What a running process of this app looks like
            [JsonIgnore] public string? FolderPath;           //Or anything running from inside this folder
            [JsonIgnore] public string? IconHint;             //Where its picture is (A program, or the Icon= of a .desktop file)
        }

        //Where WalkerWorks apps live, one folder per app (Change it before you call LocalApps)
        public static string WalkerWorksDirectory { get; set; } = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "WalkerWorks", "Apps");

        //Asked before another device starts or stops something (Device, Action "start" / "stop"), say no to block it
        public static Func<string, string, bool> Allow { get; set; } = (Device, Action) => true;

        const int MaxApps = 2000;
        const string Indicator = "holy.";

        //Tests put their own list here
        internal static List<AppEntry>? Override;
        internal static EclipseBroker? Node;

        //The node was built again, call Start() again
        internal static void Reset()
        {
            lock (Gate) { _Apps = null; }
        }

        static EclipseBroker Net => Node ?? Identity.YuukoNode ?? throw new InvalidOperationException("Create the node first (Identity.CreateNode).");

        static readonly object Gate = new();
        static List<AppEntry>? _Apps;
        static DateTime _ScanTime;

        //Starts listening for other devices, call it once after Identity.CreateNode
        public static void Start() => Attach(Net);

        internal static void Attach(EclipseBroker Target)
        {
            Target.On(Indicator + "apps", (c, _) => Task.FromResult(CommandResult.Ok(JsonSerializer.SerializeToUtf8Bytes(LocalApps()))));
            Target.On(Indicator + "running", (c, _) => Task.FromResult(CommandResult.Ok(JsonSerializer.SerializeToUtf8Bytes(LocalRunning()))));
            Target.On(Indicator + "icons", (c, _) => Task.FromResult(HandleIcons(c)));
            Target.On(Indicator + "start", (c, _) => Task.FromResult(Control(c, "start", StartLocal)));
            Target.On(Indicator + "stop", (c, _) => Task.FromResult(Control(c, "stop", StopLocal)));
        }

        static CommandResult Control(CommandContext Context, string Action, Func<string, string?> Do)
        {
            if (!Allow(Context.Origin, Action)) return CommandResult.Denied("this device does not allow that");
            var Problem = Do(Context.PayloadAsString());
            return Problem is null ? CommandResult.Ok() : CommandResult.Error(Problem);
        }

        #region Read

        //Everything installed on THIS device (Looked up again after 30 seconds, or when you pass Rescan)
        public static List<AppEntry> LocalApps(bool Rescan = false)
        {
            lock (Gate)
            {
                var Apps = Override;

                if (Apps is null)
                {
                    if (Rescan || _Apps is null || DateTime.UtcNow - _ScanTime > TimeSpan.FromSeconds(30))
                    {
                        _Apps = Scan(SteamRoot(), WalkerWorksDirectory, MenuDirectories(), DesktopDirectories());
                        _ScanTime = DateTime.UtcNow;
                    }

                    Apps = _Apps;
                }

                MarkRunning(Apps);
                return Apps;
            }
        }

        //Only what is open on THIS device right now
        public static List<AppEntry> LocalRunning() => LocalApps().Where(a => a.Running).ToList();

        //Everything installed on another device
        public static async Task<List<AppEntry>> GetApps(string Device) => await Ask(Device, "apps");

        //Only what is open on another device right now
        public static async Task<List<AppEntry>> GetRunning(string Device) => await Ask(Device, "running");

        static async Task<List<AppEntry>> Ask(string Device, string What)
        {
            var Reply = await Net.SendCommandAsync(Device, Indicator + What, Array.Empty<byte>());
            if (!Reply.IsOk) throw new InvalidOperationException($"{Device} said {Reply.Status}: {Reply.Message}");

            var Apps = JsonSerializer.Deserialize<List<AppEntry>>(Reply.Result) ?? new List<AppEntry>();
            return Apps.Take(MaxApps).ToList();
        }

        #endregion

        #region Icons

        const int MaxIconBytes = 256 * 1024;                //A bigger picture than this isn't an icon
        const int MaxIconBatch = 20;                        //Names in one request
        const int MaxIconReply = 600_000;                   //Picture bytes in one answer (A command is at most 1 MB and pictures grow a third in JSON)

        static readonly SemaphoreSlim IconQueue = new(1, 1);
        static readonly object IconGate = new();
        static readonly Dictionary<string, byte[]?> IconCache = new();            //This device's pictures, by app ID
        static readonly Dictionary<string, byte[]> RemoteIconCache = new();       //Other devices' pictures, by device and what was asked

        //The picture of an app on THIS device, asked for by its name, ID or path (PNG on Windows, a PNG or SVG file's bytes on Linux), null if there isn't one
        public static byte[]? LocalIcon(string NameOrPath) => LocalIcons(new[] { NameOrPath }).GetValueOrDefault(NameOrPath);

        //Pictures for a list of names, IDs or paths, the ones with no picture are left out
        public static Dictionary<string, byte[]> LocalIcons(IEnumerable<string> NamesOrPaths) => FindIcons(NamesOrPaths, true, int.MaxValue, out _);

        //The picture of an app on another device
        public static async Task<byte[]?> GetIcon(string Device, string NameOrPath) =>
            (await GetIcons(Device, new[] { NameOrPath })).GetValueOrDefault(NameOrPath);

        //Pictures for a list of names, IDs or paths on another device (Queued: one request at a time in the order they came, a long list is asked for in batches)
        //Another device can only be asked about apps it listed, so a path only works if it's the path of one of them
        public static async Task<Dictionary<string, byte[]>> GetIcons(string Device, IEnumerable<string> NamesOrPaths)
        {
            var Found = new Dictionary<string, byte[]>();
            var Wanted = new Queue<string>(NamesOrPaths.Where(n => !string.IsNullOrWhiteSpace(n) && n.Length <= 260).Distinct().Take(MaxApps));

            await IconQueue.WaitAsync();
            try
            {
                while (Wanted.Count > 0)
                {
                    var Batch = new List<string>();

                    while (Batch.Count < MaxIconBatch && Wanted.Count > 0)
                    {
                        var Key = Wanted.Dequeue();
                        byte[]? Cached;
                        bool Have;
                        lock (IconGate) Have = RemoteIconCache.TryGetValue(Device + "|" + Key, out Cached);

                        if (Have) Found[Key] = Cached!;
                        else Batch.Add(Key);
                    }

                    if (Batch.Count == 0) continue;

                    var Reply = await Net.SendCommandAsync(Device, Indicator + "icons", JsonSerializer.SerializeToUtf8Bytes(Batch));
                    if (!Reply.IsOk) throw new InvalidOperationException($"{Device} said {Reply.Status}: {Reply.Message}");

                    var Answer = JsonNode.Parse(Reply.Result)!;

                    foreach (var (Key, Picture) in Answer["icons"]!.AsObject())
                    {
                        if (!Batch.Contains(Key) || Picture is null) continue;

                        var Bytes = Convert.FromBase64String((string)Picture!);
                        if (Bytes.Length > MaxIconBytes) continue;

                        Found[Key] = Bytes;
                        lock (IconGate)
                        {
                            if (RemoteIconCache.Count > 500) RemoteIconCache.Clear();
                            RemoteIconCache[Device + "|" + Key] = Bytes;
                        }
                    }

                    //They didn't fit in one answer, so they go again
                    foreach (var Key in Answer["skipped"]!.AsArray().Select(k => (string)k!))
                        if (Batch.Contains(Key)) Wanted.Enqueue(Key);
                }
            }
            finally { IconQueue.Release(); }

            return Found;
        }

        //What another device asks for: names, IDs or paths of apps we listed (Never any other file)
        static CommandResult HandleIcons(CommandContext Context)
        {
            try
            {
                var Asked = JsonSerializer.Deserialize<List<string>>(Context.Payload) ?? new List<string>();
                if (Asked.Count > 50) return CommandResult.Error("too many at once");

                var Found = FindIcons(Asked.Where(a => a is { Length: > 0 and <= 260 }), false, MaxIconReply, out var Skipped);

                var Icons = new JsonObject();
                foreach (var (Key, Bytes) in Found) Icons[Key] = Convert.ToBase64String(Bytes);

                var Answer = new JsonObject { ["icons"] = Icons, ["skipped"] = new JsonArray(Skipped.Select(s => (JsonNode)s).ToArray()) };
                return CommandResult.Ok(Encoding.UTF8.GetBytes(Answer.ToJsonString()));
            }
            catch (JsonException) { return CommandResult.Error("malformed"); }
        }

        //AnyFile is for this device only: a path that isn't one of the apps is still looked at. Skipped are the ones that didn't fit in MaxBytes
        static Dictionary<string, byte[]> FindIcons(IEnumerable<string> Keys, bool AnyFile, int MaxBytes, out List<string> Skipped)
        {
            var Found = new Dictionary<string, byte[]>();
            Skipped = new List<string>();
            var Total = 0;
            var Apps = LocalApps();

            foreach (var Key in Keys.Distinct())
            {
                var App = FindApp(Apps, Key);
                byte[]? Bytes;

                if (App is not null) Bytes = IconFor(App);
                else if (AnyFile && File.Exists(Key)) Bytes = IconFromFile(Key);
                else Bytes = null;

                if (Bytes is null) continue;

                //The first one always goes, so a list can't get stuck
                if (Found.Count > 0 && Total + Bytes.Length > MaxBytes) { Skipped.Add(Key); continue; }

                Found[Key] = Bytes;
                Total += Bytes.Length;
            }

            return Found;
        }

        static AppEntry? FindApp(List<AppEntry> Apps, string Key)
        {
            var Compare = OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal;

            return Apps.FirstOrDefault(a => a.ID == Key)
                ?? Apps.FirstOrDefault(a => string.Equals(a.Name, Key, StringComparison.OrdinalIgnoreCase))
                ?? Apps.FirstOrDefault(a => new[] { a.ExePath, a.Launch, a.IconHint, a.FolderPath }.Any(p => p != null && string.Equals(p, Key, Compare)));
        }

        static byte[]? IconFor(AppEntry App)
        {
            lock (IconGate)
            {
                if (IconCache.TryGetValue(App.ID, out var Cached)) return Cached;
            }

            byte[]? Bytes = null;

            foreach (var Source in new[] { App.IconHint, App.ExePath, App.Launch })
            {
                if (string.IsNullOrEmpty(Source) || Source.Contains("://")) continue;

                Bytes = IconFromFile(Source);
                if (Bytes is not null) break;
            }

            //A game or an app's folder: the first program inside it
            if (Bytes is null && App.FolderPath is not null && Directory.Exists(App.FolderPath) && OperatingSystem.IsWindows())
            {
                try
                {
                    foreach (var Program in Directory.EnumerateFiles(App.FolderPath, "*.exe", SearchOption.TopDirectoryOnly).Take(5)
                        .Concat(Directory.EnumerateFiles(App.FolderPath, "*.exe", SearchOption.AllDirectories).Take(5)))
                    {
                        Bytes = IconFromFile(Program);
                        if (Bytes is not null) break;
                    }
                }
                catch { }
            }

            lock (IconGate)
            {
                if (IconCache.Count > 2000) IconCache.Clear();
                IconCache[App.ID] = Bytes;
            }

            return Bytes;
        }

        //A picture file is sent as it is, a program or shortcut has its icon taken out (Windows), a Linux icon name is looked up in the icon folders
        static byte[]? IconFromFile(string Source)
        {
            try
            {
                if (!File.Exists(Source))
                {
                    if (OperatingSystem.IsWindows() || Source.Contains('/')) return null;
                    Source = FindIconByName(Source) ?? "";
                    if (Source.Length == 0) return null;
                }

                var Extension = Path.GetExtension(Source).ToLowerInvariant();

                if (Extension is ".png" or ".svg")
                {
                    var Info = new FileInfo(Source);
                    return Info.Length is > 0 and <= MaxIconBytes ? File.ReadAllBytes(Source) : null;
                }

                return OperatingSystem.IsWindows() ? WindowsIcon(Source) : null;
            }
            catch { return null; }
        }

        [SupportedOSPlatform("windows")]
        static byte[]? WindowsIcon(string Source)
        {
            try
            {
                using var Icon = System.Drawing.Icon.ExtractAssociatedIcon(Source);
                if (Icon is null) return null;

                using var Picture = Icon.ToBitmap();
                using var Out = new MemoryStream();
                Picture.Save(Out, System.Drawing.Imaging.ImageFormat.Png);

                return Out.Length <= MaxIconBytes ? Out.ToArray() : null;
            }
            catch { return null; }
        }

        //Linux: the icon name in a .desktop file is looked up in the icon folders, biggest sensible size first
        static string? FindIconByName(string Name)
        {
            var Home = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
            var Roots = new[] { Path.Combine(Home, ".local", "share"), "/usr/local/share", "/usr/share", "/var/lib/flatpak/exports/share", Path.Combine(Home, ".local", "share", "flatpak", "exports", "share") };

            foreach (var Size in new[] { "256x256", "128x128", "96x96", "64x64", "48x48", "scalable" })
                foreach (var Root in Roots)
                    foreach (var Extension in new[] { ".png", ".svg" })
                    {
                        var Found = Path.Combine(Root, "icons", "hicolor", Size, "apps", Name + Extension);
                        if (File.Exists(Found)) return Found;
                    }

            foreach (var Extension in new[] { ".png", ".svg" })
            {
                var Found = Path.Combine("/usr/share/pixmaps", Name + Extension);
                if (File.Exists(Found)) return Found;
            }

            return null;
        }

        #endregion

        #region Update

        //Open an app on THIS device, comes back with why it didn't if it didn't
        public static string? StartLocal(string ID)
        {
            var App = LocalApps().FirstOrDefault(a => a.ID == ID);
            if (App is null) return "No app with that ID";
            if (App.Running) return "Already running";

            try
            {
                Process.Start(StartInfoFor(App))?.Dispose();
                return null;
            }
            catch (Exception ex)
            {
                return "Could not start it (" + ex.GetType().Name + ")";
            }
        }

        //Close an app on THIS device, asks nicely first and forces it after 2 seconds
        public static string? StopLocal(string ID)
        {
            var App = LocalApps().FirstOrDefault(a => a.ID == ID);
            if (App is null) return "No app with that ID";
            if (App.ExePath is null && App.FolderPath is null) return "We can't tell which process belongs to that app";

            var Found = false;
            foreach (var P in Processes())
            {
                using (P.Process)
                {
                    if (!Matches(App, P.Path)) continue;
                    Found = true;

                    try
                    {
                        //No window to ask means nobody to ask, so it's ended right away
                        if (!P.Process.CloseMainWindow() || !P.Process.WaitForExit(2000)) P.Process.Kill(true);
                    }
                    catch { }
                }
            }

            _ScanTime = DateTime.MinValue;
            return Found ? null : "It isn't running";
        }

        //Open an app on another device
        public static async Task StartApp(string Device, string ID) => await Tell(Device, "start", ID);

        //Close an app on another device
        public static async Task StopApp(string Device, string ID) => await Tell(Device, "stop", ID);

        static async Task Tell(string Device, string Action, string ID)
        {
            var Reply = await Net.SendCommandAsync(Device, Indicator + Action, Encoding.UTF8.GetBytes(ID));
            if (!Reply.IsOk) throw new InvalidOperationException($"{Device} said {Reply.Status}: {Reply.Message}");
        }

        #endregion

        #region Finding apps

        //Every place we look, each one given in so tests can point them somewhere else
        internal static List<AppEntry> Scan(string? Steam, string? WalkerWorks, IEnumerable<string> MenuDirs, IEnumerable<string> DesktopDirs)
        {
            var Found = new Dictionary<string, AppEntry>();

            void Add(AppEntry? App)
            {
                if (App is not null && Found.Count < MaxApps) Found.TryAdd(App.ID, App);
            }

            foreach (var A in SteamApps(Steam)) Add(A);
            foreach (var A in WalkerWorksApps(WalkerWorks)) Add(A);
            foreach (var Dir in MenuDirs) foreach (var A in StartMenuApps(Dir)) Add(A);
            foreach (var Dir in DesktopDirs) foreach (var A in DesktopFileApps(Dir)) Add(A);

            return Found.Values.OrderBy(a => a.Name, StringComparer.OrdinalIgnoreCase).ToList();
        }

        static string MakeID(string Source, string Key)
        {
            var Hash = SHA256.HashData(Encoding.UTF8.GetBytes(Source + "|" + Key.ToLowerInvariant()));
            return Source.ToLowerInvariant() + "-" + Convert.ToHexString(Hash, 0, 8).ToLowerInvariant();
        }

        #region Steam

        static string? SteamRoot()
        {
            var Home = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
            var Options = new List<string>();

            if (OperatingSystem.IsWindows())
            {
                try { Options.Add((string?)Microsoft.Win32.Registry.GetValue(@"HKEY_CURRENT_USER\Software\Valve\Steam", "SteamPath", null) ?? ""); } catch { }
                Options.Add(@"C:\Program Files (x86)\Steam");
            }
            else
            {
                Options.Add(Path.Combine(Home, ".steam", "steam"));
                Options.Add(Path.Combine(Home, ".local", "share", "Steam"));
                Options.Add(Path.Combine(Home, ".var", "app", "com.valvesoftware.Steam", ".local", "share", "Steam"));
            }

            return Options.FirstOrDefault(o => o.Length > 0 && Directory.Exists(Path.Combine(o, "steamapps")));
        }

        //Steam keeps games in several libraries, steamapps/libraryfolders.vdf lists them
        static IEnumerable<AppEntry> SteamApps(string? Root)
        {
            if (Root is null) yield break;

            var Libraries = new List<string> { Root };
            var Vdf = Path.Combine(Root, "steamapps", "libraryfolders.vdf");

            if (File.Exists(Vdf))
            {
                foreach (Match M in Regex.Matches(File.ReadAllText(Vdf), "\"path\"\\s+\"([^\"]+)\""))
                {
                    var Library = M.Groups[1].Value.Replace("\\\\", "\\");
                    if (!Libraries.Contains(Library, StringComparer.OrdinalIgnoreCase)) Libraries.Add(Library);
                }
            }

            foreach (var Library in Libraries)
            {
                var Steamapps = Path.Combine(Library, "steamapps");
                if (!Directory.Exists(Steamapps)) continue;

                foreach (var Manifest in Directory.EnumerateFiles(Steamapps, "appmanifest_*.acf"))
                {
                    string Text;
                    try { Text = File.ReadAllText(Manifest); } catch { continue; }

                    var AppID = Regex.Match(Text, "\"appid\"\\s+\"(\\d+)\"").Groups[1].Value;
                    var Name = Regex.Match(Text, "\"name\"\\s+\"([^\"]+)\"").Groups[1].Value;
                    var Folder = Regex.Match(Text, "\"installdir\"\\s+\"([^\"]+)\"").Groups[1].Value;
                    if (AppID.Length == 0 || Name.Length == 0) continue;

                    //Steam's own tools aren't apps
                    if (Name.StartsWith("Steamworks", StringComparison.OrdinalIgnoreCase) || Name.StartsWith("Proton", StringComparison.OrdinalIgnoreCase)
                        || Name.StartsWith("Steam Linux Runtime", StringComparison.OrdinalIgnoreCase)) continue;

                    yield return new AppEntry
                    {
                        ID = MakeID("Steam", AppID),
                        Name = Name,
                        Source = "Steam",
                        Launch = "steam://rungameid/" + AppID,
                        FolderPath = Folder.Length == 0 ? null : Path.Combine(Steamapps, "common", Folder),
                    };
                }
            }
        }

        #endregion

        #region WalkerWorks

        //One folder per app, the app is the file named like the folder (Name.exe, Name.xur, or just Name on Linux)
        static IEnumerable<AppEntry> WalkerWorksApps(string? Root)
        {
            if (Root is null || !Directory.Exists(Root)) yield break;

            foreach (var Folder in Directory.EnumerateDirectories(Root))
            {
                var Name = Path.GetFileName(Folder);
                var Main = new[] { Name + ".exe", Name + ".xur", Name }
                    .Select(f => Path.Combine(Folder, f)).FirstOrDefault(File.Exists);
                if (Main is null) continue;

                yield return new AppEntry
                {
                    ID = MakeID("WalkerWorks", Name),
                    Name = Name,
                    Source = "WalkerWorks",
                    Launch = Main,
                    ExePath = Main,
                    FolderPath = Folder,
                    IconHint = Main,
                };
            }
        }

        #endregion

        #region Apps menu

        static IEnumerable<string> MenuDirectories()
        {
            if (!OperatingSystem.IsWindows()) return Array.Empty<string>();

            return new[]
            {
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "Microsoft", "Windows", "Start Menu", "Programs"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "Microsoft", "Windows", "Start Menu", "Programs"),
            };
        }

        //Start Menu shortcuts (Windows), we start the shortcut itself so its arguments are kept
        static IEnumerable<AppEntry> StartMenuApps(string Dir)
        {
            if (!Directory.Exists(Dir)) yield break;

            foreach (var Shortcut in Directory.EnumerateFiles(Dir, "*.lnk", SearchOption.AllDirectories))
            {
                var Name = Path.GetFileNameWithoutExtension(Shortcut);
                if (Name.Contains("uninstall", StringComparison.OrdinalIgnoreCase)) continue;

                var (Target, Arguments) = ShortcutTarget(Shortcut);
                if (Target is null || !Target.EndsWith(".exe", StringComparison.OrdinalIgnoreCase)) continue;

                yield return new AppEntry
                {
                    ID = MakeID("StartMenu", Target + " " + Arguments),
                    Name = Name,
                    Source = "StartMenu",
                    Launch = Shortcut,
                    IconHint = Target,

                    //A shortcut with arguments runs through another program (powershell, cmd, a browser), so a running powershell isn't necessarily this app
                    ExePath = Arguments.Length == 0 ? Target : null,
                };
            }
        }

        static (string? Target, string Arguments) ShortcutTarget(string Shortcut)
        {
            if (!OperatingSystem.IsWindows()) return (null, "");

            try
            {
                var ShellType = Type.GetTypeFromProgID("WScript.Shell");
                if (ShellType is null) return (null, "");

                dynamic Shell = Activator.CreateInstance(ShellType)!;
                dynamic Link = Shell.CreateShortcut(Shortcut);
                string Target = Link.TargetPath;
                string Arguments = Link.Arguments;
                return (Target.Length == 0 ? null : Target, Arguments);
            }
            catch { return (null, ""); }
        }

        static IEnumerable<string> DesktopDirectories()
        {
            if (OperatingSystem.IsWindows()) return Array.Empty<string>();

            var Home = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
            return new[]
            {
                "/usr/share/applications",
                Path.Combine(Home, ".local", "share", "applications"),
                "/var/lib/flatpak/exports/share/applications",
                Path.Combine(Home, ".local", "share", "flatpak", "exports", "share", "applications"),
                "/var/lib/snapd/desktop/applications",
            };
        }

        //Linux .desktop files, the same list a desktop's app menu shows
        static IEnumerable<AppEntry> DesktopFileApps(string Dir)
        {
            if (!Directory.Exists(Dir)) yield break;

            foreach (var File_ in Directory.EnumerateFiles(Dir, "*.desktop", SearchOption.AllDirectories))
            {
                var Entry = new Dictionary<string, string>();
                var InEntry = false;

                string[] Lines;
                try { Lines = File.ReadAllLines(File_); } catch { continue; }

                foreach (var Line in Lines)
                {
                    if (Line.StartsWith("[")) { InEntry = Line.Trim() == "[Desktop Entry]"; continue; }

                    var At = Line.IndexOf('=');
                    if (InEntry && At > 0) Entry.TryAdd(Line[..At].Trim(), Line[(At + 1)..].Trim());
                }

                if (Entry.GetValueOrDefault("Type") != "Application") continue;
                if (Entry.GetValueOrDefault("NoDisplay") == "true" || Entry.GetValueOrDefault("Hidden") == "true") continue;
                if (!Entry.TryGetValue("Name", out var Name) || !Entry.TryGetValue("Exec", out var Exec)) continue;

                //%u, %F and friends are filled in by the menu when you open a file, we have nothing to give them
                var Parts = Split(Regex.Replace(Exec, "%[a-zA-Z%]", ""));
                if (Parts.Count == 0) continue;

                //"flatpak run x" or "env X=1 app" start something else, so we can't tell which process is theirs
                var Wrappers = new[] { "flatpak", "snap", "env", "sh", "bash" };
                var Program = Path.GetFileName(Parts[0]);

                yield return new AppEntry
                {
                    ID = MakeID("Desktop", Path.GetFileName(File_)),
                    Name = Name,
                    Source = "Desktop",
                    Launch = Parts[0],
                    Args = string.Join(" ", Parts.Skip(1)),
                    ExePath = Wrappers.Contains(Program) ? null : Program,
                    IconHint = Entry.GetValueOrDefault("Icon"),
                };
            }
        }

        //Splits an Exec line into words, keeping "quoted bits" together
        static List<string> Split(string Line)
        {
            var Words = new List<string>();
            var Current = new StringBuilder();
            var Quoted = false;

            foreach (var Letter in Line)
            {
                if (Letter == '"') Quoted = !Quoted;
                else if (char.IsWhiteSpace(Letter) && !Quoted)
                {
                    if (Current.Length > 0) { Words.Add(Current.ToString()); Current.Clear(); }
                }
                else Current.Append(Letter);
            }

            if (Current.Length > 0) Words.Add(Current.ToString());
            return Words;
        }

        #endregion

        #endregion

        #region Running apps

        static ProcessStartInfo StartInfoFor(AppEntry App)
        {
            //Links, shortcuts and .xur files go to the system, so it picks the right program
            var ToSystem = App.Launch.Contains("://") || App.Launch.EndsWith(".lnk", StringComparison.OrdinalIgnoreCase)
                || App.Launch.EndsWith(".xur", StringComparison.OrdinalIgnoreCase);

            var Info = new ProcessStartInfo(App.Launch) { UseShellExecute = ToSystem };

            if (!ToSystem)
            {
                foreach (var Word in Split(App.Args)) Info.ArgumentList.Add(Word);
                if (App.FolderPath is not null) Info.WorkingDirectory = App.FolderPath;
            }

            return Info;
        }

        static List<(Process Process, string? Path)> Processes()
        {
            var All = new List<(Process, string?)>();

            foreach (var P in Process.GetProcesses())
            {
                string? Path = null;
                try { Path = P.MainModule?.FileName; } catch { }   //System processes say no, that's fine
                All.Add((P, Path));
            }

            return All;
        }

        static bool Matches(AppEntry App, string? ProcessPath)
        {
            if (ProcessPath is null) return false;
            var Compare = OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal;

            if (App.ExePath is not null)
            {
                //A bare name (Linux .desktop) matches on the file name, a full path on the whole path
                var Same = App.ExePath.Contains(Path.DirectorySeparatorChar) || App.ExePath.Contains(Path.AltDirectorySeparatorChar)
                    ? string.Equals(App.ExePath, ProcessPath, Compare)
                    : string.Equals(App.ExePath, Path.GetFileName(ProcessPath), Compare);
                if (Same) return true;
            }

            return App.FolderPath is not null
                && ProcessPath.StartsWith(App.FolderPath.TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar, Compare);
        }

        static void MarkRunning(List<AppEntry> Apps)
        {
            var Open = Processes();

            try
            {
                foreach (var App in Apps)
                    App.Running = Open.Any(p => Matches(App, p.Path));
            }
            finally
            {
                foreach (var P in Open) P.Process.Dispose();
            }
        }

        #endregion
    }
}
