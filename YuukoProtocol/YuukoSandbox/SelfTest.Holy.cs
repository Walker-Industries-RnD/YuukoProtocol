using YuukoProtocol;
using YuukoProtocol.Dogma;

namespace YuukoSandbox;

// Tests for HolyMother: finding apps (Steam, WalkerWorks, apps menu), and seeing / starting / stopping them from another device.
public static partial class SelfTest
{
    private static async Task HolyMotherTests()
    {
        Section("apps on a device (HolyMother)");

        // A fake Steam with two libraries, a WalkerWorks folder and a Linux apps menu, all in a temp folder.
        string root = TempDir("holy");
        string steam = Path.Combine(root, "Steam"), second = Path.Combine(root, "Games2"), works = Path.Combine(root, "WalkerWorks"), menu = Path.Combine(root, "applications");
        Directory.CreateDirectory(Path.Combine(steam, "steamapps")); Directory.CreateDirectory(Path.Combine(second, "steamapps")); Directory.CreateDirectory(menu);

        File.WriteAllText(Path.Combine(steam, "steamapps", "libraryfolders.vdf"),
            "\"libraryfolders\"\n{\n\t\"0\"\n\t{\n\t\t\"path\"\t\t\"" + steam.Replace("\\", "\\\\") + "\"\n\t}\n\t\"1\"\n\t{\n\t\t\"path\"\t\t\"" + second.Replace("\\", "\\\\") + "\"\n\t}\n}\n");
        File.WriteAllText(Path.Combine(steam, "steamapps", "appmanifest_100.acf"), "\"AppState\"\n{\n\t\"appid\"\t\t\"100\"\n\t\"name\"\t\t\"First Game\"\n\t\"installdir\"\t\t\"FirstGame\"\n}\n");
        File.WriteAllText(Path.Combine(second, "steamapps", "appmanifest_200.acf"), "\"AppState\"\n{\n\t\"appid\"\t\t\"200\"\n\t\"name\"\t\t\"Second Game\"\n\t\"installdir\"\t\t\"SecondGame\"\n}\n");
        File.WriteAllText(Path.Combine(steam, "steamapps", "appmanifest_228980.acf"), "\"AppState\"\n{\n\t\"appid\"\t\t\"228980\"\n\t\"name\"\t\t\"Steamworks Common Redistributables\"\n\t\"installdir\"\t\t\"Steamworks Shared\"\n}\n");

        Directory.CreateDirectory(Path.Combine(works, "Marimo")); File.WriteAllText(Path.Combine(works, "Marimo", "Marimo.exe"), "x");
        Directory.CreateDirectory(Path.Combine(works, "NoMainFile")); File.WriteAllText(Path.Combine(works, "NoMainFile", "readme.txt"), "x");

        File.WriteAllText(Path.Combine(menu, "editor.desktop"), "[Desktop Entry]\nType=Application\nName=Text Editor\nExec=/usr/bin/editor --new-window %U\n");
        File.WriteAllText(Path.Combine(menu, "hidden.desktop"), "[Desktop Entry]\nType=Application\nName=Hidden Thing\nExec=hidden\nNoDisplay=true\n");
        File.WriteAllText(Path.Combine(menu, "wrapped.desktop"), "[Desktop Entry]\nType=Application\nName=Wrapped\nExec=flatpak run org.example.App\n");
        File.WriteAllText(Path.Combine(menu, "tool.desktop"), "[Desktop Entry]\nType=Link\nName=Not An App\nExec=nothing\n");

        var found = HolyMother.Scan(steam, works, Array.Empty<string>(), new[] { menu });
        var names = found.Select(a => a.Name).ToList();
        Check("Steam games are found in every library listed in libraryfolders.vdf", names.Contains("First Game") && names.Contains("Second Game"));
        Check("...but Steam's own redistributables are not apps", !names.Any(n => n.StartsWith("Steamworks")));
        Check("a WalkerWorks folder with a main file is an app, one without is not", names.Contains("Marimo") && !names.Contains("NoMainFile"));
        Check("a .desktop file is an app (and its %U placeholder is dropped)", found.Single(a => a.Name == "Text Editor") is { Launch: "/usr/bin/editor", Args: "--new-window" });
        Check("hidden entries and entries that are not applications are left out", !names.Contains("Hidden Thing") && !names.Contains("Not An App"));
        Check("an app started through a wrapper (flatpak run) can't be matched to a process", found.Single(a => a.Name == "Wrapped").ExePath is null);
        Check("the list is sorted by name", names.SequenceEqual(names.OrderBy(n => n, StringComparer.OrdinalIgnoreCase)));
        Check("IDs are the same every time and different per app", HolyMother.Scan(steam, works, Array.Empty<string>(), new[] { menu }).Select(a => a.ID).SequenceEqual(found.Select(a => a.ID)) && found.Select(a => a.ID).Distinct().Count() == found.Count);
        Check("Steam games start through a steam:// link", found.Single(a => a.Name == "First Game").Launch == "steam://rungameid/100");
        Check("nothing sent to other devices tells them where the app is", !System.Text.Json.JsonSerializer.Serialize(found).Contains(root.Replace("\\", "\\\\")));
        Check("missing folders are fine", HolyMother.Scan(Path.Combine(root, "nope"), Path.Combine(root, "nope"), new[] { Path.Combine(root, "nope") }, new[] { Path.Combine(root, "nope") }).Count == 0);

        // A real program we can start and stop: a copy of a system tool that waits, in its own folder so nothing else matches it.
        string sleeper = Path.Combine(root, "Sleeper");
        Directory.CreateDirectory(sleeper);
        string exe = Path.Combine(sleeper, OperatingSystem.IsWindows() ? "Sleeper.exe" : "Sleeper");
        File.Copy(OperatingSystem.IsWindows() ? Path.Combine(Environment.SystemDirectory, "PING.EXE") : "/bin/sleep", exe, true);
        var entry = new HolyMother.AppEntry
        {
            ID = "test-sleeper", Name = "Sleeper", Source = "WalkerWorks", Launch = exe, ExePath = exe, FolderPath = sleeper,
            Args = OperatingSystem.IsWindows() ? "-n 60 127.0.0.1" : "60",
        };
        var forbidden = new HolyMother.AppEntry { ID = "test-nothing", Name = "No Process", Source = "Desktop", Launch = "x" };

        using var bus = new LocalBroker();
        var (n, _) = await Group(bus, new[] { "pc", "phone", "stranger" }, new[] { ("pc", "phone") });
        HolyMother.Override = new List<HolyMother.AppEntry> { entry, forbidden };
        HolyMother.Node = n["phone"];
        HolyMother.Attach(n["pc"]);
        var allowed = new List<string>();
        HolyMother.Allow = (device, action) => { lock (allowed) allowed.Add(device + "/" + action); return true; };
        try
        {
            var apps = await HolyMother.GetApps("pc");
            Check("another device can see the apps on this one", apps.Count == 2 && apps.Any(a => a.ID == "test-sleeper" && a.Name == "Sleeper" && a.Source == "WalkerWorks"));
            Check("...and nothing is running yet", (await HolyMother.GetRunning("pc")).Count == 0 && apps.All(a => !a.Running));

            await HolyMother.StartApp("pc", "test-sleeper");
            Check("another device can start an app", await Eventually(() => HolyMother.LocalRunning().Any(a => a.ID == "test-sleeper"), 8000));
            Check("...and sees it listed as running", (await HolyMother.GetRunning("pc")).Select(a => a.ID).SequenceEqual(new[] { "test-sleeper" }));
            Check("starting something that is already running is refused", await ThrowsAsync(() => HolyMother.StartApp("pc", "test-sleeper")));

            await HolyMother.StopApp("pc", "test-sleeper");
            Check("another device can stop it again", await Eventually(() => HolyMother.LocalRunning().Count == 0, 8000));
            Check("stopping something that isn't running says so", await ThrowsAsync(() => HolyMother.StopApp("pc", "test-sleeper")));
            Check("an ID we never listed can't be started (devices send IDs, never commands)", await ThrowsAsync(() => HolyMother.StartApp("pc", "calc.exe")));
            Check("an app we can't match to a process can't be stopped", await ThrowsAsync(() => HolyMother.StopApp("pc", "test-nothing")));
            lock (allowed) Check("the permission hook saw who asked and what for", allowed.Contains("phone/start") && allowed.Contains("phone/stop"));

            HolyMother.Allow = (device, action) => false;
            Check("a device can be stopped from starting anything", await ThrowsAsync(() => HolyMother.StartApp("pc", "test-sleeper")) && HolyMother.LocalRunning().Count == 0);
        }
        finally
        {
            HolyMother.StopLocal("test-sleeper");
            HolyMother.Override = null; HolyMother.Node = null; HolyMother.Allow = (d, a) => true;
            foreach (var node in n.Values) node.Dispose();
        }
    }

    // Pictures of apps: asked for by name, ID or path, one or a list, from this device or another (queued, in batches).
    private static async Task HolyIconTests()
    {
        Section("app icons (HolyMother)");

        string root = TempDir("holy-icons");
        byte[] Png(int extra, int seed) => new byte[] { 0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A }.Concat(Bytes(extra, seed)).ToArray();

        // Apps whose picture is a PNG file next to them (works the same on every OS), a program whose icon has to be taken out, and one with no picture.
        string sleeperExe = Path.Combine(root, OperatingSystem.IsWindows() ? "Prog.exe" : "Prog");
        if (OperatingSystem.IsWindows()) File.Copy(Path.Combine(Environment.SystemDirectory, "PING.EXE"), sleeperExe, true);
        File.WriteAllBytes(Path.Combine(root, "small.png"), Png(500, 1));
        File.WriteAllBytes(Path.Combine(root, "toobig.png"), Png(300_000, 2));
        var apps = new List<HolyMother.AppEntry>
        {
            new() { ID = "icon-small", Name = "Small", Source = "WalkerWorks", Launch = "x", ExePath = Path.Combine(root, "small.exe"), IconHint = Path.Combine(root, "small.png") },
            new() { ID = "icon-none", Name = "No Picture", Source = "Desktop", Launch = "x" },
            new() { ID = "icon-big-bad", Name = "Too Big", Source = "Desktop", Launch = "x", IconHint = Path.Combine(root, "toobig.png") },
        };
        if (OperatingSystem.IsWindows()) apps.Add(new() { ID = "icon-prog", Name = "Program", Source = "StartMenu", Launch = sleeperExe, ExePath = sleeperExe, IconHint = sleeperExe });

        // Eight big pictures: together too many for one answer, so they have to come in several.
        for (int i = 0; i < 8; i++)
        {
            File.WriteAllBytes(Path.Combine(root, $"big{i}.png"), Png(200_000, 10 + i));
            apps.Add(new() { ID = $"icon-big{i}", Name = $"Big {i}", Source = "Desktop", Launch = "x", IconHint = Path.Combine(root, $"big{i}.png") });
        }

        // A long list of small ones (more than one batch).
        for (int i = 0; i < 45; i++)
            apps.Add(new() { ID = $"icon-many{i}", Name = $"Many {i}", Source = "Desktop", Launch = "x", IconHint = Path.Combine(root, "small.png") });

        using var bus = new LocalBroker();
        var (n, _) = await Group(bus, new[] { "pc", "phone", "stranger" }, new[] { ("pc", "phone") });
        HolyMother.Override = apps;
        HolyMother.Node = n["phone"];
        HolyMother.Attach(n["pc"]);
        try
        {
            byte[]? small = HolyMother.LocalIcon("Small");
            Check("an app's picture is found by its name", small is { Length: > 8 } && small[1] == 0x50);
            Check("...by its ID, and by its path", HolyMother.LocalIcon("icon-small")!.SequenceEqual(small!) && HolyMother.LocalIcon(Path.Combine(root, "small.exe"))!.SequenceEqual(small!));
            Check("...whatever the capital letters in its name", HolyMother.LocalIcon("sMaLL")!.SequenceEqual(small!));
            Check("an app with no picture, and a name nobody has, give null", HolyMother.LocalIcon("No Picture") is null && HolyMother.LocalIcon("Not An App") is null);
            Check("a picture bigger than an icon is refused", HolyMother.LocalIcon("Too Big") is null);
            Check("a path to any picture on THIS device works, even if it isn't an app", HolyMother.LocalIcon(Path.Combine(root, "small.png"))!.SequenceEqual(small!));
            if (OperatingSystem.IsWindows())
            {
                byte[]? taken = HolyMother.LocalIcon("Program");
                Check("on Windows the icon is taken out of a program as a PNG", taken is { Length: > 100 } && taken[0] == 0x89 && taken[1] == 0x50);
            }

            var some = HolyMother.LocalIcons(new[] { "Small", "No Picture", "icon-small", "nope" });
            Check("a list gives a picture for each that has one, under the name it was asked with", some.Count == 2 && some.ContainsKey("Small") && some.ContainsKey("icon-small"));

            // from another device
            var remote = await HolyMother.GetIcon("pc", "Small");
            Check("another device gets the same picture by name", remote is not null && remote.SequenceEqual(small!));
            Check("...and by ID and by path of an app it lists", (await HolyMother.GetIcon("pc", "icon-small"))!.SequenceEqual(small!) && (await HolyMother.GetIcon("pc", Path.Combine(root, "small.exe")))!.SequenceEqual(small!));

            // a path that isn't one of the apps can't be used to look at other files
            File.WriteAllBytes(Path.Combine(root, "private.png"), Png(100, 77));
            Check("another device can't ask for a picture file that isn't one of the apps", await HolyMother.GetIcon("pc", Path.Combine(root, "private.png")) is null);

            var list = await HolyMother.GetIcons("pc", new[] { "Small", "icon-small", "No Picture", "Not An App", "Too Big" });
            Check("a list from another device gets what exists and leaves out the rest", list.Count == 2 && list.ContainsKey("Small") && list.ContainsKey("icon-small"));

            var many = await HolyMother.GetIcons("pc", Enumerable.Range(0, 45).Select(i => $"Many {i}"));
            Check("a list longer than one batch comes back whole", many.Count == 45 && many.Values.All(v => v.SequenceEqual(small!)));

            var big = await HolyMother.GetIcons("pc", Enumerable.Range(0, 8).Select(i => $"Big {i}"));
            Check("pictures that are too many for one answer arrive in several, none missing", big.Count == 8 && Enumerable.Range(0, 8).All(i => big[$"Big {i}"].SequenceEqual(File.ReadAllBytes(Path.Combine(root, $"big{i}.png")))));

            var queued = await Task.WhenAll(
                HolyMother.GetIcons("pc", Enumerable.Range(0, 30).Select(i => $"Many {i}")),
                HolyMother.GetIcons("pc", Enumerable.Range(15, 30).Select(i => $"Many {i}")),
                HolyMother.GetIcons("pc", new[] { "Small", "Big 3" }));
            Check("lists asked for at the same time are queued and each gets its own answer", queued[0].Count == 30 && queued[1].Count == 30 && queued[2].Count == 2 && queued[2]["Big 3"].Length > 100_000);

            HolyMother.Override = new List<HolyMother.AppEntry>();
            var cached = await HolyMother.GetIcon("pc", "Small");
            Check("a picture already fetched isn't asked for again", cached is not null && cached.SequenceEqual(small!));

            Check("a device that isn't connected gets an error, not a hang", await ThrowsAsync(() => HolyMother.GetIcon("stranger", "Never Asked")));
        }
        finally
        {
            HolyMother.Override = null; HolyMother.Node = null;
            foreach (var node in n.Values) node.Dispose();
        }
    }

    private static async Task<bool> ThrowsAsync(Func<Task> action)
    {
        try { await action(); return false; }
        catch (InvalidOperationException) { return true; }
    }
}
