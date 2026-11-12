// DeviceDirectory.cs
// Your list of paired devices, and a way to talk to them by a local nickname ("moniker").
//
//   node.PairDevice("phone", "phone-01", "<fingerprint>", "My Pixel", "mobile");
//   await node.Device("phone").SendAsync("Notify", "dinner is ready");
//   await node.DeviceGroup("mobile").SendAsync("DoNotDisturb");      // every device in a group
//   foreach (var d in node.DeviceStatuses()) Console.WriteLine($"{d.Moniker}: {(d.IsOnline ? "online" : "offline")}");
//
// A moniker is YOURS: it lives in this device's directory and is never sent over the network.
// The thing that actually identifies a device is its key fingerprint, which the directory pins.
// Renaming a moniker therefore never disturbs a connection.
//
// Walker Industries R&D — YuukoProtocol

using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Pariah_Cybersecurity;
using WISecureData;
using JSONDataHandler = Pariah_Cybersecurity.DataHandler.JSONDataHandler;
using JSONObject = System.Text.Json.Nodes.JsonObject;

namespace YuukoProtocol
{
    //One paired device.
    public sealed record DeviceRecord(
        string Moniker,
        string ClientId,
        string Fingerprint,
        string? DisplayName,
        IReadOnlyList<string> Groups
        );


    //A paired device joined with its live connection state.
    public sealed record DeviceStatus(
        string Moniker,
        string ClientId,
        string Fingerprint,
        string? DisplayName,
        IReadOnlyList<string> Groups,
        bool IsConnected,
        bool IsOnline,
        DateTimeOffset? LastSeenUtc);

    //The paired-device list. In memory by default. Give it a key and a path and it is kept on disk, ENCRYPTED and
    //tamper-evident with that key (the contents are only names and fingerprints, so the point of the key is that nobody can
    //add a trusted device by editing the file). Whoever holds the key can read and change the list.
    public sealed class DeviceDirectory
    {
        private readonly object _lock = new();
        private readonly List<DeviceRecord> _items = new();
        private readonly string? _path;

        //Raised after any change (add, remove, rename, regroup).
        public event Action? Changed;

        private readonly SecureData _key;   // a struct: there is no null to check, a default key is refused by the handler

        private const string Variable = "FileShape";

        //A directory that lives in memory only.
        public DeviceDirectory() { }

        //A directory saved to path: a file name ending in .json (or no extension), kept in that folder,
        //encrypted with key. If the file already exists it is loaded before this returns. A file that cannot be
        //opened (wrong key, damaged, changed, or from a newer version) throws FormatException: it is NEVER treated as an
        //empty list, because an empty list would silently un-pair every device. The previous version of the file is kept beside it
        //as .bak. The directory keeps using key for as long as it lives, so do not dispose it first.
        public DeviceDirectory(SecureData key, string? path = null)
        {
            _key = key;
            if (path is null) return;

            var full = Path.GetFullPath(path);
            if (Path.HasExtension(full) && !string.Equals(Path.GetExtension(full), ".json", StringComparison.OrdinalIgnoreCase))
                throw new ArgumentException("The device list is stored as a .json file; give a path ending in .json (or no extension).", nameof(path));
            _path = Path.Combine(Path.GetDirectoryName(full)!, Path.GetFileNameWithoutExtension(full) + ".json");

            Load();
        }

        //Nicknames and group names: 1-64 characters of letters, digits, '.', '_' and '-'.
        public static bool IsValidName(string? s) =>
            !string.IsNullOrEmpty(s) && s.Length <= 64 &&
            s.All(c => char.IsAsciiLetterOrDigit(c) || c is '.' or '_' or '-');

        public IReadOnlyList<DeviceRecord> All()
        {
            lock (_lock) return _items.ToList();
        }

        //Looks a device up by nickname (case-insensitive).
        public DeviceRecord? Find(string moniker)
        {
            lock (_lock) return _items.FirstOrDefault(i => string.Equals(i.Moniker, moniker, StringComparison.OrdinalIgnoreCase));
        }

        public DeviceRecord? FindByClientId(string clientId)
        {
            lock (_lock) return _items.FirstOrDefault(i => string.Equals(i.ClientId, clientId, StringComparison.Ordinal));
        }

        public DeviceRecord? FindByFingerprint(string fingerprint)
        {
            var fp = (fingerprint ?? "").Trim().ToLowerInvariant();
            lock (_lock) return _items.FirstOrDefault(i => i.Fingerprint == fp);
        }

        public IReadOnlyList<DeviceRecord> InGroup(string group)
        {
            lock (_lock) return _items.Where(i => i.Groups.Any(g => string.Equals(g, group, StringComparison.OrdinalIgnoreCase))).ToList();
        }

        //Pairs a device. Nickname, id and fingerprint must each be unused.
        public DeviceRecord Add(string moniker, string clientId, string fingerprint,
            string? displayName = null, IEnumerable<string>? groups = null)
        {
            var rec = Build(moniker, clientId, fingerprint, displayName, groups);
            lock (_lock)
            {
                if (_items.Any(i => string.Equals(i.Moniker, rec.Moniker, StringComparison.OrdinalIgnoreCase)))
                    throw new InvalidOperationException($"A device is already paired as '{rec.Moniker}'.");
                if (_items.Any(i => string.Equals(i.ClientId, rec.ClientId, StringComparison.Ordinal)))
                    throw new InvalidOperationException($"A device with id '{rec.ClientId}' is already paired.");
                if (_items.Any(i => i.Fingerprint == rec.Fingerprint))
                    throw new InvalidOperationException("A device with that fingerprint is already paired.");

                _items.Add(rec);
                try { Save(); } catch { _items.Remove(rec); throw; }
            }
            RaiseChanged();
            return rec;
        }

        public bool Remove(string moniker)
        {
            lock (_lock)
            {
                var rec = _items.FirstOrDefault(i => string.Equals(i.Moniker, moniker, StringComparison.OrdinalIgnoreCase));
                if (rec is null) return false;
                _items.Remove(rec);
                try { Save(); } catch { _items.Add(rec); throw; }
            }
            RaiseChanged();
            return true;
        }

        //Changes a nickname. The device's key and connection are untouched.
        public DeviceRecord Rename(string oldMoniker, string newMoniker)
        {
            if (!IsValidName(newMoniker)) throw new ArgumentException(BadNameMessage("nickname"), nameof(newMoniker));
            DeviceRecord updated;
            lock (_lock)
            {
                int idx = _items.FindIndex(i => string.Equals(i.Moniker, oldMoniker, StringComparison.OrdinalIgnoreCase));
                if (idx < 0) throw new KeyNotFoundException($"No device is paired as '{oldMoniker}'.");
                if (_items.Any(i => string.Equals(i.Moniker, newMoniker, StringComparison.OrdinalIgnoreCase) && !ReferenceEquals(i, _items[idx])))
                    throw new InvalidOperationException($"A device is already paired as '{newMoniker}'.");

                var before = _items[idx];
                updated = before with { Moniker = newMoniker };
                _items[idx] = updated;
                try { Save(); } catch { _items[idx] = before; throw; }
            }
            RaiseChanged();
            return updated;
        }

        public DeviceRecord SetGroups(string moniker, IEnumerable<string> groups)
        {
            var clean = CleanGroups(groups);
            DeviceRecord updated;
            lock (_lock)
            {
                int idx = _items.FindIndex(i => string.Equals(i.Moniker, moniker, StringComparison.OrdinalIgnoreCase));
                if (idx < 0) throw new KeyNotFoundException($"No device is paired as '{moniker}'.");
                var before = _items[idx];
                updated = before with { Groups = clean };
                _items[idx] = updated;
                try { Save(); } catch { _items[idx] = before; throw; }
            }
            RaiseChanged();
            return updated;
        }

        //Internals

        private static string BadNameMessage(string what) =>
            $"A {what} is 1-64 characters: letters, digits, '.', '_' or '-'.";

        private static List<string> CleanGroups(IEnumerable<string>? groups)
        {
            var list = new List<string>();
            foreach (var g in groups ?? Enumerable.Empty<string>())
            {
                if (!IsValidName(g)) throw new ArgumentException(BadNameMessage("group name"), nameof(groups));
                if (!list.Contains(g, StringComparer.OrdinalIgnoreCase)) list.Add(g);
            }
            return list;
        }

        private static DeviceRecord Build(string moniker, string clientId, string fingerprint, string? displayName, IEnumerable<string>? groups)
        {
            if (!IsValidName(moniker)) throw new ArgumentException(BadNameMessage("nickname"), nameof(moniker));
            if (string.IsNullOrWhiteSpace(clientId) || clientId.Length > 128)
                throw new ArgumentException("clientId must be 1-128 characters.", nameof(clientId));

            var fp = (fingerprint ?? "").Trim().ToLowerInvariant();
            if (fp.Length != 64 || !fp.All(Uri.IsHexDigit))
                throw new ArgumentException("fingerprint must be 64 hex characters (YuukoIdentity.Fingerprint).", nameof(fingerprint));

            return new DeviceRecord(moniker, clientId, fp,
                displayName is { Length: > 128 } d ? d[..128] : displayName, CleanGroups(groups));
        }

        private void RaiseChanged()
        {
            try { Changed?.Invoke(); } catch { /* a subscriber's bug must not corrupt the directory */ }
        }

        private sealed class FileShape
        {
            public int Version { get; set; } = 1;
            public List<DeviceRecord> Devices { get; set; } = new();

            public FileShape() { }
        }

        //Saving and loading

        // Pariah's JSON handler is async-only. The public methods here are synchronous (so nothing that calls them had to change),
        // so the async work is run on the thread pool and waited for: there is no synchronization context for it to deadlock
        // on, and every failure reaches the caller instead of vanishing inside an unobserved task.
        private static void Run(Func<Task> work) => Task.Run(work).GetAwaiter().GetResult();
        private static T Run<T>(Func<Task<T>> work) => Task.Run(work).GetAwaiter().GetResult();

        // Called with _lock held (by Add / Remove / Rename / SetGroups), so saves can never overlap.
        // Throws if the file could not be written, which makes the caller undo its change.
        private void Save()
        {
            if (_path is null) return;
            var snapshot = _items.ToList();
            Run(() => WriteFileAsync(_path, _key, SerializeShape(snapshot)));
        }

        private static string SerializeShape(List<DeviceRecord> items) =>
            JsonSerializer.Serialize(new FileShape { Devices = items });

        //Writes the list. The new version goes to a temporary file first and is then swapped in, because the handler writes the
        //real file in place (a crash half way through would leave a damaged file and an un-paired group). The version it
        //replaces is kept as .bak. Internal so the self-test can write files this class itself never would.
        internal static async Task WriteFileAsync(string file, SecureData key, string shapeJson)
        {
            file = System.IO.Path.GetFullPath(file);      //A name with no folder in front of it is the current folder
            string dir = Path.GetDirectoryName(file)!;
            string name = Path.GetFileNameWithoutExtension(file);
            Directory.CreateDirectory(dir);

            string tmpName = name + ".saving";
            string tmpFile = Path.Combine(dir, tmpName + ".json");
            try
            {
                if (File.Exists(tmpFile)) File.Delete(tmpFile);   // left over from a crash

                await JSONDataHandler.CreateJsonFile(tmpName, dir, new JSONObject());
                var json = await JSONDataHandler.LoadJsonFile(tmpName, dir);
                json = await JSONDataHandler.AddToJson<string>(json, Variable, shapeJson, key);
                await JSONDataHandler.SaveJson(json);

                if (File.Exists(file)) File.Copy(file, file + ".bak", overwrite: true);
                File.Move(tmpFile, file, overwrite: true);
            }
            finally
            {
                try { if (File.Exists(tmpFile)) File.Delete(tmpFile); } catch { /* it is only a temporary file */ }
            }
        }

        internal static async Task<string> ReadFileAsync(string file, SecureData key)
        {
            file = System.IO.Path.GetFullPath(file);
            var json = await JSONDataHandler.LoadJsonFile(Path.GetFileNameWithoutExtension(file), Path.GetDirectoryName(file)!);
            return (string)await JSONDataHandler.GetVariable<string>(json, Variable, key);
        }

        private string OpenFailureMessage(Exception e) =>
            $"Could not open '{_path}': wrong key, or the file was damaged or changed ({FirstLine(e)})."
            + (File.Exists(_path + ".bak") ? $" The previous save is kept at '{_path}.bak'." : "");

        private static string FirstLine(Exception e)
        {
            var m = e.GetBaseException().Message;
            int nl = m.IndexOfAny(new[] { '\r', '\n' });
            return nl < 0 ? m : m[..nl];
        }

        private void Load()
        {
            if (!File.Exists(_path)) return;   // a new directory

            string shapeJson;
            try { shapeJson = Run(() => ReadFileAsync(_path!, _key)); }
            catch (Exception e) { throw new FormatException(OpenFailureMessage(e), e); }

            FileShape? f;
            try { f = JsonSerializer.Deserialize<FileShape>(shapeJson); }
            catch (JsonException e) { throw new FormatException($"'{_path}' is not a device directory file.", e); }
            if (f is null || f.Version != 1) throw new FormatException($"'{_path}' is not a device directory file (or is a newer version).");

            // A bad entry must not be skipped quietly: skipping a trusted device is safe, but silently loading a
            // half-valid list could hide that something is wrong. Nothing is kept unless every entry is good.
            var accepted = new List<DeviceRecord>();
            foreach (var d in f.Devices)
            {
                DeviceRecord rec;
                try { rec = Build(d.Moniker, d.ClientId, d.Fingerprint, d.DisplayName, d.Groups); }
                catch (ArgumentException e) { throw new FormatException($"'{_path}' has an invalid entry: {e.Message}", e); }

                if (accepted.Any(i => string.Equals(i.Moniker, rec.Moniker, StringComparison.OrdinalIgnoreCase) ||
                                      i.ClientId == rec.ClientId || i.Fingerprint == rec.Fingerprint))
                    throw new FormatException($"'{_path}' lists '{rec.Moniker}' more than once.");
                accepted.Add(rec);
            }
            _items.AddRange(accepted);
        }
    }

    //Talks to one paired device by nickname.
    public sealed class DeviceHandle
    {
        private readonly EclipseBroker _broker;

        internal DeviceHandle(EclipseBroker broker, DeviceRecord record)
        {
            _broker = broker;
            Record = record;
        }

        public DeviceRecord Record { get; }
        public string Moniker => Record.Moniker;
        public string ClientId => Record.ClientId;
        public string Fingerprint => Record.Fingerprint;
        public string? DisplayName => Record.DisplayName;

        public bool IsConnected => _broker.IsConnected(ClientId);
        public bool IsOnline => _broker.IsOnline(ClientId);
        public DateTimeOffset? LastSeenUtc => _broker.LastSeen(ClientId);

        //Asks the device to run a command and waits for its ack.
        public Task<CommandAck> SendAsync(string command, byte[]? payload = null, CommandOptions? options = null, CancellationToken ct = default) =>
            _broker.SendCommandAsync(ClientId, command, payload, options, ct);

        //Same, with a text payload.
        public Task<CommandAck> SendTextAsync(string command, string text, CommandOptions? options = null, CancellationToken ct = default) =>
            _broker.SendCommandAsync(ClientId, command, System.Text.Encoding.UTF8.GetBytes(text), options, ct);

        public Task<CommandAck> PingAsync(CancellationToken ct = default) => _broker.PingAsync(ClientId, ct);

        //Fetches the packets the device is serving on a topic.
        public Task<IReadOnlyList<YuukoPacket>> RequestAsync(string topic, CancellationToken ct = default) =>
            _broker.RequestAsync(ClientId, topic, ct);

        //Ends our sessions with the device. With ban it also cannot reconnect until unbanned.
        public Task<bool> KickAsync(bool ban = false, CancellationToken ct = default) =>
            _broker.KickAsync(ClientId, ban, null, ct);
    }

    //A group of paired devices you can send to at once.
    public sealed class DeviceSet : IEnumerable<DeviceHandle>
    {
        internal DeviceSet(IReadOnlyList<DeviceHandle> devices) => Devices = devices;

        public IReadOnlyList<DeviceHandle> Devices { get; }
        public int Count => Devices.Count;

        //The same set without the named devices.
        public DeviceSet Except(params string[] monikers) => new(Devices
            .Where(d => !monikers.Any(m => string.Equals(m, d.Moniker, StringComparison.OrdinalIgnoreCase))).ToList());

        //Only the devices we have heard from recently.
        public DeviceSet OnlineOnly() => new(Devices.Where(d => d.IsOnline).ToList());

        //Sends the command to every device in parallel; the result maps each nickname to its ack.
        public async Task<IReadOnlyDictionary<string, CommandAck>> SendAsync(string command, byte[]? payload = null,
            CommandOptions? options = null, CancellationToken ct = default)
        {
            var sent = Devices.Select(d => (d.Moniker, Ack: d.SendAsync(command, payload, options, ct))).ToList();
            await Task.WhenAll(sent.Select(s => s.Ack)).ConfigureAwait(false);
            return sent.ToDictionary(s => s.Moniker, s => s.Ack.Result, StringComparer.OrdinalIgnoreCase);
        }

        public IEnumerator<DeviceHandle> GetEnumerator() => Devices.GetEnumerator();
        IEnumerator IEnumerable.GetEnumerator() => GetEnumerator();
    }
}
