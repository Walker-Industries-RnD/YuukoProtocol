// AuditWitness.cs
// Keeps the newest head of other devices' audit logs, so a log that has entries cut off its end, or an earlier entry rewritten, doesn't match what was seen.
//
//   using var witness = new AuditWitness(node, "heads.json", key);      // on the devices that watch (path and key are optional: without them it is kept in memory only)
//   using var anchor = log.AnchorTo(node, "main");                      // on the device that writes the log: sends its head after every entry
//   var result = await log.VerifyWithWitnessesAsync(node, "main");      // later: does what the others saw match the file?
//
// What a witness believes: only what a device says about ITS OWN log (the device is known from the handshake, not from what it says), and only if the
// number goes up. The same number with another hash is kept as a conflict, because that is what a rewritten log looks like. The heads are saved
// (encrypted, through Pariah's JSONDataHandler) a few seconds after they change, so a witness that restarts still remembers.
//
// What it can NOT do: a device that has no witness connected while it writes, or whose witnesses were all wiped, can be cut off unnoticed. And a witness only
// knows what it was told, so entries written while it was off are first seen when the next entry is written.
//
// Walker Industries R&D - YuukoProtocol

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;
using WISecureData;

namespace YuukoProtocol
{
    public sealed class AuditWitness : IDisposable
    {
        //How long after a change the heads are saved (Tests make it short)
        internal static TimeSpan SaveEvery = TimeSpan.FromSeconds(5);

        const int MaxLogs = 4096, MaxNamesPerDevice = 16;

        public sealed class Seen
        {
            public long Seq { get; set; }
            public string Hash { get; set; } = "";
            public bool Conflict { get; set; }
        }

        sealed class Shape { public Dictionary<string, Seen> Heads { get; set; } = new(); }

        readonly EclipseBroker Node;
        readonly string? Path;
        readonly SecureData Key;
        readonly Dictionary<string, Seen> Heads = new(StringComparer.Ordinal);
        readonly object Gate = new();
        Timer? Pending;
        int _Disposed;

        public AuditWitness(EclipseBroker node, string? path = null, SecureData? key = null)
        {
            if (path is not null && key is null) throw new ArgumentException("A file of heads needs a key.", nameof(key));

            Node = node ?? throw new ArgumentNullException(nameof(node));
            Path = path;
            Key = key ?? default;

            //A wrong key or a damaged file throws, we never start with nothing by ourselves (Everything seen so far would be forgotten)
            if (path is not null && System.IO.File.Exists(path))
            {
                var Said = Task.Run(() => DeviceDirectory.ReadFileAsync(path, Key)).GetAwaiter().GetResult();
                Heads = JsonSerializer.Deserialize<Shape>(Said)?.Heads ?? throw new InvalidOperationException("The file of heads is empty.");
            }

            node.On("audit.head", (c, _) => Task.FromResult(HandleHead(c)));
            node.On("audit.gethead", (c, _) => Task.FromResult(HandleGet(c)));
        }

        internal static bool SafeName(string name) =>
            name.Length is >= 1 and <= 64 && name.All(c => char.IsAsciiLetterOrDigit(c) || c is '.' or '_' or '-');

        //What we saw of a device's log (nothing if we saw none)
        public Seen? HeadOf(string device, string name)
        {
            lock (Gate) return Heads.TryGetValue(device + "/" + name, out var Found) ? new Seen { Seq = Found.Seq, Hash = Found.Hash, Conflict = Found.Conflict } : null;
        }

        //A device tells us the newest entry of its log
        CommandResult HandleHead(CommandContext Context)
        {
            if (Context.Payload.Length > 512) return CommandResult.Error("too big");

            try
            {
                var Body = JsonNode.Parse(Context.Payload)!;
                string Name = (string?)Body["n"] ?? "", Hash = (string?)Body["h"] ?? "";
                long Seq = (long?)Body["s"] ?? 0;

                if (!SafeName(Name) || Seq < 1 || Hash.Length != 64 || !Hash.All(Uri.IsHexDigit)) return CommandResult.Error("malformed");

                string Key_ = Context.Origin + "/" + Name;
                lock (Gate)
                {
                    if (!Heads.TryGetValue(Key_, out var Old))
                    {
                        if (Heads.Count >= MaxLogs || Heads.Keys.Count(k => k.StartsWith(Context.Origin + "/", StringComparison.Ordinal)) >= MaxNamesPerDevice) return CommandResult.Error("too many logs");
                        Heads[Key_] = new Seen { Seq = Seq, Hash = Hash.ToLowerInvariant() };
                    }
                    else if (Seq > Old.Seq) { Old.Seq = Seq; Old.Hash = Hash.ToLowerInvariant(); }
                    else if (Seq == Old.Seq && !string.Equals(Old.Hash, Hash, StringComparison.OrdinalIgnoreCase)) Old.Conflict = true;     //Two versions of the same entry
                    else return CommandResult.Ok();       //Older, or the same: nothing to remember
                }

                SaveSoon();
                return CommandResult.Ok();
            }
            catch (Exception ex) when (BadInput.Is(ex)) { return CommandResult.Error("malformed"); }
        }

        //A device asks what we saw of its log
        CommandResult HandleGet(CommandContext Context)
        {
            try
            {
                string Name = (string?)JsonNode.Parse(Context.Payload)?["n"] ?? "";
                if (!SafeName(Name)) return CommandResult.Error("malformed");

                var Found = HeadOf(Context.Origin, Name);
                if (Found is null) return CommandResult.Error("none");

                return CommandResult.Ok(System.Text.Encoding.UTF8.GetBytes(new JsonObject { ["s"] = Found.Seq, ["h"] = Found.Hash, ["c"] = Found.Conflict }.ToJsonString()));
            }
            catch (Exception ex) when (BadInput.Is(ex)) { return CommandResult.Error("malformed"); }
        }

        void SaveSoon()
        {
            if (Path is null || Volatile.Read(ref _Disposed) != 0) return;
            lock (Gate) Pending ??= new Timer(_ => Save(), null, SaveEvery, Timeout.InfiniteTimeSpan);
        }

        void Save()
        {
            if (Path is null) return;

            string Said;
            lock (Gate)
            {
                Pending?.Dispose();
                Pending = null;
                Said = JsonSerializer.Serialize(new Shape { Heads = Heads });
            }

            try { Task.Run(() => DeviceDirectory.WriteFileAsync(Path, Key, Said)).GetAwaiter().GetResult(); }
            catch { /* the next change tries again */ }
        }

        public void Dispose()
        {
            if (Interlocked.Exchange(ref _Disposed, 1) != 0) return;

            Save();
            Node.Off("audit.head");
            Node.Off("audit.gethead");
        }
    }
}
