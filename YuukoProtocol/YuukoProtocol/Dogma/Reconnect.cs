// Reconnect.cs - Devices you paired find each other again after they were turned off and on, without pairing again.
//
//   Reconnect.Open("reconnect.json", FileKey);                // BEFORE Identity.CreateNode: this device's UUID, its port and the addresses of the paired devices
//   await Identity.CreateNode(...);
//   await Reconnect.Start();                                  // after CreateNode and again in NodeRestarted (Like the other Start calls)
//
//   Reconnect.Found += (name, endpoint) => ...;              // a paired device showed up at an address (The node is built again to dial it)
//   Reconnect.Devices;                                        // the paired devices we remember (UUID, name, fingerprint, address, last seen)
//   Reconnect.Forget(uuid);                                   // stop looking for one
//
// What each device has: a UUID that nobody else can claim (Made once and saved), and its own private/public keys (Kyber and Dilithium, the ones the handshake
// already uses). When two devices connect they swap cards (UUID and address) over the encrypted session, so each side pins "this UUID belongs to this key". Later
// a different key claiming the same UUID or name is refused.
//
// Three things make them find each other again:
//   1. A FIXED PORT: the node listens on the same port every time (Chosen once, saved), so the address from last time is still the address.
//   2. SAVED ADDRESSES: the node dials the addresses it remembers as soon as it starts. Zenoh tries again until the other side is up.
//   3. A BEACON for when the address changed (A new IP from the router): a device that is missing a paired device announces where it is on the local network.
//      The announcement is {address, minute, tag} where the tag is an HMAC made with a key MUTATED from the group key (Argon2id, the one Pariah uses): only a device in the
//      group can make or check one, it doesn't carry the UUID, and it changes every minute, so nobody outside can tell who is talking or follow a device. A device
//      that hears a beacon that matches a UUID it knows, and isn't connected to it, remembers the new address and dials it (Only the device with the lower UUID dials, so
//      the two don't call each other at once).
//
// Everything saved (UUID, port, the paired devices) goes through Pariah's JSONDataHandler, encrypted with the key you give.
//
// What it does NOT do: it only finds devices on the same network (Beacons are multicast and in plain view: someone on the network can see that a beacon was sent and
// the address in it, not who sent it), a device in the group could send a beacon with a wrong address for another device (It only wastes a dial, the handshake
// still checks the keys), and it doesn't work between networks.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using WISecureData;

namespace YuukoProtocol.Dogma
{
    public static class Reconnect
    {
        //How often a device that is missing a paired device announces itself, and how often it tries the ones it knows
        public static TimeSpan BeaconEvery { get; set; } = TimeSpan.FromSeconds(10);
        public static TimeSpan RetryEvery { get; set; } = TimeSpan.FromSeconds(10);

        //The host or IP we tell others, set it if the one found by itself is wrong. Nothing means the first network address of this device
        public static string? AdvertiseHost { get; set; }

        //A paired device we remember
        public class Known
        {
            public string Uuid { get; set; } = "";
            public string Name { get; set; } = "";
            public string Fingerprint { get; set; } = "";
            public string Endpoint { get; set; } = "";
            public DateTime LastSeen { get; set; }
        }

        public static event Action<string, string>? Found;

        internal static void RaiseFound(string Name, string Endpoint) => Found?.Invoke(Name, Endpoint);

        static Store? Data;
        static Finder? Current;
        static ZenohBroker? Link;

        #region Create

        //Before Identity.CreateNode: loads (Or makes) the file with this device's UUID, its port and the paired devices, and tells Identity where to listen and who to dial
        public static void Open(string Path, SecureData Key)
        {
            Data = Store.Open(Path, Key);

            //The first time we pick a free port and keep it
            if (Data.Port == 0)
            {
                Data.Port = ZenohBroker.FindFreePort();
                Data.Save();
            }

            Identity.ListenPort = Data.Port;
            foreach (var Device in Data.Devices.Where(d => d.Endpoint.Length > 0)) Identity.RememberEndpoint(Device.Endpoint);
        }

        //After Identity.CreateNode, and again in Identity.NodeRestarted
        public static async Task Start()
        {
            var Data = Reconnect.Data ?? throw new InvalidOperationException("Call Reconnect.Open first.");
            var Node = Identity.YuukoNode ?? throw new InvalidOperationException("Create the node first (Identity.CreateNode).");

            if (Current is null)
            {
                //Beacons need the plain multicast kind of link (The node itself stays on TLS and only dials addresses)
                Link = ZenohBroker.Open(new ZenohBrokerOptions { EnableTls = false, AllowPlaintextDiscovery = true, DeviceName = "reconnect", AutoListen = false });

                Current = await Finder.Create(Data, Mutate(Identity.GroupKeyBytes), Link, Identity.MyEndpoint,
                    Name => Identity.YuukoNode?.IsConnected(Name) ?? false,
                    async Name => { var N = Identity.YuukoNode; if (N is not null) await N.PingAsync(Name); },
                    (Device, Endpoint) => { Identity.RememberEndpoint(Endpoint); _ = Identity.Rebuild(); },
                    BeaconEvery, RetryEvery);
            }

            //If the port had to change, the new one is saved
            if (Identity.ListenPort != Data.Port) { Data.Port = Identity.ListenPort; Data.Save(); }

            Current.Attach(Node);
        }

        //The group key mutated into a key just for beacons (Argon2id, the same one Pariah is built on), so a beacon proves its maker is in the group and the group key itself is never used
        //Pariah's own DeriveKey isn't public, so this calls the Argon2 library it uses. Modest memory (19 MB), it runs once
        internal static byte[] Mutate(byte[] GroupKey)
        {
            if (GroupKey is null || GroupKey.Length < 16) throw new InvalidOperationException("The group key is missing or too short.");

            using var Argon = new Konscious.Security.Cryptography.Argon2id((byte[])GroupKey.Clone())
            {
                Salt = Encoding.UTF8.GetBytes("yuuko-reconnect-beacon-v1"),
                DegreeOfParallelism = 1,
                MemorySize = 19456,
                Iterations = 2,
            };

            return Argon.GetBytes(32);
        }

        #endregion

        #region Read

        //This device's UUID (Made once, saved)
        public static string MyUuid => Data?.Uuid ?? throw new InvalidOperationException("Call Reconnect.Open first.");

        //The paired devices we remember
        public static List<Known> Devices => Data?.Snapshot() ?? new();

        //This device's address as tcp/host:port, nothing if it has no network address
        internal static string? HostEndpoint(int Port)
        {
            var Host = AdvertiseHost;
            if (Host is not null) return $"tcp/{Host}:{Port}";

            foreach (var Nic in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (Nic.OperationalStatus != OperationalStatus.Up || Nic.NetworkInterfaceType is NetworkInterfaceType.Loopback or NetworkInterfaceType.Tunnel) continue;

                var Ip = Nic.GetIPProperties().UnicastAddresses.FirstOrDefault(a => a.Address.AddressFamily == AddressFamily.InterNetwork && !a.Address.ToString().StartsWith("169.254"));
                if (Ip is not null) return $"tcp/{Ip.Address}:{Port}";
            }

            return null;
        }

        #endregion

        #region Delete

        public static void Forget(string Uuid) => Data?.Forget(Uuid);

        public static void Stop()
        {
            Current?.Dispose();
            Link?.Dispose();
            Current = null;
            Link = null;
        }

        #endregion


        //What is saved: this device's UUID, its port and the paired devices (Through Pariah's JSONDataHandler, encrypted)
        internal sealed class Store
        {
            sealed class Shape
            {
                public string Uuid { get; set; } = "";
                public int Port { get; set; }
                public List<Known> Devices { get; set; } = new();
            }

            readonly string? Path;
            readonly SecureData Key;
            readonly object Gate = new();

            public string Uuid = "";
            public int Port;
            public List<Known> Devices = new();

            Store(string? Path, SecureData Key) { this.Path = Path; this.Key = Key; }

            //Nothing saved on disk, for tests
            internal static Store InMemory(string? Uuid = null) => new(null, default) { Uuid = Uuid ?? Guid.NewGuid().ToString() };

            public static Store Open(string Path, SecureData Key)
            {
                var Made = new Store(Path, Key);

                if (System.IO.File.Exists(Path))
                {
                    //A wrong key or a damaged file throws here, we never start over by ourselves (The paired devices would be forgotten)
                    var Said = Task.Run(() => DeviceDirectory.ReadFileAsync(Path, Key)).GetAwaiter().GetResult();
                    var Back = JsonSerializer.Deserialize<Shape>(Said) ?? throw new InvalidOperationException("The reconnect file is empty.");

                    Made.Uuid = Back.Uuid;
                    Made.Port = Back.Port;
                    Made.Devices = Back.Devices;
                }

                if (Made.Uuid.Length == 0)
                {
                    Made.Uuid = Guid.NewGuid().ToString();
                    Made.Save();
                }

                return Made;
            }

            public void Save()
            {
                if (Path is null) return;

                string Said;
                lock (Gate) Said = JsonSerializer.Serialize(new Shape { Uuid = Uuid, Port = Port, Devices = Devices });
                Task.Run(() => DeviceDirectory.WriteFileAsync(Path, Key, Said)).GetAwaiter().GetResult();
            }

            public List<Known> Snapshot() { lock (Gate) return Devices.Select(d => new Known { Uuid = d.Uuid, Name = d.Name, Fingerprint = d.Fingerprint, Endpoint = d.Endpoint, LastSeen = d.LastSeen }).ToList(); }

            public void Forget(string Uuid)
            {
                lock (Gate) Devices.RemoveAll(d => d.Uuid == Uuid);
                Save();
            }

            //A device told us who it is over the encrypted session. A UUID, a name and a key belong together, and stay together
            public bool Learn(string Uuid, string Name, string Fingerprint, string Endpoint)
            {
                lock (Gate)
                {
                    var Clash = Devices.FirstOrDefault(d => d.Uuid == Uuid || d.Name == Name || d.Fingerprint == Fingerprint);

                    if (Clash is null) Devices.Add(new Known { Uuid = Uuid, Name = Name, Fingerprint = Fingerprint, Endpoint = Endpoint, LastSeen = DateTime.UtcNow });
                    else if (Clash.Uuid != Uuid || Clash.Name != Name || Clash.Fingerprint != Fingerprint) return false;      //Someone else wants this one's place
                    else { Clash.Endpoint = Endpoint.Length > 0 ? Endpoint : Clash.Endpoint; Clash.LastSeen = DateTime.UtcNow; }
                }

                Save();
                return true;
            }

            public void Moved(string Uuid, string Endpoint)
            {
                lock (Gate)
                {
                    var Device = Devices.FirstOrDefault(d => d.Uuid == Uuid);
                    if (Device is null) return;
                    Device.Endpoint = Endpoint;
                    Device.LastSeen = DateTime.UtcNow;
                }

                Save();
            }
        }


        //The beacons and the retrying, one per device (Tests make several in one process)
        internal sealed class Finder : IDisposable
        {
            const string Topic = "yuuko/reconnect/beacon";
            static readonly Regex Address = new(@"^tcp/[A-Za-z0-9.\-]{1,100}:[0-9]{2,5}$", RegexOptions.Compiled);
            static readonly TimeSpan Cooldown = TimeSpan.FromSeconds(15);

            public readonly Store Data;
            readonly byte[] Key;
            readonly IYuukoApi Link;
            readonly Func<string?> MyEndpoint;
            readonly Func<string, bool> Connected;
            readonly Func<string, Task> Poke;
            readonly Action<Known, string> Redial;
            readonly CancellationTokenSource Stopping = new();
            readonly Dictionary<string, DateTime> Dialed = new();
            readonly Func<YuukoPacket, Task> Listener;
            EclipseBroker? Node;
            int _Disposed;

            public int Heard;                                                       //Beacons that were ours to read, for tests
            public int Redialed;

            Finder(Store Data, byte[] Key, IYuukoApi Link, Func<string?> MyEndpoint, Func<string, bool> Connected, Func<string, Task> Poke, Action<Known, string> Redial)
            {
                this.Data = Data; this.Key = Key; this.Link = Link; this.MyEndpoint = MyEndpoint; this.Connected = Connected; this.Poke = Poke; this.Redial = Redial;
                Listener = OnBeacon;
            }

            public static async Task<Finder> Create(Store Data, byte[] Key, IYuukoApi Link, Func<string?> MyEndpoint, Func<string, bool> Connected, Func<string, Task> Poke, Action<Known, string> Redial, TimeSpan Beacon, TimeSpan Retry)
            {
                var Made = new Finder(Data, Key, Link, MyEndpoint, Connected, Poke, Redial);
                await Link.SubscribeAsync(Topic, Made.Listener);

                _ = Task.Run(() => Made.Loop(Beacon, Made.Announce));
                _ = Task.Run(() => Made.Loop(Retry, Made.TryKnown));
                return Made;
            }

            async Task Loop(TimeSpan Every, Func<Task> Work)
            {
                while (!Stopping.IsCancellationRequested)
                {
                    try { await Task.Delay(Every, Stopping.Token); }
                    catch (OperationCanceledException) { return; }

                    try { await Work(); } catch { }
                }
            }

            #region Cards: who the other device is, over the encrypted session

            //After the node is built (Again)
            public void Attach(EclipseBroker Node)
            {
                this.Node = Node;
                Node.On("reconnect.card", (c, _) => Task.FromResult(TakeCard(c.FromId, c.Payload)));
                Node.PeerConnected += Peer => _ = Task.Run(() => SendCard(Node, Peer.Id));

                foreach (var Id in Node.ConnectedPeers) _ = Task.Run(() => SendCard(Node, Id));
            }

            async Task SendCard(EclipseBroker From, string To)
            {
                try
                {
                    var Body = new JsonObject { ["u"] = Data.Uuid, ["e"] = MyEndpoint() ?? "" };
                    await From.SendCommandAsync(To, "reconnect.card", Encoding.UTF8.GetBytes(Body.ToJsonString()), new CommandOptions { Timeout = TimeSpan.FromSeconds(3), Retries = 1 });
                }
                catch { }
            }

            //The other device says its UUID and address. Who it is comes from the handshake (Its key), not from what it says
            CommandResult TakeCard(string From, byte[] Payload)
            {
                if (Payload.Length > 1024) return CommandResult.Error("too big");

                try
                {
                    var Body = JsonNode.Parse(Payload)!;
                    var Uuid = (string?)Body["u"] ?? "";
                    var Endpoint = (string?)Body["e"] ?? "";

                    if (!Guid.TryParse(Uuid, out _) || (Endpoint.Length > 0 && !Address.IsMatch(Endpoint))) return CommandResult.Error("malformed");

                    var Fingerprint = Node?.Peers.FirstOrDefault(p => p.Id == From)?.Fingerprint;
                    if (Fingerprint is null) return CommandResult.Denied("no session");

                    return Data.Learn(Uuid, From, Fingerprint, Endpoint) ? CommandResult.Ok() : CommandResult.Denied("that UUID, name or key belongs to another device");
                }
                catch (Exception ex) when (BadInput.Is(ex))
                {
                    return CommandResult.Error("malformed");
                }
            }

            #endregion

            #region Beacons: where we are, for devices that lost us

            static long Minute(DateTime At) => (long)(At - DateTime.UnixEpoch).TotalSeconds / 60;

            byte[] Tag(string Uuid, string Endpoint, long Minute) =>
                HMACSHA256.HashData(Key, Encoding.UTF8.GetBytes($"{Uuid}|{Endpoint}|{Minute}")).Take(16).ToArray();

            //Only while a paired device is missing, a device that has everybody says nothing
            async Task Announce()
            {
                if (!Data.Snapshot().Any(d => !Connected(d.Name))) return;

                var Where = MyEndpoint();
                if (Where is null) return;

                long Now = Minute(DateTime.UtcNow);
                var Body = new JsonObject { ["e"] = Where, ["w"] = Now, ["t"] = Convert.ToBase64String(Tag(Data.Uuid, Where, Now)) };
                await Link.PublishAsync(Topic, YuukoPacket.Ephemeral("beacon", Encoding.UTF8.GetBytes(Body.ToJsonString())), Stopping.Token);
            }

            //Someone announced where it is. If it is a paired device that is missing, and it is ours to call, call it
            Task OnBeacon(YuukoPacket Packet)
            {
                string Endpoint; long Window; byte[] Tag_;

                try
                {
                    var Body = JsonNode.Parse(Packet.Data)!;
                    Endpoint = (string?)Body["e"] ?? "";
                    Window = (long?)Body["w"] ?? -1;
                    Tag_ = Convert.FromBase64String((string?)Body["t"] ?? "");
                }
                catch (Exception ex) when (BadInput.Is(ex)) { return Task.CompletedTask; }

                if (Tag_.Length != 16 || !Address.IsMatch(Endpoint) || Math.Abs(Window - Minute(DateTime.UtcNow)) > 1) return Task.CompletedTask;

                //Whose is it? Only a device in the group can have made a tag that fits one of the UUIDs we know
                var Who = Data.Snapshot().FirstOrDefault(d => d.Uuid != Data.Uuid && CryptographicOperations.FixedTimeEquals(Tag(d.Uuid, Endpoint, Window), Tag_));
                if (Who is null) return Task.CompletedTask;

                Interlocked.Increment(ref Heard);

                //Not missing, or the other one calls (The lower UUID calls, so the two don't call each other at once)
                if (Connected(Who.Name) || string.CompareOrdinal(Data.Uuid, Who.Uuid) > 0) return Task.CompletedTask;

                lock (Dialed)
                {
                    if (Dialed.TryGetValue(Who.Uuid, out var Last) && DateTime.UtcNow - Last < Cooldown) return Task.CompletedTask;
                    Dialed[Who.Uuid] = DateTime.UtcNow;
                }

                Interlocked.Increment(ref Redialed);
                Data.Moved(Who.Uuid, Endpoint);
                Reconnect.RaiseFound(Who.Name, Endpoint);
                Redial(Who, Endpoint);
                return Task.CompletedTask;
            }

            //Every so often: the paired devices that aren't connected get a ping, which opens a session if the link is there (The saved address)
            async Task TryKnown()
            {
                foreach (var Device in Data.Snapshot().Where(d => !Connected(d.Name)))
                {
                    try { await Poke(Device.Name); } catch { }
                }
            }

            #endregion

            public void Dispose()
            {
                if (Interlocked.Exchange(ref _Disposed, 1) != 0) return;

                Stopping.Cancel();
                try { Link.UnsubscribeAsync(Topic, Listener).GetAwaiter().GetResult(); } catch { }
            }
        }
    }
}
