// Cogitarium.cs - The Cogitarium: devices near each other share a signed stream with each other, so one source doesn't have to send it to everyone.
//
// The Cogitarium was made specifically for the SCCN (Streaming Gaussian Splatting for high-density AR, its Collective Distribution part), but it only moves
// signed bytes between nearby devices, so it works for anything else too. It is built around a streetpass model: devices that pass each other find each
// other (Nearby.cs), see what streams are around before accepting any (Cogitarium.Offers), and swap small cards (Nearby.MyCard).
//
//   Cogitarium.Start();                                       // once, after Identity.CreateNode
//   Cogitarium.JoinChunk("district-12");                      // be part of that area's mesh
//   Cogitarium.AcceptSource(sourceFingerprint);               // streams from this source are accepted (and passed on), anything else is only offered
//   Cogitarium.StreamOffered += stream => ...;                // a source you haven't accepted has a stream here, Cogitarium.Accept(stream) to take it
//
//   // Receive:
//   Cogitarium.SegmentReceived += (stream, segment) => Render(stream.Name, segment.Level, segment.Data);
//
//   // Send (this device is the source):
//   var stream = Cogitarium.StartStream("district-12", "Cafe scene");
//   await stream.Send(bytes, Cogitarium.Full);                // goes to the best few devices in the chunk, who pass it on
//
//   // Which sizes this device wants for a chunk (The further away it is, the smaller):
//   Cogitarium.Want("district-12", Cogitarium.Quarter, Cogitarium.Sixteenth);
//
//   // If a device changes what it passes on:
//   Cogitarium.DeviceDistrusted += (device, reason) => ...;
//
// How it works: devices in the same chunk tell each other they are there (and which sizes they want). The source signs every piece of the
// stream and sends it to a few of the devices with the strongest connection (InitialReceivers). Each device that gets a piece checks the
// signature, uses it, and passes it to its own best few (Fanout) that want that size, so 1000 devices in a room need the source to talk to
// 10 and the rest pass it on, and nothing is sent twice to the same device because every piece has a number and repeats are dropped.
// A device only accepts and passes on streams from sources you accepted, by the source's fingerprint. Streams from other sources are only OFFERED to you (their name
// and source, checked against their signature, never passed on) so you can look at what is around and choose.
//
// Who gets pieces first: every device tells its neighbors how it is doing (Cogitarium.MyStatus: wifi strength, how busy the wifi is, battery and battery
// size, the app feeds these in). Each neighbor gets a RANK from 0 to 100 out of that, minus points for every different neighbor that distrusts it, and the
// highest rank is sent to first. A source goes down its list from the best to the worst until InitialReceivers devices took the piece. The numbers are
// what the device SAYS, nothing here measures them, so a liar can claim to be perfect (It can't change a piece though). The distrusts are not said by
// the device, we count them ourselves. The time a device takes to answer is only used to break a tie.
//
// Liars and routes (Cogitarium.Ratings.cs): devices rate the main device that fed them (with a receipt the source can check), the source leaves out a group
// that praises or slanders against everyone else, and rotates its main devices until as many devices as possible are green. A device can also choose to get
// the stream from the mesh or straight from the source (Cogitarium.SetRoute).
//
// Tampering: a device that passes on a piece that was changed fails the signature at the next device. That device stops using it as a source of
// data and stops passing anything to it (Distrusted), and tells the other devices in the chunk. When enough different neighbors (VotesToDistrust)
// say the same about a device it is distrusted by everyone who heard it, even if they never saw it do anything themselves. A distrusted
// device is never picked as an initial receiver, so the next best one takes its place.
//
// Strangers: Cogitarium.Start() works over your private group, so only devices you paired with. For devices you don't know, call
// await Nearby.Start() instead (Nearby.cs): it opens a second node that lets strangers in and finds them on the network, and Cogitarium runs on it.
//
// What it does NOT do: it doesn't find devices itself (They have to be connected already, or Nearby finds them),
// it doesn't carry video or Gaussian splats (It carries bytes you give it, a piece is at most 512 KB), and it can't tell a liar from
// a device that was lied to: a device that only DROPS pieces (instead of changing them) isn't noticed. Votes only count from devices
// directly connected to you, but a person with many devices can still vote many times, so don't treat the number as proof.

//Note I had these comments put atop the files because I am sure i'll forget how this all works in 2 months


using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;

namespace YuukoProtocol.Dogma
{
    public static partial class Cogitarium
    {
        //The five sizes a piece can be (1/1, 3/4, 1/2, 1/4 and 1/16 of full)
        public const int Full = 0;
        public const int ThreeQuarters = 1;
        public const int Half = 2;
        public const int Quarter = 3;
        public const int Sixteenth = 4;

        public const int MaxSegmentBytes = 512 * 1024;

        //How many devices the source sends each piece to, and how many each device passes it to
        public static int InitialReceivers { get; set; } = 10;
        public static int Fanout { get; set; } = 3;

        //How many different neighbors have to accuse a device before we distrust it without seeing it ourselves
        public static int VotesToDistrust { get; set; } = 3;

        //How much each part of a device's status counts toward its rank (Only the proportions matter)
        public static double WifiWeight { get; set; } = 30;
        public static double UsageWeight { get; set; } = 15;
        public static double BatteryWeight { get; set; } = 25;
        public static double CapacityWeight { get; set; } = 10;

        //Points taken off the rank for each different neighbor that distrusts the device
        public static double DistrustPenalty { get; set; } = 30;

        //A battery this big (mAh) or bigger gets all the capacity points
        public static double FullCapacity { get; set; } = 5000;

        //What a device says about itself, the app feeds it in (Nothing is measured here)
        public class DeviceStatus
        {
            public double WifiStrength;            //0 to 100, higher is better
            public double WifiUsage;               //0 to 100, how busy the wifi has been on average, lower is better
            public double BatteryPercent;          //0 to 100
            public double BatteryCapacity;         //mAh, how big the battery is
        }

        //0 to 100, higher gets pieces first. A device that said nothing counts as 50
        public static double Rank(DeviceStatus? Status, int Distrusts)
        {
            double Total = WifiWeight + UsageWeight + BatteryWeight + CapacityWeight;
            double Points = 50;

            if (Status is not null && Total > 0)
            {
                double Size = FullCapacity > 0 ? Math.Min(100, Status.BatteryCapacity / FullCapacity * 100) : 100;
                Points = (WifiWeight * Status.WifiStrength + UsageWeight * (100 - Status.WifiUsage) + BatteryWeight * Status.BatteryPercent + CapacityWeight * Size) / Total;
            }

            return Math.Clamp(Points - Distrusts * DistrustPenalty, 0, 100);
        }

        public class StreamInfo
        {
            public string ID = "";
            public string Name = "";
            public string ChunkID = "";
            public string Source = "";            //The device that makes it
            public string Fingerprint = "";        //What you accept it by
        }

        public class Segment
        {
            public long Sequence;
            public int Level;
            public byte[] Data = Array.Empty<byte>();
            public string From = "";               //The device that handed it to us
        }

        public class NeighborInfo
        {
            public string Device = "";
            public double Score;                   //Milliseconds it takes to answer us, lower is better
            public bool Distrusted;
            public List<int> Levels = new();       //The sizes it wants
            public DeviceStatus? Status;           //What it said about itself, nothing if it said nothing
            public int Distrusts;                  //How many different neighbors distrust it
            public double Rank;                    //Where it stands, 0 to 100
        }

        //A stream this device is the source of
        public class Stream
        {
            public StreamInfo Info = new();
            internal Mesh? Owner;
            internal long Next;

            //The devices the source sends to first, chosen by the ratings
            public List<string> Mains => Owner?.MainsOf(this) ?? new();

            //What the devices say about each main, the devices left out of that, and the share of devices that are green
            public List<MainRating> Ratings() => Owner?.RatingsOf(this) ?? new();
            public List<string> Suspects() => Owner?.SuspectsOf(this) ?? new();
            public double Coverage => Owner?.CoverageOf(this) ?? 0;

            //Look at the ratings now (It also happens by itself every RateEvery)
            public void Rebalance() => Owner?.Review(this);

            //Signs a piece and sends it to the best few devices in the chunk, comes back with how many took it
            public Task<int> Send(byte[] Data, int Level = Full) =>
                (Owner ?? throw new InvalidOperationException("This stream was stopped.")).Send(this, Data, Level);

            public void Stop()
            {
                Owner?.StopStream(this);
                Owner = null;
            }
        }

        //Fire in every mesh, tests listen to the one they made
        public static event Action<StreamInfo, Segment>? SegmentReceived;
        public static event Action<StreamInfo>? StreamFound;
        public static event Action<StreamInfo>? StreamOffered;       //A source we haven't accepted has a stream here (Streetpass: see what's around, then choose)
        public static event Action<string, string>? DeviceDistrusted;

        internal static void RaiseSegment(StreamInfo Info, Segment Piece) => SegmentReceived?.Invoke(Info, Piece);
        internal static void RaiseFound(StreamInfo Info) => StreamFound?.Invoke(Info);
        internal static void RaiseOffered(StreamInfo Info) => StreamOffered?.Invoke(Info);
        internal static void RaiseDistrusted(string Device, string Reason) => DeviceDistrusted?.Invoke(Device, Reason);

        internal static Mesh? Default { get; private set; }

        static Mesh Net => Default ?? throw new InvalidOperationException("Call Cogitarium.Start() first.");

        //Starts taking part over your private group, call it once after Identity.CreateNode (Or use Nearby.Start() for strangers)
        public static void Start()
        {
            if (Default is not null) return;
            if (Identity.YuukoNode is null) throw new InvalidOperationException("Create the node first (Identity.CreateNode).");
            Default = new Mesh(Identity.YuukoNode);
        }

        //Nearby.Start() puts the mesh on its own open node (Where strangers can join), Start() isn't needed then
        internal static void Attach(EclipseBroker Node)
        {
            Default?.Dispose();
            Default = new Mesh(Node);
        }

        //The node was built again, call Start() again (The nearby node isn't the one that was built again, so it stays unless Nearby.Stop() asks)
        internal static void Reset(bool Force = false)
        {
            if (Nearby.IsOn && !Force) return;

            Default?.Dispose();
            Default = null;
        }

        //What other devices accept this device's streams by
        public static string MyFingerprint => Net.MyFingerprint;

        //What this device tells its neighbors about itself, set it again whenever it changes (Not more than every few seconds)
        public static DeviceStatus? MyStatus
        {
            get => Net.MyStatus;
            set => Net.SetStatus(value ?? throw new ArgumentNullException(nameof(value)));
        }

        #region Create

        //Be part of an area's mesh, devices in the same chunk pass streams to each other
        public static void JoinChunk(string ChunkID) => Net.JoinChunk(ChunkID);

        //Streams from this source are accepted and passed on (Anything else is only offered, never passed on)
        public static void AcceptSource(string Fingerprint) => Net.AcceptSource(Fingerprint);

        //Accept the source of an offered stream, the stream starts at once
        public static void Accept(StreamInfo Offer) => Net.AcceptSource(Offer.Fingerprint);

        //Make this device a source in a chunk
        public static Stream StartStream(string ChunkID, string Name) => Net.StartStream(ChunkID, Name);

        #endregion

        #region Read

        //The devices connected to us that are in this chunk, best connection first
        public static List<NeighborInfo> Neighbors(string ChunkID) => Net.Neighbors(ChunkID);

        //The streams we know about
        public static List<StreamInfo> Streams => Net.Streams();

        //Streams from sources we haven't accepted, near us right now
        public static List<StreamInfo> Offers => Net.Offers();

        public static bool IsDistrusted(string Device) => Net.IsDistrusted(Device);

        public static List<string> DistrustedDevices => Net.DistrustedDevices();

        #endregion

        #region Update

        //Which sizes this device wants for a chunk (Nothing listed means all of them), devices pass us nothing else
        public static void Want(string ChunkID, params int[] Levels) => Net.Want(ChunkID, Levels);

        //Stop trusting a device yourself (Without waiting for votes)
        public static void Distrust(string Device) => Net.Distrust(Device, "by hand");

        //Trust a device again
        public static void Forgive(string Device) => Net.Forgive(Device);

        #endregion

        #region Delete

        public static void LeaveChunk(string ChunkID) => Net.LeaveChunk(ChunkID);

        //Streams from this source aren't accepted or passed on anymore
        public static void RejectSource(string Fingerprint) => Net.RejectSource(Fingerprint);

        #endregion


        internal sealed partial class Mesh : IDisposable
        {
            const int DefaultScore = 250;                       //What we assume about a device we haven't spoken to yet
            const int SeenWindow = 1024;                        //How many pieces back a repeat is still noticed
            const int MaxHops = 16;
            const int MaxOffers = 256;
            static readonly CommandOptions Quick = new() { Timeout = TimeSpan.FromSeconds(3), Retries = 0 };

            class Peer
            {
                public Dictionary<string, int> Chunks = new();   //Chunk and the sizes it wants
                public double Score = DefaultScore;              //Milliseconds it takes to answer us
                public DeviceStatus? Status;                     //What it said about itself
                public long HelloAt;                             //When its newest hello was made, so an older one that arrives late is ignored
            }

            class Offer
            {
                public StreamInfo Info = new();
                public byte[] Announce = Array.Empty<byte>();
                public string From = "";
            }

            class Known
            {
                public StreamInfo Info = new();
                public PublicKeys Keys = null!;
                public byte[] Announce = Array.Empty<byte>();    //As it came, so we can pass it to a neighbor who joins later
                public bool Mine;
                public long Highest = -1;
                public SortedSet<long> Seen = new();

                //What we need to rate the main that fed us
                public long WindowStart = -1;                    //Highest when this round began
                public long WindowGot;                           //Pieces used this round
                public Dictionary<string, int> Via = new();      //Main and how many pieces came through it this round
                public string LastMain = "";
                public long LastSeq = -1;
                public string LastHash = "";                     //Of the newest piece, the receipt
                public DateTime LastAt;
            }

            readonly EclipseBroker Node;
            readonly YuukoIdentity Me;
            readonly object Gate = new();
            readonly HashSet<string> MyChunks = new();
            readonly Dictionary<string, int> MyWants = new();
            readonly HashSet<string> Accepted = new();
            readonly ConcurrentDictionary<string, Peer> Peers = new();
            readonly ConcurrentDictionary<string, Known> Known_ = new();
            readonly ConcurrentDictionary<string, Offer> Offered = new();     //Streams from sources we haven't accepted
            readonly ConcurrentDictionary<string, string> Distrusted = new();
            readonly ConcurrentDictionary<string, HashSet<string>> Votes = new();
            int _Disposed;

            //Counts, for tests and for you to look at
            public int Forwarded;
            public int Rejected;

            public DeviceStatus? MyStatus { get; private set; }

            public event Action<StreamInfo, Segment>? SegmentReceived;
            public event Action<StreamInfo>? StreamFound;
            public event Action<StreamInfo>? StreamOffered;
            public event Action<string, string>? DeviceDistrusted;

            public Mesh(EclipseBroker Node)
            {
                this.Node = Node;
                Me = Node.LocalIdentity;

                Node.On("sccn.hello", (c, _) => Task.FromResult(HandleHello(c)));
                Node.On("sccn.announce", (c, _) => Task.FromResult(HandleAnnounce(c)));
                Node.On("sccn.segment", (c, _) => Task.FromResult(HandleSegment(c)));
                Node.On("sccn.warn", (c, _) => Task.FromResult(HandleWarn(c)));
                Node.On("sccn.status", (c, _) => Task.FromResult(HandleStatus(c)));
                Node.On("sccn.rate", (c, _) => Task.FromResult(HandleRate(c)));
                Node.On("sccn.direct", (c, _) => Task.FromResult(HandleDirect(c)));
                Node.PeerConnected += OnPeerConnected;
                Node.PeerDisconnected += OnPeerDisconnected;

                foreach (var Id in Node.ConnectedPeers) Peers.TryAdd(Id, new Peer());

                _ = Task.Run(Tick);
            }

            public string MyFingerprint => Me.Fingerprint;

            //Tests decide who counts as the strongest connection
            internal void SetScore(string Device, double Milliseconds) { if (Peers.TryGetValue(Device, out var Neighbor)) Neighbor.Score = Milliseconds; }

            public void Dispose()
            {
                if (Interlocked.Exchange(ref _Disposed, 1) != 0) return;

                Stopping.Cancel();
                Node.PeerConnected -= OnPeerConnected;
                Node.PeerDisconnected -= OnPeerDisconnected;
                foreach (var Command in new[] { "sccn.hello", "sccn.announce", "sccn.segment", "sccn.warn", "sccn.status", "sccn.rate", "sccn.direct" }) Node.Off(Command);
            }

            #region Create

            public void JoinChunk(string ChunkID)
            {
                CheckName(ChunkID);
                lock (Gate)
                {
                    MyChunks.Add(ChunkID);
                    MyWants.TryAdd(ChunkID, 31);
                }

                TellEveryone();
            }

            public void AcceptSource(string Fingerprint)
            {
                lock (Gate) Accepted.Add(Fingerprint);

                //What it already offered is ours now, and the rest is passed on from here
                foreach (var Old in Offered.Values.Where(o => o.Info.Fingerprint == Fingerprint).ToList())
                {
                    Offered.TryRemove(Old.Info.ID, out _);
                    Take(Old.Announce, Old.From);
                }

                TellEveryone();                         //Neighbors that know its streams tell us again
            }

            public Stream StartStream(string ChunkID, string Name)
            {
                CheckName(ChunkID);
                if (string.IsNullOrWhiteSpace(Name) || Name.Length > 64) throw new ArgumentException("A stream name is 1 to 64 characters.");
                lock (Gate) { if (!MyChunks.Contains(ChunkID)) throw new InvalidOperationException("Join the chunk first."); }

                var Info = new StreamInfo
                {
                    ID = Convert.ToHexString(RandomNumberGenerator.GetBytes(8)).ToLowerInvariant(),
                    Name = Name,
                    ChunkID = ChunkID,
                    Source = Node.ClientId,
                    Fingerprint = Me.Fingerprint,
                };

                var Keys = Me.ExportPublicKeys();
                var Announce = new JsonObject
                {
                    ["id"] = Info.ID, ["name"] = Info.Name, ["chunk"] = Info.ChunkID, ["source"] = Info.Source,
                    ["keys"] = JsonSerializer.SerializeToNode(Keys),
                    ["sig"] = Convert.ToBase64String(Me.Sign(AnnounceBytes(Info))),
                };

                var Bytes = Encoding.UTF8.GetBytes(Announce.ToJsonString());
                Known_[Info.ID] = new Known { Info = Info, Keys = Keys, Announce = Bytes, Mine = true };

                var Made = new Stream { Info = Info, Owner = this };
                Sources[Info.ID] = new Source { Info = Info, Stream = Made };
                SendToChunk(ChunkID, "sccn.announce", Bytes, null);
                return Made;
            }

            #endregion

            #region Read

            public List<NeighborInfo> Neighbors(string ChunkID) =>
                Peers.Where(p => p.Value.Chunks.ContainsKey(ChunkID))
                    .OrderByDescending(p => RankOf(p.Key, p.Value)).ThenBy(p => p.Value.Score)
                    .Select(p => new NeighborInfo
                    {
                        Device = p.Key,
                        Score = p.Value.Score,
                        Status = p.Value.Status,
                        Distrusts = DistrustCount(p.Key),
                        Rank = RankOf(p.Key, p.Value),
                        Distrusted = Distrusted.ContainsKey(p.Key),
                        Levels = Enumerable.Range(0, 5).Where(l => (p.Value.Chunks[ChunkID] & (1 << l)) != 0).ToList(),
                    }).ToList();

            public List<StreamInfo> Streams() => Known_.Values.Select(k => k.Info).ToList();

            public List<StreamInfo> Offers() => Offered.Values.Select(o => o.Info).ToList();

            public bool IsDistrusted(string Device) => Distrusted.ContainsKey(Device);

            public List<string> DistrustedDevices() => Distrusted.Keys.ToList();

            #endregion

            #region Update

            public void Want(string ChunkID, int[] Levels)
            {
                CheckName(ChunkID);

                var Mask = 0;
                foreach (var Level in Levels)
                {
                    if (Level is < 0 or > 4) throw new ArgumentOutOfRangeException(nameof(Levels));
                    Mask |= 1 << Level;
                }

                lock (Gate)
                {
                    if (!MyChunks.Contains(ChunkID)) throw new InvalidOperationException("Join the chunk first.");
                    MyWants[ChunkID] = Mask == 0 ? 31 : Mask;
                }

                TellEveryone();
            }

            public void Distrust(string Device, string Reason)
            {
                if (!Distrusted.TryAdd(Device, Reason)) return;

                DeviceDistrusted?.Invoke(Device, Reason);
                RaiseDistrusted(Device, Reason);
            }

            public void Forgive(string Device)
            {
                Distrusted.TryRemove(Device, out _);
                Votes.TryRemove(Device, out _);
            }

            #endregion

            #region Delete

            public void LeaveChunk(string ChunkID)
            {
                lock (Gate)
                {
                    MyChunks.Remove(ChunkID);
                    MyWants.Remove(ChunkID);
                }

                foreach (var Id in Known_.Where(k => k.Value.Info.ChunkID == ChunkID).Select(k => k.Key)) Known_.TryRemove(Id, out _);
                foreach (var Id in Offered.Where(o => o.Value.Info.ChunkID == ChunkID).Select(o => o.Key)) Offered.TryRemove(Id, out _);
                TellEveryone();
            }

            public void RejectSource(string Fingerprint)
            {
                lock (Gate) Accepted.Remove(Fingerprint);
                foreach (var Id in Known_.Where(k => k.Value.Info.Fingerprint == Fingerprint && !k.Value.Mine).Select(k => k.Key)) Known_.TryRemove(Id, out _);
            }

            public void StopStream(Stream Stream)
            {
                Known_.TryRemove(Stream.Info.ID, out _);
                Sources.TryRemove(Stream.Info.ID, out _);
            }

            #endregion

            #region Sending our own stream

            public async Task<int> Send(Stream Stream, byte[] Data, int Level)
            {
                if (Data is null || Data.Length == 0) throw new ArgumentException("There is nothing to send.");
                if (Data.Length > MaxSegmentBytes) throw new ArgumentException($"A piece is at most {MaxSegmentBytes} bytes, cut it up.");
                if (Level is < 0 or > 4) throw new ArgumentOutOfRangeException(nameof(Level));

                var Sequence = Interlocked.Increment(ref Stream.Next) - 1;
                var Sig = Me.Sign(SegmentBytes(Stream.Info.ID, Stream.Info.ChunkID, Sequence, Level, Data));

                //Every copy says which main it was sent to (The device that rates it reads it), the signature doesn't change
                byte[] Payload(string Main) =>
                    Frame(new JsonObject { ["id"] = Stream.Info.ID, ["seq"] = Sequence, ["lv"] = Level, ["h"] = 0, ["m"] = Main, ["sig"] = Convert.ToBase64String(Sig) }, Data);

                var Source = Sources[Stream.Info.ID];
                Remember(Source, Sequence, Data);

                //From the best to the worst, a device that doesn't take it is replaced by the next one down
                var Order = Choose(Source, Level);
                int Took = 0, Next = 0;

                while (Took < InitialReceivers && Next < Order.Count)
                {
                    var Wave = Order.Skip(Next).Take(InitialReceivers - Took).ToList();
                    Next += Wave.Count;
                    Took += (await Task.WhenAll(Wave.Select(r => SendPiece(r, Payload(r))))).Count(a => a);
                }

                await SendDirect(Source, Payload);
                return Took;
            }

            async Task<bool> SendPiece(string Device, byte[] Payload)
            {
                try
                {
                    var Ack = await Node.SendCommandAsync(Device, "sccn.segment", Payload, Quick);
                    Learn(Device, Ack);
                    return Ack.IsOk;
                }
                catch { return false; }
            }

            //How long a device takes to answer decides who we prefer (A bit of the old number is kept so one slow answer doesn't change much)
            void Learn(string Device, CommandAck Ack)
            {
                if (!Peers.TryGetValue(Device, out var Neighbor)) return;
                var Ms = Ack.IsFromPeer ? Ack.Elapsed.TotalMilliseconds : 1500;
                Neighbor.Score = Neighbor.Score * 0.7 + Ms * 0.3;
            }

            //The best few devices in a chunk that want this size (Not distrusted, not in Skip), highest rank first and the quicker one if it's a tie
            List<string> Pick(string ChunkID, int Level, int Count, HashSet<string>? Skip) =>
                Peers.Where(p => p.Value.Chunks.TryGetValue(ChunkID, out var Mask) && (Mask & (1 << Level)) != 0)
                    .Where(p => !Distrusted.ContainsKey(p.Key) && (Skip is null || !Skip.Contains(p.Key)) && Node.IsConnected(p.Key))
                    .OrderByDescending(p => RankOf(p.Key, p.Value)).ThenBy(p => p.Value.Score)
                    .Take(Math.Max(0, Count))
                    .Select(p => p.Key)
                    .ToList();

            #endregion

            #region Telling neighbors how we are doing

            double RankOf(string Device, Peer Neighbor) => Rank(Neighbor.Status, DistrustCount(Device));

            //How many different neighbors have said it tampered
            int DistrustCount(string Device)
            {
                if (!Votes.TryGetValue(Device, out var Who)) return 0;
                lock (Who) return Who.Count;
            }

            public void SetStatus(DeviceStatus Status)
            {
                if (!Fine(Status)) throw new ArgumentOutOfRangeException(nameof(Status), "Wifi and battery are 0 to 100, the battery size is in mAh.");

                MyStatus = new DeviceStatus { WifiStrength = Status.WifiStrength, WifiUsage = Status.WifiUsage, BatteryPercent = Status.BatteryPercent, BatteryCapacity = Status.BatteryCapacity };
                foreach (var Id in Node.ConnectedPeers) _ = Task.Run(() => SendStatus(Id));
            }

            static bool Fine(DeviceStatus S) =>
                double.IsFinite(S.WifiStrength) && double.IsFinite(S.WifiUsage) && double.IsFinite(S.BatteryPercent) && double.IsFinite(S.BatteryCapacity)
                && S.WifiStrength is >= 0 and <= 100 && S.WifiUsage is >= 0 and <= 100 && S.BatteryPercent is >= 0 and <= 100 && S.BatteryCapacity is >= 0 and <= 1_000_000;

            async Task SendStatus(string Device)
            {
                var Mine = MyStatus;
                if (Mine is null) return;

                var Body = new JsonObject { ["w"] = Mine.WifiStrength, ["u"] = Mine.WifiUsage, ["b"] = Mine.BatteryPercent, ["c"] = Mine.BatteryCapacity };
                await SendPiece2(Device, "sccn.status", Encoding.UTF8.GetBytes(Body.ToJsonString()));
            }

            //A neighbor says how it is doing, we believe it as far as it makes sense (Within range) and no further
            CommandResult HandleStatus(CommandContext Context)
            {
                if (Distrusted.ContainsKey(Context.FromId)) return CommandResult.Denied("distrusted");
                if (Context.Payload.Length > 1024) return CommandResult.Error("too big");

                try
                {
                    var Body = JsonNode.Parse(Context.Payload)!;
                    var Said = new DeviceStatus
                    {
                        WifiStrength = (double?)Body["w"] ?? throw new FormatException(),
                        WifiUsage = (double?)Body["u"] ?? throw new FormatException(),
                        BatteryPercent = (double?)Body["b"] ?? throw new FormatException(),
                        BatteryCapacity = (double?)Body["c"] ?? throw new FormatException(),
                    };

                    if (!Fine(Said)) return CommandResult.Error("out of range");

                    Peers.GetOrAdd(Context.FromId, _ => new Peer()).Status = Said;
                    return CommandResult.Ok();
                }
                catch (Exception ex) when (BadInput.Is(ex))
                {
                    return CommandResult.Error("malformed");
                }
            }

            //Tests decide how many neighbors distrust a device
            internal void AddVote(string Accused, string Voter)
            {
                var Who = Votes.GetOrAdd(Accused, _ => new HashSet<string>());
                lock (Who) Who.Add(Voter);
            }

            #endregion

            #region Telling neighbors where we are

            void OnPeerConnected(PeerInfo Connected)
            {
                if (Volatile.Read(ref _Disposed) != 0) return;
                Peers.TryAdd(Connected.Id, new Peer());
                _ = Task.Run(async () => { await TellOne(Connected.Id); await SendStatus(Connected.Id); });
            }

            void OnPeerDisconnected(string Id, string Reason)
            {
                Peers.TryRemove(Id, out _);
                foreach (var S in Sources.Values) { lock (S) { S.Direct.Remove(Id); S.Raters.TryRemove(Id, out _); } }
                foreach (var Old in Offered.Values.Where(o => o.From == Id || o.Info.Source == Id).ToList()) Offered.TryRemove(Old.Info.ID, out _);
            }

            void TellEveryone()
            {
                foreach (var Id in Node.ConnectedPeers) _ = Task.Run(() => TellOne(Id));
            }

            //A hello that gets no answer is sent again (twice at most), or that neighbor would never know which chunks we are in
            async Task TellOne(string Device)
            {
                for (int Try = 0; Try < 3 && Volatile.Read(ref _Disposed) == 0; Try++)
                {
                    try
                    {
                        var Chunks = new JsonObject();
                        long Stamp = DateTime.UtcNow.Ticks;
                        lock (Gate) foreach (var Chunk in MyChunks) Chunks[Chunk] = Internet.Contains(Chunk) ? 0 : MyWants.GetValueOrDefault(Chunk, 31);     //0: pieces come straight from the source

                        var Ack = await Node.SendCommandAsync(Device, "sccn.hello", Encoding.UTF8.GetBytes(new JsonObject { ["c"] = Chunks, ["t"] = Stamp }.ToJsonString()), Quick);
                        Learn(Device, Ack);

                        if (Ack.Status is not (AckStatus.TimedOut or AckStatus.Unreachable)) return;
                        await Task.Delay(500);
                    }
                    catch { return; }
                }
            }

            //A neighbor says which chunks it is in and what sizes it wants, then we tell it about the streams we know in those
            CommandResult HandleHello(CommandContext Context)
            {
                var Sender = Context.FromId;
                if (Distrusted.ContainsKey(Sender)) return CommandResult.Denied("distrusted");

                try
                {
                    var Chunks = new Dictionary<string, int>();
                    var Body = JsonNode.Parse(Context.Payload)?["c"]?.AsObject() ?? throw new FormatException();
                    if (Body.Count > 32) return CommandResult.Error("too many chunks");

                    foreach (var (Chunk, Mask) in Body)
                    {
                        var Wanted = (int?)Mask ?? -1;
                        if (!SafeName(Chunk) || Wanted is < 0 or > 31) return CommandResult.Error("malformed");
                        Chunks[Chunk] = Wanted;
                    }

                    var Neighbor = Peers.GetOrAdd(Sender, _ => new Peer());

                    //Two hellos can arrive in the wrong order, the one made first must not win
                    long Made = (long?)JsonNode.Parse(Context.Payload)?["t"] ?? 0;
                    lock (Neighbor)
                    {
                        if (Made != 0 && Made < Neighbor.HelloAt) return CommandResult.Ok("old");
                        Neighbor.HelloAt = Math.Max(Neighbor.HelloAt, Made);
                        Neighbor.Chunks = Chunks;
                    }

                    foreach (var Stream in Known_.Values.Where(k => Chunks.ContainsKey(k.Info.ChunkID)))
                    {
                        var Announce = Stream.Announce;
                        _ = Task.Run(() => SendPiece2(Sender, "sccn.announce", Announce));
                    }

                    return CommandResult.Ok();
                }
                catch (Exception ex) when (BadInput.Is(ex))
                {
                    return CommandResult.Error("malformed");
                }
            }

            async Task SendPiece2(string Device, string Command, byte[] Payload)
            {
                try { Learn(Device, await Node.SendCommandAsync(Device, Command, Payload, Quick)); }
                catch { }
            }

            #endregion

            #region Streams other devices make

            //A source says what its stream is, signed. We keep it only if we accepted that source and are in that chunk, and pass it on
            CommandResult HandleAnnounce(CommandContext Context)
            {
                if (Distrusted.ContainsKey(Context.FromId)) return CommandResult.Denied("distrusted");
                return Take(Context.Payload, Context.FromId);
            }

            CommandResult Take(byte[] Payload, string From)
            {
                if (Payload.Length > 64 * 1024) return CommandResult.Error("too big");

                try
                {
                    var Body = JsonNode.Parse(Payload)!;
                    var Info = new StreamInfo
                    {
                        ID = (string?)Body["id"] ?? "",
                        Name = (string?)Body["name"] ?? "",
                        ChunkID = (string?)Body["chunk"] ?? "",
                        Source = (string?)Body["source"] ?? "",
                    };

                    var Keys = Body["keys"].Deserialize<PublicKeys>() ?? throw new FormatException();
                    var Sig = Convert.FromBase64String((string?)Body["sig"] ?? "");

                    if (Info.ID.Length != 16 || !SafeName(Info.ID) || !SafeName(Info.ChunkID) || Info.Name.Length is 0 or > 64 || Info.Source.Length is 0 or > 128)
                        return CommandResult.Error("malformed");

                    Info.Fingerprint = YuukoIdentity.FingerprintOf(Keys);

                    bool Mine, Wanted;
                    lock (Gate)
                    {
                        Mine = Accepted.Contains(Info.Fingerprint);
                        Wanted = MyChunks.Contains(Info.ChunkID);
                    }

                    if (!Wanted) return CommandResult.Ok("not in that chunk");
                    if (Known_.ContainsKey(Info.ID) || Offered.ContainsKey(Info.ID)) return CommandResult.Ok("known");
                    if (!YuukoIdentity.VerifySignature(Keys.Signing, AnnounceBytes(Info), Sig)) return CommandResult.Error("bad signature");

                    //Not accepted: we only say it's there, it isn't kept as a stream or passed on
                    if (!Mine)
                    {
                        if (Offered.Count >= MaxOffers) return CommandResult.Ok("too many offers");
                        if (!Offered.TryAdd(Info.ID, new Offer { Info = Info, Announce = Payload, From = From })) return CommandResult.Ok("known");

                        StreamOffered?.Invoke(Info);
                        RaiseOffered(Info);
                        return CommandResult.Ok("offered");
                    }

                    if (!Known_.TryAdd(Info.ID, new Known { Info = Info, Keys = Keys, Announce = Payload })) return CommandResult.Ok("known");

                    StreamFound?.Invoke(Info);
                    RaiseFound(Info);

                    if (InternetChunk(Info.ChunkID)) _ = Task.Run(() => PullOne(Info, true));

                    SendToChunk(Info.ChunkID, "sccn.announce", Payload, From);
                    return CommandResult.Ok();
                }
                catch (Exception ex) when (BadInput.Is(ex))
                {
                    return CommandResult.Error("malformed");
                }
            }

            void SendToChunk(string ChunkID, string Command, byte[] Payload, string? Except)
            {
                foreach (var Id in Peers.Where(p => p.Value.Chunks.ContainsKey(ChunkID) && p.Key != Except && !Distrusted.ContainsKey(p.Key)).Select(p => p.Key))
                    _ = Task.Run(() => SendPiece2(Id, Command, Payload));
            }

            #endregion

            #region Getting a piece and passing it on

            CommandResult HandleSegment(CommandContext Context)
            {
                var Sender = Context.FromId;
                if (Distrusted.ContainsKey(Sender)) return CommandResult.Denied("distrusted");

                if (!Unframe(Context.Payload, out var Header, out var Data)) return CommandResult.Error("malformed");
                if (Data.Length == 0 || Data.Length > MaxSegmentBytes) return CommandResult.Error("wrong size");

                string Id, Main; long Sequence; int Level, Hops; byte[] Sig;

                try
                {
                    Id = (string?)Header["id"] ?? "";
                    Sequence = (long?)Header["seq"] ?? -1;
                    Level = (int?)Header["lv"] ?? -1;
                    Hops = (int?)Header["h"] ?? 0;
                    Main = (string?)Header["m"] ?? "";
                    Sig = Convert.FromBase64String((string?)Header["sig"] ?? "");
                }
                catch (Exception ex) when (BadInput.Is(ex)) { return CommandResult.Error("malformed"); }

                if (Sequence < 0 || Level is < 0 or > 4 || Hops is < 0 or > MaxHops || Sig.Length is 0 or > 16384 || Main.Length > 128) return CommandResult.Error("malformed");

                //Pieces for a stream we don't know, or a chunk we left, aren't an offence, they're just not for us
                if (!Known_.TryGetValue(Id, out var Stream) || Stream.Mine) return CommandResult.Ok("unknown stream");
                lock (Gate) { if (!MyChunks.Contains(Stream.Info.ChunkID)) return CommandResult.Ok("not in that chunk"); }

                //A repeat is dropped before it costs us a signature check
                lock (Stream)
                {
                    if (Sequence < Stream.Highest - SeenWindow || Stream.Seen.Contains(Sequence)) return CommandResult.Ok("repeat");
                }

                //The one who handed it to us gets the blame, it passed on something it shouldn't have
                if (!YuukoIdentity.VerifySignature(Stream.Keys.Signing, SegmentBytes(Id, Stream.Info.ChunkID, Sequence, Level, Data), Sig))
                {
                    Interlocked.Increment(ref Rejected);
                    Accuse(Sender, Stream, "bad signature");
                    return CommandResult.Error("bad signature");
                }

                lock (Stream)
                {
                    if (!Stream.Seen.Add(Sequence)) return CommandResult.Ok("repeat");

                    Stream.Highest = Math.Max(Stream.Highest, Sequence);
                    while (Stream.Seen.Count > SeenWindow) Stream.Seen.Remove(Stream.Seen.Min);
                    Intake(Stream, Sequence, Data, Main);
                }

                var Piece = new Segment { Sequence = Sequence, Level = Level, Data = Data, From = Sender };
                SegmentReceived?.Invoke(Stream.Info, Piece);
                RaiseSegment(Stream.Info, Piece);

                //A device that gets the stream from the source itself doesn't pass it on
                if (Hops < MaxHops && !InternetChunk(Stream.Info.ChunkID))
                {
                    Header["h"] = Hops + 1;
                    PassOn(Stream, Level, Frame(Header, Data), Sender);
                }

                return CommandResult.Ok();
            }

            //To our best few that want this size, not the one it came from and not the source itself (It has it)
            void PassOn(Known Stream, int Level, byte[] Payload, string Sender)
            {
                var Skip = new HashSet<string> { Sender, Stream.Info.Source };

                foreach (var Device in Pick(Stream.Info.ChunkID, Level, Fanout, Skip))
                {
                    Interlocked.Increment(ref Forwarded);
                    _ = Task.Run(() => SendPiece(Device, Payload));
                }
            }

            #endregion

            #region Tampering

            //We saw it ourselves: no more pieces from that device, and the others in the chunk are told
            void Accuse(string Device, Known Stream, string Reason)
            {
                if (!Distrusted.TryAdd(Device, Reason)) return;

                DeviceDistrusted?.Invoke(Device, Reason);
                RaiseDistrusted(Device, Reason);

                var Warning = Encoding.UTF8.GetBytes(new JsonObject { ["who"] = Device, ["stream"] = Stream.Info.ID, ["why"] = Reason }.ToJsonString());
                SendToChunk(Stream.Info.ChunkID, "sccn.warn", Warning, Device);
            }

            //A neighbor says a device tampered. One neighbor isn't enough: it has to be VotesToDistrust different ones
            CommandResult HandleWarn(CommandContext Context)
            {
                var Voter = Context.FromId;
                if (Distrusted.ContainsKey(Voter)) return CommandResult.Denied("distrusted");

                try
                {
                    var Body = JsonNode.Parse(Context.Payload)!;
                    var Accused = (string?)Body["who"] ?? "";
                    var StreamID = (string?)Body["stream"] ?? "";

                    //Only about a stream we know, from a neighbor in that chunk, and not about us or about themselves
                    if (Accused.Length is 0 or > 128 || Accused == Node.ClientId || Accused == Voter) return CommandResult.Error("malformed");
                    if (!Known_.TryGetValue(StreamID, out var Stream)) return CommandResult.Ok("unknown stream");
                    if (!Peers.TryGetValue(Voter, out var Neighbor) || !Neighbor.Chunks.ContainsKey(Stream.Info.ChunkID)) return CommandResult.Ok("not in that chunk");

                    int Count;
                    var Who = Votes.GetOrAdd(Accused, _ => new HashSet<string>());
                    lock (Who) { Who.Add(Voter); Count = Who.Count; }

                    if (Count >= VotesToDistrust) Distrust(Accused, $"{Count} neighbors say it tampered");
                    return CommandResult.Ok();
                }
                catch (Exception ex) when (BadInput.Is(ex))
                {
                    return CommandResult.Error("malformed");
                }
            }

            #endregion

            #region What gets signed

            //Every part is cut to a length first, so two different messages can't make the same bytes
            static byte[] Pack(params string[] Parts)
            {
                using var Out = new System.IO.MemoryStream();

                foreach (var Part in Parts)
                {
                    var Bytes = Encoding.UTF8.GetBytes(Part);
                    Out.Write(BitConverter.GetBytes(Bytes.Length));
                    Out.Write(Bytes);
                }

                return Out.ToArray();
            }

            internal static byte[] AnnounceBytes(StreamInfo Info) => Pack("sccn1-announce", Info.ID, Info.Name, Info.ChunkID, Info.Source);

            internal static byte[] SegmentBytes(string ID, string ChunkID, long Sequence, int Level, byte[] Data) =>
                Pack("sccn1-segment", ID, ChunkID, Sequence.ToString(), Level.ToString()).Concat(SHA256.HashData(Data)).ToArray();

            #endregion

            #region Framing

            //[4 bytes: header length][header JSON][the data]
            internal static byte[] Frame(JsonObject Header, byte[] Data)
            {
                var Head = Encoding.UTF8.GetBytes(Header.ToJsonString());
                var Out = new byte[4 + Head.Length + Data.Length];

                System.Buffers.Binary.BinaryPrimitives.WriteInt32BigEndian(Out, Head.Length);
                Head.CopyTo(Out, 4);
                Data.CopyTo(Out, 4 + Head.Length);
                return Out;
            }

            static bool Unframe(byte[] Bytes, out JsonObject Header, out byte[] Data)
            {
                Header = new JsonObject();
                Data = Array.Empty<byte>();

                if (Bytes.Length < 4) return false;
                var Length = System.Buffers.Binary.BinaryPrimitives.ReadInt32BigEndian(Bytes);
                if (Length <= 0 || Length > 16 * 1024 || 4 + Length > Bytes.Length) return false;

                try { Header = JsonNode.Parse(Bytes.AsSpan(4, Length))?.AsObject() ?? throw new JsonException(); }
                catch (Exception ex) when (BadInput.Is(ex)) { return false; }

                Data = Bytes.AsSpan(4 + Length).ToArray();
                return true;
            }

            static bool SafeName(string Text) =>
                Text.Length is > 0 and <= 64 && Text.All(c => char.IsLetterOrDigit(c) || c is '-' or '_' or '.' or ':');

            static void CheckName(string Text)
            {
                if (!SafeName(Text)) throw new ArgumentException("A chunk is 1 to 64 letters, digits, - _ . or :");
            }

            #endregion
        }
    }
}
