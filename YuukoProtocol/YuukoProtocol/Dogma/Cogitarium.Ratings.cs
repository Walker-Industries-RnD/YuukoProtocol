// Cogitarium.Ratings.cs - Liars and routes for the Cogitarium: devices rate the main devices, the source notices a group that lies, and a device picks the mesh or the internet.
//
//   // On every device (nothing to call, it happens by itself while a stream comes in): every RateEvery it rates the main device that fed it
//
//   // On the source:
//   var stream = Cogitarium.StartStream("district-12", "Cafe scene");
//   stream.Mains;            // the devices it sends to first (Rotated by itself until as many devices as possible are green)
//   stream.Ratings();        // what the devices say about each main: the average, how many rated, how many are green
//   stream.Suspects();       // devices whose ratings were left out
//   Cogitarium.MainsChanged += (stream, mains) => ...;
//   Cogitarium.Suspected += (stream, devices) => ...;
//
//   // On a device that wants the stream straight from the source instead of from the mesh:
//   await Cogitarium.SetRoute("district-12", Cogitarium.Route.Internet);     // or Mesh, or Auto (Mesh, until it starves)
//
// The rating: every RateEvery a device that gets a stream rates the main device that most of its pieces came through (The source stamps every copy with
// the device it sent that copy to, and the stamp travels with it). The rating is 0 to 100 (How many of the pieces that should have come really did) and
// it carries a RECEIPT: the number of the latest piece the device holds and a short hash of it. The source remembers what it sent, so it can tell a real
// receipt from a made up one: a hash that doesn't match, or a piece the source never sent, is a lie (The device is left out). A receipt that is old is
// not a lie, the device is just behind, and it counts as red whatever number it said. Nobody can rate well without really holding the latest pieces.
// A device never rates itself: a main device that got the piece from the source has nobody to rate, and a rating about the sender is ignored.
//
// The average: the source averages the ratings of each main. If a small group (MinGroup or more) rates a main very high while at least twice as many rate it
// very low (Or the other way round), that group is left out of the average: it looks like bots praising a bad main (Or slandering a good one). Nobody is banned,
// it is only decided again every round, so a device that stops lying is counted again.
//
// The rotation: the share of devices that are green is the coverage. If it is under TargetGreen the source takes its worst main out and tries the best
// connection it hasn't tried (Or tried the longest ago). If that made the coverage worse it goes back to the best set it has seen. This repeats, so it
// bounces around the main devices until it finds the set that gives as many devices as possible the green.
//
// The route: Mesh is the normal one. Internet asks the source to send every piece to this device itself (The source needs to be connected to it, and sends to
// at most MaxDirect devices that way), and this device stops asking its neighbors for pieces and stops passing them on. Auto is Mesh until no piece has come
// for AutoAfter, then Internet for AutoRetry, then Mesh again.
//
// What it does NOT do: ratings go straight to the source, so a device that isn't connected to the source can't rate. A device the source can't tell apart
// from many (Free identities) can still outvote the real ones if there are more of them than the real ones. A device that only ever received nothing has
// no main to blame.

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
        //How often devices rate the main device, and how often the source looks at the ratings
        public static TimeSpan RateEvery { get; set; } = TimeSpan.FromSeconds(5);

        //A rating at or above this is green
        public static double GreenAt { get; set; } = 70;

        //Praise is at or above this, a very low rating is at or below LowAt
        public static double HighAt { get; set; } = 90;
        public static double LowAt { get; set; } = 30;

        //The fewest devices that count as a group (And the fewest the source needs to judge anything)
        public static int MinGroup { get; set; } = 3;

        //The share of devices that should be green before the source stops looking for a better set
        public static double TargetGreen { get; set; } = 0.9;

        public static bool AutoRotate { get; set; } = true;

        //The most devices the source sends to itself (Route.Internet)
        public static int MaxDirect { get; set; } = 100;

        //Route.Auto: how long without a piece before it goes to the internet, and how long it stays there
        public static TimeSpan AutoAfter { get; set; } = TimeSpan.FromSeconds(6);
        public static TimeSpan AutoRetry { get; set; } = TimeSpan.FromSeconds(30);

        public enum Route { Mesh, Internet, Auto }

        //What the devices say about one main device
        public class MainRating
        {
            public string Main = "";               //Empty is pieces that came straight from the source
            public double Mean;                    //0 to 100
            public int Raters;
            public int Green;
            public int Ignored;                    //Devices left out of the average
        }

        public static event Action<StreamInfo, List<string>>? MainsChanged;
        public static event Action<StreamInfo, List<string>>? Suspected;

        internal static void RaiseMains(StreamInfo Info, List<string> Mains) => MainsChanged?.Invoke(Info, Mains);
        internal static void RaiseSuspected(StreamInfo Info, List<string> Devices) => Suspected?.Invoke(Info, Devices);

        //Get the stream from the mesh, straight from the source (Internet), or the mesh until it fails. Comes back with false if the source can't be reached (Nothing changes then)
        public static Task<bool> SetRoute(string ChunkID, Route How) => Net.SetRoute(ChunkID, How);

        public static Route RouteOf(string ChunkID) => Net.RouteOf(ChunkID);


        internal sealed partial class Mesh
        {
            sealed record Receipt(string Hash, DateTime At);

            sealed class Rating
            {
                public string Main = "";
                public double Q;
                public bool Proven;
                public bool Forged;
                public DateTime At;
            }

            //What the source keeps for each stream it makes
            sealed class Source
            {
                public StreamInfo Info = new();
                public Stream Stream = null!;
                public List<string> Mains = new();                                 //Who it sends to first
                public bool Pinned;                                                //The ratings changed them, so the rank doesn't pick them anymore
                public ConcurrentDictionary<long, Receipt> Sent = new();            //The last pieces it sent, to check receipts against
                public ConcurrentDictionary<string, Rating> Raters = new();
                public HashSet<string> Direct = new();
                public HashSet<string> Suspects = new();
                public double Best = -1;
                public List<string> BestSet = new();
                public Dictionary<string, DateTime> Tried = new();
            }

            sealed class Verdict
            {
                public List<MainRating> Mains = new();
                public HashSet<string> Suspects = new();
                public int Raters;
                public int Green;
                public double Coverage => Raters == 0 ? 0 : (double)Green / Raters;
            }

            const int KeepSent = 128;

            readonly ConcurrentDictionary<string, Source> Sources = new();
            readonly Dictionary<string, Route> Routes = new();
            readonly HashSet<string> Internet = new();                              //Chunks we get straight from the source
            readonly Dictionary<string, DateTime> AutoSince = new();
            readonly CancellationTokenSource Stopping = new();

            public event Action<StreamInfo, List<string>>? MainsChanged;
            public event Action<StreamInfo, List<string>>? Suspected;

            static string Hash8(byte[] Data) => Convert.ToHexString(SHA256.HashData(Data))[..16].ToLowerInvariant();

            bool InternetChunk(string ChunkID) { lock (Gate) return Internet.Contains(ChunkID); }

            //Every RateEvery: rate the main that fed us, look at the ratings of our own streams, check the route
            async Task Tick()
            {
                while (!Stopping.IsCancellationRequested)
                {
                    try { await Task.Delay(RateEvery, Stopping.Token); }
                    catch (OperationCanceledException) { return; }

                    try
                    {
                        SendRatings();
                        await CheckRoutes();
                        if (AutoRotate) foreach (var S in Sources.Values.ToList()) Review(S.Stream);
                    }
                    catch { }
                }
            }

            #region Source: what it keeps and who it sends to first

            //Keeps what a piece looked like, so a receipt for it can be checked
            void Remember(Source S, long Sequence, byte[] Data)
            {
                S.Sent[Sequence] = new Receipt(Hash8(Data), DateTime.UtcNow);
                if (Sequence >= KeepSent) S.Sent.TryRemove(Sequence - KeepSent, out _);
            }

            internal string? ReceiptOf(Stream Stream, long Sequence) =>
                Sources.TryGetValue(Stream.Info.ID, out var S) && S.Sent.TryGetValue(Sequence, out var R) ? R.Hash : null;

            //The mains first (Filled up from the best ranked when there are fewer than InitialReceivers), then everyone else in rank order
            List<string> Choose(Source S, int Level)
            {
                var All = Pick(S.Info.ChunkID, Level, int.MaxValue, null);
                var Alive = Candidates(S.Info.ChunkID);

                lock (S)
                {
                    //Until the ratings change something, the best ranked are the mains
                    if (!S.Pinned) S.Mains = Alive.Take(Math.Max(0, InitialReceivers)).ToList();

                    S.Mains.RemoveAll(m => !Alive.Contains(m));
                    foreach (var C in Alive) { if (S.Mains.Count >= InitialReceivers) break; if (!S.Mains.Contains(C)) S.Mains.Add(C); }
                    while (S.Mains.Count > Math.Max(0, InitialReceivers)) S.Mains.RemoveAt(S.Mains.Count - 1);

                    return S.Mains.Where(All.Contains).Concat(All.Where(a => !S.Mains.Contains(a))).ToList();
                }
            }

            //Everyone connected to us in the chunk we could use, best rank first (Whatever sizes they want)
            List<string> Candidates(string ChunkID) =>
                Peers.Where(p => p.Value.Chunks.ContainsKey(ChunkID) && !Distrusted.ContainsKey(p.Key) && Node.IsConnected(p.Key))
                    .OrderByDescending(p => RankOf(p.Key, p.Value)).ThenBy(p => p.Value.Score)
                    .Select(p => p.Key).ToList();

            public List<string> MainsOf(Stream Stream)
            {
                if (!Sources.TryGetValue(Stream.Info.ID, out var S)) return new();
                lock (S) return S.Mains.ToList();
            }

            public List<MainRating> RatingsOf(Stream Stream) => Sources.TryGetValue(Stream.Info.ID, out var S) ? Judge(S).Mains : new();

            public List<string> SuspectsOf(Stream Stream) => Sources.TryGetValue(Stream.Info.ID, out var S) ? Judge(S).Suspects.ToList() : new();

            public double CoverageOf(Stream Stream) => Sources.TryGetValue(Stream.Info.ID, out var S) ? Judge(S).Coverage : 0;

            //For tests: are we pulling this chunk from the source, and how many devices does the source serve itself
            internal bool Pulling(string ChunkID) => InternetChunk(ChunkID);

            internal int DirectOf(Stream Stream)
            {
                if (!Sources.TryGetValue(Stream.Info.ID, out var S)) return 0;
                lock (S) return S.Direct.Count;
            }

            //Tests give a rating without a device behind it
            internal void AddRating(Stream Stream, string Rater, string Main, double Q, bool Proven = true, bool Forged = false) =>
                Sources[Stream.Info.ID].Raters[Rater] = new Rating { Main = Main, Q = Q, Proven = Proven, Forged = Forged, At = DateTime.UtcNow };

            #endregion

            #region Device: rating the main that fed us

            void SendRatings()
            {
                foreach (var K in Known_.Values.Where(k => !k.Mine).ToList())
                {
                    if (InternetChunk(K.Info.ChunkID) || !Node.IsConnected(K.Info.Source)) continue;

                    double Q; string Main, Hash; long Sequence;
                    var Now = DateTime.UtcNow;

                    lock (K)
                    {
                        //Nothing yet, or the stream has been over a while
                        if (K.LastSeq < 0 || Now - K.LastAt > 5 * RateEvery) continue;

                        long Expected = K.Highest - K.WindowStart;
                        if (Expected <= 0 && K.WindowGot == 0)
                        {
                            //Nothing new since last time: slow source, or the main stopped passing it on
                            if (Now - K.LastAt <= 2 * RateEvery) continue;
                            Q = 0;
                        }
                        else Q = Math.Min(1.0, (double)K.WindowGot / Math.Max(1, Expected)) * 100;

                        if (K.Via.Count > 0) K.LastMain = K.Via.OrderByDescending(v => v.Value).First().Key;
                        Main = K.LastMain; Hash = K.LastHash; Sequence = K.LastSeq;

                        K.WindowStart = K.Highest;
                        K.WindowGot = 0;
                        K.Via.Clear();
                    }

                    //A main device got it from the source itself, it has nobody but itself to rate
                    if (Main == Node.ClientId) continue;

                    var Body = new JsonObject { ["s"] = K.Info.ID, ["m"] = Main, ["q"] = Q, ["n"] = Sequence, ["h"] = Hash };
                    _ = Task.Run(() => SendPiece2(K.Info.Source, "sccn.rate", Encoding.UTF8.GetBytes(Body.ToJsonString())));
                }
            }

            //Called for every piece we use: who it came through, and what the newest one looked like
            void Intake(Known K, long Sequence, byte[] Data, string Main)
            {
                K.WindowGot++;
                K.Via[Main] = K.Via.GetValueOrDefault(Main) + 1;
                if (Sequence >= K.LastSeq) { K.LastSeq = Sequence; K.LastHash = Hash8(Data); }
                K.LastAt = DateTime.UtcNow;
            }

            #endregion

            #region Source: getting the ratings and judging them

            //A device rates a main. The receipt has to be real or the device is left out
            CommandResult HandleRate(CommandContext Context)
            {
                var Rater = Context.FromId;
                if (Distrusted.ContainsKey(Rater)) return CommandResult.Denied("distrusted");
                if (Context.Payload.Length > 1024) return CommandResult.Error("too big");

                try
                {
                    var Body = JsonNode.Parse(Context.Payload)!;
                    string StreamID = (string?)Body["s"] ?? "", Main = (string?)Body["m"] ?? "", Hash = (string?)Body["h"] ?? "";
                    double Q = (double?)Body["q"] ?? throw new FormatException();
                    long Sequence = (long?)Body["n"] ?? throw new FormatException();

                    if (!Sources.TryGetValue(StreamID, out var S)) return CommandResult.Ok("unknown stream");
                    if (Main.Length > 128 || !double.IsFinite(Q) || Q is < 0 or > 100 || Sequence < 0 || Hash.Length != 16 || !Hash.All(Uri.IsHexDigit)) return CommandResult.Error("malformed");
                    if (!Peers.TryGetValue(Rater, out var Neighbor) || !Neighbor.Chunks.ContainsKey(S.Info.ChunkID)) return CommandResult.Ok("not in that chunk");
                    if (Main == Rater) return CommandResult.Ok("not about yourself");           //Praising yourself is not a rating

                    var Now = DateTime.UtcNow;
                    var Rating = new Rating { Main = Main, Q = Q, At = Now };

                    lock (S)
                    {
                        if (S.Raters.TryGetValue(Rater, out var Old) && Now - Old.At < RateEvery / 2) return CommandResult.Ok("too soon");

                        if (Sequence >= Interlocked.Read(ref S.Stream.Next)) Rating.Forged = true;          //A piece we never sent
                        else if (S.Sent.TryGetValue(Sequence, out var Mine))
                        {
                            if (!string.Equals(Mine.Hash, Hash, StringComparison.OrdinalIgnoreCase)) Rating.Forged = true;   //Not what we sent
                            else Rating.Proven = Now - Mine.At <= 3 * RateEvery;                                          //Real, and recent or not
                        }
                        //Older than we remember: it is behind, not lying

                        S.Raters[Rater] = Rating;
                    }

                    return CommandResult.Ok();
                }
                catch (Exception ex) when (BadInput.Is(ex))
                {
                    return CommandResult.Error("malformed");
                }
            }

            //Average the ratings per main, leaving out liars and groups that disagree with everyone else
            Verdict Judge(Source S)
            {
                var V = new Verdict();
                var Now = DateTime.UtcNow;
                var Fresh = S.Raters.Where(r => Now - r.Value.At <= 3 * RateEvery).ToList();

                foreach (var Liar in Fresh.Where(r => r.Value.Forged)) V.Suspects.Add(Liar.Key);
                var Honest = Fresh.Where(r => !r.Value.Forged).ToList();

                //A receipt that is old counts as red, whatever number came with it
                double Said(KeyValuePair<string, Rating> R) => R.Value.Proven ? R.Value.Q : 0;

                foreach (var Group in Honest.GroupBy(r => r.Value.Main))
                {
                    var High = Group.Where(r => r.Value.Proven && r.Value.Q >= HighAt).ToList();
                    var Low = Group.Where(r => Said(r) <= LowAt).ToList();
                    var LowReal = Low.Where(r => r.Value.Proven).ToList();

                    //A few praise it and at least twice as many say it is awful: the few are leaving, or the other way round
                    if (High.Count >= MinGroup && Low.Count >= 2 * High.Count) foreach (var R in High) V.Suspects.Add(R.Key);
                    else if (LowReal.Count >= MinGroup && High.Count >= 2 * LowReal.Count) foreach (var R in LowReal) V.Suspects.Add(R.Key);
                }

                foreach (var Group in Honest.GroupBy(r => r.Value.Main))
                {
                    var Counted = Group.Where(r => !V.Suspects.Contains(r.Key)).ToList();
                    int Out = Group.Count() - Counted.Count;
                    int Green = Counted.Count(r => Said(r) >= GreenAt);

                    V.Mains.Add(new MainRating { Main = Group.Key, Mean = Counted.Count == 0 ? 0 : Counted.Average(Said), Raters = Counted.Count, Green = Green, Ignored = Out });
                    V.Raters += Counted.Count;
                    V.Green += Green;
                }

                V.Mains = V.Mains.OrderByDescending(m => m.Mean).ToList();
                return V;
            }

            #endregion

            #region Source: bouncing around the mains until the most devices are green

            internal void Review(Stream Stream)
            {
                if (!Sources.TryGetValue(Stream.Info.ID, out var S)) return;

                var V = Judge(S);

                //Tell about new suspects
                List<string>? Fresh = null;
                lock (S)
                {
                    var New = V.Suspects.Where(x => !S.Suspects.Contains(x)).ToList();
                    S.Suspects = V.Suspects;
                    if (New.Count > 0) Fresh = New;
                }
                if (Fresh is not null) { Suspected?.Invoke(S.Info, Fresh); RaiseSuspected(S.Info, Fresh); }

                if (V.Raters < MinGroup) return;                       //Too few to judge

                List<string>? Changed = null;
                lock (S)
                {
                    S.Best *= 0.95;                                    //An old good result fades, the network changes

                    if (V.Coverage >= S.Best) { S.Best = V.Coverage; S.BestSet = S.Mains.ToList(); }
                    else if (S.BestSet.Count > 0 && !S.Mains.SequenceEqual(S.BestSet))
                    {
                        //The last change made it worse, go back to the best set
                        S.Mains = S.BestSet.ToList();
                        Changed = S.Mains.ToList();
                    }

                    if (Changed is null && V.Coverage < TargetGreen)
                    {
                        //Take the worst main out, try the connection we haven't tried (Or tried the longest ago)
                        var Worst = V.Mains.Where(m => m.Raters > 0 && S.Mains.Contains(m.Main)).OrderBy(m => m.Mean).FirstOrDefault();
                        var Spare = Candidates(S.Info.ChunkID).Where(c => !S.Mains.Contains(c)).OrderBy(c => S.Tried.GetValueOrDefault(c, DateTime.MinValue)).FirstOrDefault();

                        if (Worst is not null && Spare is not null)
                        {
                            S.Tried[Worst.Main] = DateTime.UtcNow;
                            S.Mains[S.Mains.IndexOf(Worst.Main)] = Spare;
                            Changed = S.Mains.ToList();
                        }
                    }

                    if (Changed is not null) { S.Pinned = true; S.Raters.Clear(); }         //Let the devices rate the new set, not the old one
                }

                if (Changed is not null) { MainsChanged?.Invoke(S.Info, Changed); RaiseMains(S.Info, Changed); }
            }

            #endregion

            #region The mesh or the internet

            public Route RouteOf(string ChunkID) { lock (Gate) return Routes.GetValueOrDefault(ChunkID, Route.Mesh); }

            public async Task<bool> SetRoute(string ChunkID, Route How)
            {
                CheckName(ChunkID);
                lock (Gate) { if (!MyChunks.Contains(ChunkID)) throw new InvalidOperationException("Join the chunk first."); }

                //Nobody to pull it from: stay on the mesh, we'd be left with nothing
                if (How == Route.Internet && !await Pull(ChunkID, true)) return false;
                if (How != Route.Internet) await Pull(ChunkID, false);

                lock (Gate)
                {
                    Routes[ChunkID] = How;
                    if (How == Route.Internet) Internet.Add(ChunkID); else Internet.Remove(ChunkID);
                    AutoSince.Remove(ChunkID);
                }

                TellEveryone();                                         //Neighbors stop (Or start) sending us pieces
                return true;
            }

            //Ask the sources of the streams in a chunk to send us every piece themselves (Or to stop). True if at least one said yes
            async Task<bool> Pull(string ChunkID, bool On)
            {
                var Sources_ = Known_.Values.Where(k => !k.Mine && k.Info.ChunkID == ChunkID && Node.IsConnected(k.Info.Source)).Select(k => k.Info).ToList();
                var Answers = await Task.WhenAll(Sources_.Select(i => PullOne(i, On)));
                return Answers.Any(a => a);
            }

            async Task<bool> PullOne(StreamInfo Info, bool On)
            {
                try
                {
                    var Ack = await Node.SendCommandAsync(Info.Source, "sccn.direct", Encoding.UTF8.GetBytes(new JsonObject { ["s"] = Info.ID, ["on"] = On }.ToJsonString()), Quick);
                    Learn(Info.Source, Ack);
                    return Ack.IsOk;
                }
                catch { return false; }
            }

            //A device wants the stream from us itself (Or doesn't anymore)
            CommandResult HandleDirect(CommandContext Context)
            {
                var Who = Context.FromId;
                if (Distrusted.ContainsKey(Who)) return CommandResult.Denied("distrusted");

                try
                {
                    var Body = JsonNode.Parse(Context.Payload)!;
                    var StreamID = (string?)Body["s"] ?? "";
                    bool On = (bool?)Body["on"] ?? throw new FormatException();

                    if (!Sources.TryGetValue(StreamID, out var S)) return CommandResult.Ok("unknown stream");
                    if (!Peers.TryGetValue(Who, out var Neighbor) || !Neighbor.Chunks.ContainsKey(S.Info.ChunkID)) return CommandResult.Ok("not in that chunk");

                    lock (S)
                    {
                        if (!On) S.Direct.Remove(Who);
                        else if (S.Direct.Contains(Who)) { }
                        else if (S.Direct.Count >= MaxDirect) return CommandResult.Error("full");
                        else S.Direct.Add(Who);
                    }

                    return CommandResult.Ok();
                }
                catch (Exception ex) when (BadInput.Is(ex))
                {
                    return CommandResult.Error("malformed");
                }
            }

            //The devices that asked for this stream themselves, the pieces go to them as well (Not counted among the mains)
            async Task SendDirect(Source S, Func<string, byte[]> Payload)
            {
                List<string> To;
                lock (S) To = S.Direct.Where(Node.IsConnected).ToList();
                await Task.WhenAll(To.Select(d => SendPiece(d, Payload(""))));
            }

            //Route.Auto: no piece for a while means the mesh isn't working for us, go to the internet for a bit and then try the mesh again
            async Task CheckRoutes()
            {
                var Now = DateTime.UtcNow;
                List<string> Autos;
                lock (Gate) Autos = Routes.Where(r => r.Value == Route.Auto).Select(r => r.Key).ToList();

                foreach (var Chunk in Autos)
                {
                    bool On; DateTime? Since;
                    lock (Gate) { On = Internet.Contains(Chunk); Since = AutoSince.TryGetValue(Chunk, out var T) ? T : null; }

                    var Live = Known_.Values.Where(k => !k.Mine && k.Info.ChunkID == Chunk && k.LastAt != default).ToList();

                    if (On)
                    {
                        if (Since is null || Now - Since < AutoRetry) continue;

                        await Pull(Chunk, false);
                        lock (Gate) { Internet.Remove(Chunk); AutoSince.Remove(Chunk); }
                        foreach (var K in Live) K.LastAt = Now;          //The mesh gets a fair chance to prove itself
                        TellEveryone();
                    }
                    else if (Live.Any(k => Now - k.LastAt > AutoAfter && Now - k.LastAt < 10 * AutoAfter) && await Pull(Chunk, true))
                    {
                        lock (Gate) { Internet.Add(Chunk); AutoSince[Chunk] = Now; }
                        TellEveryone();
                    }
                }
            }

            #endregion
        }
    }
}
