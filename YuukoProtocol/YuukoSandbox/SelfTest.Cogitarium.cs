using System.Collections.Concurrent;
using System.Text;
using System.Text.Json.Nodes;
using YuukoProtocol;
using YuukoProtocol.Dogma;

namespace YuukoSandbox;

// Tests for collective distribution (SCCN): a signed stream passed along a mesh of devices, who gets it and who doesn't, and what happens to a device that changes it.
public static partial class SelfTest
{
    // Each mesh with a list of what it was given
    private sealed class Listening
    {
        public Cogitarium.Mesh Mesh = null!;
        public ConcurrentQueue<Cogitarium.Segment> Got = new();
        public int Count => Got.Count;
        public List<long> Sequences => Got.Select(s => s.Sequence).OrderBy(s => s).ToList();
    }

    private static Dictionary<string, Listening> MakeMeshes(Dictionary<string, EclipseBroker> nodes, params string[] names)
    {
        var all = new Dictionary<string, Listening>();
        foreach (var name in names)
        {
            var l = new Listening { Mesh = new Cogitarium.Mesh(nodes[name]) };
            var mine = l;
            l.Mesh.SegmentReceived += (info, piece) => mine.Got.Enqueue(piece);
            all[name] = l;
        }
        return all;
    }

    // A device that doesn't run the mesh itself, so a test can make it misbehave (Says hello so the others see it as a neighbor)
    private static async Task SayHello(EclipseBroker raw, string to, string chunk) =>
        await raw.SendCommandAsync(to, "sccn.hello", Encoding.UTF8.GetBytes(new JsonObject { ["c"] = new JsonObject { [chunk] = 31 } }.ToJsonString()));

    private static async Task CogitariumTests()
    {
        Section("collective distribution (SCCN)");

        int initial = Cogitarium.InitialReceivers, fanout = Cogitarium.Fanout, votes = Cogitarium.VotesToDistrust;
        try
        {
            await CogitariumRelay();
            await CogitariumNotAccepted();
            await CogitariumSizes();
            await CogitariumBestConnections();
            await CogitariumRank();
            await CogitariumTampering();
            await CogitariumBadInput();
        }
        finally { Cogitarium.InitialReceivers = initial; Cogitarium.Fanout = fanout; Cogitarium.VotesToDistrust = votes; }
    }

    // ---- a piece reaches devices the source isn't connected to, once each, and only the ones that should ----
    private static async Task CogitariumRelay()
    {
        using var bus = new LocalBroker();
        // s - a - {b, c} - d with extra links so there are several ways to reach each, e is in another chunk, z is a spy that records
        var (n, _) = await Group(bus, new[] { "s", "a", "b", "c", "d", "e", "z" },
            new[] { ("s", "a"), ("a", "b"), ("a", "c"), ("b", "c"), ("b", "d"), ("c", "d"), ("a", "e"), ("a", "z"), ("z", "b") });
        var m = MakeMeshes(n, "s", "a", "b", "c", "d", "e");
        var spied = new ConcurrentQueue<byte[]>();
        n["z"].On("sccn.hello", (c, _) => Task.FromResult(CommandResult.Ok()));
        n["z"].On("sccn.announce", (c, _) => Task.FromResult(CommandResult.Ok()));
        n["z"].On("sccn.segment", (c, _) => { spied.Enqueue(c.Payload); return Task.FromResult(CommandResult.Ok()); });
        try
        {
            string source = m["s"].Mesh.MyFingerprint;
            foreach (var name in new[] { "s", "a", "b", "c", "d" }) m[name].Mesh.JoinChunk("room");
            m["e"].Mesh.JoinChunk("elsewhere");
            foreach (var name in new[] { "a", "b", "c", "d", "e" }) m[name].Mesh.AcceptSource(source);
            await SayHello(n["z"], "a", "room"); await SayHello(n["z"], "b", "room");

            Check("devices in the same chunk learn about each other", await Eventually(() => m["s"].Mesh.Neighbors("room").Count == 1 && m["a"].Mesh.Neighbors("room").Count >= 3 && m["d"].Mesh.Neighbors("room").Count == 2, 8000));
            Check("a device in another chunk isn't a neighbor", m["a"].Mesh.Neighbors("room").All(x => x.Device != "e") && m["a"].Mesh.Neighbors("elsewhere").Single().Device == "e");

            var stream = m["s"].Mesh.StartStream("room", "Cafe scene");
            Check("a stream is announced through the mesh to devices that accepted its source", await Eventually(() => m["d"].Mesh.Streams().Count == 1 && m["a"].Mesh.Streams().Count == 1, 8000));
            Check("...with the name, chunk, source and fingerprint of the one that made it", m["d"].Mesh.Streams()[0] is { Name: "Cafe scene", ChunkID: "room", Source: "s" } info && info.Fingerprint == source);
            Check("a device in another chunk doesn't keep it", m["e"].Mesh.Streams().Count == 0);

            byte[] frame = Bytes(40_000, 1);
            int took = await stream.Send(frame, Cogitarium.Full);
            Check("the source only has to send to the devices it's connected to", took == 1);
            Check("the piece reaches every device in the chunk, even the ones the source isn't connected to", await Eventually(() => new[] { "a", "b", "c", "d" }.All(x => m[x].Count >= 1), 8000));
            await Task.Delay(500);
            Check("...exactly once each, however many ways there were to get it", new[] { "a", "b", "c", "d" }.All(x => m[x].Count == 1));
            Check("...with the data unchanged, and it says who handed it over", m["d"].Got.Single().Data.SequenceEqual(frame) && m["d"].Got.Single().Level == Cogitarium.Full && m["a"].Got.Single().From == "s");
            Check("the source doesn't get its own stream back, and a device in another chunk gets nothing", m["s"].Count == 0 && m["e"].Count == 0);
            Check("devices passed it on, not just received it", m["a"].Mesh.Forwarded > 0);

            await stream.Send(Bytes(10, 2), Cogitarium.Full);
            Check("the next piece has the next number", await Eventually(() => m["d"].Count == 2, 8000) && m["d"].Sequences.SequenceEqual(new long[] { 0, 1 }));

            // a recorded piece sent again is dropped, and the one that sent it isn't blamed
            Check("a spy in the mesh saw pieces go by", await Eventually(() => !spied.IsEmpty, 5000));
            byte[] recorded = spied.First();
            var again = await n["z"].SendCommandAsync("b", "sccn.segment", recorded);
            await Task.Delay(300);
            Check("a piece sent again is dropped (repeat), not counted twice", again.IsOk && m["b"].Count == 2 && !m["b"].Mesh.IsDistrusted("z"));

            // leaving
            m["b"].Mesh.LeaveChunk("room");
            await stream.Send(Bytes(10, 3), Cogitarium.Full);
            Check("a device that left the chunk gets nothing and forgets the stream", await Eventually(() => m["d"].Count == 3, 8000) && m["b"].Count == 2 && m["b"].Mesh.Streams().Count == 0);

            stream.Stop();
            Check("a stopped stream can't send", await Throws2<InvalidOperationException>(() => stream.Send(Bytes(10, 4), Cogitarium.Full)));
        }
        finally { foreach (var l in m.Values) l.Mesh.Dispose(); foreach (var node in n.Values) node.Dispose(); }
    }

    // ---- only sources you accepted ----
    private static async Task CogitariumNotAccepted()
    {
        using var bus = new LocalBroker();
        var (n, _) = await Group(bus, new[] { "s", "x", "y", "z" }, new[] { ("s", "x"), ("x", "y"), ("z", "x") });
        var m = MakeMeshes(n, "s", "x", "y", "z");
        try
        {
            foreach (var name in new[] { "s", "x", "y", "z" }) m[name].Mesh.JoinChunk("room");
            m["y"].Mesh.AcceptSource(m["s"].Mesh.MyFingerprint);     // x doesn't accept it, so it won't pass it on
            Check("(setup) the devices see each other", await Eventually(() => m["s"].Mesh.Neighbors("room").Count == 1 && m["x"].Mesh.Neighbors("room").Count == 3, 8000));

            var stream = m["s"].Mesh.StartStream("room", "Mine");
            var stranger = m["z"].Mesh.StartStream("room", "Not accepted by anyone");
            await Task.Delay(500);
            Check("a device that didn't accept the source doesn't keep or pass on its stream", m["x"].Mesh.Streams().Count == 0 && m["y"].Mesh.Streams().Count == 0);

            int took = await stream.Send(Bytes(100, 5), Cogitarium.Full);
            await stranger.Send(Bytes(100, 6), Cogitarium.Full);
            await Task.Delay(500);
            Check("...and nothing reaches the device behind it", took == 1 && m["x"].Count == 0 && m["y"].Count == 0);

            m["x"].Mesh.AcceptSource(m["s"].Mesh.MyFingerprint);
            Check("once it accepts the source it hears about the stream (a neighbor tells it again)", await Eventually(() => m["x"].Mesh.Streams().Count == 1, 8000));
            await Eventually(() => m["y"].Mesh.Streams().Count == 1, 8000);      // the one behind it has to know the stream before a piece comes
            await stream.Send(Bytes(100, 7), Cogitarium.Full);
            Check("...and now passes it on", await Eventually(() => m["y"].Count == 1 && m["x"].Count == 1, 8000));
            Check("a source nobody accepted still never shows up", m["y"].Mesh.Streams().All(s => s.Name == "Mine") && m["x"].Mesh.Streams().All(s => s.Name == "Mine"));

            m["y"].Mesh.RejectSource(m["s"].Mesh.MyFingerprint);
            await stream.Send(Bytes(100, 8), Cogitarium.Full);
            await Task.Delay(500);
            Check("a source can be rejected again", m["y"].Count == 1 && m["y"].Mesh.Streams().Count == 0);
        }
        finally { foreach (var l in m.Values) l.Mesh.Dispose(); foreach (var node in n.Values) node.Dispose(); }
    }

    // ---- the sizes a device wants ----
    private static async Task CogitariumSizes()
    {
        using var bus = new LocalBroker();
        var (n, _) = await Group(bus, new[] { "s", "a", "p", "q" }, new[] { ("s", "a"), ("a", "p"), ("a", "q") });
        var m = MakeMeshes(n, "s", "a", "p", "q");
        try
        {
            foreach (var name in new[] { "s", "a", "p", "q" }) m[name].Mesh.JoinChunk("far");
            foreach (var name in new[] { "a", "p", "q" }) m[name].Mesh.AcceptSource(m["s"].Mesh.MyFingerprint);
            m["p"].Mesh.Want("far", new[] { Cogitarium.Quarter, Cogitarium.Sixteenth });          // far away: small is enough
            Check("(setup) a neighbor's wanted sizes are known", await Eventually(() => m["a"].Mesh.Neighbors("far").Any(x => x.Device == "p" && x.Levels.SequenceEqual(new[] { 3, 4 })), 8000));

            var stream = m["s"].Mesh.StartStream("far", "Park");
            Check("(setup) everyone knows the stream", await Eventually(() => m["p"].Mesh.Streams().Count == 1 && m["q"].Mesh.Streams().Count == 1, 8000));

            foreach (var level in new[] { Cogitarium.Full, Cogitarium.Half, Cogitarium.Quarter, Cogitarium.Sixteenth })
                await stream.Send(Bytes(100, 10 + level), level);

            Check("a device that wants everything gets every size", await Eventually(() => m["q"].Count == 4, 8000) && m["q"].Got.Select(g => g.Level).OrderBy(l => l).SequenceEqual(new[] { 0, 2, 3, 4 }));
            Check("a device that only wants small sizes isn't sent the big ones", await Eventually(() => m["p"].Count == 2, 8000) && m["p"].Got.Select(g => g.Level).OrderBy(l => l).SequenceEqual(new[] { 3, 4 }));
            Check("a size that isn't one of the five is refused", await Throws2<ArgumentOutOfRangeException>(() => stream.Send(Bytes(10, 1), 5)) && Catch(() => m["p"].Mesh.Want("far", new[] { 7 })) is ArgumentOutOfRangeException);
        }
        finally { foreach (var l in m.Values) l.Mesh.Dispose(); foreach (var node in n.Values) node.Dispose(); }
    }

    // ---- who it is sent to: the strongest connections, a few at a time ----
    private static Cogitarium.DeviceStatus Status(double wifi = 90, double usage = 10, double battery = 90, double size = 5000) =>
        new() { WifiStrength = wifi, WifiUsage = usage, BatteryPercent = battery, BatteryCapacity = size };

    // ---- who gets pieces first: a rank out of what each device says about itself, and the source goes down the list ----
    private static async Task CogitariumRank()
    {
        double ww = Cogitarium.WifiWeight, uw = Cogitarium.UsageWeight, bw = Cogitarium.BatteryWeight, cw = Cogitarium.CapacityWeight, pen = Cogitarium.DistrustPenalty;
        try
        {
            // the number
            Check("a device that said nothing is in the middle", Cogitarium.Rank(null, 0) == 50);
            Check("a healthy device ranks high and a poor one low", Cogitarium.Rank(Status(), 0) > 85 && Cogitarium.Rank(Status(10, 90, 10, 1000), 0) < 25);
            Check("a weaker signal ranks lower", Cogitarium.Rank(Status(wifi: 40), 0) < Cogitarium.Rank(Status(wifi: 80), 0));
            Check("busier wifi ranks lower", Cogitarium.Rank(Status(usage: 80), 0) < Cogitarium.Rank(Status(usage: 20), 0));
            Check("less battery ranks lower", Cogitarium.Rank(Status(battery: 20), 0) < Cogitarium.Rank(Status(battery: 80), 0));
            Check("a smaller battery ranks lower, and a bigger one than FullCapacity gets no extra", Cogitarium.Rank(Status(size: 2000), 0) < Cogitarium.Rank(Status(size: 5000), 0) && Cogitarium.Rank(Status(size: 5000), 0) == Cogitarium.Rank(Status(size: 20000), 0));
            Check("every distrust takes points off, never below 0", Cogitarium.Rank(Status(), 1) == Cogitarium.Rank(Status(), 0) - Cogitarium.DistrustPenalty && Cogitarium.Rank(Status(), 9) == 0);
            Cogitarium.WifiWeight = Cogitarium.UsageWeight = Cogitarium.BatteryWeight = Cogitarium.CapacityWeight = 0;
            Check("with every weight at zero nothing divides by zero", Cogitarium.Rank(Status(), 0) == 50);
            Cogitarium.WifiWeight = 1; Cogitarium.UsageWeight = Cogitarium.BatteryWeight = Cogitarium.CapacityWeight = 0;
            Check("the weights decide what counts", Cogitarium.Rank(Status(wifi: 70, battery: 5), 0) == 70);
        }
        finally { Cogitarium.WifiWeight = ww; Cogitarium.UsageWeight = uw; Cogitarium.BatteryWeight = bw; Cogitarium.CapacityWeight = cw; Cogitarium.DistrustPenalty = pen; }

        // the mesh
        int initial = Cogitarium.InitialReceivers;
        using var bus = new LocalBroker();
        var rs = new[] { "r1", "r2", "r3", "r4", "r5" };
        var (n, _) = await Group(bus, new[] { "src", "spy" }.Concat(rs).ToArray(), rs.Concat(new[] { "spy" }).Select(r => ("src", r)).ToArray());
        var m = MakeMeshes(n, new[] { "src" }.Concat(rs).ToArray());
        int spyGot = 0;
        n["spy"].On("sccn.hello", (c, _) => Task.FromResult(CommandResult.Ok()));
        n["spy"].On("sccn.announce", (c, _) => Task.FromResult(CommandResult.Ok()));
        n["spy"].On("sccn.segment", (c, _) => { Interlocked.Increment(ref spyGot); return Task.FromResult(CommandResult.Error("no")); });
        try
        {
            Check("(setup) a device has no status until it sets one", m["r1"].Mesh.MyStatus is null);
            foreach (var name in m.Keys) m[name].Mesh.JoinChunk("hall");
            foreach (var r in rs) m[r].Mesh.AcceptSource(m["src"].Mesh.MyFingerprint);
            Check("(setup) the source sees its neighbors", await Eventually(() => m["src"].Mesh.Neighbors("hall").Count == 5, 8000));
            var stream = m["src"].Mesh.StartStream("hall", "Hall");
            Check("(setup) they know the stream", await Eventually(() => rs.All(r => m[r].Mesh.Streams().Count == 1), 8000));

            // r3 is the healthiest, r1 the poorest, and r1 is also the quickest to answer (so speed alone would pick it)
            m["r1"].Mesh.SetStatus(Status(40, 60, 30, 3000));
            m["r2"].Mesh.SetStatus(Status(60, 40, 60, 4000));
            m["r3"].Mesh.SetStatus(Status(95, 5, 95, 5000));
            m["r4"].Mesh.SetStatus(Status(75, 25, 70, 4000));
            m["r5"].Mesh.SetStatus(Status(85, 15, 85, 5000));
            Check("what a device says about itself reaches its neighbors", await Eventually(() => m["src"].Mesh.Neighbors("hall").All(x => x.Status is not null), 8000));
            Check("...as the numbers it said", m["src"].Mesh.Neighbors("hall").Single(x => x.Device == "r3").Status is { WifiStrength: 95, WifiUsage: 5, BatteryPercent: 95, BatteryCapacity: 5000 });
            foreach (var r in rs) m["src"].Mesh.SetScore(r, 900);
            m["src"].Mesh.SetScore("r1", 5); m["src"].Mesh.SetScore("r2", 10);
            Check("neighbors are listed from the best rank to the worst, not the quickest", m["src"].Mesh.Neighbors("hall").Select(x => x.Device).SequenceEqual(new[] { "r3", "r5", "r4", "r2", "r1" }));
            Check("...each with its rank", m["src"].Mesh.Neighbors("hall").Select(x => x.Rank).SequenceEqual(m["src"].Mesh.Neighbors("hall").Select(x => x.Rank).OrderByDescending(x => x)) && m["src"].Mesh.Neighbors("hall")[0].Rank > 90);

            Cogitarium.InitialReceivers = 2;
            int took = await stream.Send(Bytes(100, 40), Cogitarium.Full);
            await Task.Delay(500);
            Check("the source sends to the best ranked, even though others answer faster", took == 2 && m["r3"].Count == 1 && m["r5"].Count == 1 && m["r1"].Count + m["r2"].Count + m["r4"].Count == 0);

            // two different neighbors distrust r3: it falls (They are not enough to throw it out, VotesToDistrust is 3)
            m["src"].Mesh.AddVote("r3", "x1"); m["src"].Mesh.AddVote("r3", "x2"); m["src"].Mesh.AddVote("r3", "x1");
            var r3 = m["src"].Mesh.Neighbors("hall").Single(x => x.Device == "r3");
            Check("every different neighbor that distrusts a device counts once, and takes points off its rank", r3.Distrusts == 2 && !r3.Distrusted && r3.Rank < Cogitarium.Rank(Status(95, 5, 95, 5000), 0) - 50);
            took = await stream.Send(Bytes(100, 41), Cogitarium.Full);
            await Task.Delay(500);
            Check("...so the pieces go to the next best", took == 2 && m["r5"].Count == 2 && m["r4"].Count == 1 && m["r3"].Count == 1);

            // the best ranked device refuses: the next one down takes its place
            await SayHello(n["spy"], "src", "hall");
            await n["spy"].SendCommandAsync("src", "sccn.status", Encoding.UTF8.GetBytes(new JsonObject { ["w"] = 100, ["u"] = 0, ["b"] = 100, ["c"] = 5000 }.ToJsonString()));
            Check("(setup) the source ranks the spy first", await Eventually(() => m["src"].Mesh.Neighbors("hall").First().Device == "spy", 5000));
            took = await stream.Send(Bytes(100, 42), Cogitarium.Full);
            await Task.Delay(500);
            Check("a device that doesn't take the piece is skipped and the source goes further down until it has enough", spyGot >= 1 && took == 2 && m["r5"].Count == 3 && m["r4"].Count == 2);

            // what a device says is believed only within reason
            var spyStatus = () => m["src"].Mesh.Neighbors("hall").First(x => x.Device == "spy").Status!;
            async Task<bool> Refused(string body) => !(await n["spy"].SendCommandAsync("src", "sccn.status", Encoding.UTF8.GetBytes(body))).IsOk;
            Check("a status out of range is refused", await Refused("{\"w\":150,\"u\":0,\"b\":100,\"c\":5000}") && await Refused("{\"w\":-1,\"u\":0,\"b\":100,\"c\":5000}") && await Refused("{\"w\":50,\"u\":0,\"b\":100,\"c\":99999999}"));
            Check("a status with a part missing, of the wrong type, or not JSON is refused", await Refused("{\"w\":50}") && await Refused("{\"w\":\"high\",\"u\":0,\"b\":1,\"c\":1}") && await Refused("nope") && await Refused("[]"));
            Check("...and the last good status stays", spyStatus() is { WifiStrength: 100, BatteryPercent: 100 });

            // setting our own
            Check("a device can't set a status that is out of range", Catch(() => m["r1"].Mesh.SetStatus(Status(wifi: 101))) is ArgumentOutOfRangeException && Catch(() => m["r1"].Mesh.SetStatus(Status(battery: double.NaN))) is ArgumentOutOfRangeException);
            Check("...and its old one stays", m["r1"].Mesh.MyStatus is { WifiStrength: 40 });

            // a distrusted device is not listened to
            m["src"].Mesh.Distrust("r1", "test");
            m["r1"].Mesh.SetStatus(Status(100, 0, 100, 5000));
            await Task.Delay(500);
            Check("a distrusted device can't change its rank by talking", m["src"].Mesh.Neighbors("hall").Single(x => x.Device == "r1").Status is { WifiStrength: 40 });
        }
        finally { Cogitarium.InitialReceivers = initial; foreach (var l in m.Values) l.Mesh.Dispose(); foreach (var node in n.Values) node.Dispose(); }
    }

    private static async Task CogitariumBestConnections()
    {
        using var bus = new LocalBroker();
        var leaves = new[] { "l1", "l2", "l3", "l4", "l5", "l6" };
        var (n, _) = await Group(bus, new[] { "s", "h" }.Concat(leaves).ToArray(), new[] { ("s", "h") }.Concat(leaves.Select(l => ("h", l))).ToArray());
        var m = MakeMeshes(n, new[] { "s", "h" }.Concat(leaves).ToArray());
        try
        {
            foreach (var name in m.Keys) m[name].Mesh.JoinChunk("hall");
            foreach (var name in m.Keys.Where(k => k != "s")) m[name].Mesh.AcceptSource(m["s"].Mesh.MyFingerprint);
            Check("(setup) the hub knows all its neighbors", await Eventually(() => m["h"].Mesh.Neighbors("hall").Count == 7 && m["s"].Mesh.Neighbors("hall").Count == 1, 8000));

            var stream = m["s"].Mesh.StartStream("hall", "Hall");
            Check("(setup) the stream is known everywhere", await Eventually(() => leaves.All(l => m[l].Mesh.Streams().Count == 1), 8000));

            Cogitarium.Fanout = 2;
            foreach (var l in leaves) m["h"].Mesh.SetScore(l, 500);
            m["h"].Mesh.SetScore("l3", 10); m["h"].Mesh.SetScore("l5", 20);
            await stream.Send(Bytes(100, 20), Cogitarium.Full);
            await Task.Delay(800);
            Check("a device passes a piece on to its best few connections only", leaves.Count(l => m[l].Count > 0) == 2 && m["l3"].Count == 1 && m["l5"].Count == 1);
            Check("...and the best ones are the ones that answer fastest", m["h"].Mesh.Neighbors("hall").Take(2).Select(x => x.Device).OrderBy(x => x).SequenceEqual(new[] { "l3", "l5" }));

            // the source itself: it sends to InitialReceivers, then the next best when one is distrusted
            using var bus2 = new LocalBroker();
            var rs = new[] { "r1", "r2", "r3", "r4" };
            var (n2, _) = await Group(bus2, new[] { "src" }.Concat(rs).ToArray(), rs.Select(r => ("src", r)).ToArray());
            var m2 = MakeMeshes(n2, new[] { "src" }.Concat(rs).ToArray());
            try
            {
                foreach (var name in m2.Keys) m2[name].Mesh.JoinChunk("hall");
                foreach (var r in rs) m2[r].Mesh.AcceptSource(m2["src"].Mesh.MyFingerprint);
                Check("(setup) the source sees its neighbors", await Eventually(() => m2["src"].Mesh.Neighbors("hall").Count == 4, 8000));
                var s2 = m2["src"].Mesh.StartStream("hall", "Src");
                Check("(setup) they know the stream", await Eventually(() => rs.All(r => m2[r].Mesh.Streams().Count == 1), 8000));

                Cogitarium.InitialReceivers = 2; Cogitarium.Fanout = 3;
                foreach (var r in rs) m2["src"].Mesh.SetScore(r, 300);
                m2["src"].Mesh.SetScore("r2", 5); m2["src"].Mesh.SetScore("r4", 9);
                int took = await s2.Send(Bytes(100, 30), Cogitarium.Full);
                await Task.Delay(500);
                Check("the source sends to the best few it's connected to", took == 2 && m2["r2"].Count == 1 && m2["r4"].Count == 1 && m2["r1"].Count == 0 && m2["r3"].Count == 0);

                m2["src"].Mesh.Distrust("r2", "test");
                took = await s2.Send(Bytes(100, 31), Cogitarium.Full);
                await Task.Delay(500);
                Check("a distrusted device is skipped and the next best takes its place", took == 2 && m2["r2"].Count == 1 && m2["r4"].Count == 2 && m2["r1"].Count + m2["r3"].Count == 1);

                m2["src"].Mesh.Forgive("r2");
                m2["src"].Mesh.SetScore("r2", 1);      // real answers moved the scores while the test ran
                Check("a device can be forgiven and is used again", !m2["src"].Mesh.IsDistrusted("r2") && m2["src"].Mesh.Neighbors("hall").First().Device == "r2");
            }
            finally { foreach (var l in m2.Values) l.Mesh.Dispose(); foreach (var node in n2.Values) node.Dispose(); }
        }
        finally { foreach (var l in m.Values) l.Mesh.Dispose(); foreach (var node in n.Values) node.Dispose(); }
    }

    // ---- a device that changes a piece ----
    private static async Task CogitariumTampering()
    {
        Cogitarium.VotesToDistrust = 3; Cogitarium.Fanout = 3; Cogitarium.InitialReceivers = 10;

        using var bus = new LocalBroker();
        var vs = new[] { "v1", "v2", "v3", "v4" };
        // m is the middleman between the source and v1, v3 and v4. v2 isn't connected to it, only to the three that are.
        var (n, _) = await Group(bus, new[] { "s", "m" }.Concat(vs).ToArray(),
            new[] { ("s", "m"), ("m", "v1"), ("m", "v3"), ("m", "v4"), ("v1", "v2"), ("v3", "v2"), ("v4", "v2") });
        var l = MakeMeshes(n, new[] { "s" }.Concat(vs).ToArray());
        string mode = "off"; string[] targets = Array.Empty<string>();
        var forwarded = new ConcurrentQueue<string>();
        n["m"].On("sccn.hello", (c, _) => Task.FromResult(CommandResult.Ok()));
        n["m"].On("sccn.announce", (c, ct) =>
        {
            foreach (var v in vs.Where(v => v != "v2")) _ = n["m"].SendCommandAsync(v, "sccn.announce", c.Payload);
            return Task.FromResult(CommandResult.Ok());
        });
        n["m"].On("sccn.segment", (c, ct) =>
        {
            // what the middleman does to a piece: nothing (honest) or changes the last byte, then hands it to the ones it's told to
            var bytes = c.Payload.ToArray();
            if (mode == "tamper") bytes[^1] ^= 0xFF;
            foreach (var v in targets) { forwarded.Enqueue(v); _ = n["m"].SendCommandAsync(v, "sccn.segment", bytes); }
            return Task.FromResult(CommandResult.Ok());
        });
        try
        {
            foreach (var name in l.Keys) l[name].Mesh.JoinChunk("room");
            foreach (var v in vs) l[v].Mesh.AcceptSource(l["s"].Mesh.MyFingerprint);
            foreach (var v in vs.Where(v => v != "v2")) await SayHello(n["m"], v, "room");
            await SayHello(n["m"], "s", "room");

            Check("(setup) the source sees the middleman and the devices see each other", await Eventually(() => l["s"].Mesh.Neighbors("room").Count == 1 && l["v2"].Mesh.Neighbors("room").Count == 3, 8000));
            var stream = l["s"].Mesh.StartStream("room", "Cafe");
            Check("(setup) every device knows the stream", await Eventually(() => vs.All(v => l[v].Mesh.Streams().Count == 1), 8000));

            // honest first: the middleman passes it on untouched
            mode = "honest"; targets = new[] { "v1" };
            await stream.Send(Bytes(500, 40), Cogitarium.Full);
            Check("a piece the middleman passes on untouched is accepted", await Eventually(() => l["v1"].Count == 1, 8000) && !l["v1"].Mesh.IsDistrusted("m"));

            // one device sees it change a piece: that's one accusation, not enough for the others yet
            mode = "tamper"; targets = new[] { "v1" };
            await stream.Send(Bytes(500, 41), Cogitarium.Full);
            Check("a piece that was changed is refused", await Eventually(() => l["v1"].Mesh.IsDistrusted("m") && l["v1"].Mesh.Rejected == 1, 8000));
            await Task.Delay(800);
            Check("one neighbor saying so isn't enough for the others", !l["v2"].Mesh.IsDistrusted("m") && !l["v3"].Mesh.IsDistrusted("m"));

            // two more see the same, and now a device that never saw it happen believes them
            targets = new[] { "v3", "v4" };
            await stream.Send(Bytes(500, 42), Cogitarium.Full);
            Check("each device that saw a changed piece distrusts the one that handed it over", await Eventually(() => l["v3"].Mesh.IsDistrusted("m") && l["v4"].Mesh.IsDistrusted("m"), 8000));
            Check("a device that was never handed a changed piece believes enough different neighbors", await Eventually(() => l["v2"].Mesh.IsDistrusted("m"), 8000) && l["v2"].Mesh.Rejected == 0);
            Check("nothing that was changed ever reached a screen (pieces 1 and 2 were changed on the way)", l.Values.All(x => !x.Sequences.Contains(1) && !x.Sequences.Contains(2)));
            Check("...and what did arrive is exactly what the source sent", l.Values.All(x => x.Got.All(p => p.Data.SequenceEqual(Bytes(500, 40 + (int)p.Sequence)))));
            Check("the mesh went round the device that lied: the good piece reached the others through each other", await Eventually(() => new[] { "v1", "v2", "v3", "v4" }.All(v => l[v].Sequences.Contains(0)), 8000));

            // a distrusted device is ignored from then on, even when it behaves
            mode = "honest"; targets = new[] { "v1", "v3" };
            await stream.Send(Bytes(500, 43), Cogitarium.Full);
            await Task.Delay(800);
            Check("a distrusted device's pieces are ignored even if they're fine", l.Values.All(x => !x.Sequences.Contains(3)));
            Check("the devices that know about it can say who", l["v2"].Mesh.DistrustedDevices().SequenceEqual(new[] { "m" }) && !l["v2"].Mesh.IsDistrusted("v1"));

            // accusations only count when they are about a stream we know, from different neighbors, and never about ourselves
            var fresh = await n["v1"].SendCommandAsync("v2", "sccn.warn", Encoding.UTF8.GetBytes("{\"who\":\"v3\",\"stream\":\"0000000000000000\",\"why\":\"x\"}"));
            var self = await n["v1"].SendCommandAsync("v2", "sccn.warn", Encoding.UTF8.GetBytes("{\"who\":\"v2\",\"stream\":\"" + stream.Info.ID + "\",\"why\":\"x\"}"));
            var sameVoter = new[] { 1, 2, 3, 4 }.Select(_ => n["v1"].SendCommandAsync("v2", "sccn.warn", Encoding.UTF8.GetBytes("{\"who\":\"v4\",\"stream\":\"" + stream.Info.ID + "\",\"why\":\"x\"}"))).ToArray();
            await Task.WhenAll(sameVoter);
            Check("an accusation about a stream we don't know, or about ourselves, counts for nothing", fresh.IsOk && self.Status == AckStatus.Error && !l["v2"].Mesh.IsDistrusted("v3"));
            Check("the same device accusing again and again is still one vote", !l["v2"].Mesh.IsDistrusted("v4"));

            l["v2"].Mesh.Forgive("m");
            Check("a distrusted device can be forgiven", !l["v2"].Mesh.IsDistrusted("m") && l["v2"].Mesh.DistrustedDevices().Count == 0);
        }
        finally { foreach (var x in l.Values) x.Mesh.Dispose(); foreach (var node in n.Values) node.Dispose(); }
    }

    // ---- input that makes no sense never breaks anything and never gets anyone blamed ----
    private static async Task CogitariumBadInput()
    {
        using var bus = new LocalBroker();
        var (n, _) = await Group(bus, new[] { "s", "a", "raw" }, new[] { ("s", "a"), ("raw", "a") });
        var m = MakeMeshes(n, "s", "a");
        try
        {
            foreach (var name in m.Keys) m[name].Mesh.JoinChunk("room");
            m["a"].Mesh.AcceptSource(m["s"].Mesh.MyFingerprint);
            await Eventually(() => m["s"].Mesh.Neighbors("room").Count == 1, 5000);
            var stream = m["s"].Mesh.StartStream("room", "Cafe");
            await Eventually(() => m["a"].Mesh.Streams().Count == 1, 5000);

            Check("a piece bigger than the limit isn't sent", await Throws2<ArgumentException>(() => stream.Send(new byte[Cogitarium.MaxSegmentBytes + 1], Cogitarium.Full)));
            Check("an empty piece isn't sent", await Throws2<ArgumentException>(() => stream.Send(Array.Empty<byte>(), Cogitarium.Full)));

            var junk = await n["raw"].SendCommandAsync("a", "sccn.segment", Encoding.UTF8.GetBytes("not a frame"));
            var noHeader = await n["raw"].SendCommandAsync("a", "sccn.segment", new byte[] { 0, 0, 0, 0 });
            var badHello = await n["raw"].SendCommandAsync("a", "sccn.hello", Encoding.UTF8.GetBytes("{\"c\":{\"has space\":31}}"));
            var badMask = await n["raw"].SendCommandAsync("a", "sccn.hello", Encoding.UTF8.GetBytes("{\"c\":{\"room\":99}}"));
            var badAnnounce = await n["raw"].SendCommandAsync("a", "sccn.announce", Encoding.UTF8.GetBytes("{\"id\":\"x\"}"));
            var badWarn = await n["raw"].SendCommandAsync("a", "sccn.warn", Encoding.UTF8.GetBytes("nope"));
            Check("frames, hellos, announcements and warnings that make no sense are refused", junk.Status == AckStatus.Error && noHeader.Status == AckStatus.Error && badHello.Status == AckStatus.Error && badMask.Status == AckStatus.Error && badAnnounce.Status == AckStatus.Error && badWarn.Status == AckStatus.Error);

            var header = new JsonObject { ["id"] = stream.Info.ID, ["seq"] = 0, ["lv"] = 0, ["h"] = 0, ["sig"] = Convert.ToBase64String(new byte[10]) };
            var tooBig = await n["raw"].SendCommandAsync("a", "sccn.segment", Cogitarium.Mesh.Frame(header, new byte[Cogitarium.MaxSegmentBytes + 1]));
            var unknown = await n["raw"].SendCommandAsync("a", "sccn.segment", Cogitarium.Mesh.Frame(new JsonObject { ["id"] = "ffffffffffffffff", ["seq"] = 0, ["lv"] = 0, ["h"] = 0, ["sig"] = "AAAA" }, new byte[10]));
            Check("a piece that's too big, or for a stream nobody knows, is refused or ignored", tooBig.Status == AckStatus.Error && unknown.IsOk);
            Check("none of that gets the sender distrusted (it isn't tampering)", !m["a"].Mesh.IsDistrusted("raw") && m["a"].Count == 0);

            // a piece with the right shape but not signed by the source IS tampering
            var forged = await n["raw"].SendCommandAsync("a", "sccn.segment", Cogitarium.Mesh.Frame(header, new byte[100]));
            Check("a piece that claims to be from the source but isn't signed by it gets the sender distrusted", forged.Status == AckStatus.Error && m["a"].Mesh.IsDistrusted("raw"));

            Check("a chunk name that isn't a name is refused", Catch(() => m["a"].Mesh.JoinChunk("two words")) is ArgumentException && Catch(() => m["a"].Mesh.JoinChunk(new string('x', 65))) is ArgumentException);
            Check("a stream can't start in a chunk this device didn't join", await Task.FromResult(Catch(() => m["a"].Mesh.StartStream("other", "x")) is InvalidOperationException));
        }
        finally { foreach (var l in m.Values) l.Mesh.Dispose(); foreach (var node in n.Values) node.Dispose(); }
    }
}
