using System.Collections.Concurrent;
using System.Text;
using System.Text.Json.Nodes;
using YuukoProtocol;
using YuukoProtocol.Dogma;

namespace YuukoSandbox;

// Tests for finding strangers (Nearby): devices that know nothing about each other find each other and take part in a mesh, and what a stranger is and isn't allowed to do.
public static partial class SelfTest
{
    private static readonly TimeSpan FastBeacon = TimeSpan.FromMilliseconds(150);

    private static async Task<List<Nearby.Presence>> Strangers(IYuukoApi bus, int count)
    {
        // Every identity first: making keys while other nodes are already shaking hands fails
        var ids = Enumerable.Range(0, count).Select(_ => YuukoIdentity.Create(Nearby.NewID())).ToList();
        var all = new List<Nearby.Presence>();
        foreach (var id in ids) all.Add(await Nearby.Presence.Create(bus, id, FastBeacon));
        return all;
    }

    private static async Task NearbyTests()
    {
        Section("nearby (strangers)");

        int max = Nearby.MaxNeighbors;
        try
        {
            await NearbyFind();
            await NearbyStream();
            await NearbyLimits();
            await NearbyBadBeacons();
            await NearbyOffers();
            await NearbyCards();
            await NearbyStart();
            await NearbyStatic();
            await NearbyRealZenoh();
        }
        finally { Nearby.MaxNeighbors = max; }
    }

    // ---- devices that never met find each other, and end up in the same mesh ----
    private static async Task NearbyFind()
    {
        using var bus = new LocalBroker();
        var p = await Strangers(bus, 4);
        try
        {
            Check("devices with no group key, no device list and no certificate find each other", await Eventually(() => p.All(x => x.Node.ConnectedPeers.Count == 3), 15000));
            Check("every device announces a random ID, not a name", p.All(x => x.Node.ClientId.StartsWith("near-") && x.Node.ClientId.Length == 21) && p.Select(x => x.Node.ClientId).Distinct().Count() == 4);
        }
        finally { foreach (var x in p) x.Dispose(); }
    }

    // ---- Cogitarium over the nearby nodes: a stream from a stranger reaches the others, only if they accepted the source ----
    private static async Task NearbyStream()
    {
        using var bus = new LocalBroker();
        var p = await Strangers(bus, 4);
        var m = p.Select(x => new Cogitarium.Mesh(x.Node)).ToList();
        var got = m.Select(_ => new ConcurrentQueue<Cogitarium.Segment>()).ToList();
        for (int i = 0; i < m.Count; i++) { var q = got[i]; m[i].SegmentReceived += (info, piece) => q.Enqueue(piece); }
        try
        {
            await Eventually(() => p.All(x => x.Node.ConnectedPeers.Count == 3), 15000);
            foreach (var x in m) x.JoinChunk("plaza");

            // m[0] is the source, m[1] and m[2] accepted it, m[3] didn't
            string source = m[0].MyFingerprint;
            m[1].AcceptSource(source); m[2].AcceptSource(source);
            Check("strangers learn who is in the chunk", await Eventually(() => m.All(x => x.Neighbors("plaza").Count == 3), 8000));

            var stream = m[0].StartStream("plaza", "Fountain");
            Check("the stream is found by the devices that accepted the source", await Eventually(() => m[1].Streams().Count == 1 && m[2].Streams().Count == 1, 8000));
            Check("a stranger that didn't accept the source doesn't keep the stream", m[3].Streams().Count == 0);

            byte[] frame = Bytes(30_000, 9);
            await stream.Send(frame, Cogitarium.Full);
            Check("the piece reaches the devices that accepted the source, unchanged", await Eventually(() => got[1].Count == 1 && got[2].Count == 1, 8000) && got[1].Single().Data.SequenceEqual(frame) && got[2].Single().Data.SequenceEqual(frame));
            await Task.Delay(300);
            Check("...and nobody else shows it", got[3].IsEmpty && got[0].IsEmpty);
        }
        finally { foreach (var x in m) x.Dispose(); foreach (var x in p) x.Dispose(); }
    }

    // ---- what a stranger is allowed to ask this node ----
    private static async Task NearbyLimits()
    {
        using var bus = new LocalBroker();
        var p = await Strangers(bus, 3);
        var m = p.Select(x => new Cogitarium.Mesh(x.Node)).ToList();
        int max = Nearby.MaxNeighbors;
        try
        {
            await Eventually(() => p.All(x => x.Node.ConnectedPeers.Count == 2), 15000);
            string other = p[1].Node.ClientId;
            p[1].Node.On("secret.thing", (c, _) => Task.FromResult(CommandResult.Ok()));

            Check("a stranger can ping (Presence)", (await p[0].Node.PingAsync(other)).IsOk);
            Check("a stranger can't run anything but stream commands", (await p[0].Node.SendCommandAsync(other, "secret.thing")).Status == AckStatus.Denied);
            Check("...nor a command of the private group's kind", (await p[0].Node.SendCommandAsync(other, "holy.apps")).Status == AckStatus.Denied && (await p[0].Node.SendCommandAsync(other, "dag.manifest")).Status == AckStatus.Denied);

            // a piece bigger than the limit never gets to a handler
            bool big = false;
            try { var r = await p[0].Node.SendCommandAsync(other, "sccn.segment", new byte[Cogitarium.MaxSegmentBytes + 200 * 1024]); big = !r.IsOk; } catch (ArgumentException) { big = true; }
            Check("something far bigger than a piece is refused", big);
        }
        finally { foreach (var x in m) x.Dispose(); foreach (var x in p) x.Dispose(); }

        // the limit on how many neighbors
        using var crowd = new LocalBroker();
        Nearby.MaxNeighbors = 2;
        var c = await Strangers(crowd, 6);
        try
        {
            Check("a device doesn't stay connected to more than MaxNeighbors strangers", await Eventually(() => c.All(x => x.Node.ConnectedPeers.Count <= 2) && c.Any(x => x.Node.ConnectedPeers.Count == 2), 15000));
            await Task.Delay(1500);
            Check("...and it stays that way", c.All(x => x.Node.ConnectedPeers.Count <= 2));
        }
        finally { Nearby.MaxNeighbors = max; foreach (var x in c) x.Dispose(); }
    }

    // ---- an announcement that isn't one is ignored ----
    private static async Task NearbyBadBeacons()
    {
        using var bus = new LocalBroker();
        var p = (await Strangers(bus, 1))[0];
        try
        {
            async Task Say(byte[] data) => await bus.PublishAsync("yuuko/nearby/presence", YuukoPacket.Ephemeral("beacon", data));
            string high = "near-" + new string('f', 16);

            await Say(Encoding.UTF8.GetBytes("not json at all"));
            await Say(Encoding.UTF8.GetBytes("{}"));
            await Say(Encoding.UTF8.GetBytes(new JsonObject { ["id"] = "pc" }.ToJsonString()));                          // a name, not a nearby ID
            await Say(Encoding.UTF8.GetBytes(new JsonObject { ["id"] = "near-" + new string('z', 16) }.ToJsonString()));   // not hex
            await Say(Encoding.UTF8.GetBytes(new JsonObject { ["id"] = "near-" + new string('f', 400) }.ToJsonString()));  // too long
            await Say(Encoding.UTF8.GetBytes(new JsonObject { ["id"] = p.Node.ClientId }.ToJsonString()));               // ourselves
            await Say(Encoding.UTF8.GetBytes(new JsonObject { ["id"] = 5 }.ToJsonString()));                              // wrong type
            await Task.Delay(500);
            Check("garbage, names, our own ID and wrong types are ignored without a connection attempt or a crash", p.Node.ConnectedPeers.Count == 0);

            // a good ID of nobody: we try to call it once and give up, the node still works
            await Say(Encoding.UTF8.GetBytes(new JsonObject { ["id"] = high }.ToJsonString()));
            await Task.Delay(300);
            Check("a good-looking ID that nobody answers to doesn't connect to anything", p.Node.ConnectedPeers.Count == 0);
        }
        finally { p.Dispose(); }
    }

    // ---- streetpass: a stream from a source we haven't accepted is only offered, until we choose ----
    private static async Task NearbyOffers()
    {
        using var bus = new LocalBroker();
        var p = await Strangers(bus, 4);
        var m = p.Select(x => new Cogitarium.Mesh(x.Node)).Take(3).ToList();     // p[3] is a spy that isn't running the mesh
        var got = m.Select(_ => new ConcurrentQueue<Cogitarium.Segment>()).ToList();
        var offered = new ConcurrentQueue<Cogitarium.StreamInfo>();
        var seen = new ConcurrentQueue<byte[]>();
        for (int i = 0; i < m.Count; i++) { var q = got[i]; m[i].SegmentReceived += (info, piece) => q.Enqueue(piece); }
        m[1].StreamOffered += info => offered.Enqueue(info);
        p[3].Node.On("sccn.hello", (c, _) => Task.FromResult(CommandResult.Ok()));
        p[3].Node.On("sccn.announce", (c, _) => { seen.Enqueue(c.Payload); return Task.FromResult(CommandResult.Ok()); });
        try
        {
            await Eventually(() => p.All(x => x.Node.ConnectedPeers.Count == 3), 15000);
            foreach (var x in m) x.JoinChunk("plaza");
            await SayHello(p[3].Node, p[0].Node.ClientId, "plaza");
            await SayHello(p[3].Node, p[2].Node.ClientId, "plaza");
            m[2].AcceptSource(m[0].MyFingerprint);

            var stream = m[0].StartStream("plaza", "Fountain");
            Check("a source we haven't accepted is offered to us, with its name and fingerprint", await Eventually(() => m[1].Offers().Count == 1, 8000) && m[1].Offers()[0] is { Name: "Fountain", ChunkID: "plaza" } o && o.Fingerprint == m[0].MyFingerprint);
            Check("...and we are told", await Eventually(() => offered.Count == 1, 3000));
            Check("an offer isn't a stream: nothing is kept or shown", m[1].Streams().Count == 0);
            Check("the device that accepted the source has the stream and no offer", await Eventually(() => m[2].Streams().Count == 1, 8000) && m[2].Offers().Count == 0);

            await stream.Send(Bytes(2000, 5), Cogitarium.Full);
            Check("pieces of an offered stream aren't used", await Eventually(() => got[2].Count == 1, 8000) && got[1].IsEmpty);

            // a spy in the chunk hears the announcement as well
            Check("a spy in the chunk heard the announcement", await Eventually(() => !seen.IsEmpty, 5000));

            // an offer must be signed by the source it says it is from
            var forged = JsonNode.Parse(Encoding.UTF8.GetString(seen.First()))!.AsObject();
            forged["name"] = "Free money";
            forged["id"] = "ffffffffffffffff";
            var sent = await p[3].Node.SendCommandAsync(p[1].Node.ClientId, "sccn.announce", Encoding.UTF8.GetBytes(forged.ToJsonString()));
            Check("an offer with a changed name or id is refused (bad signature), it isn't listed", !sent.IsOk && m[1].Offers().Count == 1);
            Check("garbage isn't listed either", !(await p[3].Node.SendCommandAsync(p[1].Node.ClientId, "sccn.announce", Encoding.UTF8.GetBytes("{\"id\":5}"))).IsOk && m[1].Offers().Count == 1);

            // choosing
            m[1].AcceptSource(offered.First().Fingerprint);
            Check("accepting an offer turns it into a stream at once", await Eventually(() => m[1].Streams().Count == 1 && m[1].Offers().Count == 0, 8000));
            // a live piece that is lost is not sent again, so the test sends the next one
            bool arrived = false;
            for (int i = 0; i < 3 && !arrived; i++) { await stream.Send(Bytes(2000, 6), Cogitarium.Full); arrived = await Eventually(() => got[1].Count >= 1, 4000); }
            Check("...and its pieces arrive from then on", arrived);

            // leaving the area forgets what was offered there
            m[2].RejectSource(m[0].MyFingerprint);
            m[2].LeaveChunk("plaza"); m[2].JoinChunk("plaza");
            Check("rejecting a source drops its stream", await Eventually(() => m[2].Streams().Count == 0, 5000));
            m[1].LeaveChunk("plaza");
            Check("leaving a chunk forgets its offers", m[1].Offers().Count == 0);
        }
        finally { foreach (var x in m) x.Dispose(); foreach (var x in p) x.Dispose(); }
    }

    // ---- streetpass: cards are swapped with everyone we connect to ----
    private static async Task NearbyCards()
    {
        using var bus = new LocalBroker();
        var p = await Strangers(bus, 2);
        var seenBy0 = new ConcurrentQueue<Nearby.Met>();
        p[0].Card = Encoding.UTF8.GetBytes("zero says hi"); p[1].Card = Encoding.UTF8.GetBytes("one says hi");
        p[0].Passed += x => seenBy0.Enqueue(x);
        try
        {
            Check("when two devices connect they swap cards", await Eventually(() => p[0].Met.Count == 1 && p[1].Met.Count == 1, 15000));
            var a = p[0].Met.Values.Single(); var b = p[1].Met.Values.Single();
            Check("...each holds the other's card and the fingerprint the handshake proved", Encoding.UTF8.GetString(a.Card) == "one says hi" && a.Fingerprint == p[1].Node.Fingerprint && Encoding.UTF8.GetString(b.Card) == "zero says hi" && b.Fingerprint == p[0].Node.Fingerprint);
            Check("...once, and the first meeting counts as one time", a.Times == 1 && seenBy0.Count == 1 && a.FirstMet <= a.LastMet);

            // the same device card again soon is the same meeting, much later it is another time
            string other = p[1].Node.ClientId;
            byte[] body = Encoding.UTF8.GetBytes(new JsonObject { ["card"] = Convert.ToBase64String(Encoding.UTF8.GetBytes("changed")) }.ToJsonString());
            await p[1].Node.SendCommandAsync(p[0].Node.ClientId, "sccn.card", body);
            Check("a card sent again soon updates the card but isn't a new meeting", Encoding.UTF8.GetString(a.Card) == "changed" && a.Times == 1 && seenBy0.Count == 1);
            a.LastMet = DateTime.UtcNow.AddMinutes(-30);
            await p[1].Node.SendCommandAsync(p[0].Node.ClientId, "sccn.card", body);
            Check("...and a card much later is another meeting", a.Times == 2 && seenBy0.Count == 2);

            // bad cards
            var big = new JsonObject { ["card"] = Convert.ToBase64String(new byte[Nearby.MaxCardBytes + 1]) }.ToJsonString();
            Check("a card that's too big is refused", !(await p[1].Node.SendCommandAsync(p[0].Node.ClientId, "sccn.card", Encoding.UTF8.GetBytes(big))).IsOk);
            Check("a card that isn't a card is refused", !(await p[1].Node.SendCommandAsync(p[0].Node.ClientId, "sccn.card", Encoding.UTF8.GetBytes("{\"card\":\"%%%\"}"))).IsOk && !(await p[1].Node.SendCommandAsync(p[0].Node.ClientId, "sccn.card", Encoding.UTF8.GetBytes("nope"))).IsOk);
            Check("...and nobody was added by it", p[0].Met.Count == 1);
            Check("a card is at most 1 KB when you set it", Catch(() => Nearby.MyCard = new byte[Nearby.MaxCardBytes + 1]) is ArgumentException && Catch(() => Nearby.MyCard = null!) is ArgumentException);
            Nearby.Forget("not a fingerprint");
        }
        finally { foreach (var x in p) x.Dispose(); }
    }

    // ---- starting on a link the app made, with a card set first, and an identity that stays ----
    private static async Task NearbyStart()
    {
        using var bus = new LocalBroker();
        string file = Path.Combine(Path.GetTempPath(), "yuuko-nearby-" + Guid.NewGuid().ToString("N") + ".identity");
        var other = (await Strangers(bus, 1))[0];
        var passed = new ConcurrentQueue<Nearby.Met>();
        Nearby.Passed += x => passed.Enqueue(x);
        other.Card = Encoding.UTF8.GetBytes("other card");
        try
        {
            Nearby.MyCard = Encoding.UTF8.GetBytes("my card");
            await Nearby.Start(bus, file);
            string first = Nearby.MyID;
            Check("Nearby starts on a link the app gives it", Nearby.IsOn && first.StartsWith("near-") && Cogitarium.Default is not null);
            Check("...finds a device on it and swaps cards (set before Start)", await Eventually(() => Nearby.Neighbors.Count == 1 && Nearby.People.Count == 1 && !passed.IsEmpty, 15000) && Encoding.UTF8.GetString(Nearby.People[0].Card) == "other card" && Encoding.UTF8.GetString(other.Met.Values.Single().Card) == "my card");

            Cogitarium.Reset();
            Check("the private node being built again doesn't remove the nearby mesh", Cogitarium.Default is not null);
            await Nearby.Start(bus);
            Check("starting twice is fine", Nearby.MyID == first);

            Nearby.Forget(Nearby.People[0].Fingerprint);
            Check("a person can be forgotten", Nearby.People.Count == 0);

            Nearby.Stop();
            Check("stop closes the node and the mesh, not the app's link", !Nearby.IsOn && Cogitarium.Default is null && !(await Throws2<ObjectDisposedException>(() => bus.PublishAsync("x", YuukoPacket.Ephemeral("x", new byte[1])))));

            await Nearby.Start(bus, file);
            Check("a path keeps the same identity between runs", Nearby.MyID == first);
            Nearby.Stop();
        }
        finally { Nearby.Stop(); other.Dispose(); try { File.Delete(file); } catch { } Nearby.MyCard = Array.Empty<byte>(); }
    }

    // ---- the public side of it ----
    private static async Task NearbyStatic()
    {
        Check("Nearby is off until started", !Nearby.IsOn && Nearby.Neighbors.Count == 0);
        Check("MyID asks for Start first", Catch(() => _ = Nearby.MyID) is InvalidOperationException);
        Nearby.Stop();
        Check("Stop when it never started is fine", !Nearby.IsOn);

        // Reset (Pairing builds the private node again) leaves the nearby mesh alone, Stop removes it
        using var bus = new LocalBroker();
        var p = (await Strangers(bus, 1))[0];
        try
        {
            Cogitarium.Attach(p.Node);
            Check("Cogitarium runs on the node it was attached to", Cogitarium.Default is not null && Cogitarium.MyFingerprint == p.Node.Fingerprint);
            Cogitarium.Reset(true);
            Check("a forced reset removes it", Cogitarium.Default is null);
        }
        finally { p.Dispose(); }
    }

    // ---- two real Zenoh sessions on this machine, with nothing told about each other but a shared network ----
    private static async Task NearbyRealZenoh()
    {
        ZenohBroker? a = null, b = null;
        Nearby.Presence? pa = null, pb = null;
        try
        {
            a = ZenohBroker.Open(new ZenohBrokerOptions { EnableTls = false, AllowPlaintextDiscovery = true, DeviceName = "nearby-a" });
            b = ZenohBroker.Open(new ZenohBrokerOptions { EnableTls = false, AllowPlaintextDiscovery = true, DeviceName = "nearby-b" });
            pa = await Nearby.Presence.Create(a, YuukoIdentity.Create(Nearby.NewID()), FastBeacon);
            pb = await Nearby.Presence.Create(b, YuukoIdentity.Create(Nearby.NewID()), FastBeacon);

            bool found = await Eventually(() => pa.Node.ConnectedPeers.Count == 1 && pb.Node.ConnectedPeers.Count == 1, 20000);
            Check("two real Zenoh sessions that were never told about each other find each other and handshake", found);
            if (found)
            {
                var ma = new Cogitarium.Mesh(pa.Node); var mb = new Cogitarium.Mesh(pb.Node);
                var got = new ConcurrentQueue<Cogitarium.Segment>();
                mb.SegmentReceived += (info, piece) => got.Enqueue(piece);
                ma.JoinChunk("street"); mb.JoinChunk("street");
                mb.AcceptSource(ma.MyFingerprint);
                await Eventually(() => ma.Neighbors("street").Count == 1 && mb.Neighbors("street").Count == 1, 8000);
                var stream = ma.StartStream("street", "Live");
                await Eventually(() => mb.Streams().Count == 1, 8000);
                byte[] frame = Bytes(100_000, 3);
                await stream.Send(frame, Cogitarium.Full);
                Check("...and a signed stream goes over the real transport", await Eventually(() => got.Count == 1, 8000) && got.Single().Data.SequenceEqual(frame));
                ma.Dispose(); mb.Dispose();
            }
        }
        catch (Exception e) { Check("real Zenoh nearby ran without an error (" + e.GetType().Name + ": " + e.Message + ")", false); }
        finally { pa?.Dispose(); pb?.Dispose(); a?.Dispose(); b?.Dispose(); }
    }
}
