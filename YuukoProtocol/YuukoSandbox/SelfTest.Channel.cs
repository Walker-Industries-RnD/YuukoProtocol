using System.Collections.Concurrent;
using System.Diagnostics;
using System.Text;
using System.Text.Json.Nodes;
using YuukoProtocol;

namespace YuukoSandbox;

// Tests for the encrypted channel between devices: who is connected, kicking, running commands on
// another device, recovering when messages get lost or a device restarts, presence, and nicknames.
// Same helpers (Check / Tap / Edit) as SelfTest.cs.
public static partial class SelfTest
{
    private const string DataTopic = "yuuko/eclipse/data";

    // DataType numbers on the wire (EclipseBroker.DataType).
    private const int DReq = 0, DResp = 1, DCmd = 2, DAck = 3, DNoSession = 4, DClose = 5;

    private static int? DataTypeOf(string topic, YuukoPacket p) =>
        topic == DataTopic ? JsonNode.Parse(p.Data)?["type"]?.GetValue<int>() : null;

    private static EclipseBroker Node(IYuukoApi bus, YuukoIdentity id, Action<EclipseBrokerOptions>? configure = null)
    {
        var o = new EclipseBrokerOptions
        {
            RequestTimeout = TimeSpan.FromSeconds(2),
            CommandTimeout = TimeSpan.FromSeconds(2),
        };
        o.Handshake.Timeout = TimeSpan.FromSeconds(3);
        configure?.Invoke(o);
        return EclipseBroker.Create(bus, id, o);
    }

    private static async Task<bool> Eventually(Func<bool> condition, int timeoutMs = 3000)
    {
        var sw = Stopwatch.StartNew();
        while (sw.ElapsedMilliseconds < timeoutMs)
        {
            if (condition()) return true;
            await Task.Delay(20);
        }
        return condition();
    }

    private static byte[] Bytes(string s) => Encoding.UTF8.GetBytes(s);

    // ── peers ────────────────────────────────────────────────────────────────

    private static async Task Peers()
    {
        Section("peers (who is connected)");
        using var bus = new LocalBroker();
        var pid = YuukoIdentity.Create("provider");
        var cid = YuukoIdentity.Create("client");
        using var prov = Node(bus, pid);
        using var cli = Node(bus, cid);
        await prov.StartAsync();
        await cli.StartAsync();

        var connected = new ConcurrentQueue<string>();
        prov.PeerConnected += p => connected.Enqueue("prov saw " + p.Id);
        cli.PeerConnected += p => connected.Enqueue("cli saw " + p.Id);

        Check("nobody is connected before anyone talks", prov.ConnectedPeers.Count == 0 && cli.ConnectedPeers.Count == 0);

        var ping = await cli.PingAsync("provider");
        Check("the first ping opens a session and succeeds", ping.IsOk);
        Check("both sides now list each other", cli.ConnectedPeers.Contains("provider") && prov.ConnectedPeers.Contains("client"));
        Check("each side sees the other's key fingerprint",
            cli.Peers.Single().Fingerprint == pid.Fingerprint && prov.Peers.Single().Fingerprint == cid.Fingerprint);
        Check("PeerConnected fired on both sides",
            await Eventually(() => connected.Contains("prov saw client") && connected.Contains("cli saw provider")));
        Check("a peer we just heard from is online", cli.IsOnline("provider") && prov.IsOnline("client"));
        Check("a peer we never met is neither connected nor online", !cli.IsConnected("stranger") && !cli.IsOnline("stranger"));
    }

    // ── broadcast / relay ────────────────────────────────────────────────────

    // Builds a group of devices where ONLY the listed pairs trust each other (so only they can connect), connects each
    // pair, and gives every device a "note" command that records (origin, hand-over device, text).
    private static async Task<(Dictionary<string, EclipseBroker> nodes, Dictionary<string, ConcurrentQueue<string>> log)> Group(
        IYuukoApi bus, string[] names, (string, string)[] links, Action<string, EclipseBrokerOptions>? configure = null,
        string[]? withoutHandler = null, bool trustEachOthersBroadcasts = true)
    {
        var ids = names.ToDictionary(n => n, n => YuukoIdentity.Create(n));
        var nodes = new Dictionary<string, EclipseBroker>();
        var log = new Dictionary<string, ConcurrentQueue<string>>();
        foreach (var n in names)
        {
            var me = n;
            nodes[n] = Node(bus, ids[n], o =>
            {
                foreach (var (a, b) in links)
                {
                    if (a == me) o.Handshake.TrustDevice(b, ids[b].Fingerprint);
                    if (b == me) o.Handshake.TrustDevice(a, ids[a].Fingerprint);
                }
                // Broadcasts are signed; a device only runs one whose signer it knows. Here every device knows all the others.
                if (trustEachOthersBroadcasts)
                    foreach (var other in names.Where(x => x != me)) o.TrustOrigin(other, ids[other].Fingerprint);
                configure?.Invoke(me, o);
            });
            log[n] = new ConcurrentQueue<string>();
            if (withoutHandler?.Contains(n) == true) continue;
            var q = log[n];
            nodes[n].On("note", (ctx, _) =>
            {
                q.Enqueue($"{ctx.Origin}|{ctx.FromId}|{ctx.IsBroadcast}|{ctx.PayloadAsString()}");
                return Task.FromResult(CommandResult.Ok());
            });
        }
        foreach (var n in nodes.Values) await n.StartAsync();
        foreach (var (a, b) in links) await nodes[a].PingAsync(b);
        return (nodes, log);
    }

    private static async Task Relay()
    {
        Section("broadcast (relay through other devices)");

        // Phone <-> PC and Phone <-> Handheld. PC and Handheld never connect to each other.
        {
            using var bus = new LocalBroker();
            var (n, log) = await Group(bus, new[] { "pc", "phone", "handheld" }, new[] { ("pc", "phone"), ("phone", "handheld") });
            try
            {
                Check("setup: the PC and the handheld are not connected to each other",
                    !n["pc"].ConnectedPeers.Contains("handheld") && !n["handheld"].ConnectedPeers.Contains("pc")
                    && n["phone"].ConnectedPeers.Count == 2);

                var r = await n["pc"].BroadcastAsync("note", Bytes("hello"));
                Check("the PC hands it to the phone and the phone accepts", r.Acks.Count == 1 && r.AllAccepted && r.Acks.ContainsKey("phone"));
                Check("the handheld gets it, though the PC is not connected to it", await Eventually(() => log["handheld"].Count == 1));
                Check("the phone ran it too", log["phone"].Count == 1);
                Check("the handheld sees the PC as the origin, the phone as the hand-over, and that it was a broadcast",
                    log["handheld"].TryPeek(out var line) && line == "pc|phone|True|hello");
                Check("the device that started it does not run it itself", log["pc"].IsEmpty);

                await Task.Delay(500);
                Check("nothing echoes back: each device ran it exactly once",
                    log["pc"].Count == 0 && log["phone"].Count == 1 && log["handheld"].Count == 1);

                // The other direction works the same way.
                await n["handheld"].BroadcastAsync("note", Bytes("back"));
                Check("a broadcast from the far end reaches the PC", await Eventually(() => log["pc"].Count == 1));
            }
            finally { foreach (var x in n.Values) x.Dispose(); }
        }

        // Everyone connected to everyone: each device would hear it from two places.
        {
            using var bus = new LocalBroker();
            var names = new[] { "a", "b", "c", "d" };
            var links = new[] { ("a", "b"), ("a", "c"), ("a", "d"), ("b", "c"), ("b", "d"), ("c", "d") };
            var (n, log) = await Group(bus, names, links);
            try
            {
                await n["a"].BroadcastAsync("note", Bytes("x"));
                Check("full mesh: everyone else got it", await Eventually(() => log["b"].Count >= 1 && log["c"].Count >= 1 && log["d"].Count >= 1));
                await Task.Delay(800);   // give any echo time to happen
                Check("full mesh: every device ran it exactly once (no loop)",
                    log["a"].Count == 0 && log["b"].Count == 1 && log["c"].Count == 1 && log["d"].Count == 1);
                Check("full mesh: still exactly once after a pause", log.Values.Sum(q => q.Count) == 3);

                // Two broadcasts are two different changes.
                await n["a"].BroadcastAsync("note", Bytes("y"));
                await n["a"].BroadcastAsync("note", Bytes("y"));
                Check("two broadcasts with the same text are two separate runs",
                    await Eventually(() => log["b"].Count == 3 && log["c"].Count == 3 && log["d"].Count == 3));
            }
            finally { foreach (var x in n.Values) x.Dispose(); }
        }

        // A ring (a loop in the network) with a device in the middle that does not know the command.
        {
            using var bus = new LocalBroker();
            var (n, log) = await Group(bus, new[] { "a", "b", "c", "d" },
                new[] { ("a", "b"), ("b", "c"), ("c", "d"), ("d", "a") }, withoutHandler: new[] { "b" });
            try
            {
                var r = await n["a"].BroadcastAsync("note", Bytes("ring"));
                Check("ring: a device without the command still accepts it and passes it on", r.AllAccepted);
                Check("ring: the far side gets it", await Eventually(() => log["c"].Count >= 1 && log["d"].Count >= 1));
                await Task.Delay(800);
                Check("ring: it goes round once, not forever",
                    log["a"].Count == 0 && log["b"].Count == 0 && log["c"].Count == 1 && log["d"].Count == 1);
            }
            finally { foreach (var x in n.Values) x.Dispose(); }
        }

        // A chain a-b-c-d with a short hop limit.
        {
            using var bus = new LocalBroker();
            var (n, log) = await Group(bus, new[] { "a", "b", "c", "d" },
                new[] { ("a", "b"), ("b", "c"), ("c", "d") }, (name, o) => { if (name == "a") o.RelayMaxHops = 1; });
            try
            {
                await n["a"].BroadcastAsync("note", Bytes("short"));
                Check("hop limit: reaches as far as the limit allows", await Eventually(() => log["b"].Count == 1 && log["c"].Count == 1));
                await Task.Delay(500);
                Check("hop limit: and no further", log["d"].IsEmpty);
            }
            finally { foreach (var x in n.Values) x.Dispose(); }
        }

        // A handler that breaks must not stop the others hearing it; the authorizer is respected.
        {
            using var bus = new LocalBroker();
            var (n, log) = await Group(bus, new[] { "a", "b", "c" }, new[] { ("a", "b"), ("b", "c") }, (name, o) =>
            {
                if (name == "b") o.CommandAuthorizer = (peer, cmd) => cmd != "forbidden";
            });
            try
            {
                n["b"].On("boom", (_, _) => throw new InvalidOperationException("nope"));
                n["c"].On("boom", (ctx, _) => { log["c"].Enqueue("boom ran"); return Task.FromResult(CommandResult.Ok()); });
                var r = await n["a"].BroadcastAsync("boom");
                Check("a handler that throws gives an error ack", r.Acks["b"].Status == AckStatus.Error);
                Check("but the broadcast still reached the next device", await Eventually(() => log["c"].Contains("boom ran")));

                n["c"].On("forbidden", (ctx, _) => { log["c"].Enqueue("forbidden ran"); return Task.FromResult(CommandResult.Ok()); });
                var denied = await n["a"].BroadcastAsync("forbidden");
                await Task.Delay(400);
                Check("the authorizer can refuse a broadcast: Denied, and it goes no further",
                    denied.Acks["b"].Status == AckStatus.Denied && !log["c"].Contains("forbidden ran"));
            }
            finally { foreach (var x in n.Values) x.Dispose(); }
        }

        // Misuse and abuse.
        {
            using var bus = new LocalBroker();
            var (n, log) = await Group(bus, new[] { "a", "b", "c" }, new[] { ("a", "b"), ("b", "c") });
            try
            {
                Check("reserved names cannot be broadcast", Throws<ArgumentException>(() => n["a"].BroadcastAsync("yuuko.ping")));
                Check("an oversized payload is refused before sending", Throws<ArgumentException>(() => n["a"].BroadcastAsync("note", new byte[2 << 20])));
                Check("a large payload that fits is delivered intact", await LargeBroadcastArrives(n["a"], log["c"]));

                // Hand the relay command a forged or broken envelope directly (what a hostile neighbour could do).
                var junk = await n["a"].SendCommandAsync("b", "yuuko.relay", Bytes("not json"));
                Check("a malformed relay is answered with an error, not run", junk.Status == AckStatus.Error);
                var reserved = await n["a"].SendCommandAsync("b", "yuuko.relay",
                    Bytes("{\"origin\":\"x\",\"id\":\"1\",\"ttl\":3,\"name\":\"yuuko.ping\",\"data\":\"\"}"));
                Check("a relay naming a reserved command is refused", reserved.Status == AckStatus.Error);
                var noOrigin = await n["a"].SendCommandAsync("b", "yuuko.relay", Bytes("{\"id\":\"1\",\"ttl\":3,\"name\":\"note\",\"data\":\"\"}"));
                Check("a relay with no origin is refused", noOrigin.Status == AckStatus.Error);

                // The same signed broadcast sent twice runs once. (A new request id each time, so this tests the broadcast id memory, not the retry cache.)
                var (_, wire) = n["a"].BuildBroadcast("note", Bytes("once"));
                var first = await n["a"].SendCommandAsync("b", "yuuko.relay", wire);
                var second = await n["a"].SendCommandAsync("b", "yuuko.relay", wire);
                int runs = log["b"].Count(l => l.EndsWith("|once", StringComparison.Ordinal));
                Check("replaying the same broadcast id runs it once", first.IsOk && second.IsOk && second.Message == "duplicate" && runs == 1);

                // A broadcast nobody signed is not run, however it is dressed up.
                var unsigned = await n["a"].SendCommandAsync("b", "yuuko.relay",
                    Bytes("{\"origin\":\"ghost\",\"id\":\"abc\",\"ttl\":0,\"name\":\"note\",\"data\":\"aGk=\"}"));
                Check("an unsigned broadcast is refused", unsigned.Status == AckStatus.Denied && !log["b"].Any(l => l.StartsWith("ghost|", StringComparison.Ordinal)));
            }
            finally { foreach (var x in n.Values) x.Dispose(); }
        }

        // The origin is proven by its signature, not by the device that handed the broadcast over.
        {
            using var bus = new LocalBroker();
            // a (origin) and m (the hostile device in the middle) both connect to b. x is a stranger.
            var (n, log) = await Group(bus, new[] { "a", "b", "m", "x" }, new[] { ("a", "b"), ("m", "b") },
                trustEachOthersBroadcasts: false);
            try
            {
                n["b"].TrustOrigin("a", n["a"].Fingerprint);   // b knows a's key; it has never heard of x
                string Ran(string text) => log["b"].FirstOrDefault(l => l.EndsWith("|" + text, StringComparison.Ordinal)) ?? "";
                async Task<CommandAck> ViaM(byte[] wire) => await n["m"].SendCommandAsync("b", "yuuko.relay", wire);
                static byte[] Edit(byte[] wire, Action<JsonObject> change)
                {
                    var o = JsonNode.Parse(wire)!.AsObject();
                    change(o);
                    return Encoding.UTF8.GetBytes(o.ToJsonString());
                }

                // A forged copy must not use up the id: the real one still gets through afterwards.
                var (id1, good1) = n["a"].BuildBroadcast("note", Bytes("real"));
                var evil = Edit(good1, o => o["data"] = Convert.ToBase64String(Bytes("evil")));
                var r1 = await ViaM(evil);
                Check("a relay that changes the data is refused (the signature no longer matches)", r1.Status == AckStatus.Denied && Ran("evil") == "");
                var r1b = await ViaM(good1);
                Check("...and the genuine copy, same id, still goes through afterwards", r1b.IsOk && Ran("real") == "a|m|True|real");
                Check("the handler is told the real origin (a) and the device that handed it over (m)", Ran("real") == "a|m|True|real");

                var (_, good2) = n["a"].BuildBroadcast("note", Bytes("two"));
                n["b"].On("other", (c, _) => { log["b"].Enqueue("OTHER ran"); return Task.FromResult(CommandResult.Ok()); });
                var r2 = await ViaM(Edit(good2, o => o["name"] = "other"));
                Check("a relay that swaps the command name is refused", r2.Status == AckStatus.Denied && !log["b"].Contains("OTHER ran"));

                var (_, good3) = n["a"].BuildBroadcast("note", Bytes("three"));
                var r3 = await ViaM(Edit(good3, o => o["origin"] = "x"));
                Check("a relay that renames the origin is refused", r3.Status == AckStatus.Denied && Ran("three") == "");

                var (_, good4) = n["a"].BuildBroadcast("note", Bytes("four"));
                var r4 = await ViaM(Edit(good4, o =>
                {
                    var sig = Convert.FromBase64String(o["signature"]!.GetValue<string>());
                    sig[sig.Length / 2] ^= 1;
                    o["signature"] = Convert.ToBase64String(sig);
                }));
                Check("a signature with one flipped bit is refused", r4.Status == AckStatus.Denied && Ran("four") == "");

                var (_, good5) = n["a"].BuildBroadcast("note", Bytes("five"));
                var r5 = await ViaM(Edit(good5, o => { o.Remove("signature"); }));
                var r5b = await ViaM(Edit(good5, o => { o.Remove("keys"); }));
                Check("a broadcast with the signature or the keys stripped is refused",
                    r5.Status == AckStatus.Denied && r5b.Status == AckStatus.Denied && Ran("five") == "");

                // An imposter signs with its OWN key but claims to be a.
                var (_, xwire) = n["x"].BuildBroadcast("note", Bytes("imposter"));
                var r6 = await ViaM(Edit(xwire, o => o["origin"] = "a"));
                Check("someone else's key claiming to be a is refused (the key is not a's)", r6.Status == AckStatus.Denied && Ran("imposter") == "");
                // The hard case: x signs everything correctly, with its own key, but names "a" as the origin.
                var (_, ximp) = n["x"].BuildBroadcast("note", Bytes("imposter2"), claimOrigin: "a");
                var r6c = await ViaM(ximp);
                Check("a perfectly signed broadcast that claims to be from a, signed by x's key, is refused (key is not a's)",
                    r6c.Status == AckStatus.Denied && Ran("imposter2") == "");
                var r6b = await ViaM(xwire);
                Check("a stranger signing as itself is refused (b does not know x)", r6b.Status == AckStatus.Denied && Ran("imposter") == "");

                // Old and future-dated broadcasts (a replay from long ago, or a wrong clock).
                var (_, old) = n["a"].BuildBroadcast("note", Bytes("old"), DateTimeOffset.UtcNow.AddMinutes(-30));
                var (_, future) = n["a"].BuildBroadcast("note", Bytes("future"), DateTimeOffset.UtcNow.AddMinutes(30));
                var (_, fresh) = n["a"].BuildBroadcast("note", Bytes("fresh"), DateTimeOffset.UtcNow.AddSeconds(-30));
                var r7 = await ViaM(old);
                var r8 = await ViaM(future);
                var r9 = await ViaM(fresh);
                Check("a broadcast signed 30 minutes ago is refused", r7.Status == AckStatus.Denied && Ran("old") == "");
                Check("a broadcast dated 30 minutes ahead is refused", r8.Status == AckStatus.Denied && Ran("future") == "");
                Check("(control) one signed 30 seconds ago is fine", r9.IsOk && Ran("fresh") != "");

                // A device we hold a session with is known by the key it proved in the handshake, with or without a pin.
                n["b"].UntrustOrigin("a");
                var (_, good6) = n["a"].BuildBroadcast("note", Bytes("six"));
                var r10 = await ViaM(good6);
                Check("a device you are connected to is known without pinning it", r10.IsOk && Ran("six") != "");
            }
            finally { foreach (var x in n.Values) x.Dispose(); }
        }

        // Pinning an origin does not let it connect; an unknown origin's broadcast stops at the first device that doesn't know it.
        {
            using var bus = new LocalBroker();
            var (n, log) = await Group(bus, new[] { "pc", "phone", "handheld" }, new[] { ("pc", "phone"), ("phone", "handheld") },
                trustEachOthersBroadcasts: false);
            try
            {
                n["phone"].TrustOrigin("pc", n["pc"].Fingerprint);   // the phone knows the PC. The handheld does not.
                await n["pc"].BroadcastAsync("note", Bytes("hi"));
                await Task.Delay(600);
                Check("the handheld refuses a broadcast whose origin it does not know, though the phone relayed it", log["handheld"].IsEmpty);
                Check("the phone (which knows the PC) ran it", log["phone"].Count == 1);

                n["handheld"].TrustOrigin("pc", n["pc"].Fingerprint);
                await n["pc"].BroadcastAsync("note", Bytes("again"));
                Check("once the handheld pins the PC's key, the next one arrives", await Eventually(() => log["handheld"].Count == 1));
                Check("it arrives marked as coming from the PC through the phone", log["handheld"].TryPeek(out var l) && l == "pc|phone|True|again");
                Check("trusting an origin did not let it connect", !n["pc"].ConnectedPeers.Contains("handheld") && !n["handheld"].ConnectedPeers.Contains("pc"));
            }
            finally { foreach (var x in n.Values) x.Dispose(); }
        }

        // The memory of seen broadcasts is bounded, and full means refuse (never forget early and re-run).
        {
            using var bus = new LocalBroker();
            var (n, log) = await Group(bus, new[] { "a", "b" }, new[] { ("a", "b") }, (name, o) => { if (name == "b") o.RelayMaxRemembered = 3; });
            try
            {
                for (int i = 0; i < 3; i++) await n["a"].BroadcastAsync("note", Bytes("m" + i));
                await Eventually(() => log["b"].Count == 3);
                var r = await n["a"].BroadcastAsync("note", Bytes("overflow"));
                Check("when the seen-list is full, a new relayed broadcast gets Busy", r.Acks["b"].Status == AckStatus.Busy);
                Check("and it was not run", log["b"].Count == 3);
            }
            finally { foreach (var x in n.Values) x.Dispose(); }
        }
    }

    private static bool Throws<T>(Func<Task> f) where T : Exception
    {
        try { f().GetAwaiter().GetResult(); return false; }
        catch (T) { return true; }
        catch { return false; }
    }

    private static async Task<bool> LargeBroadcastArrives(EclipseBroker from, ConcurrentQueue<string> intoLog)
    {
        string big = new string('z', 600_000);
        var r = await from.BroadcastAsync("note", Bytes(big));
        return r.AllAccepted && await Eventually(() => intoLog.Any(l => l.EndsWith("|" + big)), 5000);
    }

    // ── kicking ──────────────────────────────────────────────────────────────

    private static async Task Kicking()
    {
        Section("kicking");
        {
            using var bus = new LocalBroker();
            using var prov = Node(bus, YuukoIdentity.Create("provider"));
            using var cli = Node(bus, YuukoIdentity.Create("client"));
            prov.Serve("t", YuukoPacket.FromBytes("k", Bytes("v")));
            await prov.StartAsync();
            await cli.StartAsync();

            var reasons = new ConcurrentQueue<string>();
            cli.PeerDisconnected += (id, reason) => reasons.Enqueue(reason);

            Check("(control) the client gets data before the kick", (await cli.RequestAsync("provider", "t")).Count == 1);

            Check("KickAsync reports it kicked a connected peer", await prov.KickAsync("client", ban: true, reason: "testing"));
            Check("the provider no longer lists the client", prov.ConnectedPeers.Count == 0);
            Check("the client is told and drops its half too", await Eventually(() => cli.ConnectedPeers.Count == 0));
            Check("the client learns the reason", await Eventually(() => reasons.Any(r => r.Contains("closed by peer") && r.Contains("testing"))));

            var sw = Stopwatch.StartNew();
            var denied = await cli.RequestAsync("provider", "t");
            Check($"a banned peer gets nothing and finds out fast ({sw.ElapsedMilliseconds} ms)", denied.Count == 0 && sw.ElapsedMilliseconds < 1500);

            prov.Unban("client");
            Check("after Unban the client reconnects and gets data", (await cli.RequestAsync("provider", "t")).Count == 1);
        }
        {
            using var bus = new LocalBroker();
            using var prov = Node(bus, YuukoIdentity.Create("provider"));
            using var cli = Node(bus, YuukoIdentity.Create("client"));
            prov.Serve("t", YuukoPacket.FromBytes("k", Bytes("v")));
            await prov.StartAsync();
            await cli.StartAsync();
            await cli.PingAsync("provider");

            await prov.KickAsync("client", ban: false);
            Check("a kick WITHOUT a ban lets the client straight back in", (await cli.RequestAsync("provider", "t")).Count == 1);
        }
        {
            using var bus = new LocalBroker();
            using var prov = Node(bus, YuukoIdentity.Create("provider"));
            using var late = Node(bus, YuukoIdentity.Create("late"));
            await prov.StartAsync();
            await late.StartAsync();

            Check("kicking a peer we have no session with returns false", !await prov.KickAsync("late", ban: true));
            Check("...but the ban still applies when it shows up", (await late.PingAsync("provider")).Status == AckStatus.Unreachable);
        }
        {
            // Someone on the mesh turns a genuine reply into a fake "Close" to knock the session over.
            using var raw = new LocalBroker();
            int swapped = 0;
            var tap = new Tap(raw)
            {
                OnPublish = (topic, p) => DataTypeOf(topic, p) == DResp && Interlocked.Increment(ref swapped) == 1
                    ? Edit(p, o => o["type"] = DClose)
                    : p,
            };
            using var prov = Node(tap, YuukoIdentity.Create("provider"));
            using var cli = Node(raw, YuukoIdentity.Create("client"), o => o.RequestTimeout = TimeSpan.FromMilliseconds(400));
            prov.Serve("t", YuukoPacket.FromBytes("k", Bytes("v")));
            await prov.StartAsync();
            await cli.StartAsync();

            var drops = new ConcurrentQueue<string>();
            cli.PeerDisconnected += (id, reason) => drops.Enqueue(reason);

            var got = await cli.RequestAsync("provider", "t");   // 1st reply is swapped for a fake Close; the retry is genuine
            Check("(the fake Close really was sent)", swapped >= 1);
            Check("a forged Close does NOT end the session", cli.IsConnected("provider") && drops.IsEmpty);
            Check("and the data still arrives on the retry", got.Count == 1);
        }
    }

    // ── commands ─────────────────────────────────────────────────────────────

    private static async Task Commands()
    {
        Section("commands (run something on another device)");
        using var bus = new LocalBroker();
        int secretRan = 0;
        using var prov = Node(bus, YuukoIdentity.Create("provider"), o =>
        {
            o.CommandAuthorizer = (peer, name) => name != "secret";
            o.MaxCommandBytes = 1000;
        });
        using var cli = Node(bus, YuukoIdentity.Create("client"));

        prov.On("echo", (ctx, ct) => Task.FromResult(CommandResult.Ok(ctx.Payload)));
        prov.On("upper", (ctx, ct) => Task.FromResult(CommandResult.Ok(ctx.PayloadAsString().ToUpperInvariant())));
        prov.On("who", (ctx, ct) => Task.FromResult(CommandResult.Ok(ctx.FromId)));
        prov.On("secret", (ctx, ct) => { Interlocked.Increment(ref secretRan); return Task.FromResult(CommandResult.Ok()); });
        prov.On("boom", (ctx, ct) => throw new InvalidOperationException("boom-secret-text"));
        cli.On("whoami", (ctx, ct) => Task.FromResult(CommandResult.Ok(ctx.FromId)));
        cli.On("echoback", (ctx, ct) => Task.FromResult(CommandResult.Ok(ctx.Payload)));
        await prov.StartAsync();
        await cli.StartAsync();

        var up = await cli.SendCommandAsync("provider", "upper", Bytes("hello"));
        Check("a command runs on the other device and its answer comes back", up.IsOk && up.ResultAsString() == "HELLO");
        Check("the handler is told who sent it", (await cli.SendCommandAsync("provider", "who")).ResultAsString() == "client");
        Check("it also works the other way (provider -> client) over the same session",
            (await prov.SendCommandAsync("client", "whoami")).ResultAsString() == "provider");

        var unknown = await cli.SendCommandAsync("provider", "no-such-command");
        Check("an unknown command is reported as such", unknown.Status == AckStatus.UnknownCommand && unknown.IsFromPeer);

        var denied = await cli.SendCommandAsync("provider", "secret");
        Check("the authorizer can refuse a command", denied.Status == AckStatus.Denied);
        Check("...and the refused handler never ran", secretRan == 0);

        var boom = await cli.SendCommandAsync("provider", "boom");
        Check("a handler that throws becomes an Error ack", boom.Status == AckStatus.Error);
        Check("...naming the exception type but not leaking its message", (boom.Message ?? "").Contains("InvalidOperationException") && !(boom.Message ?? "").Contains("boom-secret-text"));

        var big = await cli.SendCommandAsync("provider", "echo", new byte[1500]);
        Check("a payload over the receiver's limit is refused", big.Status == AckStatus.Error && (big.Message ?? "").Contains("too large"));

        using (var tiny = Node(bus, YuukoIdentity.Create("tiny"), o => o.MaxCommandBytes = 50))
        {
            bool refused = false;
            try { await tiny.SendCommandAsync("provider", "echo", new byte[100]); } catch (ArgumentException) { refused = true; }
            Check("a payload over the SENDER's own limit is refused locally", refused);
        }

        Check("command names starting 'yuuko.' are reserved", Throws<ArgumentException>(() => cli.On("yuuko.ping", (c, t) => Task.FromResult(CommandResult.Ok()))));
        Check("empty command names are refused", Throws<ArgumentException>(() => cli.On("", (c, t) => Task.FromResult(CommandResult.Ok()))));

        var ping = await cli.PingAsync("provider");
        Check($"ping works and measures the round trip ({ping.Elapsed.TotalMilliseconds:F1} ms)", ping.IsOk && ping.Elapsed < TimeSpan.FromSeconds(2));

        // Many at once: the 8 lanes get reused and every answer must match its own question.
        var many = await Task.WhenAll(Enumerable.Range(0, 64).Select(async i =>
        {
            var a = await cli.SendCommandAsync("provider", "echo", Bytes("msg-" + i));
            return a.IsOk && a.ResultAsString() == "msg-" + i;
        }));
        Check("64 concurrent commands each get their OWN answer back", many.All(x => x));

        // Both devices talking at once: each side's own lanes must not collide with the answers it is sending.
        var toProv = Enumerable.Range(0, 100).Select(async i =>
            (await cli.SendCommandAsync("provider", "echo", Bytes("c" + i))) is { IsOk: true } a && a.ResultAsString() == "c" + i);
        var toCli = Enumerable.Range(0, 100).Select(async i =>
            (await prov.SendCommandAsync("client", "echoback", Bytes("p" + i))) is { IsOk: true } a && a.ResultAsString() == "p" + i);
        var both = await Task.WhenAll(toProv.Concat(toCli));
        Check("100 commands each way at the same time all succeed", both.All(x => x));

        // Limits, on a node configured for them.
        {
            using var b2 = new LocalBroker();
            using var slow = Node(b2, YuukoIdentity.Create("slow"), o => o.MaxConcurrentCommands = 1);
            using var c2 = Node(b2, YuukoIdentity.Create("c2"));
            slow.On("slow", async (ctx, ct) => { await Task.Delay(600, ct); return CommandResult.Ok(); });
            await slow.StartAsync();
            await c2.StartAsync();
            await c2.PingAsync("slow");

            var first = c2.SendCommandAsync("slow", "slow");
            await Task.Delay(150);
            var second = await c2.SendCommandAsync("slow", "slow");
            Check("a device already at its concurrency limit answers Busy", second.Status == AckStatus.Busy);
            Check("...and the command that was running still finishes", (await first).IsOk);
        }
        {
            using var b3 = new LocalBroker();
            using var hang = Node(b3, YuukoIdentity.Create("hang"), o => o.CommandHandlerTimeout = TimeSpan.FromMilliseconds(200));
            using var c3 = Node(b3, YuukoIdentity.Create("c3"));
            hang.On("hang", async (ctx, ct) => { await Task.Delay(5000, ct); return CommandResult.Ok(); });
            await hang.StartAsync();
            await c3.StartAsync();

            var r = await c3.SendCommandAsync("hang", "hang");
            Check("a handler that runs too long is cancelled and reported", r.Status == AckStatus.Error && (r.Message ?? "").Contains("timed out"));
        }
    }

    // ── recovering from lost messages and restarts ───────────────────────────

    private static async Task SessionHealing()
    {
        Section("healing (lost messages, restarts)");

        {
            // The answer is lost on its way back. The sender retries; the receiver must NOT run it twice.
            using var raw = new LocalBroker();
            int dropped = 0, ran = 0;
            var tap = new Tap(raw) { OnPublish = (topic, p) => DataTypeOf(topic, p) == DAck && Interlocked.Increment(ref dropped) == 1 ? null : p };
            using var prov = Node(tap, YuukoIdentity.Create("provider"));
            using var cli = Node(raw, YuukoIdentity.Create("client"));
            prov.On("count", (ctx, ct) => { Interlocked.Increment(ref ran); return Task.FromResult(CommandResult.Ok("done")); });
            await prov.StartAsync();
            await cli.StartAsync();

            var ack = await cli.SendCommandAsync("provider", "count", null, new CommandOptions { Timeout = TimeSpan.FromMilliseconds(400), Retries = 1 });
            Check("a lost ACK is recovered by the retry", ack.IsOk && ack.ResultAsString() == "done");
            Check("...and the command ran exactly ONCE", ran == 1);
            Check("(the ack really was dropped)", dropped >= 1);

            var after = await Task.WhenAll(Enumerable.Range(0, 20).Select(_ => cli.SendCommandAsync("provider", "count")));
            Check("later commands keep working on the remaining lanes", after.All(a => a.IsOk) && ran == 21);
        }
        {
            // The command itself is lost on its way there.
            using var raw = new LocalBroker();
            int dropped = 0, ran = 0;
            var tap = new Tap(raw) { OnPublish = (topic, p) => DataTypeOf(topic, p) == DCmd && Interlocked.Increment(ref dropped) == 1 ? null : p };
            using var prov = Node(raw, YuukoIdentity.Create("provider"));
            using var cli = Node(tap, YuukoIdentity.Create("client"));
            prov.On("count", (ctx, ct) => { Interlocked.Increment(ref ran); return Task.FromResult(CommandResult.Ok()); });
            await prov.StartAsync();
            await cli.StartAsync();

            var ack = await cli.SendCommandAsync("provider", "count", null, new CommandOptions { Timeout = TimeSpan.FromMilliseconds(400), Retries = 1 });
            Check("a lost COMMAND is recovered by the retry, and runs once", ack.IsOk && ran == 1);
        }
        {
            // Every lane gets poisoned: the session must be replaced, not wedged.
            using var raw = new LocalBroker();
            int dropped = 0, ran = 0;
            var tap = new Tap(raw) { OnPublish = (topic, p) => DataTypeOf(topic, p) == DCmd && Interlocked.Increment(ref dropped) <= 2 ? null : p };
            using var prov = Node(raw, YuukoIdentity.Create("provider"));
            using var cli = Node(tap, YuukoIdentity.Create("client"), o => o.Handshake.MaxChannels = 2);
            prov.On("count", (ctx, ct) => { Interlocked.Increment(ref ran); return Task.FromResult(CommandResult.Ok()); });
            await prov.StartAsync();
            await cli.StartAsync();

            var reasons = new ConcurrentQueue<string>();
            int connects = 0;
            cli.PeerDisconnected += (id, reason) => reasons.Enqueue(reason);
            cli.PeerConnected += _ => Interlocked.Increment(ref connects);

            var ack = await cli.SendCommandAsync("provider", "count", null, new CommandOptions { Timeout = TimeSpan.FromMilliseconds(300), Retries = 2 });
            Check("when every lane has failed, the session is replaced and the command still gets through", ack.IsOk && ran == 1);
            Check("...by a fresh handshake (the old session was dropped)", connects == 2 && reasons.Any(r => r.Contains("every lane")));
        }
        {
            // The provider restarts and forgets every session; the client is still holding a stale one.
            using var bus = new LocalBroker();
            var provId = YuukoIdentity.Create("provider");
            var prov1 = Node(bus, provId);
            using var cli = Node(bus, YuukoIdentity.Create("client"));
            prov1.On("hi", (ctx, ct) => Task.FromResult(CommandResult.Ok("one")));
            await prov1.StartAsync();
            await cli.StartAsync();
            Check("(control) works before the restart", (await cli.SendCommandAsync("provider", "hi")).ResultAsString() == "one");

            prov1.Dispose();
            using var prov2 = Node(bus, provId);
            prov2.On("hi", (ctx, ct) => Task.FromResult(CommandResult.Ok("two")));
            await prov2.StartAsync();

            var sw = Stopwatch.StartNew();
            var ack = await cli.SendCommandAsync("provider", "hi");
            Check($"after the provider restarts, the client recovers on its own ({sw.ElapsedMilliseconds} ms)", ack.IsOk && ack.ResultAsString() == "two" && sw.ElapsedMilliseconds < 2500);
        }
        {
            // Not reachable at all: the answer must be a clear 'Unreachable', not a hang.
            using var bus = new LocalBroker();
            using var cli = Node(bus, YuukoIdentity.Create("client"), o => o.Handshake.Timeout = TimeSpan.FromMilliseconds(500));
            var sw = Stopwatch.StartNew();
            var ack = await cli.SendCommandAsync("nobody-home", "hi");
            Check($"a device that is not there is reported Unreachable, not hung on ({sw.ElapsedMilliseconds} ms)", ack.Status == AckStatus.Unreachable && sw.ElapsedMilliseconds < 3000);
        }
    }

    // ── presence ─────────────────────────────────────────────────────────────

    private static async Task Presence()
    {
        Section("presence (is it still there?)");
        {
            using var bus = new LocalBroker();
            using var prov = Node(bus, YuukoIdentity.Create("provider"), o =>
            {
                o.HeartbeatInterval = TimeSpan.FromMilliseconds(100);
                o.PresenceTimeout = TimeSpan.FromMilliseconds(500);
                o.PingTimeout = TimeSpan.FromMilliseconds(300);
                o.Handshake.MaxChannels = 64;     // plenty of lanes so the session outlives this test
            });
            var cli = Node(bus, YuukoIdentity.Create("client"));
            await prov.StartAsync();
            await cli.StartAsync();
            await prov.PingAsync("client");

            await Task.Delay(1200);
            Check("the heartbeat keeps a healthy peer online past the presence window", prov.IsOnline("client"));

            cli.Dispose();     // the peer goes silent
            Check("a peer that goes silent is reported offline", await Eventually(() => !prov.IsOnline("client"), 3000));
            Check("...while it is still listed as connected until its lanes run out", prov.IsConnected("client"));
        }
        {
            using var bus = new LocalBroker();
            using var prov = Node(bus, YuukoIdentity.Create("provider"), o =>
            {
                o.HeartbeatInterval = TimeSpan.FromMilliseconds(100);
                o.PingTimeout = TimeSpan.FromMilliseconds(250);
                o.Handshake.MaxChannels = 2;
            });
            var cli = Node(bus, YuukoIdentity.Create("client"));
            await prov.StartAsync();
            await cli.StartAsync();
            await prov.PingAsync("client");

            var reasons = new ConcurrentQueue<string>();
            prov.PeerDisconnected += (id, reason) => reasons.Enqueue(reason);

            cli.Dispose();
            Check("a peer that stays silent is eventually dropped", await Eventually(() => !prov.IsConnected("client"), 6000));
            Check("...and PeerDisconnected says why", await Eventually(() => reasons.Any(r => r.Contains("stopped answering"))));
        }
    }

    // ── device directory (nicknames) ─────────────────────────────────────────

    private static async Task DeviceDirectoryTests()
    {
        Section("device directory (nicknames)");

        var phone = YuukoIdentity.Create("phone-01");
        var dir = new DeviceDirectory();
        dir.Add("Phone", "phone-01", phone.Fingerprint, "My phone", new[] { "mobile" });
        Check("a nickname is found regardless of case", dir.Find("phone")?.ClientId == "phone-01" && dir.Find("PHONE") is not null);
        Check("a nickname must be unique", Throws<InvalidOperationException>(() => dir.Add("phone", "x", YuukoIdentity.Create("x").Fingerprint)));
        Check("a client id can only be paired once", Throws<InvalidOperationException>(() => dir.Add("p2", "phone-01", YuukoIdentity.Create("x").Fingerprint)));
        Check("a fingerprint can only be paired once", Throws<InvalidOperationException>(() => dir.Add("p3", "x", phone.Fingerprint)));
        var other = YuukoIdentity.Create("o").Fingerprint;
        Check("nicknames with spaces/symbols are refused", Throws<ArgumentException>(() => dir.Add("bad name!", "o", other)));
        Check("empty and over-long nicknames are refused", Throws<ArgumentException>(() => dir.Add("", "o", other)) && Throws<ArgumentException>(() => dir.Add(new string('a', 65), "o", other)));
        Check("a malformed fingerprint is refused", Throws<ArgumentException>(() => dir.Add("o", "o", "nope")));

        int changes = 0;
        dir.Changed += () => changes++;
        dir.Rename("phone", "pixel");
        Check("rename changes the nickname and nothing else", dir.Find("phone") is null && dir.Find("pixel")!.Fingerprint == phone.Fingerprint && changes == 1);
        dir.Add("tablet", "tablet-01", other);
        Check("renaming onto a taken nickname is refused", Throws<InvalidOperationException>(() => dir.Rename("tablet", "PIXEL")));

        // (the file-backed directory is tested in SelfTest.Directory.cs)

        // Using it for real.
        {
            using var raw = new LocalBroker();
            var everything = new Tap(raw);   // sees every message from every node, to check what goes on the wire
            var provId = YuukoIdentity.Create("provider");
            var phoneId = YuukoIdentity.Create("phone-01");
            using var prov = Node(everything, provId, o => o.Directory = new DeviceDirectory());
            using var ph = Node(everything, phoneId);
            using var stranger = Node(everything, YuukoIdentity.Create("stranger"));
            int notified = 0;
            ph.On("notify", (ctx, ct) => { Interlocked.Increment(ref notified); return Task.FromResult(CommandResult.Ok(ctx.PayloadAsString())); });
            await prov.StartAsync();
            await ph.StartAsync();
            await stranger.StartAsync();

            var early = await ph.PingAsync("provider");
            Check("a node given an EMPTY directory lets nobody in", early.Status == AckStatus.Unreachable);

            prov.PairDevice("kitchen-tablet-nick", "phone-01", phoneId.Fingerprint, "Mum's tablet", "family");
            Check("after pairing, that device can connect", (await ph.PingAsync("provider")).IsOk);
            Check("a device that was not paired still cannot", (await stranger.PingAsync("provider")).Status == AckStatus.Unreachable);

            var viaName = await prov.Device("kitchen-tablet-nick").SendTextAsync("notify", "dinner is ready");
            Check("send a command by nickname", viaName.IsOk && viaName.ResultAsString() == "dinner is ready" && notified == 1);
            Check("nicknames are case-insensitive", (await prov.Device("KITCHEN-TABLET-NICK").PingAsync()).IsOk);

            var status = prov.DeviceStatuses().Single();
            Check("the device list shows live state", status.Moniker == "kitchen-tablet-nick" && status.IsConnected && status.IsOnline && status.Groups.Contains("family"));
            Check("an unknown nickname is an error, not a silent no-op", Throws<KeyNotFoundException>(() => prov.Device("nobody")));

            var onWire = string.Join("\n", everything.Seen);
            Check("(control) the scan can see ids that DO travel", onWire.Contains("phone-01"));
            Check("a nickname never appears on the wire", !onWire.Contains("kitchen-tablet-nick"));
            Check("a display name never appears on the wire", !onWire.Contains("Mum's tablet"));

            Check("UnpairDeviceAsync removes the device", await prov.UnpairDeviceAsync("kitchen-tablet-nick"));
            Check("...and it is kicked", await Eventually(() => !prov.IsConnected("phone-01")));
            Check("...and cannot come back", (await ph.PingAsync("provider")).Status == AckStatus.Unreachable);
        }

        // Group sends.
        {
            using var bus = new LocalBroker();
            using var prov = Node(bus, YuukoIdentity.Create("provider"));
            int c1 = 0, c2 = 0, c3 = 0;
            var ids = new[] { YuukoIdentity.Create("c1"), YuukoIdentity.Create("c2"), YuukoIdentity.Create("c3") };
            var nodes = new List<EclipseBroker>();
            try
            {
                var counters = new[] { (Action)(() => Interlocked.Increment(ref c1)), () => Interlocked.Increment(ref c2), () => Interlocked.Increment(ref c3) };
                for (int i = 0; i < 3; i++)
                {
                    var bump = counters[i];
                    var n = Node(bus, ids[i]);
                    n.On("count", (ctx, ct) => { bump(); return Task.FromResult(CommandResult.Ok()); });
                    await n.StartAsync();
                    nodes.Add(n);
                }
                prov.PairDevice("c1", "c1", ids[0].Fingerprint, null, "phones");
                prov.PairDevice("c2", "c2", ids[1].Fingerprint, null, "phones");
                prov.PairDevice("c3", "c3", ids[2].Fingerprint, null, "other");
                await prov.StartAsync();

                var acks = await prov.DeviceGroup("phones").SendAsync("count");
                Check("a group send reaches every device in the group, and only them",
                    acks.Count == 2 && acks.Values.All(a => a.IsOk) && c1 == 1 && c2 == 1 && c3 == 0);

                await prov.DeviceGroup("phones").Except("c2").SendAsync("count");
                Check("Except() leaves the named device out", c1 == 2 && c2 == 1);
                Check("AllDevices() is every paired device", prov.AllDevices().Count == 3);
            }
            finally { foreach (var n in nodes) n.Dispose(); }
        }
    }

    // ── regression ───────────────────────────────────────────────────────────

    private static async Task Regression()
    {
        Section("regression (the original behaviour still holds)");
        using var bus = new LocalBroker();
        using var prov = Node(bus, YuukoIdentity.Create("provider"));
        for (int i = 0; i < 64; i++) prov.Serve($"topic/{i}", YuukoPacket.FromBytes("k", Bytes("v" + i)));
        await prov.StartAsync();
        using var cli = Node(bus, YuukoIdentity.Create("client"));

        var results = await Task.WhenAll(Enumerable.Range(0, 64).Select(async i =>
            (await cli.RequestAsync("provider", "topic/" + i)).FirstOrDefault()?.DataAsString() == "v" + i));
        Check("64 concurrent data requests over lanes, each gets its own data", results.All(x => x));
        Check("a request for an unknown topic returns an empty list", (await cli.RequestAsync("provider", "no/such/topic")).Count == 0);
    }
}
