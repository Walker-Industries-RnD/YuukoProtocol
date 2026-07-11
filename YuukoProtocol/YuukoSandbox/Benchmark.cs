using System.Diagnostics;
using System.Text;
using YuukoProtocol;

namespace YuukoSandbox;

// EclipseBroker / handshake performance benchmark. Runs entirely in-process over
// LocalBroker, so it measures the crypto + protocol overhead only (NOT network).
//
// Use dotnet run --project YuukoSandbox -- bench
//
// No native zenoh-c needed  


public static class Benchmark
{
    public static async Task RunAsync()
    {
        Console.WriteLine("== YuukoProtocol / EclipseBroker performance ==");
        Console.WriteLine("(in-process LocalBroker transport — measures crypto + protocol overhead, NOT network)\n");

        await HandshakeCost();
        await WarmRoundTrip();
        await ThroughputByLanes();
        await RawAead();

        Console.WriteLine("\nDone. Remember: over a real Zenoh network, latency dominates and this overhead disappears.");
    }

    // A. Handshake cost (Kyber-1024 KEM + HKDF + lane setup) — one-time per peer.
    private static async Task HandshakeCost()
    {
        const int n = 200;
        for (int i = 0; i < 20; i++) // warmup
        {
            using var t = new LocalBroker();
            using var p = EclipseBroker.Create(t, YuukoIdentity.Create("p")); await p.StartAsync();
            using var r = EclipseBroker.Create(t, YuukoIdentity.Create($"w{i}"));
            await r.RequestAsync("p", "x");
        }

        var identities = Enumerable.Range(0, n).Select(i => YuukoIdentity.Create($"req{i}")).ToArray();
        using var transport = new LocalBroker();
        using var provider = EclipseBroker.Create(transport, YuukoIdentity.Create("provider")); await provider.StartAsync();
        provider.Serve("t", YuukoPacket.FromBytes("k", Encoding.UTF8.GetBytes("v")));

        var sw = Stopwatch.StartNew();
        for (int i = 0; i < n; i++)
        {
            using var req = EclipseBroker.Create(transport, identities[i]);
            await req.RequestAsync("provider", "t"); // first call = full handshake + 1 request
        }
        sw.Stop();
        Console.WriteLine($"A. Handshake + first request : {sw.Elapsed.TotalMilliseconds / n,7:F3} ms/peer   ({n} peers)");
    }

    // B. Warm request round-trip on an established session (serial).
    private static async Task WarmRoundTrip()
    {
        using var transport = new LocalBroker();
        using var provider = EclipseBroker.Create(transport, YuukoIdentity.Create("provider")); await provider.StartAsync();
        var payload = new byte[256]; Random.Shared.NextBytes(payload);
        provider.Serve("t", YuukoPacket.FromBytes("k", payload));
        using var alice = EclipseBroker.Create(transport, YuukoIdentity.Create("alice"));

        for (int i = 0; i < 1000; i++) await alice.RequestAsync("provider", "t"); // establish + warmup

        const int n = 20000;
        var sw = Stopwatch.StartNew();
        for (int i = 0; i < n; i++) await alice.RequestAsync("provider", "t");
        sw.Stop();
        Console.WriteLine($"B. Warm request round-trip   : {sw.Elapsed.TotalMilliseconds / n * 1000,7:F2} us/req   " +
                          $"({n / sw.Elapsed.TotalSeconds,10:N0} req/s serial, 256B payload)");
    }

    // C. Throughput with concurrency (lanes).
    private static async Task ThroughputByLanes()
    {
        foreach (int lanes in new[] { 1, 8, 32 })
        {
            using var transport = new LocalBroker();
            var opts = new EclipseBrokerOptions(); opts.Handshake.MaxChannels = lanes;
            using var provider = EclipseBroker.Create(transport, YuukoIdentity.Create("provider"), opts); await provider.StartAsync();
            var payload = new byte[256]; Random.Shared.NextBytes(payload);
            provider.Serve("t", YuukoPacket.FromBytes("k", payload));
            var aopts = new EclipseBrokerOptions(); aopts.Handshake.MaxChannels = lanes;
            using var alice = EclipseBroker.Create(transport, YuukoIdentity.Create("alice"), aopts); await alice.StartAsync();
            await alice.RequestAsync("provider", "t"); // establish

            const int n = 20000;
            var sw = Stopwatch.StartNew();
            await Task.WhenAll(Enumerable.Range(0, n).Select(_ => alice.RequestAsync("provider", "t")));
            sw.Stop();
            Console.WriteLine($"C. Throughput @ {lanes,2} lanes    : {n / sw.Elapsed.TotalSeconds,10:N0} req/s   ({n} reqs in {sw.Elapsed.TotalMilliseconds:F0} ms)");
        }
    }

    // D. Raw AES-256-GCM (encrypt on one peer, decrypt on the other) over one lane.
    private static async Task RawAead()
    {
        using var transport = new LocalBroker();
        using var host = new YuukoHandshake(transport, YuukoIdentity.Create("provider")); await host.StartAsync();
        using var client = new YuukoHandshake(transport, YuukoIdentity.Create("alice"));
        var clientSession = await client.RequestSessionAsync("provider");
        host.TryGetSession("alice", out var hostSession); // peer decrypts what client encrypts
        if (clientSession is null || hostSession is null) { Console.WriteLine("D. (session setup failed)"); return; }

        var pt = new byte[256]; Random.Shared.NextBytes(pt);
        for (int i = 0; i < 1000; i++) { var w = clientSession.EncryptOnLane(1, "M", pt); hostSession.DecryptOnLane(1, w); }

        const int n = 200000;
        var sw = Stopwatch.StartNew();
        for (int i = 0; i < n; i++) { var w = clientSession.EncryptOnLane(1, "M", pt); hostSession.DecryptOnLane(1, w); }
        sw.Stop();
        Console.WriteLine($"D. Raw AEAD enc+dec (256B)   : {sw.Elapsed.TotalMilliseconds / n * 1000,7:F2} us/op   ({n / sw.Elapsed.TotalSeconds,10:N0} op/s)");
    }
}
