using System.Diagnostics;
using System.Text;
using YuukoProtocol;

namespace YuukoSandbox;

// ─────────────────────────────────────────────────────────────────────────────
// TEMPLATE: a service between two devices.
//
//   dotnet run --project YuukoSandbox -- id <file> <name>
//       Create (or load) this device's identity file and print its fingerprint.
//   dotnet run --project YuukoSandbox -- provider [id] [listen-endpoint] [options]
//       Device A: owns the data.
//   dotnet run --project YuukoSandbox -- client <providerId> [connect-endpoint] [options]
//       Device B: asks for it.
//
//   Endpoints look like  tcp/192.168.1.10:7447  (omit both for LAN multicast discovery).
//
//   LOCKING IT DOWN (all optional, but use them on anything that is not a throwaway test):
//     --identity <file>            keep a stable identity across restarts (the file holds the PRIVATE key)
//     --id-password <text>         encrypt that file (8+ characters; Pariah: Argon2id + AES-256-GCM). Prefer the
//                                  YUUKO_ID_PASSWORD environment variable: command lines show up in process lists.
//                                  A plaintext file is encrypted in place the first time it is loaded with a password.
//     --name <id>                  client only: the id this device goes by (needed with --identity)
//     --trust <name>=<fingerprint> provider only, repeatable: only these devices, with exactly
//                                  these keys, may connect. Get a fingerprint from the `id` command.
//     --psk <text>                 shared secret, 16+ characters; or set YUUKO_PSK so it stays out
//                                  of your shell history / process list. Both sides need the same one.
//
//   RUNNING A COMMAND on the provider instead of fetching data (the provider knows `echo` and `time`):
//     client <providerId> <endpoint> --cmd echo --payload hello [--count 200]
//
//   TLS on the link (underneath the Kyber + AES-256-GCM session):
//     --tls --ca ca.pem                                (client)
//     --tls --cert server.pem --key server-key.pem     (provider)
//     --mtls                                           (both) also make clients present a certificate:
//                                                      client gets  --cert client.pem --key client-key.pem
//
// First-time pairing: run `id` on each device, then give each side the other's fingerprint.
//
// To make YOUR service: copy this file, change DataTopic, change what the provider
// Serve()s, and change what the client does with the packets it gets back.
// ─────────────────────────────────────────────────────────────────────────────
public static class ServiceTemplate
{
    // The topic your service's data lives on. Use a stable path (see YuukoTopics).
    private const string DataTopic = "yuuko/example/greetings";

    public static async Task RunAsync(string[] args)
    {
        var role = args[0].ToLowerInvariant();
        var flags = Flags.Parse(args);

        try
        {
            switch (role)
            {
                case "id": RunId(flags); break;
                case "offer": await RunOffer(flags); break;
                case "join": await RunJoin(flags); break;
                case "provider": await RunProvider(flags); break;
                case "client": await RunClient(flags); break;
                default: Console.WriteLine("Usage: id <file> <name>  |  provider [id] [endpoint]  |  client <providerId> [endpoint]"); break;
            }
        }
        catch (Exception e) when (e is FormatException or InvalidOperationException or ArgumentException)
        {
            // Setup mistakes (old identity file, short PSK, bad --trust...) deserve a sentence, not a stack trace.
            Console.WriteLine("Error: " + e.Message);
            Environment.ExitCode = 1;
        }
    }

    // ── Print a device's fingerprint (creates the identity file if needed) ───
    private static void RunId(Flags f)
    {
        var file = f.Positional(1);
        var name = f.Positional(2);
        if (file is null || name is null) { Console.WriteLine("usage: id <file> <name>"); return; }

        var identity = YuukoIdentity.LoadOrCreate(file, name, f.IdPassword);
        Console.WriteLine($"name:        {identity.ClientId}");
        Console.WriteLine($"fingerprint: {identity.Fingerprint}");
        Console.WriteLine($"file:        {Path.GetFullPath(file)}");
        Console.WriteLine(YuukoIdentity.IsEncryptedIdentity(File.ReadAllBytes(file))
            ? "stored:      ENCRYPTED with a password"
            : "stored:      PLAINTEXT - anyone who can read this file can impersonate this device (use --id-password)");
    }

    // ── Pairing, the easy way: no fingerprints or addresses to type ──────────
    //
    //   Device A:  dotnet run --project YuukoSandbox -- offer <name> [--code-file code.txt] [--minutes 5]
    //                prints a pairing code (also written to --code-file). It is a SECRET until it has been used.
    //   Device B:  dotnet run --project YuukoSandbox -- join "<code>" --name <its own name> [--cmd echo --payload hi]
    //                pairs, then optionally runs a command on A. After this the two trust each other's keys.
    //
    //   TLS is on unless you say --no-tls. Each device makes its own certificate the first time (in its app-data
    //   folder, or --tls-dir). Both flags apply to `offer` and `join`.
    private static async Task RunOffer(Flags f)
    {
        var name = f.Positional(1) ?? "offerer";
        var zopts = new ZenohBrokerOptions { DeviceName = name, TlsDirectory = f.Get("tls-dir") };
        f.ApplyTls(zopts);
        using var transport = ZenohBroker.Open(zopts);

        var identity = f.Get("identity") is { } file ? YuukoIdentity.LoadOrCreate(file, name, f.IdPassword) : YuukoIdentity.Create(name);
        var opts = new EclipseBrokerOptions();
        opts.Handshake.RequireKnownDevices = true;          // nobody gets in without the code or a pin
        f.ApplyHandshake(opts.Handshake);
        using var node = EclipseBroker.Create(transport, identity, opts);
        await node.StartAsync();
        node.On("echo", (ctx, ct) => Task.FromResult(CommandResult.Ok(ctx.Payload)));

        var done = new TaskCompletionSource<string>();
        node.DevicePaired += (id, fp) => done.TrySetResult(id);

        var minutes = int.TryParse(f.Get("minutes"), out var m) ? m : 5;
        var offer = node.BeginPairing(TimeSpan.FromMinutes(minutes));
        if (f.Get("code-file") is { } codeFile) File.WriteAllText(codeFile, offer.Code);
        Console.WriteLine($"[offer] '{name}' listening on {string.Join(", ", transport.ListenEndpoints)}  (TLS {(zopts.EnableTls ? "on" : "OFF")})");
        Console.WriteLine($"[offer] pairing code (valid {minutes} min, one use):");
        Console.WriteLine(offer.Code);

        using var stop = new CancellationTokenSource(TimeSpan.FromMinutes(minutes + 1));
        Console.CancelKeyPress += (_, e) => { e.Cancel = true; stop.Cancel(); };
        try
        {
            var who = await done.Task.WaitAsync(stop.Token);
            Console.WriteLine($"[offer] PAIRED with '{who}'. Trusted devices now: {string.Join(", ", node.Devices.All().Select(d => d.Moniker))}");
            await Task.Delay(TimeSpan.FromSeconds(f.Has("stay") ? 3600 : 6), stop.Token);   // stay up so the new device can run commands
        }
        catch (OperationCanceledException) { Console.WriteLine("[offer] stopped without pairing."); }
    }

    private static async Task RunJoin(Flags f)
    {
        var codeText = f.Positional(1);
        if (codeText is null) { Console.WriteLine("usage: join \"<code>\" --name <this device's name>"); return; }
        if (!PairingCode.TryParse(codeText, out var code, out var error)) { Console.WriteLine("Error: " + error); Environment.ExitCode = 1; return; }

        var name = f.Get("name") ?? "joiner";
        // The code names the other device's address and certificate; this builds transport options that use them.
        var zopts = code!.ToTransportOptions(name, f.Get("tls-dir"));
        f.ApplyTls(zopts);
        using var transport = ZenohBroker.Open(zopts);

        var identity = f.Get("identity") is { } file ? YuukoIdentity.LoadOrCreate(file, name, f.IdPassword) : YuukoIdentity.Create(name);
        var opts = new EclipseBrokerOptions();
        f.ApplyHandshake(opts.Handshake);
        using var node = EclipseBroker.Create(transport, identity, opts);

        var result = await node.PairWithAsync(code, moniker: f.Get("as"));
        if (!result.Success) { Console.WriteLine("[join] FAILED: " + result.Failure); Environment.ExitCode = 2; return; }
        Console.WriteLine($"[join] PAIRED with '{result.DeviceId}' (nickname '{result.Moniker}'). It is now trusted by key.");

        if (f.Get("cmd") is { } command)
        {
            var ack = await node.SendCommandAsync(result.DeviceId!, command, Encoding.UTF8.GetBytes(f.Get("payload") ?? ""));
            Console.WriteLine($"[join] {command} -> {ack}  result=\"{ack.ResultAsString()}\"");
        }
    }

    // ── Device A: provider ───────────────────────────────────────────────────
    private static async Task RunProvider(Flags f)
    {
        var id = f.Positional(1) ?? "provider-demo";
        var listen = f.Positional(2); // e.g. tcp/0.0.0.0:7447

        // 1. Transport: how bytes move between devices (Zenoh = peer-to-peer).
        var zopts = new ZenohBrokerOptions();
        if (listen is not null) zopts.ListenEndpoints.Add(listen);
        f.ApplyTls(zopts);
        using var transport = ZenohBroker.Open(zopts);

        // 2. Identity: this device's post-quantum (Kyber-1024) keypair.
        var identity = f.Get("identity") is { } file ? YuukoIdentity.LoadOrCreate(file, id, f.IdPassword) : YuukoIdentity.Create(id);

        // 3. The secure overlay: handshake + per-peer encrypted sessions.
        var opts = new EclipseBrokerOptions();
        f.ApplyHandshake(opts.Handshake);
        // opts.Handshake.BannedClients.Add("known-bad-app");   // admission control
        using var node = EclipseBroker.Create(transport, identity, opts);
        await node.StartAsync();

        // 4. Put data out. Same name overwrites (retained store); Tombstone deletes.
        var counter = 0;
        node.Serve(DataTopic, YuukoPacket.FromBytes("hello", Encoding.UTF8.GetBytes("Hello from " + id)));

        // Commands other devices can run here. Each handler gets who asked and what they sent.
        node.On("echo", (ctx, ct) => Task.FromResult(CommandResult.Ok(ctx.Payload)));
        node.On("time", (ctx, ct) => Task.FromResult(CommandResult.Ok(DateTimeOffset.Now.ToString("O"))));
        Console.WriteLine($"[provider] '{id}'  fingerprint {identity.Fingerprint}");
        Console.WriteLine($"[provider] {Describe(opts.Handshake)}");
        Console.WriteLine($"[provider] serving '{DataTopic}'. Ctrl+C to stop.");

        using var stop = new CancellationTokenSource();
        Console.CancelKeyPress += (_, e) => { e.Cancel = true; stop.Cancel(); };
        try
        {
            while (!stop.IsCancellationRequested)
            {
                await Task.Delay(TimeSpan.FromSeconds(5), stop.Token);
                node.Serve(DataTopic, YuukoPacket.FromBytes("tick",
                    Encoding.UTF8.GetBytes($"tick #{++counter} at {DateTime.Now:T}")));
            }
        }
        catch (OperationCanceledException) { }
    }

    // ── Device B: client ─────────────────────────────────────────────────────
    private static async Task RunClient(Flags f)
    {
        var providerId = f.Positional(1);
        if (providerId is null) { Console.WriteLine("client needs <providerId>"); return; }
        var connect = f.Positional(2); // e.g. tcp/192.168.1.10:7447

        var zopts = new ZenohBrokerOptions();
        if (connect is not null) zopts.ConnectEndpoints.Add(connect);
        f.ApplyTls(zopts);
        using var transport = ZenohBroker.Open(zopts);

        var name = f.Get("name") ?? "client-" + Guid.NewGuid().ToString("N")[..6];
        var identity = f.Get("identity") is { } file ? YuukoIdentity.LoadOrCreate(file, name, f.IdPassword) : YuukoIdentity.Create(name);

        var opts = new EclipseBrokerOptions();
        f.ApplyHandshake(opts.Handshake);
        using var node = EclipseBroker.Create(transport, identity, opts);

        // --cmd: run a command on the provider (optionally many at once) instead of fetching data.
        if (f.Get("cmd") is { } command)
        {
            var payload = Encoding.UTF8.GetBytes(f.Get("payload") ?? "");
            int count = int.TryParse(f.Get("count"), out var c) ? Math.Max(1, c) : 1;
            var sw = Stopwatch.StartNew();
            var acks = await Task.WhenAll(Enumerable.Range(0, count).Select(_ => node.SendCommandAsync(providerId, command, payload)));
            Console.WriteLine($"[client] {acks.Count(a => a.IsOk)}/{count} ok in {sw.ElapsedMilliseconds} ms; first: {acks[0]}  result=\"{acks[0].ResultAsString()}\"");
            return;
        }

        // First RequestAsync to a provider does the handshake automatically,
        // then every later call reuses the encrypted session.
        var packets = await node.RequestAsync(providerId, DataTopic);

        if (packets.Count == 0)
        {
            Console.WriteLine("[client] no data - provider unreachable, refused us (not trusted / wrong key / wrong PSK / banned), or topic is empty.");
            return;
        }
        foreach (var p in packets)
            Console.WriteLine($"[client] {p.Name}: {p.DataAsString()}");
    }

    private static string Describe(HandshakeOptions h)
    {
        var who = h.RequireKnownDevices ? $"LOCKED to {h.TrustedDevices.Count} pinned device(s)" : "OPEN: any device that reaches this port may connect";
        var psk = h.RequirePreSharedKey ? "PSK required" : "no PSK";
        return $"{who}; {psk}";
    }

    // ── tiny arg helper (so the template has no dependencies) ────────────────
    private sealed class Flags
    {
        private readonly List<string> _positional = new();
        private readonly Dictionary<string, List<string?>> _flags = new(StringComparer.OrdinalIgnoreCase);

        public static Flags Parse(string[] args)
        {
            var f = new Flags();
            for (int i = 0; i < args.Length; i++)
            {
                if (args[i].StartsWith("--"))
                {
                    var key = args[i][2..];
                    var hasValue = i + 1 < args.Length && !args[i + 1].StartsWith("--");
                    if (!f._flags.TryGetValue(key, out var list)) f._flags[key] = list = new List<string?>();
                    list.Add(hasValue ? args[++i] : null);
                }
                else f._positional.Add(args[i]);
            }
            return f;
        }

        public string? Positional(int i) => i < _positional.Count ? _positional[i] : null;

        /// <summary>Password for the identity file: --id-password, else the YUUKO_ID_PASSWORD environment variable.</summary>
        public string? IdPassword => Get("id-password") ?? Environment.GetEnvironmentVariable("YUUKO_ID_PASSWORD");
        public bool Has(string key) => _flags.ContainsKey(key);
        public string? Get(string key) => _flags.TryGetValue(key, out var l) ? l.LastOrDefault(v => v is not null) : null;
        public IEnumerable<string> All(string key) =>
            _flags.TryGetValue(key, out var l) ? l.Where(v => v is not null).Select(v => v!) : Enumerable.Empty<string>();

        public void ApplyTls(ZenohBrokerOptions o)
        {
            // TLS is ON by default (the device makes its own certificate). --no-tls turns it off, which also brings LAN
            // auto-discovery back. --ca/--cert/--key bring your own files instead of the automatic ones.
            if (Has("no-tls")) { o.EnableTls = false; return; }
            o.EnableTls = true;
            if (Get("tls-dir") is { } dir) o.TlsDirectory = dir;      // where this device's automatic certificate lives
            if (Get("tls-name") is { } who) o.DeviceName = who;
            if (Get("ca") is { } ca) o.TlsRootCaCertificate = ca;
            if (Get("cert") is { } cert) { o.TlsListenCertificate = cert; o.TlsConnectCertificate = cert; }
            if (Get("key") is { } key) { o.TlsListenPrivateKey = key; o.TlsConnectPrivateKey = key; }
            o.TlsEnableMutual = !Has("no-mtls");   // mutual TLS is the default: strangers are turned away at the TLS layer
        }

        public void ApplyHandshake(HandshakeOptions h)
        {
            var psk = Get("psk") ?? Environment.GetEnvironmentVariable("YUUKO_PSK");
            if (!string.IsNullOrEmpty(psk))
            {
                h.PreSharedKey = Encoding.UTF8.GetBytes(psk);
                h.RequirePreSharedKey = true;     // refuse to start with a key that is too short
            }

            foreach (var t in All("trust"))
            {
                var eq = t.IndexOf('=');
                if (eq <= 0) throw new ArgumentException($"--trust expects name=fingerprint, got '{t}'.");
                h.TrustDevice(t[..eq], t[(eq + 1)..]);   // also switches allowlist mode on
            }
        }
    }
}
