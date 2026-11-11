using System.Collections.Concurrent;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using YuukoProtocol;

namespace YuukoSandbox;

// ─────────────────────────────────────────────────────────────────────────────
// Self-test for the secure core. Everything runs in-process over LocalBroker, so it needs
// no network and no native zenoh-c:
//
//     dotnet run --project YuukoSandbox -- selftest
//
// It checks the things that should work AND the attacks that should fail. A "PASS" next to an
// attack means the attack was refused. Exit code is 0 only if everything passed.
//
// Tests are grouped by feature; each group is a method below. To add one, copy a Check(...) line.
// ─────────────────────────────────────────────────────────────────────────────
public static partial class SelfTest
{
    private static int _failures;
    private static int _checks;

    private static void Check(string name, bool ok)
    {
        _checks++;
        Console.WriteLine($"[{(ok ? "PASS" : "FAIL")}] {name}");
        if (!ok) _failures++;
    }

    private static void Section(string title) => Console.WriteLine($"\n-- {title}");

    public static async Task<int> RunAsync()
    {
        Console.WriteLine("== YuukoProtocol self-test (in-process LocalBroker) ==");
        var sw = Stopwatch.StartNew();

        await Identity();
        await Allowlist();
        await PreSharedKey();
        await ProviderAuthentication();
        await HandshakeAbuse();
        await Peers();
        await Kicking();
        await Commands();
        await Relay();
        TlsCertificates();
        TlsGroups();
        PairingCodes();
        await Pairing();
        await PairingWithTls();
        await GroupChanges();
        await SessionHealing();
        await Presence();
        await DeviceDirectoryTests();
        await DeviceDirectoryFile();
        await AuditLogTests();
        OtAlgebra();
        OtServerAndClient();
        await OtNetworkTests();
        await CrdtTests();
        await HolyMotherTests();
        await HolyIconTests();
        await DagTests();
        await CogitariumTests();
        await NearbyTests();
        await ForwardSecrecy();
        await TamperedThrowAwayKey();
        await IdentityAtRest();
        await Rotation();
        await Regression();

        Console.WriteLine(_failures == 0
            ? $"\nALL PASS ({_checks} checks, {sw.Elapsed.TotalSeconds:F1}s)"
            : $"\n{_failures} FAILED of {_checks} ({sw.Elapsed.TotalSeconds:F1}s)");
        return _failures == 0 ? 0 : 1;
    }

    // ── helpers ──────────────────────────────────────────────────────────────

    private static HandshakeOptions Opts(Action<HandshakeOptions>? f = null)
    {
        var o = new HandshakeOptions { Timeout = TimeSpan.FromSeconds(3) };
        f?.Invoke(o);
        return o;
    }

    // Did a session come back, and how long did it take? (A refusal should be near-instant.)
    private static async Task<(bool ok, long ms)> TryConnect(IYuukoApi t, YuukoIdentity id, HandshakeOptions o, string provider)
    {
        var sw = Stopwatch.StartNew();
        using var h = new YuukoHandshake(t, id, o);
        var s = await h.RequestSessionAsync(provider);
        return (s is not null, sw.ElapsedMilliseconds);
    }

    private static async Task<YuukoHandshake> StartProvider(IYuukoApi t, YuukoIdentity id, HandshakeOptions o)
    {
        var p = new YuukoHandshake(t, id, o);
        await p.StartAsync();
        return p;
    }

    /// <summary>
    /// A transport wrapper for staging attacks. Every packet published through it is recorded, and
    /// <see cref="OnPublish"/> may drop it (return null) or swap in a changed copy.
    /// </summary>
    private sealed class Tap : IYuukoApi
    {
        private readonly IYuukoApi _inner;
        public Func<string, YuukoPacket, YuukoPacket?>? OnPublish;
        public readonly ConcurrentQueue<string> Seen = new();

        public Tap(IYuukoApi inner) => _inner = inner;

        public Task PublishAsync(string topic, YuukoPacket packet, CancellationToken ct = default)
        {
            Seen.Enqueue(Encoding.UTF8.GetString(packet.Data));
            if (OnPublish is null) return _inner.PublishAsync(topic, packet, ct);
            var changed = OnPublish(topic, packet);
            return changed is null ? Task.CompletedTask : _inner.PublishAsync(topic, changed, ct);
        }

        public Task<IReadOnlyList<YuukoPacket>> RequestAsync(string topic, CancellationToken ct = default) => _inner.RequestAsync(topic, ct);
        public Task SubscribeAsync(string topic, Func<YuukoPacket, Task> handler, CancellationToken ct = default) => _inner.SubscribeAsync(topic, handler, ct);
        public Task UnsubscribeAsync(string topic, Func<YuukoPacket, Task> handler, CancellationToken ct = default) => _inner.UnsubscribeAsync(topic, handler, ct);
    }

    // The wire format is plain JSON, so an attacker's edit is just a JSON edit.
    private static YuukoPacket Edit(YuukoPacket p, Action<JsonObject> change)
    {
        var obj = JsonNode.Parse(p.Data)!.AsObject();
        change(obj);
        return YuukoPacket.Ephemeral(p.Name, Encoding.UTF8.GetBytes(obj.ToJsonString()));
    }

    // HandshakeType numbers on the wire.
    private const int Hello = 0, Challenge = 1, Response = 2, Accept = 3, Reject = 4;

    private static int HandshakeTypeOf(YuukoPacket p) => JsonNode.Parse(p.Data)!["Type"]!.GetValue<int>();

    private static string FlipFirstByte(string base64)
    {
        var b = Convert.FromBase64String(base64);
        b[0] ^= 0xFF;
        return Convert.ToBase64String(b);
    }

    // ── identity ─────────────────────────────────────────────────────────────

    private static async Task Identity()
    {
        Section("identity");
        var alice = YuukoIdentity.Create("alice");
        Check("fingerprint is 64 lowercase hex chars", alice.Fingerprint.Length == 64 && alice.Fingerprint.All(Uri.IsHexDigit) && alice.Fingerprint == alice.Fingerprint.ToLowerInvariant());
        Check("fingerprint matches the exported public keys", YuukoIdentity.FingerprintOf(alice.ExportPublicKeys()) == alice.Fingerprint);
        Check("two identities have different fingerprints", YuukoIdentity.Create("alice").Fingerprint != alice.Fingerprint);

        var restored = YuukoIdentity.Import(alice.Export());
        Check("export/import keeps ClientId + fingerprint", restored.ClientId == "alice" && restored.Fingerprint == alice.Fingerprint);

        var file = Path.Combine(Path.GetTempPath(), "yuuko-selftest-" + Guid.NewGuid().ToString("N") + ".id");
        try
        {
            var first = YuukoIdentity.LoadOrCreate(file, "dev-1");
            var second = YuukoIdentity.LoadOrCreate(file, "dev-1");
            Check("LoadOrCreate returns the SAME identity on the second call", first.Fingerprint == second.Fingerprint);
            bool refused = false;
            try { YuukoIdentity.LoadOrCreate(file, "someone-else"); } catch (InvalidOperationException) { refused = true; }
            Check("LoadOrCreate refuses to silently switch ClientId", refused);
        }
        finally { File.Delete(file); }

        // Splice halves from two identities together: each of these must be caught on import.
        var a = JsonNode.Parse(YuukoIdentity.Create("a").Export())!;
        var b = JsonNode.Parse(YuukoIdentity.Create("b").Export())!;
        var swapKyber = JsonNode.Parse(a.ToJsonString())!; swapKyber["KyberPrivate"] = b["KyberPrivate"]!.DeepClone();
        var swapSigning = JsonNode.Parse(a.ToJsonString())!; swapSigning["SigningPrivate"] = b["SigningPrivate"]!.DeepClone();
        Check("Import rejects a Kyber public/private mismatch", ImportFails(swapKyber.ToJsonString()));
        Check("Import rejects a signing public/private mismatch", ImportFails(swapSigning.ToJsonString()));
        Check("Import rejects garbage", ImportFails("not json"));
        var v1 = JsonNode.Parse(a.ToJsonString())!; v1["Version"] = 1;
        Check("Import explains an old (v1) identity file instead of loading it", ImportFails(v1.ToJsonString(), "older version"));
        await Task.CompletedTask;

        static bool ImportFails(string text, string? mustMention = null)
        {
            try { YuukoIdentity.Import(Encoding.UTF8.GetBytes(text)); return false; }
            catch (FormatException e) { return mustMention is null || e.Message.Contains(mustMention); }
        }
    }

    // ── allowlist / key pinning ──────────────────────────────────────────────

    private static async Task Allowlist()
    {
        Section("allowlist (key pinning)");
        var alice = YuukoIdentity.Create("alice");
        var restored = YuukoIdentity.Import(alice.Export());
        {
            using var t = new LocalBroker();
            var po = Opts(o => o.TrustDevice("alice", alice.Fingerprint));
            using var prov = await StartProvider(t, YuukoIdentity.Create("provider"), po);

            Check("pinned device with its real keys CONNECTS", (await TryConnect(t, alice, Opts(), "provider")).ok);
            Check("same device after export/import still connects (restart-safe)", (await TryConnect(t, restored, Opts(), "provider")).ok);

            var stranger = await TryConnect(t, YuukoIdentity.Create("mallory"), Opts(), "provider");
            Check($"unknown id is rejected ({stranger.ms} ms, no timeout wait)", !stranger.ok && stranger.ms < 1500);

            var impostor = await TryConnect(t, YuukoIdentity.Create("alice"), Opts(), "provider");   // claims alice, different keys
            Check($"known id with DIFFERENT keys is rejected ({impostor.ms} ms)", !impostor.ok && impostor.ms < 1500);

            po.UntrustDevice("alice");
            po.TrustDevice("someone-else", YuukoIdentity.Create("x").Fingerprint);   // allowlist stays on
            Check("after UntrustDevice a new handshake from that id is rejected", !(await TryConnect(t, YuukoIdentity.Create("alice"), Opts(), "provider")).ok);
        }
        {
            using var t = new LocalBroker();
            var po = Opts(o => { o.TrustDevice("alice", alice.Fingerprint); o.BannedClients.Add("alice"); });
            using var prov = await StartProvider(t, YuukoIdentity.Create("provider"), po);
            Check("ban still wins over the allowlist", !(await TryConnect(t, alice, Opts(), "provider")).ok);
        }
        bool badFp = false;
        try { Opts().TrustDevice("x", "not-a-fingerprint"); } catch (ArgumentException) { badFp = true; }
        Check("TrustDevice rejects a malformed fingerprint", badFp);
    }

    // ── pre-shared key ───────────────────────────────────────────────────────

    private static async Task PreSharedKey()
    {
        Section("pre-shared key");
        var psk = RandomNumberGenerator.GetBytes(32);
        {
            using var t = new LocalBroker();
            using var prov = await StartProvider(t, YuukoIdentity.Create("provider"), Opts(o => { o.PreSharedKey = psk; o.RequirePreSharedKey = true; }));

            Check("client WITH the key connects", (await TryConnect(t, YuukoIdentity.Create("c1"), Opts(o => o.PreSharedKey = psk), "provider")).ok);
            var noKey = await TryConnect(t, YuukoIdentity.Create("c2"), Opts(), "provider");
            Check($"client WITHOUT the key fails ({noKey.ms} ms)", !noKey.ok);
            Check("client with the WRONG key fails", !(await TryConnect(t, YuukoIdentity.Create("c3"), Opts(o => o.PreSharedKey = RandomNumberGenerator.GetBytes(32)), "provider")).ok);
        }
        Check("RequirePreSharedKey refuses a key shorter than 16 bytes", Throws<InvalidOperationException>(() =>
            new YuukoHandshake(new LocalBroker(), YuukoIdentity.Create("p"), Opts(o => { o.PreSharedKey = new byte[8]; o.RequirePreSharedKey = true; }))));
        Check("RequirePreSharedKey refuses an empty key", Throws<InvalidOperationException>(() =>
            new YuukoHandshake(new LocalBroker(), YuukoIdentity.Create("p"), Opts(o => o.RequirePreSharedKey = true))));
    }

    private static bool Throws<T>(Action a) where T : Exception
    {
        try { a(); return false; } catch (T) { return true; }
    }

    // ── provider authentication ──────────────────────────────────────────────

    private static async Task ProviderAuthentication()
    {
        Section("provider authentication (is the thing that answered really the device I pinned?)");
        var real = YuukoIdentity.Create("provider");
        var client = YuukoIdentity.Create("client");

        {
            using var t = new LocalBroker();
            using var prov = await StartProvider(t, real, Opts());
            var pinned = await TryConnect(t, client, Opts(o => o.TrustDevice("provider", real.Fingerprint)), "provider");
            Check("requester pinned to the real provider CONNECTS", pinned.ok);
            Console.WriteLine($"       (handshake incl. Dilithium5 sign+verify took {pinned.ms} ms)");

            var wrongPin = await TryConnect(t, client, Opts(o => o.TrustDevice("provider", YuukoIdentity.Create("x").Fingerprint)), "provider");
            Check($"requester pinned to a DIFFERENT fingerprint refuses the real provider ({wrongPin.ms} ms)", !wrongPin.ok && wrongPin.ms < 1500);
        }
        {
            // The impostor has the right NAME but its own keys. The real provider is not on the mesh at all.
            using var t = new LocalBroker();
            var impostor = YuukoIdentity.Create("provider");
            using var imp = await StartProvider(t, impostor, Opts());

            var pinned = await TryConnect(t, client, Opts(o => o.TrustDevice("provider", real.Fingerprint)), "provider");
            Check($"IMPOSTOR answering as 'provider' is refused by a pinned requester ({pinned.ms} ms)", !pinned.ok && pinned.ms < 1500);

            var unpinned = await TryConnect(t, client, Opts(), "provider");
            Check("(documented limit) with NO pin there is nothing to check against, so the impostor is accepted", unpinned.ok);
        }
        {
            // Flip one byte of the provider's signature in flight.
            using var raw = new LocalBroker();
            bool tamper = false;
            var tap = new Tap(raw)
            {
                OnPublish = (_, p) => tamper && HandshakeTypeOf(p) == Challenge
                    ? Edit(p, o => o["Signature"] = FlipFirstByte(o["Signature"]!.GetValue<string>()))
                    : p,
            };
            using var prov = await StartProvider(tap, real, Opts());
            // The requester talks to 'raw' for its own sends but hears the tapped provider's answers.
            Check("(control) same setup with no tampering connects", (await TryConnect(raw, client, Opts(), "provider")).ok);
            tamper = true;
            var r = await TryConnect(raw, client, Opts(), "provider");
            Check("a tampered signature is refused even with NO pin", !r.ok);
        }
        {
            // Replay: record a genuine CHALLENGE, then feed it to the same requester during a NEW handshake.
            using var raw = new LocalBroker();
            YuukoPacket? recorded = null;
            YuukoPacket? replay = null;
            var tap = new Tap(raw)
            {
                OnPublish = (_, p) =>
                {
                    if (HandshakeTypeOf(p) != Challenge) return p;
                    if (recorded is null) { recorded = p; return p; }          // handshake 1: let it through
                    // handshake 2: swap in the old challenge, relabelled so the requester will look at it
                    var newId = JsonNode.Parse(p.Data)!["HandshakeId"]!.GetValue<string>();
                    replay = Edit(recorded, o => o["HandshakeId"] = newId);
                    return replay;
                },
            };
            using var prov = await StartProvider(tap, real, Opts());
            var first = await TryConnect(raw, client, Opts(o => o.TrustDevice("provider", real.Fingerprint)), "provider");
            var second = await TryConnect(raw, client, Opts(o => o.TrustDevice("provider", real.Fingerprint)), "provider");
            Check("first handshake works (this is the genuine challenge being recorded)", first.ok);
            Check("replaying that old CHALLENGE into a new handshake is refused", replay is not null && !second.ok);
        }
        {
            // Forged ACCEPT: swallow the real one and inject a fake. The requester must not believe it.
            using var raw = new LocalBroker();
            bool forge = false;
            var tap = new Tap(raw)
            {
                OnPublish = (_, p) => forge && HandshakeTypeOf(p) == Accept
                    ? Edit(p, o => o["EncAccept"] = Convert.ToBase64String(RandomNumberGenerator.GetBytes(64)))
                    : p,
            };
            using var prov = await StartProvider(tap, real, Opts());
            Check("(control) same setup with a genuine ACCEPT connects", (await TryConnect(raw, client, Opts(), "provider")).ok);
            forge = true;
            var r = await TryConnect(raw, client, Opts(o => o.Timeout = TimeSpan.FromSeconds(1)), "provider");
            Check("a forged ACCEPT does not establish a session", !r.ok);
        }
    }

    // ── handshake abuse ──────────────────────────────────────────────────────

    private static async Task HandshakeAbuse()
    {
        Section("handshake abuse (malformed input, flooding)");

        // Hand-built HELLOs that are wrong in different ways. None should hurt the provider.
        {
            using var t = new LocalBroker();
            var provId = YuukoIdentity.Create("provider");
            using var prov = await StartProvider(t, provId, Opts());

            async Task Send(Action<JsonObject> shape)
            {
                var o = new JsonObject
                {
                    ["Type"] = Hello, ["FromId"] = "evil", ["ToId"] = "provider", ["HandshakeId"] = Guid.NewGuid().ToString("N"),
                    ["KyberPub"] = new JsonObject { ["t"] = "AAAA", ["rho"] = "AAAA" },
                    ["SigPub"] = new JsonObject { ["rho"] = "AAAA", ["t1"] = "AAAA" },
                    ["NonceC"] = Convert.ToBase64String(new byte[16]),
                };
                shape(o);
                await t.PublishAsync("yuuko/handshake", YuukoPacket.Ephemeral("Hello:x", Encoding.UTF8.GetBytes(o.ToJsonString())));
            }

            await Send(_ => { });                                           // garbage key material
            await Send(o => o.Remove("KyberPub"));                          // missing keys
            await Send(o => o.Remove("SigPub"));
            await Send(o => o.Remove("NonceC"));
            await Send(o => o["FromId"] = new string('x', 5000));           // absurd id
            await Send(o => o["FromId"] = "");                              // empty id
            await t.PublishAsync("yuuko/handshake", YuukoPacket.Ephemeral("junk", Encoding.UTF8.GetBytes("{not json")));
            Check("malformed HELLOs are ignored and the provider still works afterwards",
                (await TryConnect(t, YuukoIdentity.Create("good"), Opts(), "provider")).ok);
        }

        // Pending-handshake cap + expiry: attackers that never finish tie up slots, then lose them.
        {
            using var raw = new LocalBroker();
            var dropping = new Tap(raw) { OnPublish = (_, p) => HandshakeTypeOf(p) == Response ? null : p };   // never answer the challenge
            using var prov = await StartProvider(raw, YuukoIdentity.Create("provider"),
                Opts(o => { o.MaxPendingHandshakes = 3; o.Timeout = TimeSpan.FromMilliseconds(1500); }));

            var hung = Enumerable.Range(0, 3).Select(i =>
                TryConnect(dropping, YuukoIdentity.Create("atk" + i), Opts(o => o.Timeout = TimeSpan.FromMilliseconds(1000)), "provider")).ToArray();
            await Task.Delay(150);

            var shed = await TryConnect(raw, YuukoIdentity.Create("good-1"), Opts(o => o.Timeout = TimeSpan.FromMilliseconds(800)), "provider");
            Check("with the pending cap full, a new HELLO is shed (dropped)", !shed.ok);

            await Task.WhenAll(hung);
            await Task.Delay(900);                                          // the stuck entries are now past their expiry
            Check("after the stuck entries expire, the next HELLO purges them and connects",
                (await TryConnect(raw, YuukoIdentity.Create("good-2"), Opts(), "provider")).ok);
        }
    }
}
