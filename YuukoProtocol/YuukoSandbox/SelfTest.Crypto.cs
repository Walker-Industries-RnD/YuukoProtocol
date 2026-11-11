using System.Collections.Concurrent;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using Pariah_Cybersecurity;
using YuukoProtocol;

namespace YuukoSandbox;

// Tests for the deeper cryptographic properties: forward secrecy, a tampered throw-away key, identity
// files encrypted at rest, and session rotation. Same helpers (Check / Tap / Edit / Node) as the other files.
public static partial class SelfTest
{
    private const string HandshakeTopic = "yuuko/handshake";

    private static Dictionary<string, byte[]> Dict(JsonNode? n) =>
        n!.AsObject().ToDictionary(kv => kv.Key, kv => Convert.FromBase64String(kv.Value!.GetValue<string>()));

    private static byte[] B64(JsonNode? n) => Convert.FromBase64String(n!.GetValue<string>());

    private static JsonObject ToJson(Dictionary<string, byte[]> d)
    {
        var o = new JsonObject();
        foreach (var kv in d) o[kv.Key] = Convert.ToBase64String(kv.Value);
        return o;
    }

    // ── forward secrecy ──────────────────────────────────────────────────────

    private static async Task ForwardSecrecy()
    {
        Section("forward secrecy (a stolen identity must not unlock a recording)");
        const string secretText = "TOP-SECRET-PAYLOAD-12345";

        var pid = YuukoIdentity.Create("provider");
        var cid = YuukoIdentity.Create("client");
        using var raw = new LocalBroker();
        var tap = new Tap(raw);
        using var prov = Node(tap, pid);
        using var cli = Node(tap, cid);
        prov.On("vault", (ctx, ct) => Task.FromResult(CommandResult.Ok("stored")));
        await prov.StartAsync();
        await cli.StartAsync();

        var ack = await cli.SendCommandAsync("provider", "vault", Bytes(secretText));
        Check("(control) the command goes through", ack.IsOk);

        // The attacker has: a full recording of the wire, and BOTH devices' long-term identity (stolen later).
        var wire = tap.Seen.Select(t => JsonNode.Parse(t)!.AsObject()).ToList();
        var hello = wire.First(o => o["HandshakeId"] is not null && o["Type"]?.GetValue<int>() == Hello);
        var chal = wire.First(o => o["HandshakeId"] is not null && o["Type"]?.GetValue<int>() == Challenge);
        var cmd = wire.First(o => o["requestId"] is not null && o["type"]?.GetValue<int>() == DCmd);

        byte[] nonceC = B64(hello["NonceC"]), nonceS = B64(chal["NonceS"]), sessionId = B64(chal["SessionId"]);
        byte[] kemCipher = B64(chal["KemCipher"]), kemCipherEph = B64(chal["KemCipherEph"]);
        var requesterFp = YuukoIdentity.FingerprintOf(new PublicKeys(Dict(hello["KyberPub"]), Dict(hello["SigPub"])));
        var ephDigest = YuukoIdentity.KyberPublicDigest(Dict(hello["EphKyberPub"]));
        byte[] transcript = YuukoHandshake.TranscriptHash(hello["HandshakeId"]!.GetValue<string>(),
            "provider", "client", pid.Fingerprint, requesterFp, nonceC, nonceS, kemCipher, ephDigest, kemCipherEph, sessionId);

        // Everything a thief of the client's identity file can compute: open the long-term KEM ciphertext.
        byte[] secretLong = EasyPQC.Keys.CreateSecretTwo(new Dictionary<string, byte[]>(cid.KyberPrivate), kemCipher);

        bool Opens(byte[]? guessAtEphemeralSecret)
        {
            try
            {
                var (c2s, s2c) = YuukoHandshake.DeriveSessionKeys(Array.Empty<byte>(), nonceC, transcript, secretLong, guessAtEphemeralSecret);
                using var observer = new HandshakeSession("provider", "client", "client", sendKey: s2c, recvKey: c2s,
                    baseSessionId: sessionId, maxLanes: 8, isInitiator: false, remoteFingerprint: requesterFp);
                var plain = observer.DecryptOnLane(cmd["lane"]!.GetValue<int>(), B64(cmd["payload"]), "CMD");
                return plain.Length > 0;   // AES-GCM only returns data if the key was right
            }
            catch { return false; }
        }

        Check("a long-term-key thief cannot open the recorded command (using what they can compute)", !Opens(null));
        Check("...nor by guessing the throw-away secret as zeros", !Opens(new byte[32]));
        Check("...nor by reusing the long-term secret in its place", !Opens(secretLong));
        Check("the secret text is not visible anywhere on the wire", !string.Join("\n", tap.Seen).Contains(secretText)
            && !tap.Seen.Any(t => t.Contains(Convert.ToBase64String(Bytes(secretText)))));

        // Each handshake uses a different throw-away key, so two sessions never share one.
        var again = Node(tap, YuukoIdentity.Create("client2"));
        await again.StartAsync();
        await again.PingAsync("provider");
        var hellos = tap.Seen.Select(t => JsonNode.Parse(t)!.AsObject())
            .Where(o => o["HandshakeId"] is not null && o["Type"]?.GetValue<int>() == Hello)
            .Select(o => o["EphKyberPub"]!.ToJsonString()).ToList();
        again.Dispose();
        Check("every handshake sends a DIFFERENT throw-away key", hellos.Count >= 2 && hellos.Distinct().Count() == hellos.Count);
    }

    // The throw-away key travels in HELLO. Swapping it for the attacker's own must not get anywhere.
    private static async Task TamperedThrowAwayKey()
    {
        Section("tampered throw-away key");
        var real = YuukoIdentity.Create("provider");
        var client = YuukoIdentity.Create("client");
        var (attackerPub, _) = EasyPQC.Keys.Initiate();

        using var raw = new LocalBroker();
        bool swap = false;
        var tap = new Tap(raw)
        {
            OnPublish = (topic, p) => swap && topic == HandshakeTopic && HandshakeTypeOf(p) == Hello
                ? Edit(p, o => o["EphKyberPub"] = ToJson(attackerPub))
                : p,
        };
        using var prov = await StartProvider(raw, real, Opts());
        Check("(control) an untouched HELLO connects", (await TryConnect(tap, client, Opts(), "provider")).ok);
        swap = true;
        var r = await TryConnect(tap, client, Opts(), "provider");
        Check($"a HELLO whose throw-away key was swapped for the attacker's gets nowhere ({r.ms} ms)", !r.ok);
    }

    // ── identity files, encrypted at rest (Pariah: Argon2id + AES-256-GCM) ────

    private static async Task IdentityAtRest()
    {
        Section("identity files at rest");
        string dir = Path.Combine(Path.GetTempPath(), "yuuko-idtest-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        try
        {
            const string pw = "correct horse battery";
            string file = Path.Combine(dir, "a.id");

            var id = YuukoIdentity.LoadOrCreate(file, "dev", pw);
            byte[] onDisk = File.ReadAllBytes(file);
            string text = Encoding.UTF8.GetString(onDisk);
            Check("a new identity is created ENCRYPTED when a password is given", YuukoIdentity.IsEncryptedIdentity(onDisk));
            Check("...and the file shows no key material or field names", !text.Contains("KyberPrivate") && !text.Contains("SigningPrivate") && !text.Contains("ClientId"));

            // Look for real private bytes in the file, in the two encodings a leak could take.
            var plain = JsonNode.Parse(id.Export())!;
            string leak = plain["KyberPrivate"]!["s"]!.GetValue<string>();
            Check("...nor any piece of the private key", !text.Contains(leak[..24]) && !text.Contains(leak[^24..]));

            var back = YuukoIdentity.LoadOrCreate(file, "dev", pw);
            Check("it loads again with the password, with the same fingerprint", back.Fingerprint == id.Fingerprint && back.ClientId == "dev");

            Check("loading without the password is refused, and says why", FormatMessage(() => YuukoIdentity.LoadOrCreate(file, "dev")).Contains("encrypted"));
            Check("the wrong password is refused", FormatMessage(() => YuukoIdentity.LoadOrCreate(file, "dev", "not the password")).Contains("Wrong password"));

            byte[] flipped = (byte[])onDisk.Clone();
            flipped[^10] ^= 0x01;
            File.WriteAllBytes(file, flipped);
            Check("a file with one changed byte is refused, not loaded", FormatMessage(() => YuukoIdentity.LoadOrCreate(file, "dev", pw)).Contains("Wrong password"));
            File.WriteAllBytes(file, onDisk);

            Check("a password under 8 characters is refused", Throws<ArgumentException>(() => id.Save(Path.Combine(dir, "short.id"), "short")));
            Check("an encrypted identity still refuses to be loaded under another name",
                Throws<InvalidOperationException>(() => YuukoIdentity.LoadOrCreate(file, "someone-else", pw)));

            // Existing plaintext file -> encrypted in place the first time it is loaded with a password.
            string old = Path.Combine(dir, "old.id");
            var legacy = YuukoIdentity.LoadOrCreate(old, "legacy");
            Check("(setup) a plaintext identity file exists", !YuukoIdentity.IsEncryptedIdentity(File.ReadAllBytes(old)));
            Check("a plaintext file still loads without a password", YuukoIdentity.LoadOrCreate(old, "legacy").Fingerprint == legacy.Fingerprint);
            var upgraded = YuukoIdentity.LoadOrCreate(old, "legacy", pw);
            Check("loading it WITH a password encrypts it in place", YuukoIdentity.IsEncryptedIdentity(File.ReadAllBytes(old)) && upgraded.Fingerprint == legacy.Fingerprint);
            Check("...and it is the same device afterwards", YuukoIdentity.LoadOrCreate(old, "legacy", pw).Fingerprint == legacy.Fingerprint);

            // An identity read back from an encrypted file is a fully working one.
            using var bus = new LocalBroker();
            using var prov = await StartProvider(bus, YuukoIdentity.Create("provider"), Opts(o => o.TrustDevice("dev", id.Fingerprint)));
            Check("a device restored from its encrypted file still passes the allowlist", (await TryConnect(bus, back, Opts(), "provider")).ok);
        }
        finally { Directory.Delete(dir, true); }
        await Task.CompletedTask;

        static string FormatMessage(Action a)
        {
            try { a(); return ""; } catch (FormatException e) { return e.Message; } catch (Exception e) { return "WRONG EXCEPTION " + e.GetType().Name; }
        }
    }

    // ── session rotation ─────────────────────────────────────────────────────

    private static async Task Rotation()
    {
        Section("session rotation (keys do not live forever)");
        var age = TimeSpan.FromMilliseconds(300);
        var grace = TimeSpan.FromMilliseconds(300);

        {
            using var bus = new LocalBroker();
            using var prov = Node(bus, YuukoIdentity.Create("provider"), o => { o.Handshake.MaxSessionAge = age; o.Handshake.RotationGrace = grace; });
            using var cli = Node(bus, YuukoIdentity.Create("client"), o => { o.Handshake.MaxSessionAge = age; o.Handshake.RotationGrace = grace; });
            prov.On("n", (ctx, ct) => Task.FromResult(CommandResult.Ok("ok")));
            await prov.StartAsync();
            await cli.StartAsync();
            int connects = 0;
            cli.PeerConnected += _ => Interlocked.Increment(ref connects);

            Check("(control) first command works on the first session", (await cli.SendCommandAsync("provider", "n")).IsOk && connects == 1);

            await Task.Delay(400);   // older than MaxSessionAge, younger than MaxSessionAge + RotationGrace
            var second = await cli.SendCommandAsync("provider", "n");
            Check("a session older than MaxSessionAge is replaced by a fresh handshake, and the command still works", second.IsOk && connects == 2);
            Check("(for a moment both sessions exist)", cli.SessionCountWith("provider") == 2);

            await Task.Delay(700);   // past the old session's grace
            Check("after the grace period the old session is gone (only the new keys remain)", await Eventually(() => cli.SessionCountWith("provider") == 1));
            Check("and everything keeps working on the new session", (await cli.SendCommandAsync("provider", "n")).IsOk);
        }
        {
            // The receiving side enforces the limit on its own: a client that never rotates is made to.
            using var bus = new LocalBroker();
            using var prov = Node(bus, YuukoIdentity.Create("provider"), o =>
            {
                o.Handshake.MaxSessionAge = TimeSpan.FromMilliseconds(300);
                o.Handshake.RotationGrace = TimeSpan.FromMilliseconds(100);
            });
            using var cli = Node(bus, YuukoIdentity.Create("client"), o => o.Handshake.MaxSessionAge = TimeSpan.Zero);   // never rotates
            prov.On("n", (ctx, ct) => Task.FromResult(CommandResult.Ok("ok")));
            await prov.StartAsync();
            await cli.StartAsync();
            int connects = 0;
            cli.PeerConnected += _ => Interlocked.Increment(ref connects);

            await cli.SendCommandAsync("provider", "n");
            await Task.Delay(600);   // the provider's copy is now past MaxSessionAge + RotationGrace
            var sw = Stopwatch.StartNew();
            var ack = await cli.SendCommandAsync("provider", "n");
            Check($"a session past its hard expiry is refused by the receiver; the client re-handshakes and succeeds ({sw.ElapsedMilliseconds} ms)",
                ack.IsOk && connects == 2 && sw.ElapsedMilliseconds < 2500);
        }
        {
            // A rekey that fails must not take down a working connection.
            using var bus = new LocalBroker();
            EclipseBrokerOptions? providerOpts = null;
            using var prov = Node(bus, YuukoIdentity.Create("provider"), o => providerOpts = o);
            using var cli = Node(bus, YuukoIdentity.Create("client"), o => o.Handshake.MaxSessionAge = TimeSpan.FromMilliseconds(200));
            prov.On("n", (ctx, ct) => Task.FromResult(CommandResult.Ok("ok")));
            await prov.StartAsync();
            await cli.StartAsync();
            int connects = 0;
            cli.PeerConnected += _ => Interlocked.Increment(ref connects);

            await cli.SendCommandAsync("provider", "n");
            await Task.Delay(300);
            providerOpts!.Handshake.BannedClients.Add("client");   // new handshakes are refused; the existing session is untouched

            var sw = Stopwatch.StartNew();
            var ack = await cli.SendCommandAsync("provider", "n");
            Check($"when the rekey is refused, the client keeps using its working session ({sw.ElapsedMilliseconds} ms)", ack.IsOk && connects == 1 && sw.ElapsedMilliseconds < 1500);
            var sw2 = Stopwatch.StartNew();
            Check($"...and does not retry the refused rekey on every call ({sw2.ElapsedMilliseconds} ms)", (await cli.SendCommandAsync("provider", "n")).IsOk && sw2.ElapsedMilliseconds < 500);
        }
    }
}
