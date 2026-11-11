using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json.Nodes;
using YuukoProtocol;

namespace YuukoSandbox;

// Tests for TLS certificates, pairing codes, adding a device with a code, and group changes (introduce / revoke).
// Same helpers (Check / Tap / Node / Group) as the other SelfTest files.
public static partial class SelfTest
{
    private static string TempDir(string name)
    {
        string d = Path.Combine(Path.GetTempPath(), "yuuko-selftest-" + Guid.NewGuid().ToString("N")[..8], name);
        Directory.CreateDirectory(d);
        return d;
    }

    private static bool Fails(Action a)
    {
        try { a(); return false; } catch { return true; }
    }

    // ── TLS certificates ─────────────────────────────────────────────────────

    private static void TlsCertificates()
    {
        Section("TLS certificate (check, create, renew)");
        string dir = TempDir("a");

        Check("no certificate yet", YuukoTls.Check(dir, "alpha") == CertificateState.Missing);
        var c1 = YuukoTls.EnsureCertificate(dir, "alpha");
        Check("one is created", c1.WasCreated && File.Exists(c1.CertPath) && File.Exists(c1.KeyPath) && File.Exists(c1.CaCertPath));
        Check("and it is valid", YuukoTls.Check(dir, "alpha") == CertificateState.Valid);
        Check("it expires about a year out", (c1.ExpiresUtc - DateTimeOffset.UtcNow).TotalDays is > 360 and < 366);

        byte[] before = File.ReadAllBytes(c1.CertPath);
        var c2 = YuukoTls.EnsureCertificate(dir, "alpha");
        Check("asking again changes nothing", !c2.WasCreated && c2.CaFingerprint == c1.CaFingerprint && File.ReadAllBytes(c2.CertPath).SequenceEqual(before));
        Check("a device always trusts its own CA", YuukoTls.TrustedFingerprints(c1).Contains(c1.CaFingerprint));

        File.WriteAllText(c1.KeyPath, "junk");
        Check("a damaged key is noticed", YuukoTls.Check(dir, "alpha") == CertificateState.Invalid);
        var c3 = YuukoTls.EnsureCertificate(dir, "alpha");
        Check("and repaired, keeping the same CA (devices that trust it keep trusting it)",
            c3.WasCreated && YuukoTls.Check(dir, "alpha") == CertificateState.Valid && c3.CaFingerprint == c1.CaFingerprint);

        string other = TempDir("b");
        var b = YuukoTls.EnsureCertificate(other, "beta");
        File.Copy(b.CertPath, c1.CertPath, overwrite: true);
        Check("someone else's certificate dropped in is rejected (key does not match)", YuukoTls.Check(dir, "alpha") == CertificateState.Invalid);
        YuukoTls.EnsureCertificate(dir, "alpha");
        Check("(repaired again)", YuukoTls.Check(dir, "alpha") == CertificateState.Valid);

        // Same name, matching key, but signed by somebody else's CA: only the "signed by OUR CA" check can notice.
        string forged = TempDir("forged");
        var f = YuukoTls.EnsureCertificate(forged, "alpha");
        File.Copy(f.CertPath, c1.CertPath, overwrite: true);
        File.Copy(f.KeyPath, c1.KeyPath, overwrite: true);
        Check("a certificate with the right name and key but signed by a different CA is rejected", YuukoTls.Check(dir, "alpha") == CertificateState.Invalid);
        YuukoTls.EnsureCertificate(dir, "alpha");
        Check("(repaired once more)", YuukoTls.Check(dir, "alpha") == CertificateState.Valid);

        Check("a certificate made for another device name is not accepted", YuukoTls.Check(dir, "gamma") == CertificateState.Invalid);

        string soon = TempDir("c");
        var s1 = YuukoTls.EnsureCertificate(soon, "delta", leafLifetime: TimeSpan.FromDays(10));
        Check("a certificate close to expiry is reported", YuukoTls.Check(soon, "delta") == CertificateState.ExpiresSoon);
        var s2 = YuukoTls.EnsureCertificate(soon, "delta");
        Check("and renewed, with the same CA", s2.WasCreated && s2.CaFingerprint == s1.CaFingerprint && YuukoTls.Check(soon, "delta") == CertificateState.Valid
            && (s2.ExpiresUtc - DateTimeOffset.UtcNow).TotalDays > 300);

        // Trusting other devices' CAs.
        Check("a peer's CA can be trusted", YuukoTls.TrustPeer(c1, b.CaPem));
        Check("...once", !YuukoTls.TrustPeer(c1, b.CaPem));
        Check("it is then in the trust file", YuukoTls.TrustedFingerprints(c1).Contains(b.CaFingerprint));
        Check("a leaf certificate is refused as a trust anchor (that would let one device in, not a CA)",
            Fails(() => YuukoTls.TrustPeer(c1, File.ReadAllText(b.CertPath))));
        Check("junk is refused", Fails(() => YuukoTls.TrustPeer(c1, "not a certificate")));
        Check("a peer can be un-trusted", YuukoTls.UntrustPeer(c1, b.CaFingerprint) && !YuukoTls.TrustedFingerprints(c1).Contains(b.CaFingerprint));
        Check("a device's own CA cannot be removed by accident", !YuukoTls.UntrustPeer(c1, c1.CaFingerprint) && YuukoTls.TrustedFingerprints(c1).Contains(c1.CaFingerprint));

        // The options helper points Zenoh at the files.
        var z = new ZenohBrokerOptions { EnableTls = false };
        YuukoTls.Apply(z, c1);
        Check("Apply turns TLS on and points at the files",
            z.EnableTls && z.TlsListenCertificate == c1.CertPath && z.TlsRootCaCertificate == c1.TrustBundlePath && z.TlsEnableMutual);
        Check("options pointed at a certificate remember it (the transport reports it, so the device knows its authority)", z.TlsCertificate?.CaFingerprint == c1.CaFingerprint);
        Check("TLS is on by default", new ZenohBrokerOptions().EnableTls);
        Check("...and so is mutual TLS (a device with no certificate from a trusted authority is turned away)", new ZenohBrokerOptions().TlsEnableMutual);

        // A key that does not belong to the certificate must be noticed even when the name and the signature are fine.
        string mismatch = TempDir("mismatch");
        var m1 = YuukoTls.EnsureCertificate(mismatch, "alpha");
        string otherKeyDir = TempDir("otherkey");
        var m2 = YuukoTls.EnsureCertificate(otherKeyDir, "alpha");
        File.Copy(m2.KeyPath, m1.KeyPath, overwrite: true);
        Check("a private key that belongs to a different certificate is rejected", YuukoTls.Check(mismatch, "alpha") == CertificateState.Invalid);

        // Temporary certificates for pairing.
        var (tc, tk) = YuukoTls.IssueTemporary(c1, TimeSpan.FromMinutes(7));
        using (var tcert = X509Certificate2.CreateFromPem(tc, tk))
        {
            Check("a temporary certificate comes with its key", tcert.HasPrivateKey);
            Check("...lasts only as long as asked", (tcert.NotAfter.ToUniversalTime() - DateTime.UtcNow).TotalMinutes is > 5 and < 8);
        }
        Check("...is signed by this device's authority and nobody else's", ChainsTo(tc, c1.CaPem) && !ChainsTo(tc, b.CaPem));
        Check("...and every one is different", YuukoTls.IssueTemporary(c1, TimeSpan.FromMinutes(7)).CertPem != tc);
        Check("a temporary certificate cannot be made to last for days", Fails(() => YuukoTls.IssueTemporary(c1, TimeSpan.FromDays(3))) && Fails(() => YuukoTls.IssueTemporary(c1, TimeSpan.Zero)));
    }

    private static bool ChainsTo(string certPem, string caPem)
    {
        using var leaf = X509Certificate2.CreateFromPem(certPem);
        using var ca = X509Certificate2.CreateFromPem(caPem);
        using var chain = new X509Chain();
        chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
        chain.ChainPolicy.CustomTrustStore.Add(ca);
        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        return chain.Build(leaf);
    }

    // ── joining another device's TLS group ───────────────────────────────────

    private static void TlsGroups()
    {
        Section("TLS group (one authority for every device)");
        string da = TempDir("ga"), db = TempDir("gb");
        var a = YuukoTls.EnsureCertificate(da, "pc");
        var b0 = YuukoTls.EnsureCertificate(db, "phone");
        string caKeyA = File.ReadAllText(Path.Combine(da, "ca.key"));
        Check("(setup) two devices start with different authorities", a.CaFingerprint != b0.CaFingerprint);

        // Things that must be refused leave the device exactly as it was.
        string dx = TempDir("gx");
        var x0 = YuukoTls.EnsureCertificate(dx, "tablet");
        string wrongKey = File.ReadAllText(Path.Combine(dx, "ca.key"));
        Check("an authority certificate with someone else's key is refused", Fails(() => YuukoTls.AdoptGroup(x0, a.CaPem, wrongKey)));
        Check("a device certificate is not accepted as an authority", Fails(() => YuukoTls.AdoptGroup(x0, File.ReadAllText(a.CertPath), caKeyA)));
        Check("junk is refused", Fails(() => YuukoTls.AdoptGroup(x0, "junk", "junk")));
        Check("...and the device is untouched by all of that",
            YuukoTls.Check(dx, "tablet") == CertificateState.Valid && YuukoTls.FingerprintOfPem(File.ReadAllText(x0.CaCertPath)) == x0.CaFingerprint);

        YuukoTls.WritePairingCredentials(b0, tc0(), tk0());
        var joined = YuukoTls.AdoptGroup(b0, a.CaPem, caKeyA);
        Check("adopting makes a device's authority the group's", joined.CaFingerprint == a.CaFingerprint);
        Check("its new certificate is valid and comes from the group's authority",
            YuukoTls.Check(db, "phone") == CertificateState.Valid && ChainsTo(File.ReadAllText(joined.CertPath), a.CaPem));
        Check("so the original device's authority accepts it, with no change to the original device", ChainsTo(File.ReadAllText(joined.CertPath), File.ReadAllText(a.CaCertPath)));
        var trusted = YuukoTls.TrustedFingerprints(joined);
        Check("the device trusts the group's authority and no longer its old one", trusted.Contains(a.CaFingerprint) && !trusted.Contains(b0.CaFingerprint));
        Check("the temporary pairing certificate is deleted", !File.Exists(Path.Combine(db, "pairing-cert.pem")) && !File.Exists(Path.Combine(db, "pairing-key.pem")));
        Check("a device keeps its own keys when it joins (only the authority changes)", File.Exists(joined.KeyPath) && joined.DeviceId == "phone");

        static string tc0() => YuukoTls.IssueTemporary(YuukoTls.EnsureCertificate(TempDir("tmpissuer"), "x"), TimeSpan.FromMinutes(5)).CertPem;
        static string tk0() => YuukoTls.IssueTemporary(YuukoTls.EnsureCertificate(TempDir("tmpissuer2"), "y"), TimeSpan.FromMinutes(5)).KeyPem;
    }

    // ── pairing code format ──────────────────────────────────────────────────

    private static void PairingCodes()
    {
        Section("pairing code (the thing you show or scan)");
        string dir = TempDir("code");
        var cert = YuukoTls.EnsureCertificate(dir, "phone");
        byte[] token = RandomNumberGenerator.GetBytes(16);
        string fp = Convert.ToHexString(RandomNumberGenerator.GetBytes(32)).ToLowerInvariant();
        var made = new PairingCode("phone", fp, "tcp/192.168.1.5:7447", cert.CaPem, token, DateTimeOffset.UtcNow.AddMinutes(5));
        string text = made.Encode();

        Check("starts with a recognisable prefix", text.StartsWith("YUUKO2-"));
        var back = PairingCode.Parse(text);
        Check("it reads back exactly: name, keys, address",
            back.DeviceId == "phone" && back.Fingerprint == fp && back.Endpoint == "tcp/192.168.1.5:7447");
        Check("...the TLS certificate", back.CaCertificatePem is not null && YuukoTls.FingerprintOfPem(back.CaCertificatePem) == cert.CaFingerprint);
        Check("...and the token", back.Token.SequenceEqual(token));
        Check("...and the expiry (to the second)", Math.Abs((back.ExpiresUtc - made.ExpiresUtc).TotalSeconds) < 1.5);
        Check("a code that is still in date is not expired", !back.IsExpired);

        Check("spaces, line breaks and lower case are forgiven",
            PairingCode.TryParse(string.Join(" \n", text.ToLowerInvariant().Split('-')), out var lenient, out _) && lenient!.Fingerprint == fp);
        string confusable = text[7..].Replace('0', 'O').Replace('1', 'l');
        Check("O/0 and I/L/1 mix-ups are forgiven", PairingCode.TryParse("YUUKO2-" + confusable, out var conf, out _) && conf!.Fingerprint == fp);

        // One wrong character anywhere must be caught, never silently read as a different code.
        int caught = 0, tried = 0;
        string body = text[7..].Replace("-", "");
        for (int i = 0; i < body.Length; i += 37)
        {
            char[] chars = body.ToCharArray();
            chars[i] = chars[i] == 'A' ? 'B' : 'A';
            tried++;
            if (!PairingCode.TryParse("YUUKO2" + new string(chars), out _, out var err) && err!.Contains("typo")) caught++;
        }
        Check($"a single wrong character is caught by the checksum ({caught}/{tried} positions tried)", tried > 10 && caught == tried);
        // A stranger can make a code whose checksum is right and whose contents are junk. It must be refused, not crash the reader.
        bool noCrash = true, refused = true;
        foreach (var junk in new[] { new byte[] { 1, 2, 3, 4, 5 }, RandomNumberGenerator.GetBytes(300), new byte[600] })
        {
            try { refused &= !PairingCode.TryParse(made.EncodeCore(junk), out _, out _); }
            catch { noCrash = false; }
        }
        Check("a code with a correct checksum but a junk certificate is refused cleanly, never a crash", noCrash && refused);
        Check("a cut-off code is refused",!PairingCode.TryParse(text[..^12], out _, out _));
        Check("junk, empty and null are refused", !PairingCode.TryParse("hello", out _, out _) && !PairingCode.TryParse("", out _, out _) && !PairingCode.TryParse(null, out _, out _));
        Check("a code from a different version is refused", !PairingCode.TryParse("YUUKO3-AAAA-AAAA", out _, out _) && !PairingCode.TryParse("YUUKO1-AAAA-AAAA", out _, out _));
        Check("an enormous input is refused quickly", !PairingCode.TryParse("YUUKO2-" + new string('A', 100_000), out _, out _));

        // The temporary client certificate and its key travel in the code, and come out usable.
        var (tcPem, tkPem) = YuukoTls.IssueTemporary(cert, TimeSpan.FromMinutes(5));
        var withTemp = new PairingCode("phone", fp, "tcp/10.0.0.2:7447", cert.CaPem, token, DateTimeOffset.UtcNow.AddMinutes(5), tcPem, tkPem);
        var tempBack = PairingCode.Parse(withTemp.Encode());
        Check("a temporary certificate and its key survive the code",
            tempBack.BootstrapCertificatePem is not null && tempBack.BootstrapPrivateKeyPem is not null
            && YuukoTls.FingerprintOfPem(tempBack.BootstrapCertificatePem) == YuukoTls.FingerprintOfPem(tcPem));
        using (var usable = X509Certificate2.CreateFromPem(tempBack.BootstrapCertificatePem!, tempBack.BootstrapPrivateKeyPem!))
            Check("...and the key still matches the certificate", usable.HasPrivateKey);
        Check("a certificate without its key (or the reverse) is not a valid code", Fails(() => new PairingCode("phone", fp, null, cert.CaPem, token, DateTimeOffset.UtcNow.AddMinutes(5), tcPem, null)));

        var joinOpts = withTemp.ToTransportOptions("joiner", TempDir("joiner2"));
        Check("joining with it turns on mutual TLS and presents the temporary certificate",
            joinOpts.EnableTls && joinOpts.TlsEnableMutual && joinOpts.TlsConnectCertificate is not null
            && joinOpts.TlsConnectCertificate.EndsWith("pairing-cert.pem") && File.Exists(joinOpts.TlsConnectPrivateKey!)
            && joinOpts.TlsListenCertificate != joinOpts.TlsConnectCertificate
            && joinOpts.TlsCertificate is not null && joinOpts.Clone().TlsCertificate is not null);
        Check("a code from a device with no TLS joins without TLS", !new PairingCode("tv", fp, "tcp/10.0.0.3:7447", null, token, DateTimeOffset.UtcNow.AddMinutes(1)).ToTransportOptions("j", TempDir("j3")).EnableTls);

        var bare = new PairingCode("tv", fp, null, null, token, DateTimeOffset.UtcNow.AddMinutes(1));
        var bareBack = PairingCode.Parse(bare.Encode());
        Check("a code with no address and no certificate also works", bareBack.Endpoint is null && bareBack.CaCertificatePem is null && bareBack.DeviceId == "tv");

        Check("an expired code reads fine but says so", new PairingCode("tv", fp, null, null, token, DateTimeOffset.UtcNow.AddMinutes(-1)).IsExpired);
        Check("printing a code object never shows the secret", !made.ToString().Contains(text) && !made.ToString().Contains(Convert.ToHexString(token), StringComparison.OrdinalIgnoreCase));
        Check("the transport options carry the address and trust the certificate",
            FromCodeOptions(back).ConnectEndpoints.Single() == "tcp/192.168.1.5:7447");
    }

    private static ZenohBrokerOptions FromCodeOptions(PairingCode c) => c.ToTransportOptions("joiner", TempDir("joiner"));

    private static async Task PairingWithTls()
    {
        Section("pairing with TLS (mutual TLS stays on, and a newcomer still gets in)");
        using var bus = new LocalBroker();
        string da = TempDir("pa"), db = TempDir("pb");
        var ca = YuukoTls.EnsureCertificate(da, "anchor");
        var cb = YuukoTls.EnsureCertificate(db, "phone");
        EclipseBrokerOptions? anchorOpts = null;
        using var a = Node(bus, YuukoIdentity.Create("anchor"), o => { o.Handshake.RequireKnownDevices = true; o.TlsCertificate = ca; anchorOpts = o; });
        using var b = Node(bus, YuukoIdentity.Create("phone"), o => o.TlsCertificate = cb);
        await a.StartAsync();   // b is deliberately NOT started: pairing has to start it (the offerer sends to it the instant they are paired)

        var offer = a.BeginPairing();
        Check("the code carries the TLS authority's certificate and a temporary certificate for the newcomer",
            offer.Details.CaCertificatePem is not null && offer.Details.BootstrapCertificatePem is not null);
        Check("the temporary certificate comes from the offering device's authority and lasts about the window",
            ChainsTo(offer.Details.BootstrapCertificatePem!, ca.CaPem)
            && X509Certificate2.CreateFromPem(offer.Details.BootstrapCertificatePem!).NotAfter.ToUniversalTime() - DateTime.UtcNow < TimeSpan.FromMinutes(9));
        Check("the authority's KEY is not in the code", !offer.Code.Contains("PRIVATE", StringComparison.OrdinalIgnoreCase)
            && PairingCode.Parse(offer.Code).CaCertificatePem is { } caText && !caText.Contains("PRIVATE"));

        var r = await b.PairWithAsync(offer.Code);
        Check("pairing works", r.Success);
        Check("the newcomer joined the offering device's TLS group, and is told to restart its transport",
            r.RestartTransport && b.NeedsTransportRestart && YuukoTls.FingerprintOfPem(File.ReadAllText(cb.CaCertPath)) == ca.CaFingerprint);
        Check("its permanent certificate is already valid on disk", YuukoTls.Check(db, "phone") == CertificateState.Valid);
        Check("the offering device's authority did not change",
            YuukoTls.Check(da, "anchor") == CertificateState.Valid && YuukoTls.FingerprintOfPem(File.ReadAllText(ca.CaCertPath)) == ca.CaFingerprint);
        Check("a device that must restart cannot offer codes until it has (they would carry the old authority)", Fails(() => b.BeginPairing()));
        Check("the newcomer has a working link to the offering device", (await b.PingAsync("anchor")).IsOk);

        Check("the newcomer was offered the TLS group exactly once", b.TlsGroupMessagesSeen == 1);

        // A device that is merely trusted, and connects the ordinary way, must never be sent the group's signing key.
        var emmaId = YuukoIdentity.Create("emma");
        anchorOpts!.Handshake.TrustDevice("emma", emmaId.Fingerprint);
        using var emma = Node(bus, emmaId, o => o.Handshake.TrustDevice("anchor", a.Fingerprint));
        await emma.StartAsync();
        Check("(setup) emma connects normally", (await emma.PingAsync("anchor")).IsOk && a.ConnectedPeers.Contains("emma"));
        await Task.Delay(600);
        Check("a device that connected without pairing is never offered the TLS group", emma.TlsGroupMessagesSeen == 0);

        // The group command carries a signing key. Nobody may send it unless we just asked THEM to pair with us.
        string evilDir = TempDir("evil");
        var evil = YuukoTls.EnsureCertificate(evilDir, "evil");
        byte[] push = System.Text.Json.JsonSerializer.SerializeToUtf8Bytes(new { CaPem = evil.CaPem, CaKeyPem = File.ReadAllText(Path.Combine(evilDir, "ca.key")) });
        var ack = await b.SendCommandAsync("anchor", "yuuko.tlsgroup", push);
        Check("a paired device cannot push a TLS authority onto a device that did not ask for one", ack.Status == AckStatus.Denied
            && YuukoTls.FingerprintOfPem(File.ReadAllText(ca.CaCertPath)) == ca.CaFingerprint);
        var ack2 = await a.SendCommandAsync("phone", "yuuko.tlsgroup", push);
        Check("...nor can the offering device send it again once pairing is over", ack2.Status == AckStatus.Denied
            && YuukoTls.FingerprintOfPem(File.ReadAllText(cb.CaCertPath)) == ca.CaFingerprint);

        // A device that already has devices of its own will not abandon them for another group.
        string dc = TempDir("pc");
        var cc = YuukoTls.EnsureCertificate(dc, "carol");
        using var c = Node(bus, YuukoIdentity.Create("carol"), o => o.TlsCertificate = cc);
        c.PairDevice("old", "old-id", new string('a', 64));
        var refused = await c.PairWithAsync(a.BeginPairing().Code);
        Check("a device that already has paired devices will not abandon them by joining another group",
            !refused.Success && refused.Failure!.Contains("group") && YuukoTls.FingerprintOfPem(File.ReadAllText(cc.CaCertPath)) == cc.CaFingerprint);

        // A device already in the same group needs no restart.
        string dd = TempDir("pd");
        var cd = YuukoTls.AdoptGroup(YuukoTls.EnsureCertificate(dd, "dave"), ca.CaPem, File.ReadAllText(Path.Combine(da, "ca.key")));
        using var d = Node(bus, YuukoIdentity.Create("dave"), o => o.TlsCertificate = cd);
        await d.StartAsync();
        var same = await d.PairWithAsync(a.BeginPairing().Code);
        Check("a device already in the same TLS group pairs without a restart", same.Success && !same.RestartTransport && !d.NeedsTransportRestart);
    }

    // ── pairing: adding a device with a code ─────────────────────────────────

    private static async Task Pairing()
    {
        Section("pairing (adding a new device with a code)");

        // The offering device is locked down: nobody it has not been told about may connect.
        {
            using var bus = new LocalBroker();
            var tap = new Tap(bus);
            var aid = YuukoIdentity.Create("anchor");
            var bid = YuukoIdentity.Create("newcomer");
            EclipseBrokerOptions? bopts = null;
            using var a = Node(tap, aid, o => o.Handshake.RequireKnownDevices = true);
            using var b = Node(tap, bid, o => bopts = o);
            await a.StartAsync(); await b.StartAsync();
            var paired = new ConcurrentQueue<string>();
            a.DevicePaired += (id, f) => paired.Enqueue(id + "/" + f);

            Check("(control) without a code the newcomer is refused", !(await b.PingAsync("anchor")).IsOk);
            Check("(control) and nothing was pinned by trying", !a.Devices.All().Any() && !bopts!.Handshake.RequireKnownDevices);

            var offer = a.BeginPairing();
            Check("an offer is open", a.PairingOpen && offer.Code.StartsWith("YUUKO2-"));
            var tokenBytes = offer.Details.Token;

            var result = await b.PairWithAsync(offer.Code, moniker: "main");
            Check("the newcomer pairs with the code", result.Success && result.DeviceId == "anchor" && result.Moniker == "main");
            Check("the offering side now trusts exactly the newcomer's keys", a.Devices.FindByClientId("newcomer")?.Fingerprint == bid.Fingerprint);
            Check("the newcomer now trusts exactly the offering side's keys and lists it by the nickname it chose", b.Devices.Find("main")?.Fingerprint == aid.Fingerprint);
            Check("the offering side was told", await Eventually(() => paired.Contains("newcomer/" + bid.Fingerprint)));
            Check("they are connected", a.ConnectedPeers.Contains("newcomer") && b.ConnectedPeers.Contains("anchor"));
            Check("and commands work both ways", (await b.PingAsync("anchor")).IsOk && (await a.PingAsync("newcomer")).IsOk);
            Check("the window closed by itself: the code is spent", !a.PairingOpen);

            string wire = string.Join("\n", tap.Seen);
            Check("the secret token never appeared on the wire (hex, base64 or raw)",
                !wire.Contains(Convert.ToBase64String(tokenBytes)) && !wire.Contains(Convert.ToHexString(tokenBytes), StringComparison.OrdinalIgnoreCase));

            // The same code again, from a different device.
            using var c = Node(tap, YuukoIdentity.Create("late"));
            await c.StartAsync();
            var again = await c.PairWithAsync(offer.Code);
            Check("the used code does not work a second time, for anyone", !again.Success && !a.Devices.All().Any(d => d.ClientId == "late"));
        }

        // Wrong token, expired window, cancelled window, attempt limit.
        {
            using var bus = new LocalBroker();
            var aid = YuukoIdentity.Create("anchor");
            using var a = Node(bus, aid, o => o.Handshake.RequireKnownDevices = true);
            await a.StartAsync();

            EclipseBrokerOptions? opts = null;
            using var b = Node(bus, YuukoIdentity.Create("newcomer"), o => opts = o);
            await b.StartAsync();

            var offer = a.BeginPairing();
            var wrong = new PairingCode("anchor", aid.Fingerprint, null, null, RandomNumberGenerator.GetBytes(16), DateTimeOffset.UtcNow.AddMinutes(5));
            var r1 = await b.PairWithAsync(wrong);
            Check("a code with the wrong token is refused", !r1.Success);
            Check("...and leaves nothing behind on either side", !a.Devices.All().Any() && !opts!.Handshake.TrustedDevices.Any() && !opts.Handshake.RequireKnownDevices);
            Check("...but the genuine code still works after a failed guess", (await b.PairWithAsync(offer.Code)).Success);
        }
        {
            using var bus = new LocalBroker();
            using var a = Node(bus, YuukoIdentity.Create("anchor"), o => o.Handshake.RequireKnownDevices = true);
            using var b = Node(bus, YuukoIdentity.Create("newcomer"));
            await a.StartAsync(); await b.StartAsync();

            var offer = a.BeginPairing(TimeSpan.FromMilliseconds(400));
            await Task.Delay(700);
            Check("a window that has run out is closed", !a.PairingOpen);
            Check("...and its code is refused", !(await b.PairWithAsync(offer.Code)).Success && !a.Devices.All().Any());

            // The joiner's own copy of the code claims to be in date (its clock says so); only the OFFERING side's window can refuse.
            var inDate = new PairingCode("anchor", a.Fingerprint, null, null, offer.Details.Token, DateTimeOffset.UtcNow.AddMinutes(5));
            Check("the offering side refuses an expired window itself, whatever the joiner's code says",
                !(await b.PairWithAsync(inDate)).Success && !a.Devices.All().Any());

            var offer2 = a.BeginPairing();
            a.CancelPairing();
            Check("a cancelled window is closed", !a.PairingOpen && !(await b.PairWithAsync(offer2.Code)).Success);

            Check("an expired code is refused before even connecting",
                (await b.PairWithAsync(new PairingCode("anchor", a.Fingerprint, null, null, RandomNumberGenerator.GetBytes(16), DateTimeOffset.UtcNow.AddSeconds(-5)))).Failure!.Contains("expired"));
            Check("a code made by this very device is refused", (await a.PairWithAsync(a.BeginPairing().Code)).Failure!.Contains("this device"));
            Check("windows must be a sensible length", Fails(() => a.BeginPairing(TimeSpan.Zero)) && Fails(() => a.BeginPairing(TimeSpan.FromHours(5))));
        }
        {
            using var bus = new LocalBroker();
            var aid = YuukoIdentity.Create("anchor");
            using var a = Node(bus, aid, o => o.Handshake.RequireKnownDevices = true);
            using var b = Node(bus, YuukoIdentity.Create("newcomer"));
            await a.StartAsync(); await b.StartAsync();

            var offer = a.BeginPairing(maxAttempts: 2);
            for (int i = 0; i < 2; i++)
                await b.PairWithAsync(new PairingCode("anchor", aid.Fingerprint, null, null, RandomNumberGenerator.GetBytes(16), DateTimeOffset.UtcNow.AddMinutes(5)));
            Check("a window allows only so many attempts; after that even the right code is refused",
                !a.PairingOpen && !(await b.PairWithAsync(offer.Code)).Success);
        }

        // Things that must not be possible even with a good code.
        {
            using var bus = new LocalBroker();
            var aid = YuukoIdentity.Create("anchor");
            using var a = Node(bus, aid, o => o.Handshake.RequireKnownDevices = true);
            var bid = YuukoIdentity.Create("bob");
            using var b = Node(bus, bid);
            await a.StartAsync(); await b.StartAsync();
            Check("(setup) bob pairs", (await b.PairWithAsync(a.BeginPairing().Code)).Success);

            using var impostor = Node(bus, YuukoIdentity.Create("bob"));   // same name, different keys
            await impostor.StartAsync();
            var r = await impostor.PairWithAsync(a.BeginPairing().Code);
            Check("a different device claiming bob's name cannot pair over the top of bob", !r.Success);
            Check("bob's pinned keys are unchanged", a.Devices.FindByClientId("bob")?.Fingerprint == bid.Fingerprint);

            // The offering device is not who the code says: the code names anchor's keys, a different device answers.
            using var fakeAnchor = Node(bus, YuukoIdentity.Create("anchor-fake"), o => o.Handshake.RequireKnownDevices = true);
            await fakeAnchor.StartAsync();
            var fakeOffer = fakeAnchor.BeginPairing();
            var lying = new PairingCode("anchor-fake", aid.Fingerprint /* the REAL anchor's keys */, null, null, fakeOffer.Details.Token, DateTimeOffset.UtcNow.AddMinutes(5));
            using var victim = Node(bus, YuukoIdentity.Create("victim"));
            await victim.StartAsync();
            Check("a device that is not the one the code names cannot complete pairing (its keys do not match)", !(await victim.PairWithAsync(lying)).Success && !victim.Devices.All().Any());

            // After pairing, strangers are still refused.
            using var stranger = Node(bus, YuukoIdentity.Create("stranger"));
            await stranger.StartAsync();
            Check("once the window is spent, strangers are refused again", !(await stranger.PingAsync("anchor")).IsOk);
        }

        // Pairing together with a group pre-shared key.
        {
            using var bus = new LocalBroker();
            byte[] psk = Encoding.UTF8.GetBytes("a-group-secret-16+");
            using var a = Node(bus, YuukoIdentity.Create("anchor"), o => { o.Handshake.RequireKnownDevices = true; o.Handshake.PreSharedKey = psk; o.Handshake.RequirePreSharedKey = true; });
            using var good = Node(bus, YuukoIdentity.Create("good"), o => { o.Handshake.PreSharedKey = psk; o.Handshake.RequirePreSharedKey = true; });
            using var nopsk = Node(bus, YuukoIdentity.Create("nopsk"));
            await a.StartAsync(); await good.StartAsync(); await nopsk.StartAsync();
            var offer = a.BeginPairing();
            Check("a newcomer without the group key cannot use the code", !(await nopsk.PairWithAsync(offer.Code)).Success);
            Check("a newcomer with the group key can", (await good.PairWithAsync(offer.Code)).Success);
        }
    }

    // ── group changes: introduce / revoke ────────────────────────────────────

    private static async Task GroupChanges()
    {
        Section("group changes (one device tells the others about a new one)");

        using var bus = new LocalBroker();
        var policyLog = new ConcurrentQueue<GroupChange>();
        bool bAllows = false, cAllows = true;
        // a is connected to b and c. b and c have never met.
        var (n, log) = await Group(bus, new[] { "a", "b", "c" }, new[] { ("a", "b"), ("a", "c") }, (name, o) =>
        {
            if (name == "b") o.GroupChangePolicy = ch => { policyLog.Enqueue(ch); return Task.FromResult(bAllows); };
            if (name == "c") o.GroupChangePolicy = ch => Task.FromResult(cAllows);
        });
        try
        {
            Check("(setup) b and c cannot reach each other", !(await n["b"].PingAsync("c")).IsOk);

            // Policy says no.
            bAllows = false;
            var r1 = await n["a"].IntroduceAsync("c");
            Check("a policy that says no changes nothing", r1.Acks["b"].Status == AckStatus.Denied && !(await n["b"].PingAsync("c")).IsOk);
            Check("the policy was told who announced it, and that it came by broadcast",
                policyLog.TryPeek(out var first) && first.IntroducedBy == "a" && first.DeviceId == "c" && first.ViaRelay && first.Kind == GroupChangeKind.Introduce);

            // Policy says yes.
            bAllows = true;
            var r2 = await n["a"].IntroduceAsync("c");
            Check("a policy that says yes lets the group trust the new device", r2.Acks["b"].IsOk);
            Check("b and c can now talk (each was told about the other)", await Eventually(() => n["b"].PingAsync("c").GetAwaiter().GetResult().IsOk, 6000));

            // Devices without a policy refuse everything.
            var (m, _) = await Group(bus, new[] { "p", "q", "r" }, new[] { ("p", "q"), ("p", "r") });
            try
            {
                var r3 = await m["p"].IntroduceAsync("r");
                Check("a device with no policy refuses every introduction", r3.Acks["q"].Status == AckStatus.Denied && !(await m["q"].PingAsync("r")).IsOk);
            }
            finally { foreach (var x in m.Values) x.Dispose(); }

            // A name that is already trusted with other keys.
            var (k, _) = await Group(bus, new[] { "x", "y", "z" }, new[] { ("x", "y"), ("x", "z") }, (name, o) =>
            {
                o.GroupChangePolicy = ch => Task.FromResult(true);
                if (name == "y") o.Handshake.TrustDevice("z", new string('a', 64));   // y already "knows" a z with different keys
            });
            try
            {
                var r4 = await k["x"].IntroduceAsync("z");
                Check("an introduction cannot replace the keys of a name that is already trusted", r4.Acks["y"].Status == AckStatus.Denied);
            }
            finally { foreach (var x in k.Values) x.Dispose(); }

            // A broadcast altered in transit is refused by the signature, whatever it says.
            string fakeFp = Convert.ToHexString(RandomNumberGenerator.GetBytes(32)).ToLowerInvariant();
            byte[] intro = Encoding.UTF8.GetBytes($"{{\"Id\":\"zed\",\"Fingerprint\":\"{fakeFp}\"}}");
            var (_, signed) = n["a"].BuildBroadcast("yuuko.introduce", intro);
            var altered = JsonNode.Parse(signed)!.AsObject();
            altered["data"] = Convert.ToBase64String(Encoding.UTF8.GetBytes($"{{\"Id\":\"zed\",\"Fingerprint\":\"{new string('b', 64)}\"}}"));
            var bad = await n["a"].SendCommandAsync("b", "yuuko.relay", Encoding.UTF8.GetBytes(altered.ToJsonString()));
            Check("an introduction altered in transit is refused (signature)", bad.Status == AckStatus.Denied);
            var okIntro = await n["a"].SendCommandAsync("b", "yuuko.relay", signed);
            Check("(control) the untouched one is accepted", okIntro.IsOk);

            // The built-in names cannot be broadcast through the public call.
            Check("the public broadcast call still refuses built-in names", Throws<ArgumentException>(() => n["a"].BroadcastAsync("yuuko.introduce")));

            // Revoking.
            Check("(setup) b is currently connected to c", n["b"].ConnectedPeers.Contains("c"));
            var r5 = await n["a"].RevokeAsync("c");
            Check("a revocation reaches the group and is accepted by a policy that allows it", r5.Acks["b"].IsOk);
            Check("the revoked device is disconnected from b", await Eventually(() => !n["b"].ConnectedPeers.Contains("c")));
            Check("b can no longer reach c", !(await n["b"].PingAsync("c")).IsOk);
            Check("a, which revoked it, disconnected it too", await Eventually(() => !n["a"].ConnectedPeers.Contains("c")));

            bAllows = false;
            var again = await n["a"].BroadcastAsync("note", Bytes("still here"));
            Check("(the group still works after a revocation)", again.AllAccepted);
            Check("revoking a device you do not trust is an error, not a no-op", Throws<InvalidOperationException>(() => n["a"].RevokeAsync("nobody")));
            Check("introducing a device you do not trust is an error too", Throws<InvalidOperationException>(() => n["a"].IntroduceAsync("nobody")));
        }
        finally { foreach (var x in n.Values) x.Dispose(); }

        // A prompt nobody ever answers must not hold the device's command slot forever.
        {
            var (t, _) = await Group(bus, new[] { "a3", "b3", "c3" }, new[] { ("a3", "b3"), ("a3", "c3") }, (name, o) =>
            {
                if (name != "b3") return;
                o.MaxConcurrentCommands = 1;                         // one slot: if the prompt keeps it, the next command is "Busy"
                o.CommandHandlerTimeout = TimeSpan.FromSeconds(1);
                o.GroupChangePolicy = _ => new TaskCompletionSource<bool>().Task;   // the user walked away: never answers
            });
            try
            {
                var r = await t["a3"].IntroduceAsync("c3");
                await Task.Delay(1500);
                Check("a prompt that is never answered counts as a refusal after the time limit", r.Acks["b3"].Status != AckStatus.Ok);
                var after = await t["a3"].PingAsync("b3");
                Check("...and does not keep the device's command slot (the next command still runs)", after.IsOk);
            }
            finally { foreach (var x in t.Values) x.Dispose(); }
        }

        // A policy that throws counts as "no".
        {
            var (t, _) = await Group(bus, new[] { "a2", "b2", "c2" }, new[] { ("a2", "b2"), ("a2", "c2") },
                (name, o) => { if (name == "b2") o.GroupChangePolicy = _ => throw new InvalidOperationException("ui crashed"); });
            try
            {
                var r = await t["a2"].IntroduceAsync("c2");
                Check("a policy that throws is treated as a refusal", r.Acks["b2"].Status == AckStatus.Denied);
            }
            finally { foreach (var x in t.Values) x.Dispose(); }
        }
    }
}
