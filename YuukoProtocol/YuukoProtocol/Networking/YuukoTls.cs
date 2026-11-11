// YuukoTls.cs
// TLS certificates for the Zenoh link, made without openssl.
//
// Every device owns a tiny two-level setup:
//   ca.pem / ca.key      this device's own certificate authority (self-signed, 10 years)
//   cert.pem / key.pem   the certificate the device presents (signed by that CA, 1 year, renewed automatically)
//   trust.pem            the CA certificates this device trusts: its own plus those of paired devices
//
// A device trusts ANOTHER device's link only if that device's CA is in trust.pem, and the only way a CA gets in is
// through pairing (PairingCode carries it) or an explicit YuukoTls.TrustPeer call. Nothing is trusted because it
// "looks valid". The Yuuko handshake (pinned Kyber/Dilithium keys) is what authenticates devices; this layer hides
// who talks to whom from anyone listening on the network, and lets a device refuse a fake server before any
// Yuuko message is exchanged.

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace YuukoProtocol
{
    public enum CertificateState
    {
        /// <summary>No certificate files here.</summary>
        Missing,
        /// <summary>A certificate exists, is valid, and has more than the renewal margin left.</summary>
        Valid,
        /// <summary>Valid now but inside the renewal margin: <see cref="YuukoTls.EnsureCertificate"/> will replace the certificate.</summary>
        ExpiresSoon,
        Expired,
        /// <summary>Files exist but cannot be used (damaged, the key does not match, wrong device, not signed by this device's CA).</summary>
        Invalid,
    }

    /// <summary>A device's certificate files, ready to give to <see cref="ZenohBrokerOptions"/>.</summary>
    public sealed record YuukoCertificate(
        string Directory,
        string DeviceId,
        string CaCertPath,
        string CertPath,
        string KeyPath,
        string TrustBundlePath,
        string CaPem,
        string CaFingerprint,
        DateTimeOffset ExpiresUtc,
        bool WasCreated);

    public static class YuukoTls
    {
        public static readonly TimeSpan DefaultCaLifetime = TimeSpan.FromDays(3650);
        public static readonly TimeSpan DefaultLeafLifetime = TimeSpan.FromDays(365);
        public static readonly TimeSpan DefaultRenewBefore = TimeSpan.FromDays(30);

        private const string CaCertFile = "ca.pem", CaKeyFile = "ca.key", CertFile = "cert.pem", KeyFile = "key.pem", TrustFile = "trust.pem";

        /// <summary>Where a device's certificate lives unless you say otherwise: the user's local app-data folder.</summary>
        public static string DefaultDirectory(string deviceId)
        {
            string root = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
            if (string.IsNullOrEmpty(root)) root = Path.GetTempPath();
            return Path.Combine(root, "YuukoProtocol", "tls", Sanitize(deviceId));
        }

        /// <summary>Is there a usable Yuuko certificate in <paramref name="directory"/>? Changes nothing.</summary>
        public static CertificateState Check(string directory, string deviceId, TimeSpan? renewBefore = null)
        {
            var margin = renewBefore ?? DefaultRenewBefore;
            string ca = Path.Combine(directory, CaCertFile), cert = Path.Combine(directory, CertFile), key = Path.Combine(directory, KeyFile);
            if (!File.Exists(ca) && !File.Exists(cert) && !File.Exists(key)) return CertificateState.Missing;
            if (!File.Exists(ca) || !File.Exists(cert) || !File.Exists(key)) return CertificateState.Invalid;

            try
            {
                using var caCert = X509Certificate2.CreateFromPem(File.ReadAllText(ca));
                using var leaf = X509Certificate2.CreateFromPem(File.ReadAllText(cert), File.ReadAllText(key));   // throws if the key does not match

                if (!leaf.HasPrivateKey || !KeyMatchesCertificate(leaf, leaf.GetECDsaPrivateKey())) return CertificateState.Invalid;
                if (!string.Equals(CommonName(leaf), deviceId, StringComparison.Ordinal)) return CertificateState.Invalid;
                if (!SignedBy(leaf, caCert)) return CertificateState.Invalid;

                var now = DateTime.UtcNow;
                if (caCert.NotAfter.ToUniversalTime() <= now || leaf.NotAfter.ToUniversalTime() <= now) return CertificateState.Expired;
                if (leaf.NotAfter.ToUniversalTime() - now < margin || caCert.NotAfter.ToUniversalTime() - now < margin) return CertificateState.ExpiresSoon;
                return CertificateState.Valid;
            }
            catch { return CertificateState.Invalid; }
        }

        /// <summary>
        /// Makes sure <paramref name="directory"/> holds a usable certificate for <paramref name="deviceId"/> and returns it.
        /// If one is already there and valid it is left alone; if there is none, or it is damaged, expired or about to
        /// expire, it is created or renewed. A renewal keeps the same CA while that is still valid, so devices that already
        /// trust this one keep trusting it.
        /// </summary>
        public static YuukoCertificate EnsureCertificate(string directory, string deviceId, TimeSpan? leafLifetime = null, TimeSpan? renewBefore = null)
        {
            if (string.IsNullOrWhiteSpace(directory)) throw new ArgumentException("directory must be non-empty.", nameof(directory));
            if (string.IsNullOrWhiteSpace(deviceId)) throw new ArgumentException("deviceId must be non-empty.", nameof(deviceId));
            Directory.CreateDirectory(directory);
            RestrictToOwner(directory, isDirectory: true);

            var state = Check(directory, deviceId, renewBefore);
            bool created = false;
            if (state is not CertificateState.Valid)
            {
                var margin = renewBefore ?? DefaultRenewBefore;
                // Keep the CA (so paired devices keep trusting us) if it is still good; replace only the leaf.
                if (state is CertificateState.ExpiresSoon or CertificateState.Expired or CertificateState.Invalid && TryLoadCa(directory, deviceId, margin, out var ca))
                {
                    using (ca) IssueLeaf(directory, deviceId, ca!, leafLifetime ?? DefaultLeafLifetime);
                }
                else
                {
                    CreateAll(directory, deviceId, leafLifetime ?? DefaultLeafLifetime);
                }
                created = true;
            }

            string caPem = File.ReadAllText(Path.Combine(directory, CaCertFile));
            using var caNow = X509Certificate2.CreateFromPem(caPem);
            using var leafNow = X509Certificate2.CreateFromPem(File.ReadAllText(Path.Combine(directory, CertFile)));

            var result = new YuukoCertificate(directory, deviceId,
                Path.Combine(directory, CaCertFile), Path.Combine(directory, CertFile), Path.Combine(directory, KeyFile),
                Path.Combine(directory, TrustFile), caPem.Trim() + "\n", Fingerprint(caNow),
                new DateTimeOffset(leafNow.NotAfter.ToUniversalTime()), created);

            EnsureTrustContains(result, caPem);   // a device always trusts its own CA
            return result;
        }

        /// <summary>
        /// Makes <paramref name="peerCaPem"/> (another device's CA certificate, from its pairing code) trusted by this
        /// device. Returns false if it was already trusted. Throws if it is not a certificate.
        /// </summary>
        public static bool TrustPeer(YuukoCertificate mine, string peerCaPem)
        {
            if (mine is null) throw new ArgumentNullException(nameof(mine));
            using var parsed = ParseCa(peerCaPem);   // throws on junk
            return EnsureTrustContains(mine, peerCaPem);
        }

        /// <summary>Stops trusting a peer CA (by its fingerprint) and rewrites the trust file. Takes effect for NEW connections after the next <c>ZenohBroker.Open</c>.</summary>
        public static bool UntrustPeer(YuukoCertificate mine, string caFingerprint)
        {
            var keep = new List<string>();
            bool removed = false;
            foreach (var pem in ReadPems(mine.TrustBundlePath))
            {
                using var c = X509Certificate2.CreateFromPem(pem);
                if (Fingerprint(c) == caFingerprint.Trim().ToLowerInvariant() && Fingerprint(c) != mine.CaFingerprint) { removed = true; continue; }
                keep.Add(pem);
            }
            if (removed) WriteText(mine.TrustBundlePath, string.Join("\n", keep) + "\n", secret: false);
            return removed;
        }

        /// <summary>Fingerprints of every CA this device trusts (its own first).</summary>
        public static IReadOnlyList<string> TrustedFingerprints(YuukoCertificate mine) =>
            ReadPems(mine.TrustBundlePath).Select(p => { using var c = X509Certificate2.CreateFromPem(p); return Fingerprint(c); }).ToList();

        /// <summary>
        /// Points <paramref name="options"/> at this certificate: turns TLS on, presents the certificate when listening
        /// and when connecting, and trusts the CAs in the trust file.
        /// </summary>
        /// <param name="requireClientCertificates">
        /// Demand a certificate from whoever connects (mutual TLS, the default). A stranger is turned away before a single
        /// Yuuko message is read. A device being paired gets past it with the short-lived certificate in its pairing code.
        /// </param>
        public static void Apply(ZenohBrokerOptions options, YuukoCertificate cert, bool requireClientCertificates = true)
        {
            if (options is null) throw new ArgumentNullException(nameof(options));
            options.EnableTls = true;
            options.TlsCertificate = cert;
            options.TlsRootCaCertificate = cert.TrustBundlePath;
            options.TlsListenCertificate = cert.CertPath;
            options.TlsListenPrivateKey = cert.KeyPath;
            options.TlsConnectCertificate = cert.CertPath;
            options.TlsConnectPrivateKey = cert.KeyPath;
            options.TlsEnableMutual = requireClientCertificates;
            options.TlsVerifyNameOnConnect = false;   // devices are known by key, not by DNS name; the CA check is what counts here
        }

        // ── creation ─────────────────────────────────────────────────────────────

        private static void CreateAll(string dir, string deviceId, TimeSpan leafLifetime)
        {
            using var caKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            var caReq = new CertificateRequest("CN=" + deviceId + " (Yuuko CA)", caKey, HashAlgorithmName.SHA256);
            caReq.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, true, 0, true));
            caReq.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
            caReq.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(caReq.PublicKey, false));

            var now = DateTimeOffset.UtcNow;
            using var ca = caReq.CreateSelfSigned(now.AddMinutes(-5), now.Add(DefaultCaLifetime));

            WriteText(Path.Combine(dir, CaKeyFile), caKey.ExportPkcs8PrivateKeyPem(), secret: true);
            WriteText(Path.Combine(dir, CaCertFile), ca.ExportCertificatePem(), secret: false);

            IssueLeaf(dir, deviceId, ca, leafLifetime);
        }

        // 'ca' must carry its private key.
        private static void IssueLeaf(string dir, string deviceId, X509Certificate2 ca, TimeSpan lifetime)
        {
            using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            var now = DateTimeOffset.UtcNow;
            using var leaf = SignLeaf(ca, key, deviceId, now.AddMinutes(-5), now.Add(lifetime));
            WriteText(Path.Combine(dir, KeyFile), key.ExportPkcs8PrivateKeyPem(), secret: true);
            WriteText(Path.Combine(dir, CertFile), leaf.ExportCertificatePem(), secret: false);
        }

        private static X509Certificate2 SignLeaf(X509Certificate2 ca, ECDsa key, string commonName, DateTimeOffset notBefore, DateTimeOffset notAfter)
        {
            var req = new CertificateRequest("CN=" + commonName, key, HashAlgorithmName.SHA256);
            req.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
            req.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true));
            req.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(new OidCollection
            {
                new Oid("1.3.6.1.5.5.7.3.1"),   // server authentication
                new Oid("1.3.6.1.5.5.7.3.2"),   // client authentication
            }, false));
            var san = new SubjectAlternativeNameBuilder();
            san.AddDnsName("yuuko.device");   // present for strict clients; names are not checked (see Apply)
            req.CertificateExtensions.Add(san.Build());
            req.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(req.PublicKey, false));
            req.CertificateExtensions.Add(X509AuthorityKeyIdentifierExtension.CreateFromCertificate(ca, true, false));

            var caEnd = new DateTimeOffset(ca.NotAfter.ToUniversalTime());
            if (notAfter > caEnd) notAfter = caEnd;   // a certificate cannot outlive the one that signed it

            byte[] serial = RandomNumberGenerator.GetBytes(16);
            serial[0] &= 0x7F;   // keep it positive
            if (serial[0] == 0) serial[0] = 1;

            return req.Create(ca, notBefore, notAfter, serial);
        }

        /// <summary>
        /// A short-lived certificate and key for ONE newcomer, signed by this device's CA, so that device can get through
        /// mutual TLS to be paired. It goes in the pairing code (<see cref="PairingCode"/>) and stops working at
        /// <paramref name="lifetime"/>; it is never saved by the device that issues it. (Existing links are not cut when
        /// it expires, and a certificate only matters to the TLS layer: the Yuuko handshake still has to succeed.)
        /// </summary>
        public static (string CertPem, string KeyPem) IssueTemporary(YuukoCertificate mine, TimeSpan lifetime)
        {
            if (lifetime <= TimeSpan.Zero || lifetime > TimeSpan.FromHours(2)) throw new ArgumentOutOfRangeException(nameof(lifetime));
            using var ca = X509Certificate2.CreateFromPem(File.ReadAllText(mine.CaCertPath), File.ReadAllText(Path.Combine(mine.Directory, CaKeyFile)));
            using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            var now = DateTimeOffset.UtcNow;
            using var leaf = SignLeaf(ca, key, "yuuko-pairing", now.AddMinutes(-5), now.Add(lifetime));
            return (leaf.ExportCertificatePem(), key.ExportPkcs8PrivateKeyPem());
        }

        /// <summary>Saves a pairing code's temporary certificate and key next to this device's own, and returns their paths. <see cref="AdoptGroup"/> removes them again.</summary>
        public static (string CertPath, string KeyPath) WritePairingCredentials(YuukoCertificate mine, string certPem, string keyPem)
        {
            string cp = Path.Combine(mine.Directory, "pairing-cert.pem"), kp = Path.Combine(mine.Directory, "pairing-key.pem");
            WriteText(kp, keyPem, secret: true);
            WriteText(cp, certPem, secret: false);
            return (cp, kp);
        }

        /// <summary>
        /// Joins another device's group at the TLS layer: this device's CA is replaced by that group's CA (certificate AND
        /// key, handed over by the device that paired us, over the encrypted session), a new certificate is issued from
        /// it, and the old CA stops being trusted. From then on every member trusts the same single CA, so adding a device
        /// never means updating the others. <b>The transport must be opened again to use the new certificate.</b>
        /// Holding the group's CA key lets this device issue certificates too, so every member is trusted with it.
        /// </summary>
        public static YuukoCertificate AdoptGroup(YuukoCertificate mine, string groupCaPem, string groupCaKeyPem)
        {
            if (mine is null) throw new ArgumentNullException(nameof(mine));
            using (ParseCa(groupCaPem)) { }   // must be a real, unexpired CA
            using (var withKey = X509Certificate2.CreateFromPem(groupCaPem, groupCaKeyPem))
                if (!withKey.HasPrivateKey || !KeyMatchesCertificate(withKey, withKey.GetECDsaPrivateKey()))
                    throw new ArgumentException("The CA key does not belong to that CA certificate.");

            string oldFingerprint = FingerprintOfPem(File.ReadAllText(mine.CaCertPath));
            WriteText(Path.Combine(mine.Directory, CaKeyFile), groupCaKeyPem, secret: true);
            WriteText(mine.CaCertPath, groupCaPem.Trim() + Environment.NewLine, secret: false);

            // Our old certificate was signed by the old CA: drop it so a new one is issued from the group CA.
            File.Delete(mine.CertPath);
            File.Delete(mine.KeyPath);
            File.Delete(Path.Combine(mine.Directory, "pairing-cert.pem"));   // the temporary pairing certificate has done its job
            File.Delete(Path.Combine(mine.Directory, "pairing-key.pem"));

            // The old CA is no longer ours to trust; the group CA is.
            var keep = ReadPems(mine.TrustBundlePath).Where(p => FingerprintOfPem(p) != oldFingerprint).ToList();
            WriteText(mine.TrustBundlePath, string.Join(Environment.NewLine, keep) + (keep.Count > 0 ? Environment.NewLine : ""), secret: false);

            return EnsureCertificate(mine.Directory, mine.DeviceId);
        }

        private static bool TryLoadCa(string dir, string deviceId, TimeSpan margin, out X509Certificate2? ca)
        {
            ca = null;
            try
            {
                string caPath = Path.Combine(dir, CaCertFile), keyPath = Path.Combine(dir, CaKeyFile);
                if (!File.Exists(caPath) || !File.Exists(keyPath)) return false;
                var c = X509Certificate2.CreateFromPem(File.ReadAllText(caPath), File.ReadAllText(keyPath));
                bool good = c.HasPrivateKey
                    && c.NotAfter.ToUniversalTime() - DateTime.UtcNow > margin;
                if (!good) { c.Dispose(); return false; }
                ca = c;
                return true;
            }
            catch { return false; }
        }

        // ── trust file ───────────────────────────────────────────────────────────

        private static bool EnsureTrustContains(YuukoCertificate mine, string pem)
        {
            using var wanted = ParseCa(pem);
            string fp = Fingerprint(wanted);

            var existing = File.Exists(mine.TrustBundlePath) ? ReadPems(mine.TrustBundlePath) : new List<string>();
            foreach (var p in existing)
            {
                try { using var c = X509Certificate2.CreateFromPem(p); if (Fingerprint(c) == fp) return false; }
                catch { /* a damaged entry is dropped when we rewrite below */ }
            }

            var all = new List<string>();
            foreach (var p in existing)
            {
                try { using var _ = X509Certificate2.CreateFromPem(p); all.Add(p.Trim()); } catch { }
            }
            all.Add(wanted.ExportCertificatePem().Trim());
            WriteText(mine.TrustBundlePath, string.Join("\n", all) + "\n", secret: false);
            return true;
        }

        // Only a real CA certificate may be trusted: a stray end-entity certificate would let that one device in.
        private static X509Certificate2 ParseCa(string pem)
        {
            var c = X509Certificate2.CreateFromPem(pem);
            var bc = c.Extensions.OfType<X509BasicConstraintsExtension>().FirstOrDefault();
            if (bc is null || !bc.CertificateAuthority) { c.Dispose(); throw new ArgumentException("That is not a CA certificate."); }
            if (c.NotAfter.ToUniversalTime() <= DateTime.UtcNow) { c.Dispose(); throw new ArgumentException("That CA certificate has expired."); }
            return c;
        }

        private static List<string> ReadPems(string path)
        {
            var list = new List<string>();
            if (!File.Exists(path)) return list;
            const string begin = "-----BEGIN CERTIFICATE-----", end = "-----END CERTIFICATE-----";
            string text = File.ReadAllText(path);
            int i = 0;
            while ((i = text.IndexOf(begin, i, StringComparison.Ordinal)) >= 0)
            {
                int j = text.IndexOf(end, i, StringComparison.Ordinal);
                if (j < 0) break;
                list.Add(text.Substring(i, j + end.Length - i));
                i = j + end.Length;
            }
            return list;
        }

        // ── helpers ──────────────────────────────────────────────────────────────

        /// <summary>SHA-256 of a certificate, lowercase hex. This is what identifies a CA.</summary>
        public static string Fingerprint(X509Certificate2 cert) =>
            Convert.ToHexString(SHA256.HashData(cert.RawData)).ToLowerInvariant();

        /// <summary>Fingerprint of the first certificate in <paramref name="pem"/>.</summary>
        public static string FingerprintOfPem(string pem)
        {
            using var c = X509Certificate2.CreateFromPem(pem);
            return Fingerprint(c);
        }

        // Does this private key really belong to this certificate? (Checked explicitly: do not rely on the loader to refuse a mismatch.)
        private static bool KeyMatchesCertificate(X509Certificate2 cert, ECDsa? key)
        {
            if (key is null) return false;
            using var pub = cert.GetECDsaPublicKey();
            return pub is not null && CryptographicOperations.FixedTimeEquals(pub.ExportSubjectPublicKeyInfo(), key.ExportSubjectPublicKeyInfo());
        }

        private static string CommonName(X509Certificate2 c) => c.GetNameInfo(X509NameType.SimpleName, false);

        private static bool SignedBy(X509Certificate2 leaf, X509Certificate2 ca)
        {
            using var chain = new X509Chain();
            chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
            chain.ChainPolicy.CustomTrustStore.Add(ca);
            chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
            chain.ChainPolicy.VerificationFlags = X509VerificationFlags.IgnoreNotTimeValid;   // time is judged separately
            return chain.Build(leaf);
        }

        private static string Sanitize(string s)
        {
            var sb = new StringBuilder();
            foreach (char c in s) sb.Append(char.IsAsciiLetterOrDigit(c) || c is '.' or '_' or '-' ? c : '_');
            return sb.Length == 0 ? "device" : sb.ToString();
        }

        private static void WriteText(string path, string text, bool secret)
        {
            string tmp = path + ".tmp";
            File.WriteAllText(tmp, text);
            if (secret) RestrictToOwner(tmp, isDirectory: false);
            File.Move(tmp, path, overwrite: true);
        }

        // Unix: owner only. Windows: the folder under the user's profile is already private to the user; nothing to do.
        private static void RestrictToOwner(string path, bool isDirectory)
        {
            if (OperatingSystem.IsWindows()) return;
            try
            {
                File.SetUnixFileMode(path, isDirectory
                    ? UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute
                    : UnixFileMode.UserRead | UnixFileMode.UserWrite);
            }
            catch { /* best effort */ }
        }
    }
}
