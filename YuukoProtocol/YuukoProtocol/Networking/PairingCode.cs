// PairingCode.cs
// The thing one device shows (as text, or as a QR code made from the text) and another device reads.
//
// It carries what a new device needs to find and trust the device that made it:
//   - the device's name and key fingerprint   (so the new device pins the RIGHT keys before it connects)
//   - the address and port it listens on      (so nobody has to type an IP address)
//   - its TLS CA certificate                  (so the new device can verify the link before sending anything)
//   - a one-time token                        (so the device that made the code can tell a real newcomer from a stranger)
//
// THE CODE IS A SECRET until it has been used or has expired: whoever has it can pair. It is never sent over the
// network; the token only enters the key derivation of one handshake (see YuukoHandshake.BeginPairing).
//
// Text form:  YUUKO1-XXXXXX-XXXXXX-...   (Crockford base32 + a 4-byte checksum, so a typo is caught instead of misread)

using System;
using System.Buffers.Binary;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace YuukoProtocol
{
    public sealed class PairingCode
    {
        public const string Prefix = "YUUKO2-";
        private const int Version = 2;
        private const int MaxTextLength = 8192;
        private const int TokenBytes = 16;

        public string DeviceId { get; }
        /// <summary>The offering device's key fingerprint (64 hex characters).</summary>
        public string Fingerprint { get; }
        /// <summary>Where to connect, e.g. <c>tcp/192.168.1.5:7447</c>. Null if the offering device can be found another way (LAN discovery with TLS off).</summary>
        public string? Endpoint { get; }
        /// <summary>The offering device's TLS CA certificate (PEM), if its link uses TLS.</summary>
        public string? CaCertificatePem { get; }
        /// <summary>A short-lived TLS client certificate issued for this one newcomer, so it can get through the offering device's mutual TLS. Part of the secret.</summary>
        public string? BootstrapCertificatePem { get; }
        internal string? BootstrapPrivateKeyPem { get; }
        internal byte[] Token { get; }
        public DateTimeOffset ExpiresUtc { get; }

        public bool IsExpired => DateTimeOffset.UtcNow >= ExpiresUtc;

        public PairingCode(string deviceId, string fingerprint, string? endpoint, string? caCertificatePem, byte[] token, DateTimeOffset expiresUtc,
            string? bootstrapCertificatePem = null, string? bootstrapPrivateKeyPem = null)
        {
            if (string.IsNullOrWhiteSpace(deviceId) || Encoding.UTF8.GetByteCount(deviceId) > 128) throw new ArgumentException("deviceId must be 1-128 bytes.", nameof(deviceId));
            var fp = (fingerprint ?? "").Trim().ToLowerInvariant();
            if (fp.Length != 64 || !fp.All(Uri.IsHexDigit)) throw new ArgumentException("fingerprint must be 64 hex characters.", nameof(fingerprint));
            if (token is null || token.Length != TokenBytes) throw new ArgumentException($"token must be {TokenBytes} bytes.", nameof(token));
            if (endpoint is not null && Encoding.UTF8.GetByteCount(endpoint) > 512) throw new ArgumentException("endpoint is too long.", nameof(endpoint));

            DeviceId = deviceId;
            Fingerprint = fp;
            Endpoint = string.IsNullOrWhiteSpace(endpoint) ? null : endpoint;
            CaCertificatePem = string.IsNullOrWhiteSpace(caCertificatePem) ? null : caCertificatePem;
            if (string.IsNullOrWhiteSpace(bootstrapCertificatePem) != string.IsNullOrWhiteSpace(bootstrapPrivateKeyPem))
                throw new ArgumentException("The temporary certificate and its key come together.");
            BootstrapCertificatePem = string.IsNullOrWhiteSpace(bootstrapCertificatePem) ? null : bootstrapCertificatePem;
            BootstrapPrivateKeyPem = string.IsNullOrWhiteSpace(bootstrapPrivateKeyPem) ? null : bootstrapPrivateKeyPem;
            Token = (byte[])token.Clone();
            ExpiresUtc = expiresUtc;
        }

        /// <summary>The text to show or turn into a QR code. Treat it like a password until it has been used.</summary>
        public string Encode() => EncodeCore(CaCertificatePem is null ? Array.Empty<byte>() : PemToDer(CaCertificatePem));

        // The certificate bytes are a parameter only so the self-test can make a code with a VALID checksum and a broken certificate.
        internal string EncodeCore(byte[] ca)
        {
            byte[] id = Encoding.UTF8.GetBytes(DeviceId);
            byte[] ep = Endpoint is null ? Array.Empty<byte>() : Encoding.UTF8.GetBytes(Endpoint);

            using var ms = new System.IO.MemoryStream();
            ms.WriteByte(Version);
            Span<byte> eight = stackalloc byte[8];
            BinaryPrimitives.WriteInt64BigEndian(eight, ExpiresUtc.ToUnixTimeSeconds());
            ms.Write(eight);
            ms.Write(Token);
            ms.Write(Convert.FromHexString(Fingerprint));
            ms.WriteByte((byte)id.Length); ms.Write(id);
            Span<byte> two = stackalloc byte[2];
            BinaryPrimitives.WriteUInt16BigEndian(two, (ushort)ep.Length); ms.Write(two); ms.Write(ep);
            BinaryPrimitives.WriteUInt16BigEndian(two, (ushort)ca.Length); ms.Write(two); ms.Write(ca);
            byte[] bc = BootstrapCertificatePem is null ? Array.Empty<byte>() : PemToDer(BootstrapCertificatePem);
            byte[] bk = BootstrapPrivateKeyPem is null ? Array.Empty<byte>() : KeyPemToDer(BootstrapPrivateKeyPem);
            BinaryPrimitives.WriteUInt16BigEndian(two, (ushort)bc.Length); ms.Write(two); ms.Write(bc);
            BinaryPrimitives.WriteUInt16BigEndian(two, (ushort)bk.Length); ms.Write(two); ms.Write(bk);

            byte[] body = ms.ToArray();
            byte[] all = new byte[body.Length + 4];
            body.CopyTo(all, 0);
            SHA256.HashData(body).AsSpan(0, 4).CopyTo(all.AsSpan(body.Length));

            string b32 = Base32.Encode(all);
            var sb = new StringBuilder(Prefix);
            for (int i = 0; i < b32.Length; i += 6)
            {
                if (i > 0) sb.Append('-');
                sb.Append(b32, i, Math.Min(6, b32.Length - i));
            }
            return sb.ToString();
        }

        public static PairingCode Parse(string text) =>
            TryParse(text, out var code, out var error) ? code! : throw new FormatException(error);

        /// <summary>Reads a code typed or scanned by a person. Forgives spaces, dashes, lower case and O/0, I/L/1 mix-ups; refuses anything damaged.</summary>
        public static bool TryParse(string? text, out PairingCode? code, out string? error)
        {
            code = null; error = null;
            try
            {
                if (string.IsNullOrWhiteSpace(text)) { error = "The pairing code is empty."; return false; }
                if (text.Length > MaxTextLength) { error = "That is too long to be a pairing code."; return false; }

                string t = new string(text.Where(c => !char.IsWhiteSpace(c) && c != '-').ToArray()).ToUpperInvariant();
                string prefix = Prefix.Replace("-", "");
                if (!t.StartsWith(prefix, StringComparison.Ordinal)) { error = "That is not a Yuuko pairing code (it should start with YUUKO1)."; return false; }

                byte[]? all = Base32.Decode(t[prefix.Length..]);
                if (all is null || all.Length < 4 + 1 + 8 + TokenBytes + 32 + 1 + 2 + 2 + 2 + 2) { error = "That pairing code is damaged or incomplete. Check it was copied completely."; return false; }

                byte[] body = all[..^4];
                if (!CryptographicOperations.FixedTimeEquals(all.AsSpan(all.Length - 4), SHA256.HashData(body).AsSpan(0, 4)))
                { error = "That pairing code has a typo or is cut short (checksum does not match)."; return false; }
                if (body[0] != Version) { error = "That pairing code is from a different version of Yuuko Protocol."; return false; }

                int p = 1;
                long expires = BinaryPrimitives.ReadInt64BigEndian(body.AsSpan(p, 8)); p += 8;
                byte[] token = body[p..(p + TokenBytes)]; p += TokenBytes;
                string fp = Convert.ToHexString(body.AsSpan(p, 32)).ToLowerInvariant(); p += 32;
                int idLen = body[p++];
                if (p + idLen + 4 > body.Length) { error = "That pairing code is damaged."; return false; }
                string id = Encoding.UTF8.GetString(body, p, idLen); p += idLen;
                int epLen = BinaryPrimitives.ReadUInt16BigEndian(body.AsSpan(p, 2)); p += 2;
                if (p + epLen + 2 > body.Length) { error = "That pairing code is damaged."; return false; }
                string? ep = epLen == 0 ? null : Encoding.UTF8.GetString(body, p, epLen); p += epLen;
                int caLen = BinaryPrimitives.ReadUInt16BigEndian(body.AsSpan(p, 2)); p += 2;
                if (p + caLen + 4 > body.Length) { error = "That pairing code is damaged."; return false; }
                string? caPem = caLen == 0 ? null : DerToPem(body.AsSpan(p, caLen).ToArray()); p += caLen;
                int bcLen = BinaryPrimitives.ReadUInt16BigEndian(body.AsSpan(p, 2)); p += 2;
                if (p + bcLen + 2 > body.Length) { error = "That pairing code is damaged."; return false; }
                string? bcPem = bcLen == 0 ? null : DerToPem(body.AsSpan(p, bcLen).ToArray()); p += bcLen;
                int bkLen = BinaryPrimitives.ReadUInt16BigEndian(body.AsSpan(p, 2)); p += 2;
                if (p + bkLen != body.Length) { error = "That pairing code is damaged."; return false; }
                string? bkPem = bkLen == 0 ? null : KeyDerToPem(body.AsSpan(p, bkLen).ToArray());
                if ((bcPem is null) != (bkPem is null)) { error = "That pairing code is damaged."; return false; }

                code = new PairingCode(id, fp, ep, caPem, token, DateTimeOffset.FromUnixTimeSeconds(expires), bcPem, bkPem);
                return true;
            }
            catch (Exception e) when (e is not OutOfMemoryException)
            {
                // This reads text a stranger may have made (the checksum catches typos, it does not authenticate),
                // so whatever is wrong inside it - a bad certificate, odd lengths - is "damaged", never a crash.
                code = null;
                error = "That pairing code is damaged.";
                return false;
            }
        }

        /// <summary>
        /// Transport settings for a device that is about to join using this code: connects to the code's address and trusts
        /// the code's TLS certificate. Creates this device's own certificate first if it has none. Open the transport
        /// with the result, then call <see cref="EclipseBroker.PairWithAsync"/>.
        /// </summary>
        public ZenohBrokerOptions ToTransportOptions(string? deviceName = null, string? tlsDirectory = null)
        {
            var o = new ZenohBrokerOptions { DeviceName = deviceName, TlsDirectory = tlsDirectory };
            if (Endpoint is not null) o.ConnectEndpoints.Add(Endpoint);

            if (CaCertificatePem is null)
            {
                o.EnableTls = false;   // the offering device does not use TLS, so this link cannot either
                return o;
            }

            string name = string.IsNullOrWhiteSpace(deviceName) ? Environment.MachineName : deviceName!;
            var mine = YuukoTls.EnsureCertificate(tlsDirectory ?? YuukoTls.DefaultDirectory(name), name);
            YuukoTls.TrustPeer(mine, CaCertificatePem);   // so we can check THEIR certificate
            YuukoTls.Apply(o, mine);                      // mutual TLS on; our own certificate for anyone who connects to us

            // The temporary certificate is what gets us through THEIR mutual TLS while we are being paired.
            if (BootstrapCertificatePem is not null && BootstrapPrivateKeyPem is not null)
            {
                var (certPath, keyPath) = YuukoTls.WritePairingCredentials(mine, BootstrapCertificatePem, BootstrapPrivateKeyPem);
                o.TlsConnectCertificate = certPath;
                o.TlsConnectPrivateKey = keyPath;
            }
            return o;
        }

        // Never print the token.
        public override string ToString() => $"PairingCode({DeviceId}, expires {ExpiresUtc:u})";

        private static byte[] PemToDer(string pem)
        {
            using var c = System.Security.Cryptography.X509Certificates.X509Certificate2.CreateFromPem(pem);
            return c.RawData;
        }

        private static byte[] KeyPemToDer(string pem)
        {
            var found = PemEncoding.Find(pem);
            return Convert.FromBase64String(pem[found.Base64Data]);
        }

        // Also proves the bytes are a usable key: anything else throws, and TryParse turns that into "damaged".
        private static string KeyDerToPem(byte[] der)
        {
            using var key = ECDsa.Create();
            key.ImportPkcs8PrivateKey(der, out _);
            return new string(PemEncoding.Write("PRIVATE KEY", der));
        }

        private static string DerToPem(byte[] der)
        {
            using var c = System.Security.Cryptography.X509Certificates.X509Certificate2.CreateFromPem(
                new string(PemEncoding.Write("CERTIFICATE", der)));
            return c.ExportCertificatePem();
        }

        // Crockford base32: no I, L, O or U, so a code read aloud or off a screen is hard to get wrong.
        private static class Base32
        {
            private const string Alphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";

            public static string Encode(byte[] data)
            {
                var sb = new StringBuilder((data.Length * 8 + 4) / 5);
                int buffer = 0, bits = 0;
                foreach (byte b in data)
                {
                    buffer = (buffer << 8) | b;
                    bits += 8;
                    while (bits >= 5) { sb.Append(Alphabet[(buffer >> (bits - 5)) & 31]); bits -= 5; }
                }
                if (bits > 0) sb.Append(Alphabet[(buffer << (5 - bits)) & 31]);
                return sb.ToString();
            }

            public static byte[]? Decode(string text)
            {
                var output = new System.IO.MemoryStream();
                int buffer = 0, bits = 0;
                foreach (char raw in text)
                {
                    char c = raw switch { 'O' => '0', 'I' or 'L' => '1', _ => raw };
                    int v = Alphabet.IndexOf(c);
                    if (v < 0) return null;
                    buffer = (buffer << 5) | v;
                    bits += 5;
                    if (bits >= 8) { output.WriteByte((byte)((buffer >> (bits - 8)) & 0xFF)); bits -= 8; }
                }
                return output.ToArray();
            }
        }
    }
}
