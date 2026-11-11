"""
mutation-check.py - proves the self-test would notice if the security code broke.

A passing test only means something if it would FAIL when the code is wrong. This script breaks the
code on purpose, one security rule at a time, runs the self-test, and checks that it complains.
Then it puts every file back exactly as it was.

    python tools/mutation-check.py            run all of them (takes a few minutes)
    python tools/mutation-check.py M1 M7      run only the ones whose label starts with M1 / M7

Exit code 0 = every deliberate break was caught. 1 = something slipped past the tests (or an anchor
below no longer matches the code, which means this file needs updating after your change).

If it is interrupted, leftover copies are named *.mutbak next to the source file: copy one back over
the original (or run `git diff` to see what is different).
"""
import os
import shutil
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))   # the solution folder
HS = os.path.join(ROOT, "YuukoProtocol", "Networking", "YuukoHandshake.cs")
EB = os.path.join(ROOT, "YuukoProtocol", "Networking", "EclipseBroker.cs")
TLS = os.path.join(ROOT, "YuukoProtocol", "Networking", "YuukoTls.cs")
PC = os.path.join(ROOT, "YuukoProtocol", "Networking", "PairingCode.cs")
ZB = os.path.join(ROOT, "YuukoProtocol", "Networking", "ZenohBroker.cs")
DD = os.path.join(ROOT, "YuukoProtocol", "Networking", "DeviceDirectory.cs")
AL = os.path.join(ROOT, "YuukoProtocol", "Networking", "AuditLog.cs")
OPT = os.path.join(ROOT, "YuukoProtocol", "Dogma", "OpTransform.cs")
OTS = os.path.join(ROOT, "YuukoProtocol", "Dogma", "OtSession.cs")
DS = os.path.join(ROOT, "YuukoProtocol", "Dogma", "DocSync.cs")
SC = os.path.join(ROOT, "YuukoProtocol", "Dogma", "SimpleCRDT.cs")

# (label, [(file, exact text to replace, what to replace it with), ...])
# A mutation may change several places at once (needed when both ends of the protocol must agree).
MUTATIONS = [
    ("M1 provider signature check removed", [(HS,
        'if (!YuukoIdentity.VerifySignature(ch.ProviderSigPub, transcript, ch.Signature))\n'
        '                    throw new CryptographicException("Provider signature is invalid.");',
        '// MUTATION: signature check removed')]),
    ("M2 requester no longer checks the provider pin", [(HS,
        'if (_opts.RequireKnownDevices)\n                {\n'
        '                    if (!_opts.TrustedDevices.TryGetValue(ch.FromId, out var pinned)',
        'if (false)\n                {\n'
        '                    if (!_opts.TrustedDevices.TryGetValue(ch.FromId, out var pinned)')]),
    ("M3 provider allowlist check removed", [(HS,
        'if (_opts.RequireKnownDevices && !pairing && !IsPinnedDevice(hello))',
        'if (false && _opts.RequireKnownDevices && !pairing && !IsPinnedDevice(hello))')]),
    ("M4 any ACCEPT is believed (no decrypt check)", [(HS,
        'try\n            {\n'
        '                byte[] plain = session.DecryptOnLane(HandshakeSession.HandshakeLane, acc.EncAccept, "ACCEPT");\n'
        '                if (!CryptographicOperations.FixedTimeEquals(plain, Encoding.UTF8.GetBytes(acc.HandshakeId))) return;\n'
        '            }\n            catch { return; }',
        '// MUTATION: accept check removed')]),
    ("M5 a Close is believed without decrypting it", [(EB,
        'try { reason = Encoding.UTF8.GetString(session.DecryptOnLane(HandshakeSession.ControlLane, msg.Payload, "CLOSE")); }\n'
        '            catch { return; }   // not really from the peer',
        'reason = "forged";')]),
    ("M6 retries run the command again (no dedupe)", [(EB,
        'if (!_recent.TryAdd(key, record))',
        '_recent[key] = record; if (false)')]),
    ("M7 forward secrecy removed (throw-away secret not mixed into the keys)", [
        (HS, 'hello.NonceC, transcript, encap.key, encapEph.key);',
             'hello.NonceC, transcript, encap.key, null);'),
        (HS, 'state.NonceC, transcript, secretLong, secretEph);',
             'state.NonceC, transcript, secretLong, null);')]),
    ("M8 identity files saved unencrypted even with a password", [(HS,
        'byte[] content = password is null ? Export() : ExportEncrypted(password);',
        'byte[] content = Export();')]),
    ("M9 session rotation switched off", [(HS,
        '_opts.MaxSessionAge > TimeSpan.Zero && DateTimeOffset.UtcNow - s.CreatedUtc > _opts.MaxSessionAge;',
        'false;')]),
    ("M10 hard session expiry switched off", [(HS,
        '_opts.MaxSessionAge > TimeSpan.Zero && DateTimeOffset.UtcNow - s.CreatedUtc > _opts.MaxSessionAge + _opts.RotationGrace;',
        'false;')]),
    ("M11 broadcasts are not remembered (a relayed change can loop / run twice)", [(EB,
        'if (!_relaySeen.TryAdd(key, DateTimeOffset.UtcNow + RelayRememberFor))',
        '_relaySeen[key] = DateTimeOffset.UtcNow + RelayRememberFor; if (false)')]),
    ("M12 hop limit ignored (a broadcast is always passed on)", [(EB,
        'if (ttl > 0)\n            {\n                var next',
        'if (true)\n            {\n                var next')]),
    ("M13 authorizer skipped for relayed commands", [(EB,
        'if (!IsRelayableBuiltIn(env.Name) && _opts.CommandAuthorizer is { } authorize)',
        'if (!IsRelayableBuiltIn(env.Name) && _opts.CommandAuthorizer is { } authorize && false)')]),
    ("M14 broadcast origin never verified", [(EB,
        'string? problem = VerifyBroadcast(env);',
        'string? problem = null;')]),
    ("M15 broadcast keys not compared with the trusted fingerprint", [(EB,
        'if (!string.Equals(actual, expected, StringComparison.OrdinalIgnoreCase)) return "keys do not match the trusted origin";',
        '')]),
    ("M16 broadcast age not checked", [(EB,
        'if (now - env.SignedAtMs > (long)_opts.RelayMaxAge.TotalMilliseconds) return "broadcast too old";',
        '')]),
    ("M17 broadcast data not covered by the signature", [(EB,
        'w.Write(System.Security.Cryptography.SHA256.HashData(data));',
        '')]),
    ("M18 broadcast command name not covered by the signature", [(EB,
        '                w.Write(name);\n                w.Write(signedAtMs);',
        '                w.Write(signedAtMs);')]),
    ("M19 unknown origins accepted (no trust lookup)", [(EB,
        'if (expected is null) return "origin is not trusted here";',
        'if (expected is null) expected = YuukoIdentity.FingerprintOf(env.Keys);')]),
    ("M20 pairing token not mixed into the keys (any token would do)", [
        (HS, 'pairing ? CombinePsk(_opts.PreSharedKey, pairToken!) : _opts.PreSharedKey,',
             '_opts.PreSharedKey,'),
        (HS, 'state.PairingToken is null ? _opts.PreSharedKey : CombinePsk(_opts.PreSharedKey, state.PairingToken),',
             '_opts.PreSharedKey,')]),
    ("M21 pairing token not spent after use (a code works repeatedly)", [(HS,
        '_pairToken = null;\n                return true;',
        'return true;')]),
    ("M22 pairing attempts not limited", [(HS,
        '_pairAttemptsLeft--;', '')]),
    ("M23 pairing may overwrite a name that is already paired with other keys", [(HS,
        'if (pairing && _opts.TrustedDevices.ContainsKey(hello.FromId) && !IsPinnedDevice(hello))',
        'if (false && pairing && _opts.TrustedDevices.ContainsKey(hello.FromId) && !IsPinnedDevice(hello))')]),
    ("M24 pairing window never expires", [
        (HS, 'if (_pairToken is null || DateTimeOffset.UtcNow >= _pairExpires || _pairAttemptsLeft <= 0) return false;',
             'if (_pairToken is null || _pairAttemptsLeft <= 0) return false;'),
        (HS, 'if (_pairToken is null || DateTimeOffset.UtcNow >= _pairExpires) return false;\n                CryptographicOperations',
             'if (_pairToken is null) return false;\n                CryptographicOperations')]),
    ("M25 group changes accepted when no policy is set", [(EB,
        'if (_opts.GroupChangePolicy is not { } policy)\n            {',
        'var policy = _opts.GroupChangePolicy ?? (_ => Task.FromResult(true));\n            if (false)\n            {')]),
    ("M26 an introduction may replace the keys of a name already trusted", [(EB,
        ': CommandResult.Denied("that name is already paired with different keys");',
        ': CommandResult.Ok("already trusted");')]),
    ("M27 a non-CA certificate is accepted as a trust anchor", [(TLS,
        'if (bc is null || !bc.CertificateAuthority) { c.Dispose(); throw new ArgumentException("That is not a CA certificate."); }',
        '')]),
    ("M28 a certificate signed by another CA is accepted", [(TLS,
        'if (!SignedBy(leaf, caCert)) return CertificateState.Invalid;',
        '')]),
    ("M29 pairing code checksum not verified", [(PC,
        'if (!CryptographicOperations.FixedTimeEquals(all.AsSpan(all.Length - 4), SHA256.HashData(body).AsSpan(0, 4)))',
        'if (false)')]),
    ("M30 the TLS group (a signing key) is accepted from anyone, any time", [(EB,
        'if (from is null || !string.Equals(from, ctx.FromId, StringComparison.Ordinal) || Environment.TickCount64 > until)',
        'if (false)')]),
    # M31 / M34 (adopting a CA, or loading a leaf, with a key that does not match) are omitted on purpose: on Windows
    # .NET's own loader refuses a mismatched key, so the explicit KeyMatchesCertificate checks (kept for platforms
    # where it may not) can never be the thing that fails. The tests still prove the outcome.
    ("M32 a device with paired devices abandons them to join another group", [(EB,
        'if (mine.CaFingerprint != YuukoTls.FingerprintOfPem(code.CaCertificatePem) && Devices.All().Count > 0)',
        'if (false)')]),
    ("M33 mutual TLS off by default", [(ZB,
        'public bool TlsEnableMutual { get; set; } = true;',
        'public bool TlsEnableMutual { get; set; } = false;')]),
    ("M35 pairing does not start listening first (the group handover is lost)", [(EB,
        '            await StartAsync(ct).ConfigureAwait(false);\n\n            // With TLS, the other device will hand us',
        '            // (not started)\n\n            // With TLS, the other device will hand us')]),
    ("M36 the temporary pairing certificate lasts far longer than asked", [(TLS,
        'using var leaf = SignLeaf(ca, key, "yuuko-pairing", now.AddMinutes(-5), now.Add(lifetime));',
        'using var leaf = SignLeaf(ca, key, "yuuko-pairing", now.AddMinutes(-5), now.AddDays(300));')]),
    ("M37 options forget which certificate they were built from", [(TLS,
        '            options.TlsCertificate = cert;\n',
        '')]),
    ("M38 the group's signing key is sent without being asked to a device that never paired", [(EB,
        'if (_shareGroupWith.TryRemove(s.RemoteId, out _)) _ = Task.Run(() => ShareGroupAsync(s.RemoteId));',
        '_ = Task.Run(() => ShareGroupAsync(s.RemoteId));')]),
    ("M39 a device list that cannot be opened is treated as empty", [(DD,
        'catch (Exception e) { throw new FormatException(OpenFailureMessage(e), e); }',
        'catch (Exception) { shapeJson = "{\\"Version\\":1,\\"Devices\\":[]}"; }')]),
    ("M40 the previous version of the device list is not kept", [(DD,
        'if (File.Exists(file)) File.Copy(file, file + ".bak", overwrite: true);',
        '')]),
    ("M41 a device list from a newer version is accepted", [(DD,
        'if (f is null || f.Version != 1)',
        'if (f is null)')]),
    ("M42 a device list may name a device twice", [(DD,
        'if (accepted.Any(i => string.Equals(',
        'if (false && accepted.Any(i => string.Equals(')]),
    ("M43 a failed save of the device list is swallowed", [(DD,
        'Run(() => WriteFileAsync(_path, _key, SerializeShape(snapshot)));',
        'try { Run(() => WriteFileAsync(_path, _key, SerializeShape(snapshot))); } catch { }')]),
    ("M44 an unanswered group-change prompt waits forever (holds a command slot)", [(EB,
        'allowed = await Task.WhenAny(decision, timeout).ConfigureAwait(false) == decision\n                          && await decision.ConfigureAwait(false);',
        'allowed = await decision.ConfigureAwait(false);')]),
    ("M45 audit log: the link to the previous entry is not checked", [(AL,
        'if (!string.Equals(e.Prev, prev, StringComparison.Ordinal)) return Bad(e.Seq,',
        'if (false) return Bad(e.Seq,')]),
    ("M46 audit log: the key is ignored (plain hash instead of HMAC)", [(AL,
        'if (_macKey is null) digest = SHA256.HashData(payload);',
        'if (true) digest = SHA256.HashData(payload);')]),
    ("M47 audit log: sealing does not mark the file read-only", [(AL,
        'File.SetAttributes(path, File.GetAttributes(path) | FileAttributes.ReadOnly);',
        '')]),
    ("M48 audit log: a flood of refused connections is written in full", [(AL,
        'if (_refused.TryGetValue(key, out var seen) && now - seen.At < RefusedWindowSeconds * 1000L)',
        'if (false && _refused.TryGetValue(key, out var seen) && now - seen.At < RefusedWindowSeconds * 1000L)')]),
    ("M49 audit log: a log that ends in a half-written entry is added to anyway", [(AL,
        'if (!EndsWithNewline())\n                throw new FormatException($"\'{Path}\' ends in a partly written entry.',
        'if (false)\n                throw new FormatException($"\'{Path}\' ends in a partly written entry.')]),
    ("M50 OT: an edit that cuts an emoji in half is accepted", [(OPT,
        'if (endsWithHigh != startsWithLow)',
        'if (false)')]),
    ("M51 OT: an unconfirmed edit is sent again with its old revision (transformed twice)", [(OPT,
        '_outstanding is null ? null : (Revision, _outstanding);',
        '_outstanding is null ? null : (Math.Max(0, Revision - 1), _outstanding);')]),
    ("M52 OT: a member accepts edits that claim to come from the owner but did not", [(OTS,
        '|| d.OwnerId != ctx.FromId) return CommandResult.Ok();',
        ') return CommandResult.Ok();')]),
    ("M53 OT: an edit sent twice is applied twice", [(OTS,
        'if (seq <= last.Seq) return CommandResult.Ok(Write(w => w.WriteNumber("rev", last.Rev)));',
        'if (false) return CommandResult.Ok(Write(w => w.WriteNumber("rev", last.Rev)));')]),
    ("M54 OT: any device may edit a document that lists its writers", [(OTS,
        'if (d.Writers is not null && !d.Writers.Contains(author))',
        'if (false && d.Writers is not null && !d.Writers.Contains(author))')]),
    ("M55 CRDT: changes learned by catching up are not passed on", [(DS,
        'if (relay && doc is not null && update.Length > 0)',
        'if (false && relay && doc is not null && update.Length > 0)')]),
    ("M56 CRDT: documents get the library's default (colliding) id", [(SC,
        'return new Doc(new YDotNet.Document.Options.DocOptions { Id = id == 0 ? 1u : id });',
        'return new Doc();')]),
    ("M57 CRDT: any device may remove a document", [(DS,
        'if (!AnyMemberMayRemove && doc.DeviceName != ctx.Origin) return CommandResult.Denied(',
        'if (false && !AnyMemberMayRemove && doc.DeviceName != ctx.Origin) return CommandResult.Denied(')]),
]


def run(cmd, timeout=280):
    return subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True, timeout=timeout)


def apply(edits):
    """Backs up each file once, applies all edits, returns the list of backups (or None + a message)."""
    backups = {}
    texts = {}
    for path, old, new in edits:
        if path not in texts:
            raw = open(path, "rb").read().decode("utf-8")
            texts[path] = (raw.replace("\r\n", "\n"), "\r\n" in raw)
        t, crlf = texts[path]
        if t.count(old) != 1:
            return None, f"anchor matched {t.count(old)} times: {old[:70]!r}"
        texts[path] = (t.replace(old, new), crlf)
    for path, (t, crlf) in texts.items():
        backups[path] = path + ".mutbak"
        shutil.copyfile(path, backups[path])
        open(path, "wb").write((t.replace("\n", "\r\n") if crlf else t).encode("utf-8"))
    return backups, None


def main():
    only = sys.argv[1:]
    bad = 0
    ran = 0
    for label, edits in MUTATIONS:
        if only and not any(label.startswith(o) for o in only):
            continue
        ran += 1
        backups, problem = apply(edits)
        if backups is None:
            print(f"{label}: ANCHOR NOT FOUND - {problem}\n      (the code changed; update this script)")
            bad += 1
            continue
        try:
            b = run(["dotnet", "build", "YuukoProtocol.slnx", "-v", "q", "-clp:ErrorsOnly", "-m:1", "-p:UseSharedCompilation=false", "-nodeReuse:false"])
            if b.returncode != 0:
                print(f"{label}: the broken version did not compile - fix the mutation\n{b.stdout[-400:]}")
                bad += 1
                continue

            r = run(["dotnet", "run", "--project", "YuukoSandbox", "--no-build", "--", "selftest"])
            fails = [l for l in r.stdout.splitlines() if l.startswith("[FAIL]")]
            if fails:
                print(f"{label}: CAUGHT ({len(fails)} failing check(s))")
                for f in fails[:3]:
                    print("      " + f)
            elif "ALL PASS" not in r.stdout:
                # No failed check, but the run did not finish either. That is a crash, not a clean detection.
                tail = (r.stderr.strip().splitlines() or r.stdout.strip().splitlines() or ["(no output)"])[-1][:140]
                print(f"{label}: CAUGHT BY A CRASH (exit {r.returncode}) - make the test fail cleanly instead\n      {tail}")
            else:
                print(f"{label}: NOT CAUGHT  <-- the tests did not notice this break")
                bad += 1
        finally:
            for path, backup in backups.items():
                shutil.copyfile(backup, path)
                os.remove(backup)

    b = run(["dotnet", "build", "YuukoProtocol.slnx", "-v", "q", "-clp:ErrorsOnly", "-m:1", "-p:UseSharedCompilation=false", "-nodeReuse:false"])
    print("restored, clean rebuild:", "ok" if b.returncode == 0 else "FAILED")
    print(f"\n{ran - bad}/{ran} caught" if ran else "nothing ran")
    return 0 if (bad == 0 and b.returncode == 0 and ran) else 1


if __name__ == "__main__":
    sys.exit(main())
