# Yuuko Protocol: developer notes

Written for whoever works on this next (probably you, later). Everything here was checked against the
code and run, not assumed. Where something is NOT verified, it says so.

## What is in here

| Folder | What it is |
|---|---|
| `YuukoProtocol.Definitions/` | The types **both** Yuuko and the XRUIOS use: Yuuko Bindings (`DirectoryManager`, `DirectoryRef`...), `FileRecord`, `DirectoryRecord`, `Handle`, `ResolvedMedia`, the `Media` helpers. net8.0. Namespace is still `YuukoProtocol`. |
| `YuukoProtocol/` | The protocol: `ZenohBroker` (transport), `YuukoHandshake` (identity + sessions), `EclipseBroker` (data, commands, peers, kick), `DeviceDirectory` (nicknames). |
| `YuukoSandbox/` | Things you run: the self-test, the benchmark, and a two-device sample. |
| `libs/` | The **one** copy of `PariahCybersecurity.dll`, `EclipseLCL.dll`, `EclipseProject.dll`. Copied from the XRUIOS libs (the XRUIOS build wins). |
| `tools/mutation-check.py` | Breaks security code on purpose and checks the self-test notices. |
| `sync-libs.ps1` | Keeps `libs/` and the XRUIOS libs identical (see "Keeping the XRUIOS in step"). |

## Run things

```
dotnet run --project YuukoSandbox -- selftest      # 542 checks, ~40 s, no network needed. Exit code 0 = all passed
dotnet run --project YuukoSandbox -- bench         # speed numbers
python tools/mutation-check.py                     # after changing handshake/broker code (55 deliberate breaks, ~45 minutes)
.\sync-libs.ps1 -Check                             # are the shared DLLs identical in both repos?
```

Two real devices, the easy way (TLS is on, certificates are made automatically, no fingerprints or addresses to type):

```
dotnet run --project YuukoSandbox -- offer anchor --code-file code.txt                      # device A: prints a pairing code
dotnet run --project YuukoSandbox -- join "<the code>" --name phone --cmd echo --payload hi   # device B: pairs, then runs a command on A
```

The manual way, with fingerprints (see the comment at the top of `YuukoSandbox/ServiceTemplate.cs` for every flag):

```
dotnet run --project YuukoSandbox -- id headset.id headset --id-password "<8+ chars>"      # prints the fingerprint
dotnet run --project YuukoSandbox -- provider computer tcp/0.0.0.0:7447 --identity prov.id --trust headset=<fingerprint> --psk <16+ chars>
dotnet run --project YuukoSandbox -- client computer tcp/<ip>:7447 --name headset --identity headset.id --trust computer=<fingerprint> --psk <same> --cmd echo --payload hi
```
(Use the `YUUKO_ID_PASSWORD` and `YUUKO_PSK` environment variables instead of the flags: command lines show up in process lists.)

## How a connection works (one paragraph)

Each device has an identity: a Kyber-1024 key pair and a Dilithium5 key pair. The **fingerprint** is a hash of the
public halves. You pair a device by telling the other one its fingerprint (`TrustDevice`). To connect, the requester
sends its public keys plus a **throw-away Kyber key** made just for this handshake. The provider checks the keys against
its allowlist, then encapsulates a secret to the long-term key AND one to the throw-away key, hashes the whole exchange,
and **signs** that hash with Dilithium. The requester checks the signature against the provider's pinned fingerprint,
opens both ciphertexts, **destroys the throw-away private key**, and proves it holds its long-term private key. Both
derive AES-256-GCM session keys from (both secrets + the exchange hash + the PSK) with HKDF. Data and commands travel
over the session in independent "lanes". Sessions are replaced after an hour.

## What the pieces give you

- `node.Peers`, `ConnectedPeers`, `IsOnline(id)`, `PeerConnected` / `PeerDisconnected`: who is connected.
- `node.KickAsync(id, ban)` ends sessions and tells the peer (authenticated); `Unban(id)` undoes a ban.
- `node.On("Name", handler)` / `node.SendCommandAsync(id, "Name", payload)`: run a function on another device and
  get an ack (`Ok`, `Error`, `Denied`, `UnknownCommand`, `Busy`, or local `TimedOut` / `Unreachable`). Retries are safe:
  the receiver runs a command at most once. Gate commands with `CommandAuthorizer`.
- `node.BroadcastAsync("Name", payload)`: run a command on **every device in the group**, including ones this device is not
  connected to. Each device that gets it runs it, then hands it to its own other peers. The result lists only the acks of the
  devices you handed it to directly. Details below.
- `node.PairDevice("nickname", clientId, fingerprint)`, `node.Device("nickname").SendAsync(...)`,
  `node.DeviceGroup("phones").SendAsync(...)`, `node.DeviceStatuses()`: talk to devices by a **local** nickname.
  Nicknames never go on the wire (checked by a test).
- `YuukoIdentity.LoadOrCreate(path, id, password)`: a stable identity, encrypted at rest when you give a password.

## Broadcast (relay): how it works and what it means for your sync systems

Example: phone connected to PC and handheld; PC and handheld not connected to each other. `pc.BroadcastAsync("note", data)`
reaches the phone, the phone runs it and passes it to the handheld, which runs it.

- Every broadcast has a permanent id: `(origin device, random id)`. A device remembers the ids it has handled
  (`RelayDedupeWindow`, 10 min) and ignores a repeat without running or forwarding it. That is what stops loops (a full mesh,
  a ring). It is tested with a full mesh, a ring, and a replayed envelope.
- A device passes it on to every connected peer **except** the one it came from and the one that started it.
- `RelayMaxHops` (8) limits how many devices it is handed through, as a second safety net.
- The device that starts a broadcast does **not** run it itself. If you want it to happen locally too, do that yourself.
- A device without the command still passes it on (its ack says so). A handler that throws does not stop the others.
- `CommandAuthorizer` is asked about the **origin** (checked, see Trust below) and the command name.
- Inside a handler: `ctx.Origin` is who started it, `ctx.FromId` is who handed it over, `ctx.IsBroadcast` is true.
- It only travels over sessions that already exist (`ConnectedPeers`). Devices are not connected on demand.
- If the seen-list is full (`RelayMaxRemembered`), new relayed broadcasts are answered `Busy`. It never forgets early, because
  forgetting would make a replay run twice.
- Names starting with `yuuko.` cannot be broadcast. Payloads are limited to about 3/4 of `MaxCommandBytes`.

**Trust.** Encryption is between neighbours, so a device that relays a broadcast **can read it**. It **cannot forge or change
it**: the origin signs every broadcast (Dilithium5) over its id, the command name, the data, the origin's name and the time.
A receiver runs it only if all of these hold, and tells the sender `Denied` otherwise:
1. the signing key hashes to a fingerprint this device already trusts **for that origin**: the key it proved in a live
   session with it, or a pin (`TrustDevice`, the device directory, or `TrustOrigin(id, fingerprint)`);
2. the signature is valid;
3. it was signed within `RelayMaxAge` (5 min) and not more than `RelayClockSkew` (2 min) ahead of this device's clock.

`TrustOrigin` lets a device accept someone's broadcasts **without** letting it connect. In the phone/PC/handheld example
the handheld needs `handheld.TrustOrigin("pc", pcFingerprint)`; without it the handheld refuses the PC's broadcasts even
though the phone relays them. The first pairing still needs the fingerprint checked out of band (rule 4 below).

What a relay can still do: **read** the content, **drop** a broadcast, or **shorten** its reach (the hop count is not signed).
What it cannot: change the data or the command, claim another origin, or replay it later (ids are remembered longer than a
signature stays valid). The signature adds about 12 KB per broadcast. Devices need clocks within a couple of minutes of each
other. Only forged *copies* are refused; a forged copy never uses up the real one's id.

**Broadcast is not state.** It tells devices to do something now. A device that was offline misses it, and nothing re-sends
it. Keeping devices in step belongs in your sync layers (event log, CRDT, Merkle DAG), which can use broadcast as the
"something changed, come and get it" nudge. Do not re-broadcast from inside a handler: that is a new broadcast with a new id,
so the dedupe cannot stop it.

## The paired-device list (`DeviceDirectory`)

```csharp
var key = new SecureData(Encoding.UTF8.GetBytes(passwordOrKey));      // NOT SecureData.FromString: that wipes the string you pass it
opts.Directory = new DeviceDirectory(key, "devices.json");            // stored as devices.json in that folder
```

- **Encrypted and tamper-evident** with the key (Pariah's JSON handler: the list is packed as one encrypted string). It only holds names
  and fingerprints, so secrecy is not the point: the point is that **nobody can add a trusted device by editing the file**. Whoever
  has the key can read and change it. If the key sits in config next to the file there is no protection at all: derive it from a
  password (Argon2) or keep it in the OS keystore.
- **A file that cannot be opened is never treated as empty.** Wrong key, damaged, changed, truncated, plain JSON, a newer version,
  a device listed twice, a bad entry: the constructor throws `FormatException` (and names the `.bak`), because an empty list would
  silently un-pair every device. The file is left exactly as it was.
- **Saves are crash-safe.** The new version is written to a temporary file and swapped in, and the version it replaces is kept as
  `devices.json.bak`. A failed save is reported to the caller and the change is undone (nothing is announced). The backup is never
  used automatically (it could be an older list with a revoked device back in it): open it deliberately if you need it.
- **Everything stays synchronous** (`Add`, `Remove`, `Rename`, `SetGroups`, `PairDevice`). The async work happens inside, on the
  thread pool. **Each save and each load takes about 160 ms** (the library derives the key with Argon2id every time), and a change
  holds the list's lock while it saves. Fine for pairing; do not use it for anything that changes constantly.
- **Not handled:** two processes sharing one file; rolling the file back to an older valid copy (not detected); the key itself (the
  directory uses it for as long as it lives, so do not dispose it first).
- `new DeviceDirectory()` (no key, no path) keeps the list in memory only.

## Audit log, shared text (OT) and shared documents (CRDT)

Wiki pages: `7 - Examples`, `8 - Audit Log`, `DOGMA I - CRDT`, `DOGMA II - Operational Transformation`. Runnable, narrated demos (no network needed):

```
dotnet run --project YuukoSandbox -- example ot | crdt | audit
```

**`AuditLog`** (`Networking/AuditLog.cs`). Append-only, one JSON entry per line, each holding the hash of the one before it. With a key (`SecureData`) each
hash is an HMAC, so history cannot be rewritten by someone who knows the format; without one it only catches accidents. `OpenReadOnly` can read and verify
but not write, and works while a writer is running. `Seal()` marks the file read-only at the OS level. It cannot see entries cut off the END: keep `Head`
elsewhere and pass it to `Verify`. `Attach(node)` records the node's `AuditEvent`s (kicks, bans, refused handshakes, pairing windows, group decisions,
denied commands) plus connects, disconnects and pairings; repeats of the same refused (who, why) within a minute are folded into one entry.

**`OpTransform`** (the public API, `Dogma/OpTransform.cs`: `Start`, `CreateText`, `JoinText`, `GetText`, `RemoveText`, `SharedText`) over the internal engine **`OtSession`** (`Dogma/OtSession.cs`) and **`TextOperation` / `OtServer` / `OtClient`** (`Dogma/OpTransform.cs`). One device OWNS a document and puts every edit in
order; the others send it edits (`ot.op`) and receive accepted ones (`ot.apply`); `ot.fetch` catches up a device that missed some. Rules that matter if you change it:
- An unconfirmed edit that is sent AGAIN must be sent in its current form (`OtClient.Outstanding` returns it at the current revision). Sending it with its old
  revision makes the owner transform it twice and corrupts the text. The owner also remembers the last edit number it took from each device, so a repeat is a no-op.
- `ot.apply` is accepted only from the document's owner.
- Edits that would cut an emoji in half, or insert half of one, are refused (JSON cannot carry a lone surrogate, which would silently corrupt the text in transit).
- Positions are UTF-16 units. A document is at most 200,000 characters.

**`DocSync` / `SimpleCRDT`** (`Dogma/DocSync.cs`, `Dogma/SimpleCRDT.cs`), YDotNet (Yjs). No owner. A change is broadcast as it happens; devices that connect swap what each
is missing (`crdt.sync` then `crdt.push`), and changes learned that way are passed on to the other devices; a periodic comparison (default 20 s) heals a lost message.
There is no "newest wins": merging gives the same result in any order. **Two silent YDotNet 0.6 traps, so always create documents with `SimpleCRDT.NewDoc()`:**
the default document id comes from a tiny range (about 6 in 100 back-to-back pairs collide, and colliding devices corrupt each other's text with no error), and an
explicit id above 32 bits is accepted but its edits are dropped by the receiver, which still answers "Ok". The self-test covers both.

**`DAG`** (`Dogma/DAG.cs` repository, `Dogma/DAG.Sync.cs` sync), folder sync. Files are cut in 256 KB chunks, a file's hash is the hash of its chunk hashes, and a sync is a
three-way compare (this device, the other device, what both agreed on last time) so it can tell who changed what. Newest wins on a conflict and the loser is kept as
`name (conflict <hash8>).ext`; the name is made from the content so both devices make the same one and a conflict never multiplies. **Things that must stay true:** a path from
another device only goes through `SafeRelative` / `SafePath`; a download is only put in place after its hash is checked; a folder that can't be read is an error, never "empty"
(an unplugged drive must not delete everything elsewhere); deletes go to `.yuuko/trash`; a sync with errors doesn't notify the other device (or two devices that can't agree
would ask each other forever). The engine is `DAG.Syncer` (one per node, like `DocSync`) so the self-test can run several devices in one process.

**`HolyMother`** (`Dogma/HolyMother.cs`): other devices list, start and stop apps and ask for their pictures by ID or name; they never send a command line or a file path of their own.

**`Cogitarium`** (`Dogma/Cogitarium.cs`), the SCCN's collective distribution. Devices in the same chunk pass a signed stream along: the source signs each piece (Dilithium5) and
sends it to its best few neighbors (`InitialReceivers`), each device verifies it, uses it and passes it to ITS best few that want that size (`Fanout`). Repeats are dropped by
sequence number before the signature is checked. **Things that must stay true:** a device only accepts and passes on a source it accepted by fingerprint; a bad signature gets the
device that HANDED the piece over distrusted (a repeat, an unknown stream or a wrong size does not: those aren't tampering); a device is distrusted by others only after
`VotesToDistrust` DIFFERENT direct neighbors accuse it; accusations only count about a stream we know, from a neighbor in that chunk, never about ourselves. **Known gaps:** by default it
only works between devices that are already connected (the private group refuses strangers; `Nearby` is the way in, below); a device that drops pieces instead of changing them isn't noticed; one person with many devices can vote many times; nothing is ever re-sent to a device
that missed a piece. The engine is `Cogitarium.Mesh` (one per node) so the self-test runs many devices in one process.

**The Cogitarium** is `Cogitarium.cs` + `Nearby.cs` together (made for the SCCN, with a streetpass model: strangers, offers, cards). A stream from a source you did not accept is only OFFERED (`Cogitarium.Offers`: signature checked, never passed on, 256 kept, dropped when the chunk is left or the neighbor goes) until `Accept`.

**Rank:** neighbors are ordered by a 0 to 100 rank from the status they SAID about themselves (`MyStatus`, sent as `sccn.status`, range-checked, ignored from a distrusted device) minus `DistrustPenalty` per DIFFERENT neighbor that accused them (counted locally from the votes, never said); answer time only breaks ties. A source sends down the list best to worst until `InitialReceivers` took the piece. Self-reported numbers can lie, so rank decides order only, never trust. A `sccn.hello` that times out is sent again (twice).

**`Nearby`** (`Dogma/Nearby.cs`), strangers for `Cogitarium`. It opens a SECOND node (own Zenoh session with multicast discovery on and TLS off, own random identity, own topics) so the private
node keeps refusing strangers. Devices announce `near-<16 hex>` IDs on a beacon topic and the lower ID calls the higher. **Things that must stay true:** the nearby node never has the group key,
device directory or private commands on it; its `CommandAuthorizer` allows only `sccn.*` (everything else is Denied) and `MaxCommandBytes` is a piece plus a little; beacons are untrusted input
(shape-checked, `MaxNeighbors` capped, retries rate-limited); a card is untrusted bytes (1 KB cap, identity only from the handshake fingerprint, `MaxMet` 1000); `Cogitarium.Reset()` from `Identity` must not remove the nearby mesh. **Known gaps:** same network only, plain link under the handshake
(metadata visible), cheap identities (distrust and votes are weak against a stranger who reconnects as someone new), untested on physical devices. All Kyber calls in `YuukoHandshake` go through
`OneAtATime` because the key generator fails when two run at once, which strangers calling together would trigger.

## Building and testing on a low-memory machine

If `dotnet build` fails with `OutOfMemoryException` inside Roslyn, or MSBuild "internal failure", the machine is out of memory (games and Unity open, for example).
Build leaner: `dotnet build -m:1 -p:UseSharedCompilation=false -nodeReuse:false`, and `dotnet build-server shutdown` afterwards. `tools/mutation-check.py` does this itself.
It also edits source files temporarily while it runs: do not run it in a tree that Visual Studio has open (VS rebuilds on every edit and the two collide). Copy the
solution folder somewhere else and run it there.

## TLS, certificates and pairing codes

**TLS and mutual TLS are on by default.** `ZenohBroker.Open(new ZenohBrokerOptions())` checks for this device's Yuuko certificate and
creates it if it is missing (`YuukoTls.EnsureCertificate`, no openssl). Files live in `%LOCALAPPDATA%/YuukoProtocol/tls/<device name>`
(or `TlsDirectory`): `ca.pem`/`ca.key` (the certificate authority of the device's group, 10 years), `cert.pem`/`key.pem` (what the
device presents, 1 year, renewed automatically and signed by that authority), `trust.pem` (the authorities this device trusts).
`YuukoTls.Check(dir, name)` tells you the state without changing anything (`Missing`, `Valid`, `ExpiresSoon`, `Expired`, `Invalid`).

- **What TLS does here:** hides ids, sizes and timing from anyone on the network, and (mutual TLS) turns away any device that
  cannot show a certificate from an authority this device trusts, **before a single Yuuko message is read**. That is the flood
  protection: a stranger cannot even start a handshake. **What authenticates devices is still the Yuuko handshake** (pinned
  keys), not TLS.
- **One authority per group.** The first device's authority becomes the group's. When a device pairs, the offering device hands it
  the group's authority (certificate AND key) over the encrypted session, and the newcomer issues itself a certificate from it. Every
  member then trusts the same single authority, so **adding a device never means updating the others** and nobody has to restart.
  Because every member holds the authority's key, a stolen member can issue certificates: at the TLS layer only; the handshake
  still has to succeed, and `RevokeAsync` is how you remove a device. A device that already has paired devices of its own will not
  abandon them to join a different group (it refuses).
- **How a newcomer gets in the first time:** mutual TLS would turn it away, so the pairing code contains a *temporary* certificate
  for it alone, valid for the pairing window plus two minutes. After pairing the newcomer **must open its transport again**
  (`PairResult.RestartTransport` tells you) to switch to its permanent certificate; until then it uses the temporary one, which
  stops being accepted for new connections after a few minutes. The group handover is accepted only from the device you just
  asked to pair with, within a minute of asking, and only once.
- Turning TLS off (`EnableTls = false` / `--no-tls`) brings LAN auto-discovery back, but exposes metadata. With TLS on there is
  no auto-discovery: devices find each other through the address in a pairing code, or explicit `ConnectEndpoints`.
- **Ports:** with no `ListenEndpoints`, `ZenohBroker.Open` listens on the first FREE port from 7447 up and tells you
  (`transport.ListenEndpoints`). Zenoh itself says nothing when a port is taken, so a port you name yourself is checked too and
  `Open` throws if it is in use.
- Private keys sit in the certificate folder as plain PEM (Zenoh needs a file). Losing one lets someone pose as that device
  **at the TLS layer only**; they still cannot pass the handshake. Owner-only permissions are set on Unix; on Windows the folder
  is under your profile.
- A device's TLS trust list is read when the transport is opened. It changes only by joining a group while pairing, or by calling
  `YuukoTls.TrustPeer` yourself (for a device in a separate group). A change applies the next time the transport opens.

**Pairing codes.** One device calls `BeginPairing()` and shows the text (or a QR code made from it); the other reads it:

```csharp
// Device A (already running, with an EclipseBroker over a ZenohBroker):
var offer = node.BeginPairing();            // 5 minutes, one use. offer.Code is the text to show.
node.DevicePaired += (id, fingerprint) => ...;

// Device B:
var code = PairingCode.Parse(text);                          // catches typos (checksum)
using var transport = ZenohBroker.Open(code.ToTransportOptions("phone"));   // connects to the code's address, trusts its certificate, presents the temporary one
using var node = EclipseBroker.Create(transport, identity);
var result = await node.PairWithAsync(code, moniker: "pc"); // result.Success / result.Failure
if (result.RestartTransport) { /* joined the group's TLS authority: open the transport again before long-term use */ }
```

The code is a few thousand characters (it carries a certificate): meant to be scanned or pasted, not typed. It contains the device
name, full key fingerprint, address, TLS authority certificate (never its key), a **temporary client certificate and its key**, and a
one-time token. **Treat it as a secret until it has been used or has expired.** The token is never sent: it is mixed into the key derivation of that one
handshake, so only a device that has it can finish. On success both sides pin each other's keys and the token is spent;
a second device with the same code is refused. `maxAttempts` (default 10) limits how many connections may use a window.
Known limits: anyone who sees the code (a shoulder-surfed screen, a photo) can pair in the window; a nuisance device can use up
the attempts and close a window (offer a new code); a name already paired with other keys cannot be re-paired.
Pairing pins the newcomer, which switches the offering device into allowlist mode.

**Group changes (adding a device to everyone at once).** `node.IntroduceAsync("tablet")` tells the rest of the group to trust a device
this one already trusts (as a signed broadcast) and tells the tablet about the other members. `node.RevokeAsync("tablet")` asks them
to stop and disconnects it here. A device acts only if its `GroupChangePolicy` says yes; **with no policy it refuses
everything**. The policy is handed who announced it (verified, not claimed): ask the user there.

```csharp
opts.GroupChangePolicy = async change =>
    await ui.ConfirmAsync($"{change.IntroducedBy} wants you to {(change.Kind == GroupChangeKind.Introduce ? "trust" : "stop trusting")} {change.DeviceId}. Allow?");
```

Revocation is a request, not a guarantee: a device that is offline, or whose policy refuses, keeps trusting. Keys of a name that is
already trusted can never be replaced by an introduction. Connecting to an introduced device's address is up to your app
(`GroupChange.Endpoint`), because endpoints are set when the transport opens.

## Security: what it protects, and what it does not

Protected (each has a test that tries the attack; `selftest` runs them):
unknown devices; a known name with the wrong keys; a fake provider (when pinned); a tampered or replayed handshake;
a swapped throw-away key; forged ACCEPT / Close messages; wrong or missing PSK; malformed or flooding handshakes; lost
messages and restarts (self-healing); duplicate command execution; **a recording of the wire opened later with every
long-term key stolen (forward secrecy)**; identity files read off a disk (when password-protected); session keys that
live too long.

NOT protected, or not true. Read these before relying on it:

1. **No pin, no protection.** If a device isn't pinned, any device that claims its name is accepted. Always pin.
2. **An identity file without a password is the device.** Set a password (it is encrypted with Pariah's Argon2id +
   AES-256-GCM). A weak password is only as strong as it is: Argon2id slows guessing, it does not stop it.
3. **Forward secrecy protects old recordings, not a session an attacker is already inside.** Someone who has taken over a
   running device sees its live session keys.
4. **Verify fingerprints out of band** when pairing (read them aloud, compare on screen). A fingerprint copied over a
   channel an attacker controls proves nothing.
5. **The PSK is shared by every device.** It gates the group; it does not identify a device. Needs 16+ bytes.
6. **Revocation is local.** `UntrustDevice`/`Unpair` on one device doesn't tell the others.
7. **Metadata is visible on the link when TLS is off** (ids, sizes, timing). TLS (on by default) hides it from outsiders, per hop.
   With TLS on there is no automatic LAN discovery (`AllowPlaintextDiscovery` explains why; it was a real bypass). Without mutual
   TLS, a stranger can still open a TLS connection and flood the port; the handshake refuses them cheaply, but it is not a firewall.
8. **Custom protocol, never independently reviewed.** The algorithms are standard NIST PQC ones; the way they are
   combined here is not. Get a review before it guards anything that matters to other people.
9. Hostile floods are only lightly handled (pending-handshake cap, rate-limited replies). Not hardened against a determined DoS.
10. Tested over real Zenoh only on one machine (loopback). Not yet across two physical devices / Wi-Fi.
11. A refused connection and a timeout look alike from far away (`Unreachable` either way).
12. Rotation: an hour by default (`HandshakeOptions.MaxSessionAge`). If the peer refuses a rekey, the old session keeps
    working until its hard expiry, then the next use re-handshakes.

## Rules when you change things

- **Run `selftest` before and after.** A check that fails is telling you something real.
- **Changed handshake or broker security code?** Also run `tools/mutation-check.py`. If it prints `NOT CAUGHT`, the tests
  have a hole: add a test. `ANCHOR NOT FOUND` means the code moved and the script's text to replace needs updating.
- **Never mix Pariah builds across devices.** Two builds both said "1.0.0.1" and differed by 14 KB. Run `sync-libs.ps1 -Check`.
- **Don't renumber** the `DataType` enum in `EclipseBroker.cs`, and bump the version if you change the identity file or
  handshake format: they are wire/disk formats. (The handshake is "v3"; old and new devices cannot talk to each other.)
- `SecureData.FromString(...)` (Pariah) **wipes the string you pass it, in memory**. Never pass it a literal or a string you
  still need; build one with `new SecureData(Encoding.UTF8.GetBytes(...))` as the identity code does.

## Keeping the XRUIOS in step

The XRUIOS uses the definitions as a built DLL: `The-XRUIOS/libs/YuukoProtocol.Definitions.dll`, referenced through
`The-XRUIOS/src/YuukoProtocol.Definitions.props`. It replaced the old `YuukoProtocol.XRUIOS.Interfaces` project.

- Changed `YuukoProtocol.Definitions`? Run `.\sync-libs.ps1`, then rebuild the XRUIOS projects.
- A plain DLL reference is **not transitive**. If an XRUIOS project says it can't find `FileRecord` / `Bindings` / `Handle`,
  add `<Import Project="...\YuukoProtocol.Definitions.props" />` to that project. NuGet packages the old project used to
  supply (BouncyCastle...) are now declared on `XRUIOS.Interfaces.csproj`. The same applies to YuukoSandbox, which
  references Pariah itself because the self-test calls it directly.
- Saved `.binding` files don't contain assembly names, so renaming the assembly didn't break old data (tested). `PackData<T>`
  does embed `typeof(T).AssemblyQualifiedName`; in the code today it is only used with `string`. Don't use it with types from
  `YuukoProtocol.Definitions` unless you accept that renaming the assembly breaks old data.
- `XRUIOS.slnx` lists 52 `src/apps/*` projects whose files are not in the repo checkout, so `dotnet build XRUIOS.slnx` fails
  (`MSB3202`) for a reason unrelated to this. Build projects individually. All 42 that exist build. Whether the missing apps
  compile against the new reference is **unverified**.
- `Media.cs` and `App.cs` here are the XRUIOS versions. They contained two fixes the old Yuuko copy lacked: `DataType` is
  passed through to the bank lookups, and a missing bank file returns an empty list instead of failing.
