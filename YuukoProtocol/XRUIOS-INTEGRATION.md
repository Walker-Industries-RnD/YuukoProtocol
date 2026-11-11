# Yuuko in the XRUIOS: a start and a reference

Written from reading `C:\Users\WalkerDev\Documents\GitHub\The-XRUIOS` (the `src` folder, `libs`, the README). Nothing was changed in that repo. Everything below is a starting point; the implementations are yours.

## Where things stand

- The XRUIOS does **not** use the Yuuko networking yet. No file under `src` mentions `Identity.CreateNode`, `SimpleCRDT`, `EclipseBroker` or `ZenohBroker`.
- The `using YuukoProtocol;` lines in `AlarmClass`, `MusicPlayerClass`, `CalendarClass` and others are the shared definitions (`Bindings`, `FileRecord`, handles). They arrive as `libs\YuukoProtocol.Definitions.dll` through `src\YuukoProtocol.Definitions.props`.
- `src\systems\SyncEngineClass.cs` is an empty class. That is the obvious home for the idea, but see the next section.
- The Yuuko side is `net8.0`, the XRUIOS workers are `net10.0`. A net10 project can reference a net8 DLL.

## Where Yuuko should live: one new worker

The XRUIOS rule is one class, one process, one password (`WorkerCatalog`, `SecureWorkerHost`). Putting the Zenoh node inside `Theme` or `Clipboard` would give a network-facing process access to that worker's store. So:

- Add **one worker, `XRUIOS.Worker.Sync`**. It owns the Yuuko node and nothing else.
- It talks to the other workers the way an app does: through the Manager, using only the capabilities it was granted. A leaked Sync worker then reaches exactly what you granted it.
- It publishes and consumes XRUIOS events (`ThemeChanged`, `ClipboardChanged`, `AlarmsChanged`, `NowPlayingChanged`) and turns them into Yuuko traffic, and the reverse.

### Skeleton (copy the Theme worker, it is the smallest)

`src\workers\XRUIOS.Worker.Sync\Sync.csproj`: same as `Theme.csproj`, with `RootNamespace` / `AssemblyName` set to `XRUIOS.Worker.Sync` and `<Compile Include="../../systems/SyncEngineClass.cs" />`.
Add the Yuuko reference (see "Getting the DLLs in" below).

`Program.cs` (identical to the Theme worker apart from the name):
```csharp
using System.Reflection;
using XRUIOS.Interfaces;

global::XRUIOS.Barebones.XRUIOS.BindFromEnvironment();

const string ServerName = "XRUIOS.Worker.Sync";

await SecureWorkerHost.Run(
    serverName: ServerName,
    capabilityAssembly: Assembly.GetExecutingAssembly());
```

`Capabilities.cs`: methods with `[SeaOfDirac]`, the same shape as `AlarmCapabilities`. Suggested surface:
```csharp
public static class SyncCapabilities
{
    [SeaOfDirac("Sync.Ping", new[] { "input" }, typeof(string), typeof(string))]
    public static string Ping(string input) => "XRUIOS.Worker.Sync: " + input;

    // Pairing: CreatePairing() -> code string, ConnectToDevice(code, nickname), CancelPairing()
    // Devices:  ListDevices() -> "name|online;..." (Identity.ViewAllConnectedMachines / HasRecentActivity)
    // Apps:     ListApps(device), ListRunning(device), StartApp(device, id), StopApp(device, id)   (HolyMother)
    // Trust:    TrustDevice(name), UntrustDevice(name), KickDevice(name, ban)
}
```
Register it in `src\XRUIOS.Manager\WorkerCatalog.cs` (`Defs`), as `("Sync", PermissionGroup.Identity)`. Identity or System both fit; pick the one whose default policy you want.

Start the node once the worker has its context:
```csharp
// SyncEngineClass.cs
await Identity.CreateNode(Password, DeviceID, DeviceName, ListensToOthers: true, GroupKey, TrustedDevices, TrustedDeviceKey);
SimpleCRDT.Start(); HolyMother.Start();           // and again from Identity.NodeRestarted, see the Yuuko docs
```
Keep the identity file, the trusted-devices file and the group key under the worker's own `XRUIOS.DataPath` and `XRUIOS.encryptionKey` (`XRUIOS.Core\XRUIOS.cs`) so they are encrypted with the worker's own key, like every other store.

## Getting the DLLs in

- `libs` has `EclipseProject.dll`, `PariahCybersecurity.dll`, `YuukoProtocol.Definitions.dll` and others, and `sync-libs.ps1` (in the Yuuko repo) keeps them in step.
- The networking lives in `YuukoProtocol.dll`, which is **not** in `libs` yet. You need it, plus its NuGet dependencies (`Zenoh-CS`, `YDotNet*`, `BouncyCastle`, `Ceras`, `K4os`, and so on) and the Zenoh native targets (`ZenohNative.targets` in the Yuuko csproj).
- Easiest: a `ProjectReference` to the Yuuko project while you are developing. Then switch to the DLL plus `sync-libs.ps1` when you ship, extending the script to copy `YuukoProtocol.dll`.
- Only the Sync worker should reference it.

## The XRUIOS pieces each feature plugs into

These already exist, so the Sync worker only has to connect them.

| Feature | Existing XRUIOS piece | Yuuko side |
|---|---|---|
| Theme | Theme worker: `ListThemes`, `ApplyTheme(themeId)`, `GetActiveTheme`, `SetDesktopSync`; event `ThemeChanged` | CRDT document `settings`, label `theme`, overwrite |
| Clipboard | Clipboard worker: `Recent`, `Copy`, `Paste`, `Share(id, target)`; event `ClipboardChanged` | `BroadcastAsync("clipboard.set")` or `SendCommandAsync` for one device. `Share(id, target)` looks like it was meant for this |
| Music handoff | MusicPlayer: `NowPlaying`, `SetNowPlaying(...)`, `ListQueue`, `QueueSong`; event `NowPlayingChanged` | `SendCommandAsync(device, "music.handoff", ...)`; pause after the ack |
| Reminders | Alarm: `ListAlarms`, `AddAlarm`, `AddAlarmFull`, `DeleteAlarm`; events `AlarmsChanged`, `AlarmFired` | CRDT document `reminders`. Apply with `AddAlarm`/`DeleteAlarm` |
| Same folder | `Bindings` (UUID, resolves per device) in `YuukoProtocol.Definitions` | Sync only UUID and name in a CRDT document. Files wait for DOGMA IV |
| Apps on a device | `IAppInterpreter.ListInstalled()` and `Launch(id)`, Windows and Linux implementations already exist in `XRUIOS.Interpreter` | `HolyMother` |
| Device list | `DeviceManager` is keyboards only, nothing for peers | `Identity.ViewAllConnectedMachines()` and `HasRecentActivity` |

### One decision to make before building Holy Mother into the XRUIOS

`XRUIOS.Interpreter` already lists installed apps (`WindowsApps`, `LinuxApps`: Start Menu / `.desktop`, with ids, icons and launch). `HolyMother` scans the same places itself, so you would have **two lists and two sets of ids**. Suggested: in the XRUIOS, feed `HolyMother` from `IAppInterpreter` (add a way to hand it a list, or an `IAppSource`), keep its own scan only for Steam and WalkerWorks, and merge. What `IAppInterpreter` lacks, and `HolyMother` has: running state and stop.

## How events and calls flow (what to read first)

- `XRUIOS.SecureLayer\WorkerOcean.cs`: how a worker receives a call, checks permission and audits it.
- `XRUIOS.SecureLayer\XruiosEvents.cs` and `XruiosEventStream.cs`: `WorkerEvents.Publish(name, payload)` to send. Consuming needs the grant `Events.<Name>` (`XruiosEventNames.PermissionFor`) and goes through `Events.Poll`. I did not trace exactly how a *worker* (not an app) subscribes. Read this before relying on it.
- `XRUIOS.Interpreter\DeveloperInterpreters.cs`: the list of event names and their payload types.
- `XRUIOS.SampleApp\Program.cs`: the smallest example of an app enrolling, connecting and being denied.
- `docs\3-building\2-a-worker.html` and `docs\2-permissions\8-building-a-xruios-app.html`: how a worker and a grant list are put together.
- `XRUIOS.Manager\WorkerCatalog.cs` and `PermissionService.cs`: where workers are registered and grants are checked.

## Hazards specific to joining the two

- **Echo loops.** Applying a remote theme makes the Theme worker raise `ThemeChanged`, which the Sync worker would send out again. Same for clipboard, alarms, now-playing. Remember "this change came from `<device>`" and skip sending it back.
- **Restart on pairing.** Pairing can rebuild the Yuuko node. Hook `Identity.NodeRestarted` and run your start-up again (handlers registered with `On(...)` are lost).
- **Remote start/stop is a hole in the permission model if left open.** The README's whole point is least privilege. Put `HolyMother.Allow` behind a real check (an XRUIOS grant, a user prompt, or a per-device allow list) before any capability exposes `StartApp`.
- **Group-change prompts.** `Identity.GroupChangeRequested` needs a UI handler. With none, group changes are refused.
- **Two security models.** XRUIOS trust is Manager and PSK per worker; Yuuko trust is a device group with pairing. They do not know about each other, so the Sync worker is the bridge. Do not pass XRUIOS credentials over Yuuko.
- **Size limits.** A Yuuko command is at most 1 MB, and CRDT ids must come from `SimpleCRDT.NewDoc()`.

## Suggested order

1. Reference Yuuko from a throwaway console app and pair two machines (no XRUIOS yet).
2. Make the Sync worker with `Ping` and `CreatePairing` / `ConnectToDevice` only. Get it started by the Manager.
3. Theme (smallest: one label), then reminders, then clipboard, then music, then folders.
4. Apps last, after the `IAppInterpreter` decision.
