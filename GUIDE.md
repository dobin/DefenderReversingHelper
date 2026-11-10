# MakeMePPL detailed guide

For the shortest setup path, see the [README](README.md). This guide contains the full
setup instructions, command reference, design notes, risks, test matrix, troubleshooting,
and cleanup details.

MakeMePPL is a test-signed Windows 11 x64 WDM driver plus a user-mode CLI that sets
`EPROCESS!PS_PROTECTION` on a target process. The target becomes **Protected Process
Light (PPL)** until the protection is cleared, the driver is unloaded, or the machine
reboots.

> **Research/test tool only.** This is unsupported DKOM. Use an isolated test VM, take a
> snapshot before the first driver load, and never run it on a production host. A wrong
> EPROCESS write can bugcheck the machine.

The default protection is **PPL-Antimalware** (`0x31`). PPL-WinTcb (`0x61`) is available
but can lock administrators and debugging tools out of a process.

Vibe coded by Deepseek V4.1 Flash. With input from https://github.com/hfiref0x/KDU. 


## Features

- **PID:** `pplctl set --pid <pid>` / `clear` / `query` / `probe`
- **DLL signature mitigation:** `pplctl allow-dlls --pid <pid>` removes the
  `PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY` / Cobalt Strike `blockdll` restriction so the
  target can load unsigned DLLs
- **ACG for hooking:** `pplctl allow-dynamic-code --pid <pid>` clears
  `ProcessDynamicCodePolicy` so an in-process Detours payload can patch image code
  pages; both mitigation changes are tracked for restore
- **Name filter:** a process-creation callback protects every new image whose base name
  matches a pattern (protection is applied by a deferred driver thread shortly after
  creation); `--apply-existing` handles already-running processes
- **On-connect:** a user-mode named-pipe broker (`\\.\pipe\PplGrant`) resolves the
  connecting client's PID with `GetNamedPipeClientProcessId` and grants PPL
- Configurable signer, default Antimalware
- Blocklist for system-critical processes
- Best-effort restore of tracked processes on `clear` and driver unload
- `probe` black-box acceptance test using `OpenProcess` after enabling `SeDebugPrivilege`

The driver's control device is writable by all local users, and it never opens a network
socket, writes files, or persists state. Driver installation and removal still require an
administrator. The open device DACL is intentional for this test tool: any local process
can grant or clear PPL on any non-blocklisted process.

## Layout

```text
ppl_executor/
  MakeMePPL.sln
  shared/PplIoctl.h             shared IOCTLs and structs
  shared/PplBuilds.c/.h         NT build numbers + EPROCESS offset table
  driver/
    MakeMePPL.vcxproj
    MakeMePPL.c               DriverEntry, control device, IOCTL dispatch
    PplProtection.c/.h          PPL byte: set/clear/query, verification
    PplMitigation.c/.h          DLL signature mitigation: allow-dlls, restore
    PplTrack.c/.h               shared change-tracking table and lock
    PplFilter.c/.h              filters, process callback, blocklist
    PplLog.h                    DbgPrintEx wrapper
  usermode/
    PplCtl.vcxproj
    PplCtl.cpp                  CLI and named-pipe broker
    PplDriverClient.cpp/.h      CreateFile/DeviceIoControl helpers
  tests/
    PplTarget.vcxproj
    PplTarget.cpp                outputs test_target.exe
  dll_injector/
    DllInjector.vcxproj
    DllInjector.cpp              outputs injector.exe (--ppl/--fix-handle/--kernel-thread)
    README.md                    injector usage and MsMpEng example
    payload/
      DllPayload.vcxproj
      payload.c                  outputs payload.dll (writes C:\data marker)
    detours_payload/
      MpEngineHook.vcxproj
      MpEngineHook.c             outputs mpengine_hook.dll (Detours hook, ETW)
      README.md                  hook target, ETW events, ACG caveat
  tools/etw_listener/
    RSignalEtwListener.vcxproj
    RSignalEtwListener.cpp       outputs rsignal_etw_listener.exe (krabsetw)
    README.md                    consumer usage
  third_party/detours/
    DetoursLib.vcxproj           builds detours.lib from C:\Repos\Detours
    README.md                    Detours source location / override
  scripts/
    Build.ps1
    New-TestCert.ps1
    Sign-Driver.ps1
    Enable-TestSigning.ps1
    Install-Driver.ps1
    Uninstall-Driver.ps1
```

`bin/<Configuration>/` is the common output directory.

## Prerequisites

- Windows x64 test VM. The offset table covers Windows 8.1 through Windows 11
  25H2 and is ported from KDU; Windows 11 24H2/25H2 is the tested target
- Visual Studio 2022 with the **Desktop development with C++** workload
- Windows SDK **10.0.26100.0**
- Windows Driver Kit for SDK **10.0.26100.0**, including the
  `WindowsKernelModeDriver10.0` toolset. The scripts check for the WDK and fail with a
  clear message; **they never install it**.
- An elevated PowerShell for certificate, test-signing, install, and uninstall. CLI tests
  can run as a normal user; `probe` is most useful from an elevated shell because it needs
  `SeDebugPrivilege`
- Secure Boot **off** and test signing **on**
- HVCI / memory integrity off for this test VM
- A VM snapshot before the first load

Do not install or enable any of the above automatically from this repository. Treat the
build host and test VM as disposable.

## Build

```powershell
.\scripts\Build.ps1 -Configuration Release
```

or directly:

```powershell
& "C:\Program Files\Microsoft Visual Studio\2022\Community\MSBuild\Current\Bin\MSBuild.exe" `
  .\MakeMePPL.sln /m /p:Configuration=Release /p:Platform=x64
```

Outputs:

```text
bin\Release\MakeMePPL.sys
bin\Release\PplCtl.exe
bin\Release\test_target.exe
bin\Release\injector.exe
bin\Release\payload.dll
bin\Release\mpengine_hook.dll
bin\Release\detours.lib
```

Detours is compiled from `C:\Repos\Detours` unless `-DetoursDir <path>`,
`DETOURS_DIR`, or `/p:DetoursDir=...` points elsewhere. If the checkout is
missing, the build stops with an explicit error.

The driver is linked with `/INTEGRITYCHECK` in both configurations. Verify it:

```powershell
dumpbin /headers .\bin\Release\MakeMePPL.sys | Select-String "Check integrity"
```

That flag sets `IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY`, which
`PsSetCreateProcessNotifyRoutineEx` requires in order for the name-filter feature to work.

## Certificate, test signing, install

Run these in an elevated PowerShell.

1. Create and trust a test code-signing certificate:

   ```powershell
   $env:PPL_TEST_PFX_PASSWORD = "choose-a-non-production-password"
   .\scripts\New-TestCert.ps1
   ```

   This writes `certs\ppl_test.pfx`, `certs\ppl_test.cer`, and trusts the certificate in
   `LocalMachine\Root` and `LocalMachine\TrustedPublisher`. The PFX and password are test
   secrets; do not commit them.

2. Sign and verify the driver:

   ```powershell
   .\scripts\Sign-Driver.ps1 -Configuration Release
   ```

   It signs with SHA-256 and verifies with `signtool verify /pa`.

3. Enable test signing and reboot:

   ```powershell
   .\scripts\Enable-TestSigning.ps1
   Restart-Computer
   ```

   Confirm after reboot:

   ```powershell
   bcdedit /enum {current}   # testsigning Yes
   ```

4. Install and start the demand-start kernel service:

   ```powershell
   .\scripts\Install-Driver.ps1 -Configuration Release
   .\bin\Release\PplCtl.exe info
   ```

   Expected on this host family: build `26100` or `26200`, PPL offset `0x5FA`.

5. Uninstall:

   ```powershell
   .\scripts\Uninstall-Driver.ps1
   ```

   `sc stop` invokes `DriverUnload`, which unregisters the process callback and restores
   tracked processes. Close broker/CLI windows first.

## Quick start

Start `test_target.exe` in one window; note its PID. After an administrator has installed
and started the driver, these commands can run from a normal user console. Run `probe`
elevated if you want it to enable `SeDebugPrivilege`.

```powershell
# Grant PPL-Antimalware by PID
.\bin\Release\PplCtl.exe set --pid <pid>

# Inspect raw and user-mode views
.\bin\Release\PplCtl.exe query --pid <pid>

# OpenProcess acceptance test: all-access and VM-read should be denied
.\bin\Release\PplCtl.exe probe --pid <pid>

# Restore the tracked original byte
.\bin\Release\PplCtl.exe clear --pid <pid>

# Remove the block-non-Microsoft-binaries mitigation (blockdll)
.\bin\Release\PplCtl.exe allow-dlls --pid <pid>

# Clear ACG so an in-process Detours hook can patch code pages
.\bin\Release\PplCtl.exe allow-dynamic-code --pid <pid>
```

`allow-dlls` clears `EPROCESS!MitigationFlags` bit 23 (`SignatureMitigationOptIn`) and
zeroes `EPROCESS!SectionSignatureLevel`, the DLL signature requirement. The change is
tracked, so `clear --pid` and driver unload restore the original values. It works on
processes created with `PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY` /
`PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON` and on
processes that enabled `SetProcessMitigationPolicy(ProcessSignaturePolicy,
MicrosoftSignedOnly=1)` at runtime.

`allow-dynamic-code` clears `MitigationFlags` bit 8 (`DisableDynamicCode`, ACG). It is
also tracked, and `clear --pid` restores it together with any `allow-dlls` change.

Protect every new `test_` image automatically:

```powershell
.\bin\Release\PplCtl.exe filter add --name test_
.\bin\Release\test_target.exe
```

Apply the filter to matching processes that are already running:

```powershell
.\bin\Release\PplCtl.exe filter add --name test_ --apply-existing
```

`filter remove` and `filter clear` only stop future grants. They do not remove PPL from
processes that are already protected. Use `clear --pid` or stop the driver for that.

On-connect broker:

```powershell
# Console 1 (normal user is fine)
.\bin\Release\PplCtl.exe broker --signer am

# Console 2 (normal user is fine)
.\bin\Release\PplCtl.exe connect --hold 60

# Console 3 (elevated, so probe can enable SeDebugPrivilege)
.\bin\Release\PplCtl.exe probe --pid <PID PRINTED BY connect>
```

By default the pipe DACL allows Everyone (`--allow-all` is the default), so any local
process - elevated or not - that connects to `\\.\pipe\PplGrant` becomes PPL. This is a
deliberate privilege-escalation endpoint; run the broker only in an isolated test VM and
only for a specific test. Pass `--admin-only` to restrict the pipe to SYSTEM and
Administrators and require the target to run elevated or as SYSTEM.

The broker itself can also run as a normal user once the driver is loaded, because the
control device allows all local users. `--admin-only` restricts only the pipe, not the
device. Installing and starting the driver still require an administrator.

## DLL injection (`dll_injector`)

`dll_injector` integrates the `dll_load` lab injector. It performs remote
`LoadLibraryW` injection and adds driver-backed options for protected targets.

```powershell
# Normal target
$target = Start-Process .\bin\Release\test_target.exe -PassThru
.\bin\Release\injector.exe $target.Id .\bin\Release\payload.dll

# Protected target (elevated, driver loaded, isolated test VM)
.\bin\Release\injector.exe MsMpEng.exe .\bin\Release\payload.dll `
    --ppl --fix-handle --kernel-thread --restore
```

| Option | Effect |
|---|---|
| `--ppl` | Before `OpenProcess`, force-clear PPL (`IOCTL_PPL_FORCE_CLEAR_BY_PID`) and clear the block-non-Microsoft-binaries mitigation (`IOCTL_PPL_ALLOW_NON_MS_DLLS`). Both changes are tracked by the driver. |
| `--allow-dynamic-code` | Clear ACG (`IOCTL_PPL_ALLOW_DYNAMIC_CODE`); needed for Detours to make image code pages writable. Tracked. |
| `--fix-handle` | Restore `GrantedAccess` that Defender self-protection stripped from the `OpenProcess` handle (`IOCTL_PPL_FIX_HANDLE_ACCESS`). |
| `--kernel-thread` | Create the remote thread from kernel mode via `RtlCreateUserThread` (`IOCTL_PPL_CREATE_REMOTE_THREAD`), bypassing the user-mode protected-process check. |
| `--restore` | After injection, restore the original protection/mitigation (`IOCTL_PPL_CLEAR_BY_PID`). Only meaningful with `--ppl`. |

The first argument is a PID or an image name (for example `MsMpEng.exe`).
The payload writes `C:\data\dll_load_<pid>.txt` from `DLL_PROCESS_ATTACH`.

`--ppl` must run before `OpenProcess`, because a PPL process refuses the VM and
thread-creation rights. Run the injector elevated when targeting `MsMpEng.exe`:
after PPL is cleared the process is still a SYSTEM process. Without `--restore`,
run `pplctl clear --pid <pid>` to put the tracked protection back. See
[dll_injector/README.md](dll_injector/README.md) for details and limitations.

### Detours hook payload

`bin\Release\mpengine_hook.dll` is a Microsoft Detours payload. It hooks
`mpengine.dll!__rsignal` and emits ETW/TraceLogging events for each call:

```powershell
# Terminal 1 (elevated)
.\bin\Release\rsignal_etw_listener.exe --pid <MsMpEng pid>

# Terminal 2 (elevated)
.\bin\Release\injector.exe MsMpEng.exe .\bin\Release\mpengine_hook.dll `
    --ppl --allow-dynamic-code --fix-handle --kernel-thread --restore
```

The payload resolves the export at runtime, enlists all target threads in the
Detours transaction (and keeps their suspended handles open until commit), and
installs the hook from a worker thread rather than from `DllMain`. For every
call it emits all four arguments, the `Context` and `Data` buffers, and the
return value; the listener prints a hex+ASCII dump. Arguments and return values
are forwarded unchanged.

Detours must make code pages writable. `--ppl` clears PPL and the
block-non-Microsoft-binaries mitigation; `--allow-dynamic-code` clears
**Arbitrary Code Guard** (`ProcessDynamicCodePolicy`). If ACG is still active,
the commit fails with `ERROR_DYNAMIC_CODE_BLOCKED` (1655), which the payload
emits as a `Status` error event. See
[dll_injector/detours_payload/README.md](dll_injector/detours_payload/README.md)
for changing the hook target and more caveats.

## Cleanup

Close broker/CLI windows, then run in elevated PowerShell:

```powershell
.\scripts\Uninstall-Driver.ps1
bcdedit /set testsigning off
Restart-Computer
```

Remove the test certificate from `LocalMachine\Root` and
`LocalMachine\TrustedPublisher`, then delete the generated PFX/CER in `certs`.
Restoring protection on unload is best effort; reboot is the recovery path.
See [cleanup details](GUIDE.md#cleanup).


## Test


Run this in elevated PowerShell so `probe` can enable `SeDebugPrivilege`:

```powershell
$target = Start-Process .\bin\Release\test_target.exe -PassThru
.\bin\Release\PplCtl.exe set --pid $target.Id
.\bin\Release\PplCtl.exe query --pid $target.Id
.\bin\Release\PplCtl.exe probe --pid $target.Id
.\bin\Release\PplCtl.exe clear --pid $target.Id
```

`query` should show `0x31`; `probe` should report all-access and VM-read denied.
`clear` restores the tracked original protection byte. Existing handles are not revoked.

For name filters, the on-connect broker, other signers, and all CLI options, see the
[command reference and examples](GUIDE.md#quick-start).


## Commands

```text
pplctl info
pplctl set   --pid <pid> [--signer am|wintcb|windows|lsa|authenticode|codegen|winsystem|app] [--audit]
pplctl clear --pid <pid>
pplctl query --pid <pid>
pplctl probe --pid <pid>
pplctl allow-dlls --pid <pid>
pplctl allow-dynamic-code --pid <pid>
pplctl filter add    --name <pattern> [--signer <name>] [--audit] [--exact] [--apply-existing]
pplctl filter remove --name <pattern>
pplctl filter clear
pplctl filter list
pplctl broker  [--pipe PplGrant] [--signer am] [--audit] [--once] [--admin-only]
pplctl connect [--pipe PplGrant] [--hold <seconds>]
pplctl builds
pplctl version

injector <pid|image name> <full\path\to\payload.dll> [--ppl] [--allow-dynamic-code] [--fix-handle] [--kernel-thread] [--restore]
```

`builds` prints the build table compiled into `pplctl`, marks the running OS, and
shows whether the current build has a known `PS_PROTECTION` offset. It does not need
the driver to be loaded.

Default signer is `am` (Antimalware). Supported protection bytes include:

| Signer | PPL byte |
|---|---|
| Authenticode | `0x11` |
| CodeGen | `0x21` |
| Antimalware | `0x31` |
| LSA | `0x41` |
| Windows | `0x51` |
| WinTcb | `0x61` |
| WinSystem | `0x71` |
| App | `0x81` |

`query` prints the driver's raw byte, decoded type/signer/audit, build name, offset, and
the `PsIsProtectedProcess` / `PsIsProtectedProcessLight` flags. It also uses
`GetProcessInformation(ProcessProtectionLevelInfo)` to show the user-mode view.

`query` also reports `SignatureLevel`, `SectionSignatureLevel`, the raw
`MitigationFlags1`/`MitigationFlags2`, `block non-MS DLLs: ON/off`, and
`ACG (dynamic code): ON/off`. `allow-dlls` should change the blockdll line to
`off`; `Get-ProcessMitigation` reports `MicrosoftSignedOnly: OFF` after the
change. `allow-dynamic-code` should change the ACG line to `off`.

`probe` enables `SeDebugPrivilege` first, then tests:

1. `PROCESS_ALL_ACCESS` (expected denied for PPL)
2. `PROCESS_VM_READ | PROCESS_QUERY_INFORMATION` (expected denied for PPL)
3. `PROCESS_QUERY_LIMITED_INFORMATION` (usually allowed; the actual result is reported)

## Design notes

- **Version identification.** The driver calls `RtlGetVersion` and cross-checks
  `KUSER_SHARED_DATA->NtBuildNumber` (the same value KDU reads through
  `NtCurrentPeb()->OSBuildNumber`). A mismatch is logged and the shared-data build wins.
  `info` reports the full major/minor/build and the decoded OS name.
- **Offset table, ported from KDU.** `shared/PplBuilds.c` has one entry per exact NT build
  from Windows 8.1 (9600) through Windows 11 25H2 (26200), derived from KDU's
  `KDUGetEprocessOffsets` and `PsProtectionOffset_*` constants. `PS_PROTECTION` is
  `0x87A` for 19041-22631 and `0x5FA` for 26100-26200, among others. The table also
  records `MitigationFlags` and `ObjectTable` offsets. `PS_PROTECTION` is used for PPL;
  `MitigationFlags1` is used by `allow-dlls` and `allow-dynamic-code`. Unknown builds
  (including 26H1/26H2, which KDU does not map yet) load but
  `SET`/`FILTER`/`ALLOW-DLLS`/`ALLOW-DYNAMIC-CODE` return
  `STATUS_NOT_SUPPORTED`; the driver never guesses or scans for the field.
- **Protection byte.** PPL is set by writing only `PS_PROTECTION`. The driver does not
  change `SignatureLevel`/`SectionSignatureLevel` for a PPL grant.
- **Block non-Microsoft binaries.** `PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON`
  is not stored verbatim as a bit in `MitigationFlags2`. The kernel translates it into
  `MitigationFlags` bit 23 (`SignatureMitigationOptIn`) and raises
  `SectionSignatureLevel` to 8 (Microsoft). `allow-dlls` clears bit 23 and zeroes
  `SectionSignatureLevel`; it leaves `SignatureLevel` (the process image's own signing
  level) and `MitigationFlags2` alone. Both writes are verified.
- **ACG.** `allow-dynamic-code` clears `MitigationFlags1` bit 8
  (`DisableDynamicCode` / `ProcessDynamicCodePolicy`). Without it, a Detours payload
  cannot flip `mpengine` image code pages to writable and commit fails with
  `ERROR_DYNAMIC_CODE_BLOCKED` (1655). The write is verified and tracked; if
  `allow-dlls` already tracked the process, the entry keeps the original flags and both
  changes restore together.
- **Verification.** For PPL the driver reads the byte back and checks
  `PsIsProtectedProcess`/`PsIsProtectedProcessLight` for type 0, 1, or 2. On a signer-only
  change the boolean checks cannot distinguish signers, so the byte readback is the limit
  of the claim. A failed verification restores the old byte. For `allow-dlls`, both the
  32-bit flags value and `SectionSignatureLevel` are read back; a mismatch restores both.
- **Tracking.** A fixed 256-entry nonpaged table records PID, EPROCESS identity, the
  applied/original protection byte, and the applied/original mitigation flags and signature
  levels. The whole read/write/verify/track sequence is serialized by a push lock. If the
  table is full, the change is still applied but that process is not restored on unload.
- **Clear safety.** `clear` refuses to remove protection from an untracked process whose
  current byte is non-zero. This avoids accidentally stripping PPL from Defender, LSA, or
  a process protected by a previous driver load. A mitigation-only entry (created by
  `allow-dlls` or `allow-dynamic-code`) always has a non-zero change mask, so `clear`
  restores the mitigation and leaves the protection byte untouched.
- **Restore.** On normal `clear` or unload, the original values are written only if the
  current values still match what this driver applied. PID-reused or externally changed
  processes are skipped. A driver crash or forced unload can leave processes PPL (or with
  the DLL restriction removed) until reboot; reboot is the recovery path.
- **Filter callback.** The callback is allocation-free, does not wait on I/O, and never
  sets `CreationStatus`. It copies the matched filter and queues the PID for a driver
  system thread, which applies protection about 100 ms later. Applying PPL directly in
  the callback makes the parent's `CreateProcess` fail with access denied, because the
  parent's handle is opened after the notification returns. Blocklisted images are
  skipped. The deferred queue is drained before unload so no work item can outlive the
  driver image.
- **Blocklist.** PID 0/4 and `System`, `Registry`, `smss.exe`, `csrss.exe`,
  `wininit.exe`, `services.exe`, `lsass.exe`, `winlogon.exe` are refused. Apply-existing
  also skips the calling CLI process. The explicit PID path is intentionally more
  permissive for already-protected non-critical processes, but still logs and refuses the
  blocklist.
- **Control device.** `IoCreateDeviceSecure` with `D:P(A;;GA;;;WD)` and
  `FILE_DEVICE_SECURE_OPEN`. All IOCTLs are `METHOD_BUFFERED, FILE_ANY_ACCESS`; the device
  DACL allows every local user, so authorization is effectively delegated to the test
  environment. Loading the driver still requires an administrator.
- **No INF/catalog.** v1 installs with `sc.exe create`; no PnP packaging.

## Risks and limitations

- **Build-specific offsets.** The table is ported from KDU and covers 9600-26200. A wrong
  or missing entry is dangerous, so an unknown build returns `STATUS_NOT_SUPPORTED`; do
  not guess. Add new builds to `shared/PplBuilds.c` only after confirming the offset
  (for example with the matching type information from Vergilius Project).
- **DKOM is unsupported.** Microsoft does not support direct `EPROCESS` modification.
- **PPL is not kernel protection.** Kernel code can still manipulate the process.
- **`allow-dlls` weakens code integrity.** It removes the block-non-Microsoft-binaries
  mitigation from the target, so any unsigned DLL can load. The change is tracked and
  restored by `clear --pid` or driver unload, but a crash or forced unload leaves the
  target permissive until it exits or the machine reboots. Use only on a test target.
- **`allow-dynamic-code` weakens exploit mitigation.** It disables ACG in the target,
  allowing code pages to be made writable. An injected Detours payload then works, but
  so does any other in-process code modification. The change is tracked like
  `allow-dlls`; restore it with `--restore` / `clear --pid` when done.
- **Existing handles are not revoked.** If another process already has a full-access
  handle when the target becomes PPL, that handle may remain usable. Applying protection
  in the creation callback is stronger than PID/on-connect because fewer handles exist.
- **No inheritance.** A PPL process's children are not automatically PPL.
- **PPL-WinTcb is dangerous.** It can lock administrators and debugging tools out of a
  process. Default to Antimalware and keep a second admin console available.
- **Tracking is best effort.** Normal `clear`/unload restores tracked processes. A crash
  or forced unload can leave processes PPL until reboot.
- **The control device is a privilege boundary.** Its DACL allows all local users, so any
  local process can grant or clear PPL on any non-blocklisted process. Use only in an
  isolated test VM.
- **The broker is a privilege boundary.** The default pipe DACL is Everyone
  (`--allow-all`), so any local process can become PPL; use only in an isolated test VM.
  `--admin-only` restores the SYSTEM/Administrators-only DACL for the pipe only.
- **Test signing weakens the machine.** Turn it off and remove the test certificate when
  done.
- **No persistence.** The service is demand-start and PPL flags vanish on reboot.

## Test matrix

| # | Test | Expected |
|---|---|---|
| 1 | Build | Driver, CLI, target build; `dumpbin` shows Check integrity |
| 2 | Sign | `signtool verify /pa` succeeds |
| 3 | Load | `sc start MakeMePPL`; `pplctl info` shows 26100, `0x5FA` |
| 4 | PID set | `set`, `query` shows `0x31`; `probe` denies all-access/VM-read |
| 5 | PID clear | `clear` restores `0x00`; `probe` allows all-access |
| 6 | Filter add | New `test_target.exe` is protected; non-match is not |
| 7 | Apply existing | Already-running target becomes protected |
| 8 | Filter clear | No future grants; existing targets stay protected |
| 9 | On-connect | Broker/client report `OK`; probe denies access |
| 10 | Unload restore | `sc stop` restores the target's original byte |
| 11 | Negatives | PID 0/4, critical names, short/empty patterns, 17th filter refused; non-admin CLI succeeds |
| 12 | Stability | Many matching create/exit cycles; no bugcheck; reboot clears state |
| 13 | allow-dlls | `target_hardened.exe` (MicrosoftSignedOnly) accepts an unsigned DLL after `allow-dlls`; `query` shows `block non-MS DLLs: off`; `clear` restores it |
| 14 | DLL injector | `injector.exe` loads `payload.dll` into a normal target; `MsMpEng.exe` accepts it with `--ppl --fix-handle --kernel-thread`; `--restore` returns protection to `0x31` |
| 15 | allow-dynamic-code | `query` shows `MitigationFlags1` bit 8 cleared; `clear` restores it together with any `allow-dlls` change |
| 16 | Detours payload | `mpengine_hook.dll` emits `Detours hook installed` for `__rsignal` inside `MsMpEng.exe` with `--ppl --allow-dynamic-code --fix-handle --kernel-thread`; `rsignal_etw_listener.exe` shows `RSignalCall`/`RSignalReturn` events with hex dumps |

## Troubleshooting

- `Could not open \\.\MakeMePPL: error 5` - the device DACL denied access. Current
  builds allow all local users, so this usually means an older driver is loaded or the
  device DACL was customized. Rebuild/reinstall the driver.
- `error 2` - the driver is not loaded. Check `sc.exe query MakeMePPL`.
- Driver fails to load - confirm test signing is on, Secure Boot is off, the signature
  verifies, and HVCI is disabled in the test VM.
- `PsSetCreateProcessNotifyRoutineEx failed: 0xC0000022` - the driver image lacks
  `/INTEGRITYCHECK`; check `dumpbin /headers` for "Check integrity".
- `filter add` returns `STATUS_NOT_SUPPORTED` - the OS build has no known offset, or the
  callback is not registered. Run `pplctl builds` to see whether the running build is in
  the table.
- `allow-dlls` returns `STATUS_NOT_SUPPORTED` - the running build has no
  `MitigationFlags` offset in the table (for example 1607/1703). `pplctl info` shows
  `mitigation : allow-dlls supported` or the unsupported message.
- `allow-dlls` succeeds but a DLL still fails to load - the binary signature policy is
  gone, but another mitigation (ACG, image-load policy, or the image itself) may still
  block it. Check `Get-ProcessMitigation -Id <pid>`; `MicrosoftSignedOnly` should be OFF.
- `injector.exe` reports `OpenProcess failed (error 5)` - run it elevated. For a protected
  target such as `MsMpEng.exe`, pass `--ppl` so protection is cleared before
  `OpenProcess`; `--fix-handle` only repairs an existing handle.
- `CreateRemoteThread` fails or `LoadLibraryW` returns `NULL` - try `--kernel-thread`
  (protected-process thread check) and `--ppl` (PPL and blockdll mitigation).
- `injector.exe` reports `Could not open \\.\MakeMePPL` - the driver is not loaded, or the
  device DACL denied access. Run `pplctl info` first.
- No `[MakeMePPL]` messages - attach DebugView with kernel capture or use WinDbg.

## Cleanup

After testing:

```powershell
.\scripts\Uninstall-Driver.ps1
bcdedit /set testsigning off
Restart-Computer
```

Then remove the test certificate from both stores (replace `<thumbprint>`), delete
`certs\ppl_test.pfx`, and remove `certs\ppl_test.cer`. Do not leave test signing or a
trusted test root on a production machine.
