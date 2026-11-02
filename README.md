# PplExecutor

PplExecutor is a test-signed Windows 11 x64 WDM driver plus a user-mode CLI that sets
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
- **Name filter:** a process-creation callback protects every new image whose base name
  matches a pattern; `--apply-existing` handles already-running processes
- **On-connect:** an admin-owned named-pipe broker (`\\.\pipe\PplGrant`) resolves the
  connecting client's PID with `GetNamedPipeClientProcessId` and grants PPL
- Configurable signer, default Antimalware
- Blocklist for system-critical processes
- Best-effort restore of tracked processes on `clear` and driver unload
- `probe` black-box acceptance test using `OpenProcess` after enabling `SeDebugPrivilege`

The driver has an admin/SYSTEM-only device DACL and never opens a network socket, writes
files, or persists state.

## Layout

```text
ppl_executor/
  PplExecutor.sln
  shared/PplIoctl.h             shared IOCTLs and structs
  shared/PplBuilds.c/.h         NT build numbers + EPROCESS offset table
  driver/
    PplExecutor.vcxproj
    PplExecutor.c               DriverEntry, control device, IOCTL dispatch
    PplProtection.c/.h          offset table, DKOM, verification, tracking
    PplFilter.c/.h              filters, process callback, blocklist
    PplLog.h                    DbgPrintEx wrapper
  usermode/
    PplCtl.vcxproj
    PplCtl.cpp                  CLI and named-pipe broker
    PplDriverClient.cpp/.h      CreateFile/DeviceIoControl helpers
  tests/
    PplTarget.vcxproj
    PplTarget.cpp                outputs test_target.exe
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
- An elevated PowerShell for certificate, test-signing, install, and driver/CLI tests
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
  .\PplExecutor.sln /m /p:Configuration=Release /p:Platform=x64
```

Outputs:

```text
bin\Release\PplExecutor.sys
bin\Release\PplCtl.exe
bin\Release\test_target.exe
```

The driver is linked with `/INTEGRITYCHECK` in both configurations. Verify it:

```powershell
dumpbin /headers .\bin\Release\PplExecutor.sys | Select-String "Check integrity"
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

Start `test_target.exe` in one window; note its PID.

```powershell
# Grant PPL-Antimalware by PID
.\bin\Release\PplCtl.exe set --pid <pid>

# Inspect raw and user-mode views
.\bin\Release\PplCtl.exe query --pid <pid>

# OpenProcess acceptance test: all-access and VM-read should be denied
.\bin\Release\PplCtl.exe probe --pid <pid>

# Restore the tracked original byte
.\bin\Release\PplCtl.exe clear --pid <pid>
```

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
# Elevated console 1
.\bin\Release\PplCtl.exe broker --signer am

# Elevated console 2
.\bin\Release\PplCtl.exe connect --hold 60

# Elevated console 3
.\bin\Release\PplCtl.exe probe --pid <PID PRINTED BY connect>
```

The default pipe DACL allows only SYSTEM and Administrators. `--allow-all` changes it to
Everyone, which is a deliberate privilege-escalation endpoint; use it only in an isolated
test VM and only for a specific test.

## Commands

```text
pplctl info
pplctl set   --pid <pid> [--signer am|wintcb|windows|lsa|authenticode|codegen|winsystem|app] [--audit]
pplctl clear --pid <pid>
pplctl query --pid <pid>
pplctl probe --pid <pid>
pplctl filter add    --name <pattern> [--signer <name>] [--audit] [--exact] [--apply-existing]
pplctl filter remove --name <pattern>
pplctl filter clear
pplctl filter list
pplctl broker  [--pipe PplGrant] [--signer am] [--audit] [--once] [--allow-all]
pplctl connect [--pipe PplGrant] [--hold <seconds>]
pplctl builds
pplctl version
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
  records `MitigationFlags` and `ObjectTable` offsets for diagnostics; only
  `PS_PROTECTION` is written. Unknown builds (including 26H1/26H2, which KDU does not
  map yet) load but `SET`/`FILTER` return `STATUS_NOT_SUPPORTED`; the driver never
  guesses or scans for the field.
- **One byte.** Only `PS_PROTECTION` is written. The optional
  `SignatureLevel`/`SectionSignatureLevel` diagnostics are reported as zero because those
  undocumented exports use an output-pointer ABI; the driver deliberately does not call
  them.
- **Verification.** The driver reads the byte back and checks
  `PsIsProtectedProcess`/`PsIsProtectedProcessLight` for type 0, 1, or 2. On a signer-only
  change the boolean checks cannot distinguish signers, so the byte readback is the limit
  of the claim. A failed verification restores the old byte.
- **Tracking.** A fixed 256-entry nonpaged table records PID, EPROCESS identity, applied
  byte, and original byte. The whole read/write/verify/track sequence is serialized by a
  push lock. If the table is full, protection is still applied but that process is not
  restored on unload.
- **Clear safety.** `clear` refuses to remove protection from an untracked process whose
  current byte is non-zero. This avoids accidentally stripping PPL from Defender, LSA, or
  a process protected by a previous driver load.
- **Restore.** On normal `clear` or unload, the original byte is written only if the
  current byte still matches what this driver applied. PID-reused or externally changed
  processes are skipped. A driver crash or forced unload can leave processes PPL until
  reboot; reboot is the recovery path.
- **Filter callback.** The callback is allocation-free, does not wait on I/O, and never
  sets `CreationStatus`. It copies the matched filter, releases the filter lock, and then
  applies protection. Blocklisted images are skipped.
- **Blocklist.** PID 0/4 and `System`, `Registry`, `smss.exe`, `csrss.exe`,
  `wininit.exe`, `services.exe`, `lsass.exe`, `winlogon.exe` are refused. Apply-existing
  also skips the calling CLI process. The explicit PID path is intentionally more
  permissive for already-protected non-critical processes, but still logs and refuses the
  blocklist.
- **Control device.** `IoCreateDeviceSecure` with
  `D:P(A;;GA;;;SY)(A;;GA;;;BA)` and `FILE_DEVICE_SECURE_OPEN`. All IOCTLs are
  `METHOD_BUFFERED, FILE_ANY_ACCESS`; authorization comes from the device DACL.
- **No INF/catalog.** v1 installs with `sc.exe create`; no PnP packaging.

## Risks and limitations

- **Build-specific offsets.** The table is ported from KDU and covers 9600-26200. A wrong
  or missing entry is dangerous, so an unknown build returns `STATUS_NOT_SUPPORTED`; do
  not guess. Add new builds to `shared/PplBuilds.c` only after confirming the offset
  (for example with the matching type information from Vergilius Project).
- **DKOM is unsupported.** Microsoft does not support direct `EPROCESS` modification.
- **PPL is not kernel protection.** Kernel code can still manipulate the process.
- **Existing handles are not revoked.** If another process already has a full-access
  handle when the target becomes PPL, that handle may remain usable. Applying protection
  in the creation callback is stronger than PID/on-connect because fewer handles exist.
- **No inheritance.** A PPL process's children are not automatically PPL.
- **PPL-WinTcb is dangerous.** It can lock administrators and debugging tools out of a
  process. Default to Antimalware and keep a second admin console available.
- **Tracking is best effort.** Normal `clear`/unload restores tracked processes. A crash
  or forced unload can leave processes PPL until reboot.
- **The broker is a privilege boundary.** The default pipe DACL is admin/SYSTEM only.
  `--allow-all` lets any local process become PPL; use only in an isolated test VM.
- **Test signing weakens the machine.** Turn it off and remove the test certificate when
  done.
- **No persistence.** The service is demand-start and PPL flags vanish on reboot.

## Test matrix

| # | Test | Expected |
|---|---|---|
| 1 | Build | Driver, CLI, target build; `dumpbin` shows Check integrity |
| 2 | Sign | `signtool verify /pa` succeeds |
| 3 | Load | `sc start PplExecutor`; `pplctl info` shows 26100, `0x5FA` |
| 4 | PID set | `set`, `query` shows `0x31`; `probe` denies all-access/VM-read |
| 5 | PID clear | `clear` restores `0x00`; `probe` allows all-access |
| 6 | Filter add | New `test_target.exe` is protected; non-match is not |
| 7 | Apply existing | Already-running target becomes protected |
| 8 | Filter clear | No future grants; existing targets stay protected |
| 9 | On-connect | Broker/client report `OK`; probe denies access |
| 10 | Unload restore | `sc stop` restores the target's original byte |
| 11 | Negatives | PID 0/4, critical names, short/empty patterns, 17th filter, non-admin CLI refused |
| 12 | Stability | Many matching create/exit cycles; no bugcheck; reboot clears state |

## Troubleshooting

- `Could not open \\.\PplExecutor: error 5` - run elevated. The device DACL rejects
  non-admin callers.
- `error 2` - the driver is not loaded. Check `sc.exe query PplExecutor`.
- Driver fails to load - confirm test signing is on, Secure Boot is off, the signature
  verifies, and HVCI is disabled in the test VM.
- `PsSetCreateProcessNotifyRoutineEx failed: 0xC0000022` - the driver image lacks
  `/INTEGRITYCHECK`; check `dumpbin /headers` for "Check integrity".
- `filter add` returns `STATUS_NOT_SUPPORTED` - the OS build has no known offset, or the
  callback is not registered. Run `pplctl builds` to see whether the running build is in
  the table.
- No `[PplExecutor]` messages - attach DebugView with kernel capture or use WinDbg.

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
