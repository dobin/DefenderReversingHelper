# PplExecutor — Windows 11 PPL Flag Driver

## 0. Goal

Build a test-signed Windows 11 x64 kernel driver plus a user-mode CLI that can set the
`PS_PROTECTION` field in a target process's `EPROCESS` so the process becomes
**PPL (Protected Process Light)**.

Three user-facing interfaces:

1. **Specific PID** — `pplctl set --pid <pid> [--signer am|wintcb|...]`
2. **Process-name filter** — `pplctl filter add --name test_`; a kernel process-creation
   callback applies PPL automatically to every new matching process.
3. **On-connect** — a small admin-owned named-pipe broker; a process connects to
   `\\.\pipe\PplGrant`, the broker resolves its PID with
   `GetNamedPipeClientProcessId`, and grants PPL through the driver.

Confirmed design choices:

- On-connect = **user-mode named-pipe broker**, not a kernel-owned pipe.
- Protection level = **configurable**, default **PPL-Antimalware** (`0x31`).
- Build = **MSBuild / Visual Studio 2022 solution** with a WDK driver project and a
  user-mode console project. No CMake.

Reference implementation: `C:\Repos\RedEdr`

- `RedEdrDriver\kcallbacks.c` lines 734–1069: offset table, `PS_PROTECTION` layout,
  DKOM read/write/verify. Reuse the concept, not the whole scanner.
- `RedEdrDriver\Driver.c`: device + IOCTL skeleton. Note: it is missing a `break`
  after the first IOCTL case; do not copy that bug.
- `RedEdrDriver\RedEdrDriver.vcxproj`: `/integritycheck` is only set for Debug.
  We need it for **all** configurations.
- `generate_cert.ps1`: kernel-mode code-signing EKU and test-cert pattern.
- `Shared\common.h`: IOCTL/struct conventions.

## 1. Target Environment (detected)

| Item | Value |
|---|---|
| OS | Windows 11 Pro x64, build **26100** (24H2) |
| PPL offset for this build | **`0x5FA`** |
| Visual Studio | 2022 Community at `C:\Program Files\Microsoft Visual Studio\2022\Community` |
| MSBuild | `...\MSBuild\Current\Bin\MSBuild.exe` |
| signtool | `C:\Program Files (x86)\Windows Kits\10\bin\10.0.26100.0\x64\signtool.exe` |
| WDK | **Not installed** (`...\Include\10.0.26100.0\km` is missing) — install it first |
| VBS / HVCI | Currently off (`VirtualizationBasedSecurityStatus = 0`) |
| Secure Boot / test signing | Check from an elevated shell; Secure Boot must be off for test signing |

Prerequisites:

1. Install the **Windows Driver Kit (WDK)** for SDK 10.0.26100 via Visual Studio Installer.
   Verify `C:\Program Files (x86)\Windows Kits\10\Include\10.0.26100.0\km` exists and the
   `WindowsKernelModeDriver10.0` toolset is available.
2. Use an elevated shell for cert installation, test-signing changes, driver install, and
   all driver/CLI tests.
3. Work in a **test VM**. Take a snapshot before first driver load. A bad DKOM write can
   bugcheck the machine.

## 2. File Layout

```text
ppl_executor/
  PplExecutor.sln
  PLAN.md
  README.md                     # written after implementation
  shared/
    PplIoctl.h                  # IOCTLs + structs shared by driver and CLI
  driver/
    PplExecutor.vcxproj
    PplExecutor.c               # DriverEntry, unload, device, IRP dispatch
    PplProtection.c/.h          # offset table, PS_PROTECTION read/write/verify, tracking
    PplFilter.c/.h              # name filters, process-creation callback, apply-existing
    PplLog.h                    # DbgPrintEx wrapper
  usermode/
    PplCtl.vcxproj
    PplCtl.cpp                  # CLI: set/clear/query/probe/filter/broker/connect
    PplDriverClient.cpp/.h      # CreateFile + DeviceIoControl helpers
  tests/
    PplTarget.vcxproj
    PplTarget.cpp               # output name: test_target.exe
  scripts/
    Build.ps1
    New-TestCert.ps1
    Sign-Driver.ps1
    Enable-TestSigning.ps1
    Install-Driver.ps1
    Uninstall-Driver.ps1
```

## 3. Architecture

```text
pplctl set/filter/query ──DeviceIoControl──> \\.\PplExecutor
                                               │
                                     ┌─────────┴──────────┐
                                     │ PplExecutor.sys     │
                                     │  - IOCTL dispatch   │
                                     │  - EPROCESS DKOM    │
                                     │  - process callback │
                                     └─────────┬──────────┘
                                               │
                                     PsSetCreateProcessNotifyRoutineEx
                                               │
                                    new process matches "test_"?
                                               │
                                        set Protection = 0x31

pplctl broker <── named pipe \\.\pipe\PplGrant <── target process connects
      │
      └── GetNamedPipeClientProcessId() ──> IOCTL_SET_BY_PID

pplctl probe ──> OpenProcess(PROCESS_ALL_ACCESS) should fail for a PPL target
```

The driver only performs DKOM. The CLI and broker are ordinary user-mode admin programs.
No kernel pipe, no network socket, no service installation is required for the first version.

## 4. Shared ABI — `shared/PplIoctl.h`

Device names:

```c
#define PPL_DEVICE_NAME      L"\\Device\\PplExecutor"
#define PPL_SYMLINK_NAME     L"\\??\\PplExecutor"
#define PPL_WIN32_DEVICE     L"\\\\.\\PplExecutor"
#define PPL_DEFAULT_PIPE     L"PplGrant"
```

Protection constants:

```c
#define PS_PROTECTED_TYPE_NONE             0
#define PS_PROTECTED_TYPE_PROTECTED_LIGHT  1
#define PS_PROTECTED_TYPE_PROTECTED        2   // not exposed; PPL only

#define PS_PROTECTED_SIGNER_NONE           0
#define PS_PROTECTED_SIGNER_AUTHENTICODE   1
#define PS_PROTECTED_SIGNER_CODEGEN        2
#define PS_PROTECTED_SIGNER_ANTIMALWARE    3   // default -> 0x31
#define PS_PROTECTED_SIGNER_LSA            4
#define PS_PROTECTED_SIGNER_WINDOWS        5
#define PS_PROTECTED_SIGNER_WINTCB         6   // -> 0x61
#define PS_PROTECTED_SIGNER_WINSYSTEM      7
#define PS_PROTECTED_SIGNER_APP            8

#define MAKE_PS_PROTECTION(signer, audit, type) \
    ((UCHAR)(((signer) << 4) | (((audit) & 1) << 3) | ((type) & 7)))
```

Structs:

```c
#define PPL_MAX_FILTERS        16
#define PPL_MAX_PATTERN_CHARS  128

typedef struct _PPL_SET_REQUEST {
    ULONG ProcessId;
    UCHAR Signer;        // 1..8
    UCHAR Type;          // must be 1 (PPL) for this tool
    UCHAR Audit;         // 0 or 1
    UCHAR Reserved;
} PPL_SET_REQUEST;

typedef struct _PPL_OPERATION_RESULT {
    NTSTATUS Status;     // operation result; IRP itself usually succeeds
    UCHAR OldProtection;
    UCHAR NewProtection;
    UCHAR Reserved[2];
} PPL_OPERATION_RESULT;

typedef struct _PPL_QUERY_RESULT {
    NTSTATUS Status;
    ULONG ProcessId;
    ULONG BuildNumber;
    ULONG ProtectionOffset;
    UCHAR Protection;
    UCHAR SignatureLevel;
    UCHAR SectionSignatureLevel;
    UCHAR Flags;         // bit0 = PsIsProtectedProcess, bit1 = ...Light
} PPL_QUERY_RESULT;

typedef struct _PPL_FILTER_REQUEST {
    WCHAR Pattern[PPL_MAX_PATTERN_CHARS]; // null-terminated, 3..127 chars
    ULONG MatchMode;                      // 0 = substring, 1 = exact basename
    ULONG Flags;                          // bit0 = apply to already-running processes
    UCHAR Signer;                         // 1..8; default AM
    UCHAR Audit;                          // 0 or 1
    UCHAR Reserved[2];
} PPL_FILTER_REQUEST;

typedef struct _PPL_FILTER_RESULT {
    NTSTATUS Status;
    ULONG Applied;
    ULONG Skipped;
    ULONG Failed;
} PPL_FILTER_RESULT;

typedef struct _PPL_FILTER_LIST_ENTRY {
    WCHAR Pattern[PPL_MAX_PATTERN_CHARS];
    ULONG MatchMode;
    UCHAR Signer;
    UCHAR Audit;
    UCHAR Reserved[2];
} PPL_FILTER_LIST_ENTRY;

typedef struct _PPL_FILTER_LIST {
    NTSTATUS Status;
    ULONG Count;
    PPL_FILTER_LIST_ENTRY Entries[PPL_MAX_FILTERS];
} PPL_FILTER_LIST;

typedef struct _PPL_DRIVER_INFO {
    NTSTATUS Status;
    ULONG BuildNumber;
    ULONG ProtectionOffset;
    ULONG MaxFilters;
    ULONG Flags;         // bit0 = process-notify registered, bit1 = offset supported
    WCHAR Version[32];
} PPL_DRIVER_INFO;
```

IOCTLs (`METHOD_BUFFERED`, `FILE_ANY_ACCESS`; security comes from the device DACL):

| IOCTL | Input | Output |
|---|---|---|
| `IOCTL_PPL_SET_BY_PID` (0x800) | `PPL_SET_REQUEST` | `PPL_OPERATION_RESULT` |
| `IOCTL_PPL_CLEAR_BY_PID` (0x801) | `ULONG pid` | `PPL_OPERATION_RESULT` |
| `IOCTL_PPL_QUERY_BY_PID` (0x802) | `ULONG pid` | `PPL_QUERY_RESULT` |
| `IOCTL_PPL_FILTER_ADD` (0x803) | `PPL_FILTER_REQUEST` | `PPL_FILTER_RESULT` |
| `IOCTL_PPL_FILTER_REMOVE` (0x804) | `PPL_FILTER_REQUEST` | `PPL_FILTER_RESULT` |
| `IOCTL_PPL_FILTER_CLEAR` (0x805) | none | `PPL_FILTER_RESULT` |
| `IOCTL_PPL_FILTER_LIST` (0x806) | none | `PPL_FILTER_LIST` |
| `IOCTL_PPL_GET_INFO` (0x807) | none | `PPL_DRIVER_INFO` |

Convention: malformed buffers return `STATUS_INVALID_PARAMETER` /
`STATUS_BUFFER_TOO_SMALL`; well-formed operations complete the IRP with
`STATUS_SUCCESS` and put the real result in `Result.Status`. This lets the CLI display
`OldProtection`/`NewProtection` even on failure.

## 5. Driver Design

### 5.1 DriverEntry / unload

- Create a control device with `IoCreateDeviceSecure` using an admin/SYSTEM-only DACL:
  `L"D:P(A;;GA;;;SY)(A;;GA;;;BA)"` and `FILE_DEVICE_SECURE_OPEN`. Link `Wdmsec.lib`.
- Create symlink `\??\PplExecutor`.
- Clear `DO_DEVICE_INITIALIZING`.
- Register `PsSetCreateProcessNotifyRoutineEx(PplCreateProcessNotifyEx, FALSE)`.
  If it fails with `STATUS_ACCESS_DENIED`, log the likely cause: the driver image lacks
  `IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY` (missing `/INTEGRITYCHECK`). PID/on-connect
  still work; filter commands should return `STATUS_NOT_SUPPORTED`.
- Initialize the filter and tracking arrays.
- On unload, in this order:
  1. `PsSetCreateProcessNotifyRoutineEx(..., TRUE)` (waits for in-flight callbacks).
  2. Restore all tracked protections (best effort).
  3. Delete symlink and device.
  4. Clear filters/tracking.

### 5.2 Protection offset

```c
static const struct { ULONG Build; ULONG Offset; } g_PplOffsets[] = {
    { 22000, 0x87A },   // Win11 21H2
    { 22621, 0x87A },   // Win11 22H2
    { 22631, 0x87A },   // Win11 23H2
    { 26100, 0x5FA },   // Win11 24H2  <-- this host
    { 26200, 0x5FA },   // Win11 25H2
};
```

- Use `RtlGetVersion` in `DriverEntry`.
- If the build is unknown, load the driver but set offset 0 and make `SET`/`FILTER`
  return `STATUS_NOT_SUPPORTED`. `GET_INFO` reports the unsupported build. Do **not**
  guess an offset; a wrong write corrupts `EPROCESS`.
- Do not make RedEdr's 3-byte `SignatureLevel/SectionSignatureLevel/Protection` scanner
  the primary path. For a freshly created, unprotected process those bytes can all be
  zero, so the scan is ambiguous. Use the build table and verify with
  `PsIsProtectedProcess` / `PsIsProtectedProcessLight`.

### 5.3 Setting protection

`PsIsProtectedProcess` and `PsIsProtectedProcessLight` are exported by `ntoskrnl.exe`
(confirmed on this host) and are the end-to-end verification.

Core routine, taking an already-referenced `PEPROCESS`:

```c
NTSTATUS PplpSetProtection(
    PEPROCESS Process, ULONG Pid,
    UCHAR Signer, UCHAR Type, UCHAR Audit,
    PPL_OPERATION_RESULT* Result);
```

1. Validate `Signer <= 8`, `Type == 1` (PPL only), `Audit <= 1`.
2. Read the old byte at `(PUCHAR)Process + g_ProtectionOffset`.
3. Compute the new byte with `MAKE_PS_PROTECTION`.
4. Write it with a volatile byte store; read back.
5. Verify against the **target byte** that was written:
   - target `0x00`: `PsIsProtectedProcess` and `PsIsProtectedProcessLight` both FALSE;
   - target type 1 (PPL): both TRUE;
   - target type 2 (not exposed): protected TRUE, light FALSE.
6. If verification fails, restore the old byte, log, and return `STATUS_UNSUCCESSFUL`.
7. Record the change in the tracking table.

Note: for a signer-only change on an already-protected process, the boolean
`PsIsProtectedProcess*` checks cannot distinguish signers. In that case the build-table
offset plus the byte readback are the verification; do not claim more than that.

Use the same write/verify helper for `CLEAR_BY_PID`, passing the byte to restore
(`OriginalProtection` if tracked, otherwise `0x00`).

Only write the `Protection` byte. Do not touch `SignatureLevel` or
`SectionSignatureLevel`; KDU and RedEdr only change `Protection`, and that is enough for
the PPL access checks on these builds. If later testing shows otherwise, investigate
signature levels as a separate change.

For `QUERY`, resolve `PsGetProcessSignatureLevel` and
`PsGetProcessSectionSignatureLevel` with `MmGetSystemRoutineAddress` (RedEdr does the
same); if either is unavailable, report 0. These are read-only diagnostics.

For `CLEAR_BY_PID`:

- If the PID is in the tracking table, restore its recorded `OriginalProtection`.
- If it is **not** tracked:
  - current protection `0x00` -> success/no-op;
  - current protection non-zero -> refuse with `STATUS_ACCESS_DENIED` and log
    "refusing to unprotect an untracked protected process" (this avoids accidentally
    removing PPL from Defender/LSA or a process protected by a previous driver load).
- Verify with the same target-byte checks and untrack on success.
- Reboot is the recovery path if tracking was lost after a driver crash.

### 5.4 Tracking and restore-on-unload

Use a fixed nonpaged array (no allocation in the process-creation callback):

```c
typedef struct _PPL_TRACK_ENTRY {
    BOOLEAN InUse;
    ULONG ProcessId;
    UCHAR AppliedProtection;
    UCHAR OriginalProtection;
} PPL_TRACK_ENTRY;

PPL_TRACK_ENTRY g_Track[256];
EX_PUSH_LOCK g_TrackLock;
```

- Serialize the whole read/write/verify/track sequence with a push lock
  (`g_ProtectLock` or `g_TrackLock`) so a process-creation callback and a PID IOCTL
  cannot race on the same process. Release the lock before logging.
- On set: find an existing PID entry and update `AppliedProtection` (keep `Original`);
  otherwise take a free slot.
- On clear/unload: look up the PID; if it still exists and its current byte equals
  `AppliedProtection`, write `OriginalProtection`. If it does not match, skip (PID reuse
  or someone else changed it). This prevents clobbering unrelated processes.
- If the table is full, apply protection anyway but log "not tracked"; such a process
  will not be auto-restored on unload.
- This is a safety feature specific to this tool. If the driver crashes or is forcibly
  unloaded, tracked processes may remain PPL until reboot.

### 5.5 IOCTL dispatch

- Only handle `IRP_MJ_CREATE`, `IRP_MJ_CLOSE`, `IRP_MJ_DEVICE_CONTROL`.
- Require `PASSIVE_LEVEL` for `DEVICE_CONTROL`; return `STATUS_INVALID_DEVICE_STATE`
  otherwise.
- Copy input into a local struct, force null-termination on `Pattern`, validate all
  fields, zero the output struct, then execute.
- `SET_BY_PID` / `QUERY_BY_PID` / `CLEAR_BY_PID` use
  `PsLookupProcessByProcessId`, and always `ObDereferenceObject` before returning.
- `FILTER_ADD`:
  - Reject empty patterns, length `< 3`, length `>= PPL_MAX_PATTERN_CHARS`.
  - Reject duplicates (case-insensitive).
  - Validate `Signer <= 8` and `Audit <= 1`; store them with the pattern.
  - Add under `g_FilterLock` exclusive.
  - If `Flags & APPLY_EXISTING`, snapshot the pattern/signer/audit, release the lock,
    enumerate processes with `ZwQuerySystemInformation(SystemProcessInformation)`, and
    apply to each matching process that is not current, not blocklisted, and not already
    protected. Resolve `ZwQuerySystemInformation` with `MmGetSystemRoutineAddress` if the
    WDK headers do not declare it (RedEdr does this).
- `FILTER_REMOVE` / `FILTER_CLEAR` only change the filter list; they do not unprotect
  processes that were already protected. Use `clear --pid` or unload for that.
- `FILTER_LIST` returns `Count` plus the `Entries` array (pattern, mode, signer, audit).
- `GET_INFO` returns version, build, offset, max filters, and flags.

### 5.6 Process-creation callback and name matching

Store filters in a fixed nonpaged array guarded by `g_FilterLock`:
`{ InUse, MatchMode, Signer, Audit, Length, Pattern[128] }`.

```c
VOID PplCreateProcessNotifyEx(
    PEPROCESS Process, HANDLE ProcessId, PPS_CREATE_NOTIFY_INFO CreateInfo);
```

- `CreateInfo == NULL` means process exit: ignore.
- Fast-path return if no filters are active.
- `CreateInfo->ImageFileName` is the image name. If NULL, skip.
- Take the **base name** (last path component) and compare case-insensitively against
  each active filter:
  - default mode: substring;
  - exact mode: full base-name equality.
- Implement the comparison manually with `RtlUpcaseUnicodeChar` (or an equivalent
  kernel-safe helper). Do not depend on CRT `wcsstr`.
- If matched:
  - Skip if the process is blocklisted or is already protected (do not alter existing
    system PPL processes). Note: in this callback `PsGetCurrentProcess()` is the
    creator/parent, not the new process.
  - Apply with the filter's stored signer/audit (default
    `PS_PROTECTED_SIGNER_ANTIMALWARE`, type PPL, audit 0).
  - Never set `CreateInfo->CreationStatus` to an error; a protection failure must not
    break process creation.
  - Log the PID, base name, old/new byte, and verification result.
- The callback runs at PASSIVE_LEVEL inside a critical region with normal APCs disabled.
  Keep it allocation-free (fixed arrays), do not do file/registry I/O, and do not wait.
- If testing shows the kernel overwrites `Protection` after the callback, fall back to
  queuing a work item from the callback and applying there; verify with
  `pplctl query` as the acceptance test.

### 5.7 Safety blocklist

Refuse to protect:

- PID 0 (Idle) and PID 4 (System).
- Base names: `System`, `Registry`, `smss.exe`, `csrss.exe`, `wininit.exe`,
  `services.exe`, `lsass.exe`, `winlogon.exe`.
- The CLI/broker's own process when applying filters to existing processes.

Apply the blocklist to both the PID path and the name-filter path. Log refusals.
The explicit PID path is intentionally more permissive than the filter: it may change an
already-protected process (for example Defender), so log a warning and only do it
deliberately. PPL-WinTcb can lock administrators out of a process; the default is
PPL-Antimalware.

### 5.8 Logging

`PplLog.h`:

```c
#define PPL_LOG(fmt, ...) \
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, \
               "[PplExecutor] " fmt "\n", __VA_ARGS__)
```

Use DebugView with kernel capture, or WinDbg. Log offset/build, PID, image name, old/new
byte, verification, filter add/remove, and restore-on-unload.

## 6. User-Mode Design

### 6.1 `PplCtl` commands

```text
pplctl info
pplctl set   --pid <pid> [--signer am|wintcb|windows|lsa|authenticode|codegen|winsystem|app] [--audit]
pplctl clear --pid <pid>
pplctl query --pid <pid>
pplctl probe --pid <pid>
pplctl filter add    --name <pattern> [--signer am|wintcb|...] [--audit] [--exact] [--apply-existing]
pplctl filter remove --name <pattern>
pplctl filter clear
pplctl filter list
pplctl broker  [--pipe PplGrant] [--signer am] [--once] [--allow-all]
pplctl connect [--pipe PplGrant] [--hold <seconds>]
pplctl version
```

- Default signer is `am` (3) for `set`, `filter add`, and `broker`.
- `query` prints the driver's raw `Protection` byte, decoded type/signer/audit, build,
  offset, and the `PsIsProtectedProcess` flags. It also opens the target with
  `PROCESS_QUERY_LIMITED_INFORMATION` and calls `GetProcessInformation(
  ProcessProtectionLevelInfo)` to show the user-mode view.
- `probe` enables `SeDebugPrivilege` in its own token first, then opens the target three
  ways and prints the result plus `GetLastError()`:
  1. `PROCESS_ALL_ACCESS` — expected to fail with `ERROR_ACCESS_DENIED` for PPL.
  2. `PROCESS_VM_READ | PROCESS_QUERY_INFORMATION` — expected to fail.
  3. `PROCESS_QUERY_LIMITED_INFORMATION` — usually succeeds; report the actual result.
  Enabling `SeDebugPrivilege` makes the all-access/VM-read denials meaningful: a normal
  admin process would otherwise fail for reasons unrelated to PPL. This is the primary
  black-box acceptance test.
- `connect` prints its own PID before connecting, then the broker's response, then holds
  for `--hold` seconds (or until Enter) so another console can probe it.

### 6.2 Named-pipe broker

- `pplctl broker` creates `\\.\pipe\PplGrant` with `PIPE_ACCESS_DUPLEX`,
  `PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT`,
  `PIPE_UNLIMITED_INSTANCES`.
- Default pipe DACL: admin/SYSTEM only
  (`D:P(A;;GA;;;SY)(A;;GA;;;BA)`). `--allow-all` uses `D:P(A;;GA;;;WD)` (Everyone);
  this is a test-VM-only option and must be documented as dangerous.
- Loop:
  1. `ConnectNamedPipe`; treat `ERROR_PIPE_CONNECTED` as success (client connected
     before the call).
  2. `GetNamedPipeClientProcessId`.
  3. Skip self, PID 0/4, blocklisted names.
  4. Send `IOCTL_PPL_SET_BY_PID` with the configured signer/type.
  5. Write one line to the client:
     `OK pid=<pid> protection=0x31 signer=antimalware type=ppl`
     or `ERR pid=<pid> status=0x...`
  6. `DisconnectNamedPipe`, close the instance, repeat (unless `--once`).
- The driver also enforces the blocklist, so a malicious client cannot bypass it by
  connecting to the pipe.
- This is a deliberate privilege-escalation endpoint on the test VM. Keep the pipe
  admin-only unless the test specifically needs otherwise.

### 6.3 Driver client helper

`PplDriverClient.cpp/.h`:

- `OpenPplDevice()` — `CreateFileW(PPL_WIN32_DEVICE, GENERIC_READ | GENERIC_WRITE,
  FILE_SHARE_READ | FILE_SHARE_WRITE, ...)`.
- `PplIoctl(code, in, inLen, out, outLen)` — `DeviceIoControl` wrapper that prints
  `GetLastError()` on failure.
- `ParseSigner(name)` / `SignerName(value)`.
- NTSTATUS formatting helper (hex is sufficient; optionally `RtlNtStatusToDosError`).

## 7. Build, Sign, Install

### 7.1 WDK project settings

`driver/PplExecutor.vcxproj`:

- `ConfigurationType = Driver`
- `DriverType = WDM` (no KMDF dependency/co-installer)
- `PlatformToolset = WindowsKernelModeDriver10.0`
- `TargetVersion = Windows10` (valid for Windows 11)
- `WindowsTargetPlatformVersion = 10.0.26100.0`
- `Platform = x64` only; ARM64 is out of scope.
- `Driver_SpectreMitigation = false` (avoids extra Spectre libraries).
- **Linker: `/INTEGRITYCHECK` in both Debug and Release.**
  This sets `IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY`, which
  `PsSetCreateProcessNotifyRoutineEx` requires; without it the call returns
  `STATUS_ACCESS_DENIED`.
- Additional dependency: `Wdmsec.lib`.
- Disable automatic driver signing; sign with `scripts/Sign-Driver.ps1` after build.
- No INF/catalog is needed for `sc.exe create`. If the WDK project insists on an INF,
  add a stub and disable `Inf2Cat`; do not use it for installation in v1.

`usermode/PplCtl.vcxproj`:

- Console app, C++17, x64, `/W4`, `/EHsc`
- `_WIN32_WINNT=0x0A00`, `UNICODE`, `_UNICODE`
- Link `Advapi32.lib` (security descriptor conversion for the pipe DACL)
- Include `shared/`

`tests/PplTarget.vcxproj`:

- Console app, output name `test_target.exe`
- Prints its PID and waits for Enter. The `test_` filter must match it.

Build:

```powershell
& "C:\Program Files\Microsoft Visual Studio\2022\Community\MSBuild\Current\Bin\MSBuild.exe" `
  .\PplExecutor.sln /m /p:Configuration=Release /p:Platform=x64
```

`scripts/Build.ps1` wraps this and fails with a clear message if the WDK is missing.

### 7.2 Test certificate

`scripts/New-TestCert.ps1` (elevated):

```powershell
$cert = New-SelfSignedCertificate -Type CodeSigningCert `
  -Subject "CN=PplExecutor Test" -CertStoreLocation Cert:\CurrentUser\My `
  -HashAlgorithm SHA256 -KeyLength 2048 -NotAfter (Get-Date).AddYears(3) `
  -TextExtension @("2.5.29.37={text}1.3.6.1.4.1.311.61.4.1,1.3.6.1.5.5.7.3.3")

Export-PfxCertificate -Cert $cert -FilePath certs\ppl_test.pfx -Password $pfxPassword
Export-Certificate   -Cert $cert -FilePath certs\ppl_test.cer

Import-Certificate -FilePath certs\ppl_test.cer -CertStoreLocation Cert:\LocalMachine\Root
Import-Certificate -FilePath certs\ppl_test.cer -CertStoreLocation Cert:\LocalMachine\TrustedPublisher
```

- The EKUs are Code Signing + Kernel Mode Code Signing.
- Use a non-production PFX password (parameter or environment variable). Do not commit
  the PFX.
- The cert must be trusted in LocalMachine Root/TrustedPublisher for test signing.

Sign and verify:

```powershell
& "C:\Program Files (x86)\Windows Kits\10\bin\10.0.26100.0\x64\signtool.exe" `
  sign /fd SHA256 /f certs\ppl_test.pfx /p $password /ph /v `
  bin\Release\PplExecutor.sys

& "...\signtool.exe" verify /v /pa bin\Release\PplExecutor.sys
```

### 7.3 Enable test signing

`scripts/Enable-TestSigning.ps1` (elevated):

```powershell
bcdedit /set testsigning on
# Secure Boot must be OFF in UEFI, otherwise this fails or the driver will not load.
# Confirm-SecureBootUEFI should be False.
# Memory integrity / HVCI should also be off for this test VM.
```

Reboot. Verify with `bcdedit /enum {current}` (expect `testsigning Yes`) and
`msinfo32` (expect "Test Signing: Yes").

### 7.4 Install / start / stop

`scripts/Install-Driver.ps1`:

```powershell
sc.exe stop PplExecutor           # ignore "not started"
sc.exe delete PplExecutor         # ignore "not found"
sc.exe create PplExecutor type= kernel start= demand error= normal `
  binPath= "C:\Data\defender-2026-autumn\ppl_executor\bin\Release\PplExecutor.sys"
sc.exe start PplExecutor
sc.exe query PplExecutor
```

Uninstall:

```powershell
sc.exe stop PplExecutor
sc.exe delete PplExecutor
```

Close `pplctl`/broker windows before stopping the driver so the control device handle
does not delay unload. `sc stop` calls `DriverUnload`, which restores tracked processes.

## 8. Test Plan

| # | Test | Expected |
|---|---|---|
| 1 | Build solution | Driver + CLI + test target build; `dumpbin /headers PplExecutor.sys` shows "Force Integrity" |
| 2 | Sign + verify | `signtool verify /pa` succeeds |
| 3 | Test signing + load | `sc start PplExecutor` succeeds; `pplctl info` reports build 26100, offset `0x5FA` |
| 4 | PID set | Start `test_target.exe`; `pplctl set --pid <pid>`; `query` shows `Protection=0x31`; `probe` denies all-access/VM-read but allows limited-info |
| 5 | PID clear | `pplctl clear --pid <pid>` restores `0x00`; `probe` allows all-access |
| 6 | Filter add | `pplctl filter add --name test_`; start a new `test_target.exe`; it is protected automatically; a non-matching process is not |
| 7 | Apply existing | With `test_target.exe` already running, `filter add --name test_ --apply-existing`; it becomes protected |
| 8 | Filter clear | `filter clear` stops future grants; already-protected processes remain until `clear --pid` or driver unload |
| 9 | On-connect | `pplctl broker --signer am` in one elevated console; `pplctl connect --hold 60` in another elevated console (or run the broker with `--allow-all` for a non-admin client); broker/client report `OK`; `probe` from a third elevated console denies access |
| 10 | Unload restore | `pplctl set` a target, then `sc stop PplExecutor`; target's protection returns to its original value (usually `0x00`) |
| 11 | Negative tests | PID 0/4 refused; critical names refused; empty/short pattern refused; 17th filter refused; non-admin `pplctl` cannot open the device; broker cannot grant without admin |
| 12 | Stability | Create/exit many matching processes; no bugcheck, no stuck process; reboot clears all PPL state |

Debugging aids:

- DebugView (kernel capture) for `[PplExecutor]` lines.
- `sc.exe query PplExecutor` for load state.
- `Get-WinEvent -LogName System` for driver load errors.
- WinDbg + VM snapshot if the driver bugchecks.

## 9. Risks and Limitations

- **Offsets are build-specific.** `0x5FA` is for 26100/26200; `0x87A` is for 22000–22631.
  A wrong offset corrupts `EPROCESS`. Never guess on an unknown build; update the table.
- **DKOM is unsupported.** Microsoft does not support direct `EPROCESS` modification.
  Treat this as a test/research tool, not a production security product.
- **PPL is not kernel protection.** Kernel-mode code can still manipulate the process.
- **Pre-existing handles are not revoked.** If another process already has a full-access
  handle when the target becomes PPL, that handle may remain usable. Protection applied
  in the process-creation callback is stronger than PID/on-connect because fewer handles
  exist yet.
- **No inheritance.** A PPL process's children are not automatically PPL. Use the name
  filter or connect each child explicitly.
- **PPL-WinTcb is dangerous.** It can lock administrators and debugging tools out of the
  process. Default to PPL-Antimalware and keep a second admin console available.
- **Tracking is best-effort.** Normal `clear`/driver unload restores tracked processes.
  A driver crash or forced unload can leave processes PPL until reboot.
- **Broker is a privilege boundary.** Default pipe DACL is admin/SYSTEM only.
  `--allow-all` lets any local process become PPL; use only in an isolated test VM.
- **Test signing weakens the machine.** Turn it off and remove the test cert when done.
  Do not run this on a production host.
- **`/INTEGRITYCHECK` is mandatory.** Without it, `PsSetCreateProcessNotifyRoutineEx`
  returns `STATUS_ACCESS_DENIED`; the name-filter feature will not work.
- **No persistence.** The driver is demand-start; PPL flags are runtime-only and vanish
  on reboot.

## 10. Implementation Order

1. **Scaffold:** solution, shared header, empty driver + CLI, WDK project settings,
   `/INTEGRITYCHECK`. Acceptance: both projects build; `dumpbin` shows Force Integrity.
2. **Sign/load:** cert script, sign/verify, test-signing script, install/uninstall
   scripts. Acceptance: an empty `PplExecutor.sys` loads and unloads on 26100.
3. **PID DKOM:** offset table, `SET/CLEAR/QUERY` IOCTLs, `PsIsProtectedProcess`
   verification, tracking. Acceptance: `set/clear/query/probe` on `test_target.exe`.
4. **Name filter:** filter array, process-creation callback, apply-existing enumeration,
   blocklist. Acceptance: new `test_` processes are protected automatically.
5. **On-connect:** named-pipe broker + `connect` client, pipe DACL, PID resolution.
   Acceptance: `pplctl connect --hold` becomes PPL and `probe` denies access.
6. **Hardening:** tracking/restore on unload, concurrency review, negative tests,
   DebugView logging, README with commands and warnings.
7. **Final validation:** full test matrix, reboot, turn test signing off, document
   cleanup. Acceptance: no orphaned PPL processes after normal stop/unload.
