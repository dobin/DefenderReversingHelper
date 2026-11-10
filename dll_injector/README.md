# dll_injector — DLL injection with MakeMePPL support

This folder integrates the `dll_load` lab injector into the MakeMePPL repository.
It is a classic remote `LoadLibrary` injector, extended with driver-backed
options so it can inject into protected processes such as
**`MsMpEng.exe`** (Microsoft Defender).

It also contains a Microsoft Detours payload,
[`detours_payload`](detours_payload/README.md), for hooking a function in
`mpengine.dll` after injection. Detours is built from its own source checkout
(`C:\Repos\Detours` by default); only the payload and the static-library
project live here.

The injector uses the shared MakeMePPL ABI directly
([`../shared/PplIoctl.h`](../shared/PplIoctl.h)) and the existing usermode
client ([`../usermode/PplDriverClient.cpp`](../usermode/PplDriverClient.cpp)).
It does not duplicate the IOCTL structs.

| Component | Source | Output |
|---|---|---|
| Injector | `DllInjector.cpp` | `bin\<Configuration>\injector.exe` |
| Test payload | `payload\payload.c` | `bin\<Configuration>\payload.dll` |
| Detours payload | `detours_payload\MpEngineHook.c` | `bin\<Configuration>\mpengine_hook.dll` |
| Detours static lib | `..\third_party\detours\DetoursLib.vcxproj` | `bin\<Configuration>\detours.lib` |

`payload.dll` writes a marker file to `C:\data\dll_load_<pid>.txt` from
`DLL_PROCESS_ATTACH`, so it proves code ran inside the target process.
`mpengine_hook.dll` installs a Detours hook on `mpengine.dll!__rsignal` and
dumps every call's arguments and pointed-to data to
`C:\data\rsignal_<pid>.log`; see
[detours_payload/README.md](detours_payload/README.md).

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
bin\Release\mpengine_hook.dll
bin\Release\detours.lib
```

Detours is compiled from `C:\Repos\Detours` by default. Override the checkout
with `.\scripts\Build.ps1 -DetoursDir C:\src\Detours`, the `DETOURS_DIR`
environment variable, or `/p:DetoursDir=...` on MSBuild.

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

& $msbuild .\third_party\detours\DetoursLib.vcxproj `
    /p:Configuration=Release /p:Platform=x64 "/p:SolutionDir=$root\"

& $msbuild .\dll_injector\detours_payload\MpEngineHook.vcxproj `
    /p:Configuration=Release /p:Platform=x64 "/p:SolutionDir=$root\"
```

## Usage

```text
injector.exe <pid|image name> <full\path\to\payload.dll>
             [--ppl] [--allow-dynamic-code] [--fix-handle]
             [--kernel-thread] [--restore]
```

The first argument is either a numeric PID or an image name such as
`MsMpEng.exe` (resolved case-insensitively with Toolhelp32). The DLL path is
normalised to an absolute path before injection.

| Option | What it does | Driver IOCTL |
|---|---|---|
| `--ppl` | Removes PPL from the target and clears the block-non-Microsoft-binaries DLL mitigation before injecting. Both changes are tracked by the driver. | `IOCTL_PPL_FORCE_CLEAR_BY_PID`, `IOCTL_PPL_ALLOW_NON_MS_DLLS` |
| `--allow-dynamic-code` | Clears ACG (`DisableDynamicCode`) so an in-process Detours payload can make image code pages writable. Required for `mpengine_hook.dll` if the target has ACG. Tracked. | `IOCTL_PPL_ALLOW_DYNAMIC_CODE` |
| `--fix-handle` | Restores process access that Defender self-protection stripped from the `OpenProcess` handle. | `IOCTL_PPL_FIX_HANDLE_ACCESS` |
| `--kernel-thread` | Creates the remote thread from kernel mode, bypassing the user-mode protected-process thread-creation check. | `IOCTL_PPL_CREATE_REMOTE_THREAD` |
| `--restore` | After injection, restores the original protection and signature mitigation. Only meaningful with `--ppl` / `--allow-dynamic-code`. | `IOCTL_PPL_CLEAR_BY_PID` |

`--ppl`, `--allow-dynamic-code`, `--fix-handle`, `--kernel-thread` and
`--restore` require the MakeMePPL driver to be loaded. See
[`../README.md`](../README.md) for driver installation and
[`../GUIDE.md`](../GUIDE.md) for the full command reference.

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

### Detours hooking payload (`mpengine_hook.dll`)

`detours_payload` builds a Microsoft Detours DLL whose target is
`mpengine.dll!__rsignal`. Use the same protected-target command:

```powershell
.\bin\Release\injector.exe MsMpEng.exe .\bin\Release\mpengine_hook.dll `
    --ppl --allow-dynamic-code --fix-handle --kernel-thread --restore
Get-Content C:\data\rsignal_<MsMpEng pid>.log
```

The payload waits for `mpengine.dll`, enlists every thread in the Detours
transaction (keeping the suspended-thread handles open until commit), attaches
the hook from a worker thread, and logs every `__rsignal` call: all four
arguments, a hex+ASCII dump of `Context` (512 bytes) and `Data` (up to 4096
bytes), and the return value. It never changes arguments or return values.

Detours needs writable `mpengine.dll` code pages. PPL and the DLL signature
mitigation are cleared by `--ppl`, but **Arbitrary Code Guard**
(`ProcessDynamicCodePolicy`) is separate and is cleared by
`--allow-dynamic-code` (`pplctl allow-dynamic-code --pid <pid>`). Without it,
`DetourTransactionCommit` fails with `ERROR_DYNAMIC_CODE_BLOCKED` (1655). See
[detours_payload/README.md](detours_payload/README.md) for the hook source,
changing the target function, and more caveats.

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
2. `--allow-dynamic-code` (optional): clear ACG (`DisableDynamicCode`) so an
   in-process Detours hook can change image code-page protection.
3. `OpenProcess` with `PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION |
   PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ`.
4. `--fix-handle` (optional): rewrite the stripped `GrantedAccess` on our
   existing handle.
5. `VirtualAllocEx` + `WriteProcessMemory` for the absolute DLL path.
6. Resolve `kernel32!LoadLibraryW`.
7. `CreateRemoteThread`, or `--kernel-thread` so MakeMePPL calls
   `RtlCreateUserThread` from kernel mode.
8. Wait for the thread / poll the target's module list, then free the remote
   buffer.
9. `--restore` (optional): restore protection and mitigation, or leave the
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
- **Detours has its own prerequisites.** The hook payload needs writable code
  pages in the target. PPL and the DLL signature mitigation are not enough if
  the target also runs with ACG; add `--allow-dynamic-code` so
  `mpengine_hook.dll` can install its hook.
- **A loaded payload locks its file.** Windows keeps `payload.dll` or
  `mpengine_hook.dll` mapped in the target, so rebuilding fails while that
  target is still running. Use a different payload name for repeat tests, or
  reboot / terminate the target.
- **Leaving changes tracked.** Without `--restore`, the driver keeps the
  original values so `pplctl clear --pid <pid>` or driver unload can restore
  them.
- **`C:\data` must be writable** by the target for the marker file to appear.
- This is a test tool for your own isolated VM. Do not inject into processes
  you do not own or control.
