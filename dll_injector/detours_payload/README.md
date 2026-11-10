# detours_payload — Detours hook DLL for `mpengine.dll`

`mpengine_hook.dll` is a Microsoft Detours payload for the existing
`dll_injector`. Load it into `MsMpEng.exe` after the MakeMePPL driver clears
PPL, and it installs an inline hook on `mpengine.dll!__rsignal`.

Target:

```c
ULONG __rsignal(PVOID Context, int Signal, PVOID Data, int Flags);
```

Every call is dumped to:

```text
C:\data\rsignal_<pid>.log
```

The hook forwards all arguments and the return value unchanged. It does not
block or modify anything. For each call the log contains:

1. All four arguments: `Context`, `Signal` (hex), `Data`, and `Flags` (hex and
   decimal), plus a monotonic call number.
2. A hex + ASCII dump of `Context` (default 512 bytes).
3. A hex + ASCII dump of `Data` (default 4096 bytes, clamped to the committed
   region so guard pages are not touched).
4. The return value.

The dump is taken **before** the real function runs, so it captures the data
exactly as received.

| Output | Source | Notes |
|---|---|---|
| `bin\<Configuration>\mpengine_hook.dll` | `MpEngineHook.c` | Detours payload |
| `bin\<Configuration>\detours.lib` | `..\..\third_party\detours` | Detours, built from source |

The payload stops writing after `RSI_MAX_LOG_BYTES` (64 MB by default) and
notes the limit once in the log.

## Build

Detours stays in its own checkout. The default is `C:\Repos\Detours`; the
projects also read `DETOURS_DIR`, or an explicit MSBuild property:

```powershell
# Whole solution (also builds the driver)
.\scripts\Build.ps1 -Configuration Release

# Detours somewhere else
.\scripts\Build.ps1 -Configuration Release -DetoursDir C:\src\Detours
```

Only the new projects, if the driver is loaded and cannot be relinked:

```powershell
$root = (Get-Location).Path
$msbuild = "C:\Program Files\Microsoft Visual Studio\2022\Community\MSBuild\Current\Bin\MSBuild.exe"

& $msbuild .\third_party\detours\DetoursLib.vcxproj `
    /p:Configuration=Release /p:Platform=x64 "/p:SolutionDir=$root\"

& $msbuild .\dll_injector\detours_payload\MpEngineHook.vcxproj `
    /p:Configuration=Release /p:Platform=x64 "/p:SolutionDir=$root\"
```

## Inject into MsMpEng.exe

Elevated PowerShell, driver loaded, isolated test VM:

```powershell
.\bin\Release\injector.exe MsMpEng.exe .\bin\Release\mpengine_hook.dll `
    --ppl --allow-dynamic-code --fix-handle --kernel-thread --restore
```

The flow is the same as for any payload:

1. `--ppl` force-clears PPL and the block-non-Microsoft-binaries mitigation.
2. `--allow-dynamic-code` clears ACG / `DisableDynamicCode`.
3. `--fix-handle` repairs access stripped by Defender self-protection.
4. `--kernel-thread` creates the remote `LoadLibraryW` thread from kernel mode.
5. The payload's worker thread waits for `mpengine.dll`, resolves `__rsignal`,
   and commits the Detours transaction.
6. `--restore` puts PPL, ACG and the signature mitigation back.

Verify:

```powershell
Get-Content C:\data\rsignal_<MsMpEng pid>.log
.\bin\Release\PplCtl.exe query --pid <MsMpEng pid>
```

A successful install logs:

```text
[+] mpengine.dll @ 0x...
[+] target mpengine.dll!__rsignal @ 0x...
[*] Detours enlisted N thread(s), skipped 0
[+] Detours hook installed: mpengine.dll!__rsignal -> 0x...
```

After that each call starts with:

```text
__rsignal(ctx=..., signal=0x4019, data=..., flags=0x10 (16)) call=1
context @ ..., 512 byte(s):
    0000  44 33 22 11 ...  |D3".............|
data @ ..., 976 byte(s):
    0000  EF BE AD DE ...  |....hello from f|
__rsignal -> 0x0000800E (call=1)
```

`__rsignal` is a signal/event dispatcher used by the engine. To generate
activity, run a scan with `MpCmdRun.exe -Scan -ScanType 1` or perform actions
that make Defender inspect files.

## Changing the hook

The hook prototype and export name are compile-time constants:

- `MPENGINE_HOOK_EXPORT` in `MpEngineHook.c` (default `__rsignal`).
- `PFN___rsignal`, `Hook___rsignal`, and the `DetourAttach` call in
  `InstallHooksThread`.
- Dump sizes and the log limit: `RSI_CONTEXT_DUMP_BYTES`,
  `RSI_DATA_DUMP_BYTES`, `RSI_MAX_LOG_BYTES`.

For a different function, add the matching typedef and hook body, then change
the `DetourAttach` target. Keep the real-function pointer updated by
`DetourAttach`; the hook must forward to it.

`mpengine.dll` only exports a small named surface (`MpBootStrap`,
`MpContainer*`, `__rsignal`, `rsignal`, ...). For an internal, non-exported
function, resolve it with a signature/pattern scan and pass that address to
`DetourAttach`; the rest of the transaction is unchanged.

## Removing the hook

The hook is intentionally left installed for the life of the process. Do not
`FreeLibrary` the payload: Detours keeps a trampoline inside this DLL, so
unloading it would leave `mpengine` calling into unmapped memory. Terminate or
restart `MsMpEng.exe`/the test process to remove it.

## Caveats

- **ACG (Arbitrary Code Guard).** Detours must make `mpengine` code pages
  writable. If the target enables `ProcessDynamicCodePolicy`, the commit fails
  with `ERROR_DYNAMIC_CODE_BLOCKED` (1655). `--ppl` clears PPL and the DLL
  **signature** mitigation; `--allow-dynamic-code` clears ACG
  (`pplctl allow-dynamic-code --pid <pid>`). Use both for `MsMpEng.exe`.
  The payload logs the error if ACG is still active.
- **PPL restore timing.** `--restore` runs as soon as the module is visible.
  The payload installs the hook on a worker thread, usually well under a
  second. If you see the module load but no hook log, leave PPL cleared
  (`pplctl clear --pid <pid>`) or wait before restoring.
- **Defender reacts.** This is code modification inside the antivirus engine.
  It can crash the engine or make Defender re-apply protections. Snapshot the
  VM first.
- **One payload at a time.** Rebuilding `mpengine_hook.dll` fails while an
  `MsMpEng.exe` still has it mapped. Use a copy with a different name for
  repeat tests, or restart the service/VM.
- **x64 only.** The solution and Detours library are x64.
