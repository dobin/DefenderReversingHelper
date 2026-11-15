# detours_payload — ETW-instrumented Detours hook for `mpengine.dll`

`mpengine_hook.dll` is a Microsoft Detours payload for the existing
`dll_injector`. Load it into `MsMpEng.exe` after the MakeMePPL driver clears
PPL, and it installs an inline hook on `mpengine.dll!__rsignal`.

Target:

```c
ULONG __rsignal(PVOID Context, int Signal, PVOID Data, int Flags);
```

The hook does not write to disk. It emits ETW/TraceLogging events from a
dedicated provider, and the separate `rsignal_etw_listener.exe`
([`../../tools/etw_listener`](../../tools/etw_listener)) renders them:

```powershell
# Terminal 1 (elevated): start the consumer first
.\bin\Release\rsignal_etw_listener.exe

# Terminal 2 (elevated): inject the hook
.\bin\Release\injector.exe MsMpEng.exe .\bin\Release\mpengine_hook.dll `
    --ppl --allow-dynamic-code --fix-handle --kernel-thread --restore
```

The provider identity and event schema are in
[`../../shared/MpEngineEtw.h`](../../shared/MpEngineEtw.h):

| Item | Value |
|---|---|
| Provider name | `DefenderReversingHelper-MpEngineRSignal` |
| Provider GUID | `{9F2C5A64-3E8B-4D71-A0C6-5B7E4F1D2A93}` |
| Session name | `DefenderReversingHelper-MpEngineRSignal` |

The hook forwards all arguments and the return value unchanged. It does not
block or modify anything. For each call it emits:

1. `RSignalCall` — all four arguments: `Context`, `Signal` (hex), `Data`, and
   `Flags`, plus a monotonic call number. It also carries a hex-encoded copy of
   the bytes read from `Context` (default 512) and from `Data` (default 4096),
   clamped to the committed region so guard pages are not touched. The copy is
   taken **before** the real function runs, so it is exactly what mpengine
   received. Hex text is used instead of a binary field so every consumer
   decodes the same bytes without TraceLogging binary length-prefix ambiguity.
2. `RSignalReturn` — the return value.
3. `Status` — install/diagnostic messages (`payload attached`,
   `Detours hook installed`, failures) with a Win32 error code where relevant.
4. `EngineLog` — the engine's own log lines (`Engine: ...`,
   `Engine-HIPS: ...`), captured from the engine trace callback rather than
   from `__rsignal` (see below).
5. `EngineTrace` — the structured records handed to the same callback:
   deferred scan requests (`kind 0x28`, decoded) and engine telemetry kinds
   with a bounded payload hex copy (see below).

Event field names and types are listed in `shared/MpEngineEtw.h`. Because the
`Status`/`RSignalCall` events are ordinary `TraceLoggingWrite` calls, they can
also be captured with `wpr`/`xperf` or rendered by WPA without this listener.

| Output | Source | Notes |
|---|---|---|
| `bin\<Configuration>\mpengine_hook.dll` | `MpEngineHook.c` | Detours payload |
| `bin\<Configuration>\rsignal_etw_listener.exe` | `tools\etw_listener` | krabsetw consumer |
| `bin\<Configuration>\detours.lib` | `..\..\third_party\detours` | Detours, built from source |

When no ETW session has the provider enabled, `TraceLoggingWrite` is a cheap
no-op: the payload does not even read the `Context`/`Data` buffers. With a
listener attached, the buffers are copied and hex-encoded into events of up to
~9.5 KB each. ETW drops events (rather than blocking) if the consumer cannot
keep up; that is expected under heavy scan load.

## Engine log capture

The payload also captures the engine's own log lines:

```text
engine log: Engine-HIPS: Loaded ASR vdm rule "Block Win32 API calls from Office macro", ...
engine log: Engine: EMS scan for process: pid_8172 pid: 8172, sigseq: 0x454D53CF, ...
```

Those are not WPP traces (the `advapi32!TraceMessage` path is gated off unless
an ETW session enables it, and its text lives in a TMF that is not shipped).
mpengine formats each line in memory and hands it to a callback stored on the
process-wide engine instance; MpSvc installs that callback. The payload's
`HookMaintenanceThread` waits for the instance, replaces the callback with
`Hook_EngineTrace`, and forwards every record to the previous sink, so
Defender's own logging is unchanged.

Record layout (mpengine 1.1.26100.4 — re-check the RVAs per engine build):

| item | value |
|---|---|
| instance global | `mpengine + 0x111E110` |
| instance sanity check | `*(void**)instance == mpengine + 0x2EA820` |
| trace ABI selector | `mpengine + 0x10D0738` (`1` → legacy slot) |
| callback slots | `+0xB00` legacy, `+0xB08` new ABI, `+0xB10` context |
| record | `+0x00 kind`, `+0x08 timestamp`, `+0x10 payload` |
| kind `0x19` payload | `+0x00 level`, `+0x08 flags`, `+0x10 log*` |
| kind `0x19` log | `+0x00 module`, `+0x08 level`, `+0x10 bytes`, `+0x18 message` |

`kind 0x19` (text log) is emitted as an `EngineLog` event. The structured
records are emitted as `EngineTrace` events:

- `kind 0x28` is a deferred scan request. The payload decodes the work item
  (`opcode`, `flags`, `kind`, `target`, `version`, `id`) so the listener can
  print e.g. `engine scan request : kind=ems target=pid:8172 id=0x8E
  opcode=0x22 version=1 flags=0x1`. This is the engine's own "scan this
  process" decision and is emitted regardless of the other-kinds switch.
- `kind 0x18`/`0x1C`/`0x1E`/`0x20`/`0x46`/`0x4C`/`0x62` (engine telemetry)
  attach a bounded hex copy of the record payload
  (`RSI_ENGINE_TRACE_DUMP_BYTES`, default 256) so the fields can be decoded
  offline without rebuilding the payload. `RSI_ENGINE_CAPTURE_OTHER_KINDS=1`
  (the default) enables this; set it to `0` to emit only the text log and
  scan requests.

Caveats:

- The callback slot only exists after MpSvc boots the engine. The watchdog
  starts with the hook and arms as soon as the instance appears, so lines
  produced before that (the ASR rule dump at boot) are missed when injecting
  into an already-running `MsMpEng.exe`. Trigger `RSIG_GENERATE_SUPPORT_LOG`
  (0x4080) to make the engine dump its diagnostics again.
- Message pointers are engine-owned and valid only during the callback; the
  hook copies them before forwarding.
- If the engine reboots (`RSIG_UNLOADENGINE`, 0x400a) the watchdog re-takes
  the slot.

## Surviving engine reloads

`MpSvc` unloads and reloads `mpengine.dll` in place (engine refresh, idle
unload), and the module can come back at a **different base**. That drops the
inline Detours patch on `__rsignal` and replaces the engine instance, so a
one-shot hook stops producing events after a few minutes even though the
payload DLL is still loaded.

`mpengine_hook.dll` therefore runs one maintenance thread per process. Every
250 ms it:

1. resolves `GetModuleHandleW(L"mpengine.dll")` again,
2. compares the 16 bytes at `__rsignal` with the prologue saved before the
   first patch — if they match, the module is fresh and the detour is
   re-attached (with a 30 s backoff if the install fails, e.g. because ACG was
   restored),
3. re-arms the engine trace slot on the *current* engine instance.

The re-installs are visible in the listener as repeated `Status` events:

```text
Detours hook installed: mpengine.dll!__rsignal -> 0x...
engine log capture armed: instance=0x... slot=+0xB00 original=0x... abi=1
```

If the instance layout no longer matches the build, or the slot cannot be read or
written, the payload emits a `Status` error naming the instance and slot instead
of silently capturing nothing.

For deeper troubleshooting, compile the payload with `RSI_DIAG_LOG=1`
(`#define RSI_DIAG_LOG` in `MpEngineHook.c`): it appends a stage log to
`C:\data\mpengine_hook_<pid>.log` (DllMain, `TraceLoggingRegister` result,
hook install result, slot arming). It is off by default, so the released
payload writes nothing to disk.



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

& $msbuild .\tools\etw_listener\RSignalEtwListener.vcxproj `
    /p:Configuration=Release /p:Platform=x64 "/p:SolutionDir=$root\"
```

## Capture the events

`rsignal_etw_listener.exe` creates a real-time ETW session and subscribes to
the provider GUID. Creating a session requires elevation (or membership in
**Performance Log Users**). Useful options:

```text
--dump             print a hex+ASCII dump of the data buffer
--dump-bytes <n>   bytes of the buffer to dump (implies --dump; 0 = all, default 512)
--no-dump          compact output (default): signal, flags, data address, size
--out <file>       also write the rendered text to a file
--max-events <n>   stop after n events (handy for scripted runs)
--quiet-status     hide install/diagnostic Status events
```

By default each call is a single line with the arguments and data size:

```text
[2026-11-10 12:34:56.789] pid=4321 tid=8765 seq=1 CALL signal=0x4019 flags=0x10 data=0x0000004A2B3C0000 (976 bytes)
[2026-11-10 12:34:56.789] pid=4321 tid=8765 seq=1 RETURN status=0x0000800E
```

Add `--dump` for the hex+ASCII payload:

```text
[2026-11-10 12:34:56.789] pid=4321 tid=8765 seq=1 CALL signal=0x4019 flags=0x10 data=0x0000004A2B3C0000
    data: 976 byte(s)
      0000  EF BE AD DE ...                              |....hello from f|
```

`__rsignal` is a signal/event dispatcher used by the engine. To generate
activity, run a scan with `MpCmdRun.exe -Scan -ScanType 1` or perform actions
that make Defender inspect files.

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
5. The payload's worker thread registers the provider, waits for
   `mpengine.dll`, resolves `__rsignal`, and commits the Detours transaction.
6. `--restore` puts PPL, ACG and the signature mitigation back.

Verify:

```powershell
.\bin\Release\PplCtl.exe query --pid <MsMpEng pid>
```

A successful install emits these `Status` events:

```text
payload attached: pid=... host=...
mpengine.dll @ 0x...
target mpengine.dll!__rsignal @ 0x...
Detours enlisted N thread(s), skipped 0
Detours hook installed: mpengine.dll!__rsignal -> 0x...
```

If the listener starts after the hook is installed, the install messages are
already gone (ETW is real time), but calls appear immediately.

## Changing the hook

The hook prototype and export name are compile-time constants:

- `MPENGINE_HOOK_EXPORT` in `MpEngineHook.c` (default `__rsignal`).
- `PFN___rsignal`, `Hook___rsignal`, and the `DetourAttach` call in
  `InstallHooksThread`.
- Dump sizes: `RSI_CONTEXT_DUMP_BYTES`, `RSI_DATA_DUMP_BYTES`.

For a different function, add the matching typedef and hook body, then change
the `DetourAttach` target. Keep the real-function pointer updated by
`DetourAttach`; the hook must forward to it.

`mpengine.dll` only exports a small named surface (`MpBootStrap`,
`MpContainer*`, `__rsignal`, `rsignal`, ...). For an internal, non-exported
function, resolve it with a signature/pattern scan and pass that address to
`DetourAttach`; the rest of the transaction is unchanged.

## Removing the hook

The hook is intentionally left installed for the life of the process. Do not
`FreeLibrary` the payload: Detours keeps a trampoline inside this DLL, and the
engine trace callback slot points straight at `Hook_EngineTrace`, so unloading
the DLL would leave `mpengine` calling into unmapped memory. Terminate or
restart `MsMpEng.exe`/the test process to remove it.

## Caveats

- **ACG (Arbitrary Code Guard).** Detours must make `mpengine` code pages
  writable. If the target enables `ProcessDynamicCodePolicy`, the commit fails
  with `ERROR_DYNAMIC_CODE_BLOCKED` (1655). `--ppl` clears PPL and the DLL
  **signature** mitigation; `--allow-dynamic-code` clears ACG
  (`pplctl allow-dynamic-code --pid <pid>`). Use both for `MsMpEng.exe`.
  The failure appears as a `Status` error event when a listener is attached.
- **PPL restore timing.** `--restore` runs as soon as the module is visible.
  The payload installs the hook on a worker thread, usually well under a
  second. If you see the module load but no hook status, leave PPL cleared
  (`pplctl clear --pid <pid>`) or wait before restoring.
- **Defender reacts.** This is code modification inside the antivirus engine.
  It can crash the engine or make Defender re-apply protections. Snapshot the
  VM first.
- **One payload at a time.** Rebuilding `mpengine_hook.dll` fails while an
  `MsMpEng.exe` still has it mapped. Use a copy with a different name for
  repeat tests, or restart the service/VM.
- **x64 only.** The solution and Detours library are x64.
