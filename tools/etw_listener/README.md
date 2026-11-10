# etw_listener — krabsetw consumer for `mpengine_hook.dll`

`rsignal_etw_listener.exe` creates a real-time ETW session, subscribes to the
TraceLogging provider emitted by
[`../../dll_injector/detours_payload`](../../dll_injector/detours_payload),
and prints each `__rsignal` call, return, and install/diagnostic message. It
uses the header-only [krabsetw](../../third_party/krabsetw) library.

```powershell
# Elevated PowerShell. Start the listener first, then inject.
.\bin\Release\rsignal_etw_listener.exe --pid <MsMpEng pid> --out rsignal.txt
.\bin\Release\injector.exe MsMpEng.exe .\bin\Release\mpengine_hook.dll `
    --ppl --allow-dynamic-code --fix-handle --kernel-thread --restore
```

Options:

| Option | Meaning |
|---|---|
| `--pid <pid>` | Only show events from one process |
| `--session <name>` | Override the real-time session name |
| `--out <file>` | Also write the rendered text to a file |
| `--no-dump` | Print buffer lengths only |
| `--dump-bytes <n>` | Bytes per buffer to print (`0` = all, default 512) |
| `--max-events <n>` | Stop after n events |
| `--quiet-status` | Hide `Status` (install/diagnostic) events |
| `--help` | Usage |

The consumer needs to create an ETW session, so run it elevated or as a member
of **Performance Log Users**. It can start before or after the payload
registers its provider. Ctrl+C stops the session cleanly.

The provider GUID, session name, event names, and field names are shared with
the payload through [`../../shared/MpEngineEtw.h`](../../shared/MpEngineEtw.h).
Keep both sides in sync when changing the schema.

`TraceLoggingWrite` events can also be recorded without this tool, for example
with `wpr -start` and the provider GUID, or viewed in Windows Performance
Analyzer.
