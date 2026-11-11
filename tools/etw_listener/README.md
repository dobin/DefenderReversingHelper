# etw_listener — krabsetw consumer for `mpengine_hook.dll`

`rsignal_etw_listener.exe` creates a real-time ETW session, subscribes to the
TraceLogging provider emitted by
[`../../dll_injector/detours_payload`](../../dll_injector/detours_payload),
and prints each `__rsignal` call, return, and install/diagnostic message. It
uses the header-only [krabsetw](../../third_party/krabsetw) library.

```powershell
# Elevated PowerShell. Start the listener first, then inject.
.\bin\Release\rsignal_etw_listener.exe --out rsignal.txt
.\bin\Release\injector.exe MsMpEng.exe .\bin\Release\mpengine_hook.dll `
    --ppl --allow-dynamic-code --fix-handle --kernel-thread --restore
```

Options:

| Option | Meaning |
|---|---|
| `--session <name>` | Override the real-time session name |
| `--out <file>` | Write rendered text or binary records to a file |
| `--format <text\|binary>` | Output format (`text` is the default; `binary` requires `--out`) |
| `--dump` | Print a hex+ASCII dump of the data buffer |
| `--dump-bytes <n>` | Bytes of the buffer to dump (implies `--dump`; `0` = all, default 512) |
| `--no-dump` | Compact output (default): signal, flags, data address and size |
| `--max-events <n>` | Stop after n events |
| `--quiet-status` | Hide `Status` (install/diagnostic) events |
| `--help` | Usage |

By default each call is one line:

```text
[2026-11-10 12:34:56.789] pid=4321 tid=8765 seq=1 CALL signal=0x4019 flags=0x10 data=0x0000004A2B3C0000 (976 bytes)
```

Add `--dump` (optionally with `--dump-bytes`) for the hex+ASCII data buffer.
For framed binary payload records, use `--out rsignal.bin --format binary`.
Each CALL is written as a 10-byte little-endian header followed by the raw
payload: magic `0x5645` (`EV`), 32-bit signal ID, 32-bit payload size, payload.
Only CALL events are written to the binary file; status and return events are
still shown in the console output.

The consumer needs to create an ETW session, so run it elevated or as a member
of **Performance Log Users**. It can start before or after the payload
registers its provider. Ctrl+C stops the session cleanly.

The provider GUID, session name, event names, and field names are shared with
the payload through [`../../shared/MpEngineEtw.h`](../../shared/MpEngineEtw.h).
Keep both sides in sync when changing the schema.

`TraceLoggingWrite` events can also be recorded without this tool, for example
with `wpr -start` and the provider GUID, or viewed in Windows Performance
Analyzer.
