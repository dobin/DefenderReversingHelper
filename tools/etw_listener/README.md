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
| `--format <text\|binary\|jsonl>` | Output format (`text` is the default; `binary` and `jsonl` require `--out`) |
| `--context` | `jsonl`: also emit `ctx_addr`, `ctx_len` and `ctx_hex` |
| `--dump` | Print a hex+ASCII dump of the data buffer |
| `--dump-bytes <n>` | Bytes of the buffer to dump (implies `--dump`; `0` = all, default 512) |
| `--no-dump` | Compact output (default): signal, flags, data address and size |
| `--max-events <n>` | Stop after n events |
| `--quiet-status` | Hide `Status` (install/diagnostic) events |
| `--quiet-engine-log` | Hide `EngineLog` (engine's own log lines) events |
| `--quiet-trace` | Hide `EngineTrace` (structured engine records) |
| `--help` | Usage |

By default each call is one line:

```text
[2026-11-10 12:34:56.789] pid=4321 tid=8765 seq=1 CALL signal=0x4019 flags=0x10 data=0x0000004A2B3C0000 (976 bytes)
```

Add `--dump` (optionally with `--dump-bytes`) for the hex+ASCII data buffer.
The payload also forwards the engine's own log lines; they interleave with
the signal events:

```text
[2026-11-10 12:34:57.012] pid=4321 tid=8765 engine log: Engine-HIPS: Loaded ASR vdm rule "Block Win32 API calls from Office macro", State=5, Action=0, Type=1, ...
[2026-11-10 12:34:57.113] pid=4321 tid=8765 engine log: Engine: EMS scan for process: pid_8172 pid: 8172, sigseq: 0x454D53CF, sendMemoryScanReport: 0, source: 0
```

In `jsonl` format those are `{"k":"elog","kind":"0x19","level":...,"module":"Engine","message":"..."}`
objects; use `--quiet-engine-log` to hide them.

The payload also forwards the engine's structured trace records. A deferred
scan request (`kind 0x28`) is decoded into the same line mpclient prints:

```text
[2026-11-15 23:52:35.020] pid=5680 tid=3692 engine scan request : kind=ems target=ppids:{{8244, ...}} id=0x8E opcode=0x22 version=0 flags=0x1 caller=+0x9F9F01
```

`kind 0x18` is a generic host telemetry event (for example
`processmemoryscan`):

```text
... engine event : type=0x1 name=processmemoryscan value=pid:8172,ProcessStart:... version=0 id=0x87 detail=- caller=+0x4A73A6
```

`kind 0x38` and `kind 0x1C` are MOAC/cloud lookup records:

```text
... engine trace : kind=0x38 (moac lookup) caller=+0x295D96 detail=lookup=1A1D3D03-4302-40DF-8994-5F47D4D178D0 fileid=... id=0xF48F6190 flag=1
```

`kind 0x25` carries the scan-stage message the engine formatted:

```text
... engine scan stage : STOP:Engine quick scan variant, type 0x10050000, source=6 caller=+0x7746CC
```

The small fixed-layout records decode into named fields as well:

```text
... engine trace : kind=0x22 (host data read) caller=+0x2886A7 detail=len=8 buffer=0x15E3A5FBCB0 value=0x10
... engine trace : kind=0x2A (notification) caller=+0x3D5653 detail=type=6 object=0x1C6DD1C5940 [2]=0x0 [3]=0x0 [4]=0x2 [5]=0x0
... engine trace : kind=0x3D (host config query) caller=+0x4873AC detail=version=0x101 [1]=0x0 [2]=0x0 [3]=0x0
... engine trace : kind=0x44 (rtp update) caller=+0x348EFD detail=type=20 [1]=...
... engine trace : kind=0x52 (remediation config) caller=+0x953737 detail=delay=0 maxdelay=0 disable=0 opt1=0 opt2=0 opt4=0 opt5=0
```

Other kinds print their kind, caller RVA and a bounded payload copy:

```text
... engine trace : kind=0x3F (engine record) caller=+0x7A16FB payload=256 byte(s) hex=...
```

`caller` is the return address inside `mpengine.dll` that emitted the record;
use it to map a new kind to its function in Ghidra.  Add `--dump` to get the
full hex+ASCII dump of the captured payload; the payload capture is bounded by
`RSI_ENGINE_TRACE_DUMP_BYTES` in the DLL (default 256). Use `--quiet-trace` to
hide these records. In `jsonl` format they are
`{"k":"trace","kind":"0x28","caller_rva":...,"kind_name":"ems",
"target":"pid:8172",...}` objects; telemetry records carry `payload_hex`.

See [`docs/engine_trace_kinds.md`](../../docs/engine_trace_kinds.md) for the
recovered record layouts and the per-kind meaning.

Engine log lines are event-driven: the engine only emits them on boot (ASR rule
load), on a detection, or when its diagnostics are requested. To force a burst
while the listener runs:

```powershell
& "C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.26100.4-0\MpCmdRun.exe" -GetFiles
```

The `CALL`/`RETURN` stream runs continuously and is unrelated to the engine
log lines.
For framed binary payload records, use `--out rsignal.bin --format binary`.
Each CALL is written as a 10-byte little-endian header followed by the raw
payload: magic `0x5645` (`EV`), 32-bit signal ID, 32-bit payload size, payload.
Only CALL events are written to the binary file; status and return events are
still shown in the console output.

For machine-readable captures use `--out rsignal.jsonl --format jsonl`.  Each
CALL and RETURN is one JSON object, with the same fields the in-process
recorder in `mpclient` writes (`src/engine/mpengine_signal_record.c`):

```json
{"k":"call","i":17,"seq":17,"ts":133...,"pid":4321,"tid":8765,
 "signal":"0x4039","flags":56,"dump":56,"addr":...}
{"k":"ret","i":17,"seq":17,"ts":133...,"pid":4321,"tid":8765,"status":0}
```

`flags` is the fourth `__rsignal` argument; it is the logical request size for
signals that pass a size and must never be confused with `dump`, which is the
number of bytes the hook managed to copy (up to 4096 regardless of size).
`--format binary` and `--format jsonl` can be combined across two runs of the
same activity; `docs/rsignal_comparison.md` in `mpclient` explains why both are
needed.

The consumer needs to create an ETW session, so run it elevated or as a member
of **Performance Log Users**. It can start before or after the payload
registers its provider. Ctrl+C stops the session cleanly.

The provider GUID, session name, event names, and field names are shared with
the payload through [`../../shared/MpEngineEtw.h`](../../shared/MpEngineEtw.h).
Keep both sides in sync when changing the schema.

`TraceLoggingWrite` events can also be recorded without this tool, for example
with `wpr -start` and the provider GUID, or viewed in Windows Performance
Analyzer.
