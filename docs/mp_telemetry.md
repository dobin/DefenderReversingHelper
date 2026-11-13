# WdFilter-style kernel telemetry

## 1. Intro

This document records the protocol/design used by
`MakeMePPL.sys` to feed live file/process events to the mpclient agent
(`mpengine_client.exe agent`), which converts them into RTP notes for
`mpengine.dll`.

> Research/test tool only. The port DACL is open to any local user, matching
> the driver's control device. Use an isolated VM.


## 2. Protocol used by MakeMePPL

`shared/MpTelemetry.h` is the single source of truth; mpclient has a copy in
`include/mpengine_telemetry.h`. Keep the two in sync.

### Header (0x28 bytes)

```c
typedef struct _MP_TELEMETRY_HEADER {
    ULONG  Size;        /* total bytes, including this header   */
    USHORT Version;     /* 1                                    */
    USHORT Type;        /* EVENT / HELLO / HELLO_REPLY          */
    ULONG  ProcessId;   /* requestor (child pid for process)    */
    ULONG  ThreadId;
    ULONG  Event;       /* MP_TELEMETRY_EVENT_*                 */
    ULONG  Flags;       /* MP_TELEMETRY_FLAG_*                  */
    UINT64 Sequence;
    UINT64 Timestamp;   /* KeQuerySystemTime (100ns since 1601) */
} MP_TELEMETRY_HEADER;
```

### Event body

```c
typedef struct _MP_TELEMETRY_EVENT {
    MP_TELEMETRY_HEADER Header;
    ULONG  NameChars;        /* UTF-16 chars, excluding NUL  */
    ULONG  TargetChars;      /* rename target                */
    ULONG  CreateOptions;    /* disposition in the high byte */
    ULONG  FileAttributes;
    ULONG  ParentProcessId;
    ULONG  SubEvent;         /* write length for FILE_WRITE  */
    UINT64 CreateTime;       /* process creation FILETIME    */
    UINT64 FileId;           /* reserved (0)                 */
    WCHAR  Data[1];          /* Name NUL [Target NUL]        */
} MP_TELEMETRY_EVENT;
```

`Size` is authoritative. The consumer validates it against the
`FILTER_MESSAGE_HEADER` buffer and rejects a truncated/mismatched message.

### Events and note mapping

| Wire event | Value | Consumer note |
|---|---|---|
| `PROCESS_CREATE` | `0x0001` | process note event 1, image + create time |
| `PROCESS_EXIT` | `0x0002` | counted only |
| `FILE_CREATE` | `0x0010` | `MP_RTP_FILE_CREATE` |
| `FILE_WRITE` | `0x0011` | `MP_RTP_FILE_WRITE` when enabled |
| `FILE_CLOSE` | `0x0012` | `MP_RTP_FILE_CLOSE` if dirty |
| `FILE_RENAME` | `0x0013` | rename note (both paths) |
| `FILE_DELETE` | `0x0014` | `MP_RTP_FILE_DELETE` |
| `FILE_SET_INFO` | `0x0015` | `MP_RTP_FILE_CHANGE` |
| `FILE_SET_SECURITY` | `0x0016` | `MP_RTP_FILE_SET_SECURITY` |

`FILE_CREATE` carries the `NtCreateFile` disposition in the high byte of
`CreateOptions`.  `Flags` bit `0x8` (`WRITE_ACCESS`) is set when the requested
access includes a write/delete right.  The consumer marks a path dirty when
the disposition is not `FILE_OPEN` or the write-access bit is set, so a
read-only DLL open does not cause a close scan but a cached write issued at
APC still does.

### Handshake

The consumer sends `MP_TELEMETRY_HELLO` (`Type = HELLO`, version 1) with
`FilterSendMessage`. The driver's message callback validates the version and
returns `MP_TELEMETRY_HELLO_REPLY` with `MaxMessage` and `DriverVersion`.
A mismatch stops the consumer with `MP_E_LAYOUT_UNKNOWN`.

## 3. Driver design (`driver/MpTelemetry.c`, `MpTelemetryFile.c`)

`MpTelemetry.c` owns state, the send path, the process callback, the
communication-port callbacks and the lifecycle.  `MpTelemetryFile.c` owns the
minifilter operation table and the file callbacks.

- `FltRegisterFilter` + `FltCreateCommunicationPort(\MpEngineTelemetryPort,
  MaxConnections = 1)` + `FltStartFiltering`.
- `PsSetCreateProcessNotifyRoutineEx` for process create/exit.
- Minifilter callbacks:
  - `IRP_MJ_CREATE` post-op: skip failed/directory creates, send
    `FILE_CREATE`. The filter manager can deliver a create completion at
    `DISPATCH_LEVEL` when the create pended. Name lookup and `FltSendMessage`
    are illegal there, so the callback defers through
    `FltDoCompletionProcessingWhenSafe`. Simply returning (as an earlier
    version did) silently loses those creates, including the dirty mark that
    drives scan-on-close. The filter manager holds completion until the safe
    callback runs, so event order is preserved.
  - `IRP_MJ_WRITE` pre-op: skip paging I/O, rate-limit to 8192/second, send
    `FILE_WRITE` with the byte count.
  - `IRP_MJ_CLEANUP` pre-op: send `FILE_CLOSE`.
  - `IRP_MJ_SET_INFORMATION` pre-op: rename (`FileRenameInformation` /
    `FileRenameInformationEx`, resolved with
    `FltGetDestinationFileNameInformation`), delete
    (`FileDispositionInformation` / `Ex`), size/allocation changes.
  - `IRP_MJ_SET_SECURITY` pre-op: `FILE_SET_SECURITY`.
- `FltGetRequestorProcessId` filters pid 0/4 and the connected consumer's pid,
  so the agent's own scans cannot feed back into the note stream.
- A shared `ERESOURCE` serialises sends against disconnect/shutdown. There is
  no reply buffer, so `FltSendMessage` is fire-and-forget, but it is never
  called without a timeout: telemetry runs inside file/process callbacks, so an
  unbounded wait for a consumer that stopped reading would stall every I/O on
  every attached volume. `MP_TELEMETRY_SEND_TIMEOUT_MS` (100 ms) bounds the
  wait and the event is dropped and counted on `STATUS_TIMEOUT`. At APC_LEVEL
  the send uses a zero timeout because blocking is illegal there.
- After two consecutive timeouts the send path enters
  `MP_TELEMETRY_SEND_COOLDOWN_MS` (500 ms) of non-waiting, drop-only sends and
  then probes again. Without this, a consumer that is connected but frozen
  (suspended process, stuck worker) would charge every caller a full timeout
  for as long as it stays stuck.
- `FILE_CREATE` carries the real `IRP_MJ_CREATE` options, so
  `CreateOptions >> 24` is the `FILE_*` disposition. The consumer relies on it
  to tell a read open from a create/overwrite; sending zero makes every open
  look like `FILE_SUPERSEDE` and turns every close into a scan-on-close.
- The `WRITE_ACCESS` flag is computed in the preoperation callback from
  `Parameters.Create.SecurityContext->DesiredAccess` and passed to the
  postoperation callback as the completion context (the bitmask is stored in
  the pointer, never dereferenced). `SecurityContext` is usually NULL by the
  time the postoperation runs, and reading it there made a read-write open of
  an existing file look like a read-only open: no dirty mark and no
  scan-on-close for writes that stay in the cache.
- `MpTelemetryInitialize` is best effort. If registration fails, the PPL,
  mitigation, injection and name-filter features keep working and
  `PplCtl info` shows `telemetry : unavailable`.
- The registration provides a `FilterUnloadCallback`. Without one FltMgr makes
  the whole driver non-unloadable (`sc stop` fails with
  `ERROR_INVALID_SERVICE_CONTROL`, `fltmc unload` with
  `STATUS_FLT_DO_NOT_DETACH`), which forced a reboot for every driver update.
  The callback runs `PplDriverTeardown`, the same idempotent routine used by
  `DriverUnload`; it is idempotent because FltMgr calls the saved
  `DriverUnload` after the callback. It must call `FltUnregisterFilter` through
  `MpTelemetryShutdown`, so the teardown lives in the callback rather than only
  in `DriverUnload`.
- Close `PplCtl` and the broker before `sc stop`: an open handle to the control
  device keeps the driver image referenced even after the filter unregisters.

### Minifilter registration (`driver/MakeMePPL.inf`)

FltMgr needs a default instance and an altitude entry, which a minifilter INF
creates. `driver/MakeMePPL.inf` is an `FSFilter`-class legacy (non-PnP) INF;
`scripts/Build.ps1` stages it next to `MakeMePPL.sys` in `bin\<Configuration>`.

The service section installs `MakeMePPL.sys` into
`%SystemRoot%\System32\drivers` as `SERVICE_FILE_SYSTEM_DRIVER`
(`ServiceType = 2`, `StartType = 3`) with `Dependencies = FltMgr` and
`LoadOrderGroup = "FSFilter Anti-Virus"`. The instance data lives in the same
INF:

```ini
[MakeMePPL.AddRegistry]
HKR,,"SupportedFeatures",0x00010001,0x0000000F
HKR,"Instances","DefaultInstance",0x00000000,%InstanceName%
HKR,"Instances\%InstanceName%","Altitude",0x00000000,%InstanceAltitude%
HKR,"Instances\%InstanceName%","Flags",0x00010001,0x00000000
```

with `InstanceName = "MakeMePPL Instance"` and `InstanceAltitude = "328500"`.
These are exactly the values the old hand-written workaround created.

`scripts/Install-Driver.ps1` stops/deletes any previous service, installs the
package with `InfDefaultInstall.exe` (falling back to
`rundll32.exe setupapi.dll,InstallHinfSection DefaultInstall 132 <inf>`),
verifies that `Instances\DefaultInstance` and its `Altitude` exist, then starts
the service. `scripts/Sign-Driver.ps1` also runs `inf2cat` and signs
`MakeMePPL.cat`; the embedded `.sys` signature is still what the loader checks.
`scripts/Uninstall-Driver.ps1` stops/deletes the service and removes the copy
under `System32\drivers`.

`DefaultInstance` is required; without it `FltStartFiltering` reports no
usable instance and `PplCtl info` shows `telemetry : unavailable`.

## 4. Consumer (mpclient)

`mpengine_client.exe agent` starts the consumer before ETW:

1. `FilterConnectCommunicationPort(\MpEngineTelemetryPort)`.
2. `FilterSendMessage(HELLO)` and version check.
3. A receive thread loops `FilterGetMessage`, skips
   `sizeof(FILTER_MESSAGE_HEADER)` and copies the message into a 512-slot
   queue; a second thread turns queued messages into notes. The copy is what
   keeps the port read while a note is built or a file is scanned. Doing that
   work on the receive thread makes the driver's bounded `FltSendMessage` time
   out (visible as `send drops` in `PplCtl info`) and throttles every open on
   the volume.
   `FilterGetMessage` must pass a NULL `OVERLAPPED`: with one, the call returns
   `ERROR_IO_PENDING` immediately instead of blocking, the loop exits after the
   first call (`0x800703E5`), and the driver is left with a connected port that
   nobody drains.
   When the loop exits for any reason it closes the port, so the driver sees a
   disconnect even if the receive thread dies on its own.
   The queue is bounded: if the dispatch thread cannot keep up for long enough,
   the newest messages are dropped and counted (`queue drops` in the CLI
   summary). Shutdown discards the remaining backlog instead of waiting on
   scans.
4. File/process messages become `mp_rtp_note_*` notes and are sent through
   `0x4039`; `note.process_id` is the kernel-reported requestor pid and
   `note.create_time` is 0 for file notes (match by pid).
5. On stop, the stopper sets the stop flag and cancels the blocking
   `FilterGetMessage` (`CancelSynchronousIo` / `CancelIoEx`, retried until the
   receive thread exits), then joins the dispatch thread. The receive thread
   owns closing the port. The driver consumer is stopped before
   `0x403c/0x403f`.

A missing port is non-fatal and the agent keeps the ETW sources. If ETW
fails but the port connected, the agent continues with the kernel source
only. `--no-driver` disables the attempt; `mpengine_test.exe diag drv` tests
the port without ETW.

Path translation (`\Device\HarddiskVolumeN`, `\SystemRoot\`, `\??\`) is in
`src/drv/mpengine_drv_path.c`. A 4096-slot open-addressed hash tracks dirty
paths between create/write and cleanup; a close is sent only for a dirty path,
which is what triggers the host's scan-on-close.

## 5. Verification

```powershell
# Build and reload the driver in the test VM
.\scripts\Build.ps1 -Configuration Release
.\scripts\Sign-Driver.ps1 -Configuration Release
.\scripts\Uninstall-Driver.ps1
.\scripts\Install-Driver.ps1
.\bin\Release\PplCtl.exe info          # telemetry : minifilter active

# Consumer without ETW
cd C:\Data\defender-2026-autumn\mpclient
.\mpengine_test.exe diag drv --seconds 3 --no-elevate

# Full agent
.\mpengine_client.exe agent --seconds 10
```

A successful connection reports `driver events`/`driver notes` counts and
`0 failed`. The consumer must not log
`driver FilterGetMessage failed: 0x800703E5` (that code is
`ERROR_IO_PENDING`, i.e. the `OVERLAPPED` bug above).

`--verbose` is expensive: it logs every event and every dirty path, and on the
test VM that costs roughly the driver's 100 ms send timeout per event. Bursts
run in verbose mode therefore hit the timeout/cooldown and drop events; that is
the logging harness, not the wire path. In normal mode a create round-trip is
well under a millisecond and a scan-on-close is about 20 ms, so a single
producer stays far below the timeout.

The "consumer stopped reading" behaviour is testable without a hang: start
`diag drv`, suspend the process (`NtSuspendProcess`), then create and delete a
file. Each affected operation must finish on the order of the send timeout,
never block forever. With the cooldown, only the first couple of events pay
the timeout; later ones are dropped until the probe succeeds. Resume the
consumer and the counters keep advancing.

The loaded driver on the analysis machine predates `MpTelemetry.c`; a
`diag drv` run there returns `0x80070002` until the driver is rebuilt,
reinstalled and restarted. A driver update no longer needs a reboot: close the
agent/`PplCtl`, then `sc stop MakeMePPL && sc delete MakeMePPL`, rebuild, sign
and install again. A process that still holds the control device open keeps the
image loaded, so `sc stop` reports success while `fltmc filters` still lists the
filter until that handle closes.

## 6. Limitations

- Telemetry only. No I/O is blocked; the engine scans on dirty close.
- Scan-on-close runs on the consumer's receive thread. A slow scan reduces the
  drain rate; the driver's send timeout and cooldown keep that from stalling
  file I/O, but events generated during the stall are dropped (visible in the
  driver's drop counter).
- Process exit has no note (the recovered process factory accepts event ids
  1/2/5/6 and the exit id is unknown).
- Registry, network and image-load events remain ETW-only.
- The port DACL is open (`Everyone`, `FLT_PORT_ALL_ACCESS`). Restrict it to
  the agent image and require PPL for a production variant.
- One client at a time, matching WdFilter's single-client rule.
