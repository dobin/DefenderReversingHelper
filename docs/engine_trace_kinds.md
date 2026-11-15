# mpengine trace-callback record kinds

This is what `mpengine_hook.dll` receives from the engine trace callback
(the same callback the engine uses for its `Engine:` text log).  Layouts are
for `mpengine 1.1.26100.4` (`sha256 be18e430...e1dbff`).  Re-check the RVAs on
another engine build.

## Record envelope

```c
struct mp_trace_record {
    uint64_t kind;       /* +0x00 */
    uint64_t context;    /* +0x08, engine clock for most kinds */
    void    *payload;    /* +0x10 */
};
```

The callback is at `engine_instance + 0xB00` (legacy ABI, selector
`mpengine+0x10D0738 == 1`) or `+0xB08` (new ABI).  The selector's context is at
`+0xB10`.

The payload pointer is engine-owned and valid only during the callback.  The
hook copies what it needs before forwarding to the previous sink.  Small
payloads are stack structures, so a 256-byte read also captures unrelated
stack bytes behind them; decode only the documented fields.

Every `EngineTrace` event carries `CallerRva`, the return address inside
`mpengine.dll` that emitted the record.  That is how the kinds below were
mapped to their emitters.

## Kind map

| Kind | Listener label | Meaning | Emitter (caller RVA) |
|---|---|---|---|
| `0x0B` | host event | 0x238-byte host record | `FUN_180335884` |
| `0x13` | engine notification | notification forwarded verbatim | `FUN_1804B6FB0` (`+0x4B7074`) |
| `0x15` | engine notification | same forwarder, other notification type | `FUN_1804B6FB0` (`+0x4B7074`) |
| `0x18` | host event (telemetry) | `{u64 type; void *data}` generic event | many (`FUN_1801F0870`, `FUN_1804A7280`, ...) |
| `0x19` | text log | `Engine:` / `Engine-HIPS:` text | `FUN_180335884` |
| `0x1A` | moac entry | MOAC entry serialization, 0x50-byte form | `FUN_1802978CC`, `FUN_1804C715C` |
| `0x1C` | moac lookup (legacy) | MOAC lookup, legacy serialization | `FUN_180295C60` (`+0x295D96`) |
| `0x1F` | moac v2 attempt | result of one MOAC v2 attempt (32 bytes) | `FUN_180465C08` (`+0x465D15`) |
| `0x22` | host data read | engine reads a blob from the host | `FUN_1802885FC` (`+0x2886A7`) |
| `0x23` | host data write | engine hands a blob to the host | `FUN_1804F340C` (`+0x4F34D0`) |
| `0x25` | scan stage | `wchar_t *` stage message ("START:..."/"STOP:...") | `FUN_180774664` (`+0x7746CC`) |
| `0x28` | host work item | opcode `0x22` is a deferred scan request | `FUN_1809F9C0C` (`+0x9F9F01`), others |
| `0x2A` | notification | notification record, type 6 | `FUN_1803D54B0` (`+0x3D5653`) |
| `0x37` | moac entry | MOAC entry serialization, 0x40-byte form | `FUN_1804C715C` (`+0x4C7471`), `FUN_1802978CC` (`+0x297AA7`) |
| `0x38` | moac lookup | MOAC lookup, rich serialization | `FUN_180295C60` (`+0x295D96`) |
| `0x3D` | host config query | host fills a 0x20-byte out-buffer | `FUN_180487280` (`+0x4873AC`) |
| `0x3E` | host config release | same buffer released after use | `FUN_1804AAAD8` (`+0x4AAB5C`) |
| `0x3F` | engine record | `{u64 0x100; u64 a; u64 b}` (still raw) | `FUN_1807A1654` (`+0x7A16FB`) |
| `0x44` | rtp update | RTP/iClientInfo monitoring state update | `FUN_180348D5C` (`+0x348EFD`) |
| `0x52` | remediation config | host remediation configuration | `FUN_1809536BC` (`+0x953737`) |

Anything not in the table is printed with a bounded hex copy (default 256
bytes) so it can be decoded offline.

## `0x18` — generic host telemetry event

```c
struct trace_event {
    uint64_t type;       /* +0x00, 1 in every observed emitter */
    void    *data;       /* +0x08, type-specific */
};
```

Known `data` shapes:

- EMS scan report (`FUN_1801F0870`): `{ wchar_t *kind; wchar_t *target;
  u16 version; u16 id; ... }`.  Prints as
  `engine event : type=0x1 name=processmemoryscan value=pid:...,...`.
- `processmemoryscan` (`FUN_1804A7280`, caller `+0x4A73A6`): same
  `{name, value}` shape, e.g. `value=pid:5372,ProcessStart:...`, id `0x87`.
- Other observed names: `postsignatureupdatescan`, `package`.

## `0x22` / `0x23` — host data channel

```c
struct host_blob {
    uint32_t length;     /* +0x00, in/out: host may rewrite it */
    uint32_t pad;        /* +0x04 */
    void    *buffer;     /* +0x08 */
    uint32_t value;      /* +0x10, caller-provided id/flags */
    uint32_t pad2;       /* +0x14 */
    uint64_t extra;      /* +0x18 (0x23 only) */
};
```

`FUN_1802885FC` (0x22) reads a blob from the host into engine memory;
`FUN_1804F340C` (0x23) writes one out.  If the host changes `length`, the
engine zeroes the buffer and treats the read as refused.  Callers are the
engine's configuration/telemetry helpers (`FUN_18057E134`, `FUN_1807959B4`,
...), which read a 16-byte value and then write back a
`{u32 type=0x10006; u32 1; u64 object}` record plus a table of counters.

Live example:

```text
engine trace : kind=0x22 (host data read) caller=+0x2886A7 detail=len=8 buffer=0x15E3A5FBCB0 value=0x10
engine trace : kind=0x23 (host data write) caller=+0x4F34D0 detail=len=8 buffer=0x196F6FBAE0 value=0x30 extra=0x0
```

## `0x25` — scan stage

Payload is a `wchar_t *` pointing at the message the scan pipeline just
formatted (the hook dereferences it once).  These are the quick-scan
lifecycle lines:

```text
engine scan stage : STOP:Engine quick scan variant, type 0x10050000, source=6 caller=+0x7746CC
```

`FUN_18040AB40` formats `START:`/`STOP:Engine quick scan variant, type 0x%x,
source=%x` and calls `FUN_180774664`.

## `0x28` — host work item

```c
struct work_payload {
    uint32_t opcode;     /* +0x00, 0x22 = deferred scan request */
    uint32_t flags;      /* +0x04 */
    void    *args;       /* +0x08 */
};
```

For `opcode == 0x22`:

```c
struct work_args {
    wchar_t *kind;       /* +0x00, L"ems", L"process", ... */
    wchar_t *target;     /* +0x08, "pid:1234", "ppids:{...}" */
    uint16_t version;    /* +0x10 */
    uint16_t id;         /* +0x12, 0x8e for "ems" */
};
```

Other opcodes (`0x08`, `0x0A`, ...) carry different host tasks; only
`opcode`/`flags` are printed.

## `0x1C` / `0x38` — MOAC/cloud lookup

Both are emitted by `FUN_180295C60` (`mpengine+0x295C60`, callback call site
`+0x295D96`).  `0x38` is the rich serialization
(`(*(vtable+0x18))(entry, buffer)`); `0x1C` is the legacy path
(`(*(vtable+0x08))(entry, buffer)`).

### `0x38` payload (0x48 bytes, `FUN_1802962B0`)

```c
struct moac_lookup_rich {
    uint64_t type;         /* +0x00, 1 */
    uint64_t lookup_id[2]; /* +0x08, 16-byte lookup/context id */
    uint64_t file_id[2];   /* +0x18, FILE_ID_INFO.FileId (16 bytes) */
    uint64_t id;           /* +0x28, MOAC entry +0x40 */
    uint8_t  flags;        /* +0x30, entry +0x28; observed 1, 2, 0x80 */
    uint8_t  pad[7];       /* +0x31 */
    void    *name;         /* +0x38, inline buffer at entry +0x20 */
    uint64_t name_length;  /* +0x40, entry +0x18 (bytes) */
};
```

The name field is only filled when the entry carries a path (the
`std::wstring`-style buffer at `entry+0x08` is non-empty); file-id lookups
leave `name`/`name_length` zero and the hook prints no target.

### `0x1C` payload (0x38 bytes)

```c
struct moac_lookup_legacy {
    uint32_t type;         /* +0x00 */
    uint64_t handle;       /* +0x08 */
    uint64_t id;           /* +0x18 */
    uint8_t  flags;        /* +0x20 */
    uint8_t  pad[7];       /* +0x21 */
    void    *name;         /* +0x28 */
    uint64_t name_length;  /* +0x30 */
};
```

The legacy path was not taken by this engine build; the decoder mirrors the
same emitter's older serializer.

## `0x1A` / `0x37` — MOAC entry serialization

`FUN_1804C715C` builds a `MOACEntryUnFriendly` for a file and serializes it:

- `FUN_180298660(entry, buf)` -> `0x40`-byte form, emitted as kind `0x37`.
- `FUN_180A13080(entry, buf)` -> `0x50`-byte form, emitted as kind `0x1A`.

`FUN_1802978CC` does the same through the entry's vtable (`+0x28` -> `0x37`,
`+0x20` -> `0x1A`).  Both buffers start with the 16-byte lookup GUID, so the
hook prints `lookup=<guid>` plus the next qwords.

Live example:

```text
engine trace : kind=0x37 (moac entry) caller=+0x4C7471 detail=lookup=1A1D3D03-4302-40DF-8994-5F47D4D178D0 [2]=0x270000000075C7 [3]=0x0 [4]=0x80000005A0 [5]=0x0
```

The WPP component for this path is `Engine.Maps.BondDeserializationFailure`
(`DAT_180E8C1E0`), i.e. the entry is what the engine feeds into Bond/cloud
lookups.

## `0x1F` — MOAC v2 attempt

`FUN_180465C08` first asks `FUN_180295C60` for the legacy record; when that
returns "already handled" it runs two attempts (`DAT_180F07238` = `{1, 2}`)
and emits a 32-byte result buffer filled by the entry's vtable `+0x10`
("BadMOACV2Path" component):

```c
struct moac_v2_result { uint64_t v[4]; };
```

Live example:

```text
engine trace : kind=0x1F (moac v2 attempt) caller=+0x465D15 detail=[0]=0x1 [1]=0x100000000B9372 [2]=0xF29FDA28 [3]=0x1
```

## `0x2A` — notification record

`FUN_1803D54B0` builds a 0x60-byte record whose first field is the
notification type (`6` in every observation) and queues the object before
calling the sink:

```c
struct trace_notification {
    uint32_t type;       /* +0x00, 6 */
    uint32_t pad;        /* +0x04 */
    void    *object;     /* +0x08 */
    uint64_t a;          /* +0x10 */
    uint64_t b;          /* +0x18 */
    uint32_t flags;      /* +0x20 */
    ...
};
```

Its WPP component strings include `eSCT_AMSI`, `eSCT_IProtect`,
`eSCT_Default`, which ties the record to AMSI / Exploit Guard notifications.
The hook prints `type`, the object pointer and the next four qwords.

## `0x3D` / `0x3E` — host configuration query

`FUN_180487280` reads `MpDisableSyncSpynetCheck`, allocates a 0x20-byte
out-buffer, seeds `*(u32*)buf = 0x101` and asks the host to fill it
(kind `0x3D`).  The matching `FUN_1804AAAD8` emits kind `0x3E` and frees the
buffer.

```c
struct host_config {
    uint32_t version;    /* +0x00, 0x101 (out), host may change it */
    uint32_t pad;        /* +0x04 */
    uint64_t a;          /* +0x08 */
    uint64_t b;          /* +0x10 */
    uint64_t c;          /* +0x18 */
};
```

The related WPP block mentions `MapsDependencyAnalysisMaxReports` and
`MpDTDynLoadPaths` (`DAT_180EE78C0`), so this is the engine's dynamic-load /
dependency-analysis configuration channel.  A stub host leaves the extra
fields zero; Defender's service answers with `a=1` and two heap pointers.

## `0x44` — RTP monitoring update

`FUN_180348D5C` handles `UpdateMonitoringToRTP` and emits a 0x88-byte record.
The common form starts with type `0x14`:

```c
struct rtp_update {
    uint32_t type;       /* +0x00, 0x14 or 0x30 */
    uint32_t pad;        /* +0x04 */
    uint64_t time;       /* +0x08, engine clock/FILETIME */
    uint32_t a;          /* +0x10 */
    ...
};
```

Its WPP block (`DAT_180EFCEE0`) includes `iClientInfo` and `unavailable`,
matching the RTP client state this record describes.

## `0x52` — remediation configuration

`FUN_1809536BC` asks the host for the `RemediationConfiguration` values and
then writes them into the engine configuration store:

| Offset | Config value |
|---|---|
| `+0x00` | `routineactiondelay` |
| `+0x04` | `routineactionmaxdelay` |
| `+0x08` | `disableroutinelytakingaction` |
| `+0x0C` | option `1` |
| `+0x10` | option `2` |
| `+0x14` | option `4` |
| `+0x18` | option `5` |

```text
engine trace : kind=0x52 (remediation config) caller=+0x953737 detail=delay=0 maxdelay=0 disable=0 opt1=0 opt2=0 opt4=0 opt5=0
```

A stub host returns zeros, which is why the engine keeps its defaults.

## `0x13` / `0x15` — forwarded notifications

`FUN_1804B6FB0` takes the caller's own record (`{u32 kind; u32 flags; ...;
void *payload}`), stamps the engine clock into `+0x08` and forwards it.  The
kind therefore comes from the caller, and `0x13`/`0x15` were observed from
`FUN_1807AD920` / `FUN_1807AFE80`.  Only the first four qwords of the payload
are rendered; the tail depends on the notification type.

## Caller RVAs seen

| Kind | Caller RVA | Function |
|---|---|---|
| `0x13`/`0x15` | `+0x4B7074` | `FUN_1804B6FB0` |
| `0x18` process memory scan | `+0x4A73A6` | `FUN_1804A7280` |
| `0x1C` / `0x38` MOAC | `+0x295D96` | `FUN_180295C60` |
| `0x1F` MOAC v2 | `+0x465D15` | `FUN_180465C08` |
| `0x22` host read | `+0x2886A7` | `FUN_1802885FC` |
| `0x23` host write | `+0x4F34D0` | `FUN_1804F340C` |
| `0x25` scan stage | `+0x7746CC` | `FUN_180774664` |
| `0x28` deferred scan | `+0x9F9F01` | `FUN_1809F9C0C` |
| `0x28` other work (opcode 8) | `+0x3D70A4` | see caller in Ghidra |
| `0x28` other work (opcode 0x0A) | `+0x943FB3` | see caller in Ghidra |
| `0x2A` notification | `+0x3D5653` | `FUN_1803D54B0` |
| `0x37` MOAC entry | `+0x4C7471` | `FUN_1804C715C` |
| `0x37` MOAC entry (alt) | `+0x297AA7` | `FUN_1802978CC` |
| `0x3D` host config | `+0x4873AC` | `FUN_180487280` |
| `0x3E` host release | `+0x4AAB5C` | `FUN_1804AAAD8` |
| `0x3F` raw record | `+0x7A16FB` | `FUN_1807A1654` |
| `0x44` RTP update | `+0x348EFD` | `FUN_180348D5C` |
| `0x52` remediation | `+0x953737` | `FUN_1809536BC` |

## Decoding a new kind

1. Find the record in `engine-*.log` and read `caller=+0x...`.
2. Decompile `mpengine.dll` at `0x180000000 + RVA` in Ghidra.  The emitter
   builds the record right before the indirect call
   `(*callback)(&record)`; the assignments to the locals passed as
   `record+0x10` describe the payload.
3. Add a `#define RSI_ENGINE_KIND_...` and a decoder in `MpEngineHook.c`,
   plus a label in `RSignalEtwListener.cpp`.
