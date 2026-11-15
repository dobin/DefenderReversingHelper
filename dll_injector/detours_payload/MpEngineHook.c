/*
 * MpEngineHook.c -- Detours payload for mpengine.dll.
 *
 * This DLL is meant to be injected into a process that already has (or will
 * load) mpengine.dll, normally MsMpEng.exe. It installs a Microsoft Detours
 * inline hook on the exported __rsignal function from a worker thread, so the
 * loader lock is not held while Detours patches code.
 *
 * Target:
 *
 *     ULONG __rsignal(PVOID Context, int Signal, PVOID Data, int Flags)
 *
 * Every call is reported as ETW/TraceLogging events from the provider defined
 * in shared\MpEngineEtw.h. Nothing is written to disk by this DLL; a separate
 * process (tools\etw_listener) subscribes to the provider and renders the
 * events. Each call produces:
 *
 *     RSignalCall    all four arguments, a hex copy of the Context buffer
 *                    (RSI_CONTEXT_DUMP_BYTES) and of the Data buffer
 *                    (RSI_DATA_DUMP_BYTES), captured before the real function
 *                    runs so the payload is exactly what mpengine received
 *     RSignalReturn  the return value
 *     Status         install/diagnostic messages ("payload attached", errors)
 *
 * The same DLL also captures the engine's own log lines ("Engine: ...",
 * "Engine-HIPS: ...").  Those are not WPP: mpengine formats them and calls a
 * trace callback stored on the process-wide engine instance, and MpSvc
 * installs that callback.  Hook_EngineTrace replaces the callback and forwards
 * to the previous value, so Defender keeps behaving exactly as before.  Each
 * line travels as an EngineLog event (see the "Engine log capture" section
 * below for the layout).
 *
 * MpSvc unloads and reloads mpengine.dll in place (engine refresh/idle unload)
 * and can remap it at a different base, which drops the inline patch and
 * replaces the engine instance.  HookMaintenanceThread therefore re-resolves
 * the module every 250 ms, re-attaches the detour when the original prologue is
 * back, and re-arms the trace slot on the current instance.
 *
 * When no ETW session has the provider enabled, TraceLoggingWrite is a cheap
 * no-op and the buffers are not even read.
 *
 * Build output: bin\<Configuration>\mpengine_hook.dll
 *
 * Injecting into MsMpEng.exe requires the MakeMePPL driver:
 *
 *     injector.exe MsMpEng.exe bin\Release\mpengine_hook.dll ^
 *         --ppl --allow-dynamic-code --fix-handle --kernel-thread --restore
 *
 * Detours needs to change the protection of mpengine's code pages. If the
 * target also enables Arbitrary Code Guard (ProcessDynamicCodePolicy), the
 * commit fails. Pass --allow-dynamic-code so the injector clears ACG first.
 */

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <intrin.h>
#include <evntrace.h>
#include <TraceLoggingProvider.h>

#pragma warning(push)
#pragma warning(disable: 4201) /* Detours uses a nameless struct/union. */
#include "detours.h"
#pragma warning(pop)

#include "MpEngineEtw.h"

#define MPENGINE_DLL_NAME   "mpengine.dll"
#define MPENGINE_DLL_WNAME  L"mpengine.dll"

/*
 * The function to hook. It is a compile-time choice because the hook needs a
 * matching prototype. Override it with a project-wide preprocessor definition
 * only together with the matching typedef/hook below.
 */
#ifndef MPENGINE_HOOK_EXPORT
#define MPENGINE_HOOK_EXPORT "__rsignal"
#endif

#ifndef MPENGINE_MODULE_WAIT_MS
#define MPENGINE_MODULE_WAIT_MS 30000
#endif

/* How much memory to copy behind each pointer into the ETW event. */
#ifndef RSI_CONTEXT_DUMP_BYTES
#define RSI_CONTEXT_DUMP_BYTES 512
#endif
#ifndef RSI_DATA_DUMP_BYTES
#define RSI_DATA_DUMP_BYTES 4096
#endif

#if (RSI_CONTEXT_DUMP_BYTES <= 0) || (RSI_DATA_DUMP_BYTES <= 0)
#error RSI_*_DUMP_BYTES must be greater than zero
#endif

/*
 * The buffers travel as hex text, so each dump byte costs two characters.
 * ETW events are limited to 64 KB; keep both buffers well under that.
 */
#if (RSI_CONTEXT_DUMP_BYTES > 8192) || (RSI_DATA_DUMP_BYTES > 16384)
#error RSI_*_DUMP_BYTES are too large for a single ETW event
#endif

/*
 * RTP note payload capture (signal 0x4039).
 *
 * The 0x38-byte note is an envelope: note+0x30 points at a domain object whose
 * names and properties are further pointers.  The comparison harness needs the
 * content, so this hook walks those pointers with ReadProcessMemory and copies
 * the targets into one self-describing blob.  It does not parse anything: the
 * mpclient comparator is the only decoder.
 *
 * Wire format (must match include/mpengine_signal_capture.h):
 *   u32 magic 'PCTR', u32 version 2, u32 signal id, u32 segment count
 *   per segment: u32 tag, u32 length, u8 bytes[length]
 *
 * Strings are UTF-16LE including the terminator.  Every read is bounded by
 * CopyTargetMemory(), so a bad pointer yields fewer segments, not a fault.
 */
#ifndef RSI_CAPTURE_MAX
#define RSI_CAPTURE_MAX 8192
#endif
#if (RSI_CAPTURE_MAX > 24576) || (RSI_CAPTURE_MAX < 1024)
#error RSI_CAPTURE_MAX is out of range for a single ETW event
#endif

#define RSI_CAPTURE_MAGIC      0x52544350u
#define RSI_CAPTURE_VERSION    2u
#define RSI_CAPTURE_HEADER     16u
#define RSI_CAPTURE_SEGMENT    8u
#define RSI_NOTE_BYTES          0x38
#define RSI_NOTE_STRING_CHARS   512
#define RSI_NOTE_WINDOW         0x100
#define RSI_CAPTURE_ROOT_MAX    0x100

#define RSI_TAG_ROOT          0u
#define RSI_TAG_OBJECT        1u
#define RSI_TAG_NAME1         2u
#define RSI_TAG_NAME2         3u
#define RSI_TAG_KEY_NAME      4u
#define RSI_TAG_VALUE_NAME    5u
#define RSI_TAG_IMAGE         6u
#define RSI_TAG_CMDLINE       7u
#define RSI_TAG_PROCESS_KEY   8u
#define RSI_TAG_NET_BLOB      9u
#define RSI_TAG_SOURCE       10u
#define RSI_TAG_TARGET       11u
#define RSI_TAG_ETW_PROP     12u
#define RSI_TAG_STRING       13u
#define RSI_TAG_BLOB         14u

#define RSI_CAPTURE_MODE_ROOT_ONLY 0u
#define RSI_CAPTURE_MODE_FIELDS    1u
#define RSI_CAPTURE_MODE_RTP_NOTE  2u

#define RSI_FILE_CLOSE        0x080u
#define RSI_FILE_CREATE       0x100u
#define RSI_FILE_OPEN         0x200u
#define RSI_FILE_WRITE        0x400u

typedef struct RSI_CAPTURE {
    BYTE  *Buffer;
    SIZE_T Capacity;
    SIZE_T Used;
    UINT32 Count;
    UINT32 SignalId;
} RSI_CAPTURE;

/* Mirror of the mpclient rule table in
 * src/engine/mpengine_signal_capture.c.  Keep both in sync. */
typedef struct RSI_CAPTURE_RULE {
    int    Signal;
    UINT16 RootBytes;
    UINT16 Budget;
    UINT8  Mode;
    UINT16 FieldOffset;   /* MODE_FIELDS: string pointer offset */
    UINT16 FieldTag;
} RSI_CAPTURE_RULE;

static const RSI_CAPTURE_RULE g_CaptureRules[] = {
    { 0x4039, 0x38, 8192, RSI_CAPTURE_MODE_RTP_NOTE, 0, 0 },
    { 0x4051, 0x18, 2048, RSI_CAPTURE_MODE_FIELDS,  0x08, RSI_TAG_STRING },
    { 0x4095, 0x20, 256,  RSI_CAPTURE_MODE_ROOT_ONLY, 0, 0 }
};

/* detours.h only defines this internally; it is a normal Win32 error code. */
#ifndef ERROR_DYNAMIC_CODE_BLOCKED
#define ERROR_DYNAMIC_CODE_BLOCKED 1655L
#endif

/*
 * __rsignal has four arguments on x64:
 *   RCX = Context (in rsignal this is &DAT_18111e018)
 *   EDX = Signal/event code (0x400a, 0x4019, 0x401c, ...)
 *   R8  = Data pointer (meaning depends on the signal code)
 *   R9D = Flags/size (used as a length in some branches)
 *
 * The decompiled return values are 32-bit status codes (0, 0x800e, 0x9003...).
 */
typedef ULONG (WINAPI *PFN___rsignal)(
    PVOID Context,
    int Signal,
    PVOID Data,
    int Flags);

TRACELOGGING_DEFINE_PROVIDER(
    g_hRSignalProvider,
    MPENGINE_ETW_PROVIDER_NAME,
    MPENGINE_ETW_PROVIDER_GUID);

static PFN___rsignal g_Real__rsignal = NULL;
static volatile LONG g_HookCalls = 0;
static volatile LONG g_ProviderRegistered = 0;
static __declspec(thread) LONG g_InHook = 0;

/* ------------------------------------------------------------------------- */
/* ETW                                                                       */
/* ------------------------------------------------------------------------- */

/*
 * Status events carry human-readable install/diagnostic messages. The level
 * must be a compile-time constant (TraceLoggingWrite turns it into an enum),
 * hence the two wrappers.
 */
static void
EmitStatusInfo(
    _In_ ULONG Code,
    _In_ const char* Message)
{
    if (!g_ProviderRegistered) {
        return;
    }

    TraceLoggingWrite(
        g_hRSignalProvider,
        MPENGINE_ETW_EVENT_STATUS,
        TraceLoggingLevel(TRACE_LEVEL_INFORMATION),
        TraceLoggingUInt32(MPENGINE_ETW_TYPE_STATUS, "Type"),
        TraceLoggingUInt32(0, "SeqNum"),
        TraceLoggingUInt32(Code, "Code"),
        TraceLoggingString(Message, "Message"));
}

static void
EmitStatusError(
    _In_ ULONG Code,
    _In_ const char* Message)
{
    if (!g_ProviderRegistered) {
        return;
    }

    TraceLoggingWrite(
        g_hRSignalProvider,
        MPENGINE_ETW_EVENT_STATUS,
        TraceLoggingLevel(TRACE_LEVEL_ERROR),
        TraceLoggingUInt32(MPENGINE_ETW_TYPE_STATUS, "Type"),
        TraceLoggingUInt32(0, "SeqNum"),
        TraceLoggingUInt32(Code, "Code"),
        TraceLoggingString(Message, "Message"));
}

static void
EmitStatusInfoV(
    _In_ ULONG Code,
    _In_ const char* Format,
    ...)
{
    char message[1024];
    va_list arguments;

    va_start(arguments, Format);
    _vsnprintf_s(message, sizeof(message), _TRUNCATE, Format, arguments);
    va_end(arguments);

    EmitStatusInfo(Code, message);
}

static void
EmitStatusErrorV(
    _In_ ULONG Code,
    _In_ const char* Format,
    ...)
{
    char message[1024];
    va_list arguments;

    va_start(arguments, Format);
    _vsnprintf_s(message, sizeof(message), _TRUNCATE, Format, arguments);
    va_end(arguments);

    EmitStatusError(Code, message);
}

/*
 * Optional stage log for diagnosing a payload that loads but never emits.
 * Disabled by default: the released payload writes nothing to disk.
 */
#ifndef RSI_DIAG_LOG
#define RSI_DIAG_LOG 0
#endif

#if RSI_DIAG_LOG
static void
DiagLog(
    _In_ const char* Format,
    ...)
{
    char    path[MAX_PATH];
    char    message[512];
    HANDLE  file;
    DWORD   written = 0;
    va_list arguments;

    _snprintf_s(path, sizeof(path), _TRUNCATE,
                "C:\\data\\mpengine_hook_%lu.log",
                (unsigned long)GetCurrentProcessId());
    file = CreateFileA(path, FILE_APPEND_DATA,
                       FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                       OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE) {
        return;
    }

    va_start(arguments, Format);
    _vsnprintf_s(message, sizeof(message), _TRUNCATE, Format, arguments);
    va_end(arguments);

    (void)WriteFile(file, message, (DWORD)strlen(message), &written, NULL);
    (void)WriteFile(file, "\r\n", 2, &written, NULL);
    CloseHandle(file);
}
#else
#define DiagLog(...) ((void)0)
#endif

/*
 * Copy up to Capacity bytes from Address into Buffer. Reads only the part of
 * the request that lies inside one committed, non-guard region, so a pointer
 * near the end of a page does not make ReadProcessMemory fail as a whole.
 * Returns the number of bytes actually copied.
 */
static SIZE_T
CopyTargetMemory(
    _In_ const void* Address,
    _Out_writes_bytes_(Capacity) void* Buffer,
    _In_ SIZE_T Capacity)
{
    MEMORY_BASIC_INFORMATION memoryInfo;
    SIZE_T available;
    SIZE_T read = 0;

    if (Address == NULL || Capacity == 0) {
        return 0;
    }

    if (VirtualQuery(Address, &memoryInfo, sizeof(memoryInfo)) == 0 ||
        memoryInfo.State != MEM_COMMIT ||
        (memoryInfo.Protect & (PAGE_NOACCESS | PAGE_GUARD)) != 0) {
        return 0;
    }

    available = (SIZE_T)((const BYTE*)memoryInfo.BaseAddress +
                         memoryInfo.RegionSize -
                         (const BYTE*)Address);
    if (Capacity > available) {
        Capacity = available;
    }
    if (Capacity == 0) {
        return 0;
    }

    if (!ReadProcessMemory(GetCurrentProcess(), Address, Buffer, Capacity, &read)) {
        /* Keep whatever prefix ReadProcessMemory managed to copy. */
    }

    return read;
}

/*
 * The buffers are sent as hex text instead of TraceLoggingBinary. TraceLogging
 * binary fields are length-prefixed, and how much of that prefix a consumer
 * sees depends on its TDH usage; hex strings decode identically everywhere
 * (krabsetw, WPA, xperf) and stay well below the 64 KB ETW event limit.
 */
static void
BytesToHex(
    _In_reads_bytes_(Length) const BYTE* Bytes,
    _In_ SIZE_T Length,
    _Out_writes_z_(Length * 2 + 1) char* Hex)
{
    static const char digits[] = "0123456789ABCDEF";
    SIZE_T i;

    for (i = 0; i < Length; ++i) {
        Hex[i * 2] = digits[Bytes[i] >> 4];
        Hex[i * 2 + 1] = digits[Bytes[i] & 0x0F];
    }
    Hex[Length * 2] = '\0';
}

/* ------------------------------------------------------------------------- */
/* Note payload capture (signal 0x4039)                                      */
/* ------------------------------------------------------------------------- */

static BOOL
CaptureSegment(
    _Inout_ RSI_CAPTURE* Capture,
    _In_ UINT32 Tag,
    _In_reads_bytes_(Length) const void* Data,
    _In_ UINT32 Length)
{
    BYTE header[8];
    SIZE_T need;

    if (Data == NULL || Length == 0) {
        return FALSE;
    }
    need = sizeof(header) + (SIZE_T)Length;
    if (Capture->Used + need > Capture->Capacity) {
        return FALSE;
    }
    header[0] = (BYTE)(Tag & 0xFF);
    header[1] = (BYTE)((Tag >> 8) & 0xFF);
    header[2] = (BYTE)((Tag >> 16) & 0xFF);
    header[3] = (BYTE)((Tag >> 24) & 0xFF);
    header[4] = (BYTE)(Length & 0xFF);
    header[5] = (BYTE)((Length >> 8) & 0xFF);
    header[6] = (BYTE)((Length >> 16) & 0xFF);
    header[7] = (BYTE)((Length >> 24) & 0xFF);
    memcpy(Capture->Buffer + Capture->Used, header, sizeof(header));
    Capture->Used += sizeof(header);
    memcpy(Capture->Buffer + Capture->Used, Data, Length);
    Capture->Used += Length;
    Capture->Count++;
    return TRUE;
}

/* Read one pointer-sized value out of a structure we already copied. */
static BOOL
CapturePointer(
    _In_reads_bytes_(Length) const BYTE* Data,
    _In_ UINT32 Length,
    _In_ UINT32 Offset,
    _Out_ PVOID* Value)
{
    if (Offset + sizeof(PVOID) > Length) {
        return FALSE;
    }
    memcpy(Value, Data + Offset, sizeof(*Value));
    return *Value != NULL;
}

static BOOL
CaptureWString(
    _Inout_ RSI_CAPTURE* Capture,
    _In_ UINT32 Tag,
    _In_ const wchar_t* Text)
{
    wchar_t buffer[RSI_NOTE_STRING_CHARS];
    SIZE_T read;
    SIZE_T chars;
    SIZE_T length = 0;

    if (Text == NULL) {
        return FALSE;
    }
    read = CopyTargetMemory(Text, buffer, sizeof(buffer));
    chars = read / sizeof(wchar_t);
    if (chars == 0) {
        return FALSE;
    }
    while (length < chars && buffer[length] != L'\0') {
        length++;
    }
    if (length == 0) {
        return FALSE;
    }
    if (length >= RSI_NOTE_STRING_CHARS) {
        length = RSI_NOTE_STRING_CHARS - 1;
    }
    buffer[length] = L'\0';
    return CaptureSegment(Capture, Tag, buffer,
                          (UINT32)((length + 1) * sizeof(wchar_t)));
}

/* payload+offset -> name object -> +0x08 descriptor -> +0x08 string. */
static BOOL
CaptureNameObject(
    _Inout_ RSI_CAPTURE* Capture,
    _In_ UINT32 Tag,
    _In_reads_bytes_(Length) const BYTE* Payload,
    _In_ UINT32 Length,
    _In_ UINT32 Offset)
{
    PVOID  nameObject = NULL;
    PVOID  descriptor = NULL;
    PVOID  text = NULL;
    UINT32 type = 0;

    if (!CapturePointer(Payload, Length, Offset, &nameObject)) {
        return FALSE;
    }
    if (CopyTargetMemory((const BYTE*)nameObject + 0x08, &descriptor,
                         sizeof(descriptor)) != sizeof(descriptor) ||
        descriptor == NULL) {
        return FALSE;
    }
    if (CopyTargetMemory(descriptor, &type, sizeof(type)) != sizeof(type) ||
        type != 1) {
        return FALSE;
    }
    if (CopyTargetMemory((const BYTE*)descriptor + 0x08, &text,
                         sizeof(text)) != sizeof(text) ||
        text == NULL) {
        return FALSE;
    }
    return CaptureWString(Capture, Tag, (const wchar_t*)text);
}

/* Property array: type at +0x00, entries at +0x08, u16 count at +0x10.
 * Entries are 0x10 bytes; key 1 is a wchar_t* and key 10 is a 16-byte
 * {u64 create time, u32 pid} object. */
static void
CapturePropArray(
    _Inout_ RSI_CAPTURE* Capture,
    _In_ const BYTE* Array,
    _In_ UINT32 ImageTag,
    _In_ UINT32 KeyTag)
{
    PVOID  entries = NULL;
    UINT16 count = 0;
    UINT32 i;

    if (Array == NULL) {
        return;
    }
    if (CopyTargetMemory(Array + 0x08, &entries, sizeof(entries)) !=
            sizeof(entries) ||
        entries == NULL ||
        CopyTargetMemory(Array + 0x10, &count, sizeof(count)) !=
            sizeof(count)) {
        return;
    }
    if (count > 16) {
        count = 16;
    }
    for (i = 0; i < count; ++i) {
        const BYTE* entry = (const BYTE*)entries + (SIZE_T)i * 0x10;
        UINT32 key = 0;
        PVOID  value = NULL;

        if (CopyTargetMemory(entry, &key, sizeof(key)) != sizeof(key) ||
            CopyTargetMemory(entry + 0x08, &value, sizeof(value)) !=
                sizeof(value) ||
            value == NULL) {
            continue;
        }
        if (key == 1) {
            (void)CaptureWString(Capture, ImageTag,
                                 (const wchar_t*)value);
        } else if (key == 10) {
            BYTE bytes[16];

            if (CopyTargetMemory(value, bytes, sizeof(bytes)) ==
                sizeof(bytes)) {
                (void)CaptureSegment(Capture, KeyTag, bytes,
                                     (UINT32)sizeof(bytes));
            }
        }
    }
}

static void
CaptureFile(
    _Inout_ RSI_CAPTURE* Capture,
    _In_reads_bytes_(Length) const BYTE* Payload,
    _In_ UINT32 Length,
    _In_ UINT32 EventId)
{
    if (EventId == RSI_FILE_CLOSE || EventId == RSI_FILE_CREATE ||
        EventId == RSI_FILE_OPEN || EventId == RSI_FILE_WRITE) {
        (void)CaptureNameObject(Capture, RSI_TAG_NAME1, Payload, Length, 0x08);
    } else {
        (void)CaptureNameObject(Capture, RSI_TAG_NAME1, Payload, Length, 0x00);
        (void)CaptureNameObject(Capture, RSI_TAG_NAME2, Payload, Length, 0x08);
    }
}

static void
CaptureProcess(
    _Inout_ RSI_CAPTURE* Capture,
    _In_reads_bytes_(Length) const BYTE* Payload,
    _In_ UINT32 Length)
{
    PVOID  props = NULL;
    PVOID  props2 = NULL;
    UINT32 flags = 0;

    if (CapturePointer(Payload, Length, 0x10, &props)) {
        CapturePropArray(Capture, (const BYTE*)props, RSI_TAG_IMAGE,
                         RSI_TAG_PROCESS_KEY);
    }
    if (Length >= 0x0C) {
        memcpy(&flags, Payload + 0x08, sizeof(flags));
        if ((flags >> 24) >= 2 &&
            CapturePointer(Payload, Length, 0x18, &props2)) {
            CapturePropArray(Capture, (const BYTE*)props2, RSI_TAG_CMDLINE,
                             RSI_TAG_PROCESS_KEY);
        }
    }
}

static void
CaptureRegistry(
    _Inout_ RSI_CAPTURE* Capture,
    _In_reads_bytes_(Length) const BYTE* Payload,
    _In_ UINT32 Length)
{
    PVOID keyName = NULL;
    PVOID valueName = NULL;

    if (CapturePointer(Payload, Length, 0x08, &keyName)) {
        (void)CaptureWString(Capture, RSI_TAG_KEY_NAME,
                             (const wchar_t*)keyName);
    }
    if (CapturePointer(Payload, Length, 0x18, &valueName)) {
        (void)CaptureWString(Capture, RSI_TAG_VALUE_NAME,
                             (const wchar_t*)valueName);
    }
}

static void
CaptureNetwork(
    _Inout_ RSI_CAPTURE* Capture,
    _In_reads_bytes_(Length) const BYTE* Payload,
    _In_ UINT32 Length)
{
    PVOID  blob = NULL;
    UINT32 blobLength = 0;
    BYTE   bytes[64];

    if (!CapturePointer(Payload, Length, 0x08, &blob) || Length < 0x14) {
        return;
    }
    memcpy(&blobLength, Payload + 0x10, sizeof(blobLength));
    if (blobLength == 0) {
        return;
    }
    if (blobLength > sizeof(bytes)) {
        blobLength = (UINT32)sizeof(bytes);
    }
    if (CopyTargetMemory(blob, bytes, blobLength) == blobLength) {
        (void)CaptureSegment(Capture, RSI_TAG_NET_BLOB, bytes, blobLength);
    }
}

static void
CaptureEtw(
    _Inout_ RSI_CAPTURE* Capture,
    _In_reads_bytes_(Length) const BYTE* Payload,
    _In_ UINT32 Length)
{
    PVOID  source = NULL;
    PVOID  target = NULL;
    PVOID  props = NULL;
    UINT32 propCount = 0;
    UINT32 i;

    if (CapturePointer(Payload, Length, 0x08, &source)) {
        (void)CaptureWString(Capture, RSI_TAG_SOURCE,
                             (const wchar_t*)source);
    }
    if (CapturePointer(Payload, Length, 0x10, &target)) {
        (void)CaptureWString(Capture, RSI_TAG_TARGET,
                             (const wchar_t*)target);
    }
    if (!CapturePointer(Payload, Length, 0x18, &props) || Length < 0x24) {
        return;
    }
    memcpy(&propCount, Payload + 0x20, sizeof(propCount));
    if (propCount == 0) {
        return;
    }
    if (propCount > 8) {
        propCount = 8;
    }
    for (i = 0; i < propCount; ++i) {
        const BYTE* entry = (const BYTE*)props + (SIZE_T)i * 0x20;
        PVOID  name = NULL;
        PVOID  value = NULL;
        PVOID  type = NULL;
        wchar_t packed[RSI_NOTE_STRING_CHARS * 3];
        UINT32 length = 0;
        UINT32 part;

        if (CopyTargetMemory(entry, &name, sizeof(name)) != sizeof(name) ||
            CopyTargetMemory(entry + 0x08, &value, sizeof(value)) !=
                sizeof(value) ||
            CopyTargetMemory(entry + 0x10, &type, sizeof(type)) !=
                sizeof(type)) {
            continue;
        }
        if (name == NULL || value == NULL) {
            continue;
        }
        for (part = 0; part < 3; ++part) {
            const wchar_t* text = NULL;
            wchar_t local[RSI_NOTE_STRING_CHARS];
            SIZE_T read;
            SIZE_T chars;
            SIZE_T used = 0;
            SIZE_T avail;

            if (part == 0) {
                text = (const wchar_t*)name;
            } else if (part == 1) {
                text = (const wchar_t*)value;
            } else {
                text = (const wchar_t*)type;
            }
            if (text == NULL) {
                if (length + 1 < sizeof(packed) / sizeof(packed[0])) {
                    packed[length++] = L'\0';
                }
                continue;
            }
            read = CopyTargetMemory(text, local, sizeof(local));
            chars = read / sizeof(wchar_t);
            avail = RSI_NOTE_STRING_CHARS - 1;
            if (length + avail + 1 >=
                sizeof(packed) / sizeof(packed[0])) {
                avail = sizeof(packed) / sizeof(packed[0]) - length - 1;
            }
            while (used < chars && used < avail && local[used] != L'\0') {
                packed[length++] = local[used++];
            }
            if (length < sizeof(packed) / sizeof(packed[0])) {
                packed[length++] = L'\0';
            }
        }
        (void)CaptureSegment(Capture, RSI_TAG_ETW_PROP, packed,
                             length * (UINT32)sizeof(wchar_t));
    }
}

static void
CaptureInit(
    _Out_ RSI_CAPTURE* Capture,
    _In_ UINT32 SignalId,
    _Out_writes_bytes_(Capacity) BYTE* Buffer,
    _In_ SIZE_T Capacity)
{
    Capture->Buffer = Buffer;
    Capture->Capacity = Capacity;
    Capture->Used = RSI_CAPTURE_HEADER;
    Capture->Count = 0;
    Capture->SignalId = SignalId;
}

static SIZE_T
CaptureFinish(
    _Inout_ RSI_CAPTURE* Capture)
{
    if (Capture->Buffer == NULL || Capture->Count == 0) {
        return 0;
    }
    ((UINT32*)Capture->Buffer)[0] = RSI_CAPTURE_MAGIC;
    ((UINT32*)Capture->Buffer)[1] = RSI_CAPTURE_VERSION;
    ((UINT32*)Capture->Buffer)[2] = Capture->SignalId;
    ((UINT32*)Capture->Buffer)[3] = Capture->Count;
    return Capture->Used;
}

/*
 * Copy the domain object behind a 0x38 note.  The caller already copied the
 * note itself as RSI_TAG_ROOT.
 */
static void
CaptureRtpPayload(
    _Inout_ RSI_CAPTURE* Capture,
    _In_reads_bytes_(NoteBytes) const BYTE* Note,
    _In_ UINT32 NoteBytes)
{
    BYTE   payload[RSI_NOTE_WINDOW];
    UINT32 domain = 0;
    UINT32 eventId = 0;
    PVOID  payloadPointer = NULL;
    UINT32 window;

    if (NoteBytes < RSI_NOTE_BYTES) {
        return;
    }
    memcpy(&domain, Note + 0x08, sizeof(domain));
    memcpy(&eventId, Note + 0x18, sizeof(eventId));
    memcpy(&payloadPointer, Note + 0x30, sizeof(payloadPointer));
    if (payloadPointer == NULL) {
        return;
    }

    ZeroMemory(payload, sizeof(payload));
    window = (domain == 1) ? RSI_NOTE_WINDOW : 0x40;
    window = (UINT32)CopyTargetMemory(payloadPointer, payload, window);
    if (window == 0) {
        return;
    }
    (void)CaptureSegment(Capture, RSI_TAG_OBJECT, payload, window);

    switch (domain) {
    case 1:
        CaptureFile(Capture, payload, window, eventId);
        break;
    case 2:
        CaptureProcess(Capture, payload, window);
        break;
    case 0:
        CaptureRegistry(Capture, payload, window);
        break;
    case 4:
        CaptureNetwork(Capture, payload, window);
        break;
    case 9:
        CaptureEtw(Capture, payload, window);
        break;
    default:
        break;
    }
}

/*
 * Serialize one signal request.  The rule table is the copy plan; this is a
 * copy, not a parser.
 */
static SIZE_T
CaptureSignal(
    _In_ int Signal,
    _In_ PVOID Data,
    _In_ int Flags,
    _Out_writes_bytes_(Capacity) BYTE* Buffer,
    _In_ SIZE_T Capacity)
{
    BYTE root[RSI_CAPTURE_ROOT_MAX];
    RSI_CAPTURE capture;
    const RSI_CAPTURE_RULE* rule = NULL;
    UINT32 rootBytes;
    SIZE_T i;

    (void)Flags;

    if (Data == NULL || Buffer == NULL ||
        Capacity < RSI_CAPTURE_HEADER) {
        return 0;
    }
    for (i = 0; i < sizeof(g_CaptureRules) / sizeof(g_CaptureRules[0]); i++) {
        if (g_CaptureRules[i].Signal == Signal) {
            rule = &g_CaptureRules[i];
            break;
        }
    }
    if (rule == NULL) {
        return 0;
    }
    if (Capacity > rule->Budget) {
        Capacity = rule->Budget;
    }

    CaptureInit(&capture, (UINT32)Signal, Buffer, Capacity);

    rootBytes = rule->RootBytes;
    if (rootBytes > sizeof(root)) {
        rootBytes = (UINT32)sizeof(root);
    }
    rootBytes = (UINT32)CopyTargetMemory(Data, root, rootBytes);
    if (rootBytes == 0) {
        return 0;
    }
    (void)CaptureSegment(&capture, RSI_TAG_ROOT, root, rootBytes);

    if (rule->Mode == RSI_CAPTURE_MODE_RTP_NOTE) {
        CaptureRtpPayload(&capture, root, rootBytes);
    } else if (rule->Mode == RSI_CAPTURE_MODE_FIELDS) {
        PVOID pointer = NULL;

        if (rule->FieldOffset + sizeof(pointer) <= rootBytes &&
            CopyTargetMemory(root + rule->FieldOffset, &pointer,
                             sizeof(pointer)) == sizeof(pointer) &&
            pointer != NULL) {
            (void)CaptureWString(&capture, rule->FieldTag,
                                 (const wchar_t*)pointer);
        }
    }
    return CaptureFinish(&capture);
}

static void
EmitCall(
    _In_ PVOID Context,
    _In_ int Signal,
    _In_ PVOID Data,
    _In_ int Flags,
    _In_ LONG Sequence)
{
    BYTE contextBytes[RSI_CONTEXT_DUMP_BYTES];
    BYTE dataBytes[RSI_DATA_DUMP_BYTES];
    BYTE *captureBytes = NULL;
    char contextHex[RSI_CONTEXT_DUMP_BYTES * 2 + 1];
    char dataHex[RSI_DATA_DUMP_BYTES * 2 + 1];
    char *captureHex = NULL;
    SIZE_T contextLength;
    SIZE_T dataLength;
    SIZE_T captureLength = 0;

    /*
     * Copy before calling the real function: Data may point to a transient
     * structure that the handler releases or rewrites.
     */
    contextLength = CopyTargetMemory(Context, contextBytes, sizeof(contextBytes));
    dataLength = CopyTargetMemory(Data, dataBytes, sizeof(dataBytes));

    BytesToHex(contextBytes, contextLength, contextHex);
    BytesToHex(dataBytes, dataLength, dataHex);

    /*
     * Capture the request targets selected by the rule table (note payload,
     * exclusion path, flat blocks).  Nothing is decoded here; the mpclient
     * decoder interprets the blob.
     *
     * The buffers are heap allocated: two 8 KiB/16 KiB arrays on an engine
     * worker thread stack are not worth the risk.
     */
    captureHex = (char*)malloc(RSI_CAPTURE_MAX * 2 + 1);
    if (captureHex != NULL) {
        captureHex[0] = '\0';
        captureBytes = (BYTE*)malloc(RSI_CAPTURE_MAX);
        if (captureBytes != NULL) {
            captureLength = CaptureSignal(Signal, Data, Flags, captureBytes,
                                          RSI_CAPTURE_MAX);
            if (captureLength != 0) {
                BytesToHex(captureBytes, captureLength, captureHex);
            }
        }
    }

    TraceLoggingWrite(
        g_hRSignalProvider,
        MPENGINE_ETW_EVENT_CALL,
        TraceLoggingLevel(TRACE_LEVEL_INFORMATION),
        TraceLoggingUInt32(MPENGINE_ETW_TYPE_CALL, "Type"),
        TraceLoggingUInt32((UINT32)Sequence, "SeqNum"),
        TraceLoggingInt32(Signal, "Signal"),
        TraceLoggingInt32(Flags, "Flags"),
        TraceLoggingUInt64((UINT64)(ULONG_PTR)Context, "ContextAddress"),
        TraceLoggingUInt64((UINT64)(ULONG_PTR)Data, "DataAddress"),
        TraceLoggingUInt32((UINT32)contextLength, "ContextLength"),
        TraceLoggingUInt32((UINT32)dataLength, "DataLength"),
        TraceLoggingString(contextHex, "ContextHex"),
        TraceLoggingString(dataHex, "DataHex"),
        TraceLoggingString(captureHex != NULL ? captureHex : "", "CaptureHex"));

    free(captureBytes);
    free(captureHex);
}

static void
EmitReturn(
    _In_ LONG Sequence,
    _In_ ULONG Status)
{
    TraceLoggingWrite(
        g_hRSignalProvider,
        MPENGINE_ETW_EVENT_RETURN,
        TraceLoggingLevel(TRACE_LEVEL_INFORMATION),
        TraceLoggingUInt32(MPENGINE_ETW_TYPE_RETURN, "Type"),
        TraceLoggingUInt32((UINT32)Sequence, "SeqNum"),
        TraceLoggingUInt32(Status, "Status"));
}

/* ------------------------------------------------------------------------- */
/* Engine log capture (engine trace callback)                                */
/* ------------------------------------------------------------------------- */

/*
 * mpengine has two independent diagnostic paths:
 *
 *   WPP / advapi32!TraceMessage   high-volume debug trace.  Every call site
 *                                 is gated on flags in the WPP control block,
 *                                 so nothing is produced unless an ETW
 *                                 session enables it, and the message text
 *                                 lives in a TMF that is not shipped.
 *
 *   engine trace callback         the engine log lines Defender writes to
 *                                 MPLog ("Engine: ...", "Engine-HIPS: ...").
 *                                 Text is formatted in memory, so it can be
 *                                 captured without any ETW enablement.
 *
 * Every text line is formatted inside mpengine (EngineLog ->
 * FUN_180335738 -> FUN_180335884) and handed to a callback stored on the
 * process-wide engine instance.  MpSvc installs that callback, so replacing
 * it and forwarding to the previous value observes the lines without changing
 * engine behaviour.
 *
 * Instance layout, mpengine 1.1.26100.4 (re-check per engine build):
 *
 *   DAT_18111e110                    engine instance global
 *     +0x000  dispatcher             FUN_1802ea820
 *     +0xB00  trace callback         legacy ABI; selector DAT_1810d0738 == 1
 *     +0xB08  trace callback         new ABI (unused in this build)
 *     +0xB10  trace context          stored, not passed to the callback
 *
 * Record handed to the callback:
 *
 *   +0x00  u64 kind                 0x19 = text log
 *   +0x08  u64 timestamp
 *   +0x10  ptr payload
 *
 * kind 0x19 payload:
 *
 *   +0x00  u32 level
 *   +0x08  u64 flags
 *   +0x10  ptr log
 *
 * kind 0x19 log (pointers are engine-owned and valid only during the call):
 *
 *   +0x00  const wchar_t *module    L"Engine", L"Engine-HIPS", ...
 *   +0x08  u32 level
 *   +0x10  u64 bytes                message length in bytes, including NUL
 *   +0x18  const wchar_t *message
 *
 * The engine boots asynchronously, so the slot is polled until the instance
 * appears (and re-taken if the engine reboots and overwrites it).
 */
#define RSI_ENGINE_INSTANCE_RVA     0x111E110u
#define RSI_ENGINE_DISPATCHER_RVA   0x2EA820u
#define RSI_ENGINE_TRACE_ABI_RVA    0x10D0738u
#define RSI_ENGINE_TRACE_FN_LEGACY  0x0B00u
#define RSI_ENGINE_TRACE_FN_NEW     0x0B08u

/*
 * The engine resolves NtReadVirtualMemoryEx once into this module global and
 * calls through the pointer (mpengine 1.1.26100.4; re-check per engine build).
 * It only fills the slot while it is NULL, so the observer has to be in place
 * before the first read.
 */
#ifndef RSI_ENGINE_NTREAD_RVA
#define RSI_ENGINE_NTREAD_RVA       0x1103038u
#endif

#define RSI_ENGINE_RECORD_TIME      0x08u
#define RSI_ENGINE_RECORD_PAYLOAD   0x10u
#define RSI_ENGINE_PAYLOAD_LEVEL    0x00u
#define RSI_ENGINE_PAYLOAD_LOG      0x10u
#define RSI_ENGINE_LOG_MODULE       0x00u
#define RSI_ENGINE_LOG_LENGTH       0x10u
#define RSI_ENGINE_LOG_MESSAGE      0x18u

/*
 * Trace record kinds.  Every kind below was mapped to its mpengine emitter
 * through the CallerRva carried in the EngineTrace event (engine build
 * 1.1.26100.4, sha256 be18e430...e1dbff); see docs/engine_trace_kinds.md.
 */
#define RSI_ENGINE_KIND_NOTIFY       0x13u  /* forwarded notification         */
#define RSI_ENGINE_KIND_NOTIFY_ALT   0x15u  /* forwarded notification (alt)   */
#define RSI_ENGINE_KIND_EVENT        0x18u  /* generic telemetry event        */
#define RSI_ENGINE_KIND_LOG          0x19u  /* Engine: text log               */
#define RSI_ENGINE_KIND_MOAC_ENTRY   0x1Au  /* MOAC entry, 0x50-byte form     */
#define RSI_ENGINE_KIND_MOAC_LEGACY  0x1Cu  /* MOAC lookup, legacy form       */
#define RSI_ENGINE_KIND_MOAC_V2      0x1Fu  /* MOAC v2 attempt result         */
#define RSI_ENGINE_KIND_HOST_READ    0x22u  /* host data read                 */
#define RSI_ENGINE_KIND_HOST_WRITE   0x23u  /* host data write                */
#define RSI_ENGINE_KIND_SCAN_STAGE   0x25u  /* scan stage message             */
#define RSI_ENGINE_KIND_WORK         0x28u  /* host work item                 */
#define RSI_ENGINE_KIND_NOTIFICATION 0x2Au  /* notification record, type 6    */
#define RSI_ENGINE_KIND_MOAC_ENTRY_R 0x37u  /* MOAC entry, 0x40-byte form     */
#define RSI_ENGINE_KIND_MOAC         0x38u  /* MOAC lookup, rich form         */
#define RSI_ENGINE_KIND_HOST_CONFIG  0x3Du  /* host config query (out-buffer) */
#define RSI_ENGINE_KIND_HOST_RELEASE 0x3Eu  /* host config buffer released    */
#define RSI_ENGINE_KIND_RTP_UPDATE   0x44u  /* RTP/iClientInfo state update   */
#define RSI_ENGINE_KIND_REMEDIATION  0x52u  /* remediation configuration      */

/*
 * Kind 0x18 is the generic host telemetry event: the payload starts with a
 * u64 type (1 in every observed emitter) and a pointer to a type-specific
 * structure.  For the EMS scan-report emitter the structure is the scan
 * request args { wchar_t *kind; wchar_t *target; u16 version; u16 id; ... }.
 */
#define RSI_ENGINE_EVENT_PAYLOAD_DATA 0x08u

/*
 * Kind 0x28 is a host work item.  The engine builds it for a deferred scan and
 * calls the same instance callback as the text log:
 *
 *   record  +0x10  ptr payload
 *   payload +0x00  u32 opcode   (0x22 = deferred scan request)
 *           +0x04  u32 flags
 *           +0x08  ptr args
 *   args    +0x00  wchar_t *kind    (L"ems", L"process", ...)
 *           +0x08  wchar_t *target  ("pid:1234", "ppids:{...}")
 *           +0x10  u16 version
 *           +0x12  u16 id          (0x8e for "ems")
 */
#define RSI_ENGINE_WORK_OPCODE_DEFERRED 0x22u
#define RSI_ENGINE_WORK_PAYLOAD_OPCODE  0x00u
#define RSI_ENGINE_WORK_PAYLOAD_FLAGS   0x04u
#define RSI_ENGINE_WORK_PAYLOAD_ARGS    0x08u
#define RSI_ENGINE_WORK_ARGS_KIND       0x00u
#define RSI_ENGINE_WORK_ARGS_TARGET     0x08u
#define RSI_ENGINE_WORK_ARGS_VERSION    0x10u
#define RSI_ENGINE_WORK_ARGS_ID         0x12u

/* Also emit the structured records (scan work items, telemetry). */
#ifndef RSI_ENGINE_CAPTURE_OTHER_KINDS
#define RSI_ENGINE_CAPTURE_OTHER_KINDS 1
#endif

#ifndef RSI_ENGINE_MODULE_CHARS
#define RSI_ENGINE_MODULE_CHARS 96
#endif
#ifndef RSI_ENGINE_MESSAGE_CHARS
#define RSI_ENGINE_MESSAGE_CHARS 1024
#endif
#ifndef RSI_ENGINE_WORK_KIND_CHARS
#define RSI_ENGINE_WORK_KIND_CHARS 64
#endif
#ifndef RSI_ENGINE_WORK_TARGET_CHARS
#define RSI_ENGINE_WORK_TARGET_CHARS 256
#endif
#ifndef RSI_ENGINE_DETAIL_CHARS
#define RSI_ENGINE_DETAIL_CHARS 256
#endif

/* Bounded payload copy attached to unknown/telemetry trace records. */
#ifndef RSI_ENGINE_TRACE_DUMP_BYTES
#define RSI_ENGINE_TRACE_DUMP_BYTES 256
#endif

#define RSI_ENGINE_LOG_POLL_MS 250

/* Maximum number of threads enlisted in one Detours transaction. */
#ifndef MAX_ENLISTED_THREADS
#define MAX_ENLISTED_THREADS 4096
#endif

typedef LONG (WINAPI *PFN_ENGINE_TRACE)(const void* Record);

static PFN_ENGINE_TRACE g_RealEngineTrace = NULL;
static PVOID g_LastEngineInstance = NULL;
static PVOID g_LastArmFailureInstance = NULL;
static PVOID g_EngineModuleBase = NULL;
static volatile LONG g_EngineLogArmed = 0;
static volatile LONG g_EngineLogCalls = 0;
static volatile LONG g_EngineTraceCalls = 0;
static __declspec(thread) LONG g_InEngineLog = 0;

/* Detours state for the maintenance thread: the module can be unmapped and
 * reloaded under us, so the hook is re-installed whenever the target address
 * or its prologue changes. */
static PVOID g_HookedTarget = NULL;
static BYTE  g_HookedPrologue[16];
static BOOL  g_HookedPrologueValid = FALSE;
static ULONGLONG g_NextInstallAttempt = 0;

#ifndef RSI_HOOK_RETRY_MS
#define RSI_HOOK_RETRY_MS 30000
#endif

static DWORD
EnlistProcessThreads(
    _Out_writes_to_(Capacity, return) HANDLE* Handles,
    _In_ DWORD Capacity);

static void
ReleaseThreadHandles(
    _In_reads_(Count) HANDLE* Handles,
    _In_ DWORD Count);

static ULONG WINAPI
Hook___rsignal(
    _In_ PVOID Context,
    _In_ int Signal,
    _In_ PVOID Data,
    _In_ int Flags);

static BOOL
ReadTargetPointer(
    _In_ const void* Address,
    _Out_ PVOID* Value)
{
    *Value = NULL;
    return CopyTargetMemory(Address, Value, sizeof(*Value)) == sizeof(*Value);
}

/*
 * The slot lives in the engine's heap object, which is normally writable, but
 * the protection is restored anyway so the write is never conditional on how
 * the heap allocated the page.
 */
static BOOL
WriteTargetPointer(
    _In_ void* Address,
    _In_ PVOID Value)
{
    DWORD  previousProtect = 0;
    SIZE_T written = 0;
    BOOL   ok;

    if (!VirtualProtect(Address, sizeof(Value), PAGE_READWRITE,
                        &previousProtect)) {
        return FALSE;
    }
    ok = WriteProcessMemory(GetCurrentProcess(), Address, &Value,
                            sizeof(Value), &written) != FALSE &&
         written == sizeof(Value);
    (void)VirtualProtect(Address, sizeof(Value), previousProtect,
                         &previousProtect);
    return ok;
}

/*
 * Copy a NUL-terminated wide string out of engine memory. KnownBytes is the
 * engine's own length for the message (0 when unknown) and bounds the read.
 */
static BOOL
CopyWideString(
    _Out_writes_z_(Chars) wchar_t* Destination,
    _In_ SIZE_T Chars,
    _In_ const wchar_t* Source,
    _In_opt_ UINT64 KnownBytes)
{
    SIZE_T capacity;
    SIZE_T read;
    SIZE_T used;
    SIZE_T i;

    if (Destination == NULL || Chars == 0) {
        return FALSE;
    }
    Destination[0] = L'\0';
    if (Source == NULL) {
        return FALSE;
    }

    capacity = Chars * sizeof(wchar_t);
    if (KnownBytes != 0 && KnownBytes < capacity) {
        capacity = (SIZE_T)KnownBytes;
    }
    read = CopyTargetMemory(Source, Destination, capacity);
    used = read / sizeof(wchar_t);
    if (used == 0) {
        return FALSE;
    }

    for (i = 0; i < used; i++) {
        if (Destination[i] == L'\0') {
            return i != 0;
        }
    }
    Destination[(used < Chars) ? used : Chars - 1] = L'\0';
    return TRUE;
}

static void
EmitEngineLog(
    _In_ UINT32 Kind,
    _In_ UINT32 Level,
    _In_opt_ const wchar_t* Module,
    _In_opt_ const wchar_t* Message)
{
    char moduleUtf8[RSI_ENGINE_MODULE_CHARS * 3 + 1];
    char messageUtf8[RSI_ENGINE_MESSAGE_CHARS * 3 + 1];

    if (!g_ProviderRegistered) {
        return;
    }

    moduleUtf8[0] = '\0';
    messageUtf8[0] = '\0';

    if (Module != NULL && Module[0] != L'\0') {
        if (WideCharToMultiByte(CP_UTF8, 0, Module, -1, moduleUtf8,
                                sizeof(moduleUtf8), NULL, NULL) <= 0) {
            moduleUtf8[0] = '\0';
        }
    }
    if (Message != NULL && Message[0] != L'\0') {
        if (WideCharToMultiByte(CP_UTF8, 0, Message, -1, messageUtf8,
                                sizeof(messageUtf8), NULL, NULL) <= 0) {
            messageUtf8[0] = '\0';
        }
    }

    TraceLoggingWrite(
        g_hRSignalProvider,
        MPENGINE_ETW_EVENT_ENGINE_LOG,
        TraceLoggingLevel(TRACE_LEVEL_INFORMATION),
        TraceLoggingUInt32(MPENGINE_ETW_TYPE_ENGINE_LOG, "Type"),
        TraceLoggingUInt32((UINT32)InterlockedIncrement(&g_EngineLogCalls),
                           "SeqNum"),
        TraceLoggingUInt32(Kind, "Kind"),
        TraceLoggingUInt32(Level, "Level"),
        TraceLoggingString(moduleUtf8, "Module"),
        TraceLoggingString(messageUtf8, "Message"));
}

static void
WideToUtf8(
    _In_opt_ const wchar_t* Text,
    _Out_writes_z_(Capacity) char* Destination,
    _In_ SIZE_T Capacity)
{
    if (Destination == NULL || Capacity == 0) {
        return;
    }
    Destination[0] = '\0';
    if (Text == NULL || Text[0] == L'\0') {
        return;
    }
    if (WideCharToMultiByte(CP_UTF8, 0, Text, -1, Destination,
                            (int)Capacity, NULL, NULL) <= 0) {
        Destination[0] = '\0';
    }
}

static void
FormatGuidText(
    _In_reads_bytes_(16) const BYTE* Bytes,
    _Out_writes_z_(Chars) wchar_t* Text,
    _In_ SIZE_T Chars)
{
    (void)_snwprintf_s(Text, Chars, _TRUNCATE,
                       L"%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X",
                       ((unsigned)Bytes[0] | ((unsigned)Bytes[1] << 8) |
                        ((unsigned)Bytes[2] << 16) |
                        ((unsigned)Bytes[3] << 24)),
                       ((unsigned)Bytes[4] | ((unsigned)Bytes[5] << 8)),
                       ((unsigned)Bytes[6] | ((unsigned)Bytes[7] << 8)),
                       (unsigned)Bytes[8], (unsigned)Bytes[9],
                       (unsigned)Bytes[10], (unsigned)Bytes[11],
                       (unsigned)Bytes[12], (unsigned)Bytes[13],
                       (unsigned)Bytes[14], (unsigned)Bytes[15]);
}

/*
 * Render the qwords at Payload+Offset as "[<slot>]=0x<value> ..." so the common
 * record shape (a small engine structure with 8-byte fields) stays readable
 * without a dedicated decoder.  Slot numbers are byte offsets / 8.
 */
static void
FormatQwordFields(
    _In_reads_bytes_opt_(Count * sizeof(UINT64)) const BYTE* Payload,
    _In_ UINT32 Offset,
    _In_ UINT32 Count,
    _Out_writes_z_(Chars) wchar_t* Text,
    _In_ SIZE_T Chars)
{
    SIZE_T used = 0;
    UINT32 index;

    if (Text == NULL || Chars == 0) {
        return;
    }
    Text[0] = L'\0';
    if (Payload == NULL) {
        return;
    }

    for (index = 0; index < Count; index++) {
        UINT64 value = 0;
        int    written;

        if (CopyTargetMemory(Payload + Offset + index * sizeof(UINT64),
                             &value, sizeof(value)) != sizeof(value)) {
            break;
        }
        written = _snwprintf_s(Text + used, Chars - used, _TRUNCATE,
                               (index == 0) ? L"[%u]=0x%llX" : L" [%u]=0x%llX",
                               (unsigned)((Offset / 8) + index),
                               (unsigned long long)value);
        if (written <= 0) {
            break;
        }
        used += (SIZE_T)written;
        if (used + 32 >= Chars) {
            break;
        }
    }
}

/*
 * Kind 0x25 payload points at the wchar_t* stage message built by the scan
 * pipeline (for example L"START:Engine quick scan variant, type 0x..."), so
 * dereference it once.  Fall back to treating the payload itself as text when
 * the pointer is not readable.
 */
static void
ReadStageText(
    _In_ const void* Payload,
    _Out_writes_z_(Chars) wchar_t* Text,
    _In_ SIZE_T Chars)
{
    PVOID   text = NULL;
    wchar_t probe = L'\0';

    Text[0] = L'\0';
    if (Payload == NULL) {
        return;
    }

    if (ReadTargetPointer(Payload, &text) &&
        text != NULL &&
        CopyTargetMemory(text, &probe, sizeof(probe)) == sizeof(probe) &&
        probe >= L' ') {
        (void)CopyWideString(Text, Chars, (const wchar_t*)text, 0);
        if (Text[0] != L'\0') {
            return;
        }
    }

    (void)CopyWideString(Text, Chars, (const wchar_t*)Payload, 0);
}

/*
 * Accept a decoded name only when it looks like text.  The engine's name field
 * is often an empty/absent inline buffer, and misreading it as a string would
 * otherwise print control characters.
 */
static BOOL
TextLooksPrintable(
    _In_z_ const wchar_t* Text)
{
    SIZE_T length = wcslen(Text);
    SIZE_T printable = 0;
    SIZE_T i;

    for (i = 0; i < length; i++) {
        if (Text[i] >= L' ' && Text[i] < 0x7F) {
            printable++;
        }
    }
    return length != 0 && printable != 0 && printable * 2 >= length;
}

/*
 * The MOAC rich record carries an engine-owned name buffer plus the buffer
 * length in bytes.  Try UTF-16 first and fall back to ANSI so an unknown
 * encoding does not silently print "?".
 */
static void
ReadNameAuto(
    _In_opt_ const void* Source,
    _In_opt_ UINT64 KnownBytes,
    _Out_writes_z_(Chars) wchar_t* Text,
    _In_ SIZE_T Chars)
{
    char   ansi[RSI_ENGINE_WORK_TARGET_CHARS];
    SIZE_T length;

    Text[0] = L'\0';
    if (Source == NULL || KnownBytes == 0) {
        return;
    }

    (void)CopyWideString(Text, Chars, (const wchar_t*)Source, KnownBytes);
    if (TextLooksPrintable(Text)) {
        return;
    }

    Text[0] = L'\0';
    length = (KnownBytes < sizeof(ansi) - 1) ? (SIZE_T)KnownBytes
                                             : sizeof(ansi) - 1;
    length = CopyTargetMemory(Source, ansi, length);
    if (length == 0) {
        return;
    }
    ansi[length] = '\0';
    if (MultiByteToWideChar(CP_ACP, 0, ansi, -1, Text, (int)Chars) <= 0 ||
        !TextLooksPrintable(Text)) {
        Text[0] = L'\0';
    }
}

/*
 * Structured trace record.  Kinds 0x18/0x1C/0x28/0x38 are fully decoded and
 * the small fixed-layout records (0x13/0x15/0x1A/0x1F/0x22/0x23/0x25/0x2A/
 * 0x37/0x3D/0x3E/0x44/0x52) are decoded into named fields; anything else
 * carries a bounded hex copy of the payload for offline decoding.
 */
static void
EmitEngineTrace(
    _In_ UINT32 Kind,
    _In_ UINT64 CallerRva,
    _In_ UINT64 EngineTime,
    _In_ UINT32 Opcode,
    _In_ UINT32 Flags,
    _In_ UINT32 Version,
    _In_ UINT32 Id,
    _In_opt_ const wchar_t* KindName,
    _In_opt_ const wchar_t* Target,
    _In_opt_ const wchar_t* Detail,
    _In_reads_bytes_opt_(PayloadLength) const BYTE* Payload,
    _In_ SIZE_T PayloadLength)
{
    char kindNameUtf8[RSI_ENGINE_WORK_KIND_CHARS * 3 + 1];
    char targetUtf8[RSI_ENGINE_WORK_TARGET_CHARS * 3 + 1];
    char detailUtf8[RSI_ENGINE_DETAIL_CHARS * 3 + 1];
    char payloadHex[RSI_ENGINE_TRACE_DUMP_BYTES * 2 + 1];

    if (!g_ProviderRegistered) {
        return;
    }

    WideToUtf8(KindName, kindNameUtf8, sizeof(kindNameUtf8));
    WideToUtf8(Target, targetUtf8, sizeof(targetUtf8));
    WideToUtf8(Detail, detailUtf8, sizeof(detailUtf8));
    payloadHex[0] = '\0';

    if (Payload != NULL && PayloadLength != 0) {
        if (PayloadLength > RSI_ENGINE_TRACE_DUMP_BYTES) {
            PayloadLength = RSI_ENGINE_TRACE_DUMP_BYTES;
        }
        BytesToHex(Payload, PayloadLength, payloadHex);
    } else {
        PayloadLength = 0;
    }

    TraceLoggingWrite(
        g_hRSignalProvider,
        MPENGINE_ETW_EVENT_TRACE,
        TraceLoggingLevel(TRACE_LEVEL_INFORMATION),
        TraceLoggingUInt32(MPENGINE_ETW_TYPE_TRACE, "Type"),
        TraceLoggingUInt32((UINT32)InterlockedIncrement(&g_EngineTraceCalls),
                           "SeqNum"),
        TraceLoggingUInt32(Kind, "Kind"),
        TraceLoggingUInt64(CallerRva, "CallerRva"),
        TraceLoggingUInt64(EngineTime, "EngineTime"),
        TraceLoggingUInt32(Opcode, "Opcode"),
        TraceLoggingUInt32(Flags, "Flags"),
        TraceLoggingUInt32(Version, "Version"),
        TraceLoggingUInt32(Id, "Id"),
        TraceLoggingString(kindNameUtf8, "KindName"),
        TraceLoggingString(targetUtf8, "Target"),
        TraceLoggingString(detailUtf8, "Detail"),
        TraceLoggingUInt32((UINT32)PayloadLength, "PayloadLength"),
        TraceLoggingString(payloadHex, "PayloadHex"));
}

static void
EmitEngineTraceRecord(
    _In_ const void* Record,
    _In_ const void* Caller)
{
    const BYTE* record = (const BYTE*)Record;
    UINT64      kind = 0;
    UINT64      engineTime = 0;
    UINT64      callerRva = 0;
    PVOID       payload = NULL;

    if (Record == NULL ||
        CopyTargetMemory(record, &kind, sizeof(kind)) != sizeof(kind)) {
        return;
    }

    if (Caller != NULL) {
        const ULONG_PTR caller = (ULONG_PTR)Caller;

        if (g_EngineModuleBase != NULL &&
            caller >= (ULONG_PTR)g_EngineModuleBase &&
            caller - (ULONG_PTR)g_EngineModuleBase < 0x2000000) {
            callerRva = (UINT64)(caller - (ULONG_PTR)g_EngineModuleBase);
        } else {
            callerRva = (UINT64)caller;
        }
    }

    (void)CopyTargetMemory(record + RSI_ENGINE_RECORD_TIME,
                           &engineTime, sizeof(engineTime));
    (void)ReadTargetPointer(record + RSI_ENGINE_RECORD_PAYLOAD, &payload);

    if (kind == RSI_ENGINE_KIND_LOG) {
        PVOID   log = NULL;
        PVOID   module = NULL;
        PVOID   message = NULL;
        UINT32  level = 0;
        UINT64  bytes = 0;
        wchar_t moduleText[RSI_ENGINE_MODULE_CHARS];
        wchar_t messageText[RSI_ENGINE_MESSAGE_CHARS];

        if (payload == NULL) {
            return;
        }
        (void)CopyTargetMemory((const BYTE*)payload + RSI_ENGINE_PAYLOAD_LEVEL,
                               &level, sizeof(level));
        if (!ReadTargetPointer((const BYTE*)payload + RSI_ENGINE_PAYLOAD_LOG,
                               &log) ||
            log == NULL) {
            return;
        }
        (void)ReadTargetPointer((const BYTE*)log + RSI_ENGINE_LOG_MODULE,
                                &module);
        (void)CopyTargetMemory((const BYTE*)log + RSI_ENGINE_LOG_LENGTH,
                               &bytes, sizeof(bytes));
        (void)ReadTargetPointer((const BYTE*)log + RSI_ENGINE_LOG_MESSAGE,
                                &message);

        (void)CopyWideString(moduleText, RSI_ENGINE_MODULE_CHARS,
                             (const wchar_t*)module, 0);
        (void)CopyWideString(messageText, RSI_ENGINE_MESSAGE_CHARS,
                             (const wchar_t*)message, bytes);
        if (messageText[0] == L'\0') {
            return;
        }

        EmitEngineLog((UINT32)kind, level, moduleText, messageText);
        return;
    }

    if (kind == RSI_ENGINE_KIND_EVENT) {
        UINT64  eventType = 0;
        PVOID   data = NULL;
        PVOID   namePtr = NULL;
        PVOID   valuePtr = NULL;
        UINT16  version = 0;
        UINT16  id = 0;
        wchar_t nameText[RSI_ENGINE_WORK_KIND_CHARS];
        wchar_t valueText[RSI_ENGINE_WORK_TARGET_CHARS];

        nameText[0] = L'\0';
        valueText[0] = L'\0';

        if (payload != NULL) {
            (void)CopyTargetMemory(payload, &eventType, sizeof(eventType));
            if (ReadTargetPointer((const BYTE*)payload +
                                      RSI_ENGINE_EVENT_PAYLOAD_DATA,
                                  &data) &&
                data != NULL) {
                (void)ReadTargetPointer((const BYTE*)data + 0x00, &namePtr);
                (void)ReadTargetPointer((const BYTE*)data + 0x08, &valuePtr);
                (void)CopyTargetMemory((const BYTE*)data + 0x10,
                                       &version, sizeof(version));
                (void)CopyTargetMemory((const BYTE*)data + 0x12,
                                       &id, sizeof(id));
                (void)CopyWideString(nameText, RSI_ENGINE_WORK_KIND_CHARS,
                                     (const wchar_t*)namePtr, 0);
                (void)CopyWideString(valueText,
                                     RSI_ENGINE_WORK_TARGET_CHARS,
                                     (const wchar_t*)valuePtr, 0);
            }
        }

        EmitEngineTrace((UINT32)kind, callerRva, engineTime,
                        (UINT32)eventType, 0, (UINT32)version, (UINT32)id,
                        nameText, valueText, NULL, NULL, 0);
        return;
    }

    if (kind == RSI_ENGINE_KIND_MOAC) {
        UINT64  lookup[2] = { 0, 0 };
        UINT64  fileId[2] = { 0, 0 };
        UINT64  id = 0;
        UINT64  nameLength = 0;
        UINT32  flag = 0;
        PVOID   namePtr = NULL;
        BYTE    lookupBytes[16];
        wchar_t guidText[64];
        wchar_t nameText[RSI_ENGINE_WORK_TARGET_CHARS];
        wchar_t detailText[RSI_ENGINE_DETAIL_CHARS];

        nameText[0] = L'\0';
        detailText[0] = L'\0';
        guidText[0] = L'\0';

        if (payload != NULL) {
            (void)CopyTargetMemory((const BYTE*)payload + 0x08,
                                   &lookup[0], sizeof(lookup[0]));
            (void)CopyTargetMemory((const BYTE*)payload + 0x10,
                                   &lookup[1], sizeof(lookup[1]));
            (void)CopyTargetMemory((const BYTE*)payload + 0x18,
                                   &fileId[0], sizeof(fileId[0]));
            (void)CopyTargetMemory((const BYTE*)payload + 0x20,
                                   &fileId[1], sizeof(fileId[1]));
            (void)CopyTargetMemory((const BYTE*)payload + 0x28,
                                   &id, sizeof(id));
            (void)CopyTargetMemory((const BYTE*)payload + 0x30,
                                   &flag, sizeof(flag));
            (void)ReadTargetPointer((const BYTE*)payload + 0x38, &namePtr);
            (void)CopyTargetMemory((const BYTE*)payload + 0x40,
                                   &nameLength, sizeof(nameLength));
            (void)ReadNameAuto(namePtr, nameLength, nameText,
                               ARRAYSIZE(nameText));
        }

        memcpy(lookupBytes, lookup, sizeof(lookupBytes));
        FormatGuidText(lookupBytes, guidText, ARRAYSIZE(guidText));
        (void)_snwprintf_s(detailText, ARRAYSIZE(detailText), _TRUNCATE,
                           L"lookup=%s fileid=%016llX%016llX id=0x%llX "
                           L"flag=%u",
                           guidText,
                           (unsigned long long)fileId[0],
                           (unsigned long long)fileId[1],
                           (unsigned long long)id,
                           (unsigned)flag);

        EmitEngineTrace((UINT32)kind, callerRva, engineTime, 1, flag, 0, 0,
                        L"moaclookup", nameText, detailText, NULL, 0);
        return;
    }

    if (kind == RSI_ENGINE_KIND_MOAC_LEGACY) {
        UINT32  type = 0;
        UINT64  handle = 0;
        UINT64  id = 0;
        UINT64  nameLength = 0;
        UINT32  flag = 0;
        PVOID   namePtr = NULL;
        wchar_t nameText[RSI_ENGINE_WORK_TARGET_CHARS];
        wchar_t detailText[RSI_ENGINE_DETAIL_CHARS];

        nameText[0] = L'\0';
        detailText[0] = L'\0';

        if (payload != NULL) {
            (void)CopyTargetMemory((const BYTE*)payload + 0x00,
                                   &type, sizeof(type));
            (void)CopyTargetMemory((const BYTE*)payload + 0x08,
                                   &handle, sizeof(handle));
            (void)CopyTargetMemory((const BYTE*)payload + 0x18,
                                   &id, sizeof(id));
            (void)CopyTargetMemory((const BYTE*)payload + 0x20,
                                   &flag, sizeof(flag));
            (void)ReadTargetPointer((const BYTE*)payload + 0x28, &namePtr);
            (void)CopyTargetMemory((const BYTE*)payload + 0x30,
                                   &nameLength, sizeof(nameLength));
            (void)ReadNameAuto(namePtr, nameLength, nameText,
                               ARRAYSIZE(nameText));
        }

        (void)_snwprintf_s(detailText, ARRAYSIZE(detailText), _TRUNCATE,
                           L"handle=0x%llX id=0x%llX flag=%u",
                           (unsigned long long)handle,
                           (unsigned long long)id,
                           (unsigned)flag);

        EmitEngineTrace((UINT32)kind, callerRva, engineTime, type, flag, 0, 0,
                        L"moaclookup", nameText, detailText, NULL, 0);
        return;
    }

    if (kind == RSI_ENGINE_KIND_WORK) {
        PVOID   args = NULL;
        PVOID   kindTextPtr = NULL;
        PVOID   targetTextPtr = NULL;
        UINT32  opcode = 0;
        UINT32  flags = 0;
        UINT16  version = 0;
        UINT16  id = 0;
        wchar_t kindText[RSI_ENGINE_WORK_KIND_CHARS];
        wchar_t targetText[RSI_ENGINE_WORK_TARGET_CHARS];

        kindText[0] = L'\0';
        targetText[0] = L'\0';

        if (payload != NULL) {
            (void)CopyTargetMemory((const BYTE*)payload +
                                       RSI_ENGINE_WORK_PAYLOAD_OPCODE,
                                   &opcode, sizeof(opcode));
            (void)CopyTargetMemory((const BYTE*)payload +
                                       RSI_ENGINE_WORK_PAYLOAD_FLAGS,
                                   &flags, sizeof(flags));
            if (opcode == RSI_ENGINE_WORK_OPCODE_DEFERRED &&
                ReadTargetPointer((const BYTE*)payload +
                                      RSI_ENGINE_WORK_PAYLOAD_ARGS,
                                  &args) &&
                args != NULL) {
                (void)CopyTargetMemory((const BYTE*)args +
                                           RSI_ENGINE_WORK_ARGS_VERSION,
                                       &version, sizeof(version));
                (void)CopyTargetMemory((const BYTE*)args +
                                           RSI_ENGINE_WORK_ARGS_ID,
                                       &id, sizeof(id));
                (void)ReadTargetPointer((const BYTE*)args +
                                            RSI_ENGINE_WORK_ARGS_KIND,
                                        &kindTextPtr);
                (void)ReadTargetPointer((const BYTE*)args +
                                            RSI_ENGINE_WORK_ARGS_TARGET,
                                        &targetTextPtr);
                (void)CopyWideString(kindText, RSI_ENGINE_WORK_KIND_CHARS,
                                     (const wchar_t*)kindTextPtr, 0);
                (void)CopyWideString(targetText,
                                     RSI_ENGINE_WORK_TARGET_CHARS,
                                     (const wchar_t*)targetTextPtr, 0);
            }
        }

        EmitEngineTrace((UINT32)kind, callerRva, engineTime, opcode, flags,
                        (UINT32)version, (UINT32)id, kindText, targetText,
                        NULL, NULL, 0);
        return;
    }

    /*
     * 0x22/0x23 are the engine's host data channel: {u32 length; u32 pad;
     * void *buffer; u32 value; u32 pad; u64 extra}.  The engine reads a blob
     * from the host (0x22) or hands one to it (0x23); the host may rewrite
     * "length" at +0x00, in which case the engine discards/zeroes the buffer.
     */
    if (kind == RSI_ENGINE_KIND_HOST_READ ||
        kind == RSI_ENGINE_KIND_HOST_WRITE) {
        UINT32  length = 0;
        UINT32  value = 0;
        UINT64  buffer = 0;
        UINT64  extra = 0;
        wchar_t detailText[RSI_ENGINE_DETAIL_CHARS];

        if (payload != NULL) {
            (void)CopyTargetMemory((const BYTE*)payload + 0x00,
                                   &length, sizeof(length));
            (void)CopyTargetMemory((const BYTE*)payload + 0x08,
                                   &buffer, sizeof(buffer));
            (void)CopyTargetMemory((const BYTE*)payload + 0x10,
                                   &value, sizeof(value));
            (void)CopyTargetMemory((const BYTE*)payload + 0x18,
                                   &extra, sizeof(extra));
        }

        if (kind == RSI_ENGINE_KIND_HOST_READ) {
            (void)_snwprintf_s(detailText, ARRAYSIZE(detailText), _TRUNCATE,
                               L"len=%u buffer=0x%llX value=0x%X",
                               (unsigned)length,
                               (unsigned long long)buffer,
                               (unsigned)value);
            EmitEngineTrace((UINT32)kind, callerRva, engineTime, 0, 0, 0, 0,
                            L"hostread", NULL, detailText, NULL, 0);
        } else {
            (void)_snwprintf_s(detailText, ARRAYSIZE(detailText), _TRUNCATE,
                               L"len=%u buffer=0x%llX value=0x%X "
                               L"extra=0x%llX",
                               (unsigned)length,
                               (unsigned long long)buffer,
                               (unsigned)value,
                               (unsigned long long)extra);
            EmitEngineTrace((UINT32)kind, callerRva, engineTime, 0, 0, 0, 0,
                            L"hostwrite", NULL, detailText, NULL, 0);
        }
        return;
    }

    /*
     * 0x25 payload holds the wchar_t* stage message the scan pipeline just
     * formatted, e.g. L"START:Engine quick scan variant, type 0x...".
     */
    if (kind == RSI_ENGINE_KIND_SCAN_STAGE) {
        wchar_t stageText[RSI_ENGINE_MESSAGE_CHARS];

        stageText[0] = L'\0';
        if (payload != NULL) {
            ReadStageText(payload, stageText, ARRAYSIZE(stageText));
        }
        EmitEngineTrace((UINT32)kind, callerRva, engineTime, 0, 0, 0, 0,
                        L"scanstage", stageText, NULL, NULL, 0);
        return;
    }

    /*
     * 0x1A and 0x37 are MOAC entry serializations.  Both start with the same
     * 16-byte lookup GUID; 0x37 is the 0x40-byte form, 0x1A the 0x50-byte one.
     */
    if (kind == RSI_ENGINE_KIND_MOAC_ENTRY ||
        kind == RSI_ENGINE_KIND_MOAC_ENTRY_R) {
        BYTE    guidBytes[16];
        wchar_t guidText[64];
        wchar_t fields[RSI_ENGINE_DETAIL_CHARS];
        wchar_t detailText[RSI_ENGINE_DETAIL_CHARS];
        UINT32  qwordCount;

        ZeroMemory(guidBytes, sizeof(guidBytes));
        guidText[0] = L'\0';
        fields[0] = L'\0';
        detailText[0] = L'\0';

        if (payload != NULL) {
            (void)CopyTargetMemory(payload, guidBytes, sizeof(guidBytes));
            qwordCount = (kind == RSI_ENGINE_KIND_MOAC_ENTRY_R) ? 4 : 5;
            FormatQwordFields((const BYTE*)payload, 0x10, qwordCount,
                              fields, ARRAYSIZE(fields));
            FormatGuidText(guidBytes, guidText, ARRAYSIZE(guidText));
            (void)_snwprintf_s(detailText, ARRAYSIZE(detailText), _TRUNCATE,
                               L"lookup=%s %s", guidText, fields);
        }

        EmitEngineTrace((UINT32)kind, callerRva, engineTime, 0, 0, 0, 0,
                        L"moacentry", NULL, detailText, NULL, 0);
        return;
    }

    /* 0x1F is the result buffer of one MOAC v2 attempt (32 bytes, host filled). */
    if (kind == RSI_ENGINE_KIND_MOAC_V2) {
        wchar_t fields[RSI_ENGINE_DETAIL_CHARS];

        fields[0] = L'\0';
        FormatQwordFields((const BYTE*)payload, 0x00, 4, fields,
                          ARRAYSIZE(fields));
        EmitEngineTrace((UINT32)kind, callerRva, engineTime, 0, 0, 0, 0,
                        L"moacv2", NULL, fields, NULL, 0);
        return;
    }

    /* 0x2A is a notification record: {u32 type=6; u32 pad; u64 object; ...}. */
    if (kind == RSI_ENGINE_KIND_NOTIFICATION) {
        UINT32  type = 0;
        UINT64  object = 0;
        wchar_t fields[RSI_ENGINE_DETAIL_CHARS];
        wchar_t detailText[RSI_ENGINE_DETAIL_CHARS];

        fields[0] = L'\0';
        detailText[0] = L'\0';
        if (payload != NULL) {
            (void)CopyTargetMemory((const BYTE*)payload + 0x00,
                                   &type, sizeof(type));
            (void)CopyTargetMemory((const BYTE*)payload + 0x08,
                                   &object, sizeof(object));
            FormatQwordFields((const BYTE*)payload, 0x10, 4, fields,
                              ARRAYSIZE(fields));
        }
        (void)_snwprintf_s(detailText, ARRAYSIZE(detailText), _TRUNCATE,
                           L"type=%u object=0x%llX %s",
                           (unsigned)type,
                           (unsigned long long)object,
                           fields);
        EmitEngineTrace((UINT32)kind, callerRva, engineTime, type, 0, 0, 0,
                        L"notification", NULL, detailText, NULL, 0);
        return;
    }

    /*
     * 0x3D/0x3E bracket a host configuration query: the engine allocates a
     * 0x20-byte out-buffer (first u32 is the version, observed 0x101), lets
     * the host fill it (0x3D) and then releases it (0x3E).
     */
    if (kind == RSI_ENGINE_KIND_HOST_CONFIG ||
        kind == RSI_ENGINE_KIND_HOST_RELEASE) {
        UINT32  version = 0;
        wchar_t fields[RSI_ENGINE_DETAIL_CHARS];
        wchar_t detailText[RSI_ENGINE_DETAIL_CHARS];

        fields[0] = L'\0';
        detailText[0] = L'\0';
        if (payload != NULL) {
            (void)CopyTargetMemory((const BYTE*)payload + 0x00,
                                   &version, sizeof(version));
            FormatQwordFields((const BYTE*)payload, 0x08, 3, fields,
                              ARRAYSIZE(fields));
        }
        (void)_snwprintf_s(detailText, ARRAYSIZE(detailText), _TRUNCATE,
                           L"version=0x%X %s", (unsigned)version, fields);
        EmitEngineTrace((UINT32)kind, callerRva, engineTime, version, 0, 0, 0,
                        L"hostconfig", NULL, detailText, NULL, 0);
        return;
    }

    /* 0x44 is the RTP/iClientInfo monitoring state update ("UpdateMonitoringToRTP"). */
    if (kind == RSI_ENGINE_KIND_RTP_UPDATE) {
        UINT32  type = 0;
        wchar_t fields[RSI_ENGINE_DETAIL_CHARS];
        wchar_t detailText[RSI_ENGINE_DETAIL_CHARS];

        fields[0] = L'\0';
        detailText[0] = L'\0';
        if (payload != NULL) {
            (void)CopyTargetMemory((const BYTE*)payload + 0x00,
                                   &type, sizeof(type));
            FormatQwordFields((const BYTE*)payload, 0x08, 4, fields,
                              ARRAYSIZE(fields));
        }
        (void)_snwprintf_s(detailText, ARRAYSIZE(detailText), _TRUNCATE,
                           L"type=%u %s", (unsigned)type, fields);
        EmitEngineTrace((UINT32)kind, callerRva, engineTime, type, 0, 0, 0,
                        L"rtpupdate", NULL, detailText, NULL, 0);
        return;
    }

    /*
     * 0x52 carries the host's remediation configuration; the engine reads
     * routineactiondelay (+0x00), routineactionmaxdelay (+0x04),
     * disableroutinelytakingaction (+0x08) and three option values.
     */
    if (kind == RSI_ENGINE_KIND_REMEDIATION) {
        UINT32  delay = 0;
        UINT32  maxDelay = 0;
        UINT32  disable = 0;
        UINT32  option1 = 0;
        UINT32  option2 = 0;
        UINT32  option4 = 0;
        UINT32  option5 = 0;
        wchar_t detailText[RSI_ENGINE_DETAIL_CHARS];

        if (payload != NULL) {
            (void)CopyTargetMemory((const BYTE*)payload + 0x00,
                                   &delay, sizeof(delay));
            (void)CopyTargetMemory((const BYTE*)payload + 0x04,
                                   &maxDelay, sizeof(maxDelay));
            (void)CopyTargetMemory((const BYTE*)payload + 0x08,
                                   &disable, sizeof(disable));
            (void)CopyTargetMemory((const BYTE*)payload + 0x0C,
                                   &option1, sizeof(option1));
            (void)CopyTargetMemory((const BYTE*)payload + 0x10,
                                   &option2, sizeof(option2));
            (void)CopyTargetMemory((const BYTE*)payload + 0x14,
                                   &option4, sizeof(option4));
            (void)CopyTargetMemory((const BYTE*)payload + 0x18,
                                   &option5, sizeof(option5));
        }
        (void)_snwprintf_s(detailText, ARRAYSIZE(detailText), _TRUNCATE,
                           L"delay=%u maxdelay=%u disable=%u opt1=%u opt2=%u "
                           L"opt4=%u opt5=%u",
                           (unsigned)delay, (unsigned)maxDelay,
                           (unsigned)disable, (unsigned)option1,
                           (unsigned)option2, (unsigned)option4,
                           (unsigned)option5);
        EmitEngineTrace((UINT32)kind, callerRva, engineTime, 0, 0, 0, 0,
                        L"remediation", NULL, detailText, NULL, 0);
        return;
    }

    /*
     * 0x13/0x15 are notification records forwarded verbatim by
     * FUN_1804b6fb0; only the first four qwords are rendered because the
     * tail depends on the notification type.
     */
    if (kind == RSI_ENGINE_KIND_NOTIFY || kind == RSI_ENGINE_KIND_NOTIFY_ALT) {
        wchar_t fields[RSI_ENGINE_DETAIL_CHARS];

        fields[0] = L'\0';
        FormatQwordFields((const BYTE*)payload, 0x00, 4, fields,
                          ARRAYSIZE(fields));
        EmitEngineTrace((UINT32)kind, callerRva, engineTime, 0, 0, 0, 0,
                        L"notification", NULL, fields, NULL, 0);
        return;
    }

#if RSI_ENGINE_CAPTURE_OTHER_KINDS
    {
        BYTE   payloadBytes[RSI_ENGINE_TRACE_DUMP_BYTES];
        SIZE_T payloadRead = 0;

        if (payload != NULL) {
            payloadRead = CopyTargetMemory(payload, payloadBytes,
                                           sizeof(payloadBytes));
        }
        EmitEngineTrace((UINT32)kind, callerRva, engineTime, 0, 0, 0, 0,
                        NULL, NULL, NULL,
                        (payloadRead != 0) ? payloadBytes : NULL,
                        payloadRead);
    }
#endif
}

static LONG WINAPI
Hook_EngineTrace(
    _In_ const void* Record)
{
    PFN_ENGINE_TRACE real = g_RealEngineTrace;
    LONG status;

    /*
     * Bounded recursion guard: if the sink installed by MpSvc logs back into
     * the engine, the nested record is still forwarded but not emitted twice.
     */
    if (InterlockedIncrement(&g_InEngineLog) == 1 &&
        TraceLoggingProviderEnabled(g_hRSignalProvider, 0, 0)) {
        EmitEngineTraceRecord(Record, _ReturnAddress());
    }

    status = (real != NULL) ? real(Record) : 0;
    InterlockedDecrement(&g_InEngineLog);
    return status;
}

static void
ArmEngineLog(
    _In_ const BYTE* base)
{
    const PVOID dispatcher = (PVOID)(base + RSI_ENGINE_DISPATCHER_RVA);
    PVOID       instance = NULL;
    PVOID       owner = NULL;
    PVOID       previous;
    BOOL        usable;
    BYTE*       slot;
    BYTE        abi = 0;
    PVOID       current = NULL;

    if (CopyTargetMemory(base + RSI_ENGINE_TRACE_ABI_RVA,
                         &abi, sizeof(abi)) != sizeof(abi)) {
        return;
    }

    usable = ReadTargetPointer(base + RSI_ENGINE_INSTANCE_RVA, &instance) &&
             instance != NULL &&
             ReadTargetPointer(instance, &owner) &&
             owner == dispatcher;

    /*
     * Only act once the same instance has been observed twice in a row. That
     * keeps a transient or freed instance (the engine was unloaded between the
     * two reads) from being patched.
     */
    previous = g_LastEngineInstance;
    g_LastEngineInstance = usable ? instance : NULL;
    if (!usable || previous != instance) {
        return;
    }

    slot = (BYTE*)instance + ((abi != 0) ? RSI_ENGINE_TRACE_FN_LEGACY
                                         : RSI_ENGINE_TRACE_FN_NEW);
    if (!ReadTargetPointer(slot, &current)) {
        if (g_LastArmFailureInstance != instance) {
            g_LastArmFailureInstance = instance;
            DiagLog("engine trace slot unreadable: instance=%p slot=+0x%03X",
                    instance, (unsigned)(slot - (BYTE*)instance));
            EmitStatusErrorV(0, "engine log capture: cannot read trace slot "
                                "instance=0x%p slot=+0x%03X abi=%u",
                             instance, (unsigned)(slot - (BYTE*)instance),
                             (unsigned)abi);
        }
        return;
    }
    if (current == (PVOID)Hook_EngineTrace) {
        g_LastArmFailureInstance = NULL;
        return;
    }

    /*
     * The engine boots asynchronously: the slot is either still zero or
     * already holds MpSvc's sink. Save whatever is there (NULL is fine) and
     * take the slot over. An engine reboot or reload writes its own pointer
     * again; the next poll re-installs this hook.
     */
    g_RealEngineTrace = (PFN_ENGINE_TRACE)current;
    if (WriteTargetPointer(slot, (PVOID)Hook_EngineTrace)) {
        g_LastArmFailureInstance = NULL;
        DiagLog("engine trace slot armed: instance=%p slot=+0x%03X original=%p",
                instance, (unsigned)(slot - (BYTE*)instance), current);
        EmitStatusInfoV(0, "engine log capture armed: instance=0x%p "
                        "slot=+0x%03X original=0x%p abi=%u",
                        instance, (unsigned)(slot - (BYTE*)instance), current,
                        (unsigned)abi);
        InterlockedExchange(&g_EngineLogArmed, 1);
    } else if (g_LastArmFailureInstance != instance) {
        g_LastArmFailureInstance = instance;
        DiagLog("engine trace slot write failed: instance=%p slot=+0x%03X",
                instance, (unsigned)(slot - (BYTE*)instance));
        EmitStatusErrorV(0, "engine log capture: cannot write trace slot "
                            "instance=0x%p slot=+0x%03X",
                         instance, (unsigned)(slot - (BYTE*)instance));
    }
}

/* ------------------------------------------------------------------------- */
/* Process-memory scan observers                                             */
/* ------------------------------------------------------------------------- */

/*
 * The engine reads other processes through three host entry points:
 *
 *   OpenProcess            kernel32 import   (image resolution, EMS open)
 *   VirtualQueryEx         kernel32 import   (memory layout enumeration)
 *   NtReadVirtualMemoryEx  resolved lazily into mpengine+RSI_ENGINE_NTREAD_RVA
 *
 * This is the in-engine counterpart of mpclient's mpengine_observe.c.  It
 * patches the two IAT entries in mpengine.dll (scoped to the engine, not a
 * process-wide ntdll hook) and the engine's own read-function global, forwards
 * every call unchanged, and emits an EngineMem event with the same arguments
 * the engine passed.
 *
 * The engine module is unloaded and reloaded by MpSvc, so nothing here is
 * cached across a reload: the maintenance thread re-finds the IAT slots and
 * re-writes the read global whenever the module base changes or the engine
 * rewrites its own pointer.  The read-slot address is validated (committed,
 * writable data page; current value NULL, ntdll, or our wrapper) before it is
 * written, so a future engine build with a different RVA is reported instead
 * of corrupting unrelated engine state.
 */

typedef HANDLE (WINAPI *RSI_OPEN_PROCESS_FN)(DWORD, BOOL, DWORD);
typedef SIZE_T (WINAPI *RSI_VIRTUAL_QUERY_EX_FN)(HANDLE, LPCVOID,
                                                 PMEMORY_BASIC_INFORMATION,
                                                 SIZE_T);
typedef LONG (NTAPI *RSI_NT_READ_VM_FN)(HANDLE, PVOID, PVOID, SIZE_T,
                                        PSIZE_T, ULONG);

#define RSI_MEM_OPEN   0x1u
#define RSI_MEM_QUERY  0x2u
#define RSI_MEM_READ   0x4u
#define RSI_MEM_ALL    (RSI_MEM_OPEN | RSI_MEM_QUERY | RSI_MEM_READ)

#ifndef RSI_MEM_IAT_ENTRIES
#define RSI_MEM_IAT_ENTRIES 8192
#endif
#ifndef RSI_MEM_IAT_NAME_CHARS
#define RSI_MEM_IAT_NAME_CHARS 96
#endif

static RSI_OPEN_PROCESS_FN     g_RealOpenProcess = NULL;
static RSI_VIRTUAL_QUERY_EX_FN g_RealVirtualQueryEx = NULL;
static RSI_NT_READ_VM_FN       g_RealNtReadVirtualMemory = NULL;

static void** g_OpenProcessSlot = NULL;
static void** g_VirtualQuerySlot = NULL;
static void** g_NtReadSlot = NULL;
static PVOID  g_MemObserveModule = NULL;
static DWORD  g_MemObserveTimeDateStamp = 0;
static DWORD  g_MemObserveSizeOfImage = 0;
static LONG   g_MemObserveMask = -1;
static LONG   g_MemObserveCalls = 0;
static volatile LONG g_MemObserveActive = 0;

static HANDLE WINAPI Hook_OpenProcess(DWORD Access, BOOL Inherit, DWORD Pid);
static SIZE_T WINAPI Hook_VirtualQueryEx(HANDLE Process, LPCVOID Address,
                                         PMEMORY_BASIC_INFORMATION Info,
                                         SIZE_T Length);
static LONG NTAPI Hook_NtReadVirtualMemory(HANDLE Process, PVOID Address,
                                           PVOID Buffer, SIZE_T Size,
                                           PSIZE_T Read, ULONG Flags);

/*
 * A reload usually changes the base, but the loader can also map the new image
 * at the old base.  The PE timestamp/size pair distinguishes the two images, so
 * a cached IAT slot is never reused for a different engine build.
 */
static BOOL
ReadModuleIdentity(
    _In_ HMODULE Module,
    _Out_ DWORD* TimeDateStamp,
    _Out_ DWORD* SizeOfImage)
{
    const BYTE* base = (const BYTE*)Module;
    IMAGE_DOS_HEADER dos;
    IMAGE_NT_HEADERS nt;

    if (TimeDateStamp == NULL || SizeOfImage == NULL) {
        return FALSE;
    }
    *TimeDateStamp = 0;
    *SizeOfImage = 0;
    if (base == NULL) {
        return FALSE;
    }
    if (CopyTargetMemory(base, &dos, sizeof(dos)) != sizeof(dos) ||
        dos.e_magic != IMAGE_DOS_SIGNATURE ||
        dos.e_lfanew <= 0 || dos.e_lfanew > 0x100000) {
        return FALSE;
    }
    if (CopyTargetMemory(base + dos.e_lfanew, &nt, sizeof(nt)) != sizeof(nt) ||
        nt.Signature != IMAGE_NT_SIGNATURE) {
        return FALSE;
    }

    *TimeDateStamp = nt.FileHeader.TimeDateStamp;
    *SizeOfImage = nt.OptionalHeader.SizeOfImage;
    return TRUE;
}

static BOOL
CopyTargetString(
    _In_ const void* Address,
    _Out_writes_z_(Chars) char* Destination,
    _In_ SIZE_T Chars)
{
    SIZE_T used = 0;

    if (Destination == NULL || Chars == 0) {
        return FALSE;
    }
    Destination[0] = '\0';
    if (Address == NULL) {
        return FALSE;
    }

    while (used < Chars - 1) {
        SIZE_T read = CopyTargetMemory((const BYTE*)Address + used,
                                       Destination + used, Chars - 1 - used);
        SIZE_T i;

        if (read == 0) {
            break;
        }
        for (i = 0; i < read; ++i) {
            if (Destination[used + i] == '\0') {
                return TRUE;
            }
        }
        used += read;
    }

    Destination[used] = '\0';
    return used != 0;
}

/*
 * Find one import address table entry in a loaded module.  The PE structures
 * are copied through CopyTargetMemory so a module that is being unloaded at
 * this instant makes the walk stop instead of faulting.
 */
static void**
FindIatSlot(
    _In_ HMODULE Module,
    _In_ const char* DllName,
    _In_ const char* FunctionName)
{
    const BYTE* base = (const BYTE*)Module;
    IMAGE_DOS_HEADER dos;
    IMAGE_NT_HEADERS nt;
    DWORD importRva;
    DWORD descriptorIndex;

    if (base == NULL || DllName == NULL || FunctionName == NULL) {
        return NULL;
    }
    if (CopyTargetMemory(base, &dos, sizeof(dos)) != sizeof(dos) ||
        dos.e_magic != IMAGE_DOS_SIGNATURE ||
        dos.e_lfanew <= 0 || dos.e_lfanew > 0x100000) {
        return NULL;
    }
    if (CopyTargetMemory(base + dos.e_lfanew, &nt, sizeof(nt)) != sizeof(nt) ||
        nt.Signature != IMAGE_NT_SIGNATURE) {
        return NULL;
    }

    importRva = nt.OptionalHeader
                    .DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT]
                    .VirtualAddress;
    if (importRva == 0) {
        return NULL;
    }

    for (descriptorIndex = 0; descriptorIndex < RSI_MEM_IAT_ENTRIES;
         ++descriptorIndex) {
        IMAGE_IMPORT_DESCRIPTOR descriptor;
        char dllName[RSI_MEM_IAT_NAME_CHARS];
        DWORD lookupRva;
        DWORD thunkIndex;

        if (CopyTargetMemory(base + importRva +
                                 descriptorIndex * sizeof(descriptor),
                             &descriptor, sizeof(descriptor)) !=
                sizeof(descriptor)) {
            return NULL;
        }
        if (descriptor.Name == 0) {
            return NULL;
        }
        if (!CopyTargetString(base + descriptor.Name, dllName,
                              sizeof(dllName)) ||
            _stricmp(dllName, DllName) != 0) {
            continue;
        }

        lookupRva = descriptor.OriginalFirstThunk != 0
                        ? descriptor.OriginalFirstThunk
                        : descriptor.FirstThunk;
        for (thunkIndex = 0; thunkIndex < RSI_MEM_IAT_ENTRIES; ++thunkIndex) {
            IMAGE_THUNK_DATA lookup;
            IMAGE_THUNK_DATA* iat;
            char functionName[RSI_MEM_IAT_NAME_CHARS];

            if (CopyTargetMemory(base + lookupRva +
                                     thunkIndex * sizeof(lookup),
                                 &lookup, sizeof(lookup)) != sizeof(lookup)) {
                break;
            }
            if (lookup.u1.AddressOfData == 0) {
                break;
            }
            if (IMAGE_SNAP_BY_ORDINAL(lookup.u1.Ordinal)) {
                continue;
            }
            if (!CopyTargetString(base + lookup.u1.AddressOfData +
                                      sizeof(WORD),
                                  functionName, sizeof(functionName)) ||
                strcmp(functionName, FunctionName) != 0) {
                continue;
            }

            iat = (IMAGE_THUNK_DATA*)(base + descriptor.FirstThunk);
            return (void**)&iat[thunkIndex].u1.Function;
        }
    }

    return NULL;
}

static BOOL
EnsureSlot(
    _In_ void** Slot,
    _In_ PVOID Replacement)
{
    PVOID current = NULL;

    if (Slot == NULL || !ReadTargetPointer(Slot, &current)) {
        return FALSE;
    }
    if (current == Replacement) {
        return TRUE;
    }
    return WriteTargetPointer(Slot, Replacement);
}

static ULONG
TargetProcessId(
    _In_ HANDLE Process)
{
    DWORD pid;

    if (Process == NULL || Process == INVALID_HANDLE_VALUE) {
        return 0;
    }
    pid = GetProcessId(Process);
    return (ULONG)pid;
}

static BOOL
IsNtdllPointer(
    _In_ PVOID Address,
    _In_ HMODULE Ntdll)
{
    MEMORY_BASIC_INFORMATION memoryInfo;

    if (Address == NULL) {
        return TRUE;
    }
    if (Ntdll == NULL) {
        return FALSE;
    }
    if (VirtualQuery(Address, &memoryInfo, sizeof(memoryInfo)) == 0) {
        return FALSE;
    }
    return memoryInfo.AllocationBase == (PVOID)Ntdll;
}

static void
EmitEngineMem(
    _In_ const char* Op,
    _In_ ULONG Pid,
    _In_ UINT64 Handle,
    _In_ UINT64 Base,
    _In_ UINT64 Size,
    _In_ UINT64 Access,
    _In_ ULONG Status,
    _In_ UINT64 Transferred,
    _In_ ULONG State,
    _In_ ULONG Protect)
{
    if (!g_ProviderRegistered) {
        return;
    }

    TraceLoggingWrite(
        g_hRSignalProvider,
        MPENGINE_ETW_EVENT_MEM,
        TraceLoggingLevel(TRACE_LEVEL_INFORMATION),
        TraceLoggingUInt32(MPENGINE_ETW_TYPE_MEM, "Type"),
        TraceLoggingUInt32((UINT32)InterlockedIncrement(&g_MemObserveCalls),
                           "SeqNum"),
        TraceLoggingString(Op, "Op"),
        TraceLoggingUInt32(Pid, "Pid"),
        TraceLoggingUInt64(Handle, "Handle"),
        TraceLoggingUInt64(Base, "Base"),
        TraceLoggingUInt64(Size, "Size"),
        TraceLoggingUInt64(Access, "Access"),
        TraceLoggingUInt32(Status, "Status"),
        TraceLoggingUInt64(Transferred, "Transferred"),
        TraceLoggingUInt32(State, "State"),
        TraceLoggingUInt32(Protect, "Protect"));
}

static HANDLE WINAPI
Hook_OpenProcess(
    _In_ DWORD Access,
    _In_ BOOL Inherit,
    _In_ DWORD Pid)
{
    RSI_OPEN_PROCESS_FN real = g_RealOpenProcess;
    HANDLE handle;
    DWORD  error;
    DWORD  savedError;

    if (real == NULL) {
        SetLastError(ERROR_PROC_NOT_FOUND);
        return NULL;
    }

    handle = real(Access, Inherit, Pid);
    error = (handle != NULL) ? 0 : GetLastError();
    savedError = GetLastError();

    if (InterlockedCompareExchange(&g_MemObserveActive, 0, 0) != 0 &&
        TraceLoggingProviderEnabled(g_hRSignalProvider, 0, 0)) {
        EmitEngineMem("open", (ULONG)Pid, (UINT64)(ULONG_PTR)handle, 0, 0,
                      (UINT64)Access, error, 0, 0, 0);
    }

    SetLastError(savedError);
    return handle;
}

static SIZE_T WINAPI
Hook_VirtualQueryEx(
    _In_ HANDLE Process,
    _In_ LPCVOID Address,
    _Out_writes_bytes_(Length) PMEMORY_BASIC_INFORMATION Info,
    _In_ SIZE_T Length)
{
    RSI_VIRTUAL_QUERY_EX_FN real = g_RealVirtualQueryEx;
    SIZE_T result;
    DWORD  savedError;
    ULONG  state = 0;
    ULONG  protect = 0;
    UINT64 regionSize = 0;

    if (real == NULL) {
        SetLastError(ERROR_PROC_NOT_FOUND);
        return 0;
    }

    result = real(Process, Address, Info, Length);
    savedError = GetLastError();
    if (result != 0 && Info != NULL) {
        state = (ULONG)Info->State;
        protect = (ULONG)Info->Protect;
        regionSize = (UINT64)Info->RegionSize;
    }

    if (InterlockedCompareExchange(&g_MemObserveActive, 0, 0) != 0 &&
        TraceLoggingProviderEnabled(g_hRSignalProvider, 0, 0)) {
        EmitEngineMem("query", TargetProcessId(Process),
                      (UINT64)(ULONG_PTR)Process,
                      (UINT64)(ULONG_PTR)Address, regionSize, 0,
                      (ULONG)result, (UINT64)result, state, protect);
    }

    SetLastError(savedError);
    return result;
}

static LONG NTAPI
Hook_NtReadVirtualMemory(
    _In_ HANDLE Process,
    _In_ PVOID Address,
    _Out_writes_bytes_(Size) PVOID Buffer,
    _In_ SIZE_T Size,
    _Out_opt_ PSIZE_T Read,
    _In_ ULONG Flags)
{
    RSI_NT_READ_VM_FN real = g_RealNtReadVirtualMemory;
    LONG   status;
    DWORD  savedError;
    SIZE_T transferred = 0;

    if (real == NULL) {
        return (LONG)0xC0000001L;     /* STATUS_UNSUCCESSFUL */
    }

    status = real(Process, Address, Buffer, Size, Read, Flags);
    savedError = GetLastError();
    if (status >= 0) {
        transferred = (Read != NULL) ? *Read : Size;
    }

    if (InterlockedCompareExchange(&g_MemObserveActive, 0, 0) != 0 &&
        TraceLoggingProviderEnabled(g_hRSignalProvider, 0, 0)) {
        EmitEngineMem("read", TargetProcessId(Process),
                      (UINT64)(ULONG_PTR)Process,
                      (UINT64)(ULONG_PTR)Address, (UINT64)Size, 0,
                      (ULONG)status, (UINT64)transferred, 0, 0);
    }

    SetLastError(savedError);
    return status;
}

static void
ReportMemoryObserverMask(
    _In_ HMODULE Module,
    _In_ LONG Mask)
{
    if (Mask == g_MemObserveMask) {
        return;
    }
    g_MemObserveMask = Mask;
    InterlockedExchange(&g_MemObserveActive, (Mask != 0) ? 1 : 0);

    if (Mask == RSI_MEM_ALL) {
        EmitStatusInfoV(0, "memory observers installed: OpenProcess, "
                        "VirtualQueryEx, NtReadVirtualMemoryEx (module=0x%p)",
                        (void*)Module);
        return;
    }

    EmitStatusErrorV(0, "memory observers incomplete: OpenProcess=%s "
                     "VirtualQueryEx=%s NtReadVirtualMemoryEx=%s (module=0x%p)",
                     (Mask & RSI_MEM_OPEN) ? "ok" : "missing",
                     (Mask & RSI_MEM_QUERY) ? "ok" : "missing",
                     (Mask & RSI_MEM_READ) ? "ok" : "missing",
                     (void*)Module);
}

static void
ArmMemoryObservers(
    _In_ HMODULE Engine)
{
    const BYTE* base = (const BYTE*)Engine;
    HMODULE kernel32;
    HMODULE ntdll;
    DWORD   timeDateStamp = 0;
    DWORD   sizeOfImage = 0;
    BOOL    haveIdentity;
    LONG    mask = 0;

    if (Engine == NULL) {
        return;
    }

    haveIdentity = ReadModuleIdentity(Engine, &timeDateStamp, &sizeOfImage);
    if (g_MemObserveModule != (PVOID)Engine ||
        (haveIdentity &&
         (timeDateStamp != g_MemObserveTimeDateStamp ||
          sizeOfImage != g_MemObserveSizeOfImage))) {
        g_MemObserveModule = (PVOID)Engine;
        g_MemObserveTimeDateStamp = timeDateStamp;
        g_MemObserveSizeOfImage = sizeOfImage;
        g_OpenProcessSlot = NULL;
        g_VirtualQuerySlot = NULL;
        g_NtReadSlot = NULL;
        g_MemObserveMask = -1;
        InterlockedExchange(&g_MemObserveActive, 0);
    }

    kernel32 = GetModuleHandleW(L"kernel32.dll");
    ntdll = GetModuleHandleW(L"ntdll.dll");

    if (g_RealOpenProcess == NULL && kernel32 != NULL) {
        g_RealOpenProcess = (RSI_OPEN_PROCESS_FN)
            GetProcAddress(kernel32, "OpenProcess");
    }
    if (g_RealVirtualQueryEx == NULL && kernel32 != NULL) {
        g_RealVirtualQueryEx = (RSI_VIRTUAL_QUERY_EX_FN)
            GetProcAddress(kernel32, "VirtualQueryEx");
    }
    if (g_RealNtReadVirtualMemory == NULL && ntdll != NULL) {
        g_RealNtReadVirtualMemory = (RSI_NT_READ_VM_FN)
            GetProcAddress(ntdll, "NtReadVirtualMemoryEx");
        if (g_RealNtReadVirtualMemory == NULL) {
            g_RealNtReadVirtualMemory = (RSI_NT_READ_VM_FN)
                GetProcAddress(ntdll, "NtReadVirtualMemory");
        }
    }

    if (g_OpenProcessSlot == NULL && g_RealOpenProcess != NULL) {
        g_OpenProcessSlot = FindIatSlot(Engine, "KERNEL32.dll",
                                        "OpenProcess");
    }
    if (g_VirtualQuerySlot == NULL && g_RealVirtualQueryEx != NULL) {
        g_VirtualQuerySlot = FindIatSlot(Engine, "KERNEL32.dll",
                                         "VirtualQueryEx");
    }
    if (g_NtReadSlot == NULL && g_RealNtReadVirtualMemory != NULL) {
        BYTE* readAddress = (BYTE*)(base + RSI_ENGINE_NTREAD_RVA);
        MEMORY_BASIC_INFORMATION memoryInfo;
        PVOID current = NULL;

        if (VirtualQuery(readAddress, &memoryInfo, sizeof(memoryInfo)) != 0 &&
            memoryInfo.State == MEM_COMMIT &&
            (memoryInfo.Protect & (PAGE_NOACCESS | PAGE_GUARD)) == 0 &&
            (memoryInfo.Protect &
             (PAGE_READWRITE | PAGE_WRITECOPY |
              PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0 &&
            ReadTargetPointer(readAddress, &current) &&
            (current == NULL ||
             current == (PVOID)Hook_NtReadVirtualMemory ||
             IsNtdllPointer(current, ntdll))) {
            g_NtReadSlot = (void**)readAddress;
        }
    }

    if (g_OpenProcessSlot != NULL &&
        EnsureSlot(g_OpenProcessSlot, (PVOID)Hook_OpenProcess)) {
        mask |= RSI_MEM_OPEN;
    }
    if (g_VirtualQuerySlot != NULL &&
        EnsureSlot(g_VirtualQuerySlot, (PVOID)Hook_VirtualQueryEx)) {
        mask |= RSI_MEM_QUERY;
    }
    if (g_NtReadSlot != NULL &&
        EnsureSlot(g_NtReadSlot, (PVOID)Hook_NtReadVirtualMemory)) {
        mask |= RSI_MEM_READ;
    }

    ReportMemoryObserverMask(Engine, mask);
}

/*
 * (Re)install the __rsignal detour. mpengine.dll is unloaded and reloaded by
 * MpSvc (engine refresh/idle unload), which drops the inline patch and can
 * even remap the module at a different base. The saved prologue is compared
 * with the code now at the export: if it matches, the module is fresh again
 * and the hook has to be re-attached.
 */
static BOOL
TryInstallHook(
    _In_ HMODULE Engine)
{
    PFN___rsignal target;
    BYTE          prologue[sizeof(g_HookedPrologue)];
    HANDLE        threadHandles[MAX_ENLISTED_THREADS];
    DWORD         threadCount = 0;
    LONG          error;

    target = (PFN___rsignal)GetProcAddress(Engine, MPENGINE_HOOK_EXPORT);
    if (target == NULL ||
        CopyTargetMemory((const void*)target, prologue, sizeof(prologue)) !=
            sizeof(prologue)) {
        return FALSE;
    }

    if (g_HookedPrologueValid && g_HookedTarget == (PVOID)target &&
        memcmp(prologue, g_HookedPrologue, sizeof(prologue)) != 0) {
        return TRUE;                 /* our trampoline is still in place */
    }

    /*
     * A failed install (ACG re-enabled, code pages protected) is retried, but
     * slowly: every attempt suspends the whole process to enlist its threads.
     */
    if (g_NextInstallAttempt != 0 && GetTickCount64() < g_NextInstallAttempt) {
        return FALSE;
    }

    memcpy(g_HookedPrologue, prologue, sizeof(g_HookedPrologue));
    g_HookedPrologueValid = TRUE;
    g_HookedTarget = (PVOID)target;
    g_Real__rsignal = target;

    error = DetourTransactionBegin();
    if (error != NO_ERROR) {
        DiagLog("re-hook: DetourTransactionBegin = %ld", (long)error);
        g_NextInstallAttempt = GetTickCount64() + RSI_HOOK_RETRY_MS;
        return FALSE;
    }
    threadCount = EnlistProcessThreads(threadHandles, MAX_ENLISTED_THREADS);
    error = DetourAttach((PVOID*)&g_Real__rsignal, (PVOID)Hook___rsignal);
    if (error == NO_ERROR) {
        error = DetourTransactionCommit();
    } else {
        (void)DetourTransactionAbort();
    }
    ReleaseThreadHandles(threadHandles, threadCount);

    DiagLog("hook install @ %p -> %ld", (void*)target, (long)error);
    if (error != NO_ERROR) {
        g_NextInstallAttempt = GetTickCount64() + RSI_HOOK_RETRY_MS;
        EmitStatusErrorV((ULONG)error, "re-hook %s!%s failed: %ld",
                         MPENGINE_DLL_NAME, MPENGINE_HOOK_EXPORT, (long)error);
        return FALSE;
    }
    g_NextInstallAttempt = 0;

    EmitStatusInfoV(0, "Detours hook installed: %s!%s -> 0x%p",
                    MPENGINE_DLL_NAME, MPENGINE_HOOK_EXPORT,
                    (void*)Hook___rsignal);
    return TRUE;
}

/*
 * Keeps the hooks alive for the life of the process. The engine mapping and
 * its instance object can be replaced at any time, so both are resolved from
 * the current module every poll instead of being cached at injection time.
 */
static DWORD WINAPI
HookMaintenanceThread(
    _In_ LPVOID Parameter)
{
    (void)Parameter;

    for (;;) {
        HMODULE engine = GetModuleHandleW(MPENGINE_DLL_WNAME);

        if (engine != NULL) {
            g_EngineModuleBase = (PVOID)engine;
            (void)TryInstallHook(engine);
            ArmEngineLog((const BYTE*)engine);
            ArmMemoryObservers(engine);
        } else {
            g_EngineModuleBase = NULL;
        }

        Sleep(RSI_ENGINE_LOG_POLL_MS);
    }
}

/* ------------------------------------------------------------------------- */
/* Hook                                                                      */
/* ------------------------------------------------------------------------- */

static ULONG WINAPI
Hook___rsignal(
    _In_ PVOID Context,
    _In_ int Signal,
    _In_ PVOID Data,
    _In_ int Flags)
{
    PFN___rsignal real = g_Real__rsignal;
    ULONG status;
    LONG  call;

    if (real == NULL) {
        return 0;
    }

    /*
     * If an ETW write itself signals on this thread, forward without
     * emitting. This also bounds recursion if the provider is re-entered.
     */
    if (InterlockedIncrement(&g_InHook) > 1) {
        InterlockedDecrement(&g_InHook);
        return real(Context, Signal, Data, Flags);
    }

    call = InterlockedIncrement(&g_HookCalls);

    if (TraceLoggingProviderEnabled(g_hRSignalProvider, 0, 0)) {
        EmitCall(Context, Signal, Data, Flags, call);
    }

    status = real(Context, Signal, Data, Flags);

    if (TraceLoggingProviderEnabled(g_hRSignalProvider, 0, 0)) {
        EmitReturn(call, status);
    }

    InterlockedDecrement(&g_InHook);
    return status;
}

/* ------------------------------------------------------------------------- */
/* Detours setup                                                             */
/* ------------------------------------------------------------------------- */

static HMODULE
WaitForModule(
    _In_ LPCWSTR Name,
    _In_ DWORD TimeoutMs)
{
    ULONGLONG start = GetTickCount64();

    for (;;) {
        HMODULE module = GetModuleHandleW(Name);

        if (module != NULL) {
            return module;
        }
        if (GetTickCount64() - start >= TimeoutMs) {
            return NULL;
        }
        Sleep(100);
    }
}

/*
 * Tell Detours about every thread in this process before committing. Without
 * this, a thread that is currently executing inside the function being
 * patched can execute a half-written prologue while Detours updates it.
 *
 * DetourUpdateThread suspends each thread and stores the handle for the
 * transaction; the commit (or abort) resumes it. The caller must therefore
 * keep these handles open until the transaction has finished.
 */

static DWORD
EnlistProcessThreads(
    _Out_writes_to_(Capacity, return) HANDLE* Handles,
    _In_ DWORD Capacity)
{
    HANDLE        snapshot;
    THREADENTRY32 entry;
    DWORD         self = GetCurrentThreadId();
    DWORD         enlisted = 0;
    DWORD         skipped = 0;

    snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        EmitStatusErrorV(GetLastError(),
                         "CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD) failed; "
                         "only the current thread is covered");
        return 0;
    }

    entry.dwSize = sizeof(entry);
    if (Thread32First(snapshot, &entry)) {
        do {
            HANDLE thread;

            if (entry.th32OwnerProcessID != GetCurrentProcessId() ||
                entry.th32ThreadID == self) {
                continue;
            }
            if (enlisted >= Capacity) {
                ++skipped;
                continue;
            }

            thread = OpenThread(THREAD_SUSPEND_RESUME |
                                    THREAD_GET_CONTEXT |
                                    THREAD_SET_CONTEXT |
                                    THREAD_QUERY_INFORMATION,
                                FALSE,
                                entry.th32ThreadID);
            if (thread == NULL) {
                ++skipped;
                continue;
            }

            if (DetourUpdateThread(thread) == NO_ERROR) {
                Handles[enlisted++] = thread;
            } else {
                CloseHandle(thread);
                ++skipped;
            }
        } while (Thread32Next(snapshot, &entry));
    }

    CloseHandle(snapshot);
    EmitStatusInfoV(0, "Detours enlisted %lu thread(s), skipped %lu",
                    (unsigned long)enlisted, (unsigned long)skipped);
    return enlisted;
}

static void
ReleaseThreadHandles(
    _In_reads_(Count) HANDLE* Handles,
    _In_ DWORD Count)
{
    DWORD i;

    for (i = 0; i < Count; ++i) {
        CloseHandle(Handles[i]);
    }
}

static DWORD WINAPI
InstallHooksThread(
    _In_ LPVOID Parameter)
{
    HMODULE engine;
    LONG    error;
    HRESULT registered;
    PVOID   target;
    BYTE    prologue[sizeof(g_HookedPrologue)];
    char    host[MAX_PATH] = { 0 };
    HANDLE  threadHandles[MAX_ENLISTED_THREADS];
    DWORD   threadCount = 0;

    (void)Parameter;

    DiagLog("install thread start");

    /*
     * Register before anything else so that even early failures are visible
     * to the listener. TraceLoggingRegister must not be called from DllMain;
     * this worker thread makes it safe.
     */
    registered = TraceLoggingRegister(g_hRSignalProvider);
    DiagLog("TraceLoggingRegister hr=0x%08lX", (unsigned long)registered);
    if (SUCCEEDED(registered)) {
        InterlockedExchange(&g_ProviderRegistered, 1);
    }

    /*
     * No-op unless the process was started through DetourCreateProcessWithDll*.
     * It is harmless for a LoadLibrary-injected payload and makes the DLL
     * reusable with Detours' own injection helper.
     */
    (void)DetourRestoreAfterWith();

    (void)GetModuleFileNameA(NULL, host, sizeof(host));
    EmitStatusInfoV(0, "payload attached: pid=%lu host=%s",
                    (unsigned long)GetCurrentProcessId(), host);
    DiagLog("payload attached, waiting for %s", MPENGINE_DLL_NAME);

    engine = WaitForModule(MPENGINE_DLL_WNAME, MPENGINE_MODULE_WAIT_MS);
    DiagLog("%s = %p", MPENGINE_DLL_NAME, (void*)engine);
    if (engine == NULL) {
        EmitStatusErrorV(0, "%s is not loaded after %lu ms; no hook installed",
                         MPENGINE_DLL_NAME,
                         (unsigned long)MPENGINE_MODULE_WAIT_MS);
        return 0;
    }
    EmitStatusInfoV(0, "%s @ 0x%p", MPENGINE_DLL_NAME, (void*)engine);

    /*
     * The memory observers are data patches, not Detours code patches, so
     * install them before the __rsignal transaction: they keep working when
     * the target has ACG and the Detours commit is refused.  The maintenance
     * thread re-arms them after an engine reload.
     */
    ArmMemoryObservers(engine);

    g_Real__rsignal = (PFN___rsignal)
        GetProcAddress(engine, MPENGINE_HOOK_EXPORT);
    DiagLog("GetProcAddress(%s) = %p (err=%lu)", MPENGINE_HOOK_EXPORT,
            (void*)g_Real__rsignal, (unsigned long)GetLastError());
    if (g_Real__rsignal == NULL) {
        EmitStatusErrorV(GetLastError(), "export %s!%s not found",
                         MPENGINE_DLL_NAME, MPENGINE_HOOK_EXPORT);
        return 0;
    }
    EmitStatusInfoV(0, "target %s!%s @ 0x%p",
                    MPENGINE_DLL_NAME, MPENGINE_HOOK_EXPORT,
                    (void*)g_Real__rsignal);

    /*
     * Remember the pristine prologue before Detours overwrites it. The
     * maintenance thread compares it with the code at the export to detect a
     * module reload (the engine remaps itself when it is refreshed).
     */
    target = (PVOID)g_Real__rsignal;
    (void)CopyTargetMemory(target, prologue, sizeof(prologue));

    error = DetourTransactionBegin();
    DiagLog("DetourTransactionBegin = %ld", (long)error);
    if (error != NO_ERROR) {
        EmitStatusErrorV((ULONG)error, "DetourTransactionBegin failed");
        return 0;
    }

    threadCount = EnlistProcessThreads(threadHandles, MAX_ENLISTED_THREADS);
    DiagLog("enlisted %lu threads", (unsigned long)threadCount);

    error = DetourAttach((PVOID*)&g_Real__rsignal,
                         (PVOID)Hook___rsignal);
    DiagLog("DetourAttach = %ld", (long)error);
    if (error != NO_ERROR) {
        EmitStatusErrorV((ULONG)error, "DetourAttach(%s) failed",
                         MPENGINE_HOOK_EXPORT);
        (void)DetourTransactionAbort();
        ReleaseThreadHandles(threadHandles, threadCount);
        return 0;
    }

    error = DetourTransactionCommit();
    DiagLog("DetourTransactionCommit = %ld (Win32 %lu)", (long)error,
            (unsigned long)GetLastError());
    ReleaseThreadHandles(threadHandles, threadCount);
    if (error != NO_ERROR) {
        ULONG lastError = GetLastError();

        EmitStatusErrorV((ULONG)error, "DetourTransactionCommit failed: %ld "
                         "(Win32 %lu)", (long)error, (unsigned long)lastError);
        if (error == ERROR_DYNAMIC_CODE_BLOCKED) {
            EmitStatusErrorV(0, "the target has Arbitrary Code Guard (ACG); it "
                             "must be cleared before Detours can patch mpengine "
                             "code");
        } else if (error == ERROR_ACCESS_DENIED) {
            EmitStatusErrorV(0, "access denied; PPL/signature mitigations may "
                             "still be active, or the code pages are protected");
        }
        return 0;
    }

    EmitStatusInfoV(0, "Detours hook installed: %s!%s -> 0x%p",
                    MPENGINE_DLL_NAME, MPENGINE_HOOK_EXPORT,
                    (void*)Hook___rsignal);
    memcpy(g_HookedPrologue, prologue, sizeof(g_HookedPrologue));
    g_HookedPrologueValid = TRUE;
    g_HookedTarget = target;

    /*
     * The engine mapping and its instance object can be replaced at any time
     * (engine refresh / idle unload). One thread keeps both hooks installed
     * and also arms the engine log slot once the instance exists.
     */
    {
        HANDLE maintenance = CreateThread(NULL, 0, HookMaintenanceThread,
                                          NULL, 0, NULL);

        if (maintenance != NULL) {
            CloseHandle(maintenance);
        } else {
            EmitStatusErrorV(GetLastError(),
                             "hook maintenance thread could not be created");
        }
    }

    return 0;
}

/* ------------------------------------------------------------------------- */
/* DLL entry point                                                           */
/* ------------------------------------------------------------------------- */

BOOL WINAPI
DllMain(
    _In_ HINSTANCE Instance,
    _In_ DWORD Reason,
    _In_ LPVOID Reserved)
{
    switch (Reason) {
    case DLL_PROCESS_ATTACH:
    {
        HANDLE thread;

        DisableThreadLibraryCalls(Instance);
        DiagLog("DllMain attach pid=%lu",
                (unsigned long)GetCurrentProcessId());

        /*
         * Do not call Detours or TraceLoggingRegister from DllMain. The
         * loader lock is held here; a worker thread keeps both out of the
         * loader path.
         */
        thread = CreateThread(NULL, 0, InstallHooksThread, NULL, 0, NULL);
        if (thread != NULL) {
            DiagLog("worker thread %p created", (void*)thread);
            CloseHandle(thread);
        } else {
            DiagLog("CreateThread failed err=%lu",
                    (unsigned long)GetLastError());
        }
        break;
    }

    case DLL_PROCESS_DETACH:
        /*
         * FreeLibrary/Detach is not supported: the Detours trampoline lives in
         * this DLL, so unloading it while a hook is installed would leave
         * mpengine calling into unmapped memory. Process termination removes
         * both safely. Still unregister the provider: ETW keeps a callback
         * into this module.
         */
        if (InterlockedExchange(&g_ProviderRegistered, 0) != 0) {
            TraceLoggingUnregister(g_hRSignalProvider);
        }
        (void)Reserved;
        break;

    default:
        break;
    }

    return TRUE;
}
