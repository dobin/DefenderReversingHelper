/*
 * RSignalEtwListener.cpp -- real-time consumer for the mpengine __rsignal hook.
 *
 * Subscribes to the TraceLogging provider emitted by
 * dll_injector\detours_payload\MpEngineHook.c (g_hRSignalProvider) and renders
 * its events on the console. The contract (provider GUID, event names and
 * field names) lives in shared\MpEngineEtw.h.
 *
 * Besides RSignalCall/RSignalReturn/Status, the provider carries EngineLog
 * and EngineTrace: the engine's own text lines ("Engine: ...", "Engine-HIPS:
 * ...") and the structured records (deferred scan requests, telemetry)
 * captured by the payload's engine trace-callback hook.
 *
 * Example:
 *
 *     rsignal_etw_listener.exe --out rsignal.txt
 *     rsignal_etw_listener.exe --dump --dump-bytes 1024
 *
 * By default each call prints one line with signal, flags, the Data address
 * and the captured data size. --dump adds a hex+ASCII dump.
 * Run it elevated (or from an account in "Performance Log Users"); creating a
 * real-time trace session otherwise fails with ERROR_ACCESS_DENIED. The
 * listener can start before or after the payload registers its provider.
 */

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <windows.h>
#include <evntrace.h>

#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <mutex>
#include <string>
#include <vector>
#include <atomic>

#include "krabs.hpp"
#include "MpEngineEtw.h"

namespace {

struct Options {
    std::wstring   session = MPENGINE_ETW_SESSION_NAME;
    std::wstring   outPath;
    std::wstring   outBinPath;           /* optional framed CALL payload file */
    bool           dump = false;         /* default: sizes only */
    bool           binaryFormat = false; /* --out stores framed binary CALL payloads */
    bool           jsonlFormat = false;  /* --out stores one JSON object per event */
    bool           includeContext = false; /* add ContextAddress/Length/Hex to jsonl */
    size_t         dumpBytes = 512;      /* 0 = print everything */
    uint64_t       maxEvents = 0;        /* 0 = unlimited */
    bool           showStatus = true;
    bool           showEngineLog = true;
    bool           showEngineTrace = true;
    bool           showEngineMem = true;
};

Options                g_options;
FILE*                  g_out = nullptr;
FILE*                  g_outBin = nullptr;
std::mutex             g_outputLock;
std::atomic<uint64_t>  g_eventCount{ 0 };
std::atomic<bool>      g_stopRequested{ false };
std::atomic<bool>      g_payloadSeen{ false };
bool                   g_helpRequested = false;

/*
 * krabs creates the trace with Wnode.ClientContext = 1 (QPC), so
 * EVENT_HEADER.TimeStamp is in QPC ticks, not FILETIME units. Anchor QPC to
 * the wall clock once at startup so events can be rendered as local time.
 */
LARGE_INTEGER          g_qpcBase = {};
ULONGLONG              g_wallClockBase = 0;
ULONGLONG              g_qpcFrequency = 0;

/* ------------------------------------------------------------------------- */
/* Output                                                                    */
/* ------------------------------------------------------------------------- */

std::string
Format(
    _In_ _Printf_format_string_ const char* FormatText,
    ...)
{
    char    buffer[4096];
    va_list arguments;

    va_start(arguments, FormatText);
    _vsnprintf_s(buffer, sizeof(buffer), _TRUNCATE, FormatText, arguments);
    va_end(arguments);

    return std::string(buffer);
}

void
Print(
    _In_ const std::string& Text)
{
    std::lock_guard<std::mutex> lock(g_outputLock);

    fputs(Text.c_str(), stdout);
    fflush(stdout);

    /* jsonl output must stay parseable, so only PrintJson writes there. */
    if (g_out != nullptr && !g_options.binaryFormat &&
        !g_options.jsonlFormat) {
        fputs(Text.c_str(), g_out);
        fflush(g_out);
    }
}

/* Write a JSON record to stdout and to the --out file. */
void
PrintJson(
    _In_ const std::string& Text)
{
    std::lock_guard<std::mutex> lock(g_outputLock);

    fputs(Text.c_str(), stdout);
    fflush(stdout);

    if (g_out != nullptr) {
        fputs(Text.c_str(), g_out);
        fflush(g_out);
    }
}

bool
WriteBinaryEvent(
    _In_ FILE* Target,
    _In_ uint32_t SignalId,
    _In_reads_bytes_(PayloadSize) const BYTE* Payload,
    _In_ uint32_t PayloadSize)
{
    if (Target == nullptr) {
        return false;
    }

    /* Encode fields explicitly so the on-disk header is always little-endian. */
    BYTE header[10] = {
        0x45, 0x56,
        (BYTE)SignalId, (BYTE)(SignalId >> 8),
        (BYTE)(SignalId >> 16), (BYTE)(SignalId >> 24),
        (BYTE)PayloadSize, (BYTE)(PayloadSize >> 8),
        (BYTE)(PayloadSize >> 16), (BYTE)(PayloadSize >> 24)
    };

    std::lock_guard<std::mutex> lock(g_outputLock);
    if (fwrite(header, sizeof(header), 1, Target) != 1 ||
        (PayloadSize != 0 && fwrite(Payload, PayloadSize, 1, Target) != 1)) {
        return false;
    }

    return fflush(Target) == 0;
}

/* Wall-clock FILETIME for an event, or 0 when the QPC anchor is not ready. */
uint64_t
WallClockTimestamp(
    _In_ const EVENT_RECORD& Record)
{
    ULONGLONG ticks = (ULONGLONG)Record.EventHeader.TimeStamp.QuadPart;

    if (g_qpcFrequency == 0 || g_wallClockBase == 0 ||
        ticks < (ULONGLONG)g_qpcBase.QuadPart) {
        return 0;
    }

    return g_wallClockBase +
           ((ticks - (ULONGLONG)g_qpcBase.QuadPart) * 10000000ull) /
               g_qpcFrequency;
}

std::string
FormatTimestamp(
    _In_ const EVENT_RECORD& Record)
{
    FILETIME   fileTime;
    FILETIME   localTime;
    SYSTEMTIME systemTime;
    ULONGLONG  timestamp = WallClockTimestamp(Record);

    if (timestamp == 0) {
        GetLocalTime(&systemTime);
    } else {
        fileTime.dwLowDateTime = (DWORD)timestamp;
        fileTime.dwHighDateTime = (DWORD)(timestamp >> 32);

        if (FileTimeToLocalFileTime(&fileTime, &localTime) &&
            FileTimeToSystemTime(&localTime, &systemTime)) {
            /* Converted above. */
        } else {
            GetLocalTime(&systemTime);
        }
    }

    return Format("%04u-%02u-%02u %02u:%02u:%02u.%03u",
                  systemTime.wYear, systemTime.wMonth, systemTime.wDay,
                  systemTime.wHour, systemTime.wMinute, systemTime.wSecond,
                  systemTime.wMilliseconds);
}

int
HexNibble(
    _In_ char Value)
{
    if (Value >= '0' && Value <= '9') {
        return Value - '0';
    }
    if (Value >= 'A' && Value <= 'F') {
        return Value - 'A' + 10;
    }
    if (Value >= 'a' && Value <= 'f') {
        return Value - 'a' + 10;
    }
    return -1;
}

bool
HexDecode(
    _In_ const std::string& Hex,
    _Out_ std::vector<BYTE>& Bytes)
{
    Bytes.clear();

    if ((Hex.size() & 1) != 0) {
        return false;
    }

    Bytes.reserve(Hex.size() / 2);

    for (size_t i = 0; i < Hex.size(); i += 2) {
        int high = HexNibble(Hex[i]);
        int low = HexNibble(Hex[i + 1]);

        if (high < 0 || low < 0) {
            Bytes.clear();
            return false;
        }

        Bytes.push_back((BYTE)((high << 4) | low));
    }

    return true;
}

void
DumpBytes(
    _In_ std::string& Text,
    _In_ const char* Label,
    _In_ const std::vector<BYTE>& Bytes,
    _In_ size_t Limit)
{
    size_t shown = Bytes.size();

    if (Limit != 0 && shown > Limit) {
        shown = Limit;
    }

    Text += Format("    %s: %llu byte(s)%s\n",
                   Label,
                   (unsigned long long)Bytes.size(),
                   shown < Bytes.size() ? ", truncated" : "");

    for (size_t offset = 0; offset < shown; offset += 16) {
        char   hex[16 * 3 + 1] = { 0 };
        char   ascii[16 + 1] = { 0 };
        size_t count = shown - offset;

        if (count > 16) {
            count = 16;
        }

        for (size_t i = 0; i < count; ++i) {
            BYTE value = Bytes[offset + i];

            _snprintf_s(hex + i * 3, sizeof(hex) - i * 3, _TRUNCATE,
                        "%02X ", value);
            ascii[i] = (value >= 0x20 && value <= 0x7E) ? (char)value : '.';
        }

        Text += Format("      %04llX  %-47s  |%s|\n",
                       (unsigned long long)offset, hex, ascii);
    }
}

/* ------------------------------------------------------------------------- */
/* Trace session control                                                     */
/* ------------------------------------------------------------------------- */

/*
 * Stop the real-time session. ControlTrace is safe to call from another thread
 * (it makes ProcessTrace return); CloseTrace is not, which is why cleanup
 * stays in the trace destructor.
 */
void
StopSession(void)
{
    struct TraceInformation {
        EVENT_TRACE_PROPERTIES properties;
        wchar_t                name[1024];
    } information = {};

    information.properties.Wnode.BufferSize = sizeof(information);
    information.properties.LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);

    ControlTraceW(0, g_options.session.c_str(),
                  &information.properties, EVENT_TRACE_CONTROL_STOP);
}

DWORD WINAPI
StopSessionThread(
    _In_ PVOID Parameter)
{
    (void)Parameter;
    StopSession();
    return 0;
}

void
RequestSessionStop(void)
{
    if (!g_stopRequested.exchange(true)) {
        StopSession();
    }
}

/*
 * The event callback runs inside ProcessTrace, so do not call ControlTrace
 * from there; hand it to a worker thread instead.
 */
void
RequestSessionStopAsync(void)
{
    if (!g_stopRequested.exchange(true)) {
        QueueUserWorkItem(StopSessionThread, nullptr, WT_EXECUTEDEFAULT);
    }
}

BOOL WINAPI
ConsoleHandler(
    _In_ DWORD ControlType)
{
    switch (ControlType) {
    case CTRL_C_EVENT:
    case CTRL_BREAK_EVENT:
    case CTRL_CLOSE_EVENT:
    case CTRL_SHUTDOWN_EVENT:
        RequestSessionStop();
        return TRUE;
    default:
        return FALSE;
    }
}

/* ------------------------------------------------------------------------- */
/* Event handling                                                            */
/* ------------------------------------------------------------------------- */

std::string
JsonEscape(
    _In_ const std::string& Text)
{
    std::string escaped;

    escaped.reserve(Text.size() + 8);

    for (char value : Text) {
        switch (value) {
        case '"':  escaped += "\\\""; break;
        case '\\': escaped += "\\\\"; break;
        case '\n': escaped += "\\n";  break;
        case '\r': escaped += "\\r";  break;
        case '\t': escaped += "\\t";  break;
        default:
            if ((unsigned char)value < 0x20) {
                escaped += Format("\\u%04x", (unsigned int)(unsigned char)value);
            } else {
                escaped += value;
            }
            break;
        }
    }

    return escaped;
}

void
HandleStatusEvent(
    _In_ krabs::parser& Parser,
    _In_ const EVENT_RECORD& Record,
    _In_ const std::string& Prefix)
{
    uint32_t    code = 0;
    std::string message;

    Parser.try_parse(L"Code", code);
    Parser.try_parse(L"Message", message);

    if (!g_options.showStatus && !g_options.jsonlFormat) {
        return;
    }

    const char* level = "info";
    if (Record.EventHeader.EventDescriptor.Level == TRACE_LEVEL_ERROR) {
        level = "error";
    } else if (Record.EventHeader.EventDescriptor.Level == TRACE_LEVEL_WARNING) {
        level = "warn";
    }

    if (g_options.jsonlFormat) {
        PrintJson(Format("{\"k\":\"status\",\"ts\":%llu,\"pid\":%lu,\"tid\":%lu,"
                         "\"level\":\"%s\",\"code\":%lu,\"message\":\"%s\"}\n",
                         (unsigned long long)WallClockTimestamp(Record),
                         (unsigned long)Record.EventHeader.ProcessId,
                         (unsigned long)Record.EventHeader.ThreadId,
                         level,
                         (unsigned long)code,
                         JsonEscape(message).c_str()));
        return;
    }

    Print(Format("%s STATUS(%s) code=%lu (0x%08lX) message=\"%s\"\n",
                 Prefix.c_str(), level, (unsigned long)code,
                 (unsigned long)code, message.c_str()));
}

void
TrimTrailingWhitespace(
    _Inout_ std::string& Text)
{
    while (!Text.empty()) {
        char value = Text.back();

        if (value != '\r' && value != '\n' && value != ' ' && value != '\t') {
            break;
        }
        Text.pop_back();
    }
}

/*
 * EngineLog is produced by the payload's engine trace-callback hook, not by
 * the __rsignal path. It carries the engine's own text lines ("Engine: ...",
 * "Engine-HIPS: ...") as Module + Message, so they render verbatim.
 */
void
HandleEngineLogEvent(
    _In_ krabs::parser& Parser,
    _In_ const EVENT_RECORD& Record,
    _In_ const std::string& Prefix)
{
    uint32_t    sequence = 0;
    uint32_t    kind = 0;
    uint32_t    level = 0;
    std::string module;
    std::string message;

    Parser.try_parse(L"SeqNum", sequence);
    Parser.try_parse(L"Kind", kind);
    Parser.try_parse(L"Level", level);
    (void)Parser.try_parse(L"Module", module);
    (void)Parser.try_parse(L"Message", message);

    if (!g_options.showEngineLog) {
        return;
    }

    TrimTrailingWhitespace(message);

    if (g_options.jsonlFormat) {
        PrintJson(Format("{\"k\":\"elog\",\"seq\":%lu,\"ts\":%llu,"
                         "\"pid\":%lu,\"tid\":%lu,\"kind\":\"0x%X\","
                         "\"level\":%lu,\"module\":\"%s\",\"message\":\"%s\"}\n",
                         (unsigned long)sequence,
                         (unsigned long long)WallClockTimestamp(Record),
                         (unsigned long)Record.EventHeader.ProcessId,
                         (unsigned long)Record.EventHeader.ThreadId,
                         (unsigned int)kind,
                         (unsigned long)level,
                         JsonEscape(module).c_str(),
                         JsonEscape(message).c_str()));
        return;
    }

    if (message.empty()) {
        /* Older payloads carried structured kinds as empty EngineLog events;
         * current payloads use EngineTrace for those. */
        Print(Format("%s engine record kind=0x%X\n",
                     Prefix.c_str(), (unsigned int)kind));
        return;
    }

    if (module.empty()) {
        Print(Format("%s engine log: %s\n",
                     Prefix.c_str(), message.c_str()));
    } else {
        Print(Format("%s engine log: %s: %s\n",
                     Prefix.c_str(), module.c_str(), message.c_str()));
    }
}

const char*
EngineTraceKindLabel(
    _In_ uint32_t Kind)
{
    switch (Kind) {
    case 0x19:
        return "text log";
    case 0x28:
        return "host work item";
    case 0x0B:
        return "host event";
    case 0x13:
    case 0x15:
        return "engine notification";
    case 0x18:
        return "host event (telemetry)";
    case 0x1A:
    case 0x37:
        return "moac entry";
    case 0x1C:
        return "moac lookup (legacy)";
    case 0x1F:
        return "moac v2 attempt";
    case 0x22:
        return "host data read";
    case 0x23:
        return "host data write";
    case 0x25:
        return "scan stage";
    case 0x2A:
        return "notification";
    case 0x38:
        return "moac lookup";
    case 0x3D:
        return "host config query";
    case 0x3E:
        return "host config release";
    case 0x44:
        return "rtp update";
    case 0x52:
        return "remediation config";
    case 0x1E:
    case 0x20:
    case 0x46:
    case 0x4C:
    case 0x62:
        return "engine telemetry";
    default:
        return "engine record";
    }
}

/*
 * EngineTrace is produced by the payload's engine trace-callback hook. Kind
 * 0x28 is the engine's deferred scan request; the other kinds are structured
 * telemetry whose payload is attached as bounded hex for offline decoding.
 */
void
HandleEngineTraceEvent(
    _In_ krabs::parser& Parser,
    _In_ const EVENT_RECORD& Record,
    _In_ const std::string& Prefix)
{
    uint32_t    sequence = 0;
    uint32_t    kind = 0;
    uint32_t    opcode = 0;
    uint32_t    flags = 0;
    uint32_t    version = 0;
    uint32_t    id = 0;
    uint32_t    payloadLength = 0;
    uint64_t    callerRva = 0;
    uint64_t    engineTime = 0;
    std::string kindName;
    std::string target;
    std::string detail;
    std::string payloadHex;

    if (!g_options.showEngineTrace) {
        return;
    }

    Parser.try_parse(L"SeqNum", sequence);
    Parser.try_parse(L"Kind", kind);
    Parser.try_parse(L"CallerRva", callerRva);
    Parser.try_parse(L"EngineTime", engineTime);
    Parser.try_parse(L"Opcode", opcode);
    Parser.try_parse(L"Flags", flags);
    Parser.try_parse(L"Version", version);
    Parser.try_parse(L"Id", id);
    Parser.try_parse(L"PayloadLength", payloadLength);
    (void)Parser.try_parse(L"KindName", kindName);
    (void)Parser.try_parse(L"Target", target);
    (void)Parser.try_parse(L"Detail", detail);
    (void)Parser.try_parse(L"PayloadHex", payloadHex);

    std::vector<BYTE> payload;
    if (!payloadHex.empty()) {
        (void)HexDecode(payloadHex, payload);
    }

    if (g_options.jsonlFormat) {
        PrintJson(Format("{\"k\":\"trace\",\"seq\":%lu,\"ts\":%llu,"
                         "\"pid\":%lu,\"tid\":%lu,\"kind\":\"0x%X\","
                         "\"caller_rva\":%llu,\"kind_name\":\"%s\","
                         "\"target\":\"%s\",\"detail\":\"%s\","
                         "\"opcode\":%lu,\"flags\":%lu,"
                         "\"version\":%lu,\"id\":%lu,\"payload_len\":%lu,"
                         "\"payload_hex\":\"%s\",\"engine_time\":%llu}\n",
                         (unsigned long)sequence,
                         (unsigned long long)WallClockTimestamp(Record),
                         (unsigned long)Record.EventHeader.ProcessId,
                         (unsigned long)Record.EventHeader.ThreadId,
                         (unsigned int)kind,
                         (unsigned long long)callerRva,
                         JsonEscape(kindName).c_str(),
                         JsonEscape(target).c_str(),
                         JsonEscape(detail).c_str(),
                         (unsigned long)opcode,
                         (unsigned long)flags,
                         (unsigned long)version,
                         (unsigned long)id,
                         (unsigned long)payloadLength,
                         payloadHex.c_str(),
                         (unsigned long long)engineTime));
        return;
    }

    if (kind == 0x18) {
        Print(Format("%s engine event : type=0x%lX name=%s value=%s "
                     "version=%lu id=0x%02lX detail=%s caller=+0x%llX\n",
                     Prefix.c_str(),
                     (unsigned long)opcode,
                     kindName.empty() ? "?" : kindName.c_str(),
                     target.empty() ? "?" : target.c_str(),
                     (unsigned long)version,
                     (unsigned long)id,
                     detail.empty() ? "-" : detail.c_str(),
                     (unsigned long long)callerRva));
        return;
    }

    if (kind == 0x28) {
        if (opcode == 0x22) {
            Print(Format("%s engine scan request : kind=%s target=%s "
                         "id=0x%02lX opcode=0x22 version=%lu flags=0x%lX "
                         "caller=+0x%llX\n",
                         Prefix.c_str(),
                         kindName.empty() ? "?" : kindName.c_str(),
                         target.empty() ? "?" : target.c_str(),
                         (unsigned long)id,
                         (unsigned long)version,
                         (unsigned long)flags,
                         (unsigned long long)callerRva));
        } else {
            Print(Format("%s engine work item : opcode=0x%lX flags=0x%lX "
                         "caller=+0x%llX\n",
                         Prefix.c_str(),
                         (unsigned long)opcode,
                         (unsigned long)flags,
                         (unsigned long long)callerRva));
        }
        return;
    }

    if (kind == 0x25) {
        Print(Format("%s engine scan stage : %s caller=+0x%llX\n",
                     Prefix.c_str(),
                     target.empty() ? "?" : target.c_str(),
                     (unsigned long long)callerRva));
        return;
    }

    std::string text = Format("%s engine trace : kind=0x%X (%s) caller=+0x%llX",
                              Prefix.c_str(),
                              (unsigned int)kind,
                              EngineTraceKindLabel(kind),
                              (unsigned long long)callerRva);

    if (!kindName.empty() && !target.empty()) {
        text += Format(" kind_name=%s target=%s",
                       kindName.c_str(),
                       target.c_str());
    } else if (!target.empty()) {
        text += Format(" target=%s", target.c_str());
    }
    if (!detail.empty()) {
        text += Format(" detail=%s", detail.c_str());
    }

    size_t shownBytes = payload.empty() ? payloadLength : payload.size();

    if (shownBytes == 0) {
        text += "\n";
        Print(text);
        return;
    }

    size_t previewChars = payloadHex.size() < 64 ? payloadHex.size() : 64;
    text += Format(" payload=%llu byte(s) hex=%s%s\n",
                   (unsigned long long)shownBytes,
                   payloadHex.substr(0, previewChars).c_str(),
                   previewChars < payloadHex.size() ? "..." : "");

    if (g_options.dump && !payload.empty()) {
        DumpBytes(text, "payload", payload, g_options.dumpBytes);
    }

    Print(text);
}

/*
 * EngineMem is produced by the payload's process-memory observers.  The engine
 * calls OpenProcess / VirtualQueryEx through its kernel32 IAT and
 * NtReadVirtualMemoryEx through its own resolved pointer; Op says which one,
 * and the remaining fields mirror what the engine passed and what the OS
 * returned.
 */
void
HandleEngineMemEvent(
    _In_ krabs::parser& Parser,
    _In_ const EVENT_RECORD& Record,
    _In_ const std::string& Prefix)
{
    uint32_t    sequence = 0;
    uint32_t    targetPid = 0;
    uint32_t    status = 0;
    uint32_t    state = 0;
    uint32_t    protect = 0;
    uint64_t    handle = 0;
    uint64_t    base = 0;
    uint64_t    size = 0;
    uint64_t    access = 0;
    uint64_t    transferred = 0;
    std::string op;

    if (!g_options.showEngineMem) {
        return;
    }

    Parser.try_parse(L"SeqNum", sequence);
    Parser.try_parse(L"Pid", targetPid);
    Parser.try_parse(L"Handle", handle);
    Parser.try_parse(L"Base", base);
    Parser.try_parse(L"Size", size);
    Parser.try_parse(L"Access", access);
    Parser.try_parse(L"Status", status);
    Parser.try_parse(L"Transferred", transferred);
    Parser.try_parse(L"State", state);
    Parser.try_parse(L"Protect", protect);
    (void)Parser.try_parse(L"Op", op);

    if (g_options.jsonlFormat) {
        PrintJson(Format("{\"k\":\"mem\",\"seq\":%lu,\"ts\":%llu,"
                         "\"pid\":%lu,\"tid\":%lu,\"op\":\"%s\","
                         "\"target_pid\":%lu,\"handle\":%llu,\"base\":%llu,"
                         "\"size\":%llu,\"access\":%llu,\"status\":%lu,"
                         "\"transferred\":%llu,\"state\":%lu,"
                         "\"protect\":%lu}\n",
                         (unsigned long)sequence,
                         (unsigned long long)WallClockTimestamp(Record),
                         (unsigned long)Record.EventHeader.ProcessId,
                         (unsigned long)Record.EventHeader.ThreadId,
                         JsonEscape(op).c_str(),
                         (unsigned long)targetPid,
                         (unsigned long long)handle,
                         (unsigned long long)base,
                         (unsigned long long)size,
                         (unsigned long long)access,
                         (unsigned long)status,
                         (unsigned long long)transferred,
                         (unsigned long)state,
                         (unsigned long)protect));
        return;
    }

    if (op == "open") {
        Print(Format("%s engine scan open : pid=%lu access=0x%llX "
                     "status=0x%08lX\n",
                     Prefix.c_str(),
                     (unsigned long)targetPid,
                     (unsigned long long)access,
                     (unsigned long)status));
    } else if (op == "query") {
        Print(Format("%s engine scan query : target_pid=%lu handle=0x%llX "
                     "base=0x%llX size=0x%llX status=0x%08lX state=0x%lX "
                     "protect=0x%lX\n",
                     Prefix.c_str(),
                     (unsigned long)targetPid,
                     (unsigned long long)handle,
                     (unsigned long long)base,
                     (unsigned long long)size,
                     (unsigned long)status,
                     (unsigned long)state,
                     (unsigned long)protect));
    } else if (op == "read") {
        Print(Format("%s engine scan read : target_pid=%lu handle=0x%llX "
                     "base=0x%llX size=0x%llX status=0x%08lX read=0x%llX\n",
                     Prefix.c_str(),
                     (unsigned long)targetPid,
                     (unsigned long long)handle,
                     (unsigned long long)base,
                     (unsigned long long)size,
                     (unsigned long)status,
                     (unsigned long long)transferred));
    } else {
        Print(Format("%s engine scan mem : op=%s target_pid=%lu "
                     "handle=0x%llX base=0x%llX size=0x%llX status=0x%08lX\n",
                     Prefix.c_str(),
                     op.empty() ? "?" : op.c_str(),
                     (unsigned long)targetPid,
                     (unsigned long long)handle,
                     (unsigned long long)base,
                     (unsigned long long)size,
                     (unsigned long)status));
    }
}

void
HandleCallEvent(
    _In_ krabs::parser& Parser,
    _In_ const EVENT_RECORD& Record,
    _In_ const std::string& Prefix)
{
    int32_t     signal = 0;
    int32_t     flags = 0;
    uint32_t    sequence = 0;
    uint32_t    dataLength = 0;
    uint64_t    dataAddress = 0;
    std::string dataHex;
    std::vector<BYTE> dataBytes;

    Parser.try_parse(L"SeqNum", sequence);
    Parser.try_parse(L"Signal", signal);
    Parser.try_parse(L"Flags", flags);
    Parser.try_parse(L"DataAddress", dataAddress);
    Parser.try_parse(L"DataLength", dataLength);

    const bool needHex = g_options.dump || g_options.binaryFormat ||
                         !g_options.outBinPath.empty();
    bool hexOk = true;

    if (needHex) {
        hexOk = Parser.try_parse(L"DataHex", dataHex) &&
                HexDecode(dataHex, dataBytes);
    }

    if (g_options.binaryFormat) {
        if (hexOk && !WriteBinaryEvent(g_out, (uint32_t)signal,
                                       dataBytes.data(),
                                       (uint32_t)dataBytes.size())) {
            fprintf(stderr, "failed to write binary event\n");
        }
    }
    if (!g_options.outBinPath.empty()) {
        if (hexOk && !WriteBinaryEvent(g_outBin, (uint32_t)signal,
                                       dataBytes.data(),
                                       (uint32_t)dataBytes.size())) {
            fprintf(stderr, "failed to write framed event\n");
        }
    }
    if (!hexOk && !g_options.outBinPath.empty()) {
        fprintf(stderr, "seq=%lu: could not decode DataHex; frame not "
                        "written\n", (unsigned long)sequence);
    }

    /*
     * JSONL carries the same metadata the in-process recorder writes, so a
     * Defender capture and an mpclient capture have an identical sidecar and
     * the .bin frames stay the only payload source.
     */
    if (g_options.jsonlFormat) {
        std::string line = Format(
            "{\"k\":\"call\",\"i\":%lu,\"seq\":%lu,\"ts\":%llu,"
            "\"pid\":%lu,\"tid\":%lu,\"signal\":\"0x%X\",\"flags\":%lu,"
            "\"dump\":%lu,\"addr\":%llu",
            (unsigned long)sequence,
            (unsigned long)sequence,
            (unsigned long long)WallClockTimestamp(Record),
            (unsigned long)Record.EventHeader.ProcessId,
            (unsigned long)Record.EventHeader.ThreadId,
            (unsigned int)signal,
            (unsigned long)(uint32_t)flags,
            (unsigned long)dataLength,
            (unsigned long long)dataAddress);

        if (g_options.includeContext) {
            uint32_t          contextLength = 0;
            uint64_t          contextAddress = 0;
            std::string       contextHex;
            std::vector<BYTE> contextBytes;

            Parser.try_parse(L"ContextAddress", contextAddress);
            Parser.try_parse(L"ContextLength", contextLength);

            if (Parser.try_parse(L"ContextHex", contextHex)) {
                (void)HexDecode(contextHex, contextBytes);
            }

            line += Format(",\"ctx_addr\":%llu,\"ctx_len\":%lu,"
                           "\"ctx_hex\":\"%s\"",
                           (unsigned long long)contextAddress,
                           (unsigned long)contextLength,
                           contextHex.c_str());
        }

        /*
         * The request capture is already ASCII hex in the ETW field; pass it
         * through unchanged so both channels expose the same `capture_hex`
         * sidecar field.  Decoding happens in tools/rsignal-lab.
         */
        {
            std::string captureHex;

            if (Parser.try_parse(L"CaptureHex", captureHex) &&
                !captureHex.empty()) {
                line += Format(",\"capture_hex\":\"%s\"", captureHex.c_str());
            }
        }

        line += "}\n";
        PrintJson(line);
        return;
    }

    std::string text;

    if (g_options.binaryFormat) {
        text = Format(
            "%s seq=%lu CALL signal=0x%X flags=0x%X data=0x%016llX (%lu bytes)\n",
            Prefix.c_str(),
            (unsigned long)sequence,
            (unsigned int)signal,
            (unsigned int)flags,
            (unsigned long long)dataAddress,
            (unsigned long)dataLength);
        if (!hexOk) {
            text += "    (could not decode hex buffer field; event not written)\n";
        }
    } else if (g_options.dump) {
        text = Format(
            "%s seq=%lu CALL signal=0x%X flags=0x%X data=0x%016llX\n",
            Prefix.c_str(),
            (unsigned long)sequence,
            (unsigned int)signal,
            (unsigned int)flags,
            (unsigned long long)dataAddress);

        if (!hexOk) {
            text += "    (could not decode hex buffer field)\n";
        } else {
            DumpBytes(text, "data", dataBytes, g_options.dumpBytes);
        }
    } else {
        text = Format(
            "%s seq=%lu CALL signal=0x%X flags=0x%X data=0x%016llX (%lu bytes)\n",
            Prefix.c_str(),
            (unsigned long)sequence,
            (unsigned int)signal,
            (unsigned int)flags,
            (unsigned long long)dataAddress,
            (unsigned long)dataLength);
    }

    Print(text);
}

void
HandleReturnEvent(
    _In_ krabs::parser& Parser,
    _In_ const EVENT_RECORD& Record,
    _In_ const std::string& Prefix)
{
    uint32_t sequence = 0;
    uint32_t status = 0;

    Parser.try_parse(L"SeqNum", sequence);
    Parser.try_parse(L"Status", status);

    if (g_options.jsonlFormat) {
        PrintJson(Format("{\"k\":\"ret\",\"i\":%lu,\"seq\":%lu,\"ts\":%llu,"
                         "\"pid\":%lu,\"tid\":%lu,\"status\":%lu}\n",
                         (unsigned long)sequence,
                         (unsigned long)sequence,
                         (unsigned long long)WallClockTimestamp(Record),
                         (unsigned long)Record.EventHeader.ProcessId,
                         (unsigned long)Record.EventHeader.ThreadId,
                         (unsigned long)status));
        return;
    }

    Print(Format("%s seq=%lu RETURN status=0x%08lX\n",
                 Prefix.c_str(),
                 (unsigned long)sequence,
                 (unsigned long)status));
}

void
OnEvent(
    _In_ const EVENT_RECORD& Record,
    _In_ const krabs::trace_context& Context)
{
    try {
        krabs::schema  schema(Record, Context.schema_locator);
        krabs::parser  parser(schema);
        uint32_t       type = 0;

        if (!parser.try_parse(L"Type", type)) {
            type = 0;
        }

        g_payloadSeen = true;

        std::string prefix = Format("[%s] pid=%lu tid=%lu",
                                    FormatTimestamp(Record).c_str(),
                                    (unsigned long)Record.EventHeader.ProcessId,
                                    (unsigned long)Record.EventHeader.ThreadId);

        switch (type) {
        case MPENGINE_ETW_TYPE_CALL:
            HandleCallEvent(parser, Record, prefix);
            break;
        case MPENGINE_ETW_TYPE_RETURN:
            HandleReturnEvent(parser, Record, prefix);
            break;
        case MPENGINE_ETW_TYPE_STATUS:
            HandleStatusEvent(parser, Record, prefix);
            break;
        case MPENGINE_ETW_TYPE_ENGINE_LOG:
            HandleEngineLogEvent(parser, Record, prefix);
            break;
        case MPENGINE_ETW_TYPE_TRACE:
            HandleEngineTraceEvent(parser, Record, prefix);
            break;
        case MPENGINE_ETW_TYPE_MEM:
            HandleEngineMemEvent(parser, Record, prefix);
            break;
        default:
            Print(Format("%s event=%s (unknown type %lu)\n",
                         prefix.c_str(),
                         schema.event_name(),
                         (unsigned long)type));
            break;
        }

        uint64_t count = g_eventCount.fetch_add(1) + 1;
        if (g_options.maxEvents != 0 && count >= g_options.maxEvents) {
            RequestSessionStopAsync();
        }
    }
    catch (const std::exception& error) {
        Print(Format("event decode failed (pid=%lu): %s\n",
                     (unsigned long)Record.EventHeader.ProcessId,
                     error.what()));
    }
}

/* ------------------------------------------------------------------------- */
/* Command line                                                              */
/* ------------------------------------------------------------------------- */

void
Usage(void)
{
    fputs(
        "rsignal_etw_listener -- consume the mpengine __rsignal ETW provider\n"
        "\n"
        "Usage: rsignal_etw_listener [options]\n"
        "\n"
        "  --session <name>   real-time ETW session name\n"
        "  --out <file>       write rendered text (or binary records) to <file>\n"
        "  --out-bin <file>   also write every CALL payload as framed records;\n"
        "                     combine with --format jsonl for one aligned pair\n"
        "  --format <format>  output format: text (default), binary or jsonl\n"
        "                     binary writes CALL payloads as EV + signal ID + size + data\n"
        "                     jsonl writes one JSON object per event\n"
        "  --context          jsonl: also emit ContextAddress/Length/Hex\n"
        "  --dump             print a hex+ASCII dump of the data buffer\n"
        "  --dump-bytes <n>   bytes of the buffer to dump (implies --dump;\n"
        "                     0 = all, default 512)\n"
        "  --no-dump          compact output (default): signal, flags,\n"
        "                     data address and size\n"
        "  --max-events <n>   stop after n events\n"
        "  --quiet-status     hide Status (install/diagnostic) events\n"
        "  --quiet-engine-log hide EngineLog (engine's own log lines) events\n"
        "  --quiet-trace      hide EngineTrace (structured engine records)\n"
        "  --quiet-mem        hide EngineMem (engine OpenProcess/VirtualQueryEx/\n"
        "                     NtReadVirtualMemoryEx) events\n"
        "  --help             show this text\n"
        "\n"
        "Run elevated (or as a member of Performance Log Users). Start the\n"
        "listener before injecting mpengine_hook.dll to see early Status\n"
        "messages, then trigger engine activity, e.g.:\n"
        "\n"
        "  MpCmdRun.exe -Scan -ScanType 1\n",
        stdout);
}

bool
ParseUnsigned(
    _In_ const wchar_t* Text,
    _Out_ uint64_t& Value)
{
    wchar_t* end = nullptr;

    Value = _wcstoui64(Text, &end, 0);
    return end != nullptr && *end == L'\0' && end != Text;
}

bool
ParseOptions(
    _In_ int Argc,
    _In_reads_(Argc) wchar_t** Argv)
{
    for (int i = 1; i < Argc; ++i) {
        std::wstring argument = Argv[i];

        auto next = [&](const wchar_t* Name) -> const wchar_t* {
            if (i + 1 >= Argc) {
                fprintf(stderr, "%ls requires a value\n", Name);
                return nullptr;
            }
            return Argv[++i];
        };

        if (argument == L"--help" || argument == L"-h" || argument == L"/?") {
            Usage();
            g_helpRequested = true;
            return false;
        } else if (argument == L"--session") {
            const wchar_t* value = next(L"--session");

            if (value == nullptr) {
                return false;
            }
            g_options.session = value;
        } else if (argument == L"--out") {
            const wchar_t* value = next(L"--out");

            if (value == nullptr) {
                return false;
            }
            g_options.outPath = value;
        } else if (argument == L"--out-bin") {
            const wchar_t* value = next(L"--out-bin");

            if (value == nullptr) {
                return false;
            }
            g_options.outBinPath = value;
        } else if (argument == L"--format") {
            const wchar_t* value = next(L"--format");

            if (value == nullptr) {
                return false;
            }
            if (_wcsicmp(value, L"text") == 0) {
                g_options.binaryFormat = false;
                g_options.jsonlFormat = false;
            } else if (_wcsicmp(value, L"binary") == 0) {
                g_options.binaryFormat = true;
                g_options.jsonlFormat = false;
            } else if (_wcsicmp(value, L"jsonl") == 0) {
                g_options.binaryFormat = false;
                g_options.jsonlFormat = true;
            } else {
                fprintf(stderr, "invalid --format (expected text, binary or "
                                "jsonl)\n");
                return false;
            }
        } else if (argument == L"--context") {
            g_options.includeContext = true;
        } else if (argument == L"--dump") {
            g_options.dump = true;
        } else if (argument == L"--no-dump") {
            g_options.dump = false;
        } else if (argument == L"--dump-bytes") {
            const wchar_t* value = next(L"--dump-bytes");
            uint64_t parsed = 0;

            if (value == nullptr || !ParseUnsigned(value, parsed)) {
                fprintf(stderr, "invalid --dump-bytes\n");
                return false;
            }
            g_options.dumpBytes = (size_t)parsed;
            g_options.dump = true;
        } else if (argument == L"--max-events") {
            const wchar_t* value = next(L"--max-events");

            if (value == nullptr || !ParseUnsigned(value, g_options.maxEvents)) {
                fprintf(stderr, "invalid --max-events\n");
                return false;
            }
        } else if (argument == L"--quiet-status") {
            g_options.showStatus = false;
        } else if (argument == L"--quiet-engine-log") {
            g_options.showEngineLog = false;
        } else if (argument == L"--quiet-trace") {
            g_options.showEngineTrace = false;
        } else if (argument == L"--quiet-mem") {
            g_options.showEngineMem = false;
        } else {
            fprintf(stderr, "unknown argument: %ls\n", argument.c_str());
            Usage();
            return false;
        }
    }

    if (g_options.binaryFormat && g_options.outPath.empty()) {
        fprintf(stderr, "--format binary requires --out <file>\n");
        return false;
    }

    return true;
}

} /* namespace */

int
wmain(
    _In_ int Argc,
    _In_reads_(Argc) wchar_t** Argv)
{
    if (!ParseOptions(Argc, Argv)) {
        return g_helpRequested ? 0 : 1;
    }

    if (!g_options.outPath.empty()) {
        const wchar_t* mode = (g_options.binaryFormat || g_options.jsonlFormat)
                                  ? L"wb"
                                  : L"w";
        if (_wfopen_s(&g_out, g_options.outPath.c_str(), mode) != 0 ||
            g_out == nullptr) {
            fprintf(stderr, "cannot open output file\n");
            return 1;
        }
    }

    if (!g_options.outBinPath.empty()) {
        if (_wfopen_s(&g_outBin, g_options.outBinPath.c_str(), L"wb") != 0 ||
            g_outBin == nullptr) {
            fprintf(stderr, "cannot open framed output file\n");
            return 1;
        }
    }

    SetConsoleCtrlHandler(ConsoleHandler, TRUE);

    krabs::user_trace trace(g_options.session);

    EVENT_TRACE_PROPERTIES properties = {};
    properties.BufferSize = 256;   /* KB; larger buffers suit 4+ KB events */
    properties.FlushTimer = 1;     /* seconds */
    properties.LogFileMode = EVENT_TRACE_REAL_TIME_MODE |
                             EVENT_TRACE_NO_PER_PROCESSOR_BUFFERING;
    trace.set_trace_properties(&properties);

    krabs::provider<> provider(krabs::guid(MPENGINE_ETW_PROVIDER_GUID_STRING));
    provider.any(0);
    provider.all(0);
    provider.level(TRACE_LEVEL_VERBOSE);
    provider.add_on_event_callback(OnEvent);
    trace.enable(provider);

    Print(Format("provider : %ls\n", MPENGINE_ETW_PROVIDER_GUID_STRING));
    Print(Format("session  : %ls\n", g_options.session.c_str()));
    Print("waiting for events; press Ctrl+C to stop\n\n");

    {
        FILETIME baseTime;
        LARGE_INTEGER frequency = {};

        GetSystemTimeAsFileTime(&baseTime);
        g_wallClockBase = ((ULONGLONG)baseTime.dwHighDateTime << 32) |
                          baseTime.dwLowDateTime;

        QueryPerformanceFrequency(&frequency);
        g_qpcFrequency = (ULONGLONG)frequency.QuadPart;
        QueryPerformanceCounter(&g_qpcBase);
    }

    bool traceFailed = false;

    try {
        trace.start();
    }
    catch (const std::exception& error) {
        /*
         * Stopping the session (Ctrl+C or --max-events) makes ProcessTrace
         * return, and some ETW stacks report a harmless error for that.
         */
        if (!g_stopRequested.load()) {
            Print(Format("trace failed: %s\n", error.what()));
            Print("Run elevated (or as a Performance Log Users member) and "
                  "make sure the session name is not already in use.\n");
            traceFailed = true;
        }
    }

    Print(Format("\n%llu event(s) seen%s\n",
                 (unsigned long long)g_eventCount.load(),
                 g_payloadSeen ? "" : " (provider never appeared)"));

    if (g_out != nullptr) {
        fclose(g_out);
        g_out = nullptr;
    }

    if (g_outBin != nullptr) {
        fclose(g_outBin);
        g_outBin = nullptr;
    }

    return traceFailed ? 1 : 0;
}
