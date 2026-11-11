/*
 * RSignalEtwListener.cpp -- real-time consumer for the mpengine __rsignal hook.
 *
 * Subscribes to the TraceLogging provider emitted by
 * dll_injector\detours_payload\MpEngineHook.c (g_hRSignalProvider) and renders
 * its events on the console. The contract (provider GUID, event names and
 * field names) lives in shared\MpEngineEtw.h.
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
    bool           dump = false;         /* default: sizes only */
    bool           binaryFormat = false; /* --out stores framed binary CALL payloads */
    size_t         dumpBytes = 512;      /* 0 = print everything */
    uint64_t       maxEvents = 0;        /* 0 = unlimited */
    bool           showStatus = true;
};

Options                g_options;
FILE*                  g_out = nullptr;
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

    if (g_out != nullptr && !g_options.binaryFormat) {
        fputs(Text.c_str(), g_out);
        fflush(g_out);
    }
}

bool
WriteBinaryEvent(
    _In_ uint32_t SignalId,
    _In_reads_bytes_(PayloadSize) const BYTE* Payload,
    _In_ uint32_t PayloadSize)
{
    if (g_out == nullptr) {
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
    if (fwrite(header, sizeof(header), 1, g_out) != 1 ||
        (PayloadSize != 0 && fwrite(Payload, PayloadSize, 1, g_out) != 1)) {
        return false;
    }

    return fflush(g_out) == 0;
}

std::string
FormatTimestamp(
    _In_ const EVENT_RECORD& Record)
{
    FILETIME   fileTime;
    FILETIME   localTime;
    SYSTEMTIME systemTime;
    ULONGLONG  ticks = (ULONGLONG)Record.EventHeader.TimeStamp.QuadPart;
    ULONGLONG  timestamp = 0;

    if (g_qpcFrequency != 0 && g_wallClockBase != 0 &&
        ticks >= (ULONGLONG)g_qpcBase.QuadPart) {
        ULONGLONG delta = ticks - (ULONGLONG)g_qpcBase.QuadPart;

        timestamp = g_wallClockBase +
                    (delta * 10000000ull) / g_qpcFrequency;
    }

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

    if (!g_options.showStatus) {
        return;
    }

    const char* level = "info";
    if (Record.EventHeader.EventDescriptor.Level == TRACE_LEVEL_ERROR) {
        level = "error";
    } else if (Record.EventHeader.EventDescriptor.Level == TRACE_LEVEL_WARNING) {
        level = "warn";
    }

    Print(Format("%s STATUS(%s) code=%lu (0x%08lX) message=\"%s\"\n",
                 Prefix.c_str(), level, (unsigned long)code,
                 (unsigned long)code, message.c_str()));
}

void
HandleCallEvent(
    _In_ krabs::parser& Parser,
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

    bool hexOk = true;

    if (g_options.dump || g_options.binaryFormat) {
        hexOk = Parser.try_parse(L"DataHex", dataHex) &&
                HexDecode(dataHex, dataBytes);
    }

    if (g_options.binaryFormat && hexOk) {
        if (!WriteBinaryEvent((uint32_t)signal, dataBytes.data(),
                              (uint32_t)dataBytes.size())) {
            fprintf(stderr, "failed to write binary event\n");
        }
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
    _In_ const std::string& Prefix)
{
    uint32_t sequence = 0;
    uint32_t status = 0;

    Parser.try_parse(L"SeqNum", sequence);
    Parser.try_parse(L"Status", status);

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
            HandleCallEvent(parser, prefix);
            break;
        case MPENGINE_ETW_TYPE_RETURN:
            HandleReturnEvent(parser, prefix);
            break;
        case MPENGINE_ETW_TYPE_STATUS:
            HandleStatusEvent(parser, Record, prefix);
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
        "  --format <format>  output format: text (default) or binary\n"
        "                     binary writes CALL payloads as EV + signal ID + size + data\n"
        "  --dump             print a hex+ASCII dump of the data buffer\n"
        "  --dump-bytes <n>   bytes of the buffer to dump (implies --dump;\n"
        "                     0 = all, default 512)\n"
        "  --no-dump          compact output (default): signal, flags,\n"
        "                     data address and size\n"
        "  --max-events <n>   stop after n events\n"
        "  --quiet-status     hide Status (install/diagnostic) events\n"
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
        } else if (argument == L"--format") {
            const wchar_t* value = next(L"--format");

            if (value == nullptr) {
                return false;
            }
            if (_wcsicmp(value, L"text") == 0) {
                g_options.binaryFormat = false;
            } else if (_wcsicmp(value, L"binary") == 0) {
                g_options.binaryFormat = true;
            } else {
                fprintf(stderr, "invalid --format (expected text or binary)\n");
                return false;
            }
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
        const wchar_t* mode = g_options.binaryFormat ? L"wb" : L"w";
        if (_wfopen_s(&g_out, g_options.outPath.c_str(), mode) != 0 ||
            g_out == nullptr) {
            fprintf(stderr, "cannot open output file\n");
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

    return traceFailed ? 1 : 0;
}
