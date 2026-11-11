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
#include <stdarg.h>
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
    char contextHex[RSI_CONTEXT_DUMP_BYTES * 2 + 1];
    char dataHex[RSI_DATA_DUMP_BYTES * 2 + 1];
    SIZE_T contextLength;
    SIZE_T dataLength;

    /*
     * Copy before calling the real function: Data may point to a transient
     * structure that the handler releases or rewrites.
     */
    contextLength = CopyTargetMemory(Context, contextBytes, sizeof(contextBytes));
    dataLength = CopyTargetMemory(Data, dataBytes, sizeof(dataBytes));

    BytesToHex(contextBytes, contextLength, contextHex);
    BytesToHex(dataBytes, dataLength, dataHex);

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
        TraceLoggingString(dataHex, "DataHex"));
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
#define MAX_ENLISTED_THREADS 4096

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
    char    host[MAX_PATH] = { 0 };
    HANDLE  threadHandles[MAX_ENLISTED_THREADS];
    DWORD   threadCount = 0;

    (void)Parameter;

    /*
     * Register before anything else so that even early failures are visible
     * to the listener. TraceLoggingRegister must not be called from DllMain;
     * this worker thread makes it safe.
     */
    if (SUCCEEDED(TraceLoggingRegister(g_hRSignalProvider))) {
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

    engine = WaitForModule(MPENGINE_DLL_WNAME, MPENGINE_MODULE_WAIT_MS);
    if (engine == NULL) {
        EmitStatusErrorV(0, "%s is not loaded after %lu ms; no hook installed",
                         MPENGINE_DLL_NAME,
                         (unsigned long)MPENGINE_MODULE_WAIT_MS);
        return 0;
    }
    EmitStatusInfoV(0, "%s @ 0x%p", MPENGINE_DLL_NAME, (void*)engine);

    g_Real__rsignal = (PFN___rsignal)
        GetProcAddress(engine, MPENGINE_HOOK_EXPORT);
    if (g_Real__rsignal == NULL) {
        EmitStatusErrorV(GetLastError(), "export %s!%s not found",
                         MPENGINE_DLL_NAME, MPENGINE_HOOK_EXPORT);
        return 0;
    }
    EmitStatusInfoV(0, "target %s!%s @ 0x%p",
                    MPENGINE_DLL_NAME, MPENGINE_HOOK_EXPORT,
                    (void*)g_Real__rsignal);

    error = DetourTransactionBegin();
    if (error != NO_ERROR) {
        EmitStatusErrorV((ULONG)error, "DetourTransactionBegin failed");
        return 0;
    }

    threadCount = EnlistProcessThreads(threadHandles, MAX_ENLISTED_THREADS);

    error = DetourAttach((PVOID*)&g_Real__rsignal,
                         (PVOID)Hook___rsignal);
    if (error != NO_ERROR) {
        EmitStatusErrorV((ULONG)error, "DetourAttach(%s) failed",
                         MPENGINE_HOOK_EXPORT);
        (void)DetourTransactionAbort();
        ReleaseThreadHandles(threadHandles, threadCount);
        return 0;
    }

    error = DetourTransactionCommit();
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

        /*
         * Do not call Detours or TraceLoggingRegister from DllMain. The
         * loader lock is held here; a worker thread keeps both out of the
         * loader path.
         */
        thread = CreateThread(NULL, 0, InstallHooksThread, NULL, 0, NULL);
        if (thread != NULL) {
            CloseHandle(thread);
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
