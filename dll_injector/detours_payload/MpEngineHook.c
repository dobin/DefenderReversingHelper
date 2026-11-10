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
 * Every call is appended to:
 *
 *     C:\data\rsignal_<pid>.log
 *
 * Each entry contains all four arguments, a hex+ASCII dump of the Context
 * pointer (RSI_CONTEXT_DUMP_BYTES), a hex+ASCII dump of the Data pointer
 * (RSI_DATA_DUMP_BYTES), and the return value. The buffers are written before
 * the real function runs, so the dump shows the data exactly as received.
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
 * commit fails and the log records ERROR_DYNAMIC_CODE_BLOCKED (1655). Pass
 * --allow-dynamic-code so the injector clears ACG first.
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
#include <string.h>

#pragma warning(push)
#pragma warning(disable: 4201) /* Detours uses a nameless struct/union. */
#include "detours.h"
#pragma warning(pop)

#define LOG_DIR             "C:\\data"
#define LOG_FILE_PATTERN    LOG_DIR "\\rsignal_%lu.log"
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

/* How much memory to dump behind each pointer. */
#ifndef RSI_CONTEXT_DUMP_BYTES
#define RSI_CONTEXT_DUMP_BYTES 512
#endif
#ifndef RSI_DATA_DUMP_BYTES
#define RSI_DATA_DUMP_BYTES 4096
#endif

/* Stop writing after this much data so a noisy engine cannot fill the disk. */
#ifndef RSI_MAX_LOG_BYTES
#define RSI_MAX_LOG_BYTES (64ull * 1024ull * 1024ull)
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

static PFN___rsignal g_Real__rsignal = NULL;
static volatile LONG g_LogEnabled = 1;
static volatile LONG g_HookCalls = 0;
static CRITICAL_SECTION g_LogLock;
static BOOLEAN g_LogLockInitialized = FALSE;
static BOOLEAN g_LogLimitNoted = FALSE;
static ULONGLONG g_LogBytes = 0;
static __declspec(thread) LONG g_InHook = 0;

/* ------------------------------------------------------------------------- */
/* Logging                                                                   */
/* ------------------------------------------------------------------------- */

static void
WriteLogPrefixLocked(
    _In_ FILE* File)
{
    SYSTEMTIME now;

    GetLocalTime(&now);
    fprintf(File,
            "[%04u-%02u-%02u %02u:%02u:%02u.%03u] pid=%lu tid=%lu ",
            now.wYear, now.wMonth, now.wDay,
            now.wHour, now.wMinute, now.wSecond, now.wMilliseconds,
            (unsigned long)GetCurrentProcessId(),
            (unsigned long)GetCurrentThreadId());
}

static FILE*
OpenLogLocked(void)
{
    char path[MAX_PATH];

    if (!g_LogLockInitialized) {
        return NULL;
    }

    CreateDirectoryA(LOG_DIR, NULL);
    _snprintf_s(path, sizeof(path), _TRUNCATE,
                LOG_FILE_PATTERN, (unsigned long)GetCurrentProcessId());

    if (g_LogBytes >= RSI_MAX_LOG_BYTES) {
        if (!g_LogLimitNoted) {
            FILE* file;

            g_LogLimitNoted = TRUE;
            file = fopen(path, "a");
            if (file != NULL) {
                WriteLogPrefixLocked(file);
                fprintf(file,
                        "[!] log size limit (%llu bytes) reached; "
                        "further calls are not logged\n",
                        (unsigned long long)RSI_MAX_LOG_BYTES);
                fclose(file);
            }
        }
        return NULL;
    }

    return fopen(path, "a");
}

static void
CloseLogLocked(
    _In_ FILE* File)
{
    if (File == NULL) {
        return;
    }

    {
        __int64 size = _ftelli64(File);

        if (size > 0) {
            g_LogBytes += (ULONGLONG)size;
        }
    }
    fclose(File);
}

static void
LogV(
    _In_ const char* Format,
    _In_ va_list Arguments)
{
    char  message[1024];
    FILE* file;

    if (!g_LogLockInitialized) {
        return;
    }

    _vsnprintf_s(message, sizeof(message), _TRUNCATE, Format, Arguments);

    EnterCriticalSection(&g_LogLock);
    file = OpenLogLocked();
    if (file != NULL) {
        WriteLogPrefixLocked(file);
        fprintf(file, "%s\n", message);
        CloseLogLocked(file);
    }
    LeaveCriticalSection(&g_LogLock);
}

static void
Log(
    _In_ const char* Format,
    ...)
{
    va_list arguments;

    va_start(arguments, Format);
    LogV(Format, arguments);
    va_end(arguments);
}

static void
LogDump(
    _In_ const char* Label,
    _In_ const void* Address,
    _In_ SIZE_T Bytes)
{
    BYTE  buffer[RSI_DATA_DUMP_BYTES];
    SIZE_T read = 0;
    SIZE_T i;
    FILE* file;
    MEMORY_BASIC_INFORMATION memoryInfo;
    SIZE_T available;

    if (Address == NULL) {
        Log("%s: (null)", Label);
        return;
    }

    if (Bytes == 0 || Bytes > sizeof(buffer)) {
        Bytes = sizeof(buffer);
    }

    /*
     * Do not ask ReadProcessMemory for bytes that cross into an uncommitted
     * or guard page: it fails the whole request. Clamp to the region that is
     * actually readable from Address.
     */
    if (VirtualQuery(Address, &memoryInfo, sizeof(memoryInfo)) == 0 ||
        memoryInfo.State != MEM_COMMIT ||
        (memoryInfo.Protect & (PAGE_NOACCESS | PAGE_GUARD)) != 0) {
        Log("%s @ %p: unreadable (raw value 0x%p)",
            Label, Address, Address);
        return;
    }

    available = (SIZE_T)((const BYTE*)memoryInfo.BaseAddress +
                         memoryInfo.RegionSize -
                         (const BYTE*)Address);
    if (Bytes > available) {
        Bytes = available;
    }
    if (Bytes == 0) {
        Log("%s @ %p: unreadable (raw value 0x%p)",
            Label, Address, Address);
        return;
    }

    if (!ReadProcessMemory(GetCurrentProcess(), Address, buffer, Bytes, &read) &&
        read == 0) {
        Log("%s @ %p: unreadable (raw value 0x%p)",
            Label, Address, Address);
        return;
    }

    EnterCriticalSection(&g_LogLock);
    file = OpenLogLocked();
    if (file != NULL) {
        WriteLogPrefixLocked(file);
        fprintf(file, "%s @ %p, %llu byte(s):\n",
                Label, Address, (unsigned long long)read);

        for (i = 0; i < read; i += 16) {
            char   hex[16 * 3 + 1];
            char   ascii[16 + 1];
            SIZE_T count = read - i;
            SIZE_T j;

            if (count > 16) {
                count = 16;
            }

            memset(hex, 0, sizeof(hex));
            memset(ascii, 0, sizeof(ascii));

            for (j = 0; j < count; ++j) {
                BYTE value = buffer[i + j];

                _snprintf_s(hex + j * 3, sizeof(hex) - j * 3, _TRUNCATE,
                            "%02X ", value);
                ascii[j] = (value >= 0x20 && value <= 0x7E)
                               ? (char)value
                               : '.';
            }

            fprintf(file, "    %04llX  %-47s  |%s|\n",
                    (unsigned long long)i, hex, ascii);
        }

        CloseLogLocked(file);
    }
    LeaveCriticalSection(&g_LogLock);
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
     * If a log write itself signals on this thread, forward without logging.
     * A global log-size limit covers recursive calls from other threads.
     */
    if (InterlockedIncrement(&g_InHook) > 1) {
        InterlockedDecrement(&g_InHook);
        return real(Context, Signal, Data, Flags);
    }

    call = InterlockedIncrement(&g_HookCalls);

    if (g_LogEnabled) {
        Log("__rsignal(ctx=%p, signal=0x%X, data=%p, flags=0x%X (%d)) call=%ld",
            Context, Signal, Data, (unsigned int)Flags, Flags, (long)call);
        /*
         * Dump before calling the real function: Data may point to a transient
         * structure that the handler releases or rewrites.
         */
        LogDump("context", Context, RSI_CONTEXT_DUMP_BYTES);
        LogDump("data", Data, RSI_DATA_DUMP_BYTES);
    }

    status = real(Context, Signal, Data, Flags);

    if (g_LogEnabled) {
        Log("__rsignal -> 0x%08lX (call=%ld)",
            (unsigned long)status, (long)call);
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
        Log("[!] CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD) failed: %lu; "
            "only the current thread is covered",
            (unsigned long)GetLastError());
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
    Log("[*] Detours enlisted %lu thread(s), skipped %lu",
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

    CreateDirectoryA(LOG_DIR, NULL);

    /*
     * No-op unless the process was started through DetourCreateProcessWithDll*.
     * It is harmless for a LoadLibrary-injected payload and makes the DLL
     * reusable with Detours' own injection helper.
     */
    (void)DetourRestoreAfterWith();

    (void)GetModuleFileNameA(NULL, host, sizeof(host));
    Log("payload attached: pid=%lu host=%s",
        (unsigned long)GetCurrentProcessId(), host);

    engine = WaitForModule(MPENGINE_DLL_WNAME, MPENGINE_MODULE_WAIT_MS);
    if (engine == NULL) {
        Log("[!] %s is not loaded after %lu ms; no hook installed",
            MPENGINE_DLL_NAME, (unsigned long)MPENGINE_MODULE_WAIT_MS);
        return 0;
    }
    Log("[+] %s @ 0x%p", MPENGINE_DLL_NAME, (void*)engine);

    g_Real__rsignal = (PFN___rsignal)
        GetProcAddress(engine, MPENGINE_HOOK_EXPORT);
    if (g_Real__rsignal == NULL) {
        Log("[!] export %s!%s not found: %lu",
            MPENGINE_DLL_NAME, MPENGINE_HOOK_EXPORT,
            (unsigned long)GetLastError());
        return 0;
    }
    Log("[+] target %s!%s @ 0x%p",
        MPENGINE_DLL_NAME, MPENGINE_HOOK_EXPORT,
        (void*)g_Real__rsignal);

    error = DetourTransactionBegin();
    if (error != NO_ERROR) {
        Log("[!] DetourTransactionBegin failed: %ld", (long)error);
        return 0;
    }

    threadCount = EnlistProcessThreads(threadHandles, MAX_ENLISTED_THREADS);

    error = DetourAttach((PVOID*)&g_Real__rsignal,
                         (PVOID)Hook___rsignal);
    if (error != NO_ERROR) {
        Log("[!] DetourAttach(%s) failed: %ld", MPENGINE_HOOK_EXPORT,
            (long)error);
        (void)DetourTransactionAbort();
        ReleaseThreadHandles(threadHandles, threadCount);
        return 0;
    }

    error = DetourTransactionCommit();
    ReleaseThreadHandles(threadHandles, threadCount);
    if (error != NO_ERROR) {
        Log("[!] DetourTransactionCommit failed: %ld (Win32 %lu)",
            (long)error, (unsigned long)GetLastError());
        if (error == ERROR_DYNAMIC_CODE_BLOCKED) {
            Log("[!] the target has Arbitrary Code Guard (ACG); it must be "
                "cleared before Detours can patch mpengine code");
        } else if (error == ERROR_ACCESS_DENIED) {
            Log("[!] access denied; PPL/signature mitigations may still be "
                "active, or the code pages are protected");
        }
        return 0;
    }

    InterlockedExchange(&g_LogEnabled, 1);
    Log("[+] Detours hook installed: %s!%s -> 0x%p",
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

        InitializeCriticalSection(&g_LogLock);
        g_LogLockInitialized = TRUE;

        /*
         * Do not call Detours from DllMain. The loader lock is held here and
         * DetourTransactionCommit suspends threads and changes page
         * protections; a worker thread keeps that out of the loader path.
         */
        thread = CreateThread(NULL, 0, InstallHooksThread, NULL, 0, NULL);
        if (thread != NULL) {
            CloseHandle(thread);
        } else {
            Log("[!] CreateThread(InstallHooksThread) failed: %lu",
                (unsigned long)GetLastError());
        }
        break;
    }

    case DLL_PROCESS_DETACH:
        /*
         * FreeLibrary/Detach is not supported: the Detours trampoline lives in
         * this DLL, so unloading it while a hook is installed would leave
         * mpengine calling into unmapped memory. Process termination removes
         * both safely.
         */
        if (g_LogLockInitialized) {
            if (Reserved == NULL) {
                Log("[*] FreeLibrary requested; hooks are left installed");
            }
            g_LogLockInitialized = FALSE;
            DeleteCriticalSection(&g_LogLock);
        }
        break;

    default:
        break;
    }

    return TRUE;
}
