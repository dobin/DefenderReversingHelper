/*
 * MpEngineHook.c -- Detours payload for mpengine.dll.
 *
 * This DLL is meant to be injected into a process that already has (or will
 * load) mpengine.dll, normally MsMpEng.exe. It installs a Microsoft Detours
 * inline hook on an exported mpengine function from a worker thread, so the
 * loader lock is not held while Detours patches code.
 *
 * The example target is:
 *
 *     mpengine.dll!MpContainerAnalyze(PVOID Context, PVOID Result) -> HRESULT
 *
 * MpContainerAnalyze is called with a container/context object and a result
 * object. The hook only observes the call and forwards it to the real
 * function; it never changes arguments or the return value. Replace or extend
 * Hook_MpContainerAnalyze when you know which mpengine function you need.
 *
 * Build output: bin\<Configuration>\mpengine_hook.dll
 *
 * Log output:   C:\data\mpengine_hook_<pid>.log
 *
 * Injecting into MsMpEng.exe requires the MakeMePPL driver and the injector
 * options that clear PPL / block-non-Microsoft-binaries first:
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
#define MPENGINE_DLL_NAME   "mpengine.dll"
#define MPENGINE_DLL_WNAME  L"mpengine.dll"

/*
 * The function to hook. It is a compile-time choice because the hook needs a
 * matching prototype. Override it with a project-wide preprocessor definition
 * if you add another typed hook.
 */
#ifndef MPENGINE_HOOK_EXPORT
#define MPENGINE_HOOK_EXPORT "MpContainerAnalyze"
#endif

#ifndef MPENGINE_MODULE_WAIT_MS
#define MPENGINE_MODULE_WAIT_MS 30000
#endif

#ifndef MPENGINE_MAX_LOG_LINES
#define MPENGINE_MAX_LOG_LINES 500
#endif

/* detours.h only defines this internally; it is a normal Win32 error code. */
#ifndef ERROR_DYNAMIC_CODE_BLOCKED
#define ERROR_DYNAMIC_CODE_BLOCKED 1655L
#endif

typedef HRESULT (WINAPI *PFN_MpContainerAnalyze)(PVOID Context, PVOID Result);

static PFN_MpContainerAnalyze g_RealMpContainerAnalyze = NULL;
static volatile LONG         g_LogEnabled = 1;
static volatile LONG         g_LogLines = 0;
static volatile LONG         g_HookCalls = 0;
static CRITICAL_SECTION      g_LogLock;
static BOOLEAN               g_LogLockInitialized = FALSE;

/* ------------------------------------------------------------------------- */
/* Logging                                                                   */
/* ------------------------------------------------------------------------- */

static void
LogV(
    _In_ const char* Format,
    _In_ va_list Arguments)
{
    char       message[1024];
    char       path[MAX_PATH];
    SYSTEMTIME now;
    FILE*      file;

    if (!g_LogLockInitialized || g_LogLines >= MPENGINE_MAX_LOG_LINES) {
        return;
    }

    _vsnprintf_s(message, sizeof(message), _TRUNCATE, Format, Arguments);

    EnterCriticalSection(&g_LogLock);

    if (g_LogLines >= MPENGINE_MAX_LOG_LINES) {
        LeaveCriticalSection(&g_LogLock);
        return;
    }
    ++g_LogLines;

    GetLocalTime(&now);
    _snprintf_s(path, sizeof(path), _TRUNCATE,
                LOG_DIR "\\mpengine_hook_%lu.log",
                (unsigned long)GetCurrentProcessId());

    file = fopen(path, "a");
    if (file != NULL) {
        fprintf(file,
                "[%04u-%02u-%02u %02u:%02u:%02u.%03u] pid=%lu tid=%lu %s\n",
                now.wYear, now.wMonth, now.wDay,
                now.wHour, now.wMinute, now.wSecond, now.wMilliseconds,
                (unsigned long)GetCurrentProcessId(),
                (unsigned long)GetCurrentThreadId(),
                message);
        fclose(file);
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

/* ------------------------------------------------------------------------- */
/* Hook                                                                      */
/* ------------------------------------------------------------------------- */

static HRESULT WINAPI
Hook_MpContainerAnalyze(
    _In_ PVOID Context,
    _In_ PVOID Result)
{
    PFN_MpContainerAnalyze real = g_RealMpContainerAnalyze;
    HRESULT status;
    LONG    call;

    if (real == NULL) {
        return E_FAIL;
    }

    status = real(Context, Result);

    call = InterlockedIncrement(&g_HookCalls);
    if (g_LogEnabled && (call <= 10 || (call % 1000) == 0)) {
        Log("MpContainerAnalyze(ctx=%p, result=%p) -> 0x%08lX (call %ld)",
            Context, Result, (unsigned long)status, (long)call);
    }

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
 */
static void
EnlistProcessThreads(void)
{
    HANDLE        snapshot;
    THREADENTRY32 entry;
    DWORD         self = GetCurrentThreadId();
    DWORD         enlisted = 0;
    DWORD         skipped = 0;

    (void)DetourUpdateThread(GetCurrentThread());
    ++enlisted;

    snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        Log("[!] CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD) failed: %lu; "
            "only the hook thread is enlisted",
            (unsigned long)GetLastError());
        return;
    }

    entry.dwSize = sizeof(entry);
    if (Thread32First(snapshot, &entry)) {
        do {
            HANDLE thread;

            if (entry.th32OwnerProcessID != GetCurrentProcessId() ||
                entry.th32ThreadID == self) {
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
                ++enlisted;
            } else {
                ++skipped;
            }
            CloseHandle(thread);
        } while (Thread32Next(snapshot, &entry));
    }

    CloseHandle(snapshot);
    Log("[*] Detours enlisted %lu thread(s), skipped %lu",
        (unsigned long)enlisted, (unsigned long)skipped);
}

static DWORD WINAPI
InstallHooksThread(
    _In_ LPVOID Parameter)
{
    HMODULE engine;
    LONG    error;
    char    host[MAX_PATH] = { 0 };

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

    g_RealMpContainerAnalyze = (PFN_MpContainerAnalyze)
        GetProcAddress(engine, MPENGINE_HOOK_EXPORT);
    if (g_RealMpContainerAnalyze == NULL) {
        Log("[!] export %s!%s not found: %lu",
            MPENGINE_DLL_NAME, MPENGINE_HOOK_EXPORT,
            (unsigned long)GetLastError());
        return 0;
    }
    Log("[+] target %s!%s @ 0x%p",
        MPENGINE_DLL_NAME, MPENGINE_HOOK_EXPORT,
        (void*)g_RealMpContainerAnalyze);

    error = DetourTransactionBegin();
    if (error != NO_ERROR) {
        Log("[!] DetourTransactionBegin failed: %ld", (long)error);
        return 0;
    }

    EnlistProcessThreads();

    error = DetourAttach((PVOID*)&g_RealMpContainerAnalyze,
                         (PVOID)Hook_MpContainerAnalyze);
    if (error != NO_ERROR) {
        Log("[!] DetourAttach(%s) failed: %ld", MPENGINE_HOOK_EXPORT,
            (long)error);
        (void)DetourTransactionAbort();
        return 0;
    }

    error = DetourTransactionCommit();
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
        (void*)Hook_MpContainerAnalyze);
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
