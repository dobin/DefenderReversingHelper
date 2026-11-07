/*
 * payload.c -- injectable test DLL for the integrated DLL injector.
 *
 * When this DLL is loaded into a process (DLL_PROCESS_ATTACH) it appends a
 * line to a marker file under C:\data. That file is the proof that the
 * injection actually worked and that our code is now running inside the
 * target process.
 *
 * Build: part of MakeMePPL.sln (dll_injector/payload/DllPayload.vcxproj),
 *        output bin\<Configuration>\payload.dll.
 */

#define WIN32_LEAN_AND_MEAN
#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <stdio.h>

#define OUTPUT_DIR "C:\\data"

static void WriteMarkerFile(HINSTANCE self)
{
    char       path[MAX_PATH];
    char       line[1024];
    char       host[MAX_PATH] = { 0 };
    char       dll[MAX_PATH]  = { 0 };
    SYSTEMTIME st;
    FILE      *f;
    DWORD      pid = GetCurrentProcessId();
    DWORD      tid = GetCurrentThreadId();

    GetModuleFileNameA(NULL, host, MAX_PATH);   /* the host .exe */
    GetModuleFileNameA(self, dll,  MAX_PATH);   /* this DLL      */
    GetLocalTime(&st);

    CreateDirectoryA(OUTPUT_DIR, NULL);         /* best effort   */

    _snprintf_s(path, sizeof(path), _TRUNCATE,
                "%s\\dll_load_%lu.txt", OUTPUT_DIR, (unsigned long)pid);

    f = fopen(path, "a");
    if (f == NULL)
        return;

    _snprintf_s(line, sizeof(line), _TRUNCATE,
                "[%04u-%02u-%02u %02u:%02u:%02u.%03u] "
                "payload loaded  pid=%lu tid=%lu\r\n"
                "    host : %s\r\n"
                "    dll  : %s\r\n"
                "    base : 0x%p\r\n",
                st.wYear, st.wMonth, st.wDay,
                st.wHour, st.wMinute, st.wSecond, st.wMilliseconds,
                (unsigned long)pid, (unsigned long)tid,
                host, dll, (void *)self);

    fputs(line, f);
    fclose(f);
}

BOOL WINAPI DllMain(HINSTANCE hinstDll, DWORD fdwReason, LPVOID lpvReserved)
{
    (void)lpvReserved;

    switch (fdwReason) {
    case DLL_PROCESS_ATTACH:
        /*
         * We are running under the loader lock here, so keep this short and
         * avoid anything that can deadlock (no CreateThread + wait, no
         * LoadLibrary of other DLLs, ...). A plain file write is fine for a
         * throwaway test DLL.
         */
        DisableThreadLibraryCalls(hinstDll);
        WriteMarkerFile(hinstDll);
        break;

    case DLL_PROCESS_DETACH:
        break;
    }

    return TRUE;
}
