#include "PplDriverClient.h"
#include "PplBuilds.h"

#include <sddl.h>

#include <cstdio>
#include <cstdlib>
#include <cwchar>
#include <string>
#include <vector>

namespace {

const wchar_t* const kBlockedNames[] = {
    L"System",
    L"Registry",
    L"smss.exe",
    L"csrss.exe",
    L"wininit.exe",
    L"services.exe",
    L"lsass.exe",
    L"winlogon.exe",
};

void
PrintUsage()
{
    std::wprintf(
        L"MakeMePPL control tool\n"
        L"\n"
        L"Usage:\n"
        L"  pplctl info\n"
        L"  pplctl set   --pid <pid> [--signer am|wintcb|windows|lsa|authenticode|codegen|winsystem|app] [--audit]\n"
        L"  pplctl clear --pid <pid>\n"
        L"  pplctl query --pid <pid>\n"
        L"  pplctl probe --pid <pid>\n"
        L"  pplctl filter add    --name <pattern> [--signer <name>] [--audit] [--exact] [--apply-existing]\n"
        L"  pplctl filter remove --name <pattern>\n"
        L"  pplctl filter clear\n"
        L"  pplctl filter list\n"
        L"  pplctl broker  [--pipe PplGrant] [--signer am] [--audit] [--once] [--admin-only]\n"
        L"  pplctl connect [--pipe PplGrant] [--hold <seconds>]\n"
        L"  pplctl builds\n"
        L"  pplctl version\n"
        L"\n"
        L"Default signer is antimalware (PPL-Antimalware, protection byte 0x31).\n"
        L"Driver installation/removal requires an elevated console; pplctl commands work for any local user.\n"
        L"The control device is writable by all local users, so any local process can grant or clear PPL.\n"
        L"Broker defaults to an Everyone-writable PPL grant pipe (--allow-all); use it only in an isolated test VM.\n"
        L"--admin-only restricts the pipe to SYSTEM and Administrators instead.\n");
}

bool
ParseUlong(
    _In_ const wchar_t* Text,
    _Out_ ULONG* Value)
{
    wchar_t* end = nullptr;
    unsigned long parsed;

    if (Text == nullptr || *Text == L'\0' || *Text == L'-') {
        return false;
    }

    parsed = std::wcstoul(Text, &end, 0);
    if (end == Text || *end != L'\0') {
        return false;
    }

    *Value = static_cast<ULONG>(parsed);
    return true;
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
PrintProtection(
    _In_ UCHAR Protection)
{
    std::wprintf(L"0x%02X (type=%s, signer=%s, audit=%u)",
                 Protection,
                 PplProtectionTypeName(Protection),
                 PplSignerName(static_cast<UCHAR>((Protection >> 4) & 0xF)),
                 static_cast<unsigned>((Protection >> 3) & 1));
}

//
// GetProcessInformation(ProcessProtectionLevelInfo) uses a different encoding
// from the kernel's PS_PROTECTION byte. Decode it with the documented
// PROTECTION_LEVEL_* values instead of treating it as PS_PROTECTION.
//
const wchar_t*
ProtectionLevelName(
    _In_ DWORD Level)
{
    switch (Level) {
    case PROTECTION_LEVEL_NONE:
        return L"none";
    case PROTECTION_LEVEL_WINTCB_LIGHT:
        return L"wintcb-light";
    case PROTECTION_LEVEL_WINDOWS:
        return L"windows";
    case PROTECTION_LEVEL_WINDOWS_LIGHT:
        return L"windows-light";
    case PROTECTION_LEVEL_ANTIMALWARE_LIGHT:
        return L"antimalware-light";
    case PROTECTION_LEVEL_LSA_LIGHT:
        return L"lsa-light";
    case PROTECTION_LEVEL_WINTCB:
        return L"wintcb";
    case PROTECTION_LEVEL_CODEGEN_LIGHT:
        return L"codegen-light";
    case PROTECTION_LEVEL_AUTHENTICODE:
        return L"authenticode";
    case PROTECTION_LEVEL_PPL_APP:
        return L"ppl-app";
    case PROTECTION_LEVEL_SAME:
        return L"same";
    default:
        return L"unknown";
    }
}

bool
EnablePrivilege(
    _In_ const wchar_t* Name)
{
    HANDLE token = nullptr;
    TOKEN_PRIVILEGES privileges;
    LUID luid;

    if (!OpenProcessToken(GetCurrentProcess(),
                          TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
                          &token)) {
        return false;
    }

    if (!LookupPrivilegeValueW(nullptr, Name, &luid)) {
        CloseHandle(token);
        return false;
    }

    privileges.PrivilegeCount = 1;
    privileges.Privileges[0].Luid = luid;
    privileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    SetLastError(ERROR_SUCCESS);
    if (!AdjustTokenPrivileges(token, FALSE, &privileges, 0,
                               nullptr, nullptr)) {
        CloseHandle(token);
        return false;
    }

    CloseHandle(token);
    return GetLastError() != ERROR_NOT_ALL_ASSIGNED;
}

std::wstring
ImageBaseName(
    _In_ const std::wstring& Path)
{
    size_t position = Path.find_last_of(L"\\/");
    if (position == std::wstring::npos) {
        return Path;
    }
    return Path.substr(position + 1);
}

bool
IsBlockedImageName(
    _In_ const std::wstring& Path)
{
    std::wstring baseName = ImageBaseName(Path);

    for (const wchar_t* blocked : kBlockedNames) {
        if (_wcsicmp(baseName.c_str(), blocked) == 0) {
            return true;
        }
    }
    return false;
}

ULONG
QueryCurrentBuild()
{
    typedef LONG (WINAPI* RtlGetVersionFn)(PRTL_OSVERSIONINFOW);
    RTL_OSVERSIONINFOW version = {};
    RtlGetVersionFn rtlGetVersion;

#pragma warning(push)
#pragma warning(disable: 4191) // unsafe conversion from FARPROC
    rtlGetVersion = reinterpret_cast<RtlGetVersionFn>(
        GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "RtlGetVersion"));
#pragma warning(pop)

    if (rtlGetVersion == nullptr) {
        return 0;
    }

    version.dwOSVersionInfoSize = sizeof(version);
    if (rtlGetVersion(&version) != 0) {
        return 0;
    }

    return version.dwBuildNumber;
}

std::wstring
OffsetOrDash(
    _In_ ULONG Offset)
{
    wchar_t buffer[16];

    if (Offset == 0) {
        return L"-";
    }

    swprintf_s(buffer, _countof(buffer), L"0x%03lX",
               static_cast<unsigned long>(Offset));
    return buffer;
}

int
CommandInfo()
{
    HANDLE device;
    PPL_DRIVER_INFO info = {};
    DWORD returned = 0;

    device = PplOpenDevice();
    if (device == INVALID_HANDLE_VALUE) {
        return 1;
    }

    if (!PplIoctl(device, IOCTL_PPL_GET_INFO,
                  nullptr, 0, &info, sizeof(info), &returned)) {
        CloseHandle(device);
        return 1;
    }
    CloseHandle(device);

    std::wprintf(L"driver status : %s (0x%08lX)\n",
                 PplNtStatusText(info.Status).c_str(),
                 static_cast<unsigned long>(info.Status));
    std::wprintf(L"version       : %s\n", info.Version);
    std::wprintf(L"OS            : %s (%lu.%lu build %lu)\n",
                 PplBuildDisplayName(info.BuildNumber),
                 static_cast<unsigned long>(info.MajorVersion),
                 static_cast<unsigned long>(info.MinorVersion),
                 static_cast<unsigned long>(info.BuildNumber));
    std::wprintf(L"PPL offset    : %s%s\n",
                 OffsetOrDash(info.ProtectionOffset).c_str(),
                 (info.Flags & PPL_INFO_FLAG_OFFSET_SUPPORTED)
                     ? L""
                     : L" (unsupported build)");

    {
        PPL_BUILD_OFFSETS local = {};

        if (PplLookupBuildOffsets(info.BuildNumber, &local) &&
            local.PsProtectionOffset != 0 &&
            local.PsProtectionOffset != info.ProtectionOffset) {
            std::wprintf(
                L"warning       : driver offset 0x%03lX differs from the pplctl "
                L"table 0x%03lX\n",
                static_cast<unsigned long>(info.ProtectionOffset),
                static_cast<unsigned long>(local.PsProtectionOffset));
        }
    }

    std::wprintf(L"EPROCESS      : mit1=%s mit2=%s objtbl=%s (diagnostic)\n",
                 OffsetOrDash(info.MitigationFlags1Offset).c_str(),
                 OffsetOrDash(info.MitigationFlags2Offset).c_str(),
                 OffsetOrDash(info.ObjectTableOffset).c_str());
    std::wprintf(L"max filters   : %lu\n", info.MaxFilters);
    std::wprintf(L"notify callback: %s\n",
                 (info.Flags & PPL_INFO_FLAG_NOTIFY_REGISTERED)
                     ? L"registered"
                     : L"not registered");

    return PplNtSuccess(info.Status) ? 0 : 1;
}

int
CommandBuilds()
{
    ULONG count = 0;
    const PPL_BUILD_OFFSETS* table = PplGetBuildOffsetTable(&count);
    ULONG currentBuild = QueryCurrentBuild();
    PPL_BUILD_OFFSETS currentOffsets = {};
    bool currentSupported = false;

    std::wprintf(L"compiled offset table : %lu builds\n", count);

    if (currentBuild != 0) {
        std::wprintf(L"current OS            : %s (build %lu)\n",
                     PplBuildDisplayName(currentBuild),
                     static_cast<unsigned long>(currentBuild));

        currentSupported =
            PplLookupBuildOffsets(currentBuild, &currentOffsets) &&
            currentOffsets.PsProtectionOffset != 0;
    } else {
        std::wprintf(L"current OS            : unknown (RtlGetVersion failed)\n");
    }

    std::wprintf(L"\n  %-1s %-6s %-31s %-7s %-7s %-7s %-7s\n",
                 L"", L"build", L"Windows version", L"PPL",
                 L"mit1", L"mit2", L"objtbl");

    for (ULONG i = 0; i < count; ++i) {
        const PPL_BUILD_OFFSETS& entry = table[i];

        std::wprintf(L"  %-1s %-6lu %-31s %-7s %-7s %-7s %-7s\n",
                     (entry.BuildNumber == currentBuild) ? L"*" : L"",
                     static_cast<unsigned long>(entry.BuildNumber),
                     PplBuildDisplayName(entry.BuildNumber),
                     OffsetOrDash(entry.PsProtectionOffset).c_str(),
                     OffsetOrDash(entry.PsMitigationFlags1Offset).c_str(),
                     OffsetOrDash(entry.PsMitigationFlags2Offset).c_str(),
                     OffsetOrDash(entry.ObjectTableOffset).c_str());
    }

    if (currentBuild == 0) {
        return 0;
    }

    std::wprintf(L"\ncurrent build PPL support: %s\n",
                 currentSupported ? L"yes" : L"no");
    if (currentSupported) {
        std::wprintf(L"  PS_PROTECTION offset: %s\n",
                     OffsetOrDash(currentOffsets.PsProtectionOffset).c_str());
    } else {
        std::wprintf(L"  Unknown builds are refused; add an entry to shared/PplBuilds.c.\n");
    }

    return currentSupported ? 0 : 1;
}

int
CommandSet(int argc, wchar_t** argv)
{
    ULONG processId = 0;
    UCHAR signer = PS_PROTECTED_SIGNER_ANTIMALWARE;
    bool audit = false;
    bool havePid = false;
    PPL_SET_REQUEST request = {};
    PPL_OPERATION_RESULT result = {};
    HANDLE device;
    DWORD returned = 0;

    for (int i = 2; i < argc; ++i) {
        if (_wcsicmp(argv[i], L"--pid") == 0 && i + 1 < argc) {
            havePid = ParseUlong(argv[++i], &processId);
            if (!havePid) {
                std::fwprintf(stderr, L"Invalid --pid value.\n");
                return 2;
            }
        } else if (_wcsicmp(argv[i], L"--signer") == 0 && i + 1 < argc) {
            if (!PplParseSigner(argv[++i], &signer)) {
                std::fwprintf(stderr, L"Unknown signer '%s'.\n", argv[i]);
                return 2;
            }
        } else if (_wcsicmp(argv[i], L"--audit") == 0) {
            audit = true;
        } else {
            std::fwprintf(stderr, L"Unknown option '%s'.\n", argv[i]);
            PrintUsage();
            return 2;
        }
    }

    if (!havePid) {
        std::fwprintf(stderr, L"set requires --pid <pid>.\n");
        return 2;
    }

    request.ProcessId = processId;
    request.Signer = signer;
    request.Type = PS_PROTECTED_TYPE_PROTECTED_LIGHT;
    request.Audit = audit ? 1 : 0;

    device = PplOpenDevice();
    if (device == INVALID_HANDLE_VALUE) {
        return 1;
    }

    BOOL ok = PplIoctl(device, IOCTL_PPL_SET_BY_PID,
                       &request, sizeof(request),
                       &result, sizeof(result), &returned);
    CloseHandle(device);
    if (!ok) {
        return 1;
    }

    std::wprintf(L"set pid %lu: %s (0x%08lX)\n",
                 processId,
                 PplNtStatusText(result.Status).c_str(),
                 static_cast<unsigned long>(result.Status));
    std::wprintf(L"  old protection: ");
    PrintProtection(result.OldProtection);
    std::wprintf(L"\n  new protection: ");
    PrintProtection(result.NewProtection);
    std::wprintf(L"\n");

    return PplNtSuccess(result.Status) ? 0 : 1;
}

int
CommandClear(int argc, wchar_t** argv)
{
    ULONG processId = 0;
    bool havePid = false;
    PPL_OPERATION_RESULT result = {};
    HANDLE device;
    DWORD returned = 0;

    for (int i = 2; i < argc; ++i) {
        if (_wcsicmp(argv[i], L"--pid") == 0 && i + 1 < argc) {
            havePid = ParseUlong(argv[++i], &processId);
            if (!havePid) {
                std::fwprintf(stderr, L"Invalid --pid value.\n");
                return 2;
            }
        } else {
            std::fwprintf(stderr, L"Unknown option '%s'.\n", argv[i]);
            return 2;
        }
    }

    if (!havePid) {
        std::fwprintf(stderr, L"clear requires --pid <pid>.\n");
        return 2;
    }

    device = PplOpenDevice();
    if (device == INVALID_HANDLE_VALUE) {
        return 1;
    }

    BOOL ok = PplIoctl(device, IOCTL_PPL_CLEAR_BY_PID,
                       &processId, sizeof(processId),
                       &result, sizeof(result), &returned);
    CloseHandle(device);
    if (!ok) {
        return 1;
    }

    std::wprintf(L"clear pid %lu: %s (0x%08lX)\n",
                 processId,
                 PplNtStatusText(result.Status).c_str(),
                 static_cast<unsigned long>(result.Status));
    std::wprintf(L"  old protection: ");
    PrintProtection(result.OldProtection);
    std::wprintf(L"\n  new protection: ");
    PrintProtection(result.NewProtection);
    std::wprintf(L"\n");

    return PplNtSuccess(result.Status) ? 0 : 1;
}

void
PrintUserModeProtection(
    _In_ ULONG ProcessId)
{
    HANDLE process;
    PROCESS_PROTECTION_LEVEL_INFORMATION information = {};

    process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, ProcessId);
    if (process == nullptr) {
        DWORD error = GetLastError();
        std::wprintf(L"  user-mode view : OpenProcess failed: %lu (%s)\n",
                     error, Win32ErrorText(error).c_str());
        return;
    }

    if (GetProcessInformation(process, ProcessProtectionLevelInfo,
                              &information, sizeof(information))) {
        std::wprintf(L"  user-mode view : protection=0x%08lX (%s)\n",
                     static_cast<unsigned long>(information.ProtectionLevel),
                     ProtectionLevelName(information.ProtectionLevel));
    } else {
        DWORD error = GetLastError();
        std::wprintf(L"  user-mode view : GetProcessInformation failed: %lu (%s)\n",
                     error, Win32ErrorText(error).c_str());
    }

    CloseHandle(process);
}

int
CommandQuery(int argc, wchar_t** argv)
{
    ULONG processId = 0;
    bool havePid = false;
    PPL_QUERY_RESULT result = {};
    HANDLE device;
    DWORD returned = 0;

    for (int i = 2; i < argc; ++i) {
        if (_wcsicmp(argv[i], L"--pid") == 0 && i + 1 < argc) {
            havePid = ParseUlong(argv[++i], &processId);
            if (!havePid) {
                std::fwprintf(stderr, L"Invalid --pid value.\n");
                return 2;
            }
        } else {
            std::fwprintf(stderr, L"Unknown option '%s'.\n", argv[i]);
            return 2;
        }
    }

    if (!havePid) {
        std::fwprintf(stderr, L"query requires --pid <pid>.\n");
        return 2;
    }

    device = PplOpenDevice();
    if (device == INVALID_HANDLE_VALUE) {
        return 1;
    }

    BOOL ok = PplIoctl(device, IOCTL_PPL_QUERY_BY_PID,
                       &processId, sizeof(processId),
                       &result, sizeof(result), &returned);
    CloseHandle(device);
    if (!ok) {
        return 1;
    }

    std::wprintf(L"pid %lu: %s (0x%08lX)\n",
                 processId,
                 PplNtStatusText(result.Status).c_str(),
                 static_cast<unsigned long>(result.Status));

    if (PplNtSuccess(result.Status)) {
        std::wprintf(L"  build          : %lu (%s)\n",
                     static_cast<unsigned long>(result.BuildNumber),
                     PplBuildDisplayName(result.BuildNumber));
        std::wprintf(L"  PPL offset     : 0x%03lX\n", result.ProtectionOffset);
        std::wprintf(L"  protection     : ");
        PrintProtection(result.Protection);
        std::wprintf(L"\n");
        std::wprintf(L"  signature level: 0x%02X\n", result.SignatureLevel);
        std::wprintf(L"  section level  : 0x%02X\n", result.SectionSignatureLevel);
        std::wprintf(L"  PsIsProtectedProcess     : %s\n",
                     (result.Flags & 1) ? L"TRUE" : L"FALSE");
        std::wprintf(L"  PsIsProtectedProcessLight: %s\n",
                     (result.Flags & 2) ? L"TRUE" : L"FALSE");
    }

    PrintUserModeProtection(processId);
    return PplNtSuccess(result.Status) ? 0 : 1;
}

void
ProbeAccess(
    _In_ ULONG ProcessId,
    _In_ DWORD Access,
    _In_ const wchar_t* Label)
{
    HANDLE process;

    SetLastError(ERROR_SUCCESS);
    process = OpenProcess(Access, FALSE, ProcessId);
    if (process != nullptr) {
        std::wprintf(L"  %-46s OPEN\n", Label);
        CloseHandle(process);
        return;
    }

    {
        DWORD error = GetLastError();
        std::wprintf(L"  %-46s DENIED (%lu: %s)\n",
                     Label, error, Win32ErrorText(error).c_str());
    }
}

int
CommandProbe(int argc, wchar_t** argv)
{
    ULONG processId = 0;
    bool havePid = false;
    bool debugEnabled;

    for (int i = 2; i < argc; ++i) {
        if (_wcsicmp(argv[i], L"--pid") == 0 && i + 1 < argc) {
            havePid = ParseUlong(argv[++i], &processId);
            if (!havePid) {
                std::fwprintf(stderr, L"Invalid --pid value.\n");
                return 2;
            }
        } else {
            std::fwprintf(stderr, L"Unknown option '%s'.\n", argv[i]);
            return 2;
        }
    }

    if (!havePid) {
        std::fwprintf(stderr, L"probe requires --pid <pid>.\n");
        return 2;
    }

    debugEnabled = EnablePrivilege(SE_DEBUG_NAME);
    std::wprintf(L"probe pid %lu (SeDebugPrivilege %s)\n",
                 processId,
                 debugEnabled ? L"enabled" : L"NOT enabled");

    ProbeAccess(processId, PROCESS_ALL_ACCESS,
                L"PROCESS_ALL_ACCESS (expect DENIED)");
    ProbeAccess(processId, PROCESS_VM_READ | PROCESS_QUERY_INFORMATION,
                L"VM_READ|QUERY_INFORMATION (expect DENIED)");
    ProbeAccess(processId, PROCESS_QUERY_LIMITED_INFORMATION,
                L"QUERY_LIMITED_INFORMATION (normally allowed)");

    return 0;
}

bool
ParseFilterName(
    _In_ const std::wstring& Name)
{
    size_t length = Name.size();
    return length >= 3 && length < PPL_MAX_PATTERN_CHARS;
}

int
CommandFilterAdd(int argc, wchar_t** argv)
{
    std::wstring pattern;
    UCHAR signer = PS_PROTECTED_SIGNER_ANTIMALWARE;
    bool audit = false;
    bool exact = false;
    bool applyExisting = false;
    PPL_FILTER_REQUEST request = {};
    PPL_FILTER_RESULT result = {};
    HANDLE device;
    DWORD returned = 0;

    for (int i = 3; i < argc; ++i) {
        if (_wcsicmp(argv[i], L"--name") == 0 && i + 1 < argc) {
            pattern = argv[++i];
        } else if (_wcsicmp(argv[i], L"--signer") == 0 && i + 1 < argc) {
            if (!PplParseSigner(argv[++i], &signer)) {
                std::fwprintf(stderr, L"Unknown signer '%s'.\n", argv[i]);
                return 2;
            }
        } else if (_wcsicmp(argv[i], L"--audit") == 0) {
            audit = true;
        } else if (_wcsicmp(argv[i], L"--exact") == 0) {
            exact = true;
        } else if (_wcsicmp(argv[i], L"--apply-existing") == 0) {
            applyExisting = true;
        } else {
            std::fwprintf(stderr, L"Unknown option '%s'.\n", argv[i]);
            return 2;
        }
    }

    if (!ParseFilterName(pattern)) {
        std::fwprintf(stderr,
                      L"--name must be 3..%d characters.\n",
                      PPL_MAX_PATTERN_CHARS - 1);
        return 2;
    }

    wcsncpy_s(request.Pattern, PPL_MAX_PATTERN_CHARS,
              pattern.c_str(), _TRUNCATE);
    request.MatchMode = exact ? PPL_MATCH_EXACT : PPL_MATCH_SUBSTRING;
    request.Flags = applyExisting ? PPL_FILTER_FLAG_APPLY_EXISTING : 0;
    request.Signer = signer;
    request.Audit = audit ? 1 : 0;

    device = PplOpenDevice();
    if (device == INVALID_HANDLE_VALUE) {
        return 1;
    }

    BOOL ok = PplIoctl(device, IOCTL_PPL_FILTER_ADD,
                       &request, sizeof(request),
                       &result, sizeof(result), &returned);
    CloseHandle(device);
    if (!ok) {
        return 1;
    }

    std::wprintf(L"filter add '%s': %s (0x%08lX), applied=%lu skipped=%lu failed=%lu\n",
                 pattern.c_str(),
                 PplNtStatusText(result.Status).c_str(),
                 static_cast<unsigned long>(result.Status),
                 result.Applied, result.Skipped, result.Failed);

    return PplNtSuccess(result.Status) ? 0 : 1;
}

int
CommandFilterRemove(int argc, wchar_t** argv)
{
    std::wstring pattern;
    PPL_FILTER_REQUEST request = {};
    PPL_FILTER_RESULT result = {};
    HANDLE device;
    DWORD returned = 0;

    for (int i = 3; i < argc; ++i) {
        if (_wcsicmp(argv[i], L"--name") == 0 && i + 1 < argc) {
            pattern = argv[++i];
        } else {
            std::fwprintf(stderr, L"Unknown option '%s'.\n", argv[i]);
            return 2;
        }
    }

    if (pattern.empty() || pattern.size() >= PPL_MAX_PATTERN_CHARS) {
        std::fwprintf(stderr, L"filter remove requires a valid --name.\n");
        return 2;
    }

    wcsncpy_s(request.Pattern, PPL_MAX_PATTERN_CHARS,
              pattern.c_str(), _TRUNCATE);

    device = PplOpenDevice();
    if (device == INVALID_HANDLE_VALUE) {
        return 1;
    }

    BOOL ok = PplIoctl(device, IOCTL_PPL_FILTER_REMOVE,
                       &request, sizeof(request),
                       &result, sizeof(result), &returned);
    CloseHandle(device);
    if (!ok) {
        return 1;
    }

    std::wprintf(L"filter remove '%s': %s (0x%08lX), removed=%lu\n",
                 pattern.c_str(),
                 PplNtStatusText(result.Status).c_str(),
                 static_cast<unsigned long>(result.Status),
                 result.Applied);
    return PplNtSuccess(result.Status) ? 0 : 1;
}

int
CommandFilterClear()
{
    PPL_FILTER_RESULT result = {};
    HANDLE device;
    DWORD returned = 0;

    device = PplOpenDevice();
    if (device == INVALID_HANDLE_VALUE) {
        return 1;
    }

    BOOL ok = PplIoctl(device, IOCTL_PPL_FILTER_CLEAR,
                       nullptr, 0,
                       &result, sizeof(result), &returned);
    CloseHandle(device);
    if (!ok) {
        return 1;
    }

    std::wprintf(L"filter clear: %s (0x%08lX), removed=%lu\n",
                 PplNtStatusText(result.Status).c_str(),
                 static_cast<unsigned long>(result.Status),
                 result.Applied);
    std::wprintf(L"Already-protected processes remain protected; use clear --pid or stop the driver.\n");
    return PplNtSuccess(result.Status) ? 0 : 1;
}

int
CommandFilterList()
{
    PPL_FILTER_LIST list = {};
    HANDLE device;
    DWORD returned = 0;

    device = PplOpenDevice();
    if (device == INVALID_HANDLE_VALUE) {
        return 1;
    }

    BOOL ok = PplIoctl(device, IOCTL_PPL_FILTER_LIST,
                       nullptr, 0,
                       &list, sizeof(list), &returned);
    CloseHandle(device);
    if (!ok) {
        return 1;
    }

    if (!PplNtSuccess(list.Status)) {
        std::wprintf(L"filter list: %s (0x%08lX)\n",
                     PplNtStatusText(list.Status).c_str(),
                     static_cast<unsigned long>(list.Status));
        return 1;
    }

    std::wprintf(L"%lu filter(s)\n", list.Count);
    for (ULONG i = 0; i < list.Count && i < PPL_MAX_FILTERS; ++i) {
        const PPL_FILTER_LIST_ENTRY& entry = list.Entries[i];
        std::wprintf(L"  [%lu] '%s' mode=%s signer=%s audit=%u\n",
                     i,
                     entry.Pattern,
                     entry.MatchMode == PPL_MATCH_EXACT ? L"exact" : L"substring",
                     PplSignerName(entry.Signer),
                     static_cast<unsigned>(entry.Audit));
    }
    return 0;
}

std::wstring
FullPipePath(
    _In_ const std::wstring& Pipe)
{
    if (Pipe.size() >= 2 && Pipe[0] == L'\\' && Pipe[1] == L'\\') {
        return Pipe;
    }
    return std::wstring(L"\\\\.\\pipe\\") + Pipe;
}

bool
WritePipeLine(
    _In_ HANDLE Pipe,
    _In_ const std::wstring& Line)
{
    DWORD written = 0;
    std::wstring message = Line + L"\r\n";

    if (!WriteFile(Pipe, message.c_str(),
                   static_cast<DWORD>(message.size() * sizeof(wchar_t)),
                   &written, nullptr)) {
        std::fwprintf(stderr, L"pipe write failed: %lu (%s)\n",
                      GetLastError(), Win32ErrorText(GetLastError()).c_str());
        return false;
    }

    FlushFileBuffers(Pipe);
    return true;
}

int
CommandBroker(int argc, wchar_t** argv)
{
    std::wstring pipeName = PPL_DEFAULT_PIPE;
    UCHAR signer = PS_PROTECTED_SIGNER_ANTIMALWARE;
    bool audit = false;
    bool once = false;
    bool adminOnly = false;
    HANDLE device;
    PSECURITY_DESCRIPTOR securityDescriptor = nullptr;
    SECURITY_ATTRIBUTES securityAttributes = {};
    const wchar_t* sddl =
        L"D:P(A;;GA;;;WD)";

    for (int i = 2; i < argc; ++i) {
        if (_wcsicmp(argv[i], L"--pipe") == 0 && i + 1 < argc) {
            pipeName = argv[++i];
        } else if (_wcsicmp(argv[i], L"--signer") == 0 && i + 1 < argc) {
            if (!PplParseSigner(argv[++i], &signer)) {
                std::fwprintf(stderr, L"Unknown signer '%s'.\n", argv[i]);
                return 2;
            }
        } else if (_wcsicmp(argv[i], L"--audit") == 0) {
            audit = true;
        } else if (_wcsicmp(argv[i], L"--once") == 0) {
            once = true;
        } else if (_wcsicmp(argv[i], L"--allow-all") == 0) {
            adminOnly = false;
        } else if (_wcsicmp(argv[i], L"--admin-only") == 0) {
            adminOnly = true;
        } else {
            std::fwprintf(stderr, L"Unknown option '%s'.\n", argv[i]);
            return 2;
        }
    }

    if (adminOnly) {
        sddl = L"D:P(A;;GA;;;SY)(A;;GA;;;BA)";
    }

    device = PplOpenDevice();
    if (device == INVALID_HANDLE_VALUE) {
        return 1;
    }

    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl, SDDL_REVISION_1, &securityDescriptor, nullptr)) {
        std::fwprintf(stderr, L"Could not build pipe DACL: %lu (%s)\n",
                      GetLastError(), Win32ErrorText(GetLastError()).c_str());
        CloseHandle(device);
        return 1;
    }

    securityAttributes.nLength = sizeof(securityAttributes);
    securityAttributes.lpSecurityDescriptor = securityDescriptor;
    securityAttributes.bInheritHandle = FALSE;

    std::wstring pipePath = FullPipePath(pipeName);
    std::wprintf(L"broker pid=%lu pipe=%s signer=%s type=ppl\n",
                 GetCurrentProcessId(), pipePath.c_str(),
                 PplSignerName(signer));
    if (!adminOnly) {
        std::wprintf(L"WARNING: the default pipe DACL grants PPL to every local process that connects.\n"
                     L"         Use only in an isolated test VM, or restart with --admin-only.\n");
    }
    std::wprintf(L"Waiting for clients...\n");

    for (;;) {
        HANDLE pipe = CreateNamedPipeW(
            pipePath.c_str(),
            PIPE_ACCESS_DUPLEX | FILE_FLAG_WRITE_THROUGH,
            PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT |
                PIPE_REJECT_REMOTE_CLIENTS,
            PIPE_UNLIMITED_INSTANCES,
            4096, 4096, 0, &securityAttributes);

        if (pipe == INVALID_HANDLE_VALUE) {
            std::fwprintf(stderr, L"CreateNamedPipeW failed: %lu (%s)\n",
                          GetLastError(), Win32ErrorText(GetLastError()).c_str());
            break;
        }

        BOOL connected = ConnectNamedPipe(pipe, nullptr);
        DWORD connectError = connected ? ERROR_SUCCESS : GetLastError();

        if (!connected && connectError != ERROR_PIPE_CONNECTED) {
            std::fwprintf(stderr, L"ConnectNamedPipe failed: %lu (%s)\n",
                          connectError, Win32ErrorText(connectError).c_str());
            CloseHandle(pipe);
            break;
        }

        ULONG clientPid = 0;
        bool gotPid = GetNamedPipeClientProcessId(pipe, &clientPid) != FALSE;
        std::wstring reply;

        if (!gotPid) {
            DWORD error = GetLastError();
            reply = L"ERR pid=0 status=0x00000000 io_error=" +
                    std::to_wstring(error);
        } else if (static_cast<ULONG>(GetCurrentProcessId()) == clientPid ||
                   clientPid == 0 || clientPid == 4) {
            wchar_t message[160];
            std::swprintf(message, 160,
                          L"ERR pid=%lu status=0x00000000 reason=blocklisted",
                          clientPid);
            reply = message;
        } else {
            std::wstring imagePath;
            HANDLE clientProcess = OpenProcess(
                PROCESS_QUERY_LIMITED_INFORMATION, FALSE, clientPid);

            if (clientProcess != nullptr) {
                wchar_t path[1024];
                DWORD pathLength = static_cast<DWORD>(
                    sizeof(path) / sizeof(path[0]));
                if (QueryFullProcessImageNameW(clientProcess, 0,
                                               path, &pathLength)) {
                    imagePath.assign(path, pathLength);
                }
                CloseHandle(clientProcess);
            }

            if (!imagePath.empty() && IsBlockedImageName(imagePath)) {
                wchar_t message[160];
                std::swprintf(message, 160,
                              L"ERR pid=%lu status=0x00000000 reason=blocklisted",
                              clientPid);
                reply = message;
            } else {
                PPL_SET_REQUEST request = {};
                PPL_OPERATION_RESULT result = {};
                DWORD returned = 0;

                request.ProcessId = clientPid;
                request.Signer = signer;
                request.Type = PS_PROTECTED_TYPE_PROTECTED_LIGHT;
                request.Audit = audit ? 1 : 0;

                BOOL ok = PplIoctl(device, IOCTL_PPL_SET_BY_PID,
                                   &request, sizeof(request),
                                   &result, sizeof(result),
                                   &returned, true);

                wchar_t message[256];
                if (!ok) {
                    DWORD error = GetLastError();
                    std::swprintf(message, 256,
                                  L"ERR pid=%lu status=0x%08lX io_error=%lu",
                                  clientPid,
                                  static_cast<unsigned long>(result.Status),
                                  error);
                } else if (PplNtSuccess(result.Status)) {
                    std::swprintf(message, 256,
                                  L"OK pid=%lu protection=0x%02X signer=%s type=ppl",
                                  clientPid,
                                  result.NewProtection,
                                  PplSignerName(signer));
                } else {
                    std::swprintf(message, 256,
                                  L"ERR pid=%lu status=0x%08lX",
                                  clientPid,
                                  static_cast<unsigned long>(result.Status));
                }
                reply = message;
            }
        }

        std::wprintf(L"%s\n", reply.c_str());
        WritePipeLine(pipe, reply);

        DisconnectNamedPipe(pipe);
        CloseHandle(pipe);

        if (once) {
            break;
        }
    }

    LocalFree(securityDescriptor);
    CloseHandle(device);
    return 0;
}

int
CommandConnect(int argc, wchar_t** argv)
{
    std::wstring pipeName = PPL_DEFAULT_PIPE;
    ULONG holdSeconds = 0;

    for (int i = 2; i < argc; ++i) {
        if (_wcsicmp(argv[i], L"--pipe") == 0 && i + 1 < argc) {
            pipeName = argv[++i];
        } else if (_wcsicmp(argv[i], L"--hold") == 0 && i + 1 < argc) {
            if (!ParseUlong(argv[++i], &holdSeconds) || holdSeconds > 86400) {
                std::fwprintf(stderr, L"Invalid --hold value.\n");
                return 2;
            }
        } else {
            std::fwprintf(stderr, L"Unknown option '%s'.\n", argv[i]);
            return 2;
        }
    }

    std::wstring pipePath = FullPipePath(pipeName);
    std::wprintf(L"connect pid=%lu pipe=%s\n",
                 GetCurrentProcessId(), pipePath.c_str());
    std::wprintf(L"Ask the broker to grant PPL to PID %lu.\n",
                 GetCurrentProcessId());

    HANDLE pipe = CreateFileW(
        pipePath.c_str(),
        GENERIC_READ | GENERIC_WRITE,
        0,
        nullptr,
        OPEN_EXISTING,
        0,
        nullptr);

    if (pipe == INVALID_HANDLE_VALUE) {
        DWORD error = GetLastError();
        std::fwprintf(stderr, L"Could not open pipe: %lu (%s)\n",
                      error, Win32ErrorText(error).c_str());
        return 1;
    }

    DWORD mode = PIPE_READMODE_MESSAGE;
    SetNamedPipeHandleState(pipe, &mode, nullptr, nullptr);

    wchar_t response[512] = {};
    DWORD bytesRead = 0;
    if (!ReadFile(pipe, response,
                  static_cast<DWORD>(sizeof(response) - sizeof(wchar_t)),
                  &bytesRead, nullptr)) {
        DWORD error = GetLastError();
        std::fwprintf(stderr, L"ReadFile failed: %lu (%s)\n",
                      error, Win32ErrorText(error).c_str());
        CloseHandle(pipe);
        return 1;
    }
    response[bytesRead / sizeof(wchar_t)] = L'\0';

    std::wprintf(L"broker: %s\n", response);
    bool ok = wcsncmp(response, L"OK ", 3) == 0;

    if (holdSeconds > 0) {
        std::wprintf(L"holding for %lu seconds...\n", holdSeconds);
        Sleep(holdSeconds * 1000);
    } else {
        std::wprintf(L"Press Enter to exit and release the process...\n");
        FlushConsoleInputBuffer(GetStdHandle(STD_INPUT_HANDLE));
        (void)getwchar();
    }

    CloseHandle(pipe);
    return ok ? 0 : 1;
}

int
CommandFilter(int argc, wchar_t** argv)
{
    if (argc < 3) {
        std::fwprintf(stderr, L"filter requires add, remove, clear or list.\n");
        return 2;
    }

    if (_wcsicmp(argv[2], L"add") == 0) {
        return CommandFilterAdd(argc, argv);
    }
    if (_wcsicmp(argv[2], L"remove") == 0) {
        return CommandFilterRemove(argc, argv);
    }
    if (_wcsicmp(argv[2], L"clear") == 0) {
        if (argc != 3) {
            std::fwprintf(stderr, L"filter clear takes no options.\n");
            return 2;
        }
        return CommandFilterClear();
    }
    if (_wcsicmp(argv[2], L"list") == 0) {
        if (argc != 3) {
            std::fwprintf(stderr, L"filter list takes no options.\n");
            return 2;
        }
        return CommandFilterList();
    }

    std::fwprintf(stderr, L"Unknown filter command '%s'.\n", argv[2]);
    return 2;
}

} // namespace

int
wmain(
    _In_ int argc,
    _In_ wchar_t** argv)
{
    if (argc < 2) {
        PrintUsage();
        return 2;
    }

    if (_wcsicmp(argv[1], L"info") == 0) {
        return CommandInfo();
    }
    if (_wcsicmp(argv[1], L"set") == 0) {
        return CommandSet(argc, argv);
    }
    if (_wcsicmp(argv[1], L"clear") == 0) {
        return CommandClear(argc, argv);
    }
    if (_wcsicmp(argv[1], L"query") == 0) {
        return CommandQuery(argc, argv);
    }
    if (_wcsicmp(argv[1], L"probe") == 0) {
        return CommandProbe(argc, argv);
    }
    if (_wcsicmp(argv[1], L"filter") == 0) {
        return CommandFilter(argc, argv);
    }
    if (_wcsicmp(argv[1], L"broker") == 0) {
        return CommandBroker(argc, argv);
    }
    if (_wcsicmp(argv[1], L"connect") == 0) {
        return CommandConnect(argc, argv);
    }
    if (_wcsicmp(argv[1], L"builds") == 0) {
        return CommandBuilds();
    }
    if (_wcsicmp(argv[1], L"version") == 0) {
        ULONG build = QueryCurrentBuild();

        std::wprintf(L"MakeMePPL %s\n", PPL_DRIVER_VERSION);
        if (build != 0) {
            std::wprintf(L"OS: %s (build %lu)\n",
                         PplBuildDisplayName(build),
                         static_cast<unsigned long>(build));
        }
        return 0;
    }
    if (_wcsicmp(argv[1], L"help") == 0 ||
        _wcsicmp(argv[1], L"--help") == 0 ||
        _wcsicmp(argv[1], L"-h") == 0) {
        PrintUsage();
        return 0;
    }

    std::fwprintf(stderr, L"Unknown command '%s'.\n", argv[1]);
    PrintUsage();
    return 2;
}
