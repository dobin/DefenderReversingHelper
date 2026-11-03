#include "PplDriverClient.h"

#include <cstdio>
#include <cwchar>

HANDLE
PplOpenDevice(
    _In_ bool Quiet)
{
    HANDLE device;

    device = CreateFileW(
        PPL_WIN32_DEVICE,
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr,
        OPEN_EXISTING,
        0,
        nullptr);

    if (device == INVALID_HANDLE_VALUE && !Quiet) {
        DWORD error = GetLastError();
        std::fwprintf(stderr,
                      L"Could not open %s: error %lu (%s)\n",
                      PPL_WIN32_DEVICE, error,
                      error == ERROR_ACCESS_DENIED
                          ? L"access denied by the driver device DACL"
                          : error == ERROR_FILE_NOT_FOUND
                                ? L"is the MakeMePPL driver loaded?"
                                : L"unknown error");
    }

    return device;
}

BOOL
PplIoctl(
    _In_ HANDLE Device,
    _In_ DWORD IoctlCode,
    _In_opt_ const void* Input,
    _In_ DWORD InputSize,
    _Out_opt_ void* Output,
    _In_ DWORD OutputSize,
    _Out_opt_ DWORD* BytesReturned,
    _In_ bool Quiet)
{
    DWORD returned = 0;
    BOOL ok;

    ok = DeviceIoControl(
        Device,
        IoctlCode,
        const_cast<void*>(Input),
        InputSize,
        Output,
        OutputSize,
        &returned,
        nullptr);

    if (BytesReturned != nullptr) {
        *BytesReturned = returned;
    }

    if (!ok && !Quiet) {
        DWORD error = GetLastError();
        std::fwprintf(stderr,
                      L"DeviceIoControl(0x%08lX) failed: error %lu%s\n",
                      static_cast<unsigned long>(IoctlCode),
                      error,
                      error == ERROR_ACCESS_DENIED
                          ? L" (access denied by the driver device DACL)"
                          : L"");
    }

    return ok;
}

bool
PplNtSuccess(
    _In_ NTSTATUS Status)
{
    return Status >= 0;
}

std::wstring
PplNtStatusText(
    _In_ NTSTATUS Status)
{
    wchar_t buffer[64];

    switch (static_cast<ULONG>(Status)) {
    case 0x00000000UL:
        return L"STATUS_SUCCESS";
    case 0xC000000DUL:
        return L"STATUS_INVALID_PARAMETER";
    case 0xC0000022UL:
        return L"STATUS_ACCESS_DENIED";
    case 0xC0000034UL:
        return L"STATUS_OBJECT_NAME_NOT_FOUND";
    case 0xC0000035UL:
        return L"STATUS_OBJECT_NAME_COLLISION";
    case 0xC0000225UL:
        return L"STATUS_NOT_FOUND";
    case 0xC00000BBUL:
        return L"STATUS_NOT_SUPPORTED";
    case 0xC0000001UL:
        return L"STATUS_UNSUCCESSFUL";
    case 0xC0000017UL:
        return L"STATUS_NO_MEMORY";
    case 0xC000009AUL:
        return L"STATUS_INSUFFICIENT_RESOURCES";
    case 0xC000010AUL:
        return L"STATUS_PROCESS_IS_TERMINATING";
    default:
        std::swprintf(buffer, sizeof(buffer) / sizeof(buffer[0]),
                      L"0x%08lX",
                      static_cast<unsigned long>(Status));
        return buffer;
    }
}

bool
PplParseSigner(
    _In_ const wchar_t* Name,
    _Out_ UCHAR* Signer)
{
    if (Name == nullptr || Signer == nullptr) {
        return false;
    }

    if (_wcsicmp(Name, L"am") == 0 ||
        _wcsicmp(Name, L"antimalware") == 0) {
        *Signer = PS_PROTECTED_SIGNER_ANTIMALWARE;
        return true;
    }
    if (_wcsicmp(Name, L"wintcb") == 0) {
        *Signer = PS_PROTECTED_SIGNER_WINTCB;
        return true;
    }
    if (_wcsicmp(Name, L"windows") == 0) {
        *Signer = PS_PROTECTED_SIGNER_WINDOWS;
        return true;
    }
    if (_wcsicmp(Name, L"lsa") == 0) {
        *Signer = PS_PROTECTED_SIGNER_LSA;
        return true;
    }
    if (_wcsicmp(Name, L"authenticode") == 0) {
        *Signer = PS_PROTECTED_SIGNER_AUTHENTICODE;
        return true;
    }
    if (_wcsicmp(Name, L"codegen") == 0) {
        *Signer = PS_PROTECTED_SIGNER_CODEGEN;
        return true;
    }
    if (_wcsicmp(Name, L"winsystem") == 0) {
        *Signer = PS_PROTECTED_SIGNER_WINSYSTEM;
        return true;
    }
    if (_wcsicmp(Name, L"app") == 0) {
        *Signer = PS_PROTECTED_SIGNER_APP;
        return true;
    }

    {
        wchar_t* end = nullptr;
        unsigned long value = std::wcstoul(Name, &end, 0);
        if (end != Name && *end == L'\0' &&
            value >= PS_PROTECTED_SIGNER_AUTHENTICODE &&
            value <= PS_PROTECTED_SIGNER_APP) {
            *Signer = static_cast<UCHAR>(value);
            return true;
        }
    }

    return false;
}

const wchar_t*
PplSignerName(
    _In_ UCHAR Signer)
{
    switch (Signer) {
    case PS_PROTECTED_SIGNER_AUTHENTICODE:
        return L"authenticode";
    case PS_PROTECTED_SIGNER_CODEGEN:
        return L"codegen";
    case PS_PROTECTED_SIGNER_ANTIMALWARE:
        return L"antimalware";
    case PS_PROTECTED_SIGNER_LSA:
        return L"lsa";
    case PS_PROTECTED_SIGNER_WINDOWS:
        return L"windows";
    case PS_PROTECTED_SIGNER_WINTCB:
        return L"wintcb";
    case PS_PROTECTED_SIGNER_WINSYSTEM:
        return L"winsystem";
    case PS_PROTECTED_SIGNER_APP:
        return L"app";
    default:
        return L"none";
    }
}

const wchar_t*
PplProtectionTypeName(
    _In_ UCHAR Protection)
{
    switch (Protection & 0x7) {
    case PS_PROTECTED_TYPE_PROTECTED_LIGHT:
        return L"ppl";
    case PS_PROTECTED_TYPE_PROTECTED:
        return L"protected";
    default:
        return L"none";
    }
}
