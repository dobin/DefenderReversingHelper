#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <winioctl.h>
#include <string>

#include "../shared/PplIoctl.h"

HANDLE PplOpenDevice(_In_ bool Quiet = false);

BOOL PplIoctl(
    _In_ HANDLE Device,
    _In_ DWORD IoctlCode,
    _In_opt_ const void* Input,
    _In_ DWORD InputSize,
    _Out_opt_ void* Output,
    _In_ DWORD OutputSize,
    _Out_opt_ DWORD* BytesReturned = nullptr,
    _In_ bool Quiet = false);

bool PplNtSuccess(_In_ NTSTATUS Status);

std::wstring PplNtStatusText(_In_ NTSTATUS Status);

bool PplParseSigner(_In_ const wchar_t* Name, _Out_ UCHAR* Signer);

const wchar_t* PplSignerName(_In_ UCHAR Signer);

const wchar_t* PplProtectionTypeName(_In_ UCHAR Protection);
