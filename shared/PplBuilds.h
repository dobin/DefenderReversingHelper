#pragma once

//
// Windows build numbers and build-specific EPROCESS offsets.
//
// The build constants and the offset data are ported from KDU ("Kernel Driver
// Utility"):
//
//   Source/Shared/ntos/ntbuilds.h   build numbers
//   Source/Hamakaze/ps.h            PsProtectionOffset_* and friends
//   Source/Hamakaze/ps.cpp          KDUGetEprocessOffsets
//
// KDU resolves offsets from an exact NT build number and refuses unknown
// builds. We keep that rule: an unknown build must never be guessed, because
// writing the wrong EPROCESS byte can bugcheck the machine.
//
// PsProtectionOffset is used to set PPL. PsMitigationFlags1Offset is used by
// the allow-dlls operation; the other offsets are diagnostics.
//

#if defined(_KERNEL_MODE)
#include <ntddk.h>
#else
#include <windows.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

//
// Major Windows NT builds (KDU ntbuilds.h). The list starts at Windows 7 so
// that an old host gets a useful name in the log instead of "unknown".
//
#define PPL_NT_WIN7_RTM             7600
#define PPL_NT_WIN7_SP1             7601
#define PPL_NT_WIN8_RTM             9200
#define PPL_NT_WIN8_BLUE            9600    // Windows 8.1
#define PPL_NT_WIN10_THRESHOLD1     10240   // Windows 10 1507
#define PPL_NT_WIN10_THRESHOLD2     10586   // Windows 10 1511
#define PPL_NT_WIN10_REDSTONE1      14393   // Windows 10 1607
#define PPL_NT_WIN10_REDSTONE2      15063   // Windows 10 1703
#define PPL_NT_WIN10_REDSTONE3      16299   // Windows 10 1709
#define PPL_NT_WIN10_REDSTONE4      17134   // Windows 10 1803
#define PPL_NT_WIN10_REDSTONE5      17763   // Windows 10 1809
#define PPL_NT_WIN10_19H1           18362   // Windows 10 1903
#define PPL_NT_WIN10_19H2           18363   // Windows 10 1909
#define PPL_NT_WIN10_20H1           19041   // Windows 10 2004
#define PPL_NT_WIN10_20H2           19042   // Windows 10 20H2
#define PPL_NT_WIN10_21H1           19043   // Windows 10 21H1
#define PPL_NT_WIN10_21H2           19044   // Windows 10 21H2
#define PPL_NT_WIN10_22H2           19045   // Windows 10 22H2
#define PPL_NT_WINSRV_21H1          20348   // Windows Server 2022
#define PPL_NT_WIN11_21H2           22000   // Windows 11 21H2
#define PPL_NT_WIN11_22H2           22621   // Windows 11 22H2
#define PPL_NT_WIN11_23H2           22631   // Windows 11 23H2
#define PPL_NT_WIN11_24H2           26100   // Windows 11 24H2, Server 2025
#define PPL_NT_WIN11_25H2           26200   // Windows 11 25H2
#define PPL_NT_WIN11_26H1           28000   // Windows 11 26H1
#define PPL_NT_WIN11_26H2           26300   // Windows 11 26H2
#define PPL_NT_WIN11_ADB            29595   // Windows 11 development branch

//
// PS_PROTECTION exists from Windows 8.1 (build 9600) onward.
//
#define PPL_MIN_SUPPORTED_BUILD     PPL_NT_WIN8_BLUE

//
// EPROCESS offsets for one NT build. A zero field means "not known for this
// build"; callers must treat that as unsupported for the matching operation.
//
typedef struct _PPL_BUILD_OFFSETS {
    ULONG BuildNumber;
    ULONG PsProtectionOffset;          // EPROCESS!PS_PROTECTION (UCHAR)
    ULONG PsMitigationFlags1Offset;    // EPROCESS!MitigationFlags
    ULONG PsMitigationFlags2Offset;    // EPROCESS!MitigationFlagsHigh
    ULONG ObjectTableOffset;           // EPROCESS!ObjectTable
} PPL_BUILD_OFFSETS, *PPPL_BUILD_OFFSETS;

//
// Human-readable name for a build, e.g. L"Windows 11 24H2". Never NULL.
//
const WCHAR* PplBuildDisplayName(
    _In_ ULONG BuildNumber);

//
// Looks up the offset set for an exact NT build number. Returns FALSE and a
// zeroed (except BuildNumber) structure when the build is not in the table.
//
BOOLEAN PplLookupBuildOffsets(
    _In_ ULONG BuildNumber,
    _Out_ PPPL_BUILD_OFFSETS Offsets);

//
// Read-only access to the compiled table, used by "pplctl builds".
//
const PPL_BUILD_OFFSETS* PplGetBuildOffsetTable(
    _Out_opt_ PULONG Count);

#ifdef __cplusplus
}
#endif
