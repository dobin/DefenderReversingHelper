#include "PplBuilds.h"

//
// Build-specific EPROCESS offsets, ported from KDU's KDUGetEprocessOffsets
// (Source/Hamakaze/ps.cpp) and the PsProtectionOffset_* constants in
// Source/Hamakaze/ps.h.
//
// KDU keeps a single entry per NT build even where several releases share
// the same layout, so an unknown build can never silently inherit a nearby
// offset. Keep that property when extending the table.
//
static const PPL_BUILD_OFFSETS PplBuildOffsets[] = {
    //
    // Windows 8.1. PPL was introduced here; no mitigation/object-table data
    // is needed by this driver.
    //
    { PPL_NT_WIN8_BLUE,            0x67A, 0,     0,     0     },

    //
    // Windows 10 TH1 / TH2 / RS1.
    //
    { PPL_NT_WIN10_THRESHOLD1,     0x6AA, 0,     0,     0     },
    { PPL_NT_WIN10_THRESHOLD2,     0x6B2, 0,     0,     0     },
    { PPL_NT_WIN10_REDSTONE1,      0x6C2, 0,     0,     0     },

    //
    // Windows 10 RS2..RS5 share PsProtectionOffset 0x6CA.
    //
    { PPL_NT_WIN10_REDSTONE2,      0x6CA, 0,     0,     0     },
    { PPL_NT_WIN10_REDSTONE3,      0x6CA, 0x828, 0x82C, 0     },
    { PPL_NT_WIN10_REDSTONE4,      0x6CA, 0x828, 0x82C, 0     },
    { PPL_NT_WIN10_REDSTONE5,      0x6CA, 0x820, 0x824, 0     },

    //
    // Windows 10 1903 / 1909.
    //
    { PPL_NT_WIN10_19H1,           0x6FA, 0x850, 0x854, 0     },
    { PPL_NT_WIN10_19H2,           0x6FA, 0x850, 0x854, 0     },

    //
    // Windows 10 2004..22H2, Windows Server 2022 and Windows 11 21H2..23H2
    // all use PsProtectionOffset 0x87A.
    //
    { PPL_NT_WIN10_20H1,           0x87A, 0x9D0, 0x9D4, 0x570 },
    { PPL_NT_WIN10_20H2,           0x87A, 0x9D0, 0x9D4, 0x570 },
    { PPL_NT_WIN10_21H1,           0x87A, 0x9D0, 0x9D4, 0x570 },
    { PPL_NT_WIN10_21H2,           0x87A, 0x9D0, 0x9D4, 0x570 },
    { PPL_NT_WIN10_22H2,           0x87A, 0x9D0, 0x9D4, 0x570 },
    { PPL_NT_WINSRV_21H1,          0x87A, 0x9D0, 0x9D4, 0x570 },
    { PPL_NT_WIN11_21H2,           0x87A, 0x9D0, 0x9D4, 0x570 },
    { PPL_NT_WIN11_22H2,           0x87A, 0x9D0, 0x9D4, 0x570 },
    { PPL_NT_WIN11_23H2,           0x87A, 0x9D0, 0x9D4, 0x570 },

    //
    // Windows 11 24H2 / 25H2 (also Windows Server 2025).
    //
    { PPL_NT_WIN11_24H2,           0x5FA, 0x750, 0x754, 0x300 },
    { PPL_NT_WIN11_25H2,           0x5FA, 0x750, 0x754, 0x300 },
};

#define PPL_BUILD_OFFSETS_COUNT \
    (sizeof(PplBuildOffsets) / sizeof(PplBuildOffsets[0]))

const WCHAR*
PplBuildDisplayName(
    _In_ ULONG BuildNumber)
{
    switch (BuildNumber) {

    case PPL_NT_WIN7_RTM:       return L"Windows 7 RTM";
    case PPL_NT_WIN7_SP1:       return L"Windows 7 SP1";
    case PPL_NT_WIN8_RTM:       return L"Windows 8";
    case PPL_NT_WIN8_BLUE:      return L"Windows 8.1";

    case PPL_NT_WIN10_THRESHOLD1: return L"Windows 10 (1507)";
    case PPL_NT_WIN10_THRESHOLD2: return L"Windows 10 (1511)";
    case PPL_NT_WIN10_REDSTONE1:  return L"Windows 10 (1607)";
    case PPL_NT_WIN10_REDSTONE2:  return L"Windows 10 (1703)";
    case PPL_NT_WIN10_REDSTONE3:  return L"Windows 10 (1709)";
    case PPL_NT_WIN10_REDSTONE4:  return L"Windows 10 (1803)";
    case PPL_NT_WIN10_REDSTONE5:  return L"Windows 10 (1809)";
    case PPL_NT_WIN10_19H1:       return L"Windows 10 1903";
    case PPL_NT_WIN10_19H2:       return L"Windows 10 1909";
    case PPL_NT_WIN10_20H1:       return L"Windows 10 2004";
    case PPL_NT_WIN10_20H2:       return L"Windows 10 20H2";
    case PPL_NT_WIN10_21H1:       return L"Windows 10 21H1";
    case PPL_NT_WIN10_21H2:       return L"Windows 10 21H2";
    case PPL_NT_WIN10_22H2:       return L"Windows 10 22H2";

    case PPL_NT_WINSRV_21H1:      return L"Windows Server 2022";
    case PPL_NT_WIN11_21H2:       return L"Windows 11 21H2";
    case PPL_NT_WIN11_22H2:       return L"Windows 11 22H2";
    case PPL_NT_WIN11_23H2:       return L"Windows 11 23H2";
    case PPL_NT_WIN11_24H2:       return L"Windows 11 24H2 / Server 2025";
    case PPL_NT_WIN11_25H2:       return L"Windows 11 25H2";

    case PPL_NT_WIN11_26H1:       return L"Windows 11 26H1";
    case PPL_NT_WIN11_26H2:       return L"Windows 11 26H2";
    case PPL_NT_WIN11_ADB:        return L"Windows 11 development branch";

    default:
        return L"unknown Windows build";
    }
}

BOOLEAN
PplLookupBuildOffsets(
    _In_ ULONG BuildNumber,
    _Out_ PPPL_BUILD_OFFSETS Offsets)
{
    ULONG i;

    if (Offsets == NULL) {
        return FALSE;
    }

    RtlZeroMemory(Offsets, sizeof(*Offsets));
    Offsets->BuildNumber = BuildNumber;

    for (i = 0; i < PPL_BUILD_OFFSETS_COUNT; ++i) {
        if (PplBuildOffsets[i].BuildNumber == BuildNumber) {
            *Offsets = PplBuildOffsets[i];
            return TRUE;
        }
    }

    return FALSE;
}

const PPL_BUILD_OFFSETS*
PplGetBuildOffsetTable(
    _Out_opt_ PULONG Count)
{
    if (Count != NULL) {
        *Count = (ULONG)PPL_BUILD_OFFSETS_COUNT;
    }

    return PplBuildOffsets;
}
