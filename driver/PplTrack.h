#pragma once

#include <ntddk.h>

//
// Fixed-size table that lets the driver undo the changes it made: PPL, the
// block-non-Microsoft-binaries mitigation, or both. It is shared by the PPL
// and DLL-mitigation modules.
//
#define PPL_MAX_TRACKED_PROCESSES 256

//
// Bits in PPL_TRACK_ENTRY.ChangeMask. An entry can track protection, the
// block-non-Microsoft-binaries mitigation, or both.
//
#define PPL_TRACK_PROTECTION        0x00000001
#define PPL_TRACK_MITIGATION        0x00000002
#define PPL_TRACK_SIGNATURE_LEVELS  0x00000004

typedef struct _PPL_TRACK_ENTRY {
    BOOLEAN InUse;
    ULONG   ProcessId;
    PVOID   Process;             // EPROCESS identity check against PID reuse
    ULONG   ChangeMask;          // PPL_TRACK_*
    UCHAR   AppliedProtection;
    UCHAR   OriginalProtection;
    ULONG   AppliedMitigationFlags1;
    ULONG   OriginalMitigationFlags1;
    ULONG   AppliedMitigationFlags2;
    ULONG   OriginalMitigationFlags2;
    UCHAR   AppliedSignatureLevel;
    UCHAR   OriginalSignatureLevel;
    UCHAR   AppliedSectionSignatureLevel;
    UCHAR   OriginalSectionSignatureLevel;
} PPL_TRACK_ENTRY, *PPPL_TRACK_ENTRY;

VOID PplTrackInitialize(VOID);
BOOLEAN PplTrackIsInitialized(VOID);

//
// The lock serializes the complete read/modify/verify/track sequence. Callers
// of the *Locked helpers must hold it.
//
VOID PplTrackLock(VOID);
VOID PplTrackUnlock(VOID);

PPPL_TRACK_ENTRY PplTrackFindLocked(
    _In_ ULONG ProcessId,
    _In_ PEPROCESS Process);

PPPL_TRACK_ENTRY PplTrackGetOrCreateLocked(
    _In_ ULONG ProcessId,
    _In_ PEPROCESS Process,
    _In_ UCHAR CurrentProtection);

BOOLEAN PplTrackProtectionLocked(
    _In_ ULONG ProcessId,
    _In_ PEPROCESS Process,
    _In_ UCHAR Applied,
    _In_ UCHAR Original);

BOOLEAN PplTrackMitigationLocked(
    _In_ ULONG ProcessId,
    _In_ PEPROCESS Process,
    _In_ UCHAR CurrentProtection,
    _In_ ULONG AppliedFlags1,
    _In_ ULONG OriginalFlags1,
    _In_ ULONG AppliedFlags2,
    _In_ ULONG OriginalFlags2,
    _In_ UCHAR AppliedSignatureLevel,
    _In_ UCHAR OriginalSignatureLevel,
    _In_ UCHAR AppliedSectionSignatureLevel,
    _In_ UCHAR OriginalSectionSignatureLevel);

VOID PplTrackDropLocked(_Inout_ PPPL_TRACK_ENTRY Entry);
VOID PplTrackDropByPid(_In_ ULONG ProcessId);

//
// Restore-on-unload walks the table directly while holding the lock.
//
PPPL_TRACK_ENTRY PplTrackEntries(VOID);
VOID PplTrackResetLocked(VOID);
