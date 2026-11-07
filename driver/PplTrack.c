#include "PplTrack.h"

static PPL_TRACK_ENTRY g_Track[PPL_MAX_TRACKED_PROCESSES];
static EX_PUSH_LOCK    g_TrackLock;
static BOOLEAN         g_TrackInitialized;

VOID
PplTrackInitialize(VOID)
{
    ExInitializePushLock(&g_TrackLock);
    RtlZeroMemory(g_Track, sizeof(g_Track));
    g_TrackInitialized = TRUE;
}

BOOLEAN
PplTrackIsInitialized(VOID)
{
    return g_TrackInitialized;
}

VOID
PplTrackLock(VOID)
{
    ExAcquirePushLockExclusive(&g_TrackLock);
}

VOID
PplTrackUnlock(VOID)
{
    ExReleasePushLockExclusive(&g_TrackLock);
}

PPPL_TRACK_ENTRY
PplTrackFindLocked(
    _In_ ULONG ProcessId,
    _In_ PEPROCESS Process)
{
    ULONG i;

    for (i = 0; i < PPL_MAX_TRACKED_PROCESSES; ++i) {
        PPL_TRACK_ENTRY* entry = &g_Track[i];

        if (!entry->InUse || entry->ProcessId != ProcessId) {
            continue;
        }

        if (entry->Process == (PVOID)Process) {
            return entry;
        }

        //
        // Same PID, different EPROCESS: the old process exited and Windows
        // reused the PID. The stale entry must not be applied to the new one.
        //
        entry->InUse = FALSE;
    }

    return NULL;
}

PPPL_TRACK_ENTRY
PplTrackGetOrCreateLocked(
    _In_ ULONG ProcessId,
    _In_ PEPROCESS Process,
    _In_ UCHAR CurrentProtection)
{
    ULONG i;
    PPL_TRACK_ENTRY* entry;

    entry = PplTrackFindLocked(ProcessId, Process);
    if (entry != NULL) {
        return entry;
    }

    for (i = 0; i < PPL_MAX_TRACKED_PROCESSES; ++i) {
        if (!g_Track[i].InUse) {
            entry = &g_Track[i];
            RtlZeroMemory(entry, sizeof(*entry));
            entry->InUse = TRUE;
            entry->ProcessId = ProcessId;
            entry->Process = (PVOID)Process;
            entry->AppliedProtection = CurrentProtection;
            entry->OriginalProtection = CurrentProtection;
            return entry;
        }
    }

    return NULL;
}

BOOLEAN
PplTrackProtectionLocked(
    _In_ ULONG ProcessId,
    _In_ PEPROCESS Process,
    _In_ UCHAR Applied,
    _In_ UCHAR Original)
{
    PPL_TRACK_ENTRY* entry;

    entry = PplTrackGetOrCreateLocked(ProcessId, Process, Original);
    if (entry == NULL) {
        return FALSE;
    }

    if ((entry->ChangeMask & PPL_TRACK_PROTECTION) == 0) {
        entry->OriginalProtection = Original;
    }
    entry->AppliedProtection = Applied;
    entry->ChangeMask |= PPL_TRACK_PROTECTION;
    return TRUE;
}

BOOLEAN
PplTrackMitigationLocked(
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
    _In_ UCHAR OriginalSectionSignatureLevel)
{
    PPL_TRACK_ENTRY* entry;

    entry = PplTrackGetOrCreateLocked(ProcessId, Process, CurrentProtection);
    if (entry == NULL) {
        return FALSE;
    }

    if ((entry->ChangeMask & PPL_TRACK_MITIGATION) == 0) {
        entry->OriginalMitigationFlags1 = OriginalFlags1;
        entry->OriginalMitigationFlags2 = OriginalFlags2;
    }
    if ((entry->ChangeMask & PPL_TRACK_SIGNATURE_LEVELS) == 0) {
        entry->OriginalSignatureLevel = OriginalSignatureLevel;
        entry->OriginalSectionSignatureLevel = OriginalSectionSignatureLevel;
    }

    entry->AppliedMitigationFlags1 = AppliedFlags1;
    entry->AppliedMitigationFlags2 = AppliedFlags2;
    entry->AppliedSignatureLevel = AppliedSignatureLevel;
    entry->AppliedSectionSignatureLevel = AppliedSectionSignatureLevel;
    entry->ChangeMask |= PPL_TRACK_MITIGATION | PPL_TRACK_SIGNATURE_LEVELS;
    return TRUE;
}

VOID
PplTrackDropLocked(
    _Inout_ PPPL_TRACK_ENTRY Entry)
{
    RtlZeroMemory(Entry, sizeof(*Entry));
}

VOID
PplTrackDropByPid(
    _In_ ULONG ProcessId)
{
    ULONG i;

    if (!g_TrackInitialized) {
        return;
    }

    ExAcquirePushLockExclusive(&g_TrackLock);
    for (i = 0; i < PPL_MAX_TRACKED_PROCESSES; ++i) {
        if (g_Track[i].InUse && g_Track[i].ProcessId == ProcessId) {
            PplTrackDropLocked(&g_Track[i]);
        }
    }
    ExReleasePushLockExclusive(&g_TrackLock);
}

PPPL_TRACK_ENTRY
PplTrackEntries(VOID)
{
    return g_Track;
}

VOID
PplTrackResetLocked(VOID)
{
    RtlZeroMemory(g_Track, sizeof(g_Track));
}
