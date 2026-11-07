#include "PplMitigation.h"
#include "PplProtection.h"
#include "PplFilter.h"
#include "PplLog.h"

//
// SignatureLevel and SectionSignatureLevel are the two bytes immediately
// before PS_PROTECTION in EPROCESS on every supported build:
//
//   UCHAR SignatureLevel;          // PsProtectionOffset - 2
//   UCHAR SectionSignatureLevel;   // PsProtectionOffset - 1
//   PS_PROTECTION Protection;      // PsProtectionOffset
//
// SectionSignatureLevel is the minimum signature level the image loader
// requires for DLLs. allow-dlls clears it to 0 so unsigned DLLs can load.
// SignatureLevel (the process image's own signing level) is only read.
//
UCHAR
PplReadSignatureLevel(
    _In_ PEPROCESS Process)
{
    if (g_PplProtectionOffset < 2) {
        return 0;
    }

    return *((volatile UCHAR*)((PUCHAR)Process + g_PplProtectionOffset - 2));
}

static
VOID
PplpWriteSignatureLevel(
    _In_ PEPROCESS Process,
    _In_ UCHAR Value)
{
    volatile UCHAR* target;

    if (g_PplProtectionOffset < 2) {
        return;
    }

    target = (volatile UCHAR*)((PUCHAR)Process + g_PplProtectionOffset - 2);
    *target = Value;
    KeMemoryBarrier();
}

UCHAR
PplReadSectionSignatureLevel(
    _In_ PEPROCESS Process)
{
    if (g_PplProtectionOffset < 1) {
        return 0;
    }

    return *((volatile UCHAR*)((PUCHAR)Process + g_PplProtectionOffset - 1));
}

static
VOID
PplpWriteSectionSignatureLevel(
    _In_ PEPROCESS Process,
    _In_ UCHAR Value)
{
    volatile UCHAR* target;

    if (g_PplProtectionOffset < 1) {
        return;
    }

    target = (volatile UCHAR*)((PUCHAR)Process + g_PplProtectionOffset - 1);
    *target = Value;
    KeMemoryBarrier();
}

ULONG
PplReadMitigationFlags(
    _In_ PEPROCESS Process,
    _In_ ULONG Offset)
{
    volatile ULONG* value;

    if (Offset == 0) {
        return 0;
    }

    value = (volatile ULONG*)((PUCHAR)Process + Offset);
    return *value;
}

static
VOID
PplpWriteMitigationFlags(
    _In_ PEPROCESS Process,
    _In_ ULONG Offset,
    _In_ ULONG Value)
{
    volatile ULONG* target;

    if (Offset == 0) {
        return;
    }

    target = (volatile ULONG*)((PUCHAR)Process + Offset);
    *target = Value;
    KeMemoryBarrier();
}

static
VOID
PplpInitializeMitigationResult(
    _Out_opt_ PPPL_MITIGATION_RESULT Result,
    _In_ NTSTATUS Status,
    _In_ ULONG OldFlags1,
    _In_ ULONG NewFlags1,
    _In_ ULONG OldFlags2,
    _In_ ULONG NewFlags2,
    _In_ UCHAR OldSignatureLevel,
    _In_ UCHAR NewSignatureLevel,
    _In_ UCHAR OldSectionSignatureLevel,
    _In_ UCHAR NewSectionSignatureLevel)
{
    if (Result == NULL) {
        return;
    }

    Result->Status = Status;
    Result->OldMitigationFlags1 = OldFlags1;
    Result->NewMitigationFlags1 = NewFlags1;
    Result->OldMitigationFlags2 = OldFlags2;
    Result->NewMitigationFlags2 = NewFlags2;
    Result->OldSignatureLevel = OldSignatureLevel;
    Result->NewSignatureLevel = NewSignatureLevel;
    Result->OldSectionSignatureLevel = OldSectionSignatureLevel;
    Result->NewSectionSignatureLevel = NewSectionSignatureLevel;
}

NTSTATUS
PplAllowNonMicrosoftDllsByPid(
    _In_ ULONG ProcessId,
    _Out_ PPPL_MITIGATION_RESULT Result)
{
    PEPROCESS process = NULL;
    NTSTATUS status;
    ULONG oldFlags1;
    ULONG oldFlags2 = 0;
    ULONG newFlags1;
    ULONG verifyFlags1;
    UCHAR oldSignatureLevel;
    UCHAR oldSectionSignatureLevel;
    UCHAR newSignatureLevel;
    UCHAR newSectionSignatureLevel;
    UCHAR verifySectionSignatureLevel;
    BOOLEAN tracked = FALSE;

    PplpInitializeMitigationResult(
        Result, STATUS_SUCCESS, 0, 0, 0, 0, 0, 0, 0, 0);

    if (!g_PplOffsetSupported ||
        g_PplProtectionOffset == 0 ||
        g_PplOffsets.PsMitigationFlags1Offset == 0) {
        PplpInitializeMitigationResult(
            Result, STATUS_NOT_SUPPORTED, 0, 0, 0, 0, 0, 0, 0, 0);
        return STATUS_NOT_SUPPORTED;
    }

    if (ProcessId == 0 || ProcessId == 4) {
        PplpInitializeMitigationResult(
            Result, STATUS_ACCESS_DENIED, 0, 0, 0, 0, 0, 0, 0, 0);
        PPL_LOG("refusing PID %lu (system process)", ProcessId);
        return STATUS_ACCESS_DENIED;
    }

    status = PsLookupProcessByProcessId(
        (HANDLE)(ULONG_PTR)ProcessId, &process);
    if (!NT_SUCCESS(status)) {
        PplpInitializeMitigationResult(
            Result, status, 0, 0, 0, 0, 0, 0, 0, 0);
        PPL_LOG("allow-dlls pid=%lu: process lookup failed 0x%08X",
                ProcessId, status);
        return status;
    }

    if (PplIsBlockedProcess(process, ProcessId, NULL)) {
        status = STATUS_ACCESS_DENIED;
        PplpInitializeMitigationResult(
            Result, status, 0, 0, 0, 0, 0, 0, 0, 0);
        PPL_LOG("refusing blocklisted process pid=%lu", ProcessId);
        ObDereferenceObject(process);
        return status;
    }

    PplTrackLock();

    oldFlags1 = PplReadMitigationFlags(
        process, g_PplOffsets.PsMitigationFlags1Offset);
    oldFlags2 = PplReadMitigationFlags(
        process, g_PplOffsets.PsMitigationFlags2Offset);
    oldSignatureLevel = PplReadSignatureLevel(process);
    oldSectionSignatureLevel = PplReadSectionSignatureLevel(process);

    newFlags1 = oldFlags1 & ~PPL_MITIGATION_FLAG_SIGNATURE_OPT_IN;
    newSignatureLevel = oldSignatureLevel;
    newSectionSignatureLevel = 0;

    if (newFlags1 == oldFlags1 &&
        newSectionSignatureLevel == oldSectionSignatureLevel) {
        //
        // Nothing to clear. Do not create a tracking entry: this driver did
        // not change the process, so unload must not touch it.
        //
        status = STATUS_SUCCESS;
        PplpInitializeMitigationResult(
            Result, status,
            oldFlags1, oldFlags1, oldFlags2, oldFlags2,
            oldSignatureLevel, oldSignatureLevel,
            oldSectionSignatureLevel, oldSectionSignatureLevel);
        PPL_LOG("allow-dlls pid=%lu: already clear (MitigationFlags1=0x%08lX, SectionSignatureLevel=0x%02X)",
                ProcessId, oldFlags1, oldSectionSignatureLevel);
    } else {
        PplpWriteMitigationFlags(
            process, g_PplOffsets.PsMitigationFlags1Offset, newFlags1);
        verifyFlags1 = PplReadMitigationFlags(
            process, g_PplOffsets.PsMitigationFlags1Offset);

        if (verifyFlags1 != newFlags1) {
            PplpWriteMitigationFlags(
                process, g_PplOffsets.PsMitigationFlags1Offset, oldFlags1);
            status = STATUS_UNSUCCESSFUL;
            PplpInitializeMitigationResult(
                Result, status,
                oldFlags1, verifyFlags1, oldFlags2, oldFlags2,
                oldSignatureLevel, oldSignatureLevel,
                oldSectionSignatureLevel, oldSectionSignatureLevel);
            PPL_LOG("allow-dlls pid=%lu: MitigationFlags1 verify failed (wanted 0x%08lX, got 0x%08lX); restored 0x%08lX",
                    ProcessId, newFlags1, verifyFlags1, oldFlags1);
        } else {
            //
            // SectionSignatureLevel is the minimum signature level the image
            // loader requires for DLLs. Zero removes the requirement.
            //
            PplpWriteSectionSignatureLevel(
                process, newSectionSignatureLevel);
            verifySectionSignatureLevel =
                PplReadSectionSignatureLevel(process);

            if (verifySectionSignatureLevel != newSectionSignatureLevel) {
                PplpWriteSectionSignatureLevel(
                    process, oldSectionSignatureLevel);
                PplpWriteMitigationFlags(
                    process, g_PplOffsets.PsMitigationFlags1Offset,
                    oldFlags1);
                status = STATUS_UNSUCCESSFUL;
                PplpInitializeMitigationResult(
                    Result, status,
                    oldFlags1, verifyFlags1, oldFlags2, oldFlags2,
                    oldSignatureLevel, oldSignatureLevel,
                    oldSectionSignatureLevel, verifySectionSignatureLevel);
                PPL_LOG("allow-dlls pid=%lu: SectionSignatureLevel verify failed (wanted 0x%02X, got 0x%02X); restored",
                        ProcessId, newSectionSignatureLevel,
                        verifySectionSignatureLevel);
            } else {
                tracked = PplTrackMitigationLocked(
                    ProcessId, process,
                    PplReadProtection(process),
                    newFlags1, oldFlags1,
                    oldFlags2, oldFlags2,
                    newSignatureLevel, oldSignatureLevel,
                    newSectionSignatureLevel, oldSectionSignatureLevel);
                status = STATUS_SUCCESS;
                PplpInitializeMitigationResult(
                    Result, status,
                    oldFlags1, newFlags1, oldFlags2, oldFlags2,
                    oldSignatureLevel, newSignatureLevel,
                    oldSectionSignatureLevel, newSectionSignatureLevel);
                PPL_LOG("allow-dlls pid=%lu: MitigationFlags1 0x%08lX -> 0x%08lX, SectionSignatureLevel 0x%02X -> 0x%02X (%s)",
                        ProcessId, oldFlags1, newFlags1,
                        oldSectionSignatureLevel, newSectionSignatureLevel,
                        tracked ? "tracked" : "not tracked");
            }
        }
    }

    PplTrackUnlock();
    ObDereferenceObject(process);
    return status;
}

//
// Best-effort restore of a tracked mitigation change (MitigationFlags1 and
// SectionSignatureLevel). Returns FALSE if the current value no longer
// matches what this driver applied, or if the write-back did not verify. The
// entry is kept in that case so unload can try again.
//
BOOLEAN
PplRestoreMitigationLocked(
    _In_ PEPROCESS Process,
    _Inout_ PPPL_TRACK_ENTRY Entry)
{
    BOOLEAN changeFlags;
    BOOLEAN changeSignature;
    BOOLEAN changeSection;
    BOOLEAN ok = TRUE;
    ULONG flags;
    UCHAR signatureLevel;
    UCHAR sectionLevel;

    changeFlags =
        (Entry->ChangeMask & PPL_TRACK_MITIGATION) != 0 &&
        Entry->AppliedMitigationFlags1 != Entry->OriginalMitigationFlags1;
    if (g_PplOffsets.PsMitigationFlags1Offset == 0) {
        changeFlags = FALSE;
    }
    changeSignature =
        (Entry->ChangeMask & PPL_TRACK_SIGNATURE_LEVELS) != 0 &&
        Entry->AppliedSignatureLevel != Entry->OriginalSignatureLevel;
    changeSection =
        (Entry->ChangeMask & PPL_TRACK_SIGNATURE_LEVELS) != 0 &&
        Entry->AppliedSectionSignatureLevel != Entry->OriginalSectionSignatureLevel;

    if (!changeFlags && !changeSignature && !changeSection) {
        Entry->ChangeMask &=
            ~(PPL_TRACK_MITIGATION | PPL_TRACK_SIGNATURE_LEVELS);
        return TRUE;
    }

    if (changeFlags) {
        flags = PplReadMitigationFlags(
            Process, g_PplOffsets.PsMitigationFlags1Offset);
        if (flags != Entry->AppliedMitigationFlags1) {
            return FALSE;
        }
    }

    if (changeSignature || changeSection) {
        signatureLevel = PplReadSignatureLevel(Process);
        sectionLevel = PplReadSectionSignatureLevel(Process);
        if (signatureLevel != Entry->AppliedSignatureLevel ||
            sectionLevel != Entry->AppliedSectionSignatureLevel) {
            return FALSE;
        }
    }

    if (changeFlags) {
        PplpWriteMitigationFlags(
            Process, g_PplOffsets.PsMitigationFlags1Offset,
            Entry->OriginalMitigationFlags1);
        if (PplReadMitigationFlags(
                Process, g_PplOffsets.PsMitigationFlags1Offset) !=
            Entry->OriginalMitigationFlags1) {
            ok = FALSE;
        }
    }

    if (ok && changeSignature) {
        PplpWriteSignatureLevel(Process, Entry->OriginalSignatureLevel);
        if (PplReadSignatureLevel(Process) !=
            Entry->OriginalSignatureLevel) {
            ok = FALSE;
        }
    }

    if (ok && changeSection) {
        PplpWriteSectionSignatureLevel(
            Process, Entry->OriginalSectionSignatureLevel);
        if (PplReadSectionSignatureLevel(Process) !=
            Entry->OriginalSectionSignatureLevel) {
            ok = FALSE;
        }
    }

    if (!ok) {
        //
        // Put every changed field back to the applied value so a later retry
        // sees a consistent tracked state.
        //
        if (changeFlags) {
            PplpWriteMitigationFlags(
                Process, g_PplOffsets.PsMitigationFlags1Offset,
                Entry->AppliedMitigationFlags1);
        }
        if (changeSignature) {
            PplpWriteSignatureLevel(
                Process, Entry->AppliedSignatureLevel);
        }
        if (changeSection) {
            PplpWriteSectionSignatureLevel(
                Process, Entry->AppliedSectionSignatureLevel);
        }
        return FALSE;
    }

    Entry->ChangeMask &=
        ~(PPL_TRACK_MITIGATION | PPL_TRACK_SIGNATURE_LEVELS);
    return TRUE;
}
