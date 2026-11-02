#include "PplProtection.h"
#include "PplFilter.h"
#include "PplLog.h"

//
// Undocumented ntoskrnl exports. They are resolved dynamically so the driver
// does not depend on a particular WDK import library.
//
typedef BOOLEAN (NTAPI *PPL_PS_IS_PROTECTED_PROCESS)(_In_ PEPROCESS Process);

static PPL_PS_IS_PROTECTED_PROCESS        g_PsIsProtectedProcess;
static PPL_PS_IS_PROTECTED_PROCESS        g_PsIsProtectedProcessLight;

ULONG   g_PplBuildNumber;
ULONG   g_PplProtectionOffset;
BOOLEAN g_PplOffsetSupported;

typedef struct _PPL_OFFSET_ENTRY {
    ULONG BuildNumber;
    ULONG ProtectionOffset;
} PPL_OFFSET_ENTRY;

//
// Build-specific EPROCESS!PS_PROTECTION offsets. Never guess: an unknown
// build must fail SET/FILTER rather than corrupt an arbitrary EPROCESS byte.
//
static const PPL_OFFSET_ENTRY g_PplOffsets[] = {
    { 22000, 0x87A },   // Windows 11 21H2
    { 22621, 0x87A },   // Windows 11 22H2
    { 22631, 0x87A },   // Windows 11 23H2
    { 26100, 0x5FA },   // Windows 11 24H2
    { 26200, 0x5FA },   // Windows 11 25H2
};

#define PPL_MAX_TRACKED_PROCESSES 256

typedef struct _PPL_TRACK_ENTRY {
    BOOLEAN InUse;
    ULONG   ProcessId;
    PVOID   Process;             // EPROCESS identity check against PID reuse
    UCHAR   AppliedProtection;
    UCHAR   OriginalProtection;
} PPL_TRACK_ENTRY;

static PPL_TRACK_ENTRY g_Track[PPL_MAX_TRACKED_PROCESSES];
static EX_PUSH_LOCK    g_TrackLock;
static BOOLEAN         g_TrackInitialized;

static
PVOID
PplpGetSystemRoutine(
    _In_ PCWSTR Name)
{
    UNICODE_STRING routineName;

    RtlInitUnicodeString(&routineName, Name);
    return MmGetSystemRoutineAddress(&routineName);
}

static
UCHAR
PplpReadProtection(
    _In_ PEPROCESS Process)
{
    volatile UCHAR* value;

    if (g_PplProtectionOffset == 0) {
        return 0;
    }

    value = (volatile UCHAR*)((PUCHAR)Process + g_PplProtectionOffset);
    return *value;
}

static
VOID
PplpWriteProtection(
    _In_ PEPROCESS Process,
    _In_ UCHAR Value)
{
    volatile UCHAR* target;

    target = (volatile UCHAR*)((PUCHAR)Process + g_PplProtectionOffset);
    *target = Value;
    KeMemoryBarrier();
}

UCHAR
PplReadProtection(
    _In_ PEPROCESS Process)
{
    return PplpReadProtection(Process);
}

BOOLEAN
PplIsProcessProtected(
    _In_ PEPROCESS Process)
{
    if (g_PsIsProtectedProcess != NULL && g_PsIsProtectedProcess(Process)) {
        return TRUE;
    }
    if (g_PsIsProtectedProcessLight != NULL && g_PsIsProtectedProcessLight(Process)) {
        return TRUE;
    }

    //
    // If the exports are missing, fall back to the raw byte. This is only a
    // best-effort check used to avoid re-protecting an existing PPL process.
    //
    return (PplpReadProtection(Process) != 0);
}

static
BOOLEAN
PplpVerifyTargetByte(
    _In_ PEPROCESS Process,
    _In_ UCHAR Target,
    _In_ UCHAR Actual)
{
    BOOLEAN protectedProcess = FALSE;
    BOOLEAN protectedLight = FALSE;
    UCHAR type;

    if (Actual != Target) {
        return FALSE;
    }

    //
    // If either boolean export is unavailable, the byte readback is the
    // complete verification we can honestly perform.
    //
    if (g_PsIsProtectedProcess == NULL || g_PsIsProtectedProcessLight == NULL) {
        return TRUE;
    }

    protectedProcess = g_PsIsProtectedProcess(Process);
    protectedLight = g_PsIsProtectedProcessLight(Process);
    type = (UCHAR)(Target & 0x7);

    switch (type) {
    case PS_PROTECTED_TYPE_NONE:
        return (!protectedProcess && !protectedLight);

    case PS_PROTECTED_TYPE_PROTECTED_LIGHT:
        return (protectedProcess && protectedLight);

    case PS_PROTECTED_TYPE_PROTECTED:
        return (protectedProcess && !protectedLight);

    default:
        //
        // A pre-existing value with an unknown type can only be verified by
        // the byte readback.
        //
        return TRUE;
    }
}

static
PPL_TRACK_ENTRY*
PplpFindTrackLocked(
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

static
BOOLEAN
PplpTrackChangeLocked(
    _In_ ULONG ProcessId,
    _In_ PEPROCESS Process,
    _In_ UCHAR Applied,
    _In_ UCHAR Original)
{
    ULONG i;
    PPL_TRACK_ENTRY* entry;

    entry = PplpFindTrackLocked(ProcessId, Process);
    if (entry != NULL) {
        entry->AppliedProtection = Applied;
        return TRUE;
    }

    for (i = 0; i < PPL_MAX_TRACKED_PROCESSES; ++i) {
        if (!g_Track[i].InUse) {
            g_Track[i].InUse = TRUE;
            g_Track[i].ProcessId = ProcessId;
            g_Track[i].Process = (PVOID)Process;
            g_Track[i].AppliedProtection = Applied;
            g_Track[i].OriginalProtection = Original;
            return TRUE;
        }
    }

    return FALSE;
}

static
VOID
PplpDropTrackLocked(
    _In_ PPL_TRACK_ENTRY* Entry)
{
    RtlZeroMemory(Entry, sizeof(*Entry));
}

static
VOID
PplpDropTrackByPid(
    _In_ ULONG ProcessId)
{
    ULONG i;

    if (!g_TrackInitialized) {
        return;
    }

    ExAcquirePushLockExclusive(&g_TrackLock);
    for (i = 0; i < PPL_MAX_TRACKED_PROCESSES; ++i) {
        if (g_Track[i].InUse && g_Track[i].ProcessId == ProcessId) {
            PplpDropTrackLocked(&g_Track[i]);
        }
    }
    ExReleasePushLockExclusive(&g_TrackLock);
}

NTSTATUS
PplProtectionInitialize(VOID)
{
    RTL_OSVERSIONINFOW version;
    NTSTATUS status;
    ULONG i;

    ExInitializePushLock(&g_TrackLock);
    RtlZeroMemory(g_Track, sizeof(g_Track));
    g_TrackInitialized = TRUE;

    RtlZeroMemory(&version, sizeof(version));
    version.dwOSVersionInfoSize = sizeof(version);
    status = RtlGetVersion(&version);
    if (!NT_SUCCESS(status)) {
        PPL_LOG("RtlGetVersion failed: 0x%08X", status);
        return status;
    }

    g_PplBuildNumber = version.dwBuildNumber;
    g_PplProtectionOffset = 0;
    g_PplOffsetSupported = FALSE;

    for (i = 0; i < RTL_NUMBER_OF(g_PplOffsets); ++i) {
        if (g_PplOffsets[i].BuildNumber == version.dwBuildNumber) {
            g_PplProtectionOffset = g_PplOffsets[i].ProtectionOffset;
            g_PplOffsetSupported = TRUE;
            break;
        }
    }

    g_PsIsProtectedProcess =
        (PPL_PS_IS_PROTECTED_PROCESS)PplpGetSystemRoutine(L"PsIsProtectedProcess");
    g_PsIsProtectedProcessLight =
        (PPL_PS_IS_PROTECTED_PROCESS)PplpGetSystemRoutine(L"PsIsProtectedProcessLight");

    if (g_PplOffsetSupported) {
        PPL_LOG("build %lu, PS_PROTECTION offset 0x%03lX",
                g_PplBuildNumber, g_PplProtectionOffset);
    } else {
        PPL_LOG("unsupported build %lu; SET and FILTER disabled",
                g_PplBuildNumber);
    }

    if (g_PsIsProtectedProcess == NULL || g_PsIsProtectedProcessLight == NULL) {
        PPL_LOG("warning: PsIsProtectedProcess exports unavailable; byte readback only");
    }

    return STATUS_SUCCESS;
}

static
VOID
PplpInitializeResult(
    _Out_opt_ PPPL_OPERATION_RESULT Result,
    _In_ NTSTATUS Status,
    _In_ UCHAR OldProtection,
    _In_ UCHAR NewProtection)
{
    if (Result == NULL) {
        return;
    }

    Result->Status = Status;
    Result->OldProtection = OldProtection;
    Result->NewProtection = NewProtection;
    Result->Reserved[0] = 0;
    Result->Reserved[1] = 0;
}

NTSTATUS
PplProtectProcess(
    _In_ PEPROCESS Process,
    _In_ ULONG ProcessId,
    _In_ UCHAR Signer,
    _In_ UCHAR Audit,
    _Out_opt_ PPPL_OPERATION_RESULT Result)
{
    NTSTATUS status;
    UCHAR oldProtection;
    UCHAR newProtection;
    UCHAR verifyProtection;
    BOOLEAN tracked = FALSE;

    PplpInitializeResult(Result, STATUS_SUCCESS, 0, 0);

    if (ProcessId == 0 || ProcessId == 4) {
        status = STATUS_ACCESS_DENIED;
        PplpInitializeResult(Result, status, 0, 0);
        PPL_LOG("refusing PID %lu (system process)", ProcessId);
        return status;
    }

    if (!g_PplOffsetSupported || g_PplProtectionOffset == 0) {
        status = STATUS_NOT_SUPPORTED;
        PplpInitializeResult(Result, status, 0, 0);
        return status;
    }

    if (Signer < PS_PROTECTED_SIGNER_AUTHENTICODE ||
        Signer > PS_PROTECTED_SIGNER_APP ||
        Audit > 1) {
        status = STATUS_INVALID_PARAMETER;
        PplpInitializeResult(Result, status, 0, 0);
        return status;
    }

    if (PplIsBlockedProcess(Process, ProcessId, NULL)) {
        status = STATUS_ACCESS_DENIED;
        PplpInitializeResult(Result, status, PplpReadProtection(Process), 0);
        PPL_LOG("refusing blocklisted process pid=%lu", ProcessId);
        return status;
    }

    newProtection = MAKE_PS_PROTECTION(
        Signer, Audit, PS_PROTECTED_TYPE_PROTECTED_LIGHT);

    ExAcquirePushLockExclusive(&g_TrackLock);
    oldProtection = PplpReadProtection(Process);

    if (oldProtection == newProtection) {
        //
        // Already at the requested level. Do not take ownership of a process
        // this driver did not protect.
        //
        status = PplpVerifyTargetByte(Process, newProtection, oldProtection)
                     ? STATUS_SUCCESS
                     : STATUS_UNSUCCESSFUL;
        ExReleasePushLockExclusive(&g_TrackLock);

        PplpInitializeResult(Result, status, oldProtection, oldProtection);
        PPL_LOG("pid=%lu already at protection 0x%02X (status 0x%08X)",
                ProcessId, oldProtection, status);
        return status;
    }

    PplpWriteProtection(Process, newProtection);
    verifyProtection = PplpReadProtection(Process);

    if (!PplpVerifyTargetByte(Process, newProtection, verifyProtection)) {
        PplpWriteProtection(Process, oldProtection);
        ExReleasePushLockExclusive(&g_TrackLock);

        status = STATUS_UNSUCCESSFUL;
        PplpInitializeResult(Result, status, oldProtection, verifyProtection);
        PPL_LOG("pid=%lu verification failed: wanted 0x%02X, got 0x%02X; restored 0x%02X",
                ProcessId, newProtection, verifyProtection, oldProtection);
        return status;
    }

    tracked = PplpTrackChangeLocked(
        ProcessId, Process, newProtection, oldProtection);

    ExReleasePushLockExclusive(&g_TrackLock);

    status = STATUS_SUCCESS;
    PplpInitializeResult(Result, status, oldProtection, newProtection);
    PPL_LOG("pid=%lu protection 0x%02X -> 0x%02X (%s)",
            ProcessId, oldProtection, newProtection,
            tracked ? "tracked" : "not tracked");
    return status;
}

NTSTATUS
PplSetByPid(
    _In_ ULONG ProcessId,
    _In_ UCHAR Signer,
    _In_ UCHAR Audit,
    _Out_ PPPL_OPERATION_RESULT Result)
{
    PEPROCESS process = NULL;
    NTSTATUS status;

    PplpInitializeResult(Result, STATUS_SUCCESS, 0, 0);

    if (!g_PplOffsetSupported || g_PplProtectionOffset == 0) {
        PplpInitializeResult(Result, STATUS_NOT_SUPPORTED, 0, 0);
        return STATUS_NOT_SUPPORTED;
    }

    status = PsLookupProcessByProcessId(
        (HANDLE)(ULONG_PTR)ProcessId, &process);
    if (!NT_SUCCESS(status)) {
        PplpInitializeResult(Result, status, 0, 0);
        PPL_LOG("PsLookupProcessByProcessId(%lu) failed: 0x%08X",
                ProcessId, status);
        return status;
    }

    status = PplProtectProcess(process, ProcessId, Signer, Audit, Result);
    ObDereferenceObject(process);
    return status;
}

NTSTATUS
PplClearByPid(
    _In_ ULONG ProcessId,
    _Out_ PPPL_OPERATION_RESULT Result)
{
    PEPROCESS process = NULL;
    PPL_TRACK_ENTRY* entry;
    NTSTATUS status;
    UCHAR current;
    UCHAR target;
    UCHAR verify;

    PplpInitializeResult(Result, STATUS_SUCCESS, 0, 0);

    if (!g_PplOffsetSupported || g_PplProtectionOffset == 0) {
        PplpInitializeResult(Result, STATUS_NOT_SUPPORTED, 0, 0);
        return STATUS_NOT_SUPPORTED;
    }

    status = PsLookupProcessByProcessId(
        (HANDLE)(ULONG_PTR)ProcessId, &process);
    if (!NT_SUCCESS(status)) {
        PplpDropTrackByPid(ProcessId);
        PplpInitializeResult(Result, status, 0, 0);
        PPL_LOG("clear pid=%lu: process lookup failed 0x%08X", ProcessId, status);
        return status;
    }

    ExAcquirePushLockExclusive(&g_TrackLock);
    entry = PplpFindTrackLocked(ProcessId, process);
    current = PplpReadProtection(process);

    if (entry == NULL) {
        ExReleasePushLockExclusive(&g_TrackLock);
        ObDereferenceObject(process);

        if (current == 0) {
            PplpInitializeResult(Result, STATUS_SUCCESS, current, current);
            PPL_LOG("clear pid=%lu: already unprotected", ProcessId);
            return STATUS_SUCCESS;
        }

        PplpInitializeResult(Result, STATUS_ACCESS_DENIED, current, current);
        PPL_LOG("clear pid=%lu: refusing to unprotect untracked process at 0x%02X",
                ProcessId, current);
        return STATUS_ACCESS_DENIED;
    }

    if (current != entry->AppliedProtection) {
        ExReleasePushLockExclusive(&g_TrackLock);
        ObDereferenceObject(process);

        PplpInitializeResult(Result, STATUS_UNSUCCESSFUL, current, current);
        PPL_LOG("clear pid=%lu: current 0x%02X does not match tracked 0x%02X; unchanged",
                ProcessId, current, entry->AppliedProtection);
        return STATUS_UNSUCCESSFUL;
    }

    target = entry->OriginalProtection;

    if (target == current) {
        PplpDropTrackLocked(entry);
        ExReleasePushLockExclusive(&g_TrackLock);
        ObDereferenceObject(process);

        PplpInitializeResult(Result, STATUS_SUCCESS, current, current);
        return STATUS_SUCCESS;
    }

    PplpWriteProtection(process, target);
    verify = PplpReadProtection(process);

    if (!PplpVerifyTargetByte(process, target, verify)) {
        PplpWriteProtection(process, current);
        ExReleasePushLockExclusive(&g_TrackLock);
        ObDereferenceObject(process);

        PplpInitializeResult(Result, STATUS_UNSUCCESSFUL, current, verify);
        PPL_LOG("clear pid=%lu verification failed: wanted 0x%02X, got 0x%02X; restored 0x%02X",
                ProcessId, target, verify, current);
        return STATUS_UNSUCCESSFUL;
    }

    PplpDropTrackLocked(entry);
    ExReleasePushLockExclusive(&g_TrackLock);
    ObDereferenceObject(process);

    PplpInitializeResult(Result, STATUS_SUCCESS, current, target);
    PPL_LOG("clear pid=%lu: protection 0x%02X -> 0x%02X",
            ProcessId, current, target);
    return STATUS_SUCCESS;
}

NTSTATUS
PplQueryByPid(
    _In_ ULONG ProcessId,
    _Out_ PPPL_QUERY_RESULT Result)
{
    PEPROCESS process = NULL;
    NTSTATUS status;
    UCHAR protection;
    BOOLEAN isProtected;
    BOOLEAN isLight;

    RtlZeroMemory(Result, sizeof(*Result));
    Result->ProcessId = ProcessId;
    Result->BuildNumber = g_PplBuildNumber;
    Result->ProtectionOffset = g_PplProtectionOffset;

    status = PsLookupProcessByProcessId(
        (HANDLE)(ULONG_PTR)ProcessId, &process);
    if (!NT_SUCCESS(status)) {
        Result->Status = status;
        return status;
    }

    if (!g_PplOffsetSupported || g_PplProtectionOffset == 0) {
        ObDereferenceObject(process);
        Result->Status = STATUS_NOT_SUPPORTED;
        return STATUS_NOT_SUPPORTED;
    }

    protection = PplpReadProtection(process);
    isProtected = (g_PsIsProtectedProcess != NULL)
                      ? g_PsIsProtectedProcess(process)
                      : (protection != 0);
    isLight = (g_PsIsProtectedProcessLight != NULL)
                  ? g_PsIsProtectedProcessLight(process)
                  : ((protection & 0x7) == PS_PROTECTED_TYPE_PROTECTED_LIGHT);

    Result->Status = STATUS_SUCCESS;
    Result->Protection = protection;

    //
    // PsGetProcessSignatureLevel/PsGetProcessSectionSignatureLevel are
    // undocumented and their exported implementations use an output-pointer
    // ABI, not a UCHAR return value. Calling them as a one-argument function
    // faults inside ntoskrnl. They are optional diagnostics, so report zero.
    //
    Result->SignatureLevel = 0;
    Result->SectionSignatureLevel = 0;
    Result->Flags = (UCHAR)((isProtected ? 0x1 : 0) | (isLight ? 0x2 : 0));

    ObDereferenceObject(process);
    return STATUS_SUCCESS;
}

VOID
PplRestoreAllTracked(VOID)
{
    ULONG i;
    ULONG restored = 0;
    ULONG skipped = 0;
    ULONG failed = 0;

    if (!g_TrackInitialized) {
        return;
    }

    ExAcquirePushLockExclusive(&g_TrackLock);

    for (i = 0; i < PPL_MAX_TRACKED_PROCESSES; ++i) {
        PPL_TRACK_ENTRY* entry = &g_Track[i];
        PEPROCESS process = NULL;
        NTSTATUS status;
        UCHAR current;
        UCHAR verify;

        if (!entry->InUse) {
            continue;
        }

        status = PsLookupProcessByProcessId(
            (HANDLE)(ULONG_PTR)entry->ProcessId, &process);
        if (!NT_SUCCESS(status)) {
            entry->InUse = FALSE;
            ++skipped;
            continue;
        }

        if ((PVOID)process != entry->Process) {
            entry->InUse = FALSE;
            ObDereferenceObject(process);
            ++skipped;
            continue;
        }

        current = PplpReadProtection(process);
        if (current != entry->AppliedProtection) {
            entry->InUse = FALSE;
            ObDereferenceObject(process);
            ++skipped;
            continue;
        }

        PplpWriteProtection(process, entry->OriginalProtection);
        verify = PplpReadProtection(process);

        if (PplpVerifyTargetByte(process, entry->OriginalProtection, verify)) {
            entry->InUse = FALSE;
            ++restored;
        } else {
            //
            // Put back our value if restoring the original did not verify.
            //
            PplpWriteProtection(process, entry->AppliedProtection);
            ++failed;
        }

        ObDereferenceObject(process);
    }

    RtlZeroMemory(g_Track, sizeof(g_Track));
    ExReleasePushLockExclusive(&g_TrackLock);

    PPL_LOG("restore-on-unload: restored=%lu skipped=%lu failed=%lu",
            restored, skipped, failed);
}
