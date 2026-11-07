#include "PplProtection.h"
#include "PplFilter.h"
#include "PplLog.h"
#include "PplMitigation.h"
#include "PplTrack.h"

//
// Undocumented ntoskrnl exports. They are resolved dynamically so the driver
// does not depend on a particular WDK import library.
//
typedef BOOLEAN (NTAPI *PPL_PS_IS_PROTECTED_PROCESS)(_In_ PEPROCESS Process);

static PPL_PS_IS_PROTECTED_PROCESS        g_PsIsProtectedProcess;
static PPL_PS_IS_PROTECTED_PROCESS        g_PsIsProtectedProcessLight;

ULONG   g_PplMajorVersion;
ULONG   g_PplMinorVersion;
ULONG   g_PplBuildNumber;
ULONG   g_PplProtectionOffset;
BOOLEAN g_PplOffsetSupported;
PPL_BUILD_OFFSETS g_PplOffsets;

//
// Build-specific EPROCESS offsets live in shared/PplBuilds.c. They are ported
// from KDU's KDUGetEprocessOffsets and cover Windows 8.1 through Windows 11
// 25H2. An unknown build must fail SET/FILTER rather than corrupt an
// arbitrary EPROCESS byte.
//

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

    //
    // KDU reads a ULONG at PsProtectionOffset and writes back only the low
    // byte with the signer/type bits replaced. Writing the single UCHAR here
    // is equivalent and guarantees the other EPROCESS bytes are untouched.
    //
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

//
// KUSER_SHARED_DATA is mapped read-only at a fixed address in kernel mode.
// NtBuildNumber is at offset 0x260 (the WDK C_ASSERTs that offset). KDU reads
// the same value through NtCurrentPeb()->OSBuildNumber. RtlGetVersion is the
// primary source; this is a cross-check that also works if a shim or hook has
// changed the RtlGetVersion result.
//
static
ULONG
PplpQuerySharedBuildNumber(VOID)
{
    PKUSER_SHARED_DATA shared = (PKUSER_SHARED_DATA)0xFFFFF78000000000ULL;

    return shared->NtBuildNumber;
}

NTSTATUS
PplProtectionInitialize(VOID)
{
    RTL_OSVERSIONINFOW version;
    PPL_BUILD_OFFSETS offsets;
    NTSTATUS status;
    ULONG sharedBuild;

    PplTrackInitialize();

    RtlZeroMemory(&version, sizeof(version));
    version.dwOSVersionInfoSize = sizeof(version);
    status = RtlGetVersion(&version);
    if (!NT_SUCCESS(status)) {
        PPL_LOG("RtlGetVersion failed: 0x%08X", status);
        return status;
    }

    g_PplMajorVersion = version.dwMajorVersion;
    g_PplMinorVersion = version.dwMinorVersion;
    g_PplBuildNumber = version.dwBuildNumber;

    sharedBuild = PplpQuerySharedBuildNumber();
    if (sharedBuild != 0 && sharedBuild != g_PplBuildNumber) {
        PPL_LOG("build mismatch: RtlGetVersion=%lu, KUSER_SHARED_DATA=%lu; using %lu",
                g_PplBuildNumber, sharedBuild, sharedBuild);
        g_PplBuildNumber = sharedBuild;
    }

    RtlZeroMemory(&g_PplOffsets, sizeof(g_PplOffsets));
    g_PplOffsets.BuildNumber = g_PplBuildNumber;
    g_PplProtectionOffset = 0;
    g_PplOffsetSupported = FALSE;

    if (g_PplBuildNumber < PPL_MIN_SUPPORTED_BUILD) {
        PPL_LOG("build %lu (%ws) predates PPL (Windows 8.1); SET and FILTER disabled",
                g_PplBuildNumber,
                PplBuildDisplayName(g_PplBuildNumber));
    } else if (!PplLookupBuildOffsets(g_PplBuildNumber, &offsets) ||
               offsets.PsProtectionOffset == 0)
    {
        //
        // Never guess an offset. Known-but-unmapped builds (for example
        // 26H1/26H2) and future builds land here; the driver stays loaded
        // but SET/FILTER return STATUS_NOT_SUPPORTED.
        //
        PPL_LOG("no known EPROCESS offsets for build %lu (%ws); SET and FILTER disabled",
                g_PplBuildNumber,
                PplBuildDisplayName(g_PplBuildNumber));
    } else {
        g_PplOffsets = offsets;
        g_PplProtectionOffset = offsets.PsProtectionOffset;
        g_PplOffsetSupported = TRUE;

        PPL_LOG("build %lu (%ws), PS_PROTECTION offset 0x%03lX",
                g_PplBuildNumber,
                PplBuildDisplayName(g_PplBuildNumber),
                g_PplProtectionOffset);
        PPL_LOG("EPROCESS offsets: MitigationFlags1=0x%03lX MitigationFlags2=0x%03lX ObjectTable=0x%03lX",
                g_PplOffsets.PsMitigationFlags1Offset,
                g_PplOffsets.PsMitigationFlags2Offset,
                g_PplOffsets.ObjectTableOffset);
    }

    g_PsIsProtectedProcess =
        (PPL_PS_IS_PROTECTED_PROCESS)PplpGetSystemRoutine(L"PsIsProtectedProcess");
    g_PsIsProtectedProcessLight =
        (PPL_PS_IS_PROTECTED_PROCESS)PplpGetSystemRoutine(L"PsIsProtectedProcessLight");

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

    PplTrackLock();
    oldProtection = PplpReadProtection(Process);

    if (oldProtection == newProtection) {
        //
        // Already at the requested level. Do not take ownership of a process
        // this driver did not protect.
        //
        status = PplpVerifyTargetByte(Process, newProtection, oldProtection)
                     ? STATUS_SUCCESS
                     : STATUS_UNSUCCESSFUL;
        PplTrackUnlock();

        PplpInitializeResult(Result, status, oldProtection, oldProtection);
        PPL_LOG("pid=%lu already at protection 0x%02X (status 0x%08X)",
                ProcessId, oldProtection, status);
        return status;
    }

    PplpWriteProtection(Process, newProtection);
    verifyProtection = PplpReadProtection(Process);

    if (!PplpVerifyTargetByte(Process, newProtection, verifyProtection)) {
        PplpWriteProtection(Process, oldProtection);
        PplTrackUnlock();

        status = STATUS_UNSUCCESSFUL;
        PplpInitializeResult(Result, status, oldProtection, verifyProtection);
        PPL_LOG("pid=%lu verification failed: wanted 0x%02X, got 0x%02X; restored 0x%02X",
                ProcessId, newProtection, verifyProtection, oldProtection);
        return status;
    }

    tracked = PplTrackProtectionLocked(
        ProcessId, Process, newProtection, oldProtection);

    PplTrackUnlock();

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
    BOOLEAN mitigationRestored;

    PplpInitializeResult(Result, STATUS_SUCCESS, 0, 0);

    if (!g_PplOffsetSupported || g_PplProtectionOffset == 0) {
        PplpInitializeResult(Result, STATUS_NOT_SUPPORTED, 0, 0);
        return STATUS_NOT_SUPPORTED;
    }

    status = PsLookupProcessByProcessId(
        (HANDLE)(ULONG_PTR)ProcessId, &process);
    if (!NT_SUCCESS(status)) {
        PplTrackDropByPid(ProcessId);
        PplpInitializeResult(Result, status, 0, 0);
        PPL_LOG("clear pid=%lu: process lookup failed 0x%08X", ProcessId, status);
        return status;
    }

    PplTrackLock();
    entry = PplTrackFindLocked(ProcessId, process);
    current = PplpReadProtection(process);

    if (entry == NULL) {
        PplTrackUnlock();
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

    mitigationRestored = PplRestoreMitigationLocked(process, entry);
    if (!mitigationRestored) {
        PplTrackUnlock();
        ObDereferenceObject(process);

        PplpInitializeResult(Result, STATUS_UNSUCCESSFUL, current, current);
        PPL_LOG("clear pid=%lu: mitigation restore failed; entry retained",
                ProcessId);
        return STATUS_UNSUCCESSFUL;
    }

    if ((entry->ChangeMask & PPL_TRACK_PROTECTION) == 0) {
        //
        // Mitigation-only entry. Protection was never changed by this driver,
        // so current and target are the same.
        //
        PplTrackDropLocked(entry);
        PplTrackUnlock();
        ObDereferenceObject(process);

        PplpInitializeResult(Result, STATUS_SUCCESS, current, current);
        PPL_LOG("clear pid=%lu: mitigation restored, protection unchanged at 0x%02X",
                ProcessId, current);
        return STATUS_SUCCESS;
    }

    if (current != entry->AppliedProtection) {
        PplTrackUnlock();
        ObDereferenceObject(process);

        PplpInitializeResult(Result, STATUS_UNSUCCESSFUL, current, current);
        PPL_LOG("clear pid=%lu: current 0x%02X does not match tracked 0x%02X; protection unchanged",
                ProcessId, current, entry->AppliedProtection);
        return STATUS_UNSUCCESSFUL;
    }

    target = entry->OriginalProtection;

    if (target == current) {
        PplTrackDropLocked(entry);
        PplTrackUnlock();
        ObDereferenceObject(process);

        PplpInitializeResult(Result, STATUS_SUCCESS, current, current);
        return STATUS_SUCCESS;
    }

    PplpWriteProtection(process, target);
    verify = PplpReadProtection(process);

    if (!PplpVerifyTargetByte(process, target, verify)) {
        PplpWriteProtection(process, current);
        PplTrackUnlock();
        ObDereferenceObject(process);

        PplpInitializeResult(Result, STATUS_UNSUCCESSFUL, current, verify);
        PPL_LOG("clear pid=%lu verification failed: wanted 0x%02X, got 0x%02X; restored 0x%02X",
                ProcessId, target, verify, current);
        return STATUS_UNSUCCESSFUL;
    }

    PplTrackDropLocked(entry);
    PplTrackUnlock();
    ObDereferenceObject(process);

    PplpInitializeResult(Result, STATUS_SUCCESS, current, target);
    PPL_LOG("clear pid=%lu: protection 0x%02X -> 0x%02X",
            ProcessId, current, target);
    return STATUS_SUCCESS;
}

NTSTATUS
PplForceClearByPid(
    _In_ ULONG ProcessId,
    _Out_ PPPL_OPERATION_RESULT Result)
{
    PEPROCESS process = NULL;
    PPL_TRACK_ENTRY* entry;
    NTSTATUS status;
    UCHAR current;
    UCHAR verify;
    BOOLEAN tracked = FALSE;

    PplpInitializeResult(Result, STATUS_SUCCESS, 0, 0);

    if (!g_PplOffsetSupported || g_PplProtectionOffset == 0) {
        PplpInitializeResult(Result, STATUS_NOT_SUPPORTED, 0, 0);
        return STATUS_NOT_SUPPORTED;
    }

    if (ProcessId == 0 || ProcessId == 4) {
        PplpInitializeResult(Result, STATUS_ACCESS_DENIED, 0, 0);
        PPL_LOG("force-clear refusing PID %lu (system process)", ProcessId);
        return STATUS_ACCESS_DENIED;
    }

    status = PsLookupProcessByProcessId(
        (HANDLE)(ULONG_PTR)ProcessId, &process);
    if (!NT_SUCCESS(status)) {
        PplTrackDropByPid(ProcessId);
        PplpInitializeResult(Result, status, 0, 0);
        PPL_LOG("force-clear pid=%lu: process lookup failed 0x%08X",
                ProcessId, status);
        return status;
    }

    if (PplIsBlockedProcess(process, ProcessId, NULL)) {
        ObDereferenceObject(process);
        PplpInitializeResult(Result, STATUS_ACCESS_DENIED, 0, 0);
        PPL_LOG("force-clear refusing blocklisted process pid=%lu", ProcessId);
        return STATUS_ACCESS_DENIED;
    }

    PplTrackLock();

    current = PplpReadProtection(process);
    if (current == 0) {
        PplTrackUnlock();
        ObDereferenceObject(process);

        PplpInitializeResult(Result, STATUS_SUCCESS, current, current);
        PPL_LOG("force-clear pid=%lu: already unprotected", ProcessId);
        return STATUS_SUCCESS;
    }

    entry = PplTrackGetOrCreateLocked(ProcessId, process, current);
    if (entry != NULL &&
        ((entry->ChangeMask & PPL_TRACK_PROTECTION) == 0 ||
         entry->AppliedProtection != current)) {
        //
        // This is the first protection change, or the process was changed
        // outside the driver since our last write. Remember the value we are
        // about to remove so set+clear can put it back.
        //
        entry->OriginalProtection = current;
    }

    PplpWriteProtection(process, 0);
    verify = PplpReadProtection(process);

    if (!PplpVerifyTargetByte(process, 0, verify)) {
        PplpWriteProtection(process, current);
        PplTrackUnlock();
        ObDereferenceObject(process);

        PplpInitializeResult(Result, STATUS_UNSUCCESSFUL, current, verify);
        PPL_LOG("force-clear pid=%lu verification failed: wanted 0x00, got 0x%02X; restored 0x%02X",
                ProcessId, verify, current);
        return STATUS_UNSUCCESSFUL;
    }

    if (entry != NULL) {
        entry->AppliedProtection = 0;
        entry->ChangeMask |= PPL_TRACK_PROTECTION;
        tracked = TRUE;
    }

    PplTrackUnlock();
    ObDereferenceObject(process);

    PplpInitializeResult(Result, STATUS_SUCCESS, current, 0);
    PPL_LOG("force-clear pid=%lu: protection 0x%02X -> 0x00 (%s)",
            ProcessId, current, tracked ? "tracked" : "not tracked");
    return STATUS_SUCCESS;
}

//
// KDU-style handle access repair.
//
// Defender's self-protection registers ObRegisterCallbacks and silently lowers
// DesiredAccess on process handles (VM_WRITE, VM_OPERATION, CREATE_THREAD...).
// The open still succeeds, so the caller only notices when VirtualAllocEx or
// CreateRemoteThread fails. The callback cannot re-run for an existing handle,
// so restoring GrantedAccess in the caller's handle table is enough.
//
// The layout below matches the handle table entries KDU describes in
// Source/Hamakaze/ps.cpp (LookupHandleEntry). Entry size is 16 bytes on x64;
// GrantedAccess is the low ULONG of the second 8-byte union.
//
#define PPL_HT_TABLECODE_OFFSET          0x8
#define PPL_HT_ENTRY_SIZE                16
#define PPL_HT_GRANTED_ACCESS_OFFSET     8
#define PPL_PROCESS_ALL_ACCESS           0x001FFFFFUL
#define PPL_KERNEL_ADDRESS_MIN           0xFFFF800000000000ULL

static
BOOLEAN
PplpIsKernelPointer(
    _In_ const VOID* Pointer)
{
    return ((ULONG_PTR)Pointer >= (ULONG_PTR)PPL_KERNEL_ADDRESS_MIN);
}

static
PVOID
PplpLookupHandleEntry(
    _In_ PVOID HandleTable,
    _In_ ULONG_PTR HandleValue)
{
    ULONG_PTR tableCode;
    ULONG_PTR level;
    ULONG_PTR base;
    ULONG_PTR index;

    if (HandleTable == NULL || !PplpIsKernelPointer(HandleTable)) {
        return NULL;
    }
    if ((HandleValue & 0x3) != 0) {
        return NULL;
    }

    tableCode = *((volatile ULONG_PTR*)
                  ((PUCHAR)HandleTable + PPL_HT_TABLECODE_OFFSET));
    level = tableCode & 0x3;
    base = tableCode & ~(ULONG_PTR)0x3;
    index = HandleValue >> 2;

    if (base == 0 || !PplpIsKernelPointer((PVOID)base)) {
        return NULL;
    }

    switch (level) {
    case 0:
        return (PVOID)(base + (index * PPL_HT_ENTRY_SIZE));

    case 1:
    {
        ULONG_PTR mid;

        if (!PplpIsKernelPointer((PVOID)(base + ((index >> 8) * sizeof(ULONG_PTR))))) {
            return NULL;
        }
        mid = *((volatile ULONG_PTR*)
                (base + ((index >> 8) * sizeof(ULONG_PTR))));
        if (mid == 0 || !PplpIsKernelPointer((PVOID)mid)) {
            return NULL;
        }
        return (PVOID)(mid + ((index & 0xFF) * PPL_HT_ENTRY_SIZE));
    }

    case 2:
    {
        ULONG_PTR l1;
        ULONG_PTR l2;

        if (!PplpIsKernelPointer((PVOID)(base + ((index >> 16) * sizeof(ULONG_PTR))))) {
            return NULL;
        }
        l1 = *((volatile ULONG_PTR*)
               (base + ((index >> 16) * sizeof(ULONG_PTR))));
        if (l1 == 0 || !PplpIsKernelPointer((PVOID)l1)) {
            return NULL;
        }
        if (!PplpIsKernelPointer((PVOID)(l1 + (((index >> 8) & 0xFF) * sizeof(ULONG_PTR))))) {
            return NULL;
        }
        l2 = *((volatile ULONG_PTR*)
               (l1 + (((index >> 8) & 0xFF) * sizeof(ULONG_PTR))));
        if (l2 == 0 || !PplpIsKernelPointer((PVOID)l2)) {
            return NULL;
        }
        return (PVOID)(l2 + ((index & 0xFF) * PPL_HT_ENTRY_SIZE));
    }

    default:
        return NULL;
    }
}

NTSTATUS
PplFixHandleAccess(
    _In_ const PPL_HANDLE_FIX_REQUEST* Request,
    _Out_ PPPL_HANDLE_FIX_RESULT Result)
{
    PEPROCESS target = NULL;
    PEPROCESS current;
    PVOID handleTable;
    PVOID entry;
    ULONG_PTR objectPointer;
    ULONG oldAccess;
    ULONG newAccess;
    NTSTATUS status;

    RtlZeroMemory(Result, sizeof(*Result));

    if (!g_PplOffsetSupported || g_PplOffsets.ObjectTableOffset == 0) {
        Result->Status = STATUS_NOT_SUPPORTED;
        return STATUS_NOT_SUPPORTED;
    }

    if (Request->ProcessId == 0 ||
        Request->AccessMask == 0 ||
        (Request->AccessMask & ~PPL_PROCESS_ALL_ACCESS) != 0 ||
        Request->Reserved != 0 ||
        Request->Reserved2 != 0) {
        Result->Status = STATUS_INVALID_PARAMETER;
        return STATUS_INVALID_PARAMETER;
    }

    status = PsLookupProcessByProcessId(
        (HANDLE)(ULONG_PTR)Request->ProcessId, &target);
    if (!NT_SUCCESS(status)) {
        Result->Status = status;
        PPL_LOG("fix-handle pid=%lu: process lookup failed 0x%08X",
                Request->ProcessId, status);
        return status;
    }

    //
    // The IOCTL runs in the caller's context, so only the caller's own handle
    // table is touched. Never trust a handle value supplied for another user.
    //
    current = PsGetCurrentProcess();
    handleTable = *((volatile PVOID*)
                    ((PUCHAR)current + g_PplOffsets.ObjectTableOffset));

    //
    // Resolve the caller's handle through the object manager first. This both
    // rejects arbitrary handle values before the handle-table walk and proves
    // the handle really references the process the caller named. Access=0
    // means the stripped GrantedAccess does not block this reference.
    //
    {
        PVOID handleObject = NULL;

        status = ObReferenceObjectByHandle(
            (HANDLE)(ULONG_PTR)Request->HandleValue,
            0,
            *PsProcessType,
            KernelMode,
            &handleObject,
            NULL);
        if (!NT_SUCCESS(status) || handleObject != (PVOID)target) {
            status = NT_SUCCESS(status) ? STATUS_INVALID_HANDLE : status;
            Result->Status = status;
            PPL_LOG("fix-handle pid=%lu: handle 0x%llX does not reference the target (0x%08X)",
                    Request->ProcessId,
                    (unsigned long long)Request->HandleValue,
                    status);
            if (handleObject != NULL) {
                ObDereferenceObject(handleObject);
            }
            ObDereferenceObject(target);
            return status;
        }

        ObDereferenceObject(handleObject);
    }

    entry = PplpLookupHandleEntry(handleTable, (ULONG_PTR)Request->HandleValue);
    if (entry == NULL || !PplpIsKernelPointer(entry)) {
        status = STATUS_INVALID_HANDLE;
        Result->Status = status;
        PPL_LOG("fix-handle pid=%lu: handle 0x%llX not found in caller table",
                Request->ProcessId,
                (unsigned long long)Request->HandleValue);
        ObDereferenceObject(target);
        return status;
    }

    objectPointer = *((volatile ULONG_PTR*)entry);

    oldAccess = *((volatile ULONG*)
                  ((PUCHAR)entry + PPL_HT_GRANTED_ACCESS_OFFSET));
    *((volatile ULONG*)((PUCHAR)entry + PPL_HT_GRANTED_ACCESS_OFFSET)) =
        Request->AccessMask;
    KeMemoryBarrier();
    newAccess = *((volatile ULONG*)
                  ((PUCHAR)entry + PPL_HT_GRANTED_ACCESS_OFFSET));

    Result->OldGrantedAccess = oldAccess;
    Result->NewGrantedAccess = newAccess;
    Result->ObjectPointer = (ULONG64)objectPointer;
    Result->Status = (newAccess == Request->AccessMask)
                         ? STATUS_SUCCESS
                         : STATUS_UNSUCCESSFUL;

    status = Result->Status;
    PPL_LOG("fix-handle pid=%lu handle=0x%llX access 0x%08lX -> 0x%08lX (status 0x%08X)",
            Request->ProcessId,
            (unsigned long long)Request->HandleValue,
            oldAccess, newAccess, status);

    ObDereferenceObject(target);
    return status;
}

//
// RtlCreateUserThread is exported by ntoskrnl but not declared by the WDK
// headers used here. It calls NtCreateThreadEx from kernel mode, so
// PspCheckForInvalidAccessByProtection sees AccessMode == KernelMode and does
// not apply the PPL incompatibility check.
//
typedef NTSTATUS (NTAPI *PPL_RTL_CREATE_USER_THREAD)(
    _In_ HANDLE ProcessHandle,
    _In_opt_ PSECURITY_DESCRIPTOR SecurityDescriptor,
    _In_ BOOLEAN CreateSuspended,
    _In_ ULONG StackZeroBits,
    _In_opt_ SIZE_T StackReserve,
    _In_opt_ SIZE_T StackCommit,
    _In_ PVOID StartAddress,
    _In_opt_ PVOID Parameter,
    _Out_opt_ PHANDLE ThreadHandle,
    _Out_opt_ PCLIENT_ID ClientId);

NTSTATUS
PplCreateRemoteThread(
    _In_ const PPL_REMOTE_THREAD_REQUEST* Request,
    _Out_ PPPL_REMOTE_THREAD_RESULT Result)
{
    PEPROCESS target = NULL;
    PVOID handleObject = NULL;
    PPL_RTL_CREATE_USER_THREAD createUserThread;
    HANDLE threadHandle = NULL;
    CLIENT_ID clientId;
    NTSTATUS status;

    RtlZeroMemory(Result, sizeof(*Result));
    RtlZeroMemory(&clientId, sizeof(clientId));

    if (Request->ProcessId == 0 ||
        Request->Flags != 0 ||
        Request->ProcessHandle == 0 ||
        Request->StartAddress == 0 ||
        Request->Reserved != 0 ||
        Request->Reserved2 != 0) {
        Result->Status = STATUS_INVALID_PARAMETER;
        return STATUS_INVALID_PARAMETER;
    }

    status = PsLookupProcessByProcessId(
        (HANDLE)(ULONG_PTR)Request->ProcessId, &target);
    if (!NT_SUCCESS(status)) {
        Result->Status = status;
        PPL_LOG("create-thread pid=%lu: process lookup failed 0x%08X",
                Request->ProcessId, status);
        return status;
    }

    //
    // Confirm the caller's handle still references the requested process and
    // was not reused. Access=0 means a stripped GrantedAccess is irrelevant.
    //
    status = ObReferenceObjectByHandle(
        (HANDLE)(ULONG_PTR)Request->ProcessHandle,
        0,
        *PsProcessType,
        KernelMode,
        &handleObject,
        NULL);
    if (!NT_SUCCESS(status) || handleObject != (PVOID)target) {
        status = NT_SUCCESS(status) ? STATUS_INVALID_HANDLE : status;
        Result->Status = status;
        PPL_LOG("create-thread pid=%lu: bad process handle 0x%llX (0x%08X)",
                Request->ProcessId,
                (unsigned long long)Request->ProcessHandle,
                status);
        if (handleObject != NULL) {
            ObDereferenceObject(handleObject);
        }
        ObDereferenceObject(target);
        return status;
    }
    ObDereferenceObject(handleObject);

    createUserThread = (PPL_RTL_CREATE_USER_THREAD)
        PplpGetSystemRoutine(L"RtlCreateUserThread");
    if (createUserThread == NULL) {
        Result->Status = STATUS_NOT_SUPPORTED;
        PPL_LOG("create-thread: RtlCreateUserThread unavailable");
        ObDereferenceObject(target);
        return STATUS_NOT_SUPPORTED;
    }

    status = createUserThread(
        (HANDLE)(ULONG_PTR)Request->ProcessHandle,
        NULL,
        FALSE,
        0,
        0,
        0,
        (PVOID)(ULONG_PTR)Request->StartAddress,
        (PVOID)(ULONG_PTR)Request->Parameter,
        &threadHandle,
        &clientId);

    if (NT_SUCCESS(status)) {
        Result->ThreadId = (ULONG)(ULONG_PTR)clientId.UniqueThread;
    }

    if (threadHandle != NULL) {
        ZwClose(threadHandle);
    }

    Result->Status = status;
    PPL_LOG("create-thread pid=%lu start=0x%llX param=0x%llX -> 0x%08X tid=%lu",
            Request->ProcessId,
            (unsigned long long)Request->StartAddress,
            (unsigned long long)Request->Parameter,
            status,
            Result->ThreadId);

    ObDereferenceObject(target);
    return status;
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
    // SignatureLevel and SectionSignatureLevel are the two bytes directly in
    // front of PS_PROTECTION. Reading them here is safe and avoids the
    // undocumented output-pointer ABI of PsGetProcessSignatureLevel.
    //
    Result->SignatureLevel = PplReadSignatureLevel(process);
    Result->SectionSignatureLevel = PplReadSectionSignatureLevel(process);

    if (g_PplOffsets.PsMitigationFlags1Offset != 0) {
        Result->MitigationFlags1 = PplReadMitigationFlags(
            process, g_PplOffsets.PsMitigationFlags1Offset);
        Result->MitigationFlags2 = PplReadMitigationFlags(
            process, g_PplOffsets.PsMitigationFlags2Offset);
    }

    Result->Flags = (UCHAR)(
        (isProtected ? PPL_QUERY_FLAG_PROTECTED : 0) |
        (isLight ? PPL_QUERY_FLAG_PROTECTED_LIGHT : 0) |
        ((Result->MitigationFlags1 &
          PPL_MITIGATION_FLAG_SIGNATURE_OPT_IN) != 0
             ? PPL_QUERY_FLAG_BLOCK_NON_MS_DLLS
             : 0));

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

    if (!PplTrackIsInitialized()) {
        return;
    }

    PplTrackLock();

    for (i = 0; i < PPL_MAX_TRACKED_PROCESSES; ++i) {
        PPL_TRACK_ENTRY* entry = &PplTrackEntries()[i];
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
        {
            BOOLEAN restoredSomething = FALSE;
            BOOLEAN failedSomething = FALSE;

            if ((entry->ChangeMask &
                 (PPL_TRACK_MITIGATION | PPL_TRACK_SIGNATURE_LEVELS)) != 0) {
                if (PplRestoreMitigationLocked(process, entry)) {
                    restoredSomething = TRUE;
                } else {
                    failedSomething = TRUE;
                }
            }

            if ((entry->ChangeMask & PPL_TRACK_PROTECTION) != 0) {
                if (current != entry->AppliedProtection) {
                    //
                    // Protection was changed by someone else; do not fight it.
                    //
                } else if (entry->OriginalProtection == current) {
                    restoredSomething = TRUE;
                } else {
                    PplpWriteProtection(process, entry->OriginalProtection);
                    verify = PplpReadProtection(process);

                    if (PplpVerifyTargetByte(
                            process, entry->OriginalProtection, verify)) {
                        restoredSomething = TRUE;
                    } else {
                        //
                        // Put back our value if restoring the original did
                        // not verify.
                        //
                        PplpWriteProtection(process, entry->AppliedProtection);
                        failedSomething = TRUE;
                    }
                }
            }

            if (failedSomething) {
                ++failed;
            } else if (restoredSomething) {
                ++restored;
            } else {
                ++skipped;
            }
        }

        ObDereferenceObject(process);
    }

    PplTrackResetLocked();
    PplTrackUnlock();

    PPL_LOG("restore-on-unload: restored=%lu skipped=%lu failed=%lu",
            restored, skipped, failed);
}
