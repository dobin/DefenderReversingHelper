#include "PplFilter.h"
#include "PplProtection.h"
#include "PplLog.h"

#define PPL_FILTER_POOL_TAG 'tlfP'
#define PPL_SYSTEM_PROCESS_INFORMATION_CLASS 5
#define PPL_MAX_IMAGE_NAME 64

typedef PUCHAR (NTAPI *PPL_PS_GET_PROCESS_IMAGE_FILE_NAME)(
    _In_ PEPROCESS Process);

typedef NTSTATUS (NTAPI *PPL_QUERY_SYSTEM_INFORMATION)(
    _In_ ULONG SystemInformationClass,
    _Inout_ PVOID SystemInformation,
    _In_ ULONG SystemInformationLength,
    _Out_opt_ PULONG ReturnLength);

//
// Prefix of SYSTEM_PROCESS_INFORMATION, stable on x64. Only the fields needed
// for PID enumeration are declared; NextEntryOffset provides the stride.
//
typedef struct _PPL_SYSTEM_PROCESS_INFORMATION {
    ULONG NextEntryOffset;
    ULONG NumberOfThreads;
    LARGE_INTEGER WorkingSetPrivateSize;
    ULONG HardFaultCount;
    ULONG NumberOfThreadsHighWatermark;
    ULONGLONG CycleTime;
    LARGE_INTEGER CreateTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER KernelTime;
    UNICODE_STRING ImageName;
    LONG BasePriority;
    HANDLE UniqueProcessId;
    HANDLE InheritedFromUniqueProcessId;
} PPL_SYSTEM_PROCESS_INFORMATION, *PPPL_SYSTEM_PROCESS_INFORMATION;

typedef struct _PPL_INTERNAL_FILTER {
    BOOLEAN InUse;
    ULONG   MatchMode;
    UCHAR   Signer;
    UCHAR   Audit;
    UCHAR   Reserved[2];
    ULONG   Length;
    WCHAR   Pattern[PPL_MAX_PATTERN_CHARS];
} PPL_INTERNAL_FILTER;

static PPL_INTERNAL_FILTER g_Filters[PPL_MAX_FILTERS];
static EX_PUSH_LOCK        g_FilterLock;
static ULONG               g_FilterCount;
static BOOLEAN             g_FilterInitialized;
static volatile BOOLEAN    g_NotifyRegistered;

static PPL_PS_GET_PROCESS_IMAGE_FILE_NAME g_PsGetProcessImageFileName;
static PPL_QUERY_SYSTEM_INFORMATION       g_QuerySystemInformation;

static
VOID
PplCreateProcessNotifyEx(
    _Inout_ PEPROCESS Process,
    _In_ HANDLE ProcessId,
    _Inout_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo);

static const WCHAR* const g_BlockedNames[] = {
    L"System",
    L"Registry",
    L"smss.exe",
    L"csrss.exe",
    L"wininit.exe",
    L"services.exe",
    L"lsass.exe",
    L"winlogon.exe",
};

static
ULONG
PplpStringLength(
    _In_ const WCHAR* String,
    _In_ ULONG MaxChars)
{
    ULONG length = 0;

    while (length < MaxChars && String[length] != L'\0') {
        ++length;
    }
    return length;
}

static
BOOLEAN
PplpEqualWideCI(
    _In_ const WCHAR* Left,
    _In_ ULONG LeftLength,
    _In_ const WCHAR* Right,
    _In_ ULONG RightLength)
{
    ULONG i;

    if (LeftLength != RightLength) {
        return FALSE;
    }

    for (i = 0; i < LeftLength; ++i) {
        if (RtlUpcaseUnicodeChar(Left[i]) != RtlUpcaseUnicodeChar(Right[i])) {
            return FALSE;
        }
    }
    return TRUE;
}

static
VOID
PplpGetBaseNameUnicode(
    _In_ PCUNICODE_STRING ImageFileName,
    _Out_ const WCHAR** BaseName,
    _Out_ PULONG BaseLength)
{
    const WCHAR* buffer;
    ULONG length;
    ULONG i;

    *BaseName = NULL;
    *BaseLength = 0;

    if (ImageFileName == NULL || ImageFileName->Buffer == NULL ||
        ImageFileName->Length == 0) {
        return;
    }

    buffer = ImageFileName->Buffer;
    length = ImageFileName->Length / sizeof(WCHAR);

    for (i = length; i > 0; --i) {
        WCHAR c = buffer[i - 1];
        if (c == L'\\' || c == L'/') {
            *BaseName = &buffer[i];
            *BaseLength = length - i;
            return;
        }
    }

    *BaseName = buffer;
    *BaseLength = length;
}

static
BOOLEAN
PplpAnsiBaseMatches(
    _In_ const UCHAR* BaseName,
    _In_ ULONG BaseLength,
    _In_ const WCHAR* Target)
{
    ULONG targetLength;
    ULONG i;

    targetLength = PplpStringLength(Target, PPL_MAX_IMAGE_NAME);
    if (BaseLength != targetLength) {
        return FALSE;
    }

    for (i = 0; i < BaseLength; ++i) {
        WCHAR c = (WCHAR)BaseName[i];
        if (RtlUpcaseUnicodeChar(c) != RtlUpcaseUnicodeChar(Target[i])) {
            return FALSE;
        }
    }
    return TRUE;
}

static
BOOLEAN
PplpGetProcessBaseNameAnsi(
    _In_ PEPROCESS Process,
    _Out_ const UCHAR** BaseName,
    _Out_ PULONG BaseLength)
{
    PUCHAR imageName;
    ULONG length = 0;
    ULONG start = 0;
    ULONG i;

    *BaseName = NULL;
    *BaseLength = 0;

    if (g_PsGetProcessImageFileName == NULL) {
        return FALSE;
    }

    imageName = g_PsGetProcessImageFileName(Process);
    if (imageName == NULL) {
        return FALSE;
    }

    //
    // EPROCESS.ImageFileName is a 15-byte buffer and is not guaranteed to be
    // null-terminated when the name fills all 15 bytes.
    //
    while (length < 15 && imageName[length] != 0) {
        ++length;
    }

    for (i = 0; i < length; ++i) {
        if (imageName[i] == '\\' || imageName[i] == '/') {
            start = i + 1;
        }
    }

    *BaseName = &imageName[start];
    *BaseLength = length - start;
    return TRUE;
}

static
BOOLEAN
PplpBaseNameIsBlocked(
    _In_ const WCHAR* BaseName,
    _In_ ULONG BaseLength)
{
    ULONG i;

    for (i = 0; i < RTL_NUMBER_OF(g_BlockedNames); ++i) {
        ULONG blockedLength = PplpStringLength(
            g_BlockedNames[i], PPL_MAX_IMAGE_NAME);
        if (PplpEqualWideCI(BaseName, BaseLength,
                            g_BlockedNames[i], blockedLength)) {
            return TRUE;
        }
    }
    return FALSE;
}

BOOLEAN
PplIsBlockedPid(
    _In_ ULONG ProcessId)
{
    return (ProcessId == 0 || ProcessId == 4);
}

BOOLEAN
PplIsBlockedBaseName(
    _In_ PCUNICODE_STRING ImageFileName)
{
    const WCHAR* baseName;
    ULONG baseLength;

    PplpGetBaseNameUnicode(ImageFileName, &baseName, &baseLength);
    if (baseName == NULL || baseLength == 0) {
        return FALSE;
    }
    return PplpBaseNameIsBlocked(baseName, baseLength);
}

BOOLEAN
PplIsBlockedProcess(
    _In_ PEPROCESS Process,
    _In_ ULONG ProcessId,
    _In_opt_ PCUNICODE_STRING ImageFileName)
{
    const UCHAR* ansiBase;
    ULONG ansiLength;
    ULONG i;

    if (PplIsBlockedPid(ProcessId)) {
        return TRUE;
    }

    if (ImageFileName != NULL && ImageFileName->Length != 0) {
        return PplIsBlockedBaseName(ImageFileName);
    }

    if (!PplpGetProcessBaseNameAnsi(Process, &ansiBase, &ansiLength)) {
        return FALSE;
    }

    for (i = 0; i < RTL_NUMBER_OF(g_BlockedNames); ++i) {
        if (PplpAnsiBaseMatches(ansiBase, ansiLength, g_BlockedNames[i])) {
            return TRUE;
        }
    }
    return FALSE;
}

static
BOOLEAN
PplpFilterMatches(
    _In_ const WCHAR* BaseName,
    _In_ ULONG BaseLength,
    _In_ ULONG MatchMode,
    _In_ const WCHAR* Pattern,
    _In_ ULONG PatternLength)
{
    ULONG i;
    ULONG j;

    if (PatternLength == 0) {
        return FALSE;
    }

    if (MatchMode == PPL_MATCH_EXACT) {
        return PplpEqualWideCI(BaseName, BaseLength,
                               Pattern, PatternLength);
    }

    if (PatternLength > BaseLength) {
        return FALSE;
    }

    for (i = 0; i + PatternLength <= BaseLength; ++i) {
        BOOLEAN match = TRUE;
        for (j = 0; j < PatternLength; ++j) {
            if (RtlUpcaseUnicodeChar(BaseName[i + j]) !=
                RtlUpcaseUnicodeChar(Pattern[j])) {
                match = FALSE;
                break;
            }
        }
        if (match) {
            return TRUE;
        }
    }
    return FALSE;
}

static
BOOLEAN
PplpFilterPatternExistsLocked(
    _In_ const WCHAR* Pattern,
    _In_ ULONG Length)
{
    ULONG i;

    for (i = 0; i < PPL_MAX_FILTERS; ++i) {
        if (!g_Filters[i].InUse) {
            continue;
        }
        if (PplpEqualWideCI(g_Filters[i].Pattern, g_Filters[i].Length,
                            Pattern, Length)) {
            return TRUE;
        }
    }
    return FALSE;
}

static
NTSTATUS
PplpApplyExisting(
    _In_ const WCHAR* Pattern,
    _In_ ULONG PatternLength,
    _In_ ULONG MatchMode,
    _In_ UCHAR Signer,
    _In_ UCHAR Audit,
    _Inout_ PPPL_FILTER_RESULT Result)
{
    ULONG bufferSize = 256 * 1024;
    PVOID buffer = NULL;
    NTSTATUS status = STATUS_INSUFFICIENT_RESOURCES;
    ULONG needed = 0;
    ULONG attempt;
    ULONG currentPid;

    if (g_QuerySystemInformation == NULL) {
        return STATUS_NOT_SUPPORTED;
    }

    for (attempt = 0; attempt < 5; ++attempt) {
        buffer = ExAllocatePool2(POOL_FLAG_NON_PAGED, bufferSize,
                                 PPL_FILTER_POOL_TAG);
        if (buffer == NULL) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        status = g_QuerySystemInformation(
            PPL_SYSTEM_PROCESS_INFORMATION_CLASS,
            buffer, bufferSize, &needed);

        if (status != STATUS_INFO_LENGTH_MISMATCH &&
            status != STATUS_BUFFER_TOO_SMALL &&
            status != STATUS_BUFFER_OVERFLOW) {
            break;
        }

        ExFreePoolWithTag(buffer, PPL_FILTER_POOL_TAG);
        buffer = NULL;

        if (needed == 0 || needed > (16 * 1024 * 1024)) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        bufferSize = needed + (64 * 1024);
    }

    if (!NT_SUCCESS(status) || buffer == NULL) {
        if (buffer != NULL) {
            ExFreePoolWithTag(buffer, PPL_FILTER_POOL_TAG);
        }
        return status;
    }

    currentPid = (ULONG)(ULONG_PTR)PsGetCurrentProcessId();

    {
        ULONG offset = 0;

        for (;;) {
            PPPL_SYSTEM_PROCESS_INFORMATION processInfo;
            ULONG processId;
            PEPROCESS process = NULL;
            const UCHAR* ansiBase = NULL;
            ULONG ansiLength = 0;
            WCHAR wideBase[PPL_MAX_IMAGE_NAME];
            const WCHAR* baseName = NULL;
            ULONG baseLength = 0;

            if (offset + sizeof(PPL_SYSTEM_PROCESS_INFORMATION) > bufferSize) {
                break;
            }

            processInfo = (PPPL_SYSTEM_PROCESS_INFORMATION)((PUCHAR)buffer + offset);
            processId = (ULONG)(ULONG_PTR)processInfo->UniqueProcessId;

            if (processId != 0 && processId != 4 && processId != currentPid) {
                status = PsLookupProcessByProcessId(
                    (HANDLE)(ULONG_PTR)processId, &process);
                if (NT_SUCCESS(status)) {
                    if (PplpGetProcessBaseNameAnsi(
                            process, &ansiBase, &ansiLength) &&
                        ansiLength > 0) {
                        ULONG copyLength = ansiLength;
                        ULONG i;

                        if (copyLength >= PPL_MAX_IMAGE_NAME) {
                            copyLength = PPL_MAX_IMAGE_NAME - 1;
                        }
                        for (i = 0; i < copyLength; ++i) {
                            wideBase[i] = (WCHAR)ansiBase[i];
                        }
                        wideBase[copyLength] = L'\0';
                        baseName = wideBase;
                        baseLength = copyLength;
                    } else if (processInfo->ImageName.Buffer != NULL) {
                        PplpGetBaseNameUnicode(
                            &processInfo->ImageName, &baseName, &baseLength);
                    }

                    if (baseName != NULL &&
                        PplpFilterMatches(baseName, baseLength, MatchMode,
                                          Pattern, PatternLength)) {
                        if (PplIsBlockedProcess(
                                process, processId,
                                processInfo->ImageName.Buffer != NULL
                                    ? &processInfo->ImageName
                                    : NULL)) {
                            ++Result->Skipped;
                        } else if (PplIsProcessProtected(process)) {
                            ++Result->Skipped;
                        } else {
                            PPL_OPERATION_RESULT operationResult;
                            NTSTATUS protectStatus = PplProtectProcess(
                                process, processId, Signer, Audit,
                                &operationResult);
                            if (NT_SUCCESS(protectStatus)) {
                                ++Result->Applied;
                            } else {
                                ++Result->Failed;
                            }
                        }
                    }

                    ObDereferenceObject(process);
                }
            }

            if (processInfo->NextEntryOffset == 0) {
                break;
            }
            if (processInfo->NextEntryOffset < sizeof(ULONG) ||
                offset + processInfo->NextEntryOffset >= bufferSize) {
                break;
            }
            offset += processInfo->NextEntryOffset;
        }
    }

    ExFreePoolWithTag(buffer, PPL_FILTER_POOL_TAG);
    return STATUS_SUCCESS;
}

NTSTATUS
PplFilterInitialize(VOID)
{
    UNICODE_STRING routineName;

    ExInitializePushLock(&g_FilterLock);
    RtlZeroMemory(g_Filters, sizeof(g_Filters));
    g_FilterCount = 0;
    g_NotifyRegistered = FALSE;
    g_FilterInitialized = TRUE;

    RtlInitUnicodeString(&routineName, L"PsGetProcessImageFileName");
    g_PsGetProcessImageFileName =
        (PPL_PS_GET_PROCESS_IMAGE_FILE_NAME)MmGetSystemRoutineAddress(&routineName);

    RtlInitUnicodeString(&routineName, L"ZwQuerySystemInformation");
    g_QuerySystemInformation =
        (PPL_QUERY_SYSTEM_INFORMATION)MmGetSystemRoutineAddress(&routineName);

    if (g_QuerySystemInformation == NULL) {
        RtlInitUnicodeString(&routineName, L"NtQuerySystemInformation");
        g_QuerySystemInformation =
            (PPL_QUERY_SYSTEM_INFORMATION)MmGetSystemRoutineAddress(&routineName);
    }

    if (g_PsGetProcessImageFileName == NULL) {
        PPL_LOG("warning: PsGetProcessImageFileName unavailable; ANSI name checks limited");
    }
    if (g_QuerySystemInformation == NULL) {
        PPL_LOG("warning: system process enumeration unavailable; apply-existing disabled");
    }

    return STATUS_SUCCESS;
}

NTSTATUS
PplFilterRegisterNotify(VOID)
{
    NTSTATUS status;

    g_NotifyRegistered = TRUE;
    status = PsSetCreateProcessNotifyRoutineEx(
        PplCreateProcessNotifyEx, FALSE);

    if (NT_SUCCESS(status)) {
        PPL_LOG("process-creation callback registered");
    } else {
        g_NotifyRegistered = FALSE;
        PPL_LOG("PsSetCreateProcessNotifyRoutineEx failed: 0x%08X", status);
        if (status == STATUS_ACCESS_DENIED) {
            PPL_LOG("hint: the driver needs /INTEGRITYCHECK (Force Integrity)");
        }
    }

    return status;
}

VOID
PplFilterUnregisterNotify(VOID)
{
    NTSTATUS status;

    if (!g_NotifyRegistered) {
        return;
    }

    status = PsSetCreateProcessNotifyRoutineEx(
        PplCreateProcessNotifyEx, TRUE);

    if (NT_SUCCESS(status)) {
        g_NotifyRegistered = FALSE;
        PPL_LOG("process-creation callback unregistered");
    } else {
        g_NotifyRegistered = FALSE;
        PPL_LOG("unregister process-creation callback failed: 0x%08X", status);
    }
}

BOOLEAN
PplFilterNotifyRegistered(VOID)
{
    return g_NotifyRegistered;
}

NTSTATUS
PplFilterAdd(
    _In_ const PPL_FILTER_REQUEST* Request,
    _Out_ PPPL_FILTER_RESULT Result)
{
    ULONG length;
    ULONG i;
    PPL_INTERNAL_FILTER* slot = NULL;

    RtlZeroMemory(Result, sizeof(*Result));

    length = PplpStringLength(Request->Pattern, PPL_MAX_PATTERN_CHARS);
    if (length < 3 || length >= PPL_MAX_PATTERN_CHARS) {
        Result->Status = STATUS_INVALID_PARAMETER;
        return Result->Status;
    }

    if (Request->MatchMode != PPL_MATCH_SUBSTRING &&
        Request->MatchMode != PPL_MATCH_EXACT) {
        Result->Status = STATUS_INVALID_PARAMETER;
        return Result->Status;
    }

    if (Request->Signer < PS_PROTECTED_SIGNER_AUTHENTICODE ||
        Request->Signer > PS_PROTECTED_SIGNER_APP ||
        Request->Audit > 1 ||
        (Request->Flags & ~PPL_FILTER_FLAG_APPLY_EXISTING) != 0) {
        Result->Status = STATUS_INVALID_PARAMETER;
        return Result->Status;
    }

    if (!g_PplOffsetSupported || g_PplProtectionOffset == 0) {
        Result->Status = STATUS_NOT_SUPPORTED;
        return Result->Status;
    }

    if (!g_NotifyRegistered) {
        Result->Status = STATUS_NOT_SUPPORTED;
        return Result->Status;
    }

    ExAcquirePushLockExclusive(&g_FilterLock);

    if (PplpFilterPatternExistsLocked(Request->Pattern, length)) {
        ExReleasePushLockExclusive(&g_FilterLock);
        Result->Status = STATUS_OBJECT_NAME_COLLISION;
        return Result->Status;
    }

    for (i = 0; i < PPL_MAX_FILTERS; ++i) {
        if (!g_Filters[i].InUse) {
            slot = &g_Filters[i];
            break;
        }
    }

    if (slot == NULL) {
        ExReleasePushLockExclusive(&g_FilterLock);
        Result->Status = STATUS_INSUFFICIENT_RESOURCES;
        return Result->Status;
    }

    RtlZeroMemory(slot, sizeof(*slot));
    slot->InUse = TRUE;
    slot->MatchMode = Request->MatchMode;
    slot->Signer = Request->Signer;
    slot->Audit = Request->Audit;
    slot->Length = length;
    RtlCopyMemory(slot->Pattern, Request->Pattern,
                  length * sizeof(WCHAR));
    ++g_FilterCount;

    ExReleasePushLockExclusive(&g_FilterLock);

    PPL_LOG("filter added: pattern length=%lu mode=%lu signer=%u audit=%u",
            length, Request->MatchMode,
            Request->Signer, Request->Audit);

    Result->Status = STATUS_SUCCESS;

    if ((Request->Flags & PPL_FILTER_FLAG_APPLY_EXISTING) != 0) {
        NTSTATUS applyStatus = PplpApplyExisting(
            Request->Pattern, length, Request->MatchMode,
            Request->Signer, Request->Audit, Result);
        if (!NT_SUCCESS(applyStatus)) {
            PPL_LOG("apply-existing failed: 0x%08X (filter remains active)",
                    applyStatus);
        } else {
            PPL_LOG("apply-existing: applied=%lu skipped=%lu failed=%lu",
                    Result->Applied, Result->Skipped, Result->Failed);
        }
    }

    return Result->Status;
}

NTSTATUS
PplFilterRemove(
    _In_ const PPL_FILTER_REQUEST* Request,
    _Out_ PPPL_FILTER_RESULT Result)
{
    ULONG length;
    ULONG i;
    ULONG removed = 0;

    RtlZeroMemory(Result, sizeof(*Result));

    length = PplpStringLength(Request->Pattern, PPL_MAX_PATTERN_CHARS);
    if (length == 0 || length >= PPL_MAX_PATTERN_CHARS) {
        Result->Status = STATUS_INVALID_PARAMETER;
        return Result->Status;
    }

    ExAcquirePushLockExclusive(&g_FilterLock);
    for (i = 0; i < PPL_MAX_FILTERS; ++i) {
        if (!g_Filters[i].InUse) {
            continue;
        }
        if (PplpEqualWideCI(g_Filters[i].Pattern, g_Filters[i].Length,
                            Request->Pattern, length)) {
            RtlZeroMemory(&g_Filters[i], sizeof(g_Filters[i]));
            ++removed;
        }
    }
    if (removed <= g_FilterCount) {
        g_FilterCount -= removed;
    } else {
        g_FilterCount = 0;
    }
    ExReleasePushLockExclusive(&g_FilterLock);

    Result->Applied = removed;
    Result->Status = (removed != 0) ? STATUS_SUCCESS : STATUS_NOT_FOUND;

    PPL_LOG("filter remove: length=%lu, %lu removed (processes stay protected)",
            length, removed);
    return Result->Status;
}

NTSTATUS
PplFilterClear(
    _Out_ PPPL_FILTER_RESULT Result)
{
    ULONG removed;

    RtlZeroMemory(Result, sizeof(*Result));

    ExAcquirePushLockExclusive(&g_FilterLock);
    removed = g_FilterCount;
    RtlZeroMemory(g_Filters, sizeof(g_Filters));
    g_FilterCount = 0;
    ExReleasePushLockExclusive(&g_FilterLock);

    Result->Applied = removed;
    Result->Status = STATUS_SUCCESS;

    PPL_LOG("filter clear: removed %lu filters (processes stay protected)", removed);
    return STATUS_SUCCESS;
}

NTSTATUS
PplFilterList(
    _Out_ PPPL_FILTER_LIST List)
{
    ULONG i;
    ULONG index = 0;

    RtlZeroMemory(List, sizeof(*List));

    ExAcquirePushLockShared(&g_FilterLock);
    for (i = 0; i < PPL_MAX_FILTERS; ++i) {
        if (!g_Filters[i].InUse) {
            continue;
        }

        List->Entries[index].MatchMode = g_Filters[i].MatchMode;
        List->Entries[index].Signer = g_Filters[i].Signer;
        List->Entries[index].Audit = g_Filters[i].Audit;
        RtlCopyMemory(List->Entries[index].Pattern,
                      g_Filters[i].Pattern,
                      g_Filters[i].Length * sizeof(WCHAR));
        List->Entries[index].Pattern[g_Filters[i].Length] = L'\0';
        ++index;
    }
    ExReleasePushLockShared(&g_FilterLock);

    List->Count = index;
    List->Status = STATUS_SUCCESS;
    return STATUS_SUCCESS;
}

VOID
PplFilterShutdown(VOID)
{
    if (!g_FilterInitialized) {
        return;
    }

    ExAcquirePushLockExclusive(&g_FilterLock);
    RtlZeroMemory(g_Filters, sizeof(g_Filters));
    g_FilterCount = 0;
    ExReleasePushLockExclusive(&g_FilterLock);
}

static
VOID
PplCreateProcessNotifyEx(
    _Inout_ PEPROCESS Process,
    _In_ HANDLE ProcessId,
    _Inout_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo)
{
    ULONG pid = (ULONG)(ULONG_PTR)ProcessId;
    const WCHAR* baseName;
    ULONG baseLength;
    PPL_INTERNAL_FILTER matched;
    BOOLEAN found = FALSE;
    ULONG i;
    NTSTATUS status;
    PPL_OPERATION_RESULT result;

    if (!g_NotifyRegistered) {
        return;
    }

    if (CreateInfo == NULL) {
        return;
    }

    //
    // Fast path: the callback does no EPROCESS reads or blocklist checks when
    // no filters exist. This keeps plain driver load/unload inert.
    //
    if (g_FilterCount == 0) {
        return;
    }

    if (CreateInfo->ImageFileName == NULL ||
        CreateInfo->ImageFileName->Buffer == NULL ||
        CreateInfo->ImageFileName->Length == 0) {
        return;
    }

    if (PplIsBlockedPid(pid)) {
        return;
    }

    if (PplIsBlockedBaseName(CreateInfo->ImageFileName)) {
        PPL_LOG("filter skipped blocklisted process pid=%lu image=%wZ",
                pid, CreateInfo->ImageFileName);
        return;
    }

    if (PplIsProcessProtected(Process)) {
        return;
    }

    PplpGetBaseNameUnicode(CreateInfo->ImageFileName,
                           &baseName, &baseLength);
    if (baseName == NULL || baseLength == 0) {
        return;
    }

    RtlZeroMemory(&matched, sizeof(matched));

    ExAcquirePushLockShared(&g_FilterLock);
    for (i = 0; i < PPL_MAX_FILTERS; ++i) {
        if (!g_Filters[i].InUse) {
            continue;
        }
        if (PplpFilterMatches(baseName, baseLength,
                              g_Filters[i].MatchMode,
                              g_Filters[i].Pattern,
                              g_Filters[i].Length)) {
            matched = g_Filters[i];
            found = TRUE;
            break;
        }
    }
    ExReleasePushLockShared(&g_FilterLock);

    if (!found) {
        return;
    }

    RtlZeroMemory(&result, sizeof(result));
    status = PplProtectProcess(Process, pid, matched.Signer,
                               matched.Audit, &result);

    PPL_LOG("filter matched pid=%lu image=%wZ old=0x%02X new=0x%02X status=0x%08X",
            pid, CreateInfo->ImageFileName,
            result.OldProtection, result.NewProtection, status);
}
