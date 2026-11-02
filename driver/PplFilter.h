#pragma once

#include <ntddk.h>
#include "../shared/PplIoctl.h"

NTSTATUS PplFilterInitialize(VOID);
NTSTATUS PplFilterRegisterNotify(VOID);
VOID PplFilterUnregisterNotify(VOID);
VOID PplFilterShutdown(VOID);

BOOLEAN PplFilterNotifyRegistered(VOID);

NTSTATUS PplFilterAdd(
    _In_ const PPL_FILTER_REQUEST* Request,
    _Out_ PPPL_FILTER_RESULT Result);

NTSTATUS PplFilterRemove(
    _In_ const PPL_FILTER_REQUEST* Request,
    _Out_ PPPL_FILTER_RESULT Result);

NTSTATUS PplFilterClear(
    _Out_ PPPL_FILTER_RESULT Result);

NTSTATUS PplFilterList(
    _Out_ PPPL_FILTER_LIST List);

//
// Safety blocklist shared by the PID path, the filter path and apply-existing.
//
BOOLEAN PplIsBlockedPid(_In_ ULONG ProcessId);
BOOLEAN PplIsBlockedBaseName(_In_ PCUNICODE_STRING ImageFileName);
BOOLEAN PplIsBlockedProcess(
    _In_ PEPROCESS Process,
    _In_ ULONG ProcessId,
    _In_opt_ PCUNICODE_STRING ImageFileName);
