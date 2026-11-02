#pragma once

#include <ntddk.h>
#include "../shared/PplIoctl.h"
#include "../shared/PplBuilds.h"

//
// Declared in ntifs.h, which cannot be mixed with wdmsec.h in this driver.
//
NTKERNELAPI
NTSTATUS
PsLookupProcessByProcessId(
    _In_ HANDLE ProcessId,
    _Outptr_ PEPROCESS* Process);

extern ULONG   g_PplMajorVersion;
extern ULONG   g_PplMinorVersion;
extern ULONG   g_PplBuildNumber;
extern ULONG   g_PplProtectionOffset;
extern BOOLEAN g_PplOffsetSupported;
extern PPL_BUILD_OFFSETS g_PplOffsets;

NTSTATUS PplProtectionInitialize(VOID);

NTSTATUS PplSetByPid(
    _In_ ULONG ProcessId,
    _In_ UCHAR Signer,
    _In_ UCHAR Audit,
    _Out_ PPPL_OPERATION_RESULT Result);

NTSTATUS PplClearByPid(
    _In_ ULONG ProcessId,
    _Out_ PPPL_OPERATION_RESULT Result);

NTSTATUS PplQueryByPid(
    _In_ ULONG ProcessId,
    _Out_ PPPL_QUERY_RESULT Result);

//
// Applies protection to an already-referenced EPROCESS. Used by the PID path,
// the apply-existing path and the process-creation callback. The caller keeps
// the process reference.
//
NTSTATUS PplProtectProcess(
    _In_ PEPROCESS Process,
    _In_ ULONG ProcessId,
    _In_ UCHAR Signer,
    _In_ UCHAR Audit,
    _Out_opt_ PPPL_OPERATION_RESULT Result);

//
// Read-only helpers used by the filter module and verification.
//
UCHAR PplReadProtection(_In_ PEPROCESS Process);
BOOLEAN PplIsProcessProtected(_In_ PEPROCESS Process);

//
// Restore-on-unload. Best effort only.
//
VOID PplRestoreAllTracked(VOID);
