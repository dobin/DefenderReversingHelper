#pragma once

#include <ntddk.h>
#include "../shared/PplIoctl.h"
#include "PplTrack.h"

//
// Removes the "block non-Microsoft binaries" (Cobalt Strike blockdll) process
// mitigation by clearing EPROCESS!MitigationFlags bit 23 and zeroing
// SectionSignatureLevel. Unrelated to PS_PROTECTION/PPL.
//
NTSTATUS PplAllowNonMicrosoftDllsByPid(
    _In_ ULONG ProcessId,
    _Out_ PPPL_MITIGATION_RESULT Result);

//
// Restores the mitigation fields of a tracked entry. The caller must hold the
// track lock. Returns FALSE if the current values no longer match what this
// driver applied, or if the write-back did not verify.
//
BOOLEAN PplRestoreMitigationLocked(
    _In_ PEPROCESS Process,
    _Inout_ PPPL_TRACK_ENTRY Entry);

//
// Read-only EPROCESS field helpers. Query uses these; only this module writes
// the mitigation fields.
//
UCHAR PplReadSignatureLevel(_In_ PEPROCESS Process);
UCHAR PplReadSectionSignatureLevel(_In_ PEPROCESS Process);
ULONG PplReadMitigationFlags(_In_ PEPROCESS Process, _In_ ULONG Offset);
