#pragma once

//
// Shared ABI between MakeMePPL.sys and PplCtl.exe.
//
// This header deliberately has no kernel/user-mode includes. Include <ntddk.h>
// in kernel code and <windows.h> + <winioctl.h> in user-mode code before this
// header.
//

#if !defined(_KERNEL_MODE) && !defined(PPL_USER_NTSTATUS_DEFINED)
typedef LONG NTSTATUS;
#define PPL_USER_NTSTATUS_DEFINED
#endif

#define PPL_DRIVER_VERSION          L"1.4.0"
#define PPL_DEVICE_NAME             L"\\Device\\MakeMePPL"
#define PPL_SYMLINK_NAME            L"\\??\\MakeMePPL"
#define PPL_WIN32_DEVICE            L"\\\\.\\MakeMePPL"
#define PPL_DEFAULT_PIPE            L"PplGrant"

#define PPL_MAX_FILTERS             16
#define PPL_MAX_PATTERN_CHARS       128

//
// PS_PROTECTION layout (one byte in EPROCESS):
//   bits [2:0] = type, bit [3] = audit, bits [7:4] = signer
//
#define PS_PROTECTED_TYPE_NONE              0
#define PS_PROTECTED_TYPE_PROTECTED_LIGHT   1
#define PS_PROTECTED_TYPE_PROTECTED         2

#define PS_PROTECTED_SIGNER_NONE            0
#define PS_PROTECTED_SIGNER_AUTHENTICODE    1
#define PS_PROTECTED_SIGNER_CODEGEN         2
#define PS_PROTECTED_SIGNER_ANTIMALWARE     3
#define PS_PROTECTED_SIGNER_LSA             4
#define PS_PROTECTED_SIGNER_WINDOWS         5
#define PS_PROTECTED_SIGNER_WINTCB          6
#define PS_PROTECTED_SIGNER_WINSYSTEM       7
#define PS_PROTECTED_SIGNER_APP             8

#define MAKE_PS_PROTECTION(signer, audit, type) \
    ((UCHAR)((((signer) & 0xF) << 4) | (((audit) & 1) << 3) | ((type) & 7)))

#define PPL_MATCH_SUBSTRING         0
#define PPL_MATCH_EXACT             1

#define PPL_FILTER_FLAG_APPLY_EXISTING  0x00000001

#define PPL_INFO_FLAG_NOTIFY_REGISTERED     0x00000001
#define PPL_INFO_FLAG_OFFSET_SUPPORTED      0x00000002
#define PPL_INFO_FLAG_MITIGATION_SUPPORTED  0x00000004
#define PPL_INFO_FLAG_TELEMETRY_ACTIVE      0x00000008

//
// EPROCESS!MitigationFlags bit 23.
//
// This is the opt-in switch the kernel sets for
// PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON
// (PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY) and for
// SetProcessMitigationPolicy(ProcessSignaturePolicy, MicrosoftSignedOnly=1).
// The actual DLL requirement is EPROCESS!SectionSignatureLevel, which the
// kernel raises to 8 (Microsoft) for the ALWAYS_ON policy. Clearing this bit
// and zeroing SectionSignatureLevel removes the restriction.
//
// The creation-policy bit (bit 44 of the 64-bit mitigation options) is not
// stored verbatim in MitigationFlags2. MitigationFlags2 holds unrelated
// mitigations and is not modified.
//
#define PPL_MITIGATION_FLAG_SIGNATURE_OPT_IN 0x00800000

//
// EPROCESS!MitigationFlags1 bit 8: DisableDynamicCode / Arbitrary Code Guard
// (ACG, SetProcessMitigationPolicy(ProcessDynamicCodePolicy)). ACG has to be
// clear before Detours can change an image code page to writable.
//
#define PPL_MITIGATION_FLAG_DISABLE_DYNAMIC_CODE 0x00000100

//
// PPL_QUERY_RESULT.Flags bits.
//
#define PPL_QUERY_FLAG_PROTECTED            0x01
#define PPL_QUERY_FLAG_PROTECTED_LIGHT      0x02
#define PPL_QUERY_FLAG_BLOCK_NON_MS_DLLS    0x04

#define PPL_IOCTL_BASE              0x800
#define PPL_DEVICE_TYPE             FILE_DEVICE_UNKNOWN

#define IOCTL_PPL_SET_BY_PID \
    CTL_CODE(PPL_DEVICE_TYPE, PPL_IOCTL_BASE + 0, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_PPL_CLEAR_BY_PID \
    CTL_CODE(PPL_DEVICE_TYPE, PPL_IOCTL_BASE + 1, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_PPL_QUERY_BY_PID \
    CTL_CODE(PPL_DEVICE_TYPE, PPL_IOCTL_BASE + 2, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_PPL_FILTER_ADD \
    CTL_CODE(PPL_DEVICE_TYPE, PPL_IOCTL_BASE + 3, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_PPL_FILTER_REMOVE \
    CTL_CODE(PPL_DEVICE_TYPE, PPL_IOCTL_BASE + 4, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_PPL_FILTER_CLEAR \
    CTL_CODE(PPL_DEVICE_TYPE, PPL_IOCTL_BASE + 5, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_PPL_FILTER_LIST \
    CTL_CODE(PPL_DEVICE_TYPE, PPL_IOCTL_BASE + 6, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_PPL_GET_INFO \
    CTL_CODE(PPL_DEVICE_TYPE, PPL_IOCTL_BASE + 7, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_PPL_ALLOW_NON_MS_DLLS \
    CTL_CODE(PPL_DEVICE_TYPE, PPL_IOCTL_BASE + 8, METHOD_BUFFERED, FILE_ANY_ACCESS)

//
// Removes PPL from a process even when this driver did not apply it. The
// removed byte is recorded as the process's original protection, so a later
// set+clear restores it. This is destructive and only meant for an isolated
// test VM where the target really has to be unprotected (for example, to test
// DLL loading into a PPL system process).
//
#define IOCTL_PPL_FORCE_CLEAR_BY_PID \
    CTL_CODE(PPL_DEVICE_TYPE, PPL_IOCTL_BASE + 9, METHOD_BUFFERED, FILE_ANY_ACCESS)

//
// Restores access rights that a protection callback stripped from an existing
// handle in the calling process. This is the KDUControlHandleAccess equivalent
// (KDU -pho) and is only needed when a security product lowers DesiredAccess
// at handle creation instead of refusing the open. The driver verifies that
// the handle points at the requested process before writing the mask.
//
#define IOCTL_PPL_FIX_HANDLE_ACCESS \
    CTL_CODE(PPL_DEVICE_TYPE, PPL_IOCTL_BASE + 10, METHOD_BUFFERED, FILE_ANY_ACCESS)

//
// Creates a user thread in a target process from kernel mode. The kernel path
// bypasses the user-mode PsTestProtectedProcessIncompatibility check that makes
// NtCreateThreadEx fail against a protected process even when the process
// handle has PROCESS_CREATE_THREAD. Used only for the MsMpEng test.
//
#define IOCTL_PPL_CREATE_REMOTE_THREAD \
    CTL_CODE(PPL_DEVICE_TYPE, PPL_IOCTL_BASE + 11, METHOD_BUFFERED, FILE_ANY_ACCESS)

//
// Clears EPROCESS!MitigationFlags1 bit 8 (DisableDynamicCode / ACG) so
// in-process inline hooks can make image code pages writable. Uses
// PPL_MITIGATION_REQUEST / PPL_MITIGATION_RESULT and is tracked for restore.
//
#define IOCTL_PPL_ALLOW_DYNAMIC_CODE \
    CTL_CODE(PPL_DEVICE_TYPE, PPL_IOCTL_BASE + 12, METHOD_BUFFERED, FILE_ANY_ACCESS)

typedef struct _PPL_REMOTE_THREAD_REQUEST {
    ULONG   ProcessId;        // target process, for validation
    ULONG   Flags;            // must be 0 (thread starts immediately)
    ULONG64 ProcessHandle;    // caller's handle to the target
    ULONG64 StartAddress;     // user-mode entry point in the target
    ULONG64 Parameter;        // argument passed to StartAddress
    ULONG   Reserved;
    ULONG   Reserved2;
} PPL_REMOTE_THREAD_REQUEST, *PPPL_REMOTE_THREAD_REQUEST;

typedef struct _PPL_REMOTE_THREAD_RESULT {
    NTSTATUS Status;
    ULONG    ThreadId;
    ULONG    Flags;
    ULONG    Reserved;
} PPL_REMOTE_THREAD_RESULT, *PPPL_REMOTE_THREAD_RESULT;

typedef struct _PPL_HANDLE_FIX_REQUEST {
    ULONG   ProcessId;       // target process the handle must reference
    ULONG   AccessMask;      // new GrantedAccess (subset of PROCESS_ALL_ACCESS)
    ULONG64 HandleValue;     // handle in the calling process
    ULONG   Reserved;
    ULONG   Reserved2;
} PPL_HANDLE_FIX_REQUEST, *PPPL_HANDLE_FIX_REQUEST;

typedef struct _PPL_HANDLE_FIX_RESULT {
    NTSTATUS Status;
    ULONG    OldGrantedAccess;
    ULONG    NewGrantedAccess;
    ULONG64  ObjectPointer;  // EPROCESS the handle referenced, diagnostic only
    ULONG    Reserved;
} PPL_HANDLE_FIX_RESULT, *PPPL_HANDLE_FIX_RESULT;

typedef struct _PPL_SET_REQUEST {
    ULONG ProcessId;
    UCHAR Signer;       // 1..8
    UCHAR Type;         // must be PS_PROTECTED_TYPE_PROTECTED_LIGHT (1)
    UCHAR Audit;        // 0 or 1
    UCHAR Reserved;
} PPL_SET_REQUEST, *PPPL_SET_REQUEST;

typedef struct _PPL_OPERATION_RESULT {
    NTSTATUS Status;
    UCHAR OldProtection;
    UCHAR NewProtection;
    UCHAR Reserved[2];
} PPL_OPERATION_RESULT, *PPPL_OPERATION_RESULT;

typedef struct _PPL_MITIGATION_REQUEST {
    ULONG ProcessId;
    ULONG Reserved;     // must be 0
} PPL_MITIGATION_REQUEST, *PPPL_MITIGATION_REQUEST;

typedef struct _PPL_MITIGATION_RESULT {
    NTSTATUS Status;
    ULONG OldMitigationFlags1;
    ULONG NewMitigationFlags1;
    ULONG OldMitigationFlags2;
    ULONG NewMitigationFlags2;
    UCHAR OldSignatureLevel;
    UCHAR NewSignatureLevel;
    UCHAR OldSectionSignatureLevel;
    UCHAR NewSectionSignatureLevel;
} PPL_MITIGATION_RESULT, *PPPL_MITIGATION_RESULT;

typedef struct _PPL_QUERY_RESULT {
    NTSTATUS Status;
    ULONG ProcessId;
    ULONG BuildNumber;
    ULONG ProtectionOffset;
    UCHAR Protection;
    UCHAR SignatureLevel;
    UCHAR SectionSignatureLevel;
    UCHAR Flags;        // PPL_QUERY_FLAG_*
    ULONG MitigationFlags1;
    ULONG MitigationFlags2;
} PPL_QUERY_RESULT, *PPPL_QUERY_RESULT;

typedef struct _PPL_FILTER_REQUEST {
    WCHAR Pattern[PPL_MAX_PATTERN_CHARS];
    ULONG MatchMode;    // PPL_MATCH_SUBSTRING or PPL_MATCH_EXACT
    ULONG Flags;        // PPL_FILTER_FLAG_*
    UCHAR Signer;       // 1..8
    UCHAR Audit;        // 0 or 1
    UCHAR Reserved[2];
} PPL_FILTER_REQUEST, *PPPL_FILTER_REQUEST;

typedef struct _PPL_FILTER_RESULT {
    NTSTATUS Status;
    ULONG Applied;
    ULONG Skipped;
    ULONG Failed;
} PPL_FILTER_RESULT, *PPPL_FILTER_RESULT;

typedef struct _PPL_FILTER_LIST_ENTRY {
    WCHAR Pattern[PPL_MAX_PATTERN_CHARS];
    ULONG MatchMode;
    UCHAR Signer;
    UCHAR Audit;
    UCHAR Reserved[2];
} PPL_FILTER_LIST_ENTRY, *PPPL_FILTER_LIST_ENTRY;

typedef struct _PPL_FILTER_LIST {
    NTSTATUS Status;
    ULONG Count;
    PPL_FILTER_LIST_ENTRY Entries[PPL_MAX_FILTERS];
} PPL_FILTER_LIST, *PPPL_FILTER_LIST;

typedef struct _PPL_DRIVER_INFO {
    NTSTATUS Status;
    ULONG BuildNumber;
    ULONG ProtectionOffset;
    ULONG MaxFilters;
    ULONG Flags;        // PPL_INFO_FLAG_*
    WCHAR Version[32];

    //
    // Added in 1.1.0. The driver reports the full NT version it detected and
    // the EPROCESS offsets from its build table. Only ProtectionOffset is
    // used to set PPL; the rest are diagnostics.
    //
    ULONG MajorVersion;
    ULONG MinorVersion;
    ULONG MitigationFlags1Offset;
    ULONG MitigationFlags2Offset;
    ULONG ObjectTableOffset;
    NTSTATUS TelemetryStatus;   // last MpTelemetryInitialize result
    ULONG TelemetryStage;       // 1..6, which init call was reached

    //
    // Added with the bounded send path.  Events the driver could not hand to
    // the consumer (send timeout, cooldown, wrong IRQL), events skipped by the
    // write-rate budget, and failed sends.  Growing send drops mean the
    // consumer is not draining fast enough.
    //
    ULONG TelemetryDropped;
    ULONG TelemetryWriteSkipped;
    ULONG TelemetrySendFailures;
} PPL_DRIVER_INFO, *PPPL_DRIVER_INFO;
