#pragma once

//
// Shared ABI between PplExecutor.sys and PplCtl.exe.
//
// This header deliberately has no kernel/user-mode includes. Include <ntddk.h>
// in kernel code and <windows.h> + <winioctl.h> in user-mode code before this
// header.
//

#if !defined(_KERNEL_MODE) && !defined(PPL_USER_NTSTATUS_DEFINED)
typedef LONG NTSTATUS;
#define PPL_USER_NTSTATUS_DEFINED
#endif

#define PPL_DRIVER_VERSION          L"1.0.0"
#define PPL_DEVICE_NAME             L"\\Device\\PplExecutor"
#define PPL_SYMLINK_NAME            L"\\??\\PplExecutor"
#define PPL_WIN32_DEVICE            L"\\\\.\\PplExecutor"
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

#define PPL_INFO_FLAG_NOTIFY_REGISTERED 0x00000001
#define PPL_INFO_FLAG_OFFSET_SUPPORTED  0x00000002

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

typedef struct _PPL_QUERY_RESULT {
    NTSTATUS Status;
    ULONG ProcessId;
    ULONG BuildNumber;
    ULONG ProtectionOffset;
    UCHAR Protection;
    UCHAR SignatureLevel;
    UCHAR SectionSignatureLevel;
    UCHAR Flags;        // bit0 = protected, bit1 = protected light
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
} PPL_DRIVER_INFO, *PPPL_DRIVER_INFO;
