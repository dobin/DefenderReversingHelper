#include <ntddk.h>
#include <wdmsec.h>

#include "../shared/PplIoctl.h"
#include "PplLog.h"
#include "PplProtection.h"
#include "PplMitigation.h"
#include "PplFilter.h"

static PDEVICE_OBJECT g_DeviceObject;
static BOOLEAN        g_SymlinkCreated;

//
// Class GUID for IoCreateDeviceSecure's administrator-override mechanism.
//
static const GUID g_PplDeviceClassGuid = {
    0x6d38f7b1, 0x87c0, 0x4f4e,
    { 0x9a, 0x54, 0x3e, 0x27, 0x17, 0x9d, 0x8c, 0x11 }
};

static
NTSTATUS
PplpCreateControlDevice(
    _In_ PDRIVER_OBJECT DriverObject)
{
    UNICODE_STRING deviceName;
    UNICODE_STRING symbolicLinkName;
    UNICODE_STRING sddl;
    NTSTATUS status;

    RtlInitUnicodeString(&deviceName, PPL_DEVICE_NAME);
    RtlInitUnicodeString(&symbolicLinkName, PPL_SYMLINK_NAME);
    //
    // Test tool: allow any local user to issue IOCTLs. Loading/unloading the
    // driver still requires an administrator.
    //
    RtlInitUnicodeString(&sddl, L"D:P(A;;GA;;;WD)");

    status = IoCreateDeviceSecure(
        DriverObject,
        0,
        &deviceName,
        FILE_DEVICE_UNKNOWN,
        FILE_DEVICE_SECURE_OPEN,
        FALSE,
        &sddl,
        &g_PplDeviceClassGuid,
        &g_DeviceObject);

    if (!NT_SUCCESS(status)) {
        PPL_LOG("IoCreateDeviceSecure failed: 0x%08X", status);
        return status;
    }

    status = IoCreateSymbolicLink(&symbolicLinkName, &deviceName);
    if (!NT_SUCCESS(status)) {
        PPL_LOG("IoCreateSymbolicLink failed: 0x%08X", status);
        IoDeleteDevice(g_DeviceObject);
        g_DeviceObject = NULL;
        return status;
    }

    g_SymlinkCreated = TRUE;
    g_DeviceObject->Flags &= ~DO_DEVICE_INITIALIZING;
    return STATUS_SUCCESS;
}

static
NTSTATUS
PplpCreateClose(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);

    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

static
NTSTATUS
PplpDeviceControl(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp)
{
    PIO_STACK_LOCATION stack;
    ULONG ioctl;
    ULONG inputLength;
    ULONG outputLength;
    PVOID systemBuffer;
    NTSTATUS status = STATUS_INVALID_DEVICE_REQUEST;
    ULONG information = 0;

    UNREFERENCED_PARAMETER(DeviceObject);

    stack = IoGetCurrentIrpStackLocation(Irp);
    ioctl = stack->Parameters.DeviceIoControl.IoControlCode;
    inputLength = stack->Parameters.DeviceIoControl.InputBufferLength;
    outputLength = stack->Parameters.DeviceIoControl.OutputBufferLength;
    systemBuffer = Irp->AssociatedIrp.SystemBuffer;

    if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
        status = STATUS_INVALID_DEVICE_STATE;
        goto complete;
    }

    switch (ioctl) {
    case IOCTL_PPL_SET_BY_PID:
    {
        PPL_SET_REQUEST request;
        PPL_OPERATION_RESULT* result = (PPL_OPERATION_RESULT*)systemBuffer;

        if (inputLength < sizeof(request) || systemBuffer == NULL) {
            status = STATUS_INVALID_PARAMETER;
            break;
        }
        if (outputLength < sizeof(*result)) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }

        RtlCopyMemory(&request, systemBuffer, sizeof(request));
        RtlZeroMemory(systemBuffer, outputLength);

        if (request.ProcessId == 0 ||
            request.Signer < PS_PROTECTED_SIGNER_AUTHENTICODE ||
            request.Signer > PS_PROTECTED_SIGNER_APP ||
            request.Type != PS_PROTECTED_TYPE_PROTECTED_LIGHT ||
            request.Audit > 1) {
            status = STATUS_INVALID_PARAMETER;
            break;
        }

        (VOID)PplSetByPid(request.ProcessId, request.Signer,
                          request.Audit, result);
        status = STATUS_SUCCESS;
        information = sizeof(*result);
        break;
    }

    case IOCTL_PPL_CLEAR_BY_PID:
    {
        ULONG processId;
        PPL_OPERATION_RESULT* result = (PPL_OPERATION_RESULT*)systemBuffer;

        if (inputLength < sizeof(processId) || systemBuffer == NULL) {
            status = STATUS_INVALID_PARAMETER;
            break;
        }
        if (outputLength < sizeof(*result)) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }

        RtlCopyMemory(&processId, systemBuffer, sizeof(processId));
        RtlZeroMemory(systemBuffer, outputLength);

        (VOID)PplClearByPid(processId, result);
        status = STATUS_SUCCESS;
        information = sizeof(*result);
        break;
    }

    case IOCTL_PPL_QUERY_BY_PID:
    {
        ULONG processId;
        PPL_QUERY_RESULT* result = (PPL_QUERY_RESULT*)systemBuffer;

        if (inputLength < sizeof(processId) || systemBuffer == NULL) {
            status = STATUS_INVALID_PARAMETER;
            break;
        }
        if (outputLength < sizeof(*result)) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }

        RtlCopyMemory(&processId, systemBuffer, sizeof(processId));
        RtlZeroMemory(systemBuffer, outputLength);

        (VOID)PplQueryByPid(processId, result);
        status = STATUS_SUCCESS;
        information = sizeof(*result);
        break;
    }

    case IOCTL_PPL_FILTER_ADD:
    {
        PPL_FILTER_REQUEST request;
        PPL_FILTER_RESULT* result = (PPL_FILTER_RESULT*)systemBuffer;

        if (inputLength < sizeof(request) || systemBuffer == NULL) {
            status = STATUS_INVALID_PARAMETER;
            break;
        }
        if (outputLength < sizeof(*result)) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }

        RtlCopyMemory(&request, systemBuffer, sizeof(request));
        request.Pattern[PPL_MAX_PATTERN_CHARS - 1] = L'\0';
        RtlZeroMemory(systemBuffer, outputLength);

        (VOID)PplFilterAdd(&request, result);
        status = STATUS_SUCCESS;
        information = sizeof(*result);
        break;
    }

    case IOCTL_PPL_FILTER_REMOVE:
    {
        PPL_FILTER_REQUEST request;
        PPL_FILTER_RESULT* result = (PPL_FILTER_RESULT*)systemBuffer;

        if (inputLength < sizeof(request) || systemBuffer == NULL) {
            status = STATUS_INVALID_PARAMETER;
            break;
        }
        if (outputLength < sizeof(*result)) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }

        RtlCopyMemory(&request, systemBuffer, sizeof(request));
        request.Pattern[PPL_MAX_PATTERN_CHARS - 1] = L'\0';
        RtlZeroMemory(systemBuffer, outputLength);

        (VOID)PplFilterRemove(&request, result);
        status = STATUS_SUCCESS;
        information = sizeof(*result);
        break;
    }

    case IOCTL_PPL_FILTER_CLEAR:
    {
        PPL_FILTER_RESULT* result = (PPL_FILTER_RESULT*)systemBuffer;

        if (systemBuffer == NULL) {
            status = STATUS_INVALID_PARAMETER;
            break;
        }
        if (outputLength < sizeof(*result)) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }

        RtlZeroMemory(systemBuffer, outputLength);
        (VOID)PplFilterClear(result);
        status = STATUS_SUCCESS;
        information = sizeof(*result);
        break;
    }

    case IOCTL_PPL_FILTER_LIST:
    {
        PPL_FILTER_LIST* list = (PPL_FILTER_LIST*)systemBuffer;

        if (systemBuffer == NULL) {
            status = STATUS_INVALID_PARAMETER;
            break;
        }
        if (outputLength < sizeof(*list)) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }

        RtlZeroMemory(systemBuffer, outputLength);
        (VOID)PplFilterList(list);
        status = STATUS_SUCCESS;
        information = sizeof(*list);
        break;
    }

    case IOCTL_PPL_GET_INFO:
    {
        PPL_DRIVER_INFO* info = (PPL_DRIVER_INFO*)systemBuffer;
        ULONG j;

        if (systemBuffer == NULL) {
            status = STATUS_INVALID_PARAMETER;
            break;
        }
        if (outputLength < sizeof(*info)) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }

        RtlZeroMemory(systemBuffer, outputLength);
        info->Status = STATUS_SUCCESS;
        info->BuildNumber = g_PplBuildNumber;
        info->ProtectionOffset = g_PplProtectionOffset;
        info->MaxFilters = PPL_MAX_FILTERS;
        info->MajorVersion = g_PplMajorVersion;
        info->MinorVersion = g_PplMinorVersion;
        info->MitigationFlags1Offset = g_PplOffsets.PsMitigationFlags1Offset;
        info->MitigationFlags2Offset = g_PplOffsets.PsMitigationFlags2Offset;
        info->ObjectTableOffset = g_PplOffsets.ObjectTableOffset;
        info->Flags = (PplFilterNotifyRegistered()
                           ? PPL_INFO_FLAG_NOTIFY_REGISTERED
                           : 0) |
                      (g_PplOffsetSupported
                           ? PPL_INFO_FLAG_OFFSET_SUPPORTED
                           : 0) |
                      (g_PplOffsets.PsMitigationFlags1Offset != 0
                           ? PPL_INFO_FLAG_MITIGATION_SUPPORTED
                           : 0);

        for (j = 0;
             j + 1 < RTL_NUMBER_OF(info->Version) &&
             PPL_DRIVER_VERSION[j] != L'\0';
             ++j) {
            info->Version[j] = PPL_DRIVER_VERSION[j];
        }
        info->Version[j] = L'\0';

        status = STATUS_SUCCESS;
        information = sizeof(*info);
        break;
    }

    case IOCTL_PPL_ALLOW_NON_MS_DLLS:
    {
        PPL_MITIGATION_REQUEST request;
        PPL_MITIGATION_RESULT* result = (PPL_MITIGATION_RESULT*)systemBuffer;

        if (inputLength < sizeof(request) || systemBuffer == NULL) {
            status = STATUS_INVALID_PARAMETER;
            break;
        }
        if (outputLength < sizeof(*result)) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }

        RtlCopyMemory(&request, systemBuffer, sizeof(request));
        RtlZeroMemory(systemBuffer, outputLength);

        if (request.ProcessId == 0 || request.Reserved != 0) {
            status = STATUS_INVALID_PARAMETER;
            break;
        }

        (VOID)PplAllowNonMicrosoftDllsByPid(request.ProcessId, result);
        status = STATUS_SUCCESS;
        information = sizeof(*result);
        break;
    }

    case IOCTL_PPL_ALLOW_DYNAMIC_CODE:
    {
        PPL_MITIGATION_REQUEST request;
        PPL_MITIGATION_RESULT* result = (PPL_MITIGATION_RESULT*)systemBuffer;

        if (inputLength < sizeof(request) || systemBuffer == NULL) {
            status = STATUS_INVALID_PARAMETER;
            break;
        }
        if (outputLength < sizeof(*result)) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }

        RtlCopyMemory(&request, systemBuffer, sizeof(request));
        RtlZeroMemory(systemBuffer, outputLength);

        if (request.ProcessId == 0 || request.Reserved != 0) {
            status = STATUS_INVALID_PARAMETER;
            break;
        }

        (VOID)PplAllowDynamicCodeByPid(request.ProcessId, result);
        status = STATUS_SUCCESS;
        information = sizeof(*result);
        break;
    }

    case IOCTL_PPL_FORCE_CLEAR_BY_PID:
    {
        ULONG processId;
        PPL_OPERATION_RESULT* result = (PPL_OPERATION_RESULT*)systemBuffer;

        if (inputLength < sizeof(processId) || systemBuffer == NULL) {
            status = STATUS_INVALID_PARAMETER;
            break;
        }
        if (outputLength < sizeof(*result)) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }

        RtlCopyMemory(&processId, systemBuffer, sizeof(processId));
        RtlZeroMemory(systemBuffer, outputLength);

        (VOID)PplForceClearByPid(processId, result);
        status = STATUS_SUCCESS;
        information = sizeof(*result);
        break;
    }

    case IOCTL_PPL_FIX_HANDLE_ACCESS:
    {
        PPL_HANDLE_FIX_REQUEST request;
        PPL_HANDLE_FIX_RESULT* result = (PPL_HANDLE_FIX_RESULT*)systemBuffer;

        if (inputLength < sizeof(request) || systemBuffer == NULL) {
            status = STATUS_INVALID_PARAMETER;
            break;
        }
        if (outputLength < sizeof(*result)) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }

        RtlCopyMemory(&request, systemBuffer, sizeof(request));
        RtlZeroMemory(systemBuffer, outputLength);

        (VOID)PplFixHandleAccess(&request, result);
        status = STATUS_SUCCESS;
        information = sizeof(*result);
        break;
    }

    case IOCTL_PPL_CREATE_REMOTE_THREAD:
    {
        PPL_REMOTE_THREAD_REQUEST request;
        PPL_REMOTE_THREAD_RESULT* result = (PPL_REMOTE_THREAD_RESULT*)systemBuffer;

        if (inputLength < sizeof(request) || systemBuffer == NULL) {
            status = STATUS_INVALID_PARAMETER;
            break;
        }
        if (outputLength < sizeof(*result)) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }

        RtlCopyMemory(&request, systemBuffer, sizeof(request));
        RtlZeroMemory(systemBuffer, outputLength);

        (VOID)PplCreateRemoteThread(&request, result);
        status = STATUS_SUCCESS;
        information = sizeof(*result);
        break;
    }

    default:
        status = STATUS_INVALID_DEVICE_REQUEST;
        break;
    }

complete:
    Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = information;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}

VOID
PplUnload(
    _In_ PDRIVER_OBJECT DriverObject)
{
    UNICODE_STRING symbolicLinkName;

    PPL_LOG("unloading");

    //
    // 1. Stop new callback invocations and wait for in-flight callbacks.
    //
    PplFilterUnregisterNotify();

    //
    // 2. Flush/discard deferred filter work before restoring. The deferred
    //    thread must be gone before the driver image is unloaded.
    //
    PplFilterDrainDeferred();

    //
    // 3. Restore processes this driver protected, best effort.
    //
    PplRestoreAllTracked();

    //
    // 4. Delete the control interface.
    //
    if (g_SymlinkCreated) {
        RtlInitUnicodeString(&symbolicLinkName, PPL_SYMLINK_NAME);
        IoDeleteSymbolicLink(&symbolicLinkName);
        g_SymlinkCreated = FALSE;
    }
    if (g_DeviceObject != NULL) {
        IoDeleteDevice(g_DeviceObject);
        g_DeviceObject = NULL;
    }

    //
    // 5. Clear state.
    //
    PplFilterShutdown();

    UNREFERENCED_PARAMETER(DriverObject);
}

NTSTATUS
DriverEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath)
{
    NTSTATUS status;
    ULONG i;

    UNREFERENCED_PARAMETER(RegistryPath);

    for (i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; ++i) {
        DriverObject->MajorFunction[i] = NULL;
    }

    DriverObject->MajorFunction[IRP_MJ_CREATE] = PplpCreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = PplpCreateClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = PplpDeviceControl;
    DriverObject->DriverUnload = PplUnload;

    status = PplProtectionInitialize();
    if (!NT_SUCCESS(status)) {
        PPL_LOG("PplProtectionInitialize failed: 0x%08X", status);
        DriverObject->DriverUnload = NULL;
        return status;
    }

    status = PplFilterInitialize();
    if (!NT_SUCCESS(status)) {
        PPL_LOG("PplFilterInitialize failed: 0x%08X", status);
        DriverObject->DriverUnload = NULL;
        return status;
    }

    status = PplpCreateControlDevice(DriverObject);
    if (!NT_SUCCESS(status)) {
        PplFilterShutdown();
        DriverObject->DriverUnload = NULL;
        return status;
    }

    //
    // A failure here only disables the name-filter feature. PID and
    // on-connect grants continue to work.
    //
    (VOID)PplFilterRegisterNotify();

    PPL_LOG("loaded, build %lu (%ws), PPL offset 0x%03lX",
            g_PplBuildNumber,
            PplBuildDisplayName(g_PplBuildNumber),
            g_PplProtectionOffset);

    return STATUS_SUCCESS;
}
