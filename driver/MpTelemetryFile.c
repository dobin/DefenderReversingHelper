/*
 * MpTelemetryFile.c
 * ---------------------------------------------------------------------------
 * Minifilter operation callbacks for the WdFilter-style telemetry source.
 *
 * Create (post), write, cleanup, set-information and set-security produce the
 * MP_TELEMETRY_EVENT_FILE_* messages built by MpTelemetry.c.
 * ---------------------------------------------------------------------------
 */
#include <fltkernel.h>

#include "../shared/MpTelemetry.h"
#include "MpTelemetryInternal.h"
#include "PplDriver.h"
#include "PplLog.h"

/* The WDK in this tree does not export the minifilter sentinel macro.  The
 * filter manager uses 0x80 for IRP_MJ_OPERATION_END_OF_QUEUE. */
#ifndef IRP_MJ_OPERATION_END_OF_QUEUE
#define IRP_MJ_OPERATION_END_OF_QUEUE 0x80
#endif

static
FLT_PREOP_CALLBACK_STATUS
MpTelemetryPreCreate(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext);

static
FLT_POSTOP_CALLBACK_STATUS
MpTelemetryPostCreate(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags);

static
FLT_PREOP_CALLBACK_STATUS
MpTelemetryPreWrite(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext);

static
FLT_PREOP_CALLBACK_STATUS
MpTelemetryPreCleanup(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext);

static
FLT_PREOP_CALLBACK_STATUS
MpTelemetryPreSetInformation(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext);

static
FLT_PREOP_CALLBACK_STATUS
MpTelemetryPreSetSecurity(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext);

static
NTSTATUS
MpTelemetryFilterUnload(
    _In_ FLT_FILTER_UNLOAD_FLAGS Flags);

static const FLT_OPERATION_REGISTRATION g_Operations[] = {
    { IRP_MJ_CREATE,          0, MpTelemetryPreCreate, MpTelemetryPostCreate,
      NULL },
    { IRP_MJ_WRITE,           0, MpTelemetryPreWrite, NULL, NULL },
    { IRP_MJ_CLEANUP,         0, MpTelemetryPreCleanup, NULL, NULL },
    { IRP_MJ_SET_INFORMATION, 0, MpTelemetryPreSetInformation, NULL, NULL },
    { IRP_MJ_SET_SECURITY,    0, MpTelemetryPreSetSecurity, NULL, NULL },
    { IRP_MJ_OPERATION_END_OF_QUEUE }
};

static const FLT_REGISTRATION g_Registration = {
    sizeof(FLT_REGISTRATION),
    FLT_REGISTRATION_VERSION,
    0,
    NULL,
    g_Operations,
    MpTelemetryFilterUnload,
    NULL,   /* InstanceSetupCallback */
    NULL,   /* InstanceQueryTeardownCallback */
    NULL,   /* InstanceTeardownStartCallback */
    NULL,   /* InstanceTeardownCompleteCallback */
    NULL,   /* GenerateFileNameCallback */
    NULL,   /* NormalizeNameComponentCallback */
    NULL,   /* NormalizeContextCleanupCallback */
    NULL,   /* TransactionNotificationCallback */
    NULL,   /* NormalizeNameComponentExCallback */
    NULL    /* SectionNotificationCallback */
};

const FLT_REGISTRATION *
MpTelemetryFilterRegistration(VOID)
{
    return &g_Registration;
}

/*
 * The filter manager requires a FilterUnloadCallback for the filter to be
 * unloadable at all; without one it refuses both `fltmc unload` and
 * `sc stop` (the service stop fails with ERROR_INVALID_SERVICE_CONTROL).
 *
 * Both unload kinds arrive here (sc stop as a mandatory unload, FilterUnload
 * / fltmc unload as non-mandatory).  The filter has to unregister itself from
 * this routine, and the driver has nowhere else to restore tracked
 * protections, so the whole driver teardown runs here.  PplDriverTeardown is
 * idempotent because the filter manager then calls the saved DriverUnload.
 */
static
NTSTATUS
MpTelemetryFilterUnload(
    _In_ FLT_FILTER_UNLOAD_FLAGS Flags)
{
    UNREFERENCED_PARAMETER(Flags);

    PPL_LOG("filter unload requested");
    PplDriverTeardown();
    return STATUS_SUCCESS;
}

/*
 * Build and send the FILE_CREATE event.  Runs at PASSIVE_LEVEL only: name
 * lookup and FltSendMessage are not legal above APC, so a completion that
 * arrives at DISPATCH_LEVEL is deferred through the safe callback below.
 *
 * CreateFlags is the MP_TELEMETRY_FLAG_* mask computed in the preoperation
 * callback.  The requested access lives in Parameters.Create.SecurityContext,
 * which is only valid before the create is issued (it is usually NULL by the
 * time the postoperation callback runs), so it cannot be read here.
 */
static
void
MpTelemetryPostCreateEmit(
    _In_ PFLT_CALLBACK_DATA Data,
    _In_ ULONG CreateFlags)
{
    ULONG options;
    ULONG attributes;

    if (InterlockedCompareExchange(&g_Telemetry.Active, 0, 0) == 0 ||
        g_Telemetry.ClientPort == NULL) {
        return;
    }

    options = Data->Iopb->Parameters.Create.Options;
    attributes = Data->Iopb->Parameters.Create.FileAttributes;
    if ((options & FILE_DIRECTORY_FILE) != 0) {
        return;
    }

    /* Options carries the FILE_* disposition in the high byte; the consumer
     * uses it to tell a plain read open from a create/overwrite.  Omitting it
     * makes every open look like SUPERSEDE and turns each close into a scan. */
    MpTelemetryEmitCurrentFileEx(Data, MP_TELEMETRY_EVENT_FILE_CREATE,
                                 CreateFlags, 0, options, attributes);
}

static
FLT_POSTOP_CALLBACK_STATUS
MpTelemetryPostCreateSafe(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags)
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);

    MpTelemetryPostCreateEmit(Data, (ULONG)(ULONG_PTR)CompletionContext);
    return FLT_POSTOP_FINISHED_PROCESSING;
}

static
FLT_POSTOP_CALLBACK_STATUS
MpTelemetryPostCreate(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags)
{
    if ((Flags & FLTFL_POST_OPERATION_DRAINING) != 0) {
        return FLT_POSTOP_FINISHED_PROCESSING;
    }
    if (!NT_SUCCESS(Data->IoStatus.Status)) {
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    /*
     * A create can complete at DISPATCH_LEVEL (pended/async create).  The
     * filter manager holds completion until the safe callback runs, so event
     * order is preserved.  Skipping instead (as this used to do) silently
     * loses every create that completes asynchronously, including the dirty
     * mark the consumer needs for scan-on-close.
     */
    if (KeGetCurrentIrql() > APC_LEVEL) {
        FLT_POSTOP_CALLBACK_STATUS status = FLT_POSTOP_FINISHED_PROCESSING;

        if (!FltDoCompletionProcessingWhenSafe(Data, FltObjects,
                                               CompletionContext, Flags,
                                               MpTelemetryPostCreateSafe,
                                               &status)) {
            return FLT_POSTOP_FINISHED_PROCESSING;
        }
        return status;
    }

    MpTelemetryPostCreateEmit(Data, (ULONG)(ULONG_PTR)CompletionContext);
    return FLT_POSTOP_FINISHED_PROCESSING;
}

static
FLT_PREOP_CALLBACK_STATUS
MpTelemetryPreCreate(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext)
{
    ULONG flags = 0;
    ACCESS_MASK access = 0;

    UNREFERENCED_PARAMETER(FltObjects);

    /* A postoperation callback is only invoked when the preoperation callback
     * asked for it, so create needs this pass-through pre callback. */
    if (InterlockedCompareExchange(&g_Telemetry.Active, 0, 0) == 0 ||
        g_Telemetry.ClientPort == NULL) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }
    if (MpTelemetryRequestorPid(Data) == 0) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    /*
     * Capture the requested access now: SecurityContext is not reliable in the
     * postoperation callback.  The value is a small bitmask, never a pointer,
     * and is handed back verbatim as the completion context.
     */
    if (Data->Iopb->Parameters.Create.SecurityContext != NULL) {
        access = Data->Iopb->Parameters.Create.SecurityContext->DesiredAccess;
    }
    if ((access & (FILE_WRITE_DATA | FILE_APPEND_DATA | FILE_WRITE_EA |
                   FILE_WRITE_ATTRIBUTES | DELETE | GENERIC_WRITE |
                   MAXIMUM_ALLOWED)) != 0) {
        flags |= MP_TELEMETRY_FLAG_WRITE_ACCESS;
    }
    *CompletionContext = (PVOID)(ULONG_PTR)flags;

    return FLT_PREOP_SUCCESS_WITH_CALLBACK;
}

static
FLT_PREOP_CALLBACK_STATUS
MpTelemetryPreWrite(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext)
{
    LARGE_INTEGER now;
    LONG second;
    ULONG length;

    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);

    if (InterlockedCompareExchange(&g_Telemetry.Active, 0, 0) == 0 ||
        g_Telemetry.ClientPort == NULL) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    length = Data->Iopb->Parameters.Write.Length;
    if (length == 0) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }
    if ((Data->Iopb->IrpFlags & IRP_PAGING_IO) != 0) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    /*
     * A build or an installer can issue tens of thousands of small writes.
     * Keep a simple per-second budget so a test run does not turn into a
     * port flood.  Over-budget writes are counted and dropped.
     */
    KeQuerySystemTime(&now);
    second = (LONG)(now.QuadPart / 10000000);
    if (second != g_Telemetry.WriteSecond) {
        g_Telemetry.WriteSecond = second;
        g_Telemetry.WriteBudget = MP_TELEMETRY_WRITE_BUDGET;
    }
    if (InterlockedDecrement(&g_Telemetry.WriteBudget) < 0) {
        InterlockedIncrement(&g_Telemetry.WriteSkipped);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    MpTelemetryEmitCurrentFile(Data, MP_TELEMETRY_EVENT_FILE_WRITE, 0,
                               length);
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

static
FLT_PREOP_CALLBACK_STATUS
MpTelemetryPreCleanup(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext)
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);

    MpTelemetryEmitCurrentFile(Data, MP_TELEMETRY_EVENT_FILE_CLOSE, 0, 0);
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

static
FLT_PREOP_CALLBACK_STATUS
MpTelemetryPreSetInformation(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext)
{
    FILE_INFORMATION_CLASS infoClass;
    PVOID infoBuffer;
    ULONG infoLength;

    UNREFERENCED_PARAMETER(CompletionContext);

    if (InterlockedCompareExchange(&g_Telemetry.Active, 0, 0) == 0 ||
        g_Telemetry.ClientPort == NULL) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }
    if (MpTelemetryRequestorPid(Data) == 0) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    infoClass = Data->Iopb->Parameters.SetFileInformation.FileInformationClass;
    infoBuffer = Data->Iopb->Parameters.SetFileInformation.InfoBuffer;
    infoLength = Data->Iopb->Parameters.SetFileInformation.Length;

    if (infoBuffer == NULL) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    if (infoClass == FileRenameInformation ||
        infoClass == FileRenameInformationEx) {
        PFLT_FILE_NAME_INFORMATION oldInfo = NULL;
        PFLT_FILE_NAME_INFORMATION newInfo = NULL;
        PFILE_RENAME_INFORMATION rename = (PFILE_RENAME_INFORMATION)infoBuffer;
        ULONG required;
        NTSTATUS status;

        if (infoLength < (ULONG)FIELD_OFFSET(FILE_RENAME_INFORMATION,
                                              FileName)) {
            return FLT_PREOP_SUCCESS_NO_CALLBACK;
        }
        required = (ULONG)FIELD_OFFSET(FILE_RENAME_INFORMATION, FileName) +
                   rename->FileNameLength;
        if (rename->FileNameLength == 0 || infoLength < required) {
            return FLT_PREOP_SUCCESS_NO_CALLBACK;
        }

        status = FltGetFileNameInformation(
            Data,
            FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT,
            &oldInfo);
        if (!NT_SUCCESS(status)) {
            oldInfo = NULL;
        }

        status = FltGetDestinationFileNameInformation(
            FltObjects->Instance,
            Data->Iopb->Parameters.SetFileInformation.ParentOfTarget,
            rename->RootDirectory,
            rename->FileName,
            rename->FileNameLength,
            FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT,
            &newInfo);
        if (!NT_SUCCESS(status)) {
            newInfo = NULL;
        }

        if (oldInfo != NULL && newInfo != NULL) {
            (void)MpTelemetrySendEvent(
                MpTelemetryRequestorPid(Data),
                MP_TELEMETRY_EVENT_FILE_RENAME, 0, 0, 0, 0, 0, 0,
                oldInfo->Name.Buffer,
                oldInfo->Name.Length / sizeof(WCHAR),
                newInfo->Name.Buffer,
                newInfo->Name.Length / sizeof(WCHAR));
        } else {
            /* Destination name unavailable: still report the change so the
             * consumer can invalidate its dirty-path cache. */
            MpTelemetryEmitCurrentFile(Data,
                                       MP_TELEMETRY_EVENT_FILE_SET_INFO,
                                       0, 0);
        }

        if (oldInfo != NULL) {
            FltReleaseFileNameInformation(oldInfo);
        }
        if (newInfo != NULL) {
            FltReleaseFileNameInformation(newInfo);
        }
    } else if (infoClass == FileDispositionInformation) {
        if (infoLength >= sizeof(FILE_DISPOSITION_INFORMATION) &&
            ((PFILE_DISPOSITION_INFORMATION)infoBuffer)->DeleteFile) {
            MpTelemetryEmitCurrentFile(Data,
                                       MP_TELEMETRY_EVENT_FILE_DELETE,
                                       0, 0);
        }
    } else if (infoClass == FileDispositionInformationEx) {
        if (infoLength >= sizeof(FILE_DISPOSITION_INFORMATION_EX) &&
            (((PFILE_DISPOSITION_INFORMATION_EX)infoBuffer)->Flags &
             FILE_DISPOSITION_DELETE) != 0) {
            MpTelemetryEmitCurrentFile(Data,
                                       MP_TELEMETRY_EVENT_FILE_DELETE,
                                       0, 0);
        }
    } else if (infoClass == FileEndOfFileInformation ||
               infoClass == FileAllocationInformation ||
               infoClass == FileValidDataLengthInformation) {
        MpTelemetryEmitCurrentFile(Data, MP_TELEMETRY_EVENT_FILE_SET_INFO,
                                   0, 0);
    }

    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

static
FLT_PREOP_CALLBACK_STATUS
MpTelemetryPreSetSecurity(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext)
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);

    MpTelemetryEmitCurrentFile(Data, MP_TELEMETRY_EVENT_FILE_SET_SECURITY,
                               0, 0);
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}
