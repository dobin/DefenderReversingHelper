/*
 * MpTelemetry.c
 * ---------------------------------------------------------------------------
 * WdFilter-style kernel telemetry source for MakeMePPL.sys.
 *
 * WdFilter.sys creates filter-manager communication ports and sends
 * file/process events to MpRtp.dll with FltSendMessage().  This implements the
 * same shape for this project:
 *
 *   MakeMePPL.sys (minifilter + process callback)
 *        |  FltCreateCommunicationPort(\MpEngineTelemetryPort)
 *        |  FltSendMessage(MP_TELEMETRY_EVENT)
 *        v
 *   mpengine_client.exe agent (FilterGetMessage loop)
 *        |  mp_rtp_note_* + 0x4039
 *        v
 *   mpengine.dll behaviour monitor
 *
 * This file owns the state, send path, process callback, port callbacks and
 * lifecycle.  The minifilter operation callbacks are in MpTelemetryFile.c.
 * Initialisation is best effort: a failure here must leave the PPL and
 * injection features working.
 * ---------------------------------------------------------------------------
 */
#include <fltkernel.h>

#include "../shared/MpTelemetry.h"
#include "MpTelemetryInternal.h"
#include "MpTelemetry.h"
#include "PplLog.h"

MP_TELEMETRY_STATE g_Telemetry;

/*
 * The port is created with a DACL that allows any local user, matching the
 * rest of this test driver (the control device uses the same policy).  Only
 * one client can connect at a time (MaxConnections = 1).
 */
static SECURITY_DESCRIPTOR g_PortSecurityDescriptor;
static ACL                g_PortAcl[8];
static SID                g_WorldSid = {
    SID_REVISION,
    1,
    { 0, 0, 0, 0, 0, 1 },
    { SECURITY_WORLD_RID }
};

VOID
MpTelemetryProcessNotify(
    _Inout_ PEPROCESS Process,
    _In_ HANDLE ProcessId,
    _Inout_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo);

/* ------------------------------------------------------------------------- */
/* Send path                                                                 */
/* ------------------------------------------------------------------------- */

static
NTSTATUS
MpTelemetrySend(
    _In_reads_bytes_(Size) const VOID *Buffer,
    _In_ ULONG Size)
{
    NTSTATUS status;
    PFLT_PORT port;
    LARGE_INTEGER timeout;
    ULONG64 now;
    BOOLEAN canBlock;

    if (KeGetCurrentIrql() > APC_LEVEL) {
        InterlockedIncrement(&g_Telemetry.Dropped);
        return STATUS_INVALID_DEVICE_STATE;
    }
    if (Buffer == NULL || Size == 0 || Size > MP_TELEMETRY_MESSAGE_MAX) {
        return STATUS_INVALID_PARAMETER;
    }
    if (g_Telemetry.Filter == NULL || !g_Telemetry.PortLockReady) {
        return STATUS_PORT_DISCONNECTED;
    }

    /* A consumer that timed out recently is not draining: skip the wait
     * instead of charging every caller a full timeout.  The short cooldown
     * re-probes often enough to notice a consumer that recovered. */
    now = KeQueryInterruptTime();
    if (now < (ULONG64)InterlockedCompareExchange64(
                  &g_Telemetry.SendCooldownUntil, 0, 0)) {
        InterlockedIncrement(&g_Telemetry.Dropped);
        return STATUS_RETRY;
    }

    /* FltSendMessage allows IRQL <= APC_LEVEL.  At APC we must not block on
     * the port resource, so use a non-waiting acquire there. */
    canBlock = (KeGetCurrentIrql() == PASSIVE_LEVEL);
    if (canBlock) {
        ExAcquireResourceSharedLite(&g_Telemetry.PortLock, TRUE);
        /* Negative values are relative to the current time. */
        timeout.QuadPart =
            -(LONGLONG)MP_TELEMETRY_SEND_TIMEOUT_MS * 10000;
    } else if (!ExAcquireResourceSharedLite(&g_Telemetry.PortLock, FALSE)) {
        InterlockedIncrement(&g_Telemetry.Dropped);
        return STATUS_RETRY;
    } else {
        /* Zero means "do not wait": blocking is illegal at APC_LEVEL. */
        timeout.QuadPart = 0;
    }
    port = g_Telemetry.ClientPort;
    if (port == NULL) {
        ExReleaseResourceLite(&g_Telemetry.PortLock);
        return STATUS_PORT_DISCONNECTED;
    }

    /* No reply buffer: fire-and-forget telemetry, the same shape WdFilter
     * uses on its normal and very-low-I/O ports.  The timeout is what keeps a
     * dead or stalled consumer from wedging the filesystem. */
    status = FltSendMessage(g_Telemetry.Filter, &port, (PVOID)Buffer, Size,
                            NULL, NULL, &timeout);

    ExReleaseResourceLite(&g_Telemetry.PortLock);

    if (status == STATUS_TIMEOUT) {
        /* STATUS_TIMEOUT is a success code but the message was not consumed.
         * Only the waiting (PASSIVE) path is evidence that the consumer is
         * stuck; the APC path uses a zero timeout by design. */
        InterlockedIncrement(&g_Telemetry.Dropped);
        if (canBlock &&
            InterlockedIncrement(&g_Telemetry.SendTimeouts) >=
                MP_TELEMETRY_SEND_TIMEOUTS_BEFORE_COOLDOWN) {
            InterlockedExchange(&g_Telemetry.SendTimeouts, 0);
            InterlockedExchange64(
                &g_Telemetry.SendCooldownUntil,
                (LONG64)(now + (ULONG64)MP_TELEMETRY_SEND_COOLDOWN_MS *
                                   10000));
        }
    } else {
        if (NT_SUCCESS(status)) {
            InterlockedExchange(&g_Telemetry.SendTimeouts, 0);
        } else {
            InterlockedIncrement(&g_Telemetry.SendFailures);
        }
    }
    return status;
}

NTSTATUS
MpTelemetrySendEvent(
    _In_ ULONG ProcessId,
    _In_ ULONG EventId,
    _In_ ULONG Flags,
    _In_ ULONG ParentProcessId,
    _In_ ULONG CreateOptions,
    _In_ ULONG FileAttributes,
    _In_ ULONG Extra,
    _In_ UINT64 CreateTime,
    _In_reads_opt_(NameChars) const WCHAR *Name,
    _In_ ULONG NameChars,
    _In_reads_opt_(TargetChars) const WCHAR *Target,
    _In_ ULONG TargetChars)
{
    UINT8 buffer[MP_TELEMETRY_MESSAGE_MAX];
    MP_TELEMETRY_EVENT *message = (MP_TELEMETRY_EVENT *)buffer;
    PWCHAR cursor;
    ULONG size;
    LARGE_INTEGER now;

    if (Name == NULL) {
        NameChars = 0;
    }
    if (Target == NULL) {
        TargetChars = 0;
    }
    if (NameChars > MP_TELEMETRY_NAME_CHARS - 1) {
        NameChars = MP_TELEMETRY_NAME_CHARS - 1;
    }
    if (TargetChars > MP_TELEMETRY_NAME_CHARS - 1) {
        TargetChars = MP_TELEMETRY_NAME_CHARS - 1;
    }

    size = FIELD_OFFSET(MP_TELEMETRY_EVENT, Data);
    if ((size + (NameChars + 1 + TargetChars + 1) * sizeof(WCHAR)) >
        sizeof(buffer)) {
        return STATUS_BUFFER_OVERFLOW;
    }

    RtlZeroMemory(message, size);
    KeQuerySystemTime(&now);

    message->Header.Size      = size;
    message->Header.Version   = MP_TELEMETRY_VERSION;
    message->Header.Type      = MP_TELEMETRY_TYPE_EVENT;
    message->Header.ProcessId = ProcessId;
    message->Header.ThreadId  = (ULONG)(ULONG_PTR)PsGetCurrentThreadId();
    message->Header.Event     = EventId;
    message->Header.Flags     = Flags;
    message->Header.Sequence  =
        (UINT64)InterlockedIncrement64(&g_Telemetry.Sequence);
    message->Header.Timestamp = (UINT64)now.QuadPart;

    message->NameChars       = NameChars;
    message->TargetChars     = TargetChars;
    message->CreateOptions   = CreateOptions;
    message->FileAttributes  = FileAttributes;
    message->ParentProcessId = ParentProcessId;
    message->SubEvent        = Extra;
    message->CreateTime      = CreateTime;
    message->FileId          = 0;

    cursor = message->Data;
    if (NameChars != 0) {
        RtlCopyMemory(cursor, Name, (SIZE_T)NameChars * sizeof(WCHAR));
        cursor += NameChars;
    }
    *cursor++ = L'\0';
    if (TargetChars != 0) {
        RtlCopyMemory(cursor, Target, (SIZE_T)TargetChars * sizeof(WCHAR));
        cursor += TargetChars;
    }
    *cursor++ = L'\0';

    size = (ULONG)((PUCHAR)cursor - buffer);
    message->Header.Size = size;
    return MpTelemetrySend(buffer, size);
}

ULONG
MpTelemetryRequestorPid(
    _In_ PFLT_CALLBACK_DATA Data)
{
    ULONG pid = FltGetRequestorProcessId(Data);

    if (pid == 0 || pid == 4) {
        return 0;
    }
    if (pid == g_Telemetry.ClientProcessId) {
        return 0;
    }
    return pid;
}

/*
 * Process creation time of the acting process.
 *
 * The engine resolves a note's process with an exact {creation time, pid}
 * lookup in its ProcessInfoMap, and
 * Defender's MpRtp stamps the FILETIME on every note it builds with
 * GetProcessTimes.  A zero here does not match anything, so the file event
 * would be dropped or evaluated against an unknown process.
 *
 * The requestor is normally the current process, which needs no lookup.  A
 * foreign requestor only occurs for I/O issued by a worker thread on behalf of
 * another process; PsLookupProcessByProcessId is used then, but only at
 * PASSIVE_LEVEL (it may block) -- above that the event keeps 0.
 */
UINT64
MpTelemetryProcessCreateTime(
    _In_ ULONG ProcessId)
{
    PEPROCESS process = NULL;
    UINT64 createTime;

    if (ProcessId == 0) {
        return 0;
    }
    if (ProcessId == (ULONG)(ULONG_PTR)PsGetCurrentProcessId()) {
        return (UINT64)PsGetProcessCreateTimeQuadPart(PsGetCurrentProcess());
    }
    if (KeGetCurrentIrql() > PASSIVE_LEVEL) {
        return 0;
    }
    if (!NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)ProcessId,
                                               &process))) {
        return 0;
    }
    createTime = (UINT64)PsGetProcessCreateTimeQuadPart(process);
    ObDereferenceObject(process);
    return createTime;
}

VOID
MpTelemetryEmitCurrentFileEx(
    _In_ PFLT_CALLBACK_DATA Data,
    _In_ ULONG EventId,
    _In_ ULONG Flags,
    _In_ ULONG Extra,
    _In_ ULONG CreateOptions,
    _In_ ULONG FileAttributes)
{
    PFLT_FILE_NAME_INFORMATION info = NULL;
    NTSTATUS status;
    ULONG pid;

    if (InterlockedCompareExchange(&g_Telemetry.Active, 0, 0) == 0) {
        return;
    }
    if (KeGetCurrentIrql() > APC_LEVEL) {
        return;
    }
    pid = MpTelemetryRequestorPid(Data);
    if (pid == 0) {
        return;
    }

    status = FltGetFileNameInformation(
        Data,
        FLT_FILE_NAME_NORMALIZED |
            (KeGetCurrentIrql() == PASSIVE_LEVEL
                 ? FLT_FILE_NAME_QUERY_DEFAULT
                 : FLT_FILE_NAME_QUERY_CACHE_ONLY),
        &info);
    if (!NT_SUCCESS(status) || info == NULL) {
        return;
    }

    (void)MpTelemetrySendEvent(pid, EventId, Flags, 0, CreateOptions,
                               FileAttributes, Extra,
                               MpTelemetryProcessCreateTime(pid),
                               info->Name.Buffer,
                               info->Name.Length / sizeof(WCHAR), NULL, 0);
    FltReleaseFileNameInformation(info);
}

VOID
MpTelemetryEmitCurrentFile(
    _In_ PFLT_CALLBACK_DATA Data,
    _In_ ULONG EventId,
    _In_ ULONG Flags,
    _In_ ULONG Extra)
{
    MpTelemetryEmitCurrentFileEx(Data, EventId, Flags, Extra, 0, 0);
}

/* ------------------------------------------------------------------------- */
/* Process creation callback                                                 */
/* ------------------------------------------------------------------------- */

VOID
MpTelemetryProcessNotify(
    _Inout_ PEPROCESS Process,
    _In_ HANDLE ProcessId,
    _Inout_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo)
{
    ULONG pid = (ULONG)(ULONG_PTR)ProcessId;
    ULONG parentPid = 0;
    ULONG nameChars = 0;
    UINT64 createTime = 0;
    const WCHAR *name = NULL;

    if (InterlockedCompareExchange(&g_Telemetry.Active, 0, 0) == 0 ||
        g_Telemetry.ClientPort == NULL) {
        return;
    }
    if (pid == 0 || pid == 4 || pid == g_Telemetry.ClientProcessId) {
        return;
    }
    if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
        return;
    }

    if (CreateInfo == NULL) {
        (void)MpTelemetrySendEvent(pid, MP_TELEMETRY_EVENT_PROCESS_EXIT, 0,
                                   0, 0, 0, 0, 0, NULL, 0, NULL, 0);
        return;
    }

    parentPid = (ULONG)(ULONG_PTR)CreateInfo->ParentProcessId;
    if (CreateInfo->ImageFileName != NULL &&
        CreateInfo->ImageFileName->Buffer != NULL) {
        name = CreateInfo->ImageFileName->Buffer;
        nameChars = CreateInfo->ImageFileName->Length / sizeof(WCHAR);
        if (nameChars > MP_TELEMETRY_NAME_CHARS - 1) {
            nameChars = MP_TELEMETRY_NAME_CHARS - 1;
        }
    }

    createTime = (UINT64)PsGetProcessCreateTimeQuadPart(Process);
    (void)MpTelemetrySendEvent(pid, MP_TELEMETRY_EVENT_PROCESS_CREATE, 0,
                               parentPid, 0, 0, 0, createTime,
                               name, nameChars, NULL, 0);
}

/* ------------------------------------------------------------------------- */
/* Port callbacks                                                            */
/* ------------------------------------------------------------------------- */

static
NTSTATUS
MpTelemetryConnect(
    _In_ PFLT_PORT ClientPort,
    _In_opt_ PVOID ServerPortCookie,
    _In_reads_bytes_opt_(SizeOfContext) PVOID ConnectionContext,
    _In_ ULONG SizeOfContext,
    _Outptr_result_maybenull_ PVOID *ConnectionPortCookie)
{
    UNREFERENCED_PARAMETER(ServerPortCookie);
    UNREFERENCED_PARAMETER(ConnectionContext);
    UNREFERENCED_PARAMETER(SizeOfContext);

    if (ClientPort == NULL || ConnectionPortCookie == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    ExAcquireResourceExclusiveLite(&g_Telemetry.PortLock, TRUE);
    g_Telemetry.ClientPort = ClientPort;
    g_Telemetry.ClientProcessId = (ULONG)(ULONG_PTR)PsGetCurrentProcessId();
    *ConnectionPortCookie = ClientPort;
    ExReleaseResourceLite(&g_Telemetry.PortLock);

    PPL_LOG("telemetry client connected (pid %lu)",
            g_Telemetry.ClientProcessId);
    return STATUS_SUCCESS;
}

static
NTSTATUS
MpTelemetryDisconnect(
    _In_opt_ PVOID ClientPortCookie)
{
    PFLT_PORT port = (PFLT_PORT)ClientPortCookie;
    BOOLEAN closeIt = FALSE;

    if (g_Telemetry.PortLockReady) {
        ExAcquireResourceExclusiveLite(&g_Telemetry.PortLock, TRUE);
        if (g_Telemetry.ClientPort == port) {
            g_Telemetry.ClientPort = NULL;
            g_Telemetry.ClientProcessId = 0;
            closeIt = TRUE;
        }
        ExReleaseResourceLite(&g_Telemetry.PortLock);
    }

    if (closeIt && g_Telemetry.Filter != NULL) {
        FltCloseClientPort(g_Telemetry.Filter, &port);
    }
    PPL_LOG("telemetry client disconnected");
    return STATUS_SUCCESS;
}

static
NTSTATUS
MpTelemetryMessage(
    _In_opt_ PVOID ClientPortCookie,
    _In_reads_bytes_opt_(InputBufferLength) PVOID InputBuffer,
    _In_ ULONG InputBufferLength,
    _Out_writes_bytes_to_opt_(OutputBufferLength, *ReturnOutputBufferLength)
        PVOID OutputBuffer,
    _In_ ULONG OutputBufferLength,
    _Out_ PULONG ReturnOutputBufferLength)
{
    MP_TELEMETRY_HELLO hello;
    MP_TELEMETRY_HELLO_REPLY reply;

    UNREFERENCED_PARAMETER(ClientPortCookie);

    if (ReturnOutputBufferLength == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *ReturnOutputBufferLength = 0;

    if (InputBuffer == NULL || InputBufferLength < sizeof(MP_TELEMETRY_HELLO)) {
        return STATUS_INVALID_PARAMETER;
    }

    __try {
        RtlCopyMemory(&hello, InputBuffer, sizeof(hello));
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return STATUS_INVALID_PARAMETER;
    }

    if (hello.Type != MP_TELEMETRY_TYPE_HELLO) {
        return STATUS_INVALID_PARAMETER;
    }
    if (hello.Version != MP_TELEMETRY_VERSION) {
        return STATUS_REVISION_MISMATCH;
    }
    if (OutputBuffer == NULL ||
        OutputBufferLength < sizeof(MP_TELEMETRY_HELLO_REPLY)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    RtlZeroMemory(&reply, sizeof(reply));
    reply.Size          = sizeof(reply);
    reply.Version       = MP_TELEMETRY_VERSION;
    reply.Type          = MP_TELEMETRY_TYPE_HELLO_REPLY;
    reply.MaxMessage    = MP_TELEMETRY_MESSAGE_MAX;
    reply.Flags         = 0;
    reply.DriverVersion = (UINT64)MP_TELEMETRY_VERSION;

    __try {
        RtlCopyMemory(OutputBuffer, &reply, sizeof(reply));
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return STATUS_INVALID_PARAMETER;
    }
    *ReturnOutputBufferLength = sizeof(reply);
    return STATUS_SUCCESS;
}

/* ------------------------------------------------------------------------- */
/* Lifecycle                                                                 */
/* ------------------------------------------------------------------------- */

static
NTSTATUS
MpTelemetryBuildSecurityDescriptor(
    _Out_ PSECURITY_DESCRIPTOR *Descriptor)
{
    NTSTATUS status;

    *Descriptor = NULL;

    RtlZeroMemory(&g_PortSecurityDescriptor,
                  sizeof(g_PortSecurityDescriptor));
    RtlZeroMemory(g_PortAcl, sizeof(g_PortAcl));

    status = RtlCreateSecurityDescriptor(&g_PortSecurityDescriptor,
                                         SECURITY_DESCRIPTOR_REVISION);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    status = RtlCreateAcl(g_PortAcl, sizeof(g_PortAcl), ACL_REVISION);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    status = RtlAddAccessAllowedAce(g_PortAcl, ACL_REVISION,
                                    FLT_PORT_ALL_ACCESS, &g_WorldSid);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    status = RtlSetDaclSecurityDescriptor(&g_PortSecurityDescriptor, TRUE,
                                          g_PortAcl, FALSE);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    *Descriptor = &g_PortSecurityDescriptor;
    return STATUS_SUCCESS;
}

NTSTATUS
MpTelemetryInitialize(
    _In_ PDRIVER_OBJECT DriverObject)
{
    NTSTATUS status;
    UNICODE_STRING portName;
    OBJECT_ATTRIBUTES portAttributes;
    PSECURITY_DESCRIPTOR portSecurity = NULL;

    RtlZeroMemory(&g_Telemetry, sizeof(g_Telemetry));
    g_Telemetry.InitializeStatus = STATUS_UNSUCCESSFUL;
    g_Telemetry.InitializeStage = 1;
    status = ExInitializeResourceLite(&g_Telemetry.PortLock);
    if (!NT_SUCCESS(status)) {
        g_Telemetry.InitializeStatus = status;
        PPL_LOG("telemetry: ExInitializeResourceLite failed: 0x%08X", status);
        return status;
    }
    g_Telemetry.PortLockReady = TRUE;

    g_Telemetry.InitializeStage = 2;
    status = FltRegisterFilter(DriverObject, MpTelemetryFilterRegistration(),
                               &g_Telemetry.Filter);
    if (!NT_SUCCESS(status)) {
        g_Telemetry.InitializeStatus = status;
        PPL_LOG("telemetry: FltRegisterFilter failed: 0x%08X "
                "(check the Instances/Altitude registry values)",
                status);
        ExDeleteResourceLite(&g_Telemetry.PortLock);
        g_Telemetry.PortLockReady = FALSE;
        return status;
    }

    g_Telemetry.InitializeStage = 3;
    status = MpTelemetryBuildSecurityDescriptor(&portSecurity);
    if (!NT_SUCCESS(status)) {
        g_Telemetry.InitializeStatus = status;
        PPL_LOG("telemetry: security descriptor failed: 0x%08X", status);
        FltUnregisterFilter(g_Telemetry.Filter);
        g_Telemetry.Filter = NULL;
        ExDeleteResourceLite(&g_Telemetry.PortLock);
        g_Telemetry.PortLockReady = FALSE;
        return status;
    }

    RtlInitUnicodeString(&portName, MP_TELEMETRY_PORT_NAME);
    InitializeObjectAttributes(&portAttributes, &portName,
                               OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
                               NULL, portSecurity);
    g_Telemetry.InitializeStage = 4;
    status = FltCreateCommunicationPort(
        g_Telemetry.Filter,
        &g_Telemetry.ServerPort,
        &portAttributes,
        NULL,
        MpTelemetryConnect,
        MpTelemetryDisconnect,
        MpTelemetryMessage,
        1);
    if (!NT_SUCCESS(status)) {
        g_Telemetry.InitializeStatus = status;
        PPL_LOG("telemetry: FltCreateCommunicationPort failed: 0x%08X",
                status);
        FltUnregisterFilter(g_Telemetry.Filter);
        g_Telemetry.Filter = NULL;
        ExDeleteResourceLite(&g_Telemetry.PortLock);
        g_Telemetry.PortLockReady = FALSE;
        return status;
    }

    g_Telemetry.InitializeStage = 5;
    status = FltStartFiltering(g_Telemetry.Filter);
    if (!NT_SUCCESS(status)) {
        g_Telemetry.InitializeStatus = status;
        PPL_LOG("telemetry: FltStartFiltering failed: 0x%08X "
                "(no volume instance attached)", status);
        FltCloseCommunicationPort(g_Telemetry.ServerPort);
        g_Telemetry.ServerPort = NULL;
        FltUnregisterFilter(g_Telemetry.Filter);
        g_Telemetry.Filter = NULL;
        ExDeleteResourceLite(&g_Telemetry.PortLock);
        g_Telemetry.PortLockReady = FALSE;
        return status;
    }

    InterlockedExchange(&g_Telemetry.Active, 1);
    g_Telemetry.InitializeStatus = STATUS_SUCCESS;
    g_Telemetry.InitializeStage = 6;

    status = PsSetCreateProcessNotifyRoutineEx(MpTelemetryProcessNotify,
                                               FALSE);
    if (!NT_SUCCESS(status)) {
        PPL_LOG("telemetry: process notify registration failed: 0x%08X",
                status);
    } else {
        InterlockedExchange(&g_Telemetry.NotifyRegistered, 1);
    }

    PPL_LOG("telemetry: active on port %wZ", &portName);
    return STATUS_SUCCESS;
}

VOID
MpTelemetryShutdown(VOID)
{
    PFLT_PORT client = NULL;

    if (g_Telemetry.PortLockReady == FALSE) {
        return;
    }

    InterlockedExchange(&g_Telemetry.Active, 0);

    if (InterlockedExchange(&g_Telemetry.NotifyRegistered, 0) != 0) {
        (VOID)PsSetCreateProcessNotifyRoutineEx(MpTelemetryProcessNotify,
                                                TRUE);
    }

    /* Exactly one side closes the client port: shutdown takes the handle and
     * clears the field first, so a later disconnect callback sees no match. */
    ExAcquireResourceExclusiveLite(&g_Telemetry.PortLock, TRUE);
    client = g_Telemetry.ClientPort;
    g_Telemetry.ClientPort = NULL;
    g_Telemetry.ClientProcessId = 0;
    ExReleaseResourceLite(&g_Telemetry.PortLock);

    if (client != NULL && g_Telemetry.Filter != NULL) {
        FltCloseClientPort(g_Telemetry.Filter, &client);
    }
    if (g_Telemetry.ServerPort != NULL) {
        FltCloseCommunicationPort(g_Telemetry.ServerPort);
        g_Telemetry.ServerPort = NULL;
    }
    if (g_Telemetry.Filter != NULL) {
        FltUnregisterFilter(g_Telemetry.Filter);
        g_Telemetry.Filter = NULL;
    }

    if (g_Telemetry.PortLockReady) {
        ExDeleteResourceLite(&g_Telemetry.PortLock);
        g_Telemetry.PortLockReady = FALSE;
    }
}

BOOLEAN
MpTelemetryIsActive(VOID)
{
    return InterlockedCompareExchange(&g_Telemetry.Active, 0, 0) != 0;
}

ULONG
MpTelemetryClientProcessId(VOID)
{
    return g_Telemetry.ClientProcessId;
}

LONG64
MpTelemetryDropped(VOID)
{
    return (LONG64)g_Telemetry.Dropped;
}

LONG64
MpTelemetryWriteSkipped(VOID)
{
    return (LONG64)g_Telemetry.WriteSkipped;
}

LONG64
MpTelemetrySendFailures(VOID)
{
    return (LONG64)g_Telemetry.SendFailures;
}

NTSTATUS
MpTelemetryInitializeStatus(VOID)
{
    return g_Telemetry.InitializeStatus;
}

ULONG
MpTelemetryInitializeStage(VOID)
{
    return g_Telemetry.InitializeStage;
}
