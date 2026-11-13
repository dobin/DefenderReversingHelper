/*
 * MpTelemetryInternal.h
 * ---------------------------------------------------------------------------
 * Private state shared by the driver telemetry source and its file callbacks.
 * ---------------------------------------------------------------------------
 */
#ifndef MP_TELEMETRY_INTERNAL_H
#define MP_TELEMETRY_INTERNAL_H

#include <fltkernel.h>

#include "../shared/MpTelemetry.h"

#ifdef __cplusplus
extern "C" {
#endif

#define MP_TELEMETRY_WRITE_BUDGET 8192

/* Maximum time a single FltSendMessage may wait for the consumer.  Telemetry
 * is best effort and the send runs inside file/process callbacks: if the
 * consumer stops reading (crashed worker, suspended process, debugger) an
 * unbounded wait would stall every I/O on the volume.  Events that cannot be
 * delivered in this window are dropped and counted. */
#define MP_TELEMETRY_SEND_TIMEOUT_MS 100

/* After repeated send timeouts the consumer is not draining.  Drop events
 * without waiting for this long before probing again: otherwise every single
 * I/O would pay one full timeout while a consumer is stuck but still
 * connected. */
#define MP_TELEMETRY_SEND_TIMEOUTS_BEFORE_COOLDOWN 2
#define MP_TELEMETRY_SEND_COOLDOWN_MS 500

typedef struct _MP_TELEMETRY_STATE {
    PFLT_FILTER       Filter;
    PFLT_PORT         ServerPort;
    PFLT_PORT         ClientPort;
    ULONG             ClientProcessId;
    ERESOURCE         PortLock;
    BOOLEAN           PortLockReady;
    volatile LONG     Active;
    volatile LONG     NotifyRegistered;
    volatile LONG64   Sequence;
    volatile LONG     Dropped;            /* send path only (timeout/cooldown/IRQL) */
    volatile LONG     WriteSkipped;       /* write budget exhausted */
    volatile LONG     SendFailures;
    volatile LONG     WriteBudget;
    volatile LONG     WriteSecond;
    volatile LONG64   SendCooldownUntil;   /* KeQueryInterruptTime units */
    volatile LONG     SendTimeouts;        /* consecutive timeouts */
    NTSTATUS          InitializeStatus;
    ULONG             InitializeStage;
} MP_TELEMETRY_STATE;

extern MP_TELEMETRY_STATE g_Telemetry;

/* Registration table lives with the minifilter callbacks. */
const FLT_REGISTRATION *MpTelemetryFilterRegistration(VOID);

/* Shared event builder (MpTelemetry.c). */
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
    _In_ ULONG TargetChars);

/* Requestor filtering and the single-name file event helper. */
ULONG MpTelemetryRequestorPid(_In_ PFLT_CALLBACK_DATA Data);

VOID
MpTelemetryEmitCurrentFileEx(
    _In_ PFLT_CALLBACK_DATA Data,
    _In_ ULONG EventId,
    _In_ ULONG Flags,
    _In_ ULONG Extra,
    _In_ ULONG CreateOptions,
    _In_ ULONG FileAttributes);

VOID
MpTelemetryEmitCurrentFile(
    _In_ PFLT_CALLBACK_DATA Data,
    _In_ ULONG EventId,
    _In_ ULONG Flags,
    _In_ ULONG Extra);

#ifdef __cplusplus
}
#endif

#endif /* MP_TELEMETRY_INTERNAL_H */
