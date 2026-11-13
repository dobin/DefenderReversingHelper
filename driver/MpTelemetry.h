/*
 * MpTelemetry.h
 * ---------------------------------------------------------------------------
 * Kernel-side WdFilter-style telemetry source inside MakeMePPL.sys.
 *
 * The source is a minifilter plus a process-creation callback.  It sends
 * fixed-layout messages to a single user-mode client through a filter-manager
 * communication port.  Initialisation is best effort: a failure here must
 * leave the PPL/injection features of the driver working.
 * ---------------------------------------------------------------------------
 */
#ifndef MP_TELEMETRY_DRIVER_H
#define MP_TELEMETRY_DRIVER_H

/* fltkernel.h/ntifs.h must win over ntddk.h; including both redefines
 * PEPROCESS/PETHREAD in this WDK. */
#if !defined(_NTDDK_) && !defined(_NTIFS_)
#include <ntddk.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

/* Register the minifilter, create the communication port and start filtering.
 * Returns STATUS_SUCCESS when the telemetry source is active.  A failure is
 * non-fatal for the rest of the driver. */
NTSTATUS MpTelemetryInitialize(_In_ PDRIVER_OBJECT DriverObject);

/* Stop callbacks, disconnect the client and unregister the minifilter.
 * Safe to call when initialisation failed. */
VOID MpTelemetryShutdown(VOID);

/* Diagnostics used by PPL_GET_INFO and DbgPrint. */
BOOLEAN MpTelemetryIsActive(VOID);
ULONG MpTelemetryClientProcessId(VOID);
LONG64 MpTelemetryDropped(VOID);
LONG64 MpTelemetryWriteSkipped(VOID);
LONG64 MpTelemetrySendFailures(VOID);
NTSTATUS MpTelemetryInitializeStatus(VOID);
ULONG MpTelemetryInitializeStage(VOID);

#ifdef __cplusplus
}
#endif

#endif /* MP_TELEMETRY_DRIVER_H */
