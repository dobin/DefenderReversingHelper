/*
 * PplDriver.h
 * ---------------------------------------------------------------------------
 * Driver-wide teardown shared by the minifilter unload callback and by
 * DriverUnload.
 *
 * Deliberately free of fltkernel.h: MakeMePPL.c includes ntddk.h first and the
 * two headers conflict in this WDK.
 * ---------------------------------------------------------------------------
 */
#ifndef PPL_DRIVER_H
#define PPL_DRIVER_H

#ifdef __cplusplus
extern "C" {
#endif

/* Stop the telemetry minifilter and process callback, drain deferred work,
 * restore tracked protections and remove the control device.  Safe to call
 * more than once; only the first call does the work. */
VOID PplDriverTeardown(VOID);

#ifdef __cplusplus
}
#endif

#endif /* PPL_DRIVER_H */
