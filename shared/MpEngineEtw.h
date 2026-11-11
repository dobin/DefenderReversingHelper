/*
 * MpEngineEtw.h -- shared ETW/TraceLogging contract.
 *
 * Producer: dll_injector\detours_payload\MpEngineHook.c
 * Consumer: tools\etw_listener\RSignalEtwListener.cpp
 *
 * Both sides must agree on the provider identity and on the event field
 * names/types. Keep the C GUID tuple and the GUID string in sync; the string
 * is what the consumer passes to krabsetw.
 */
#ifndef MPENGINE_ETW_H
#define MPENGINE_ETW_H

/* TraceLogging provider identity. */
#define MPENGINE_ETW_PROVIDER_NAME "DefenderReversingHelper-MpEngineRSignal"
#define MPENGINE_ETW_PROVIDER_GUID_STRING \
    L"{9F2C5A64-3E8B-4D71-A0C6-5B7E4F1D2A93}"
#define MPENGINE_ETW_PROVIDER_GUID \
    (0x9F2C5A64, 0x3E8B, 0x4D71, 0xA0, 0xC6, 0x5B, 0x7E, 0x4F, 0x1D, 0x2A, 0x93)

/* Real-time trace session created by the listener. */
#define MPENGINE_ETW_SESSION_NAME \
    L"DefenderReversingHelper-MpEngineRSignal"

/* Event names, used only for display; the "Type" field is authoritative. */
#define MPENGINE_ETW_EVENT_CALL   "RSignalCall"
#define MPENGINE_ETW_EVENT_RETURN "RSignalReturn"
#define MPENGINE_ETW_EVENT_STATUS "Status"

/* Value of the first field ("Type") of every event. */
#define MPENGINE_ETW_TYPE_CALL   1u
#define MPENGINE_ETW_TYPE_RETURN 2u
#define MPENGINE_ETW_TYPE_STATUS 3u

/*
 * Field names, for reference:
 *
 *   RSignalCall   Type(UInt32) SeqNum(UInt32) Signal(Int32) Flags(Int32)
 *                 ContextAddress(UInt64) DataAddress(UInt64)
 *                 ContextLength(UInt32) DataLength(UInt32)
 *                 ContextHex(String) DataHex(String)
 *
 *   RSignalReturn Type(UInt32) SeqNum(UInt32) Status(UInt32)
 *
 *   Status        Type(UInt32) SeqNum(UInt32) Code(UInt32) Message(String)
 *
 * ContextHex/DataHex are uppercase hex text (two characters per captured
 * byte). Hex travels as a plain string so any consumer decodes the same bytes
 * without dealing with TraceLogging binary length prefixes.
 */

#endif /* MPENGINE_ETW_H */
