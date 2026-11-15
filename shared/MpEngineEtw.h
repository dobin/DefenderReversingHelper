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
#define MPENGINE_ETW_EVENT_CALL       "RSignalCall"
#define MPENGINE_ETW_EVENT_RETURN     "RSignalReturn"
#define MPENGINE_ETW_EVENT_STATUS     "Status"
#define MPENGINE_ETW_EVENT_ENGINE_LOG "EngineLog"
#define MPENGINE_ETW_EVENT_TRACE      "EngineTrace"

/* Value of the first field ("Type") of every event. */
#define MPENGINE_ETW_TYPE_CALL       1u
#define MPENGINE_ETW_TYPE_RETURN     2u
#define MPENGINE_ETW_TYPE_STATUS     3u
#define MPENGINE_ETW_TYPE_ENGINE_LOG 4u
#define MPENGINE_ETW_TYPE_TRACE      5u

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
 *   EngineLog     Type(UInt32) SeqNum(UInt32) Kind(UInt32) Level(UInt32)
 *                 Module(String) Message(String)
 *
 *   EngineTrace   Type(UInt32) SeqNum(UInt32) Kind(UInt32) EngineTime(UInt64)
 *                 Opcode(UInt32) Flags(UInt32) Version(UInt32) Id(UInt32)
 *                 KindName(String) Target(String) PayloadLength(UInt32)
 *                 PayloadHex(String)
 *
 * EngineLog carries the engine's own diagnostic lines (module "Engine",
 * "Engine-HIPS", ...) captured from the trace callback in the engine instance,
 * not from the WPP/TraceMessage path.  Kind is the engine record kind
 * (0x19 = text log); Level is the engine's own level for that line.
 *
 * EngineTrace carries the structured records handed to the same callback.
 * Kind 0x28 is a host work item (deferred scan request): Opcode is 0x22 for a
 * scan, Flags/Version/Id come from the work payload, KindName is L"ems" /
 * L"process" and Target is the engine's target expression.  For other kinds
 * (0x18/0x1C/0x1E/0x20/0x46/0x4C/0x62 telemetry) the decoded fields are zero
 * and PayloadHex is a bounded hex copy of the payload for offline decoding.
 * PayloadHex is uppercase hex text, like ContextHex/DataHex.
 *
 * ContextHex/DataHex are uppercase hex text (two characters per captured
 * byte). Hex travels as a plain string so any consumer decodes the same bytes
 * without dealing with TraceLogging binary length prefixes.
 */

#endif /* MPENGINE_ETW_H */
