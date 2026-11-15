/*
 * MpTelemetry.h
 * ---------------------------------------------------------------------------
 * Wire protocol between the MakeMePPL minifilter telemetry source and a
 * user-mode consumer (mpclient's mpengine_client.exe agent).
 *
 * This is a clean-room protocol modelled on WdFilter.sys:
 *
 *   WdFilter.sys  --FltCreateCommunicationPort/FltSendMessage-->  MpRtp.dll
 *   MakeMePPL.sys --FltCreateCommunicationPort/FltSendMessage-->  agent
 *
 * The message is preceded by a FILTER_MESSAGE_HEADER when it is read with
 * FilterGetMessage(); that header is supplied by the filter manager and is
 * NOT part of this structure.  Every message starts with
 * MP_TELEMETRY_HEADER.Size so the consumer can find the real length (the
 * filter manager API does not report it).
 *
 * The header is shared by kernel and user mode.  Keep it free of C++ types
 * and of user-mode-only headers.
 * ---------------------------------------------------------------------------
 */
#ifndef MP_TELEMETRY_H
#define MP_TELEMETRY_H

#ifdef _KERNEL_MODE
#if !defined(_NTDDK_) && !defined(_NTIFS_)
#include <ntddk.h>
#endif
#else
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

/* Bump when the layout or event ids change.  The consumer rejects a port
 * whose hello reply reports a different version.
 *
 * v2 added the file metadata snapshot (MetadataFlags -> FileSize, file times,
 * FileId, attributes).  It is sampled inside the create/delete operation
 * callback, while the file still exists, so a short-lived file can still be
 * reported with its real size and timestamps. */
#define MP_TELEMETRY_VERSION        2u

/* Communication port object name.  Deliberately different from Defender's
 * \MicrosoftMalwareProtection*PortWD names so the two never collide. */
#define MP_TELEMETRY_PORT_NAME      L"\\MpEngineTelemetryPort"

/* Maximum number of UTF-16 characters per path, excluding the NUL.  This is
 * MAX_PATH plus room for \Device\HarddiskVolumeNN prefixes. */
#define MP_TELEMETRY_NAME_CHARS     520

/* Largest message this implementation can produce.  The consumer allocates
 * at least this much for FilterGetMessage. */
#define MP_TELEMETRY_MESSAGE_MAX    0x900u

/* Header.Type */
#define MP_TELEMETRY_TYPE_EVENT       1u
#define MP_TELEMETRY_TYPE_HELLO       2u
#define MP_TELEMETRY_TYPE_HELLO_REPLY 3u

/* Header.Event (telemetry event kind, not an mpengine note id).  Process
 * events carry ParentProcessId, and CreateTime is the process creation time
 * (for PROCESS_EXIT it is the key of the process that stopped; both derive
 * from the PEPROCESS in the notify callback). */
#define MP_TELEMETRY_EVENT_PROCESS_CREATE   0x0001u
#define MP_TELEMETRY_EVENT_PROCESS_EXIT     0x0002u
#define MP_TELEMETRY_EVENT_FILE_CREATE      0x0010u
#define MP_TELEMETRY_EVENT_FILE_WRITE       0x0011u
#define MP_TELEMETRY_EVENT_FILE_CLOSE       0x0012u
#define MP_TELEMETRY_EVENT_FILE_RENAME      0x0013u
#define MP_TELEMETRY_EVENT_FILE_DELETE      0x0014u
#define MP_TELEMETRY_EVENT_FILE_SET_INFO    0x0015u
#define MP_TELEMETRY_EVENT_FILE_SET_SECURITY 0x0016u

/* Header.Flags */
#define MP_TELEMETRY_FLAG_DIRECTORY       0x00000001u
#define MP_TELEMETRY_FLAG_PAGING_IO       0x00000002u
#define MP_TELEMETRY_FLAG_KERNEL_COALESCED 0x00000004u
#define MP_TELEMETRY_FLAG_WRITE_ACCESS    0x00000008u

/* CreateOptions high byte (the NtCreateFile disposition) values used by the
 * consumer to decide whether a create actually creates or overwrites. */
#define MP_TELEMETRY_DISPOSITION_SUPERSEDE    0u
#define MP_TELEMETRY_DISPOSITION_OPEN         1u
#define MP_TELEMETRY_DISPOSITION_CREATE       2u
#define MP_TELEMETRY_DISPOSITION_OPEN_IF      3u
#define MP_TELEMETRY_DISPOSITION_OVERWRITE    4u
#define MP_TELEMETRY_DISPOSITION_OVERWRITE_IF 5u

/* MetadataFlags: which of the metadata fields in MP_TELEMETRY_EVENT carry a
 * value.  The driver samples them in the operation callback (post-create for
 * a create/overwrite, pre-set-information for a delete) because the file can
 * be gone by the time the user-mode consumer processes the message. */
#define MP_TELEMETRY_META_SIZE        0x00000001u
#define MP_TELEMETRY_META_TIMES       0x00000002u  /* all four FILETIMEs  */
#define MP_TELEMETRY_META_FILE_ID     0x00000004u
#define MP_TELEMETRY_META_ATTRIBUTES  0x00000008u

typedef struct _MP_TELEMETRY_HEADER {
    ULONG       Size;       /* +0x00 total bytes, including this header   */
    USHORT      Version;    /* +0x04 MP_TELEMETRY_VERSION                 */
    USHORT      Type;       /* +0x06 MP_TELEMETRY_TYPE_*                  */
    ULONG       ProcessId;  /* +0x08 requestor process id                 */
    ULONG       ThreadId;   /* +0x0c requestor thread id                  */
    ULONG       Event;      /* +0x10 MP_TELEMETRY_EVENT_*                 */
    ULONG       Flags;      /* +0x14 MP_TELEMETRY_FLAG_*                  */
    UINT64      Sequence;   /* +0x18 monotonic per-driver sequence        */
    UINT64      Timestamp;  /* +0x20 KeQuerySystemTime (100ns since 1601) */
} MP_TELEMETRY_HEADER;      /* 0x28 bytes                                 */

/*
 * Event message.  Fixed fields are followed by NameChars UTF-16 characters
 * and a NUL, then (for a rename) TargetChars characters and a NUL.  The
 * declared Data[1] is only a convenience base pointer; Size is authoritative.
 */
typedef struct _MP_TELEMETRY_EVENT {
    MP_TELEMETRY_HEADER Header;          /* +0x00                     */
    ULONG       NameChars;               /* +0x28 excluding NUL       */
    ULONG       TargetChars;             /* +0x2c excluding NUL       */
    ULONG       CreateOptions;           /* +0x30 disposition in high byte */
    ULONG       FileAttributes;          /* +0x34                     */
    ULONG       ParentProcessId;         /* +0x38 process events      */
    ULONG       SubEvent;                /* +0x3c write length for FILE_WRITE */
    UINT64      CreateTime;              /* +0x40 process create time */
    UINT64      FileId;                  /* +0x48 META_FILE_ID        */
    ULONG       MetadataFlags;           /* +0x50 MP_TELEMETRY_META_* */
    ULONG       Reserved2;               /* +0x54                     */
    UINT64      FileSize;                /* +0x58 META_SIZE           */
    UINT64      CreationTime;            /* +0x60 META_TIMES          */
    UINT64      AccessTime;              /* +0x68 META_TIMES          */
    UINT64      WriteTime;               /* +0x70 META_TIMES          */
    UINT64      ChangeTime;              /* +0x78 META_TIMES          */
    WCHAR       Data[1];                 /* +0x80 Name, NUL, [Target, NUL] */
} MP_TELEMETRY_EVENT;                    /* fixed part 0x80 bytes     */

/* Wire ABI guards: a field reorder or resize must bump MP_TELEMETRY_VERSION. */
typedef char MP_TELEMETRY_HEADER_size_check[
    sizeof(MP_TELEMETRY_HEADER) == 0x28 ? 1 : -1];
typedef char MP_TELEMETRY_EVENT_fixed_check[
    FIELD_OFFSET(MP_TELEMETRY_EVENT, Data) == 0x80 ? 1 : -1];

typedef struct _MP_TELEMETRY_HELLO {
    ULONG       Size;
    USHORT      Version;
    USHORT      Type;       /* MP_TELEMETRY_TYPE_HELLO                    */
    ULONG       ProcessId;
    ULONG       Flags;
    ULONG       Reserved;
    UINT64      Nonce;      /* echoed back by the driver                  */
} MP_TELEMETRY_HELLO;       /* 0x20 bytes                                 */

typedef struct _MP_TELEMETRY_HELLO_REPLY {
    ULONG       Size;
    USHORT      Version;
    USHORT      Type;       /* MP_TELEMETRY_TYPE_HELLO_REPLY              */
    ULONG       MaxMessage; /* largest message the driver will send       */
    ULONG       Flags;
    ULONG       Reserved;
    UINT64      DriverVersion;
} MP_TELEMETRY_HELLO_REPLY; /* 0x20 bytes                                 */

#ifdef __cplusplus
}
#endif

#endif /* MP_TELEMETRY_H */
