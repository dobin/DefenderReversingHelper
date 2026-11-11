import argparse
import base64
import json
import mmap
import struct
from collections import Counter
from typing import Generator, Iterator, Tuple

# Header layout specifier:
# < = Little-endian ordering
# H = uint16 (2 bytes, magic marker)
# I = uint32 (4 bytes, signal_id)
# I = uint32 (4 bytes, buffer_size)
HEADER_STRUCT = struct.Struct("<HII")
HEADER_SIZE = HEADER_STRUCT.size
MAGIC_MARKER = 0x5645  # ASCII 'EV'


def stream_events(filepath: str) -> Generator[Tuple[int, bytes], None, None]:
    """Memory-mapped iterator yielding (signal_id, payload_bytes) from binary file."""
    with open(filepath, "rb") as f:
        if f.seek(0, 2) == 0:
            return
        f.seek(0)
        with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:
            offset = 0
            file_len = len(mm)

            while offset + HEADER_SIZE <= file_len:
                magic, signal_id, buffer_size = HEADER_STRUCT.unpack_from(mm, offset)

                if magic != MAGIC_MARKER:
                    raise ValueError(
                        f"Corrupt frame header encountered at byte offset {offset}"
                    )

                payload_start = offset + HEADER_SIZE
                payload_end = payload_start + buffer_size
                if payload_end > file_len:
                    break

                payload = mm[payload_start:payload_end]
                yield signal_id, bytes(payload)
                offset = payload_end


def enumerate_events(filepath: str) -> Iterator[Tuple[int, int, bytes]]:
    """Yield (event_id, signal_id, payload), using 1-based file-order IDs."""
    for event_id, (signal_id, payload) in enumerate(stream_events(filepath), start=1):
        yield event_id, signal_id, payload


def event_metadata(event_id: int, signal_id: int, payload: bytes) -> dict:
    return {"id": event_id, "signal_id": signal_id, "payload_size": len(payload)}


def parse_signal_id(value: str) -> int:
    """Accept decimal signal IDs and 0x-prefixed hexadecimal IDs."""
    try:
        return int(value, 0)
    except ValueError as error:
        raise argparse.ArgumentTypeError("signal ID must be decimal or 0x-prefixed hexadecimal") from error


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Inspect framed binary event logs. Output is JSON and payloads are binary-safe."
    )
    parser.add_argument("--file", required=True, help="Path to the binary log file")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("stats", help="Count events by signal_id")

    list_parser = commands.add_parser("list", help="List event IDs and metadata")
    list_parser.add_argument("--signal-id", type=parse_signal_id, help="Filter by signal_id")
    list_parser.add_argument("--offset", type=int, default=0, help="Matching events to skip")
    list_parser.add_argument("--limit", type=int, default=100, help="Maximum results; 0 means no limit")

    details_parser = commands.add_parser("details", help="Get one event and its payload")
    details_parser.add_argument("event_id", type=int, help="1-based ID shown by list")
    details_parser.add_argument("--output", help="Save raw payload bytes to this file")
    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    try:
        if args.command == "stats":
            counts = Counter(signal_id for _, signal_id, _ in enumerate_events(args.file))
            result = {
                "event_count": sum(counts.values()),
                "signal_ids": [
                    {"signal_id": signal_id, "count": count}
                    for signal_id, count in sorted(counts.items())
                ],
            }
        elif args.command == "list":
            if args.offset < 0 or args.limit < 0:
                parser.error("--offset and --limit must be non-negative")
            events = []
            matched = 0
            for event_id, signal_id, payload in enumerate_events(args.file):
                if args.signal_id is not None and signal_id != args.signal_id:
                    continue
                if matched >= args.offset:
                    if args.limit and len(events) >= args.limit:
                        break
                    events.append(event_metadata(event_id, signal_id, payload))
                matched += 1
            result = {"events": events}
        else:
            if args.event_id < 1:
                parser.error("event_id must be at least 1")
            event = next(
                (item for item in enumerate_events(args.file) if item[0] == args.event_id),
                None,
            )
            if event is None:
                parser.error(f"event ID {args.event_id} was not found")
            event_id, signal_id, payload = event
            result = event_metadata(event_id, signal_id, payload)
            if args.output:
                with open(args.output, "wb") as output:
                    output.write(payload)
                result["payload_file"] = args.output
            else:
                result["payload_base64"] = base64.b64encode(payload).decode("ascii")
        print(json.dumps(result))
    except (OSError, ValueError) as error:
        parser.error(str(error))


if __name__ == "__main__":
    main()
