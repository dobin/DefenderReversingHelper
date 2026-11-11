import mmap
import struct
from typing import Generator, Tuple

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
        # Map file into memory for zero-copy slice operations
        with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:
            offset = 0
            file_len = len(mm)

            while offset + HEADER_SIZE <= file_len:
                magic, signal_id, buffer_size = HEADER_STRUCT.unpack_from(mm, offset)

                # Validate frame sync marker
                if magic != MAGIC_MARKER:
                    raise ValueError(
                        f"Corrupt frame header encountered at byte offset {offset}"
                    )

                payload_start = offset + HEADER_SIZE
                payload_end = payload_start + buffer_size

                # Detect incomplete writes at file EOF
                if payload_end > file_len:
                    break

                # Zero-copy slice of the payload region
                payload = mm[payload_start:payload_end]
                yield signal_id, bytes(payload)

                offset = payload_end


# Usage Example
if __name__ == "__main__":
    for signal_id, payload in stream_events("events.bin"):
        print(f"Signal ID: {signal_id} | Payload size: {len(payload)} bytes")