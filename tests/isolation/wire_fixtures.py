"""Reusable in-memory S0 wire/PNG fixtures; no S1 imports or filesystem I/O.

The default PNG is a real 1x1 RGB image. Custom PNG/header arguments also support
deliberately malformed fixtures; these builders are not production validators.
"""

import json
import struct
import zlib

from src.isolation.frames import CONTRACT_VERSION, MAGIC


def header(seq=0, kind="HTTP_RECORD", length=3, **changes):
    value = dict(magic=MAGIC, version=CONTRACT_VERSION, seq=seq, kind=kind,
                 page_id="page-1", profile_id="profile-1", declared_length=length)
    value.update(changes)
    return value


def raw_header(value):
    return json.dumps(value, separators=(",", ":")).encode("utf-8")


def packet(value, payload=b""):
    raw = raw_header(value)
    return len(raw).to_bytes(4, "big") + raw + payload


def end(seq=1, **changes):
    return packet(header(seq, "END", 0, page_id="", profile_id="", **changes))


def png_chunk(kind, data):
    return (len(data).to_bytes(4, "big") + kind + data +
            (zlib.crc32(data, zlib.crc32(kind)) & 0xffffffff).to_bytes(4, "big"))


def png(*, width=1, height=1, depth=8, color=2, idat=None, extra=b""):
    """Keep the Batch 01 configurable builder, including its negative-test inputs."""
    ihdr = struct.pack(">IIBBBBB", width, height, depth, color, 0, 0, 0)
    if idat is None:
        idat = zlib.compress(b"\x00\xff\x00\x00")
    return (b"\x89PNG\r\n\x1a\n" + png_chunk(b"IHDR", ihdr) + extra +
            png_chunk(b"IDAT", idat) + png_chunk(b"IEND", b""))


def png_1x1() -> bytes:
    """Complete 1x1 red RGB PNG for successful offline wire fixtures."""
    return png()
