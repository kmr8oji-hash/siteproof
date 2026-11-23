"""Bounded offline PNG preview, never a trusted S2 quality assessment.

Only 8-bit RGB/RGBA non-interlaced PNG is supported. Other images fail explicitly.
No threshold, capture attestation, file path or network access is introduced.
The pixel rule matches Compare.diffBand: any RGBA difference, magenta highlight.
"""
import binascii
import hashlib
import math
import struct
import zlib

MAX_BYTES = 1024 * 1024
MAX_PIXELS = 256 * 256
MAX_WIDTH, MAX_HEIGHT = 4096, 16384  # full-page captures of ordinary sites are tall (Chromium caps at 16384)
MAGIC = b"\x89PNG\r\n\x1a\n"


class PreviewError(ValueError):
    pass


def png(width, height, rgba, *, max_pixels=MAX_PIXELS):
    if (type(width) is not int or type(height) is not int or not 0 < width <= MAX_WIDTH
            or not 0 < height <= MAX_HEIGHT or width * height > max_pixels
            or type(rgba) not in (bytes,bytearray) or len(rgba) != width * height * 4):
        raise PreviewError("IMAGE_LIMIT")
    def chunk(kind, data):
        return struct.pack('>I', len(data)) + kind + data + struct.pack('>I', binascii.crc32(kind + data))
    raw = b''.join(b'\0' + bytes(rgba[y * width * 4:(y + 1) * width * 4]) for y in range(height))
    return MAGIC + chunk(b'IHDR', struct.pack('>IIBBBBB', width, height, 8, 6, 0, 0, 0)) + chunk(b'IDAT', zlib.compress(raw)) + chunk(b'IEND', b'')


def decode(data, *, max_pixels=MAX_PIXELS, max_bytes=MAX_BYTES, metadata_only=False):
    if type(data) is not bytes or not data.startswith(MAGIC) or len(data) > max_bytes:
        raise PreviewError("IMAGE_INVALID")
    pos, chunks, packed, ended, closed_idat = 8, [], bytearray(), False, False
    while pos < len(data):
        if pos + 12 > len(data):
            raise PreviewError("IMAGE_INVALID")
        length = int.from_bytes(data[pos:pos + 4], 'big')
        kind = data[pos + 4:pos + 8]
        payload = data[pos + 8:pos + 8 + length]
        end = pos + length + 12
        if end > len(data) or binascii.crc32(kind + payload) != int.from_bytes(data[end - 4:end], 'big'):
            raise PreviewError("IMAGE_INVALID")
        if kind == b'IHDR':
            if chunks or length != 13:
                raise PreviewError("IMAGE_INVALID")
            w, h, depth, color, comp, filt, interlace = struct.unpack('>IIBBBBB', payload)
            if not 0 < w <= MAX_WIDTH or not 0 < h <= MAX_HEIGHT or w * h > max_pixels:
                raise PreviewError("IMAGE_LIMIT")
            if depth != 8 or color not in (2, 6) or comp or filt or interlace:
                raise PreviewError("IMAGE_FORMAT_UNSUPPORTED")
        elif kind == b'IDAT':
            if not chunks or closed_idat:
                raise PreviewError("IMAGE_INVALID")
            packed.extend(payload)
        elif kind == b'IEND':
            if payload or not packed or end != len(data):
                raise PreviewError("IMAGE_INVALID")
            ended = True
        else:
            # Do not silently ignore color/transparency or animation semantics.
            raise PreviewError("IMAGE_FORMAT_UNSUPPORTED")
        if chunks and chunks[-1] == b'IDAT' and kind != b'IDAT':
            closed_idat = True
        chunks.append(kind); pos = end
    if not ended:
        raise PreviewError("IMAGE_INVALID")
    channels = 4 if color == 6 else 3
    stride = w * channels
    expected = (stride + 1) * h
    inflater = zlib.decompressobj()
    try:
        raw = inflater.decompress(bytes(packed), expected + 1)
    except zlib.error:
        raise PreviewError("IMAGE_INVALID") from None
    if len(raw) != expected or not inflater.eof or inflater.unused_data or inflater.unconsumed_tail:
        raise PreviewError("IMAGE_INVALID")
    if metadata_only:
        if any(raw[y * (stride + 1)] > 4 for y in range(h)):
            raise PreviewError('IMAGE_INVALID')
        return w, h
    previous, rgba = bytearray(stride), bytearray()
    def paeth(a, b, c):
        p = a + b - c
        distances = abs(p - a), abs(p - b), abs(p - c)
        return (a, b, c)[distances.index(min(distances))]
    for y in range(h):
        mode = raw[y * (stride + 1)]
        row = bytearray(raw[y * (stride + 1) + 1:(y + 1) * (stride + 1)])
        if mode > 4:
            raise PreviewError("IMAGE_INVALID")
        for i in range(stride):
            a, b, c = (row[i - channels] if i >= channels else 0), previous[i], (previous[i - channels] if i >= channels else 0)
            delta = (0, a, b, (a + b) // 2, paeth(a, b, c))[mode]
            row[i] = (row[i] + delta) & 255
        for i in range(0, stride, channels):
            rgba.extend(row[i:i + 3]); rgba.append(row[i + 3] if channels == 4 else 255)
        previous = row
    return w, h, bytes(rgba)


def dimensions(data, *, max_pixels=MAX_PIXELS, max_bytes=MAX_BYTES):
    """Validate chunks/CRC/format/inflation without reconstructing every pixel."""
    return decode(data, max_pixels=max_pixels, max_bytes=max_bytes, metadata_only=True)


def compare(before, after, *, max_pixels=MAX_PIXELS, max_bytes=MAX_BYTES):
    w, h, a = decode(before, max_pixels=max_pixels, max_bytes=max_bytes)
    x, y, b = decode(after, max_pixels=max_pixels, max_bytes=max_bytes)
    if (w, h) != (x, y):
        raise PreviewError("IMAGE_SIZE_MISMATCH")
    out, changed = bytearray(len(a)), 0
    for i in range(0, len(a), 4):
        if a[i:i + 4] != b[i:i + 4]:
            out[i:i + 4] = b'\xff\x00\x66\xff'; changed += 1
        else:
            alpha = a[i + 3] / 255
            luminance = (a[i] * 299 + a[i + 1] * 587 + a[i + 2] * 114) / 1000
            ghost = 255 - math.floor((255 - (luminance * alpha + 255 * (1 - alpha))) * .25 + .5)
            out[i:i + 4] = bytes((ghost, ghost, ghost, 255))
    return {"width": w, "height": h, "changed_pixels": changed, "total_pixels": w * h,
            "ratio": changed / (w * h)}, png(w, h, out, max_pixels=max_pixels)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def fixture(name):
    if name not in ('original', 'changed', 'missing', 'profile-mismatch'):
        raise PreviewError("FIXTURE_NOT_FOUND")
    if name == 'missing':
        return None
    pixels = bytearray((235, 240, 250, 255) * 64)
    if name == 'changed':
        pixels[:4] = b'\x10\x20\x30\xff'
    return png(8, 8, pixels)
