"""Minimal read-only LevelDB (.ldb/.sst/.log) reader used by the scanner.

Chromium's Local Storage is a LevelDB database.  Recent values are still
plain-text in the ``.log`` write-ahead file, but once LevelDB compacts them into
an ``.ldb`` table the payload strings can be Snappy-compressed.  A plain text
grep then misses the evidence, which is exactly what the public incident report
warns about.

This module implements just enough of the LevelDB table format and raw Snappy
decompression to read those blocks.  It never writes anything.
"""
from __future__ import annotations

import os
import struct
import zlib
from typing import Dict, List, Optional, Sequence, Tuple


FOOTER_SIZE = 48
TABLE_MAGIC = 0xDB4775248B80FB57
BLOCK_TRAILER = 5
MAX_BLOCK_BYTES = 32 * 1024 * 1024
MAX_BLOCKS = 4096


def _varint(data: bytes, pos: int) -> Tuple[int, int]:
    result = 0
    shift = 0
    while True:
        if pos >= len(data):
            raise ValueError("truncated varint")
        byte = data[pos]
        pos += 1
        result |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return result, pos
        shift += 7
        if shift > 63:
            raise ValueError("varint too long")


def snappy_decompress(data: bytes) -> bytes:
    """Decode the raw Snappy block format (no framing)."""
    length, pos = _varint(data, 0)
    if length > MAX_BLOCK_BYTES:
        raise ValueError("snappy output too large")
    out = bytearray()
    total = len(data)
    while pos < total:
        tag = data[pos]
        pos += 1
        kind = tag & 0x03
        if kind == 0:  # literal
            size = tag >> 2
            if size < 60:
                size += 1
            else:
                extra = size - 59
                if pos + extra > total:
                    raise ValueError("truncated literal length")
                size = int.from_bytes(data[pos:pos + extra], "little") + 1
                pos += extra
            if pos + size > total:
                raise ValueError("truncated literal")
            out += data[pos:pos + size]
            pos += size
        else:
            if kind == 1:
                if pos >= total:
                    raise ValueError("truncated copy")
                size = 4 + ((tag >> 2) & 0x07)
                offset = ((tag >> 5) << 8) | data[pos]
                pos += 1
            elif kind == 2:
                if pos + 2 > total:
                    raise ValueError("truncated copy")
                size = (tag >> 2) + 1
                offset = int.from_bytes(data[pos:pos + 2], "little")
                pos += 2
            else:
                if pos + 4 > total:
                    raise ValueError("truncated copy")
                size = (tag >> 2) + 1
                offset = int.from_bytes(data[pos:pos + 4], "little")
                pos += 4
            if offset <= 0 or offset > len(out):
                raise ValueError("invalid copy offset")
            start = len(out) - offset
            for index in range(size):
                out.append(out[start + index])
        if len(out) > length:
            raise ValueError("snappy output overrun")
    if len(out) != length:
        raise ValueError("snappy length mismatch")
    return bytes(out)


def _read_block(contents: bytes, offset: int, size: int) -> bytes:
    end = offset + size
    if size <= 0 or end + BLOCK_TRAILER > len(contents):
        raise ValueError("block out of range")
    payload = contents[offset:end]
    compression = contents[end]
    if compression == 0:
        data = payload
    elif compression == 1:
        data = snappy_decompress(payload)
    elif compression == 2:
        data = zlib.decompress(payload)
    else:
        raise ValueError(f"unsupported compression {compression}")
    if len(data) > MAX_BLOCK_BYTES:
        raise ValueError("block too large")
    return data


def _iter_entries(block: bytes):
    if len(block) < 4:
        return
    try:
        restart_count = struct.unpack_from("<I", block, len(block) - 4)[0]
    except struct.error:
        return
    limit = len(block) - 4 - restart_count * 4
    if limit <= 0:
        limit = len(block) - 4
    pos = 0
    while pos < limit:
        try:
            _shared, pos = _varint(block, pos)
            non_shared, pos = _varint(block, pos)
            value_len, pos = _varint(block, pos)
        except ValueError:
            return
        if non_shared < 0 or value_len < 0 or pos + non_shared + value_len > len(block):
            return
        pos += non_shared
        value = block[pos:pos + value_len]
        pos += value_len
        yield value


def read_table_blocks(contents: bytes) -> List[bytes]:
    """Return the decompressed data blocks of a LevelDB table."""
    if len(contents) < FOOTER_SIZE:
        return []
    footer = contents[-FOOTER_SIZE:]
    try:
        magic = struct.unpack_from("<Q", footer, FOOTER_SIZE - 8)[0]
        if magic != TABLE_MAGIC:
            return []
        pos = 0
        _, pos = _varint(footer, pos)  # metaindex offset
        _, pos = _varint(footer, pos)  # metaindex size
        index_offset, pos = _varint(footer, pos)
        index_size, pos = _varint(footer, pos)
    except (ValueError, struct.error):
        return []
    try:
        index_block = _read_block(contents, index_offset, index_size)
    except (ValueError, OSError, zlib.error):
        return []
    blocks: List[bytes] = []
    for handle in _iter_entries(index_block):
        try:
            offset, cursor = _varint(handle, 0)
            size, _ = _varint(handle, cursor)
            blocks.append(_read_block(contents, offset, size))
        except (ValueError, OSError, zlib.error):
            continue
        if len(blocks) >= MAX_BLOCKS:
            break
    return blocks


def _find(blob: bytes, needles: Sequence[bytes], found: List[str]) -> None:
    for needle in needles:
        if needle in blob and needle.decode("ascii", "replace") not in found:
            found.append(needle.decode("ascii", "replace"))


def search_leveldb(path: str, needles: Sequence[bytes], max_bytes: int = 96 * 1024 * 1024) -> Dict[str, object]:
    """Search a LevelDB file, including Snappy-compressed table blocks.

    Returns ``{"found": [...], "method": "raw"|"table"|"raw+table", ...}``.
    """
    result: Dict[str, object] = {"path": path, "found": [], "method": [], "blocks": 0, "error": ""}
    found: List[str] = []
    try:
        size = os.path.getsize(path)
    except OSError as exc:
        result["error"] = str(exc)
        return result
    try:
        with open(path, "rb") as handle:
            if size <= max_bytes:
                contents = handle.read()
            else:
                head = handle.read(max_bytes // 2)
                handle.seek(max(0, size - max_bytes // 2))
                contents = head + handle.read(max_bytes // 2)
    except OSError as exc:
        result["error"] = str(exc)
        return result
    _find(contents, needles, found)
    if found:
        result["method"] = ["raw"]
    blocks = read_table_blocks(contents)
    if blocks:
        result["blocks"] = len(blocks)
        for block in blocks:
            _find(block, needles, found)
        if found:
            result["method"] = ["table"] if result["method"] == [] else ["raw", "table"]
    result["found"] = found
    return result


def is_leveldb_table(contents: bytes) -> bool:
    if len(contents) < FOOTER_SIZE:
        return False
    try:
        return struct.unpack_from("<Q", contents, len(contents) - 8)[0] == TABLE_MAGIC
    except struct.error:
        return False
