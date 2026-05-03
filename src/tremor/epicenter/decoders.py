"""Encoding detection and decoding utilities for payload analysis.

Detects base64, hex, URL-encoded, and multi-layer encoded content
in arbitrary text. All stdlib — no external dependencies.
"""

import base64
import re
import urllib.parse
from typing import NamedTuple

from .entropy import shannon_entropy


# ---------------------------------------------------------------------------
# Detection patterns
# ---------------------------------------------------------------------------

_B64_RE = re.compile(r"[A-Za-z0-9+/]{40,}={0,3}")
_B64URL_RE = re.compile(r"[A-Za-z0-9_-]{40,}={0,3}")
_HEX_RE = re.compile(r"(?:[0-9a-fA-F]{2}){16,}")
_URL_ENC_RE = re.compile(r"(?:%[0-9a-fA-F]{2}){6,}")
_SHELL_HEX_RE = re.compile(r"(?:\\x[0-9a-fA-F]{2}){8,}")
_OCTAL_RE = re.compile(r"(?:\\[0-3][0-7]{2}){8,}")

MAX_DECODE_DEPTH = 5
MIN_DECODED_SIZE = 16

# Base64url hash-equivalent lengths to skip.
_B64URL_HASH_LENGTHS = {22, 24, 27, 28, 43, 44, 64, 86, 88}


class DecodedBlob(NamedTuple):
    """Result of a decoding attempt."""
    encoding: str
    offset: int
    encoded_length: int
    decoded_data: bytes
    decoded_entropy: float
    layers: int


class EncodingDetection(NamedTuple):
    """Detection of an encoded block (before full decode)."""
    encoding: str
    offset: int
    length: int
    raw: str


# ---------------------------------------------------------------------------
# Single-layer detection
# ---------------------------------------------------------------------------


def detect_base64_blocks(text: str, min_length: int = 40) -> list[EncodingDetection]:
    """Find base64-encoded blocks in text."""
    results = []
    for m in _B64_RE.finditer(text):
        block = m.group(0)
        if len(block) < min_length:
            continue
        if _is_known_format(block):
            continue
        results.append(EncodingDetection("base64", m.start(), len(block), block))

    for m in _B64URL_RE.finditer(text):
        block = m.group(0)
        if len(block) < min_length:
            continue
        if _is_known_format(block):
            continue
        # Skip hash-equivalent lengths for base64url
        if len(block) in _B64URL_HASH_LENGTHS:
            continue
        if not any(d.offset == m.start() for d in results):
            results.append(EncodingDetection("base64url", m.start(), len(block), block))

    return results


def detect_hex_blocks(text: str, min_bytes: int = 16) -> list[EncodingDetection]:
    """Find hex-encoded blocks in text."""
    results = []
    for m in _HEX_RE.finditer(text):
        block = m.group(0)
        if len(block) < min_bytes * 2:
            continue
        if len(block) in (32, 40, 64, 128):
            continue
        results.append(EncodingDetection("hex", m.start(), len(block), block))
    return results


def detect_url_encoded(text: str) -> list[EncodingDetection]:
    """Find URL-encoded blocks in text."""
    results = []
    for m in _URL_ENC_RE.finditer(text):
        block = m.group(0)
        results.append(EncodingDetection("url", m.start(), len(block), block))
    return results


def detect_shell_hex(text: str) -> list[EncodingDetection]:
    """Find shell-style hex escape sequences."""
    results = []
    for m in _SHELL_HEX_RE.finditer(text):
        results.append(EncodingDetection("shell_hex", m.start(), len(m.group(0)), m.group(0)))
    return results


def detect_octal_encoded(text: str) -> list[EncodingDetection]:
    """Find octal escape sequences."""
    results = []
    for m in _OCTAL_RE.finditer(text):
        results.append(EncodingDetection("octal", m.start(), len(m.group(0)), m.group(0)))
    return results


def detect_all_encodings(text: str) -> list[EncodingDetection]:
    """Run all encoding detectors on text and return combined results."""
    results = []
    results.extend(detect_base64_blocks(text))
    results.extend(detect_hex_blocks(text))
    results.extend(detect_url_encoded(text))
    results.extend(detect_shell_hex(text))
    results.extend(detect_octal_encoded(text))
    results.sort(key=lambda d: d.offset)
    return results


# ---------------------------------------------------------------------------
# Decoding
# ---------------------------------------------------------------------------


def try_decode_base64(raw: str) -> bytes | None:
    """Attempt to base64-decode a string."""
    padded = raw + "=" * (4 - len(raw) % 4) if len(raw) % 4 else raw
    try:
        return base64.b64decode(padded, validate=True)
    except Exception:
        pass
    try:
        return base64.urlsafe_b64decode(padded)
    except Exception:
        return None


def try_decode_hex(raw: str) -> bytes | None:
    """Attempt to hex-decode a string."""
    try:
        return bytes.fromhex(raw)
    except ValueError:
        return None


def try_decode_url(raw: str) -> bytes | None:
    """Attempt to URL-decode a string."""
    try:
        decoded = urllib.parse.unquote(raw)
        if decoded != raw:
            return decoded.encode("utf-8", errors="replace")
    except Exception:
        pass
    return None


def try_decode_shell_hex(raw: str) -> bytes | None:
    """Decode \\xHH escape sequences."""
    try:
        hex_str = raw.replace("\\x", "")
        return bytes.fromhex(hex_str)
    except Exception:
        return None


def try_decode_octal(raw: str) -> bytes | None:
    """Decode \\NNN octal escape sequences."""
    try:
        parts = raw.split("\\")[1:]
        return bytes(int(p[:3], 8) for p in parts if len(p) >= 3)
    except Exception:
        return None


def decode_detection(det: EncodingDetection) -> bytes | None:
    """Decode an EncodingDetection using the appropriate decoder."""
    decoders = {
        "base64": try_decode_base64,
        "base64url": try_decode_base64,
        "hex": try_decode_hex,
        "url": try_decode_url,
        "shell_hex": try_decode_shell_hex,
        "octal": try_decode_octal,
    }
    decoder = decoders.get(det.encoding)
    if decoder:
        return decoder(det.raw)
    return None


# ---------------------------------------------------------------------------
# Multi-layer decoding
# ---------------------------------------------------------------------------


def decode_multilayer(data: bytes, max_depth: int = MAX_DECODE_DEPTH) -> list[tuple[str, bytes]]:
    """Attempt to recursively decode multi-layer encoded data.

    Returns a list of (encoding_name, decoded_bytes) for each layer
    successfully stripped.
    """
    layers: list[tuple[str, bytes]] = []
    current = data

    for _ in range(max_depth):
        try:
            text = current.decode("utf-8", errors="strict")
        except UnicodeDecodeError:
            break

        text = text.strip()
        if len(text) < MIN_DECODED_SIZE:
            break

        decoded = None
        encoding = ""

        decoded = try_decode_base64(text)
        if decoded and len(decoded) >= MIN_DECODED_SIZE:
            encoding = "base64"
        else:
            decoded = try_decode_hex(text)
            if decoded and len(decoded) >= MIN_DECODED_SIZE:
                encoding = "hex"
            else:
                decoded = try_decode_url(text)
                if decoded and len(decoded) >= MIN_DECODED_SIZE and decoded != current:
                    encoding = "url"
                else:
                    break

        if decoded and encoding:
            layers.append((encoding, decoded))
            current = decoded
        else:
            break

    return layers


def decode_blob(det: EncodingDetection) -> DecodedBlob | None:
    """Fully decode an encoding detection, including multi-layer."""
    first_decode = decode_detection(det)
    if first_decode is None or len(first_decode) < MIN_DECODED_SIZE:
        return None

    layers = decode_multilayer(first_decode)
    if layers:
        final_data = layers[-1][1]
        total_layers = 1 + len(layers)
    else:
        final_data = first_decode
        total_layers = 1

    return DecodedBlob(
        encoding=det.encoding,
        offset=det.offset,
        encoded_length=det.length,
        decoded_data=final_data,
        decoded_entropy=shannon_entropy(final_data),
        layers=total_layers,
    )


# ---------------------------------------------------------------------------
# Content classification
# ---------------------------------------------------------------------------


def is_asn1_der(data: bytes) -> bool:
    """Check if data looks like ASN.1 DER-encoded content."""
    if len(data) < 4:
        return False
    tag = data[0]
    if tag not in (0x30, 0x31):
        return False
    if data[1] < 0x80:
        declared = data[1]
        return declared > 0 and declared <= len(data) - 2
    elif data[1] == 0x81:
        if len(data) < 3:
            return False
        declared = data[2]
        return declared > 0 and declared <= len(data) - 3
    elif data[1] == 0x82:
        if len(data) < 4:
            return False
        declared = (data[2] << 8) | data[3]
        return declared > 0 and declared <= len(data) - 4
    return False


def is_likely_certificate(data: bytes) -> bool:
    """Check if decoded data is likely a certificate or PKI artifact."""
    if is_asn1_der(data):
        return True
    pki_markers = [
        b"\x55\x04",
        b"\x2a\x86\x48\x86",
        b"\x2a\x86\x48\xce",
    ]
    head = data[:64]
    return any(m in head for m in pki_markers)


def _looks_like_protobuf(data: bytes) -> bool:
    """Heuristic check for protobuf wire format."""
    if len(data) < 2:
        return False
    valid_tags = 0
    i = 0
    limit = min(len(data), 32)
    while i < limit and valid_tags < 4:
        byte = data[i]
        wire_type = byte & 0x07
        field_number = byte >> 3
        if wire_type > 5 or field_number == 0:
            break
        valid_tags += 1
        i += 1
        while i < limit and data[i] & 0x80:
            i += 1
        if i < limit:
            i += 1
    return valid_tags >= 3


def _is_known_format(block: str) -> bool:
    """Check if a base64/base64url block matches known benign formats."""
    if block.startswith("eyJ"):
        return True
    if block.startswith("MII"):
        return True
    if block.startswith("PACK"):
        return True
    if block.startswith(("MIA", "MCo", "MC4", "MDQ")):
        return True
    if block.startswith(("AAAA", "AAAB")):
        return True
    if block.startswith("iVBOR"):
        return True
    if block.startswith("/9j/"):
        return True
    if block.startswith("R0lGOD"):
        return True
    if block.startswith("JVBER"):
        return True
    return False


def summarize_blob(blob: DecodedBlob, preview_bytes: int = 64) -> dict:
    """Create a human-readable summary of a decoded blob."""
    preview = base64.b64encode(blob.decoded_data[:preview_bytes]).decode()
    content_type = "unknown"
    data = blob.decoded_data
    if data[:4] == b"\x7fELF":
        content_type = "ELF binary"
    elif data[:2] == b"MZ":
        content_type = "PE binary"
    elif data[:2] == b"PK":
        content_type = "ZIP archive"
    elif data[:3] == b"\x1f\x8b\x08":
        content_type = "gzip data"
    elif data[:6] in (b"GIF87a", b"GIF89a"):
        content_type = "GIF image"
    elif data[:8] == b"\x89PNG\r\n\x1a\n":
        content_type = "PNG image"
    elif data[:2] == b"\xff\xd8":
        content_type = "JPEG image"
    elif data[:4] in (b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf",
                       b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe"):
        content_type = "Mach-O binary"
    elif data[:4] == b"\xca\xfe\xba\xbe" and len(data) > 8:
        if data[4:6] == b"\x00\x00":
            content_type = "Mach-O fat binary"
        else:
            content_type = "Java class"
    elif data[:4] == b"\x00asm":
        content_type = "WebAssembly module"
    elif is_asn1_der(data):
        content_type = "ASN.1/DER (certificate/key)"
    elif is_likely_certificate(data):
        content_type = "PKI data (certificate/key)"
    elif b"#!/" in data[:32]:
        content_type = "shell script"
    elif blob.decoded_entropy > 7.5:
        content_type = "encrypted/compressed data"
    elif blob.decoded_entropy < 4.0:
        try:
            text_data = data.decode("utf-8")
            stripped = text_data.strip()
            if stripped.startswith(("{", "[")):
                content_type = "JSON data"
            elif stripped.startswith(("<?xml", "<!")):
                content_type = "XML data"
            elif stripped.startswith(("---", "%YAML")):
                content_type = "YAML data"
            else:
                content_type = "text"
        except UnicodeDecodeError:
            content_type = "low-entropy binary"
    elif data[:16] == b"SQLite format 3\x00":
        content_type = "SQLite database"
    elif (len(data) >= 5
          and int.from_bytes(data[:4], "little") == len(data)
          and 0x01 <= data[4] <= 0x13
          and data[-1:] == b"\x00"):
        content_type = "BSON document"
    elif len(data) >= 1 and data[0] in (
        *range(0x80, 0x90),
        *range(0x90, 0xA0),
        *range(0xC0, 0xCA),
        *range(0xCC, 0xD4),
        *range(0xDC, 0xE0),
    ):
        content_type = "MessagePack data"
    elif _looks_like_protobuf(data):
        content_type = "protobuf data"
    elif 4.0 <= blob.decoded_entropy < 5.5:
        content_type = "structured binary data"
    elif 5.5 <= blob.decoded_entropy < 6.5:
        content_type = "encoded token/credential data"
    elif 6.5 <= blob.decoded_entropy < 7.5:
        content_type = "high-entropy binary (likely encrypted)"

    return {
        "encoding": blob.encoding,
        "layers": blob.layers,
        "decoded_size": len(blob.decoded_data),
        "decoded_entropy": round(blob.decoded_entropy, 2),
        "content_type": content_type,
        "preview_b64": preview,
    }
