"""Artifact scanner — detect steganographic content in CI/CD artifacts.

Scanning capabilities:
  - Image steganography (PNG, JPEG, BMP, GIF): LSB analysis, appended data,
    steg tool signatures, chi-square anomaly detection
  - Archive analysis (ZIP, TAR, GZIP): hidden files, polyglots, compression ratios
  - Build artifact analysis: Docker layers, npm/pip packages, workflow files,
    encoded payloads in YAML/JSON/shell
  - Binary analysis: section entropy, ELF/PE structure, embedded encoded strings

All stdlib — no external dependencies.
"""

import base64
import io
import json
import re
import struct
import tarfile
import zipfile
from pathlib import Path
from .models import (
    ArtifactType,
    FindingType,
    StegFinding,
    ArtifactScan,
)
from .entropy import (
    shannon_entropy,
    high_entropy_regions,
    chi_square_byte_test,
    chi_square_lsb_test,
    lsb_plane_entropy,
)
from .decoders import (
    detect_all_encodings,
    decode_blob,
    summarize_blob,
    is_likely_certificate,
)

# Graceful optional imports — these modules will be added in a follow-up.
try:
    from .png_analysis import analyze_png_pixels
except ImportError:
    analyze_png_pixels = None  # type: ignore[assignment]

try:
    from .macho import analyze_macho
except ImportError:
    analyze_macho = None  # type: ignore[assignment]


# ---------------------------------------------------------------------------
# Constants and patterns
# ---------------------------------------------------------------------------

MIN_B64_BLOCK = 100
MIN_HEX_BLOCK = 64

_STEG_SIGNATURES: list[tuple[str, bytes, str]] = [
    ("steghide", b"steghide", "Steghide marker found in file"),
    ("openstego", b"OpenStego", "OpenStego marker found in file"),
    ("openstego_sig", b"\x00\x00OSTE", "OpenStego binary signature"),
    ("lsb_steg", b"LSB-Steg", "LSB-Steg tool marker"),
    ("snow_ws", b"SNOW", "SNOW whitespace steganography marker"),
    ("outguess", b"OutGuess", "OutGuess marker found"),
    ("invisible_secrets", b"Invisible Secrets", "Invisible Secrets marker"),
    ("camouflage", b"Camouflage", "Camouflage steg tool marker"),
]

_HIDDEN_FILE_PATTERNS = [
    re.compile(r"^\."),
    re.compile(r"__MACOSX/"),
    re.compile(r"\.DS_Store$"),
    re.compile(r"Thumbs\.db$"),
    re.compile(r"\.git/"),
    re.compile(r"\.svn/"),
    re.compile(r"\.env$"),
    re.compile(r"\.ssh/"),
    re.compile(r"\.aws/"),
    re.compile(r"\.gnupg/"),
]

_OBFUSCATION_PATTERNS = [
    (re.compile(r"eval\s*\(\s*(?:base64|atob|Buffer\.from)\s*\("), "eval() with encoding function"),
    (re.compile(r"\bexec\s*\(\s*(?:base64|binascii)"), "exec() with encoding module"),
    (re.compile(r"echo\s+[A-Za-z0-9+/=]{50,}\s*\|\s*base64\s+-d"), "pipe base64 decode to execution"),
    (re.compile(r"python[23]?\s+-c\s+['\"]import\s+base64"), "python inline base64 decode"),
    (re.compile(r"curl\s+.*\|\s*(?:bash|sh|zsh|python)"), "curl pipe to shell"),
    (re.compile(r"wget\s+.*-O\s*-\s*\|\s*(?:bash|sh|zsh)"), "wget pipe to shell"),
    (re.compile(r"\$\(\s*echo\s+[A-Za-z0-9+/=]{20,}\s*\|\s*base64\s+-d\s*\)"), "command substitution with base64"),
    (re.compile(r"\\x[0-9a-fA-F]{2}(?:\\x[0-9a-fA-F]{2}){7,}"), "hex-escaped shell string"),
    (re.compile(r"printf\s+['\"](?:\\[0-9]{3}){8,}"), "printf with octal escapes"),
    (re.compile(r"IFS=.*eval"), "IFS manipulation before eval"),
    (re.compile(r"(?:rev|tac|xxd\s+-r)\s*<<<"), "reverse/decode herestring"),
    (re.compile(r"openssl\s+(?:enc|aes|des).*-d.*\|.*(?:bash|sh)"), "openssl decrypt pipe to shell"),
]

_WORKFLOW_ENV_RE = re.compile(
    r"(?:env|environment|with):\s*\n(?:\s+\w+:\s*['\"]?[A-Za-z0-9+/=]{50,}['\"]?\s*\n)",
    re.MULTILINE,
)
_WORKFLOW_RUN_RE = re.compile(r"run:\s*\|?\s*\n((?:\s+.*\n)*)", re.MULTILINE)
_BINARY_STRING_RE = re.compile(rb"[\x20-\x7e]{60,}")
_B64_LONG_RE = re.compile(r"[A-Za-z0-9+/]{80,}={0,2}")
_HEX_LONG_RE = re.compile(r"(?:[0-9a-fA-F]{2}){40,}")

_POSTINSTALL_INDICATORS = [
    "postinstall",
    "preinstall",
    "install",
    "post_install",
    "pre_install",
    "setup.py",
    "setup.cfg",
    "__init__.py",
]

_PNG_MAGIC = b"\x89PNG\r\n\x1a\n"
_JPEG_SOI = b"\xff\xd8"
_JPEG_EOI = b"\xff\xd9"
_GIF87_MAGIC = b"GIF87a"
_GIF89_MAGIC = b"GIF89a"
_BMP_MAGIC = b"BM"
_PNG_IEND = b"IEND"

_ZIP_MAGIC = b"PK\x03\x04"
_GZIP_MAGIC = b"\x1f\x8b"

_ELF_MAGIC = b"\x7fELF"
_PE_MAGIC = b"MZ"
_MACHO_MAGICS = {
    b"\xfe\xed\xfa\xce",
    b"\xfe\xed\xfa\xcf",
    b"\xce\xfa\xed\xfe",
    b"\xcf\xfa\xed\xfe",
    b"\xca\xfe\xba\xbe",
}
_WASM_MAGIC = b"\x00asm"

_MAX_TEXT_SCAN_SIZE = 10_000_000
_MAX_ARCHIVE_DEPTH = 3
_MAX_ARCHIVE_EXTRACT = 50_000_000
_MAX_ARCHIVE_MEMBERS = 100


# ---------------------------------------------------------------------------
# Artifact type detection
# ---------------------------------------------------------------------------


def detect_artifact_type(path: Path) -> ArtifactType:
    """Classify artifact type from file path, extension, and magic bytes."""
    name = path.name.lower()
    suffix = path.suffix.lower()

    image_exts = {".png", ".jpg", ".jpeg", ".bmp", ".gif", ".ico", ".tiff", ".tif", ".webp"}
    archive_exts = {".zip", ".tar", ".gz", ".tgz", ".bz2", ".xz", ".7z", ".rar"}
    workflow_exts = {".yml", ".yaml"}
    script_exts = {".sh", ".bash", ".ps1", ".bat", ".cmd", ".py", ".rb", ".pl"}
    config_exts = {".json", ".toml", ".ini", ".cfg", ".conf", ".xml"}
    binary_exts = {".exe", ".dll", ".so", ".dylib", ".bin", ".elf", ".o", ".obj"}
    package_exts = {".whl", ".gem", ".jar", ".nupkg", ".deb", ".rpm", ".egg"}

    if suffix in image_exts:
        return ArtifactType.IMAGE
    if suffix in archive_exts or name.endswith((".tar.gz", ".tar.bz2", ".tar.xz")):
        return ArtifactType.ARCHIVE
    if suffix in binary_exts:
        return ArtifactType.BINARY
    if suffix in package_exts:
        return ArtifactType.PACKAGE_ARTIFACT
    if suffix in script_exts:
        return ArtifactType.SCRIPT

    if suffix in workflow_exts:
        if any(x in str(path).lower() for x in (".github/workflows", "gitlab-ci", "circleci", "azure-pipelines")):
            return ArtifactType.WORKFLOW
        return ArtifactType.CONFIG

    if suffix in config_exts:
        return ArtifactType.CONFIG

    if any(x in name for x in ("dockerfile", "docker-compose", "jenkinsfile", "makefile")):
        return ArtifactType.CONFIG
    if any(x in name for x in ("build", "log", "output", "console")):
        return ArtifactType.BUILD_LOG
    if suffix in (".log", ".txt") and "test" not in name:
        return ArtifactType.BUILD_LOG
    if suffix in (".tar", ".tar.gz", ".tgz") or "layer" in name:
        return ArtifactType.CONTAINER_LAYER
    if any(x in name for x in ("test", "junit", "coverage", "report")):
        return ArtifactType.TEST_OUTPUT

    try:
        with open(path, "rb") as f:
            magic = f.read(16)
        if magic[:8] == _PNG_MAGIC:
            return ArtifactType.IMAGE
        if magic[:2] == _JPEG_SOI:
            return ArtifactType.IMAGE
        if magic[:6] in (_GIF87_MAGIC, _GIF89_MAGIC):
            return ArtifactType.IMAGE
        if magic[:2] == _BMP_MAGIC:
            return ArtifactType.IMAGE
        if magic[:4] == _ZIP_MAGIC:
            return ArtifactType.ARCHIVE
        if magic[:2] == _GZIP_MAGIC:
            return ArtifactType.ARCHIVE
        if magic[:4] == _ELF_MAGIC:
            return ArtifactType.BINARY
        if magic[:2] == _PE_MAGIC:
            return ArtifactType.BINARY
        if magic[:4] in _MACHO_MAGICS:
            return ArtifactType.BINARY
        if magic[:4] == _WASM_MAGIC:
            return ArtifactType.BINARY
    except (OSError, PermissionError):
        pass

    return ArtifactType.UNKNOWN


# ---------------------------------------------------------------------------
# Image steganography scanners
# ---------------------------------------------------------------------------


def _scan_png(data: bytes, path_str: str) -> list[StegFinding]:
    """Scan PNG for steganographic indicators."""
    findings: list[StegFinding] = []

    if not data.startswith(_PNG_MAGIC):
        return findings

    # --- Appended data after IEND (always check) ---
    iend_marker = b"\x00\x00\x00\x00IEND\xaeB`\x82"
    iend_pos = data.find(iend_marker)
    if iend_pos > 0:
        end_pos = iend_pos + len(iend_marker)
        if end_pos < len(data):
            trailing = data[end_pos:]
            trailing_size = len(trailing)
            if trailing_size > 16:
                trailing_entropy = shannon_entropy(trailing[:4096])
                findings.append(StegFinding(
                    finding_type=FindingType.APPENDED_DATA,
                    confidence=min(0.95, 0.6 + trailing_size / 100000),
                    description=f"PNG has {trailing_size} bytes after IEND chunk (entropy: {trailing_entropy:.1f}/8.0)",
                    evidence=f"Data starts with: {trailing[:32].hex()}",
                    location=f"{path_str} @ offset {end_pos}",
                    offset=end_pos,
                    size=trailing_size,
                    extracted_preview=base64.b64encode(trailing[:128]).decode(),
                    metadata={"trailing_entropy": round(trailing_entropy, 2)},
                ))

    # --- Pixel-level LSB analysis (decompressed) ---
    if analyze_png_pixels is not None:
        pixel_result = analyze_png_pixels(data)

        if pixel_result is not None and pixel_result.overall_suspicious:
            for ch in pixel_result.channels:
                if ch.is_suspicious:
                    findings.append(StegFinding(
                        finding_type=FindingType.LSB_ANOMALY,
                        confidence=pixel_result.confidence,
                        description=(
                            f"PNG {ch.channel} channel LSB embedding detected "
                            f"(type: {pixel_result.embedding_type}, "
                            f"est. {ch.embedding_ratio:.0%} of pixels)"
                        ),
                        evidence=(
                            f"LSB entropy: {ch.entropy:.4f}/1.0, "
                            f"chi2_norm: {ch.chi_square_norm:.3f}, "
                            f"sequential_score: {ch.sequential_score:.2f}"
                        ),
                        location=path_str,
                        size=pixel_result.info.width * pixel_result.info.height,
                        metadata={
                            "channel": ch.channel,
                            "lsb_entropy": ch.entropy,
                            "chi_square_norm": ch.chi_square_norm,
                            "embedding_ratio": ch.embedding_ratio,
                            "sequential_score": ch.sequential_score,
                            "embedding_type": pixel_result.embedding_type,
                            "image_dimensions": f"{pixel_result.info.width}x{pixel_result.info.height}",
                        },
                    ))

            if len([c for c in pixel_result.channels if c.is_suspicious]) >= 2:
                findings.append(StegFinding(
                    finding_type=FindingType.CHI_SQUARE_ANOMALY,
                    confidence=min(0.95, pixel_result.confidence + 0.1),
                    description=(
                        f"PNG multi-channel LSB anomaly — "
                        f"{len([c for c in pixel_result.channels if c.is_suspicious])}/{len(pixel_result.channels)} "
                        f"channels show embedding indicators ({pixel_result.embedding_type})"
                    ),
                    evidence=pixel_result.details,
                    location=path_str,
                    metadata={"embedding_type": pixel_result.embedding_type},
                ))
        elif pixel_result is None:
            # Fallback: compressed IDAT analysis
            _scan_png_idat_fallback(data, path_str, findings)
    else:
        # png_analysis module not available — use IDAT fallback
        _scan_png_idat_fallback(data, path_str, findings)

    findings.extend(_check_steg_signatures(data, path_str))
    return findings


def _scan_png_idat_fallback(data: bytes, path_str: str, findings: list[StegFinding]) -> None:
    """Fallback PNG analysis using compressed IDAT data."""
    idat_data = bytearray()
    pos = 8
    while pos < len(data) - 12:
        try:
            chunk_len = struct.unpack(">I", data[pos:pos + 4])[0]
            chunk_type = data[pos + 4:pos + 8]
            if chunk_type == b"IDAT":
                chunk_data = data[pos + 8:pos + 8 + chunk_len]
                idat_data.extend(chunk_data)
            pos += 12 + chunk_len
            if chunk_type == b"IEND":
                break
        except (struct.error, IndexError):
            break

    if len(idat_data) > 256:
        _, lsb_suspicious = chi_square_lsb_test(bytes(idat_data))
        if lsb_suspicious:
            findings.append(StegFinding(
                finding_type=FindingType.CHI_SQUARE_ANOMALY,
                confidence=0.5,
                description="PNG IDAT LSB distribution anomaly (compressed-level, reduced confidence)",
                evidence="Chi-square on compressed IDAT — pixel decompression unavailable",
                location=path_str,
                size=len(idat_data),
            ))

        lsb_ent = lsb_plane_entropy(bytes(idat_data))
        if lsb_ent > 7.5:
            findings.append(StegFinding(
                finding_type=FindingType.LSB_ANOMALY,
                confidence=min(0.6, 0.3 + (lsb_ent - 7.0) / 2),
                description=f"PNG IDAT LSB entropy {lsb_ent:.2f}/8.0 (compressed-level, reduced confidence)",
                evidence=f"LSB plane entropy on compressed data: {lsb_ent:.2f}",
                location=path_str,
                metadata={"lsb_entropy": round(lsb_ent, 3), "analysis_level": "compressed"},
            ))


def _scan_jpeg(data: bytes, path_str: str) -> list[StegFinding]:
    """Scan JPEG for steganographic indicators."""
    findings: list[StegFinding] = []

    if not data.startswith(_JPEG_SOI):
        return findings

    eoi_pos = data.rfind(_JPEG_EOI)
    if eoi_pos > 0:
        end_pos = eoi_pos + 2
        if end_pos < len(data):
            trailing = data[end_pos:]
            trailing_size = len(trailing)
            if trailing_size > 16:
                trailing_entropy = shannon_entropy(trailing[:4096])
                findings.append(StegFinding(
                    finding_type=FindingType.APPENDED_DATA,
                    confidence=min(0.95, 0.6 + trailing_size / 100000),
                    description=f"JPEG has {trailing_size} bytes after EOI marker (entropy: {trailing_entropy:.1f}/8.0)",
                    evidence=f"Data starts with: {trailing[:32].hex()}",
                    location=f"{path_str} @ offset {end_pos}",
                    offset=end_pos,
                    size=trailing_size,
                    extracted_preview=base64.b64encode(trailing[:128]).decode(),
                    metadata={"trailing_entropy": round(trailing_entropy, 2)},
                ))

    sos_pos = data.find(b"\xff\xda")
    if sos_pos > 0 and eoi_pos > sos_pos:
        scan_data = data[sos_pos + 2:eoi_pos]
        if len(scan_data) > 256:
            chi2, p_val = chi_square_byte_test(scan_data)
            normalized_chi2 = chi2 / 255.0 if len(scan_data) > 0 else 0
            if normalized_chi2 < 0.8 and len(scan_data) > 10000:
                findings.append(StegFinding(
                    finding_type=FindingType.CHI_SQUARE_ANOMALY,
                    confidence=0.65,
                    description=f"JPEG scan data has anomalously uniform byte distribution (chi2/dof={normalized_chi2:.2f})",
                    evidence=f"Chi-square statistic: {chi2:.1f}, normalized: {normalized_chi2:.2f}",
                    location=path_str,
                    size=len(scan_data),
                    metadata={"chi_square": round(chi2, 2), "normalized": round(normalized_chi2, 3)},
                ))

    findings.extend(_check_steg_signatures(data, path_str))
    return findings


def _scan_bmp(data: bytes, path_str: str) -> list[StegFinding]:
    """Scan BMP for steganographic indicators."""
    findings: list[StegFinding] = []

    if not data.startswith(_BMP_MAGIC) or len(data) < 54:
        return findings

    try:
        file_size = struct.unpack("<I", data[2:6])[0]
        data_offset = struct.unpack("<I", data[10:14])[0]
        bits_per_pixel = struct.unpack("<H", data[28:30])[0]
    except struct.error:
        return findings

    if file_size < len(data) and (len(data) - file_size) > 16:
        trailing_size = len(data) - file_size
        findings.append(StegFinding(
            finding_type=FindingType.APPENDED_DATA,
            confidence=0.7,
            description=f"BMP has {trailing_size} bytes beyond declared file size",
            location=f"{path_str} @ offset {file_size}",
            offset=file_size,
            size=trailing_size,
        ))

    if data_offset < len(data) and bits_per_pixel in (24, 32):
        pixel_data = data[data_offset:]
        if len(pixel_data) > 256:
            _, lsb_suspicious = chi_square_lsb_test(pixel_data)
            if lsb_suspicious:
                findings.append(StegFinding(
                    finding_type=FindingType.LSB_ANOMALY,
                    confidence=0.75,
                    description="BMP pixel data LSBs show anomalously uniform distribution",
                    evidence="Chi-square test on LSB pairs indicates possible embedding",
                    location=path_str,
                    size=len(pixel_data),
                ))

            lsb_ent = lsb_plane_entropy(pixel_data)
            if lsb_ent > 7.5:
                findings.append(StegFinding(
                    finding_type=FindingType.LSB_ANOMALY,
                    confidence=min(0.85, 0.5 + (lsb_ent - 7.0) / 2),
                    description=f"BMP LSB plane entropy is {lsb_ent:.2f}/8.0 (near-random)",
                    location=path_str,
                    metadata={"lsb_entropy": round(lsb_ent, 3)},
                ))

    findings.extend(_check_steg_signatures(data, path_str))
    return findings


def _scan_gif(data: bytes, path_str: str) -> list[StegFinding]:
    """Scan GIF for steganographic indicators."""
    findings: list[StegFinding] = []

    if not (data.startswith(_GIF87_MAGIC) or data.startswith(_GIF89_MAGIC)):
        return findings

    trailer_pos = data.rfind(b"\x3b")
    if trailer_pos > 0 and trailer_pos < len(data) - 1:
        trailing = data[trailer_pos + 1:]
        if len(trailing) > 16:
            findings.append(StegFinding(
                finding_type=FindingType.APPENDED_DATA,
                confidence=min(0.9, 0.5 + len(trailing) / 50000),
                description=f"GIF has {len(trailing)} bytes after trailer marker",
                location=f"{path_str} @ offset {trailer_pos + 1}",
                offset=trailer_pos + 1,
                size=len(trailing),
                extracted_preview=base64.b64encode(trailing[:128]).decode(),
            ))

    findings.extend(_check_steg_signatures(data, path_str))
    return findings


def scan_image(path: Path) -> ArtifactScan:
    """Scan an image file for steganographic content."""
    path_str = str(path)
    findings: list[StegFinding] = []

    try:
        data = path.read_bytes()
    except (OSError, PermissionError):
        return ArtifactScan(path=path_str, artifact_type=ArtifactType.IMAGE)

    file_size = len(data)
    entropy = shannon_entropy(data[:100000])

    if data.startswith(_PNG_MAGIC):
        findings.extend(_scan_png(data, path_str))
    elif data.startswith(_JPEG_SOI):
        findings.extend(_scan_jpeg(data, path_str))
    elif data.startswith(_BMP_MAGIC):
        findings.extend(_scan_bmp(data, path_str))
    elif data.startswith(_GIF87_MAGIC) or data.startswith(_GIF89_MAGIC):
        findings.extend(_scan_gif(data, path_str))
    else:
        findings.extend(_check_steg_signatures(data, path_str))

    he_regions = high_entropy_regions(data, threshold=7.5) if file_size > 4096 else []

    score = _compute_score(findings)
    return ArtifactScan(
        path=path_str,
        artifact_type=ArtifactType.IMAGE,
        file_size=file_size,
        entropy=entropy,
        anomaly_score=score,
        findings=findings,
        high_entropy_regions=he_regions,
    )


def _check_steg_signatures(data: bytes, path_str: str) -> list[StegFinding]:
    """Check for known steganography tool signatures in binary data."""
    findings: list[StegFinding] = []
    for sig_name, sig_bytes, description in _STEG_SIGNATURES:
        pos = data.find(sig_bytes)
        if pos >= 0:
            findings.append(StegFinding(
                finding_type=FindingType.STEG_TOOL_SIGNATURE,
                confidence=0.85,
                description=description,
                evidence=f"Signature '{sig_name}' at offset {pos}",
                location=f"{path_str} @ offset {pos}",
                offset=pos,
                size=len(sig_bytes),
                metadata={"tool": sig_name},
            ))
    return findings


# ---------------------------------------------------------------------------
# Archive scanners
# ---------------------------------------------------------------------------


def scan_archive(path: Path) -> ArtifactScan:
    """Scan an archive file for hidden content and anomalies."""
    path_str = str(path)
    findings: list[StegFinding] = []

    try:
        data = path.read_bytes()
    except (OSError, PermissionError):
        return ArtifactScan(path=path_str, artifact_type=ArtifactType.ARCHIVE)

    file_size = len(data)
    entropy = shannon_entropy(data[:100000])

    findings.extend(_detect_polyglot(data, path_str))

    suffix = path.suffix.lower()
    name = path.name.lower()

    budget = [_MAX_ARCHIVE_EXTRACT]

    if data[:4] == _ZIP_MAGIC or suffix == ".zip":
        findings.extend(_scan_zip_bytes(data, path_str, depth=0, budget=budget))
    elif data[:2] == _GZIP_MAGIC or suffix in (".gz", ".tgz"):
        findings.extend(_scan_gzip_bytes(data, path_str, depth=0, budget=budget))

    if suffix in (".tar", ".tgz") or name.endswith(".tar.gz") or name.endswith(".tar.bz2"):
        findings.extend(_scan_tar_bytes(data, path_str, depth=0, budget=budget))

    score = _compute_score(findings)
    return ArtifactScan(
        path=path_str,
        artifact_type=ArtifactType.ARCHIVE,
        file_size=file_size,
        entropy=entropy,
        anomaly_score=score,
        findings=findings,
    )


def _detect_polyglot(data: bytes, path_str: str) -> list[StegFinding]:
    """Detect polyglot files that are valid as multiple formats."""
    findings: list[StegFinding] = []
    detected_formats: list[str] = []

    if data[:8] == _PNG_MAGIC:
        detected_formats.append("PNG")
    if data[:2] == _JPEG_SOI:
        detected_formats.append("JPEG")
    if data[:4] == _ZIP_MAGIC:
        detected_formats.append("ZIP")
    if data[:2] == _GZIP_MAGIC:
        detected_formats.append("GZIP")
    if data[:4] == _ELF_MAGIC:
        detected_formats.append("ELF")
    if data[:2] == _PE_MAGIC:
        detected_formats.append("PE/MZ")
    if data[:5] == b"%PDF-":
        detected_formats.append("PDF")
    if data.startswith(_GIF87_MAGIC) or data.startswith(_GIF89_MAGIC):
        detected_formats.append("GIF")

    zip_offset = data.find(_ZIP_MAGIC, 1)
    if zip_offset > 0 and "ZIP" not in detected_formats:
        detected_formats.append(f"ZIP@{zip_offset}")

    if len(detected_formats) > 1:
        findings.append(StegFinding(
            finding_type=FindingType.POLYGLOT,
            confidence=0.9,
            description=f"File is a polyglot: valid as {' + '.join(detected_formats)}",
            evidence=f"Detected format signatures: {', '.join(detected_formats)}",
            location=path_str,
            size=len(data),
            metadata={"formats": detected_formats},
        ))

    return findings


def _is_archive_data(data: bytes, name: str) -> str | None:
    """Detect if data is a nested archive. Returns archive type or None."""
    lower = name.lower()
    if data[:4] == _ZIP_MAGIC or lower.endswith(".zip"):
        return "zip"
    if data[:2] == _GZIP_MAGIC or lower.endswith((".gz", ".tgz")):
        return "gzip"
    if lower.endswith((".tar", ".tgz")) or lower.endswith(".tar.gz") or lower.endswith(".tar.bz2"):
        return "tar"
    if len(data) > 262 and data[257:262] == b"ustar":
        return "tar"
    return None


def _scan_nested_archive(
    member_data: bytes,
    member_name: str,
    parent_path: str,
    depth: int,
    budget: list[int],
) -> list[StegFinding]:
    """Recursively scan a nested archive."""
    if depth >= _MAX_ARCHIVE_DEPTH:
        return []
    if budget[0] <= 0:
        return []

    nested_path = f"{parent_path}!{member_name}"
    archive_type = _is_archive_data(member_data, member_name)

    if archive_type == "zip":
        return _scan_zip_bytes(member_data, nested_path, depth + 1, budget)
    elif archive_type == "gzip":
        return _scan_gzip_bytes(member_data, nested_path, depth + 1, budget)
    elif archive_type == "tar":
        return _scan_tar_bytes(member_data, nested_path, depth + 1, budget)

    return []


def _scan_zip_bytes(
    data: bytes,
    path_str: str,
    depth: int = 0,
    budget: list[int] | None = None,
) -> list[StegFinding]:
    """Scan ZIP archive from bytes with recursive support."""
    findings: list[StegFinding] = []
    if budget is None:
        budget = [_MAX_ARCHIVE_EXTRACT]

    try:
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            members_scanned = 0
            for info in zf.infolist():
                if members_scanned >= _MAX_ARCHIVE_MEMBERS:
                    break
                members_scanned += 1
                name = info.filename

                for pattern in _HIDDEN_FILE_PATTERNS:
                    if pattern.search(name):
                        findings.append(StegFinding(
                            finding_type=FindingType.HIDDEN_FILE,
                            confidence=0.6,
                            description=f"Hidden/suspicious file in archive: {name}",
                            evidence=f"Matched pattern: {pattern.pattern}",
                            location=f"{path_str}!{name}",
                            size=info.file_size,
                            metadata={"archive_member": name},
                        ))
                        break

                if info.compress_size > 0 and info.file_size > 0:
                    ratio = info.file_size / info.compress_size
                    if ratio > 100 and info.file_size > 10000:
                        findings.append(StegFinding(
                            finding_type=FindingType.COMPRESSION_RATIO_ANOMALY,
                            confidence=min(0.8, 0.4 + ratio / 1000),
                            description=f"Unusual compression ratio ({ratio:.0f}:1) for {name}",
                            evidence=f"Compressed: {info.compress_size}, Original: {info.file_size}",
                            location=f"{path_str}!{name}",
                            size=info.file_size,
                            metadata={"ratio": round(ratio, 1), "archive_member": name},
                        ))
                    elif ratio < 1.01 and info.file_size > 1000 and _is_text_extension(name):
                        findings.append(StegFinding(
                            finding_type=FindingType.COMPRESSION_RATIO_ANOMALY,
                            confidence=0.4,
                            description=f"Text file '{name}' has nearly zero compression ({ratio:.2f}:1) — may contain encrypted data",
                            location=f"{path_str}!{name}",
                            size=info.file_size,
                            metadata={"ratio": round(ratio, 2), "archive_member": name},
                        ))

                if info.file_size > budget[0] or info.file_size > 50_000_000:
                    continue

                if info.file_size < 5_000_000:
                    try:
                        member_data = zf.read(info.filename)
                        budget[0] -= len(member_data)

                        if _is_archive_data(member_data, name) and depth < _MAX_ARCHIVE_DEPTH:
                            findings.extend(_scan_nested_archive(
                                member_data, name, path_str, depth, budget,
                            ))
                        elif _is_text_extension(name):
                            text = member_data.decode("utf-8", errors="ignore")
                            member_low = _is_low_signal_file(name) or _is_minified_js(member_data)
                            findings.extend(_scan_text_for_payloads(
                                text, f"{path_str}!{name}", low_signal=member_low,
                            ))
                    except Exception:
                        pass

    except zipfile.BadZipFile:
        pass
    except Exception:
        pass

    return findings


def _scan_gzip_bytes(
    data: bytes,
    path_str: str,
    depth: int = 0,
    budget: list[int] | None = None,
) -> list[StegFinding]:
    """Scan gzip data with recursive support."""
    findings: list[StegFinding] = []
    import gzip

    if budget is None:
        budget = [_MAX_ARCHIVE_EXTRACT]

    try:
        decompressed = gzip.decompress(data)
        budget[0] -= len(decompressed)

        ratio = len(decompressed) / len(data) if len(data) > 0 else 0
        if ratio > 100 and len(decompressed) > 10000:
            findings.append(StegFinding(
                finding_type=FindingType.COMPRESSION_RATIO_ANOMALY,
                confidence=min(0.7, 0.3 + ratio / 1000),
                description=f"Unusual gzip compression ratio ({ratio:.0f}:1)",
                evidence=f"Compressed: {len(data)}, Decompressed: {len(decompressed)}",
                location=path_str,
                size=len(decompressed),
            ))

        if depth < _MAX_ARCHIVE_DEPTH and budget[0] > 0:
            nested_type = _is_archive_data(decompressed, "")
            if nested_type == "tar":
                findings.extend(_scan_tar_bytes(
                    decompressed, path_str, depth + 1, budget,
                ))
    except Exception:
        pass

    return findings


def _scan_tar_bytes(
    data: bytes,
    path_str: str,
    depth: int = 0,
    budget: list[int] | None = None,
) -> list[StegFinding]:
    """Scan tar archive from bytes with recursive support."""
    findings: list[StegFinding] = []
    if budget is None:
        budget = [_MAX_ARCHIVE_EXTRACT]

    try:
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:*") as tf:
            members_scanned = 0
            for member in tf.getmembers():
                if members_scanned >= _MAX_ARCHIVE_MEMBERS:
                    break
                members_scanned += 1
                name = member.name

                for pattern in _HIDDEN_FILE_PATTERNS:
                    if pattern.search(name):
                        findings.append(StegFinding(
                            finding_type=FindingType.HIDDEN_FILE,
                            confidence=0.6,
                            description=f"Hidden/suspicious file in tar: {name}",
                            evidence=f"Matched pattern: {pattern.pattern}",
                            location=f"{path_str}!{name}",
                            size=member.size,
                            metadata={"archive_member": name},
                        ))
                        break

                if member.isfile() and member.size > 50_000_000:
                    findings.append(StegFinding(
                        finding_type=FindingType.SIZE_ANOMALY,
                        confidence=0.3,
                        description=f"Large file in archive: {name} ({member.size / 1_000_000:.1f}MB)",
                        location=f"{path_str}!{name}",
                        size=member.size,
                    ))

                if not member.isfile() or member.size > budget[0] or member.size > 50_000_000:
                    continue

                if member.size < 5_000_000:
                    try:
                        f = tf.extractfile(member)
                        if f:
                            member_data = f.read()
                            budget[0] -= len(member_data)

                            if _is_archive_data(member_data, name) and depth < _MAX_ARCHIVE_DEPTH:
                                findings.extend(_scan_nested_archive(
                                    member_data, name, path_str, depth, budget,
                                ))
                            elif _is_text_extension(name):
                                text = member_data.decode("utf-8", errors="ignore")
                                member_low = _is_low_signal_file(name) or _is_minified_js(member_data)
                                findings.extend(_scan_text_for_payloads(
                                    text, f"{path_str}!{name}", low_signal=member_low,
                                ))
                    except Exception:
                        pass

    except (tarfile.TarError, OSError):
        pass

    return findings


# ---------------------------------------------------------------------------
# Build artifact scanners
# ---------------------------------------------------------------------------


def scan_build_artifact(path: Path) -> ArtifactScan:
    """Scan build artifacts: scripts, configs, workflows, package files."""
    path_str = str(path)
    artifact_type = detect_artifact_type(path)
    findings: list[StegFinding] = []

    try:
        data = path.read_bytes()
    except (OSError, PermissionError):
        return ArtifactScan(path=path_str, artifact_type=artifact_type)

    file_size = len(data)
    entropy = shannon_entropy(data[:100000])
    text = data.decode("utf-8", errors="ignore")

    name = path.name.lower()
    suffix = path.suffix.lower()

    low_signal = _is_low_signal_file(name) or _is_minified_js(data)
    findings.extend(_scan_text_for_payloads(text, path_str, low_signal=low_signal))
    findings.extend(_scan_for_obfuscation(text, path_str))

    if suffix in (".yml", ".yaml"):
        findings.extend(_scan_workflow_yaml(text, path_str))

    if name == "package.json":
        findings.extend(_scan_package_json(text, path_str))

    if name in ("setup.py", "setup.cfg", "pyproject.toml"):
        findings.extend(_scan_python_package(text, path_str))

    if "dockerfile" in name or name == "dockerfile":
        findings.extend(_scan_dockerfile(text, path_str))

    score = _compute_score(findings)
    return ArtifactScan(
        path=path_str,
        artifact_type=artifact_type,
        file_size=file_size,
        entropy=entropy,
        anomaly_score=score,
        findings=findings,
    )


def _scan_text_for_payloads(
    text: str,
    location: str,
    low_signal: bool = False,
) -> list[StegFinding]:
    """Scan text content for encoded payloads using the decoders module."""
    findings: list[StegFinding] = []

    detections = detect_all_encodings(text)
    for det in detections:
        blob = decode_blob(det)
        if blob is None:
            continue

        summary = summarize_blob(blob)
        content_type = _context_label(location, summary["content_type"])
        summary["content_type"] = content_type

        if content_type in ("ASN.1/DER (certificate/key)", "PKI data (certificate/key)"):
            continue
        if is_likely_certificate(blob.decoded_data):
            continue

        benign_types = {
            "PNG image", "JPEG image", "GIF image",
            "JSON data", "XML data", "YAML data", "text",
            "protobuf data", "MessagePack data", "BSON document",
            "SQLite database",
            "low-entropy binary", "structured binary data",
        }
        if content_type in benign_types and blob.layers == 1:
            continue

        finding_type = FindingType.ENCODED_PAYLOAD
        if det.encoding == "base64":
            finding_type = FindingType.BASE64_BLOCK
        elif det.encoding == "hex":
            finding_type = FindingType.HEX_BLOCK
        elif det.encoding == "url":
            finding_type = FindingType.URL_ENCODED_BLOCK

        if blob.layers > 1:
            finding_type = FindingType.MULTI_LAYER_ENCODING

        confidence = 0.3
        if blob.decoded_entropy > 6.5:
            confidence += 0.2
        if blob.decoded_entropy > 7.0:
            confidence += 0.15
        if blob.encoded_length > 500:
            confidence += 0.1
        if blob.layers > 1:
            confidence += 0.15
        confidence = min(0.95, confidence)

        if low_signal:
            confidence *= 0.4

        min_entropy = 6.0 if not low_signal else 7.0
        min_size = 200 if not low_signal else 500

        should_flag = (
            blob.layers > 1
            or blob.decoded_entropy > min_entropy
            or blob.encoded_length > min_size
        )

        if not should_flag:
            continue

        if confidence < 0.15:
            continue

        findings.append(StegFinding(
            finding_type=finding_type,
            confidence=confidence,
            description=(
                f"{det.encoding.upper()} block ({blob.encoded_length} chars, "
                f"{blob.layers} layer{'s' if blob.layers > 1 else ''}) "
                f"decodes to {content_type} "
                f"(entropy: {blob.decoded_entropy:.1f}/8.0)"
            ),
            evidence=f"Decoded size: {len(blob.decoded_data)}, type: {content_type}",
            location=f"{location} @ offset {det.offset}",
            offset=det.offset,
            size=blob.encoded_length,
            extracted_preview=summary["preview_b64"],
            metadata=summary,
        ))

    return _aggregate_findings(findings, location)


def _scan_for_obfuscation(text: str, location: str) -> list[StegFinding]:
    """Scan text for obfuscated commands."""
    findings: list[StegFinding] = []

    for pattern, description in _OBFUSCATION_PATTERNS:
        for m in pattern.finditer(text):
            start = max(0, m.start() - 50)
            end = min(len(text), m.end() + 100)
            context = text[start:end].strip()

            findings.append(StegFinding(
                finding_type=FindingType.OBFUSCATED_COMMAND,
                confidence=0.75,
                description=f"Obfuscated command pattern: {description}",
                evidence=context[:200],
                location=f"{location} @ offset {m.start()}",
                offset=m.start(),
                size=m.end() - m.start(),
            ))

    return findings


def _scan_workflow_yaml(text: str, location: str) -> list[StegFinding]:
    """Scan CI/CD workflow YAML for suspicious patterns."""
    findings: list[StegFinding] = []

    for m in _WORKFLOW_ENV_RE.finditer(text):
        findings.append(StegFinding(
            finding_type=FindingType.WORKFLOW_OBFUSCATION,
            confidence=0.6,
            description="Workflow contains large inline encoded value in environment variable",
            evidence=m.group(0)[:200],
            location=f"{location} @ offset {m.start()}",
            offset=m.start(),
        ))

    for m in _WORKFLOW_RUN_RE.finditer(text):
        block = m.group(1)
        block_findings = _scan_for_obfuscation(block, location)
        findings.extend(block_findings)

    return findings


def _scan_package_json(text: str, location: str) -> list[StegFinding]:
    """Scan package.json for suspicious post-install scripts."""
    findings: list[StegFinding] = []

    try:
        pkg = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        return findings

    scripts = pkg.get("scripts", {})
    if not isinstance(scripts, dict):
        return findings

    for key in ("preinstall", "postinstall", "install", "prepare"):
        if key in scripts:
            script_val = str(scripts[key])

            if any(x in script_val.lower() for x in ("base64", "eval", "exec", "atob", "buffer.from")):
                findings.append(StegFinding(
                    finding_type=FindingType.POSTINSTALL_PAYLOAD,
                    confidence=0.8,
                    description=f"npm {key} script contains encoding/execution function",
                    evidence=script_val[:300],
                    location=f"{location} scripts.{key}",
                    metadata={"script_key": key, "script_value": script_val[:500]},
                ))

            if re.search(r"(?:curl|wget)\s+.*\|\s*(?:bash|sh|node)", script_val):
                findings.append(StegFinding(
                    finding_type=FindingType.POSTINSTALL_PAYLOAD,
                    confidence=0.85,
                    description=f"npm {key} script pipes remote content to interpreter",
                    evidence=script_val[:300],
                    location=f"{location} scripts.{key}",
                    metadata={"script_key": key},
                ))

    return findings


def _scan_python_package(text: str, location: str) -> list[StegFinding]:
    """Scan Python package metadata for suspicious install hooks."""
    findings: list[StegFinding] = []

    if "base64" in text and ("exec" in text or "eval" in text):
        findings.append(StegFinding(
            finding_type=FindingType.POSTINSTALL_PAYLOAD,
            confidence=0.75,
            description="Python setup script uses base64 with exec/eval",
            evidence=text[:500],
            location=location,
        ))

    if "cmdclass" in text and any(x in text for x in ("install", "develop", "egg_info")):
        if any(x in text for x in ("base64", "urllib", "requests.get", "subprocess")):
            findings.append(StegFinding(
                finding_type=FindingType.POSTINSTALL_PAYLOAD,
                confidence=0.65,
                description="Python package overrides install command with network/encoding operations",
                evidence=text[:500],
                location=location,
            ))

    return findings


def _scan_dockerfile(text: str, location: str) -> list[StegFinding]:
    """Scan Dockerfile for suspicious patterns."""
    findings: list[StegFinding] = []

    lines = text.split("\n")
    for i, line in enumerate(lines):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue

        if stripped.startswith(("RUN ", "ENV ", "ARG ")):
            b64_matches = re.findall(r"[A-Za-z0-9+/]{80,}={0,2}", stripped)
            for b64 in b64_matches:
                findings.append(StegFinding(
                    finding_type=FindingType.DOCKER_SUSPICIOUS_LAYER,
                    confidence=0.7,
                    description=f"Dockerfile line {i + 1} contains large base64 blob ({len(b64)} chars)",
                    evidence=stripped[:300],
                    location=f"{location}:{i + 1}",
                    offset=i,
                    size=len(b64),
                ))

        if stripped.startswith("RUN "):
            cmd = stripped[4:]
            if re.search(r"(?:curl|wget)\s+.*\|\s*(?:bash|sh|python)", cmd):
                findings.append(StegFinding(
                    finding_type=FindingType.DOCKER_SUSPICIOUS_LAYER,
                    confidence=0.6,
                    description=f"Dockerfile RUN pipes remote content to interpreter (line {i + 1})",
                    evidence=cmd[:300],
                    location=f"{location}:{i + 1}",
                ))

    return findings


# ---------------------------------------------------------------------------
# Binary artifact scanners
# ---------------------------------------------------------------------------


def scan_binary(path: Path) -> ArtifactScan:
    """Scan binary artifacts (ELF, PE, Mach-O, generic) for anomalies."""
    path_str = str(path)
    findings: list[StegFinding] = []

    try:
        data = path.read_bytes()
    except (OSError, PermissionError):
        return ArtifactScan(path=path_str, artifact_type=ArtifactType.BINARY)

    file_size = len(data)
    entropy = shannon_entropy(data[:100000])

    if entropy > 7.5 and file_size > 10000:
        findings.append(StegFinding(
            finding_type=FindingType.HIGH_ENTROPY,
            confidence=min(0.8, 0.4 + (entropy - 7.0) / 2),
            description=f"Binary has unusually high entropy ({entropy:.2f}/8.0) — possible packed/encrypted payload",
            location=path_str,
            size=file_size,
            metadata={"entropy": round(entropy, 3)},
        ))

    he_regions = high_entropy_regions(data, threshold=7.5)

    if data[:4] == _ELF_MAGIC:
        findings.extend(_scan_elf(data, path_str))
    elif data[:2] == _PE_MAGIC:
        findings.extend(_scan_pe(data, path_str))
    elif data[:4] in _MACHO_MAGICS:
        if analyze_macho is not None:
            findings.extend(analyze_macho(data, path_str))

    findings.extend(_scan_binary_strings(data, path_str))

    score = _compute_score(findings)
    return ArtifactScan(
        path=path_str,
        artifact_type=ArtifactType.BINARY,
        file_size=file_size,
        entropy=entropy,
        anomaly_score=score,
        findings=findings,
        high_entropy_regions=he_regions,
    )


def _scan_elf(data: bytes, path_str: str) -> list[StegFinding]:
    """Analyze ELF binary sections for anomalies."""
    findings: list[StegFinding] = []

    if len(data) < 64:
        return findings

    try:
        ei_class = data[4]
        ei_data = data[5]

        if ei_class == 2 and ei_data == 1:  # 64-bit LE
            fmt = "<"
            e_shoff = struct.unpack(fmt + "Q", data[40:48])[0]
            e_shentsize = struct.unpack(fmt + "H", data[58:60])[0]
            e_shnum = struct.unpack(fmt + "H", data[60:62])[0]

            if e_shoff == 0 or e_shnum == 0 or e_shentsize < 64:
                return findings

            for i in range(e_shnum):
                sh_offset = e_shoff + i * e_shentsize
                if sh_offset + e_shentsize > len(data):
                    break

                sh_type = struct.unpack(fmt + "I", data[sh_offset + 4:sh_offset + 8])[0]
                sh_size = struct.unpack(fmt + "Q", data[sh_offset + 32:sh_offset + 40])[0]
                sh_file_offset = struct.unpack(fmt + "Q", data[sh_offset + 24:sh_offset + 32])[0]

                if sh_size == 0 or sh_size > len(data):
                    continue

                section_data = data[sh_file_offset:sh_file_offset + min(sh_size, 100000)]
                if len(section_data) > 256:
                    sect_entropy = shannon_entropy(section_data)

                    if sh_type == 1 and sect_entropy > 7.5 and sh_size > 10000:
                        findings.append(StegFinding(
                            finding_type=FindingType.HIGH_ENTROPY_SECTION,
                            confidence=min(0.8, 0.4 + (sect_entropy - 7.0) / 2),
                            description=f"ELF section {i} has high entropy ({sect_entropy:.2f}/8.0, {sh_size} bytes)",
                            location=f"{path_str} section {i}",
                            offset=sh_file_offset,
                            size=sh_size,
                            metadata={"section_index": i, "section_type": sh_type, "entropy": round(sect_entropy, 3)},
                        ))

                    if sh_size > 5_000_000 and sh_type == 1:
                        findings.append(StegFinding(
                            finding_type=FindingType.UNUSUAL_SECTION_SIZE,
                            confidence=0.4,
                            description=f"ELF section {i} is unusually large ({sh_size / 1_000_000:.1f}MB)",
                            location=f"{path_str} section {i}",
                            offset=sh_file_offset,
                            size=sh_size,
                        ))

        elif ei_class == 1 and ei_data == 1:  # 32-bit LE
            fmt = "<"
            e_shoff = struct.unpack(fmt + "I", data[32:36])[0]
            e_shentsize = struct.unpack(fmt + "H", data[46:48])[0]
            e_shnum = struct.unpack(fmt + "H", data[48:50])[0]

            if e_shoff == 0 or e_shnum == 0 or e_shentsize < 40:
                return findings

            for i in range(e_shnum):
                sh_offset = e_shoff + i * e_shentsize
                if sh_offset + e_shentsize > len(data):
                    break

                sh_type = struct.unpack(fmt + "I", data[sh_offset + 4:sh_offset + 8])[0]
                sh_size = struct.unpack(fmt + "I", data[sh_offset + 20:sh_offset + 24])[0]
                sh_file_offset = struct.unpack(fmt + "I", data[sh_offset + 16:sh_offset + 20])[0]

                if sh_size == 0 or sh_size > len(data):
                    continue

                section_data = data[sh_file_offset:sh_file_offset + min(sh_size, 100000)]
                if len(section_data) > 256:
                    sect_entropy = shannon_entropy(section_data)
                    if sh_type == 1 and sect_entropy > 7.5 and sh_size > 10000:
                        findings.append(StegFinding(
                            finding_type=FindingType.HIGH_ENTROPY_SECTION,
                            confidence=min(0.8, 0.4 + (sect_entropy - 7.0) / 2),
                            description=f"ELF section {i} has high entropy ({sect_entropy:.2f}/8.0, {sh_size} bytes)",
                            location=f"{path_str} section {i}",
                            offset=sh_file_offset,
                            size=sh_size,
                            metadata={"section_index": i, "entropy": round(sect_entropy, 3)},
                        ))

    except (struct.error, IndexError):
        pass

    return findings


def _scan_pe(data: bytes, path_str: str) -> list[StegFinding]:
    """Analyze PE (Windows) binary sections for anomalies."""
    findings: list[StegFinding] = []

    if len(data) < 64 or data[:2] != _PE_MAGIC:
        return findings

    try:
        pe_offset = struct.unpack("<I", data[0x3C:0x40])[0]
        if pe_offset + 24 > len(data):
            return findings

        if data[pe_offset:pe_offset + 4] != b"PE\x00\x00":
            return findings

        num_sections = struct.unpack("<H", data[pe_offset + 6:pe_offset + 8])[0]
        optional_header_size = struct.unpack("<H", data[pe_offset + 20:pe_offset + 22])[0]

        section_start = pe_offset + 24 + optional_header_size

        for i in range(num_sections):
            sh_offset = section_start + i * 40
            if sh_offset + 40 > len(data):
                break

            section_name = data[sh_offset:sh_offset + 8].rstrip(b"\x00").decode("ascii", errors="replace")
            virtual_size = struct.unpack("<I", data[sh_offset + 8:sh_offset + 12])[0]
            raw_size = struct.unpack("<I", data[sh_offset + 16:sh_offset + 20])[0]
            raw_offset = struct.unpack("<I", data[sh_offset + 20:sh_offset + 24])[0]

            if raw_size == 0 or raw_offset + raw_size > len(data):
                continue

            section_data = data[raw_offset:raw_offset + min(raw_size, 100000)]
            if len(section_data) > 256:
                sect_entropy = shannon_entropy(section_data)

                if sect_entropy > 7.5 and raw_size > 10000:
                    findings.append(StegFinding(
                        finding_type=FindingType.HIGH_ENTROPY_SECTION,
                        confidence=min(0.8, 0.4 + (sect_entropy - 7.0) / 2),
                        description=f"PE section '{section_name}' has high entropy ({sect_entropy:.2f}/8.0, {raw_size} bytes)",
                        location=f"{path_str} section '{section_name}'",
                        offset=raw_offset,
                        size=raw_size,
                        metadata={
                            "section_name": section_name,
                            "section_index": i,
                            "entropy": round(sect_entropy, 3),
                            "virtual_size": virtual_size,
                            "raw_size": raw_size,
                        },
                    ))

                if virtual_size > 0 and raw_size > 0:
                    size_ratio = max(virtual_size, raw_size) / min(virtual_size, raw_size)
                    if size_ratio > 10 and max(virtual_size, raw_size) > 100000:
                        findings.append(StegFinding(
                            finding_type=FindingType.UNUSUAL_SECTION_SIZE,
                            confidence=0.5,
                            description=f"PE section '{section_name}' has large virtual/raw size discrepancy (ratio: {size_ratio:.1f})",
                            location=f"{path_str} section '{section_name}'",
                            offset=raw_offset,
                            size=raw_size,
                            metadata={"virtual_size": virtual_size, "raw_size": raw_size, "ratio": round(size_ratio, 1)},
                        ))

    except (struct.error, IndexError):
        pass

    return findings


def _scan_binary_strings(data: bytes, path_str: str) -> list[StegFinding]:
    """Scan binary for long encoded strings (base64, hex blobs)."""
    findings: list[StegFinding] = []

    for m in _BINARY_STRING_RE.finditer(data[:2_000_000]):
        s = m.group(0).decode("ascii")

        b64_match = _B64_LONG_RE.search(s)
        if b64_match:
            block = b64_match.group(0)
            try:
                decoded = base64.b64decode(block + "==" * (4 - len(block) % 4) if len(block) % 4 else block)
                dec_entropy = shannon_entropy(decoded)
                if dec_entropy > 6.0 and len(decoded) > 32:
                    findings.append(StegFinding(
                        finding_type=FindingType.EMBEDDED_STRINGS,
                        confidence=min(0.8, 0.4 + (dec_entropy - 6.0) / 4),
                        description=f"Embedded base64 string in binary ({len(block)} chars, decodes to {len(decoded)} bytes, entropy {dec_entropy:.1f})",
                        location=f"{path_str} @ offset {m.start()}",
                        offset=m.start(),
                        size=len(block),
                        extracted_preview=base64.b64encode(decoded[:64]).decode(),
                    ))
            except Exception:
                pass

        hex_match = _HEX_LONG_RE.search(s)
        if hex_match:
            block = hex_match.group(0)
            try:
                decoded = bytes.fromhex(block)
                dec_entropy = shannon_entropy(decoded)
                if dec_entropy > 6.0 and len(decoded) > 32:
                    findings.append(StegFinding(
                        finding_type=FindingType.EMBEDDED_STRINGS,
                        confidence=min(0.7, 0.3 + (dec_entropy - 6.0) / 4),
                        description=f"Embedded hex blob in binary ({len(block)} chars, decodes to {len(decoded)} bytes, entropy {dec_entropy:.1f})",
                        location=f"{path_str} @ offset {m.start()}",
                        offset=m.start(),
                        size=len(block),
                    ))
            except Exception:
                pass

    return findings


# ---------------------------------------------------------------------------
# Build log / container layer scanners
# ---------------------------------------------------------------------------


def scan_build_log(path: Path) -> ArtifactScan:
    """Scan a build log for embedded steganographic content."""
    path_str = str(path)
    findings: list[StegFinding] = []

    try:
        data = path.read_bytes()
        text = data.decode("utf-8", errors="ignore")
    except (OSError, PermissionError):
        return ArtifactScan(path=path_str, artifact_type=ArtifactType.BUILD_LOG)

    file_size = len(data)
    entropy = shannon_entropy(data[:100000])

    findings.extend(_scan_text_for_payloads(text, path_str))
    findings.extend(_scan_for_obfuscation(text, path_str))

    if file_size > 10_000_000:
        findings.append(StegFinding(
            finding_type=FindingType.SIZE_ANOMALY,
            confidence=0.4,
            description=f"Unusually large build log ({file_size / 1_000_000:.1f}MB)",
            location=path_str,
            size=file_size,
        ))

    score = _compute_score(findings)
    return ArtifactScan(
        path=path_str,
        artifact_type=ArtifactType.BUILD_LOG,
        file_size=file_size,
        entropy=entropy,
        anomaly_score=score,
        findings=findings,
    )


def scan_container_layer(path: Path) -> ArtifactScan:
    """Scan a container layer for hidden files and suspicious content."""
    path_str = str(path)
    findings: list[StegFinding] = []
    file_size = path.stat().st_size if path.exists() else 0

    if path.is_dir():
        for f in path.rglob("*"):
            if not f.is_file():
                continue

            name = f.name

            if name.startswith(".") and f.stat().st_size > 1024:
                try:
                    fdata = f.read_bytes()[:10000]
                    ent = shannon_entropy(fdata)
                    if ent > 7.0:
                        findings.append(StegFinding(
                            finding_type=FindingType.HIDDEN_FILE,
                            confidence=0.7,
                            description=f"Hidden high-entropy file in container layer: {name} ({ent:.1f}/8.0)",
                            location=str(f),
                            size=f.stat().st_size,
                            metadata={"entropy": round(ent, 2)},
                        ))
                except (OSError, PermissionError):
                    pass

            try:
                with open(f, "rb") as fh:
                    magic = fh.read(4)
                if magic == _ELF_MAGIC and not any(
                    x in str(f) for x in ("/bin/", "/sbin/", "/lib/", "/usr/")
                ):
                    findings.append(StegFinding(
                        finding_type=FindingType.UNEXPECTED_BINARY,
                        confidence=0.5,
                        description=f"Unexpected ELF binary in container layer: {f.relative_to(path)}",
                        location=str(f),
                        size=f.stat().st_size,
                    ))
            except (OSError, PermissionError):
                pass

    elif path.is_file():
        try:
            data = path.read_bytes()
        except (OSError, PermissionError):
            data = b""
        if data:
            budget = [_MAX_ARCHIVE_EXTRACT]
            findings.extend(_scan_tar_bytes(data, path_str, depth=0, budget=budget))

    score = _compute_score(findings)
    return ArtifactScan(
        path=path_str,
        artifact_type=ArtifactType.CONTAINER_LAYER,
        file_size=file_size,
        anomaly_score=score,
        findings=findings,
    )


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------


def scan_artifact(path: Path) -> ArtifactScan:
    """Auto-detect artifact type and scan with appropriate scanner."""
    if not path.exists():
        return ArtifactScan(path=str(path), artifact_type=ArtifactType.UNKNOWN)

    artifact_type = detect_artifact_type(path)

    dispatch = {
        ArtifactType.IMAGE: scan_image,
        ArtifactType.ARCHIVE: scan_archive,
        ArtifactType.BINARY: scan_binary,
        ArtifactType.BUILD_LOG: scan_build_log,
        ArtifactType.CONTAINER_LAYER: scan_container_layer,
        ArtifactType.WORKFLOW: scan_build_artifact,
        ArtifactType.SCRIPT: scan_build_artifact,
        ArtifactType.CONFIG: scan_build_artifact,
        ArtifactType.PACKAGE_ARTIFACT: scan_archive,
    }

    scanner = dispatch.get(artifact_type)
    if scanner:
        return scanner(path)

    return _generic_scan(path, artifact_type)


def _generic_scan(path: Path, artifact_type: ArtifactType) -> ArtifactScan:
    """Fallback scanner for unrecognized artifact types."""
    path_str = str(path)
    findings: list[StegFinding] = []

    try:
        data = path.read_bytes()
    except (OSError, PermissionError):
        return ArtifactScan(path=path_str, artifact_type=artifact_type)

    file_size = len(data)
    entropy = shannon_entropy(data[:100000])

    if entropy > 7.5 and file_size > 10000:
        findings.append(StegFinding(
            finding_type=FindingType.HIGH_ENTROPY,
            confidence=0.5,
            description=f"High-entropy artifact ({entropy:.2f}/8.0)",
            location=path_str,
            size=file_size,
        ))

    if file_size <= _MAX_TEXT_SCAN_SIZE:
        try:
            text = data.decode("utf-8", errors="ignore")
            low_signal = _is_low_signal_file(path.name) or _is_minified_js(data)
            findings.extend(_scan_text_for_payloads(text, path_str, low_signal=low_signal))
            findings.extend(_scan_for_obfuscation(text, path_str))
        except Exception:
            pass

    he_regions = high_entropy_regions(data, threshold=7.5) if file_size > 4096 else []

    score = _compute_score(findings)
    return ArtifactScan(
        path=path_str,
        artifact_type=artifact_type,
        file_size=file_size,
        entropy=entropy,
        anomaly_score=score,
        findings=findings,
        high_entropy_regions=he_regions,
    )


# ---------------------------------------------------------------------------
# Scoring
# ---------------------------------------------------------------------------


def _compute_score(findings: list[StegFinding]) -> float:
    """Compute anomaly score (0-100) from findings.

    Uses a weighted sum with diminishing returns.
    """
    if not findings:
        return 0.0

    type_weights: dict[FindingType, float] = {
        FindingType.POLYGLOT: 35,
        FindingType.APPENDED_DATA: 30,
        FindingType.STEG_TOOL_SIGNATURE: 35,
        FindingType.MULTI_LAYER_ENCODING: 30,
        FindingType.LSB_ANOMALY: 25,
        FindingType.CHI_SQUARE_ANOMALY: 20,
        FindingType.POSTINSTALL_PAYLOAD: 30,
        FindingType.OBFUSCATED_COMMAND: 25,
        FindingType.DOCKER_SUSPICIOUS_LAYER: 20,
        FindingType.WORKFLOW_OBFUSCATION: 20,
        FindingType.HIGH_ENTROPY_SECTION: 20,
        FindingType.HIGH_ENTROPY: 15,
        FindingType.HIDDEN_FILE: 15,
        FindingType.ENCODED_PAYLOAD: 15,
        FindingType.BASE64_BLOCK: 12,
        FindingType.HEX_BLOCK: 12,
        FindingType.URL_ENCODED_BLOCK: 10,
        FindingType.EMBEDDED_STRINGS: 15,
        FindingType.COMPRESSION_RATIO_ANOMALY: 12,
        FindingType.SIZE_ANOMALY: 8,
        FindingType.UNUSUAL_SECTION_SIZE: 10,
        FindingType.UNEXPECTED_BINARY: 15,
    }
    default_weight = 10

    type_counts: dict[FindingType, int] = {}
    score = 0.0

    for f in findings:
        ft = f.finding_type
        type_counts[ft] = type_counts.get(ft, 0) + 1
        count = type_counts[ft]
        weight = type_weights.get(ft, default_weight)

        diminish = min(count - 1, 10)
        contribution = weight * f.confidence / (2 ** diminish)
        score += contribution

    return min(100.0, round(score, 1))


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _is_text_extension(name: str) -> bool:
    """Check if a filename likely contains text content."""
    text_exts = {
        ".txt", ".log", ".md", ".rst", ".json", ".yml", ".yaml",
        ".xml", ".html", ".htm", ".css", ".js", ".ts", ".py",
        ".rb", ".pl", ".sh", ".bash", ".zsh", ".fish", ".ps1",
        ".bat", ".cmd", ".cfg", ".conf", ".ini", ".toml", ".env",
        ".csv", ".sql", ".java", ".c", ".cpp", ".h", ".go",
        ".rs", ".swift", ".kt", ".scala", ".r", ".m",
    }
    suffix = Path(name).suffix.lower()
    return suffix in text_exts


def _is_low_signal_file(name: str) -> bool:
    """Check if a file is expected to contain encoded content."""
    lower = name.lower()
    name_only = Path(lower).name
    cert_exts = {
        ".pem", ".crt", ".cer", ".der", ".p12", ".pfx",
        ".key", ".pub", ".jks", ".keystore", ".p7b", ".p7c",
    }
    suffix = Path(lower).suffix
    if suffix in cert_exts:
        return True
    if lower.endswith((".min.js", ".bundle.js", ".chunk.js",
                       ".min.mjs", ".bundle.mjs")):
        return True
    if lower.endswith((".map", ".js.map", ".css.map")):
        return True
    if name_only in ("package-lock.json", "yarn.lock", "pnpm-lock.yaml",
                     "Gemfile.lock", "poetry.lock", "Cargo.lock",
                     "composer.lock", "go.sum"):
        return True
    if suffix in (".woff", ".woff2", ".ttf", ".otf", ".eot"):
        return True
    if suffix in (".sqlite", ".db", ".ldb", ".log"):
        return True
    return False


_JS_INDICATORS = re.compile(
    rb"(?:function\s*\(|=>\s*\{|"
    rb"var\s+\w|let\s+\w|const\s+\w|"
    rb"module\.exports|require\(|"
    rb"exports\.\w|__webpack|"
    rb"\)\s*\{|\}\s*\))",
)


def _is_minified_js(data: bytes) -> bool:
    """Heuristic: is this data likely a minified JS bundle?"""
    sample = data[:20000]
    if len(sample) < 1000:
        return False
    hits = len(_JS_INDICATORS.findall(sample))
    density = hits / (len(sample) / 1000)
    return density > 3.0


# ---------------------------------------------------------------------------
# Context-aware content classification
# ---------------------------------------------------------------------------

_GENERIC_CONTENT_TYPES: frozenset[str] = frozenset({
    "unknown",
    "encoded token/credential data",
    "high-entropy binary (likely encrypted)",
    "structured binary data",
    "low-entropy binary",
    "high-entropy binary",
})


def _context_label(path: str, content_type: str) -> str:
    """Return a more specific content label when the file path provides context."""
    if content_type not in _GENERIC_CONTENT_TYPES:
        return content_type

    lower_path = path.lower()
    name = Path(path).name.lower()

    if "cookies/" in lower_path or "cookies" in name:
        return "browser cookie (encrypted)"
    if "history/" in lower_path or "history" in name:
        return "browser history URL data"
    if "passwords" in name:
        return "credential store data"
    if "tokens.txt" in name or "tokens/" in lower_path:
        return "authentication token"
    if "autofill/" in lower_path or "autofill" in name:
        return "browser autofill data"
    if "bankcards/" in lower_path or "bankcards" in name or "cards" in name:
        return "payment card data"
    if "localstorage/" in lower_path or "localstorage" in name:
        return "browser local storage blob"
    if "plugins/" in lower_path or "extension" in lower_path:
        return "browser extension data"
    if "steam" in lower_path:
        return "Steam session data"
    if "discord" in lower_path:
        return "Discord token/session data"
    if "telegram" in lower_path:
        return "Telegram session data"
    if name.endswith(".ldb"):
        return "LevelDB record"
    if "googleaccounts" in lower_path:
        return "Google account data"
    if "soft/" in lower_path:
        return "application session data"
    if "downloads/" in lower_path:
        return "download history record"

    return content_type


# ---------------------------------------------------------------------------
# Finding aggregation
# ---------------------------------------------------------------------------


def _aggregate_findings(findings: list[StegFinding], location: str) -> list[StegFinding]:
    """Collapse repetitive findings into summary findings."""
    if len(findings) <= 3:
        return findings

    from collections import defaultdict

    groups: dict[tuple, list[StegFinding]] = defaultdict(list)
    outliers: list[StegFinding] = []

    for f in findings:
        layers = f.metadata.get("layers", 1) if f.metadata else 1
        content_type = f.metadata.get("content_type", "") if f.metadata else ""

        if layers > 2 or f.confidence >= 0.8:
            outliers.append(f)
            continue

        key = (f.finding_type, content_type, layers)
        groups[key].append(f)

    result: list[StegFinding] = list(outliers)

    for (ftype, ctype, layers), group in groups.items():
        if len(group) <= 3:
            result.extend(group)
            continue

        entropies = []
        sizes = []
        max_conf = 0.0
        for f in group:
            max_conf = max(max_conf, f.confidence)
            if f.metadata:
                ent = f.metadata.get("decoded_entropy", 0)
                if ent:
                    entropies.append(ent)
            if f.size:
                sizes.append(f.size)

        avg_ent = sum(entropies) / len(entropies) if entropies else 0
        min_size = min(sizes) if sizes else 0
        max_size = max(sizes) if sizes else 0

        layer_desc = f"{layers} layer{'s' if layers > 1 else ''}"
        ctype_desc = ctype or "unclassified"
        size_desc = f"{min_size}-{max_size} chars" if min_size != max_size else f"{min_size} chars"

        result.append(StegFinding(
            finding_type=ftype,
            confidence=max_conf,
            description=(
                f"{len(group)} encoded blobs: {ftype.value} ({layer_desc}, "
                f"avg entropy {avg_ent:.1f}/8.0, {size_desc}). "
                f"Content: {ctype_desc}"
            ),
            evidence=f"Aggregated from {len(group)} individual findings",
            location=location,
            offset=group[0].offset,
            size=sum(sizes),
            metadata={
                "aggregated_count": len(group),
                "content_type": ctype,
                "layers": layers,
                "avg_entropy": round(avg_ent, 2),
                "max_confidence": round(max_conf, 2),
                "size_range": [min_size, max_size],
                "entropy_range": [round(min(entropies), 2), round(max(entropies), 2)] if entropies else [],
            },
        ))

    return result
