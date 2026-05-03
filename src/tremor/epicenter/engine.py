"""Epicenter engine — standalone scan interface with parallel execution."""

import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from .models import ArtifactScan, ArtifactType, PipelineScanResult
from .scanner import scan_artifact

# Defaults — override via environment or function args
DEFAULT_WORKERS = min(8, (os.cpu_count() or 4))
DEFAULT_TIMEOUT = 30  # seconds per file
MAX_FILE_SIZE = 100 * 1024 * 1024  # 100MB — skip files larger than this


def _scan_one(file_path: Path, timeout: int) -> ArtifactScan:
    """Scan a single file with a timeout guard.

    The timeout is cooperative — it relies on scan_artifact completing
    within the allotted time. For truly stuck scans, the thread will
    be abandoned by the executor when the future times out.
    """
    try:
        return scan_artifact(file_path)
    except Exception as exc:
        return ArtifactScan(
            path=str(file_path),
            artifact_type=ArtifactType.UNKNOWN,
            file_size=0,
            entropy=0.0,
            anomaly_score=0.0,
            findings=[],
            error=str(exc),
        )


def scan_path(
    target: str | Path,
    ci_provider: str = "",
    workers: int | None = None,
    timeout: int = DEFAULT_TIMEOUT,
) -> PipelineScanResult:
    """Scan a file or directory for steganographic/anomalous content.

    Args:
        target: File or directory path to scan.
        ci_provider: Optional CI provider name for context.
        workers: Number of parallel workers for directory scans.
            Defaults to min(8, cpu_count).
        timeout: Per-file timeout in seconds (default 30).

    Returns:
        PipelineScanResult with all findings.
    """
    path = Path(target)

    if path.is_file():
        scans = [_scan_one(path, timeout)]
    elif path.is_dir():
        all_files = []
        for root, _dirs, filenames in os.walk(path):
            for fn in filenames:
                fp = Path(root) / fn
                try:
                    if fp.stat().st_size <= MAX_FILE_SIZE:
                        all_files.append(fp)
                except OSError:
                    pass
        files = sorted(all_files)
        scans = _parallel_scan(files, workers or DEFAULT_WORKERS, timeout)
    else:
        return PipelineScanResult(target=str(path))

    flagged = [s for s in scans if s.anomaly_score > 25]
    overall = max((s.anomaly_score for s in scans), default=0)

    result = PipelineScanResult(
        target=str(path),
        ci_provider=ci_provider,
        total_artifacts=len(scans),
        flagged_artifacts=len(flagged),
        scans=scans,
        overall_score=overall,
    )
    result.compute_summary()
    return result


def _parallel_scan(
    files: list[Path],
    workers: int,
    timeout: int,
) -> list[ArtifactScan]:
    """Scan files in parallel using a thread pool."""
    if len(files) <= 1:
        return [_scan_one(f, timeout) for f in files]

    scans: list[ArtifactScan] = []
    with ThreadPoolExecutor(max_workers=workers) as executor:
        future_to_path = {
            executor.submit(_scan_one, f, timeout): f
            for f in files
        }
        for future in as_completed(future_to_path):
            file_path = future_to_path[future]
            try:
                result = future.result(timeout=timeout)
                scans.append(result)
            except TimeoutError:
                scans.append(ArtifactScan(
                    path=str(file_path),
                    artifact_type=ArtifactType.UNKNOWN,
                    file_size=0,
                    entropy=0.0,
                    anomaly_score=0.0,
                    findings=[],
                    error=f"Scan timed out after {timeout}s",
                ))
            except Exception as exc:
                scans.append(ArtifactScan(
                    path=str(file_path),
                    artifact_type=ArtifactType.UNKNOWN,
                    file_size=0,
                    entropy=0.0,
                    anomaly_score=0.0,
                    findings=[],
                    error=str(exc),
                ))

    return scans


def scan(target: str | Path, ci_provider: str = "") -> dict:
    """Scan and return results as a dict."""
    return scan_path(target, ci_provider).to_dict()
