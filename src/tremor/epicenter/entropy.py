"""Entropy analysis utilities for steganography detection.

Provides Shannon entropy, sliding-window entropy mapping, and chi-square
randomness testing. All stdlib — no numpy required.
"""

import math
from typing import Iterator


def shannon_entropy(data: bytes) -> float:
    """Calculate Shannon entropy of a byte sequence.

    Returns a value in [0, 8]. 8 = perfectly uniform (encrypted/compressed).
    0 = every byte identical.
    """
    length = len(data)
    if length == 0:
        return 0.0

    freq = [0] * 256
    for b in data:
        freq[b] += 1

    entropy = 0.0
    for count in freq:
        if count > 0:
            p = count / length
            entropy -= p * math.log2(p)
    return entropy


def byte_frequency(data: bytes) -> list[int]:
    """Return a 256-element list of byte value frequencies."""
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    return freq


def entropy_windows(
    data: bytes,
    window_size: int = 4096,
    step: int = 2048,
) -> Iterator[tuple[int, int, float]]:
    """Yield (offset, length, entropy) tuples over sliding windows."""
    if len(data) == 0:
        return
    if window_size > len(data):
        yield (0, len(data), shannon_entropy(data))
        return

    offset = 0
    while offset < len(data):
        end = min(offset + window_size, len(data))
        chunk = data[offset:end]
        yield (offset, len(chunk), shannon_entropy(chunk))
        offset += step
        if end == len(data):
            break


def high_entropy_regions(
    data: bytes,
    threshold: float = 7.0,
    window_size: int = 4096,
    step: int = 2048,
    merge_gap: int = 4096,
) -> list[dict]:
    """Find contiguous high-entropy regions in data.

    Returns a list of dicts: {offset, length, peak_entropy}.
    Adjacent windows above the threshold are merged if their gap is <=
    merge_gap bytes.
    """
    regions: list[dict] = []
    current: dict | None = None

    for offset, length, ent in entropy_windows(data, window_size, step):
        if ent >= threshold:
            if current is None:
                current = {
                    "offset": offset,
                    "length": length,
                    "peak_entropy": ent,
                }
            else:
                end = offset + length
                if offset - (current["offset"] + current["length"]) <= merge_gap:
                    current["length"] = end - current["offset"]
                    current["peak_entropy"] = max(current["peak_entropy"], ent)
                else:
                    regions.append(current)
                    current = {
                        "offset": offset,
                        "length": length,
                        "peak_entropy": ent,
                    }
        else:
            if current is not None:
                regions.append(current)
                current = None

    if current is not None:
        regions.append(current)

    return regions


def chi_square_byte_test(data: bytes) -> tuple[float, float]:
    """Chi-square test on byte frequency distribution.

    Compares observed byte frequencies against a uniform distribution.
    Returns (chi_square_statistic, p_value_approximation).
    """
    n = len(data)
    if n == 0:
        return (0.0, 1.0)

    freq = byte_frequency(data)
    expected = n / 256.0

    chi2 = 0.0
    for count in freq:
        diff = count - expected
        chi2 += (diff * diff) / expected

    k = 255.0
    z = ((chi2 / k) ** (1.0 / 3.0) - (1.0 - 2.0 / (9.0 * k))) / math.sqrt(
        2.0 / (9.0 * k)
    )
    p_value = _normal_cdf_approx(z)

    return (chi2, p_value)


def _normal_cdf_approx(z: float) -> float:
    """Approximate the standard normal CDF using the logistic approximation."""
    exponent = -1.7 * z - 0.73 * z ** 3 / 6.0
    if exponent > 700:
        return 0.0
    if exponent < -700:
        return 1.0
    return 1.0 / (1.0 + math.exp(exponent))


def chi_square_lsb_test(pixel_data: bytes) -> tuple[float, bool]:
    """Chi-square test specifically on LSB plane.

    Returns (chi_square_statistic, is_suspicious).
    """
    if len(pixel_data) < 256:
        return (0.0, False)

    freq = byte_frequency(pixel_data)

    chi2 = 0.0
    pairs_tested = 0
    for i in range(128):
        f0 = freq[2 * i]
        f1 = freq[2 * i + 1]
        total = f0 + f1
        if total > 0:
            expected = total / 2.0
            chi2 += ((f0 - expected) ** 2 + (f1 - expected) ** 2) / expected
            pairs_tested += 1

    if pairs_tested == 0:
        return (0.0, False)

    dof = pairs_tested
    normalized = chi2 / dof if dof > 0 else 0.0
    is_suspicious = normalized < 1.5 and len(pixel_data) > 10000

    return (chi2, is_suspicious)


def lsb_plane_entropy(data: bytes) -> float:
    """Calculate entropy of just the LSB plane.

    Packs LSBs of consecutive bytes into new bytes and measures entropy.
    High entropy (close to 8.0 for packed bytes) suggests LSB embedding.
    """
    if len(data) < 8:
        return 0.0

    packed = bytearray()
    for i in range(0, len(data) - 7, 8):
        byte_val = 0
        for j in range(8):
            byte_val |= (data[i + j] & 1) << (7 - j)
        packed.append(byte_val)

    if not packed:
        return 0.0

    return shannon_entropy(bytes(packed))
