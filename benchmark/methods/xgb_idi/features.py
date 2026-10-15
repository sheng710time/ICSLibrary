"""XGB-IDI payload entropy and sample-level statistics."""
import numpy as np
import math

def compute_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    byte_counts = np.bincount(list(data), minlength=256)
    probabilities = byte_counts / sum(byte_counts)
    return float(-np.sum([p * math.log2(p) for p in probabilities if p > 0]))

def compute_statistics(values: list[float | int], prefix: str = "") -> dict[str, float | int]:
    if not values:
        return {
            f"{prefix}std_dev": 0.0,
            f"{prefix}coefficient_variation": 0.0,
            f"{prefix}skewness": 0.0,
            f"{prefix}range": 0.0,
            f"{prefix}iqr": 0.0,
        }

    data = np.array(values, dtype=float)
    std_dev = float(np.std(data))
    mean = float(np.mean(data)) or 1e-10
    coefficient_variation = std_dev / mean
    skewness = float((np.mean(data) - np.median(data)) / std_dev) if std_dev != 0 else 0.0
    value_range = float(np.max(data) - np.min(data))
    iqr = float(np.percentile(data, 75) - np.percentile(data, 25))

    return {
        f"{prefix}std_dev": std_dev,
        f"{prefix}coefficient_variation": coefficient_variation,
        f"{prefix}skewness": skewness,
        f"{prefix}range": value_range,
        f"{prefix}iqr": iqr,
    }
