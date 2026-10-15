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



def feature_diff(sample: np.ndarray, neighbors: np.ndarray, discrete_mask: np.ndarray) -> np.ndarray:
    differences = np.abs(neighbors - sample)
    if discrete_mask.any():
        differences[:, discrete_mask] = (neighbors[:, discrete_mask] != sample[discrete_mask]).astype(np.float32)
    return differences


def compute_feature_weights(
    X_train_relief: np.ndarray,
    y_train: np.ndarray,
    discrete_mask: np.ndarray,
    iterations: int,
    neighbors: int,
    sample_size: int,
    seed: int,
) -> tuple[np.ndarray, np.ndarray]:
    rng = np.random.default_rng(seed)
    total_samples = len(X_train_relief)

    if total_samples > sample_size:
        subset_indices = rng.choice(total_samples, size=sample_size, replace=False)
        X = X_train_relief[subset_indices]
        y = y_train[subset_indices]
    else:
        X = X_train_relief
        y = y_train

    classes, counts = np.unique(y, return_counts=True)
    priors = counts / counts.sum()
    prior_map = {cls: prior for cls, prior in zip(classes, priors)}
    class_indices = {cls: np.where(y == cls)[0] for cls in classes}

    raw_weights = np.zeros(X.shape[1], dtype=np.float64)
    valid_iterations = 0

    for _ in range(iterations):
        sample_index = int(rng.integers(len(X)))
        sample_class = y[sample_index]
        sample_vector = X[sample_index]

        same_class_indices = class_indices[sample_class]
        same_class_indices = same_class_indices[same_class_indices != sample_index]
        if same_class_indices.size == 0:
            continue

        hit_distances = np.linalg.norm(X[same_class_indices] - sample_vector, axis=1)
        hit_count = min(neighbors, len(same_class_indices))
        hit_indices = same_class_indices[np.argpartition(hit_distances, hit_count - 1)[:hit_count]]
        hit_penalty = feature_diff(sample_vector, X[hit_indices], discrete_mask).mean(axis=0)

        miss_reward = np.zeros(X.shape[1], dtype=np.float64)
        current_prior = prior_map[sample_class]

        for other_class in classes:
            if other_class == sample_class:
                continue

            other_indices = class_indices[other_class]
            if other_indices.size == 0:
                continue

            miss_distances = np.linalg.norm(X[other_indices] - sample_vector, axis=1)
            miss_count = min(neighbors, len(other_indices))
            miss_indices = other_indices[np.argpartition(miss_distances, miss_count - 1)[:miss_count]]
            class_miss_reward = feature_diff(sample_vector, X[miss_indices], discrete_mask).mean(axis=0)
            class_weight = prior_map[other_class] / max(1.0 - current_prior, 1e-12)
            miss_reward += class_weight * class_miss_reward

        raw_weights += miss_reward - hit_penalty
        valid_iterations += 1

    if valid_iterations == 0:
        normalized_weights = np.ones(X.shape[1], dtype=np.float32)
        return raw_weights.astype(np.float32), normalized_weights

    raw_weights /= valid_iterations
    min_weight = float(raw_weights.min())
    max_weight = float(raw_weights.max())
    if np.isclose(min_weight, max_weight):
        normalized_weights = np.ones_like(raw_weights, dtype=np.float32)
    else:
        normalized_weights = ((raw_weights - min_weight) / (max_weight - min_weight)).astype(np.float32)

    # Keep all features active while still emphasizing high-weight features.
    scaling_weights = 0.5 + normalized_weights
    return raw_weights.astype(np.float32), scaling_weights.astype(np.float32)
