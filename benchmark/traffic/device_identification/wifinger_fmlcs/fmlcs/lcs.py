"""
LCS (Longest Common Subsequence) algorithms for FMLCS method.
Includes approximate matching and advanced matching with time variation constraints.
"""

import numpy as np
from typing import Tuple, List

# Global threshold for packet size matching
distance_thresh = 1


def approximate_match(target_seq, fingerprint_seq) -> Tuple[float, List[Tuple[int, int]]]:
    """
    Approximate LCS matching between target sequence and fingerprint sequence.

    Matches packets based on size similarity (within distance_thresh) and direction.
    Returns the best matching path with minimum time variation.

    Args:
        target_seq: Target packet sequence [(timestamp, size, direction), ...]
        fingerprint_seq: Fingerprint packet sequence [(timestamp, size, direction), ...]

    Returns:
        Tuple of (min_distance, best_matching_path)
    """
    m = len(target_seq)
    n = len(fingerprint_seq)

    dp = [[0] * (n + 1) for _ in range(m + 1)]
    paths = [[[[]] for _ in range(n + 1)] for _ in range(m + 1)]

    for i in range(1, m + 1):
        for j in range(1, n + 1):
            if (abs(target_seq[i - 1][1] - fingerprint_seq[j - 1][1]) < distance_thresh and
                target_seq[i - 1][2] == fingerprint_seq[j - 1][2]):
                dp[i][j] = dp[i - 1][j - 1] + 1
                paths[i][j] = [path + [(i - 1, j - 1)] for path in paths[i - 1][j - 1]]
            else:
                if dp[i - 1][j] > dp[i][j - 1]:
                    dp[i][j] = dp[i - 1][j]
                    paths[i][j] = paths[i - 1][j]
                elif dp[i][j - 1] > dp[i - 1][j]:
                    dp[i][j] = dp[i][j - 1]
                    paths[i][j] = paths[i][j - 1]
                elif dp[i][j-1] == dp[i-1][j] > 0:
                    dp[i][j] = dp[i][j-1]
                    paths[i][j] = set([tuple(path) for path in paths[i-1][j]])
                    paths[i][j].update([tuple(path) for path in paths[i][j-1]])
                    paths[i][j] = [list(path) for path in paths[i][j]]

    max_length = dp[m][n]
    all_paths = set()
    for i in range(len(paths)-1, -1, -1):
        for j in range(len(paths[i])-1, -1, -1):
            if dp[i][j] < max_length:
                continue
            for path in paths[i][j]:
                all_paths.add(tuple(path))

    all_paths = [list(path) for path in all_paths]

    if not all_paths:
        return float('inf'), []

    matched_target_time_seq = np.array([
        [target_seq[index_pair[0]][0] - target_seq[matched_index[0][0]][0]
         for index_pair in matched_index]
        for matched_index in all_paths
    ])
    matched_fingerprint_time_seq = np.array([
        [fingerprint_seq[index_pair[1]][0] - fingerprint_seq[matched_index[0][1]][0]
         for index_pair in matched_index]
        for matched_index in all_paths
    ])

    diff = matched_target_time_seq - matched_fingerprint_time_seq
    diff_mean = np.mean(diff, axis=1).reshape(-1, 1)
    distances = np.linalg.norm(diff - diff_mean, axis=1)
    min_distance = np.min(distances)
    min_index = np.argmin(distances)

    return min_distance, all_paths[min_index]


def advanced_approximate_match(
    target_seq: List[Tuple[float, int, str]],
    fingerprint_seq,
    variation_thresh: float = 0.2
) -> Tuple[float, List[Tuple[int, int]]]:
    """
    Advanced LCS matching with time variation constraint.

    Similar to approximate_match but also considers time difference between
    matched packets, ensuring temporal consistency.

    Args:
        target_seq: Target packet sequence [(timestamp, size, direction), ...]
        fingerprint_seq: Fingerprint packet sequence
        variation_thresh: Maximum allowed time variation for matching

    Returns:
        Tuple of (min_distance, best_matching_path)
    """
    m = len(target_seq)
    n = len(fingerprint_seq)

    dp = [[0] * (n + 1) for _ in range(m + 1)]
    paths = [[[[]] for _ in range(n + 1)] for _ in range(m + 1)]

    for i in range(1, m + 1):
        for j in range(1, n + 1):
            if (abs(target_seq[i - 1][1] - fingerprint_seq[j - 1][1]) < distance_thresh and
                target_seq[i - 1][2] == fingerprint_seq[j - 1][2] and
                abs((target_seq[i - 1][0] - target_seq[0][0]) -
                    (fingerprint_seq[j - 1][0] - fingerprint_seq[0][0])) < variation_thresh):
                dp[i][j] = dp[i - 1][j - 1] + 1
                paths[i][j] = [list(path) + [(i - 1, j - 1)] for path in paths[i - 1][j - 1]]
            else:
                if dp[i - 1][j] > dp[i][j - 1]:
                    dp[i][j] = dp[i - 1][j]
                    paths[i][j] = paths[i - 1][j]
                elif dp[i][j - 1] > dp[i - 1][j]:
                    dp[i][j] = dp[i][j - 1]
                    paths[i][j] = paths[i][j - 1]
                elif dp[i][j-1] == dp[i-1][j] > 0:
                    dp[i][j] = dp[i][j-1]
                    paths[i][j] = set([tuple(path) for path in paths[i-1][j]])
                    paths[i][j].update([tuple(path) for path in paths[i][j-1]])
                    paths[i][j] = list(paths[i][j])

    max_length = dp[m][n]
    all_paths = set()
    for i in range(len(paths)-1, -1, -1):
        for j in range(len(paths[i])-1, -1, -1):
            if dp[i][j] < max_length:
                continue
            for path in paths[i][j]:
                all_paths.add(tuple(path))

    all_paths = [list(path) for path in all_paths]

    if not all_paths:
        return float('inf'), []

    matched_target_time_seq = np.array([
        [target_seq[index_pair[0]][0] - target_seq[matched_index[0][0]][0]
         for index_pair in matched_index]
        for matched_index in all_paths
    ])
    matched_fingerprint_time_seq = np.array([
        [fingerprint_seq[index_pair[1]][0] - fingerprint_seq[matched_index[0][1]][0]
         for index_pair in matched_index]
        for matched_index in all_paths
    ])

    diff = matched_target_time_seq - matched_fingerprint_time_seq
    diff_mean = np.mean(diff, axis=1).reshape(-1, 1)
    distances = np.linalg.norm(diff - diff_mean, axis=1)
    min_distance = np.min(distances)
    min_index = np.argmin(distances)

    return min_distance, all_paths[min_index]
