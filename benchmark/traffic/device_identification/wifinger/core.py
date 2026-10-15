"""Packet-sequence matching and fingerprint extraction for WiFinger.

The implementation follows Sections IV-B--IV-D of the WiFinger paper.  The
paper's event trace is represented here by one ICS probing interaction.  A
packet consists only of relative time, observable frame length, and direction;
IP addresses and payload bytes are never matching features.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from functools import lru_cache
from itertools import combinations
from math import ceil, inf, sqrt
from statistics import median
from typing import Callable, Iterable, Sequence


CLIENT_TO_DEVICE = 1
DEVICE_TO_CLIENT = -1


@dataclass(frozen=True, slots=True)
class PacketPoint:
    """One packet in a WiFinger sequence."""

    time: float
    size: int
    direction: int

    def to_dict(self) -> dict[str, float | int]:
        return asdict(self)

    @classmethod
    def from_dict(cls, value: dict[str, float | int]) -> "PacketPoint":
        return cls(
            time=float(value["time"]),
            size=int(value["size"]),
            direction=int(value["direction"]),
        )


@dataclass(frozen=True, slots=True)
class MatchConfig:
    """WiFinger thresholds and the optional large-volume matching mode."""

    epsilon: int = 1
    gamma: float = 0.6
    beta: float = 2.0
    alpha: float = 0.2
    segment_gap: float = 0.5
    min_segment_packets: int = 3
    refinement_support: float = 0.6
    minimum_fingerprint_packets: int = 4
    advanced_matching: bool = False


@dataclass(frozen=True, slots=True)
class MatchResult:
    """Result of matching a target interaction to a base fingerprint."""

    success: bool
    matched_packets: int
    fingerprint_packets: int
    match_ratio: float
    temporal_distance: float
    score: float
    matched_pairs: tuple[tuple[int, int], ...]
    algorithm: str


@dataclass(frozen=True, slots=True)
class Fingerprint:
    """A base fingerprint and the metadata needed by the experiment runner."""

    endpoint: str
    port: int
    operation: str
    label: str
    packets: tuple[PacketPoint, ...]
    training_samples: int

    def to_dict(self) -> dict[str, object]:
        return {
            "endpoint": self.endpoint,
            "port": self.port,
            "operation": self.operation,
            "label": self.label,
            "packets": [packet.to_dict() for packet in self.packets],
            "training_samples": self.training_samples,
        }

    @classmethod
    def from_dict(cls, value: dict[str, object]) -> "Fingerprint":
        packets = tuple(PacketPoint.from_dict(item) for item in value["packets"])
        return cls(
            endpoint=str(value["endpoint"]),
            port=int(value["port"]),
            operation=str(value["operation"]),
            label=str(value["label"]),
            packets=packets,
            training_samples=int(value["training_samples"]),
        )


def normalize_sequence(sequence: Sequence[PacketPoint]) -> tuple[PacketPoint, ...]:
    """Sort a sequence and make timestamps relative to its first packet.

    WiFinger only compresses consecutive equal packets in its optional
    large-volume preprocessing path.  Ordinary ICS interactions therefore
    retain every deduplicated TCP packet.
    """

    if not sequence:
        return ()
    ordered = sorted(sequence, key=lambda packet: packet.time)
    origin = ordered[0].time
    return tuple(
        PacketPoint(
            time=max(0.0, float(packet.time) - float(origin)),
            size=int(packet.size),
            direction=int(packet.direction),
        )
        for packet in ordered
    )


def compress_repeated_packets(
    sequence: Sequence[PacketPoint], maximum_gap: float = 1.0
) -> tuple[PacketPoint, ...]:
    """Apply WiFinger's optional large-volume consecutive-packet compression."""

    normalized = normalize_sequence(sequence)
    compressed: list[PacketPoint] = []
    for point in normalized:
        if (
            compressed
            and compressed[-1].size == point.size
            and compressed[-1].direction == point.direction
            and point.time - compressed[-1].time < maximum_gap
        ):
            continue
        compressed.append(point)
    return tuple(compressed)


def packets_similar(left: PacketPoint, right: PacketPoint, epsilon: int) -> bool:
    return (
        left.direction == right.direction
        and abs(left.size - right.size) < epsilon
    )


def _better(
    candidate_length: int,
    candidate_cost: float,
    current_length: int,
    current_cost: float,
) -> bool:
    return candidate_length > current_length or (
        candidate_length == current_length and candidate_cost < current_cost
    )


def _lcs_alignment(
    left: Sequence[PacketPoint],
    right: Sequence[PacketPoint],
    predicate: Callable[[int, int], bool],
    temporal_cost: Callable[[int, int], float] | None = None,
) -> tuple[tuple[int, int], ...]:
    """Return one maximum LCS, breaking equal-length ties by temporal cost.

    WiFinger's pseudocode stores every maximum path, which is exponential in
    the worst case.  This helper keeps the best pointwise temporal path at each
    cell and is used after AFMLCS's anchor constraints have pruned alternatives.
    """

    rows = len(left) + 1
    columns = len(right) + 1
    lengths = [[0] * columns for _ in range(rows)]
    costs = [[0.0] * columns for _ in range(rows)]
    parents = [[0] * columns for _ in range(rows)]  # 1 diagonal, 2 up, 3 left
    cost_fn = temporal_cost or (lambda _i, _j: 0.0)

    for i in range(1, rows):
        for j in range(1, columns):
            best_length = lengths[i - 1][j]
            best_cost = costs[i - 1][j]
            parent = 2
            if _better(lengths[i][j - 1], costs[i][j - 1], best_length, best_cost):
                best_length = lengths[i][j - 1]
                best_cost = costs[i][j - 1]
                parent = 3
            if predicate(i - 1, j - 1):
                diagonal_length = lengths[i - 1][j - 1] + 1
                diagonal_cost = costs[i - 1][j - 1] + cost_fn(i - 1, j - 1)
                if _better(diagonal_length, diagonal_cost, best_length, best_cost):
                    best_length = diagonal_length
                    best_cost = diagonal_cost
                    parent = 1
            lengths[i][j] = best_length
            costs[i][j] = best_cost
            parents[i][j] = parent

    pairs: list[tuple[int, int]] = []
    i, j = len(left), len(right)
    while i > 0 and j > 0:
        parent = parents[i][j]
        if parent == 1:
            pairs.append((i - 1, j - 1))
            i -= 1
            j -= 1
        elif parent == 2:
            i -= 1
        else:
            j -= 1
    pairs.reverse()
    return tuple(pairs)


def _optimal_lcs_paths(
    left: Sequence[PacketPoint],
    right: Sequence[PacketPoint],
    epsilon: int,
    path_limit: int = 4096,
) -> tuple[tuple[tuple[int, int], ...], ...]:
    """Enumerate maximum LCS paths for baseline FMLCS, with a safety cap."""

    rows = len(left) + 1
    columns = len(right) + 1
    lengths = [[0] * columns for _ in range(rows)]
    for i in range(1, rows):
        for j in range(1, columns):
            if packets_similar(left[i - 1], right[j - 1], epsilon):
                lengths[i][j] = lengths[i - 1][j - 1] + 1
            else:
                lengths[i][j] = max(lengths[i - 1][j], lengths[i][j - 1])

    @lru_cache(maxsize=None)
    def backtrack(i: int, j: int) -> tuple[tuple[tuple[int, int], ...], ...]:
        if i == 0 or j == 0:
            return ((),)
        paths: list[tuple[tuple[int, int], ...]] = []
        target_length = lengths[i][j]
        if (
            packets_similar(left[i - 1], right[j - 1], epsilon)
            and lengths[i - 1][j - 1] + 1 == target_length
        ):
            paths.extend(
                path + ((i - 1, j - 1),)
                for path in backtrack(i - 1, j - 1)
            )
        if lengths[i - 1][j] == target_length:
            paths.extend(backtrack(i - 1, j))
        if lengths[i][j - 1] == target_length:
            paths.extend(backtrack(i, j - 1))

        unique: list[tuple[tuple[int, int], ...]] = []
        seen: set[tuple[tuple[int, int], ...]] = set()
        for path in paths:
            if path in seen:
                continue
            seen.add(path)
            unique.append(path)
            if len(unique) >= path_limit:
                break
        return tuple(unique)

    return backtrack(len(left), len(right))


def _temporal_distance(
    fingerprint: Sequence[PacketPoint],
    target: Sequence[PacketPoint],
    pairs: Sequence[tuple[int, int]],
) -> float:
    if not pairs:
        return inf
    left_times = [fingerprint[i].time for i, _ in pairs]
    right_times = [target[j].time for _, j in pairs]
    left_mean = sum(left_times) / len(left_times)
    right_mean = sum(right_times) / len(right_times)
    return sqrt(
        sum(
            ((left_time - left_mean) - (right_time - right_mean)) ** 2
            for left_time, right_time in zip(left_times, right_times)
        )
    )


def _build_result(
    fingerprint: Sequence[PacketPoint],
    target: Sequence[PacketPoint],
    pairs: Sequence[tuple[int, int]],
    config: MatchConfig,
    algorithm: str,
) -> MatchResult:
    match_ratio = len(pairs) / len(fingerprint) if fingerprint else 0.0
    distance = _temporal_distance(fingerprint, target, pairs)
    success = match_ratio >= config.gamma and distance < config.beta
    temporal_factor = 0.0 if distance == inf else 1.0 / (1.0 + distance)
    return MatchResult(
        success=success,
        matched_packets=len(pairs),
        fingerprint_packets=len(fingerprint),
        match_ratio=match_ratio,
        temporal_distance=distance,
        score=match_ratio * temporal_factor,
        matched_pairs=tuple(pairs),
        algorithm=algorithm,
    )


def fmlcs(
    fingerprint: Sequence[PacketPoint],
    target: Sequence[PacketPoint],
    config: MatchConfig,
) -> MatchResult:
    """Baseline fuzzy LCS matcher (Algorithm 1 in the paper)."""

    left = normalize_sequence(fingerprint)
    right = normalize_sequence(target)
    paths = _optimal_lcs_paths(left, right, config.epsilon)
    pairs = min(
        paths,
        key=lambda path: (_temporal_distance(left, right, path), path),
        default=(),
    )
    return _build_result(left, right, pairs, config, "FMLCS")


def segment_fingerprint(
    fingerprint: Sequence[PacketPoint], config: MatchConfig
) -> tuple[tuple[int, ...], ...]:
    """Split at gaps over 0.5s and merge sub-three-packet segments."""

    if not fingerprint:
        return ()
    raw_segments: list[list[int]] = [[0]]
    for index in range(1, len(fingerprint)):
        if fingerprint[index].time - fingerprint[index - 1].time > config.segment_gap:
            raw_segments.append([])
        raw_segments[-1].append(index)

    merged: list[list[int]] = []
    carry: list[int] = []
    for segment in raw_segments:
        current = carry + segment
        if len(current) < config.min_segment_packets:
            carry = current
        else:
            merged.append(current)
            carry = []
    if carry:
        if merged:
            merged[-1].extend(carry)
        else:
            merged.append(carry)
    return tuple(tuple(segment) for segment in merged)


def _select_anchor(
    fingerprint: Sequence[PacketPoint],
    target: Sequence[PacketPoint],
    first_segment: Sequence[int],
    config: MatchConfig,
) -> tuple[int, int] | None:
    for fingerprint_index in first_segment:
        for target_index, target_packet in enumerate(target):
            if packets_similar(
                fingerprint[fingerprint_index], target_packet, config.epsilon
            ):
                return fingerprint_index, target_index
    return None


def afmlcs(
    fingerprint: Sequence[PacketPoint],
    target: Sequence[PacketPoint],
    config: MatchConfig,
) -> MatchResult:
    """Anchor-constrained, segmented FMLCS used for longer traces."""

    left = normalize_sequence(fingerprint)
    right = normalize_sequence(target)
    segments = segment_fingerprint(left, config)
    if not left or not right or not segments:
        return _build_result(left, right, (), config, "AFMLCS")
    anchor = _select_anchor(left, right, segments[0], config)
    if anchor is None:
        return _build_result(left, right, (), config, "AFMLCS")
    anchor_left, anchor_right = anchor
    left_anchor_time = left[anchor_left].time
    right_anchor_time = right[anchor_right].time

    all_pairs: list[tuple[int, int]] = []
    used_target_indices: set[int] = set()
    for segment_number, indices in enumerate(segments):
        segment = [left[index] for index in indices]
        expected_start = right_anchor_time + segment[0].time - left_anchor_time
        expected_end = right_anchor_time + segment[-1].time - left_anchor_time
        candidate_indices = [
            index
            for index, packet in enumerate(right)
            if expected_start - config.alpha <= packet.time <= expected_end + config.alpha
        ]
        if not candidate_indices:
            if segment_number == 0:
                return _build_result(left, right, (), config, "AFMLCS")
            continue
        candidate_packets = [right[index] for index in candidate_indices]

        def predicate(i: int, j: int) -> bool:
            left_packet = segment[i]
            right_packet = candidate_packets[j]
            relative_gap = abs(
                (left_packet.time - left_anchor_time)
                - (right_packet.time - right_anchor_time)
            )
            return (
                packets_similar(left_packet, right_packet, config.epsilon)
                and relative_gap <= config.alpha
            )

        segment_pairs = _lcs_alignment(
            segment,
            candidate_packets,
            predicate,
            lambda i, j: (
                (segment[i].time - left_anchor_time)
                - (candidate_packets[j].time - right_anchor_time)
            )
            ** 2,
        )
        if segment_number == 0 and len(segment_pairs) < ceil(config.gamma * len(segment)):
            return _build_result(left, right, (), config, "AFMLCS")
        for segment_index, candidate_index in segment_pairs:
            target_index = candidate_indices[candidate_index]
            if target_index not in used_target_indices:
                all_pairs.append((indices[segment_index], target_index))
                used_target_indices.add(target_index)

    all_pairs.sort()
    return _build_result(left, right, all_pairs, config, "AFMLCS")


def match_fingerprint(
    fingerprint: Sequence[PacketPoint],
    target: Sequence[PacketPoint],
    config: MatchConfig | None = None,
) -> MatchResult:
    """Match with baseline FMLCS unless large-volume AFMLCS is requested.

    The paper uses AFMLCS for explicitly identified high-volume devices.  A
    packet-count cutoff was not specified, so the task adaptation does not
    invent one.  The normal ICS probing interactions use baseline FMLCS.
    """

    config = config or MatchConfig()
    normalized = normalize_sequence(fingerprint)
    if config.advanced_matching:
        return afmlcs(
            compress_repeated_packets(normalized),
            compress_repeated_packets(target),
            config,
        )
    return fmlcs(normalized, target, config)


def _extraction_alignment(
    left: Sequence[PacketPoint],
    right: Sequence[PacketPoint],
    config: MatchConfig,
) -> tuple[tuple[int, int], ...]:
    """Pairwise LCS with event-initiation time acting as the fake anchor."""

    return _lcs_alignment(
        left,
        right,
        lambda i, j: (
            packets_similar(left[i], right[j], config.epsilon)
            and abs(left[i].time - right[j].time) < config.alpha
        ),
        lambda i, j: (left[i].time - right[j].time) ** 2,
    )


def _cluster_components(
    components: Iterable[PacketPoint], config: MatchConfig
) -> tuple[PacketPoint, ...]:
    clusters: list[list[PacketPoint]] = []
    for point in sorted(components, key=lambda packet: packet.time):
        best_cluster: list[PacketPoint] | None = None
        best_gap = inf
        for cluster in clusters:
            center_time = median(packet.time for packet in cluster)
            center_size = median(packet.size for packet in cluster)
            if (
                cluster[0].direction == point.direction
                and abs(center_size - point.size) < config.epsilon
                and abs(center_time - point.time) < config.alpha
                and abs(center_time - point.time) < best_gap
            ):
                best_cluster = cluster
                best_gap = abs(center_time - point.time)
        if best_cluster is None:
            clusters.append([point])
        else:
            best_cluster.append(point)
    coarse = [
        PacketPoint(
            time=float(median(packet.time for packet in cluster)),
            size=int(round(median(packet.size for packet in cluster))),
            direction=cluster[0].direction,
        )
        for cluster in clusters
    ]
    return normalize_sequence(coarse)


def _bidirectional_support(
    coarse: Sequence[PacketPoint],
    samples: Sequence[Sequence[PacketPoint]],
    config: MatchConfig,
) -> list[int]:
    support = [0] * len(coarse)
    for sample in samples:
        forward = _extraction_alignment(coarse, sample, config)
        for coarse_index, _ in forward:
            support[coarse_index] += 1

        coarse_duration = coarse[-1].time if coarse else 0.0
        sample_duration = sample[-1].time if sample else 0.0
        reversed_coarse = tuple(
            PacketPoint(
                time=coarse_duration - packet.time,
                size=packet.size,
                direction=packet.direction,
            )
            for packet in reversed(coarse)
        )
        reversed_sample = tuple(
            PacketPoint(
                time=sample_duration - packet.time,
                size=packet.size,
                direction=packet.direction,
            )
            for packet in reversed(sample)
        )
        backward = _extraction_alignment(reversed_coarse, reversed_sample, config)
        for reversed_index, _ in backward:
            support[len(coarse) - 1 - reversed_index] += 1
    return support


def extract_fingerprint(
    samples: Sequence[Sequence[PacketPoint]],
    config: MatchConfig | None = None,
    max_samples: int = 30,
) -> tuple[PacketPoint, ...]:
    """Extract a base fingerprint using pairwise consensus and refinement.

    WiFinger uses 30 event executions.  The caller should provide samples in a
    deterministic order; extra samples are capped to the paper's training size.
    Refinement counts matches in both sliding directions and retains packets
    whose combined frequency is at least the number of training executions.
    """

    config = config or MatchConfig()
    normalized_samples = [normalize_sequence(sample) for sample in samples]
    normalized_samples = [sample for sample in normalized_samples if sample]
    normalized_samples = normalized_samples[:max_samples]
    if not normalized_samples:
        return ()
    if len(normalized_samples) == 1:
        return normalized_samples[0]

    components: list[PacketPoint] = []
    for left, right in combinations(normalized_samples, 2):
        alignment = _extraction_alignment(left, right, config)
        # The source inserts a fake initiation anchor and requires a potential
        # fingerprint length of at least three.  On already segmented ICS
        # interactions that corresponds to at least two real consensus packets.
        if len(alignment) < 2:
            continue
        if _temporal_distance(left, right, alignment) >= config.beta:
            continue
        for left_index, right_index in alignment:
            left_point = left[left_index]
            right_point = right[right_index]
            components.append(
                PacketPoint(
                    time=(left_point.time + right_point.time) / 2.0,
                    size=int(round((left_point.size + right_point.size) / 2.0)),
                    direction=left_point.direction,
                )
            )

    if not components:
        return ()

    coarse = _cluster_components(components, config)
    while coarse:
        support = _bidirectional_support(coarse, normalized_samples, config)
        refined = tuple(
            packet
            for packet, frequency in zip(coarse, support)
            if frequency >= len(normalized_samples)
        )
        if refined == coarse:
            break
        if not refined:
            return ()
        coarse = normalize_sequence(refined)
    return normalize_sequence(coarse)
