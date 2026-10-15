"""Core PingPong signature extraction and layer-3 matching.

This module is an independent Python adaptation of the algorithm described in
"Packet-Level Signatures for Smart Home Devices" (NDSS 2020).  It keeps the
paper's direction/length packet pairs, DBSCAN frequency filtering, adjacent
pair concatenation, and ordered sequence-set matching while exposing data
structures that fit the ICS endpoint/operation/round organization in this
repository.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import asdict, dataclass
from math import ceil, floor, sqrt
from statistics import median
from typing import Iterable, Sequence

import numpy as np
from sklearn.cluster import DBSCAN


CLIENT_TO_DEVICE = 1
DEVICE_TO_CLIENT = -1


@dataclass(frozen=True, slots=True)
class PacketPoint:
    """One payload-carrying TCP packet used by PingPong."""

    time: float
    size: int
    direction: int

    def __post_init__(self) -> None:
        if self.size < 0:
            raise ValueError("packet size must be non-negative")
        if self.direction not in (CLIENT_TO_DEVICE, DEVICE_TO_CLIENT):
            raise ValueError("packet direction must be +1 or -1")

    def to_dict(self) -> dict[str, float | int]:
        return asdict(self)

    @classmethod
    def from_dict(cls, value: dict[str, object]) -> "PacketPoint":
        return cls(
            time=float(value["time"]),
            size=int(value["size"]),
            direction=int(value["direction"]),
        )


@dataclass(frozen=True, slots=True)
class ExtractionConfig:
    """Paper-derived parameters plus explicit ICS adaptation controls."""

    epsilon: float = 10.0
    cluster_slack: float = 0.1
    inclusion_window_seconds: float = 15.0
    minimum_training_events: int = 5
    maximum_training_events: int = 0
    matching_strategy: str = "range"

    def __post_init__(self) -> None:
        if self.epsilon < 0:
            raise ValueError("epsilon must be non-negative")
        if not 0 <= self.cluster_slack < 1:
            raise ValueError("cluster_slack must be in [0, 1)")
        if self.inclusion_window_seconds <= 0:
            raise ValueError("inclusion_window_seconds must be positive")
        if self.minimum_training_events < 1:
            raise ValueError("minimum_training_events must be positive")
        if self.maximum_training_events < 0:
            raise ValueError("maximum_training_events must be non-negative")
        if self.matching_strategy not in {"conservative", "range"}:
            raise ValueError(
                "matching_strategy must be 'conservative' or 'range'"
            )


@dataclass(frozen=True, slots=True)
class PairOccurrence:
    """A one- or two-packet PingPong pair and its training location."""

    sample_index: int
    flow_index: int
    pair_index: int
    packets: tuple[PacketPoint, ...]

    def __post_init__(self) -> None:
        if len(self.packets) not in (1, 2):
            raise ValueError("a packet pair must contain one or two packets")
        if len(self.packets) == 2:
            if self.packets[0].direction == self.packets[1].direction:
                raise ValueError("two-packet pairs must use opposite directions")

    @property
    def direction_key(self) -> tuple[int, int | None]:
        second = self.packets[1].direction if len(self.packets) == 2 else None
        return self.packets[0].direction, second

    @property
    def length_vector(self) -> tuple[int, int]:
        second = self.packets[1].size if len(self.packets) == 2 else 0
        return self.packets[0].size, second


@dataclass(frozen=True, slots=True)
class SequenceComponent:
    """One ordered packet-sequence set in a PingPong signature."""

    directions: tuple[int, ...]
    variants: tuple[tuple[int, ...], ...]
    support: int

    def __post_init__(self) -> None:
        if not self.directions:
            raise ValueError("a sequence component cannot be empty")
        if not self.variants:
            raise ValueError("a sequence component needs at least one variant")
        if any(len(variant) != len(self.directions) for variant in self.variants):
            raise ValueError("all variants must have the component's packet count")
        if self.support < 1:
            raise ValueError("component support must be positive")

    @property
    def packet_count(self) -> int:
        return len(self.directions)

    @property
    def lower_bounds(self) -> tuple[int, ...]:
        return tuple(min(values) for values in zip(*self.variants))

    @property
    def upper_bounds(self) -> tuple[int, ...]:
        return tuple(max(values) for values in zip(*self.variants))

    def to_dict(self) -> dict[str, object]:
        return {
            "directions": list(self.directions),
            "variants": [list(variant) for variant in self.variants],
            "lower_bounds": list(self.lower_bounds),
            "upper_bounds": list(self.upper_bounds),
            "support": self.support,
        }


@dataclass(frozen=True, slots=True)
class PingPongSignature:
    """A validated endpoint-operation signature with a model label."""

    endpoint: str
    port: int
    operation: str
    label: str
    components: tuple[SequenceComponent, ...]
    training_events: int
    validation_matches: int

    @property
    def packet_count(self) -> int:
        return sum(component.packet_count for component in self.components)

    def to_dict(self) -> dict[str, object]:
        return {
            "endpoint": self.endpoint,
            "port": self.port,
            "operation": self.operation,
            "label": self.label,
            "components": [component.to_dict() for component in self.components],
            "training_events": self.training_events,
            "validation_matches": self.validation_matches,
            "packet_count": self.packet_count,
        }


@dataclass(frozen=True, slots=True)
class SignatureMatch:
    success: bool
    distance: float
    matched_packets: int
    component_spans: tuple[tuple[int, int, int], ...] = ()


@dataclass(frozen=True, slots=True)
class _BuiltComponent:
    component: SequenceComponent
    positions: dict[int, tuple[tuple[float, float], ...]]


def normalize_sequence(packets: Iterable[PacketPoint]) -> tuple[PacketPoint, ...]:
    """Sort packets and express time relative to the first packet."""

    ordered = sorted(packets, key=lambda packet: packet.time)
    if not ordered:
        return ()
    start = ordered[0].time
    return tuple(
        PacketPoint(
            time=float(packet.time - start),
            size=int(packet.size),
            direction=int(packet.direction),
        )
        for packet in ordered
    )


def make_packet_pairs(
    packets: Sequence[PacketPoint], sample_index: int = 0, flow_index: int = 0
) -> tuple[PairOccurrence, ...]:
    """Form non-overlapping request/reply pairs as defined in the paper."""

    pairs: list[PairOccurrence] = []
    packet_index = 0
    pair_index = 0
    while packet_index < len(packets):
        first = packets[packet_index]
        if (
            packet_index + 1 < len(packets)
            and first.direction != packets[packet_index + 1].direction
        ):
            pair_packets = (first, packets[packet_index + 1])
            packet_index += 2
        else:
            pair_packets = (first,)
            packet_index += 1
        pairs.append(
            PairOccurrence(
                sample_index=sample_index,
                flow_index=flow_index,
                pair_index=pair_index,
                packets=pair_packets,
            )
        )
        pair_index += 1
    return tuple(pairs)


def pair_distance(left: PairOccurrence, right: PairOccurrence) -> float:
    """Direction-aware Euclidean distance from the paper and released code."""

    if left.direction_key != right.direction_key:
        return float("inf")
    return sqrt(
        sum(
            (left_value - right_value) ** 2
            for left_value, right_value in zip(
                left.length_vector, right.length_vector
            )
        )
    )


def _frequency_bounds(events: int, slack: float) -> tuple[int, int]:
    return max(1, floor(events * (1 - slack))), ceil(events * (1 + slack))


def _normalise_event_flows(
    flows: Sequence[Sequence[PacketPoint]],
    inclusion_window_seconds: float | None = None,
) -> tuple[tuple[PacketPoint, ...], ...]:
    """Keep flow boundaries while expressing time from the event start."""

    non_empty = [
        tuple(sorted(flow, key=lambda packet: packet.time)) for flow in flows if flow
    ]
    if not non_empty:
        return ()
    event_start = min(flow[0].time for flow in non_empty)
    normalized: list[tuple[PacketPoint, ...]] = []
    for flow in non_empty:
        packets = tuple(
            PacketPoint(
                time=float(packet.time - event_start),
                size=int(packet.size),
                direction=int(packet.direction),
            )
            for packet in flow
            if inclusion_window_seconds is None
            or packet.time - event_start <= inclusion_window_seconds
        )
        if packets:
            normalized.append(packets)
    return tuple(normalized)


def _candidate_pair_clusters(
    events: Sequence[Sequence[Sequence[PacketPoint]]], config: ExtractionConfig
) -> list[tuple[PairOccurrence, ...]]:
    event_count = len(events)
    lower, upper = _frequency_bounds(event_count, config.cluster_slack)
    by_direction: dict[tuple[int, int | None], list[PairOccurrence]] = defaultdict(list)
    for sample_index, flows in enumerate(events):
        for flow_index, flow in enumerate(flows):
            for occurrence in make_packet_pairs(flow, sample_index, flow_index):
                by_direction[occurrence.direction_key].append(occurrence)

    clusters: list[tuple[PairOccurrence, ...]] = []
    for direction_key in sorted(
        by_direction, key=lambda key: (key[0], key[1] if key[1] is not None else 0)
    ):
        occurrences = by_direction[direction_key]
        if len(occurrences) < lower:
            continue
        features = np.asarray(
            [occurrence.length_vector for occurrence in occurrences], dtype=float
        )
        labels = DBSCAN(
            eps=config.epsilon,
            min_samples=lower,
            metric="euclidean",
            algorithm="auto",
        ).fit_predict(features)
        for cluster_label in sorted(set(int(value) for value in labels if value >= 0)):
            members = tuple(
                occurrence
                for occurrence, value in zip(occurrences, labels)
                if int(value) == cluster_label
            )
            event_support = len({member.sample_index for member in members})
            if lower <= len(members) <= upper and event_support >= lower:
                clusters.append(
                    tuple(
                        sorted(
                            members,
                            key=lambda item: (
                                item.sample_index,
                                item.flow_index,
                                item.pair_index,
                            ),
                        )
                    )
                )
    return clusters


def _cluster_chains(
    clusters: Sequence[Sequence[PairOccurrence]],
) -> tuple[tuple[int, ...], ...]:
    """Join candidate clusters that are adjacent in every represented event."""

    position_to_cluster: dict[tuple[int, int, int], int] = {}
    for cluster_index, cluster in enumerate(clusters):
        for occurrence in cluster:
            position_to_cluster[
                (
                    occurrence.sample_index,
                    occurrence.flow_index,
                    occurrence.pair_index,
                )
            ] = cluster_index

    proposed_next: dict[int, int] = {}
    for cluster_index, cluster in enumerate(clusters):
        following = {
            position_to_cluster.get(
                (
                    occurrence.sample_index,
                    occurrence.flow_index,
                    occurrence.pair_index + 1,
                )
            )
            for occurrence in cluster
        }
        if len(following) == 1:
            candidate = next(iter(following))
            if candidate is not None and candidate != cluster_index:
                proposed_next[cluster_index] = candidate

    predecessors: dict[int, list[int]] = defaultdict(list)
    for left, right in proposed_next.items():
        predecessors[right].append(left)
    for right, left_values in predecessors.items():
        if len(left_values) <= 1:
            continue
        winner = max(left_values, key=lambda value: (len(clusters[value]), -value))
        for left in left_values:
            if left != winner:
                proposed_next.pop(left, None)

    predecessor = {right: left for left, right in proposed_next.items()}
    chains: list[tuple[int, ...]] = []
    consumed: set[int] = set()
    starts = [index for index in range(len(clusters)) if index not in predecessor]
    for start in starts:
        chain: list[int] = []
        current = start
        while current not in consumed:
            chain.append(current)
            consumed.add(current)
            if current not in proposed_next:
                break
            current = proposed_next[current]
        chains.append(tuple(chain))
    for cluster_index in range(len(clusters)):
        if cluster_index not in consumed:
            chains.append((cluster_index,))
    return tuple(chains)


def _flatten_pair_chain(pairs: Sequence[PairOccurrence]) -> tuple[PacketPoint, ...]:
    return tuple(packet for occurrence in pairs for packet in occurrence.packets)


def _build_components(
    clusters: Sequence[Sequence[PairOccurrence]], chains: Sequence[Sequence[int]]
) -> list[_BuiltComponent]:
    occurrence_by_position = {
        (
            occurrence.sample_index,
            occurrence.flow_index,
            occurrence.pair_index,
        ): occurrence
        for cluster in clusters
        for occurrence in cluster
    }
    cluster_by_position = {
        (
            occurrence.sample_index,
            occurrence.flow_index,
            occurrence.pair_index,
        ): cluster_index
        for cluster_index, cluster in enumerate(clusters)
        for occurrence in cluster
    }

    built: list[_BuiltComponent] = []
    for chain in chains:
        first_cluster = clusters[chain[0]]
        sequences: list[tuple[PacketPoint, ...]] = []
        positions: dict[int, list[tuple[float, float]]] = defaultdict(list)
        for first_occurrence in first_cluster:
            pair_occurrences: list[PairOccurrence] = []
            valid = True
            for offset, expected_cluster in enumerate(chain):
                key = (
                    first_occurrence.sample_index,
                    first_occurrence.flow_index,
                    first_occurrence.pair_index + offset,
                )
                if cluster_by_position.get(key) != expected_cluster:
                    valid = False
                    break
                pair_occurrences.append(occurrence_by_position[key])
            if not valid:
                continue
            sequence = _flatten_pair_chain(pair_occurrences)
            sequences.append(sequence)
            positions[first_occurrence.sample_index].append(
                (
                    sequence[0].time,
                    sequence[-1].time,
                )
            )
        if not sequences:
            continue
        directions = tuple(packet.direction for packet in sequences[0])
        variants = sorted(
            {
                tuple(packet.size for packet in sequence)
                for sequence in sequences
                if tuple(packet.direction for packet in sequence) == directions
            }
        )
        if not variants:
            continue
        built.append(
            _BuiltComponent(
                component=SequenceComponent(
                    directions=directions,
                    variants=tuple(variants),
                    support=len(positions),
                ),
                positions={
                    sample_index: tuple(sorted(sample_positions))
                    for sample_index, sample_positions in positions.items()
                },
            )
        )
    return built


def _precedes(left: _BuiltComponent, right: _BuiltComponent) -> bool:
    for sample_index, left_positions in left.positions.items():
        right_positions = right.positions.get(sample_index, ())
        for _left_start, left_end in left_positions:
            if not any(right_start > left_end for right_start, _ in right_positions):
                return False
    return bool(left.positions)


def _order_components(components: Sequence[_BuiltComponent]) -> tuple[_BuiltComponent, ...]:
    """Apply PingPong's temporal ordering and shorter-set discard rule."""

    retained = list(components)
    changed = True
    while changed and len(retained) > 1:
        changed = False
        for left_index in range(len(retained)):
            for right_index in range(left_index + 1, len(retained)):
                left = retained[left_index]
                right = retained[right_index]
                if _precedes(left, right) or _precedes(right, left):
                    continue
                left_rank = (left.component.packet_count, left.component.support)
                right_rank = (right.component.packet_count, right.component.support)
                remove_index = right_index if left_rank >= right_rank else left_index
                retained.pop(remove_index)
                changed = True
                break
            if changed:
                break

    def order_key(value: _BuiltComponent) -> tuple[float, int, int]:
        starts = [start for positions in value.positions.values() for start, _ in positions]
        return (
            median(starts) if starts else float("inf"),
            -value.component.packet_count,
            -value.component.support,
        )

    return tuple(sorted(retained, key=order_key))


def extract_signature(
    samples: Sequence[Sequence[PacketPoint]],
    *,
    endpoint: str,
    port: int,
    operation: str,
    label: str,
    config: ExtractionConfig | None = None,
) -> PingPongSignature | None:
    """Compatibility wrapper for one-flow event repetitions."""

    return extract_signature_from_events(
        tuple((sample,) for sample in samples if sample),
        endpoint=endpoint,
        port=port,
        operation=operation,
        label=label,
        config=config,
    )


def extract_signature_from_events(
    events: Sequence[Sequence[Sequence[PacketPoint]]],
    *,
    endpoint: str,
    port: int,
    operation: str,
    label: str,
    config: ExtractionConfig | None = None,
) -> PingPongSignature | None:
    """Extract and validate one endpoint-operation event signature."""

    config = config or ExtractionConfig()
    normalized = [
        value
        for event in events
        if (
            value := _normalise_event_flows(
                event, config.inclusion_window_seconds
            )
        )
    ]
    if config.maximum_training_events:
        normalized = normalized[: config.maximum_training_events]
    if len(normalized) < config.minimum_training_events:
        return None
    clusters = _candidate_pair_clusters(normalized, config)
    if not clusters:
        return None
    chains = _cluster_chains(clusters)
    built_components = _order_components(_build_components(clusters, chains))
    if not built_components:
        return None

    provisional = PingPongSignature(
        endpoint=endpoint,
        port=port,
        operation=operation,
        label=label,
        components=tuple(value.component for value in built_components),
        training_events=len(normalized),
        validation_matches=0,
    )
    validation_matches = sum(
        match_signature_flows(provisional, event, config).success
        for event in normalized
    )
    lower, _upper = _frequency_bounds(len(normalized), config.cluster_slack)
    if validation_matches < lower:
        return None
    return PingPongSignature(
        endpoint=endpoint,
        port=port,
        operation=operation,
        label=label,
        components=provisional.components,
        training_events=len(normalized),
        validation_matches=validation_matches,
    )


def _window_distance(component: SequenceComponent, sizes: Sequence[int]) -> float:
    return min(
        sqrt(
            sum((size - expected) ** 2 for size, expected in zip(sizes, variant))
            / len(variant)
        )
        for variant in component.variants
    )


def _matches_component(
    component: SequenceComponent,
    window: Sequence[PacketPoint],
    config: ExtractionConfig,
) -> tuple[bool, float]:
    if tuple(packet.direction for packet in window) != component.directions:
        return False, float("inf")
    sizes = tuple(packet.size for packet in window)
    if config.matching_strategy == "conservative":
        matched = sizes in component.variants
    else:
        matched = True
        for size, lower, upper in zip(
            sizes, component.lower_bounds, component.upper_bounds
        ):
            if lower == upper:
                if size != lower:
                    matched = False
                    break
            elif not lower - config.epsilon <= size <= upper + config.epsilon:
                matched = False
                break
    return matched, _window_distance(component, sizes) if matched else float("inf")


def _component_matches(
    component: SequenceComponent,
    packets: Sequence[PacketPoint],
    config: ExtractionConfig,
) -> tuple[tuple[int, int, float], ...]:
    length = component.packet_count
    matches: list[tuple[int, int, float]] = []
    for start in range(0, len(packets) - length + 1):
        end = start + length - 1
        matched, distance = _matches_component(
            component, packets[start : end + 1], config
        )
        if matched:
            matches.append((start, end, distance))
    return tuple(matches)


def match_signature(
    signature: PingPongSignature,
    packets: Sequence[PacketPoint],
    config: ExtractionConfig | None = None,
) -> SignatureMatch:
    """Compatibility wrapper for matching inside one layer-3 flow."""

    return match_signature_flows(signature, (packets,), config)


def match_signature_flows(
    signature: PingPongSignature,
    flows: Sequence[Sequence[PacketPoint]],
    config: ExtractionConfig | None = None,
) -> SignatureMatch:
    """Match each component in one flow and combine components by time."""

    config = config or ExtractionConfig()
    normalized = _normalise_event_flows(flows)
    if not normalized or not signature.components:
        return SignatureMatch(False, float("inf"), 0)

    component_matches: list[
        tuple[tuple[float, float, int, int, int, float], ...]
    ] = []
    for component in signature.components:
        matches: list[tuple[float, float, int, int, int, float]] = []
        for flow_index, packets in enumerate(normalized):
            for start, end, distance in _component_matches(
                component, packets, config
            ):
                matches.append(
                    (
                        packets[start].time,
                        packets[end].time,
                        flow_index,
                        start,
                        end,
                        distance,
                    )
                )
        component_matches.append(tuple(matches))
    if any(not matches for matches in component_matches):
        return SignatureMatch(False, float("inf"), 0)

    states: list[
        tuple[
            float,
            float,
            float,
            int,
            int,
            tuple[tuple[int, int, int], ...],
        ]
    ] = [
        (distance, start_time, end_time, flow_index, end, ((flow_index, start, end),))
        for start_time, end_time, flow_index, start, end, distance in component_matches[0]
    ]
    for matches in component_matches[1:]:
        next_states: list[
            tuple[
                float,
                float,
                float,
                int,
                int,
                tuple[tuple[int, int, int], ...],
            ]
        ] = []
        for start_time, end_time, flow_index, start, end, distance in matches:
            viable = [
                state
                for state in states
                if start_time > state[2]
                or (
                    start_time == state[2]
                    and flow_index == state[3]
                    and start > state[4]
                )
            ]
            if not viable:
                continue
            best = min(viable, key=lambda state: (state[0], state[2], state[1]))
            next_states.append(
                (
                    best[0] + distance,
                    best[1],
                    end_time,
                    flow_index,
                    end,
                    best[5] + ((flow_index, start, end),),
                )
            )
        states = next_states
        if not states:
            return SignatureMatch(False, float("inf"), 0)

    valid_states = [
        state
        for state in states
        if state[2] - state[1] <= config.inclusion_window_seconds
    ]
    if not valid_states:
        return SignatureMatch(False, float("inf"), 0)
    best = min(valid_states, key=lambda state: (state[0], state[2], state[1]))
    matched_packets = signature.packet_count
    return SignatureMatch(
        success=True,
        distance=best[0] / max(1, len(signature.components)),
        matched_packets=matched_packets,
        component_spans=best[5],
    )
