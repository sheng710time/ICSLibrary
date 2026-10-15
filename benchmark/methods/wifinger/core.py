"""WiFinger packet, fingerprint and match data types for the ICS adapter."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Sequence


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
