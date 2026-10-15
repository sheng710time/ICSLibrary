from __future__ import annotations
from collections import defaultdict
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Iterable, Sequence
import hashlib
from .core import PacketPoint

@dataclass(frozen=True, slots=True)
class Interaction:
    """One ICS protocol operation observed for one endpoint in one round."""

    endpoint: str
    port: int
    operation: str
    packets: tuple[PacketPoint, ...]
    source_file: str
    round_id: int | None
    interaction_id: str

    def to_dict(self) -> dict[str, object]:
        return {
            "endpoint": self.endpoint,
            "port": self.port,
            "operation": self.operation,
            "packets": [packet.to_dict() for packet in self.packets],
            "source_file": self.source_file,
            "round_id": self.round_id,
            "interaction_id": self.interaction_id,
        }

    @classmethod
    def from_dict(cls, value: dict[str, object]) -> "Interaction":
        packet_values = value.get("packets")
        if not isinstance(packet_values, list):
            raise ValueError("cache interaction packets must be a list")
        return cls(
            endpoint=str(value["endpoint"]),
            port=int(value["port"]),
            operation=str(value["operation"]),
            packets=tuple(PacketPoint.from_dict(item) for item in packet_values),
            source_file=str(value["source_file"]),
            round_id=(
                None if value.get("round_id") is None else int(value["round_id"])
            ),
            interaction_id=str(value["interaction_id"]),
        )


@dataclass(frozen=True, slots=True)
class EventOccurrence:
    """One annotated probing event containing one or more TCP flows."""

    endpoint: str
    port: int
    operation: str
    source_file: str
    round_id: int | None
    occurrence_id: str
    flows: tuple[Interaction, ...]


def group_event_occurrences(
    interactions: Iterable[Interaction],
) -> dict[tuple[str, int, str], list[EventOccurrence]]:
    """Recover one event per endpoint, operation, source capture, and round."""

    grouped: dict[
        tuple[str, int, str, str, int | None], list[Interaction]
    ] = defaultdict(list)
    for interaction in interactions:
        grouped[
            (
                interaction.endpoint,
                interaction.port,
                interaction.operation,
                interaction.source_file,
                interaction.round_id,
            )
        ].append(interaction)

    by_event: dict[tuple[str, int, str], list[EventOccurrence]] = defaultdict(list)
    for key, flows in grouped.items():
        endpoint, port, operation, source_file, round_id = key
        ordered = tuple(
            sorted(
                flows,
                key=lambda flow: (
                    flow.packets[0].time if flow.packets else float("inf"),
                    flow.interaction_id,
                ),
            )
        )
        digest = hashlib.sha256(
            "\x00".join(
                (
                    str(Path(source_file).resolve()),
                    endpoint,
                    str(port),
                    operation,
                    "" if round_id is None else str(round_id),
                )
            ).encode("utf-8")
        ).hexdigest()[:20]
        occurrence = EventOccurrence(
            endpoint=endpoint,
            port=port,
            operation=operation,
            source_file=source_file,
            round_id=round_id,
            occurrence_id=f"{Path(source_file).name}:{digest}",
            flows=ordered,
        )
        by_event[(endpoint, port, operation)].append(occurrence)

    for occurrences in by_event.values():
        occurrences.sort(
            key=lambda value: (
                value.round_id if value.round_id is not None else -1,
                value.source_file,
                value.occurrence_id,
            )
        )
    return dict(by_event)
