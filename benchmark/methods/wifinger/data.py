from __future__ import annotations
from dataclasses import dataclass
from .core import PacketPoint

@dataclass(frozen=True, slots=True)
class Interaction:
    """One protocol probing interaction from one endpoint."""

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
        return cls(
            endpoint=str(value["endpoint"]),
            port=int(value["port"]),
            operation=str(value["operation"]),
            packets=tuple(PacketPoint.from_dict(item) for item in value["packets"]),
            source_file=str(value["source_file"]),
            round_id=(None if value["round_id"] is None else int(value["round_id"])),
            interaction_id=str(value["interaction_id"]),
        )
