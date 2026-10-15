from __future__ import annotations
from collections import defaultdict
from typing import Iterable
from .core import Fingerprint, MatchConfig
from .data import Interaction
from .source_adapter import extract_method_fingerprint

def build_fingerprints(
    interactions: Iterable[Interaction],
    labels: dict[str, str],
    config: MatchConfig | None = None,
    max_samples: int = 30,
    *,
    group_records: list[dict[str, object]] | None = None,
) -> list[Fingerprint]:
    """Construct independently per training endpoint/port/operation.

    group_records is an optional audit sink, never an extraction input.
    """

    config = config or MatchConfig()
    fingerprints: list[Fingerprint] = []
    grouped: dict[tuple[str, int, str], list[Interaction]] = defaultdict(list)
    for interaction in interactions:
        if interaction.endpoint not in labels:
            continue
        grouped[
            (interaction.endpoint, interaction.port, interaction.operation)
        ].append(interaction)

    # Keep the existing label/port/operation order for cross-label matching ties.
    # Endpoint order only resolves the newly possible within-label duplicates.
    for (endpoint, port, operation), samples in sorted(
        grouped.items(), key=lambda item: (labels[item[0][0]], item[0][1], item[0][2], item[0][0])
    ):
        label = labels[endpoint]
        # One endpoint-round is one independent execution.  Duplicate flows
        # inside the same round must not inflate extraction support.
        candidates: list[Interaction] = []
        seen_executions: set[tuple[object, ...]] = set()
        for sample in sorted(
            samples,
            key=lambda item: (
                item.endpoint,
                item.round_id if item.round_id is not None else -1,
                item.source_file,
                item.interaction_id,
            ),
        ):
            execution = (
                (sample.endpoint, sample.source_file, sample.round_id)
                if sample.round_id is not None
                else (sample.interaction_id,)
            )
            if execution in seen_executions:
                continue
            seen_executions.add(execution)
            candidates.append(sample)

        if len(candidates) <= max_samples:
            independent_samples = candidates
        elif max_samples == 1:
            independent_samples = [candidates[0]]
        else:
            # Retain the existing deterministic cap; A rounds 1-12 never hit it.
            indices = [
                round(index * (len(candidates) - 1) / (max_samples - 1))
                for index in range(max_samples)
            ]
            independent_samples = [candidates[index] for index in indices]
        packets = extract_method_fingerprint(
            [sample.packets for sample in independent_samples],
            config,
            max_samples=max_samples,
        )
        if group_records is not None:
            group_records.append({
                "endpoint_id": endpoint, "service_port": port,
                "operation": operation, "model_label": label,
                "raw_interactions": len(samples),
                "independent_executions": len(candidates),
                "used_executions": len(independent_samples),
                "all_interaction_ids": [s.interaction_id for s in samples],
                "selected_interaction_ids": [s.interaction_id for s in independent_samples],
                "selected_rounds": [s.round_id for s in independent_samples],
                "selected_captures": [s.source_file for s in independent_samples],
                "fingerprint_packets": len(packets),
                "extraction_status": "extracted" if len(packets) >= config.minimum_fingerprint_packets else (
                    "insufficient-independent-executions" if len(independent_samples) < 2 else (
                        "empty-after-native-extraction" if not packets else "below-minimum-fingerprint-packets")),
            })
        if len(packets) < config.minimum_fingerprint_packets:
            continue
        fingerprints.append(
            Fingerprint(
                endpoint=endpoint,
                port=port,
                operation=operation,
                label=label,
                packets=packets,
                training_samples=len(independent_samples),
            )
        )
    return fingerprints


def _overlap_upper_bound(
    fingerprint: Fingerprint, interaction: Interaction, config: MatchConfig
) -> float:
    matching = 0
    for packet in fingerprint.packets:
        if any(
            packet.direction == target.direction
            and abs(packet.size - target.size) < config.epsilon
            for target in interaction.packets
        ):
            matching += 1
    return matching / len(fingerprint.packets) if fingerprint.packets else 0.0
