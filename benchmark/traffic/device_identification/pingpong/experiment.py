from __future__ import annotations
from collections import defaultdict
from dataclasses import dataclass
from fractions import Fraction
from typing import Iterable, Mapping, Sequence
from .core import ExtractionConfig, PingPongSignature, extract_signature_from_events
from .data import Interaction, group_event_occurrences

def build_signatures(
    interactions: Iterable[Interaction],
    labels: dict[str, str],
    config: ExtractionConfig | None = None,
) -> list[PingPongSignature]:
    """Build one signature per endpoint, protocol port, and operation."""

    config = config or ExtractionConfig()
    signatures: list[PingPongSignature] = []
    grouped = group_event_occurrences(interactions)
    for (endpoint, port, operation), occurrences in sorted(grouped.items()):
        label = labels.get(endpoint)
        if label is None:
            continue
        signature = extract_signature_from_events(
            [
                tuple(flow.packets for flow in occurrence.flows)
                for occurrence in occurrences
            ],
            endpoint=endpoint,
            port=port,
            operation=operation,
            label=label,
            config=config,
        )
        if signature is not None:
            signatures.append(signature)
    return signatures


@dataclass(frozen=True, order=True, slots=True)
class _SignatureEvidence:
    packet_count: int
    validation_stability: Fraction
    component_stability: Fraction
    component_support: int


def _signature_evidence(signature: PingPongSignature) -> _SignatureEvidence:
    return _SignatureEvidence(
        packet_count=signature.packet_count,
        validation_stability=Fraction(
            signature.validation_matches, signature.training_events
        ),
        component_stability=min(
            Fraction(component.support, signature.training_events)
            for component in signature.components
        ),
        component_support=sum(
            component.support for component in signature.components
        ),
    )


def _training_label_ranks(
    signatures: Sequence[PingPongSignature],
    training_model_labels: Mapping[str, int] | Iterable[str] | None,
) -> tuple[
    tuple[str, ...],
    dict[str, tuple[object, ...]],
    Mapping[str, int] | None,
]:
    """Build model ranks and an optional endpoint-count training prior."""

    by_label: dict[str, list[PingPongSignature]] = defaultdict(list)
    for signature in signatures:
        by_label[signature.label].append(signature)
    if isinstance(training_model_labels, Mapping):
        training_support: Mapping[str, int] | None = training_model_labels
        supplied_labels = set(training_model_labels)
    else:
        training_support = None
        supplied_labels = set(training_model_labels or ())
    labels = tuple(sorted(set(by_label) | supplied_labels))
    ranks: dict[str, tuple[object, ...]] = {}
    for label in labels:
        values = by_label.get(label, [])
        evidence = max(
            (_signature_evidence(signature) for signature in values),
            default=_NO_SIGNATURE_EVIDENCE,
        )
        ranks[label] = (
            evidence.packet_count,
            evidence.validation_stability,
            evidence.component_stability,
            evidence.component_support,
        )
    return labels, ranks, training_support


_NO_SIGNATURE_EVIDENCE = _SignatureEvidence(0, Fraction(0,1), Fraction(0,1), 0)
