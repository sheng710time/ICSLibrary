"""Adapt pre-segmented ICS interactions to the supplied WiFinger extractor.

The extractor uses a synthetic timeline to align independent executions. Its
artificial zero-length anchor is removed before model identification. Matching
uses the supplied FMLCS implementation through matcher.py.
"""

from __future__ import annotations

from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
from typing import Sequence

from methods.wifinger.fmlcs.extraction import (
    obtain_fingerprint_from_large_file,
)

from .core import (
    CLIENT_TO_DEVICE,
    DEVICE_TO_CLIENT,
    MatchConfig,
    PacketPoint,
    normalize_sequence,
)


AUTHOR_UP = "UP"
AUTHOR_DOWN = "DOWN"


def _author_direction(direction: int) -> str:
    # In the author data, UP is device -> router and DOWN is router -> device.
    if direction == DEVICE_TO_CLIENT:
        return AUTHOR_UP
    if direction == CLIENT_TO_DEVICE:
        return AUTHOR_DOWN
    raise ValueError(f"Unsupported packet direction: {direction}")


def _ics_direction(direction: str) -> int:
    if direction == AUTHOR_UP:
        return DEVICE_TO_CLIENT
    if direction == AUTHOR_DOWN:
        return CLIENT_TO_DEVICE
    raise ValueError(f"Unsupported author packet direction: {direction}")


def _author_sequence(
    sequence: Sequence[PacketPoint], offset: float = 0.0
) -> list[tuple[float, int, str]]:
    return [
        (float(packet.time) + offset, int(packet.size), _author_direction(packet.direction))
        for packet in sequence
    ]


def extract_source_fingerprint(
    samples: Sequence[Sequence[PacketPoint]],
    config: MatchConfig | None = None,
    max_samples: int = 30,
) -> tuple[PacketPoint, ...]:
    """Run the author fingerprint extractor on pre-segmented ICS events.

    The author extractor expects one continuous recording and event-initiation
    timestamps.  We place the already separated ICS interactions on a synthetic
    timeline with gaps over 15 seconds.  Their starts therefore act as the fake
    anchors used by the supplied extraction code.
    """

    config = config or MatchConfig()
    if config.epsilon != 1:
        raise ValueError("The supplied WiFinger source fixes its size threshold at 1")
    normalized = [normalize_sequence(sample) for sample in samples]
    normalized = [sample for sample in normalized if sample][:max_samples]
    if not normalized:
        return ()

    all_data: list[tuple[float, int, str]] = []
    event_starts: list[float] = []
    offset = 0.0
    for sample in normalized:
        event_starts.append(offset)
        all_data.extend(_author_sequence(sample, offset))
        # The source groups events at packet gaps strictly greater than 15 s.
        offset += float(sample[-1].time) + 16.0

    # The supplied implementation is a CLI-oriented routine with progress
    # output.  Suppress that output when it is called thousands of times by the
    # model-identification experiment runner.
    with redirect_stdout(StringIO()), redirect_stderr(StringIO()):
        fingerprint = obtain_fingerprint_from_large_file(
            all_data,
            event_starts,
            config.advanced_matching,
            len(normalized),
            config.alpha,
            config.refinement_support,
        )

    return tuple(
        PacketPoint(
            time=float(time),
            size=int(size),
            direction=_ics_direction(str(direction)),
        )
        for time, size, direction in fingerprint
    )


def extract_method_fingerprint(
    samples: Sequence[Sequence[PacketPoint]],
    config: MatchConfig | None = None,
    max_samples: int = 30,
) -> tuple[PacketPoint, ...]:
    """Extract a WiFinger fingerprint from pre-segmented ICS interactions.

    The supplied pairwise/refinement routine is retained because the earlier
    native approximation over-pruned discriminating packets.  The artificial
    zero-length packet used only to align training executions is removed from
    the returned fingerprint: it is not observable traffic and must not become
    a device-model feature.
    """

    fingerprint = extract_source_fingerprint(samples, config, max_samples)
    return normalize_sequence(
        tuple(packet for packet in fingerprint if packet.size != 0)
    )
