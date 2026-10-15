# WiFinger

This directory contains the single WiFinger implementation used in the benchmark.

- `data.py` and `core.py` define ICS interactions, packets, fingerprints, and match results.
- `experiment.py` builds fingerprints separately for training endpoints and protocol operations.
- `source_adapter.py` passes independent ICS interactions to the supplied fingerprint extractor and removes its artificial alignment anchor.
- `fmlcs/extraction.py` and `fmlcs/lcs.py` contain the required supplied extraction and FMLCS algorithms.
- `matcher.py` invokes FMLCS and reuses identical size/direction path computations without truncating the matching paths.

The `fmlcs/` subdirectory is a dependency of this method, not a second benchmark variant. Shared model-label decisions and validation-based fingerprint eligibility are handled by [`../../traffic/decision.py`](../../traffic/decision.py) and [`../../traffic/run.py`](../../traffic/run.py).

Run `benchmark/traffic/run.py --method WiFinger` with the data, protocol, fold, view, and output arguments shown in the [benchmark instructions](../../README.md#2-run-the-five-cpu-traffic-methods). Fingerprints are built during execution; saved experimental predictions are not required.
