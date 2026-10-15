# Paired traffic views

These three views contain matching traffic samples for model-identification experiments. Each view contains **40,781 endpoint-round samples, 270,289 connections, and 3,190,239 packets**, drawn from 1,505 endpoints covering 71 models.

| View | Data directory | Information control |
| --- | --- | --- |
| Raw | [raw/](raw/) | Anonymized traffic from the selected observations. |
| Instance-controlled | [instance_controlled/](instance_controlled/) | Instance and session information is normalized; explicit model identifiers are retained. |
| Identifier-masked | [identifier_masked/](identifier_masked/) | Selected explicit product/model fields are additionally masked in the instance-controlled traffic. |

Each directory contains 84 TAR archives, grouped by collection, protocol, and round. Each TAR member is a connection PCAP. All views use observations from Collection A rounds 1--20 and Collections B/C rounds 17--20 for the selected endpoints. Source filenames retain their original scanning-round suffixes; use `round_index` in the sample table for within-collection rounds.

The full 20-round source captures for every collection remain in [collection_A](../collection_A/), [collection_B](../collection_B/), and [collection_C](../collection_C/).

## Shared indices

| File | Purpose |
| --- | --- |
| [indices/samples.csv](indices/samples.csv) | Endpoint-round sample IDs, endpoint IDs, collections, rounds, and traffic counts. |
| [indices/labels.csv](indices/labels.csv) | Endpoint vendor, device-type, and model labels for the resource. |
| [indices/classes.csv](indices/classes.csv) | Benchmark model-class indices. |
| [indices/endpoint_folds.csv](indices/endpoint_folds.csv) | Fixed endpoint folds. |
| [indices/sample_assignments.csv](indices/sample_assignments.csv) | Training, validation, and same/unseen test membership. |
| [indices/flows.csv.gz](indices/flows.csv.gz) | Connection-to-sample mapping and PCAP archive paths, member names, byte offsets, lengths, and SHA-256 values for all three views. |
| [indices/flow_operations.csv.gz](indices/flow_operations.csv.gz) | Protocol operations associated with each connection. |

The large connection indices are compressed CSV files. Archive paths in `flows.csv.gz` are relative to this `views/` directory. A sample can contain multiple connections; match `sample_id` across the flow and sample tables. The same flow row locates the paired connection PCAP in each view.

For example, run the following from the repository root to read and verify the first indexed connection in each view:

```python
import csv
import gzip
import hashlib
from pathlib import Path

root = Path("network_traffic/views")
with gzip.open(root / "indices/flows.csv.gz", "rt", newline="") as stream:
    row = next(csv.DictReader(stream))

for view in ("raw", "instance_controlled", "identifier_masked"):
    with (root / row[view + "_archive"]).open("rb") as stream:
        stream.seek(int(row[view + "_offset"]))
        pcap = stream.read(int(row[view + "_bytes"]))
    assert hashlib.sha256(pcap).hexdigest() == row[view + "_sha256"]
    print(view, row["flow_id"], len(pcap))
```

[files.sha256.json](files.sha256.json) records checksums for the view files and indices. The PCAP/TAR bytes match the released benchmark-data and identifier-masked archives. The benchmark can read this directory directly using `--base network_traffic/views --addon network_traffic/views`. It also supports the original archive layout. See the [run instructions](../../benchmark/README.md) and [data guide](../../benchmark/DATA.md).
