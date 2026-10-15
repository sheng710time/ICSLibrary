# Data archives

| Archive | Contents | Required for adapters |
| --- | --- | --- |
| `ICSLibrary_benchmark_data_20261015.zip` | Labels, sample/flow indices, endpoint folds, raw and instance-controlled PCAP views, paired response inputs | All methods |
| `ICSLibrary_identifier_masked_20261015.zip` | Identifier-masked PCAPs and shared operation/connection indices | Traffic methods |
| `ICSLibrary_collections_ABC_20261015.zip` | All 180 source PCAPs, original device tables and collection mapping | Broader measurement studies |
| `ICSLibrary_scanning_logs_AB_20261015.zip` | Anonymous A/B collection logs and round summaries | Broader measurement studies |
| `ICSLibrary_code_20261015.zip` | Scanner source, benchmark adapters, configurations and documentation | Alternative to a Git checkout |

The release's `SHA256SUMS` identifies the archive files. Each data archive also
contains a SHA-256 manifest of its members. The benchmark indices and PCAP bytes
are unchanged from the finalized experimental dataset; archive manifests were
regenerated after removing internal verification reports and historical plans.

The benchmark subset contains 1,505 endpoints and 71 models. The complete
resource has 2,205 endpoints and 165 models. `samples.csv` identifies endpoint-round
observations; `flows.csv` locates their connection PCAPs and packet membership.
The two controlled views retain connection boundaries, packet lengths, directions
and relative timing. The protocol transformations are supplied as readable code
in `data/pcap_views.py` and `data/identifier_policy.py`.

Dataset inputs are distinct from experimental outputs: scanning logs describe
collection queries; they are not model-training logs or prediction records.
