# Scanning logs

These CSV files record protocol queries from Collections A and B, including returned information, query outcomes, and collection metadata. They are collection data, not model-training logs.

| Path | Scope |
| --- | --- |
| `collection_A/`, `collection_B/` | Queries to the 2,205 labeled resource endpoints: 120 round files, 565,640 query records |
| `all_scanned_endpoints/collection_A/`, `all_scanned_endpoints/collection_B/` | All queried endpoints in the corresponding rounds: 120 files, 2,961,960 query records |
| `scanning_info/collection_A/`, `scanning_info/collection_B/` | Six protocol/collection metadata files |
| `round_summary.csv` | Per-round counts, timing, capture/log paths, and checksums for all 120 rounds |

A query-log row describes one protocol query, not one device or endpoint-round traffic sample. The all-endpoint scope includes the labeled resource; the two counts should not be added together. Collection C provides packet captures but no corresponding scanning-log export.

Addresses are anonymized consistently with the [device labels](../device_information/labels.csv) and [packet captures](../network_traffic/). Original-address mappings are not supplied. Paths in `round_summary.csv` are relative to the repository root; `round_index` identifies rounds 1--20 within each collection/protocol.

The [scanning-log archive](https://github.com/sheng710time/ICSLibrary/releases/latest/download/ICSLibrary_scanning_logs_AB_20261015.zip) contains the same query and collection-metadata CSVs. Inside the archive, the labeled and all-endpoint scopes are under `scanning_logs_AB/labeled_resource/scanning_logs/` and `scanning_logs_AB/all_scanned_endpoints/scanning_logs/`, respectively, with collections named `A` and `B`.
