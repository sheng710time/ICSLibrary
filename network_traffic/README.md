# Network traffic

This directory contains all 180 anonymized PCAP files in the full resource: three collections, three protocols, and 20 rounds per protocol in each collection.

| Directory | Collection conditions |
| --- | --- |
| `collection_A/` | Earlier collection at the first scanner location |
| `collection_B/` | Same scanner location, 28 days after Collection A |
| `collection_C/` | Second scanner location during the later collection period |

Each collection has `modbus/`, `enip/`, and `s7/` subdirectories. Captures preserve requests, responses, and transport behavior.

`captures.csv` maps each collection/protocol/round to its PCAP path, byte count, SHA-256 checksum, and packet count. Use `round_index` for the within-collection round number (1--20); the source filenames retain their original scanning-round suffixes. File paths are relative to the repository root.

[Device labels](../device_information/) identify endpoints through protocol, anonymous address, and port. [Scanning logs](../scanning_logs/) supplement Collections A and B with query outcomes and collection metadata.

## Paired traffic views

The benchmark uses selected endpoint-round samples to construct raw, instance-controlled, and identifier-masked views. These reusable views, their sample/connection indices, and endpoint folds are available in the [benchmark-data](https://github.com/sheng710time/ICSLibrary/releases/latest/download/ICSLibrary_benchmark_data_20261015.zip) and [identifier-masked](https://github.com/sheng710time/ICSLibrary/releases/latest/download/ICSLibrary_identifier_masked_20261015.zip) archives. See the [benchmark data guide](../benchmark/DATA.md) for loading them.

The [complete-collection archive](https://github.com/sheng710time/ICSLibrary/releases/latest/download/ICSLibrary_collections_ABC_20261015.zip) contains the same 180 PCAPs and the collection mapping under `metadata/source_artifacts.csv`.
