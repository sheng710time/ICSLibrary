# Data archives

Download the files from the [ICSLibrary release](https://github.com/sheng710time/ICSLibrary/releases/latest). The release is the data distribution point for this repository.

| Archive | Contents | Use |
| --- | --- | --- |
| [ICSLibrary_benchmark_data_20261015.zip](https://github.com/sheng710time/ICSLibrary/releases/latest/download/ICSLibrary_benchmark_data_20261015.zip) | Labels, sample/connection indices, endpoint folds, raw and instance-controlled PCAP views, paired response inputs | All benchmark methods |
| [ICSLibrary_identifier_masked_20261015.zip](https://github.com/sheng710time/ICSLibrary/releases/latest/download/ICSLibrary_identifier_masked_20261015.zip) | Identifier-masked PCAPs and connection/operation indices | Traffic-view comparisons |
| [ICSLibrary_collections_ABC_20261015.zip](https://github.com/sheng710time/ICSLibrary/releases/latest/download/ICSLibrary_collections_ABC_20261015.zip) | All 180 source PCAPs, source device tables, normalized endpoint labels, and collection mapping | Full resource and broader measurement studies |
| [ICSLibrary_scanning_logs_AB_20261015.zip](https://github.com/sheng710time/ICSLibrary/releases/latest/download/ICSLibrary_scanning_logs_AB_20261015.zip) | Anonymized A/B query records, collection metadata, and round summaries | Collection and response-availability studies |
| [ICSLibrary_code_20261015.zip](https://github.com/sheng710time/ICSLibrary/releases/latest/download/ICSLibrary_code_20261015.zip) | Scanner source, benchmark code, configurations, and documentation | Alternative to a Git checkout |

## Extraction and verification

Verify downloads using the release's [SHA256SUMS](https://github.com/sheng710time/ICSLibrary/releases/latest/download/SHA256SUMS). Each data archive also contains a SHA-256 manifest of its members.

Extract the benchmark-data and identifier-masked archives into `data/` at the repository root:

```text
data/
├── v4_threefold/
└── v4_identifier_addon_v3/
```

Keep the inner TAR files intact: the data loader reads connection PCAPs directly from them. These directory names are the paths expected by the [run instructions](README.md).

Extract the complete-collection and scanning-log archives into separate directories when using them for measurement studies. Their included README files explain their records and mappings.

## Records and observation units

The full resource contains 2,205 endpoints and 165 models. In the complete-collection archive, the source device tables contain 2,219 records; `metadata/labels.csv` contains the 2,205 retained endpoints after excluding 14 paired Modbus port-503 records. `metadata/source_artifacts.csv` maps collection rounds to capture files.

The benchmark subset contains 1,505 endpoints and 71 models. `samples.csv` identifies endpoint-round observations; `flows.csv` locates their connection PCAPs and packet membership. Each of the three traffic views contains the same 40,781 samples, 270,289 connections, and 3,190,239 packets. The controlled views preserve connection boundaries, packet lengths, directions, and relative timing. Transformations are documented in [pcap_views.py](data/pcap_views.py) and [identifier_policy.py](data/identifier_policy.py).

Scanning logs describe collection queries. The log archive contains records for the labeled resource and a separate scope covering all scanned endpoints, together with collection metadata. A log row represents one query, not an endpoint-round traffic sample. Collection C includes packet captures but no corresponding scanning-log export.
