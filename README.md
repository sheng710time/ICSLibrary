# ICSLibrary

ICSLibrary provides labeled network traffic and protocol responses from Internet-facing industrial control system (ICS) devices, together with a benchmark for model identification.

**[Browse the device information](device_information/)** · **[Browse the traffic](network_traffic/)** · **[Browse the scanning logs](scanning_logs/)** · **[Run the benchmark](benchmark/README.md)** · **[Download archives](https://github.com/sheng710time/ICSLibrary/releases/latest)**

## Resource overview

- **2,205 labeled endpoints**, spanning **20 vendors, 8 device types, and 165 models**.
- Three protocols: **Modbus/TCP, EtherNet/IP, and S7comm**.
- **180 anonymized PCAP files** across Collections A, B, and C, with 20 rounds per protocol in each collection.
- Device information tables, plus query logs and collection summaries for Collections A and B.
- A model-identification benchmark covering **1,505 endpoints and 71 models**, with fixed endpoint folds and **40,781 endpoint-round samples** in each traffic view.

Collections A and B were conducted from the same scanner location 28 days apart. Collection C was conducted from a second location during the later collection period. Consistent IP address anonymization links observations of the same endpoint across the collection records.

## Dataset and code organization

```text
ICSLibrary/
├── device_information/       # Protocol-specific identity tables and unified endpoint labels
├── network_traffic/          # All 180 collection PCAPs and their round index
│   ├── collection_A/
│   ├── collection_B/
│   ├── collection_C/
│   └── views/                # Three paired views and shared sample/connection indices
│       ├── raw/
│       ├── instance_controlled/
│       ├── identifier_masked/
│       └── indices/          # Shared samples, endpoint folds, and connection mappings
├── scanning_logs/            # Query records and collection metadata
│   ├── collection_A/         # Records for the labeled resource
│   ├── collection_B/
│   ├── all_scanned_endpoints/
│   └── scanning_info/
├── ics scanners/             # Collection scanner and scheduler source code
├── benchmark/                # Evaluation methods, configurations, and run instructions
│   ├── traffic/              # Five CPU traffic methods
│   ├── trafficformer/        # TrafficFormer adaptation
│   ├── agent/                # Response-identification methods
│   ├── cases/                # 90 endpoints and 180 paired response inputs
│   └── data/                 # Loaders and traffic-view transformations
├── LICENSE
└── README.md
```

| Directory | Contents |
| --- | --- |
| [device_information](device_information/README.md) | Three protocol-specific source tables and `labels.csv`, the normalized labels for the 2,205 retained endpoints. |
| [network_traffic](network_traffic/README.md) | Full captures for Collections A, B, and C; `captures.csv` maps collection rounds to PCAP files. [views/](network_traffic/views/README.md) provides the three paired benchmark views and shared indices. |
| [scanning_logs](scanning_logs/README.md) | A/B query records for the labeled resource, a separate scope covering all scanned endpoints, collection metadata, and `round_summary.csv`. |
| [ics scanners](ics%20scanners/README.md) | Java and SQL source files documenting collection operations and scheduling. |
| [benchmark](benchmark/README.md) | Runnable method adaptations, configurations, dependencies, and instructions. [cases/](benchmark/cases/README.md) contains the fixed response-based case study inputs. |

## Archive downloads

The [release](https://github.com/sheng710time/ICSLibrary/releases/latest) provides archives for bulk download. The collection and log archives contain the data available in the corresponding repository directories. The benchmark archives bundle the paired traffic views and fixed evaluation inputs in the layout used by the evaluation code.

| Download | Contents |
| --- | --- |
| [Complete collections](https://github.com/sheng710time/ICSLibrary/releases/latest/download/ICSLibrary_collections_ABC_20261015.zip) | All 180 anonymized PCAPs, device information tables, unified labels, and collection/round mapping. |
| [Scanning logs](https://github.com/sheng710time/ICSLibrary/releases/latest/download/ICSLibrary_scanning_logs_AB_20261015.zip) | A/B query records, collection metadata, and round summaries. |
| [Benchmark data](https://github.com/sheng710time/ICSLibrary/releases/latest/download/ICSLibrary_benchmark_data_20261015.zip) | Labels, endpoint folds, sample and connection indices, raw and instance-controlled traffic, and paired response inputs. |
| [Identifier-masked view](https://github.com/sheng710time/ICSLibrary/releases/latest/download/ICSLibrary_identifier_masked_20261015.zip) | Identifier-masked traffic and corresponding connection/operation indices. |
| [Source code](https://github.com/sheng710time/ICSLibrary/releases/latest/download/ICSLibrary_code_20261015.zip) | Scanner and benchmark source, configurations, instructions, small data tables/indices, and the paired response cases. Download the traffic and query logs separately. |

[SHA256SUMS](https://github.com/sheng710time/ICSLibrary/releases/latest/download/SHA256SUMS) provides checksums for the five archives. The [data guide](benchmark/DATA.md) describes the benchmark inputs and archive extraction paths.

## Model-identification benchmark

The benchmark evaluates same-endpoint model recognition and unseen-endpoint model identification using six traffic-based methods: LSIF, IDT-AIM, XGB-IDI, PingPong, WiFinger, and TrafficFormer. The [raw](network_traffic/views/raw/), [instance-controlled](network_traffic/views/instance_controlled/), and [identifier-masked](network_traffic/views/identifier_masked/) views support comparisons of instance information and explicit model identifiers. The [paired response case study](benchmark/cases/README.md) compares protocol rules, neural extraction, an adapted NS-FirmID pipeline, and an API extractor on 90 endpoints.

A Git checkout contains the traffic views, evaluation indices, and response cases needed to run the benchmark directly. Alternatively, download the source-code package plus the benchmark-data and identifier-masked archives. The [run instructions](benchmark/README.md) cover both options, environment setup, and commands for each method. Full collection captures and query logs support broader measurement studies and are optional for benchmark execution.

The evaluation workflows operate on released records offline; they do not invoke the Internet scanners.

## What each evaluation uses

| Evaluation | Data | Instructions |
| --- | --- | --- |
| Same-endpoint and unseen-endpoint model identification | Three traffic views, endpoint folds, sample assignments, and model labels | [Traffic methods](benchmark/README.md#2-run-the-five-cpu-traffic-methods), [TrafficFormer](benchmark/README.md#3-run-trafficformer) |
| Instance-information and model-identifier comparisons | Matching samples in raw, instance-controlled, and identifier-masked views | [View definitions and indices](network_traffic/views/README.md) |
| Temporal and scanner-location evaluation | Fixed endpoint folds and A/B/C test samples | [Evaluation conventions](benchmark/README.md#data-and-evaluation-conventions) |
| Paired response interpretation | 90 endpoints under two evidence conditions | [Case inputs](benchmark/cases/README.md), [run commands](benchmark/README.md#4-run-the-paired-response-case-study) |

Evaluation produces new metrics from the supplied inputs. Intermediate caches and model checkpoints are generated locally as needed and do not have to be retained after use.
