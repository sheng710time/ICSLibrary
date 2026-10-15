# ICSLibrary

ICSLibrary provides labeled network traffic and protocol responses from Internet-facing industrial control system (ICS) devices, together with a benchmark for model identification.

**[Download the dataset and code](https://github.com/sheng710time/ICSLibrary/releases/latest)** · **[Run the benchmark](benchmark/README.md)** · **[Data guide](benchmark/DATA.md)**

## Resource overview

- **2,205 labeled endpoints**, spanning **20 vendors, 8 device types, and 165 models**.
- Three protocols: **Modbus/TCP, EtherNet/IP, and S7comm**.
- **180 anonymized PCAP files** across Collections A, B, and C, with 20 rounds per protocol in each collection.
- Device information tables, plus scanning logs for Collections A and B.
- A model-identification benchmark covering **1,505 endpoints and 71 models**, with fixed endpoint folds and **40,781 endpoint-round samples** in each traffic view.

Collections A and B were conducted from the same scanner location 28 days apart. Collection C was conducted from a second location during the later collection period. Consistent IP address anonymization links observations of the same endpoint across the collection records.

## Download the data

The [release](https://github.com/sheng710time/ICSLibrary/releases/latest) contains the complete data archives and a standalone code package. All files needed for the resource are listed below; downloading or cloning the repository alone provides the code, not the data archives.

| Download | Contents |
| --- | --- |
| [Complete collections](https://github.com/sheng710time/ICSLibrary/releases/latest/download/ICSLibrary_collections_ABC_20261015.zip) | All 180 anonymized PCAPs, source device information tables, normalized labels for 2,205 endpoints, and collection/round mapping. |
| [Scanning logs](https://github.com/sheng710time/ICSLibrary/releases/latest/download/ICSLibrary_scanning_logs_AB_20261015.zip) | Anonymized query records, collection metadata, and round summaries for Collections A and B. |
| [Benchmark data](https://github.com/sheng710time/ICSLibrary/releases/latest/download/ICSLibrary_benchmark_data_20261015.zip) | Labels, endpoint folds, sample and connection indices, raw and instance-controlled traffic, and paired response inputs. |
| [Identifier-masked view](https://github.com/sheng710time/ICSLibrary/releases/latest/download/ICSLibrary_identifier_masked_20261015.zip) | Identifier-masked traffic and corresponding connection/operation indices. |
| [Source code](https://github.com/sheng710time/ICSLibrary/releases/latest/download/ICSLibrary_code_20261015.zip) | Scanner source, benchmark code, configurations, dependencies, and instructions; an alternative to cloning this repository. |

[SHA256SUMS](https://github.com/sheng710time/ICSLibrary/releases/latest/download/SHA256SUMS) provides checksums for the five archives. See the [data guide](benchmark/DATA.md) for archive contents and extraction paths.

## Run the benchmark

The benchmark evaluates same-endpoint model recognition and unseen-endpoint model identification using six traffic-based methods: LSIF, IDT-AIM, XGB-IDI, PingPong, WiFinger, and TrafficFormer. Three paired traffic views support comparisons of instance information and explicit model identifiers. The response-based case study compares protocol rules, neural extraction, and an adapted NS-FirmID pipeline.

1. Clone this repository or extract the source-code archive.
2. Download and extract the benchmark-data and identifier-masked archives into `data/` at the repository root.
3. Follow the [environment setup and execution instructions](benchmark/README.md) for the selected method.

The complete collections and scanning logs support broader identification and measurement studies; they are optional for running the benchmark. Each evaluation workflow computes predictions and metrics from the released inputs.

## Repository contents

```text
ICSLibrary/
├── benchmark/       # Evaluation code, configurations, dependencies, and data guide
├── scanners/        # Collection scanner and scheduler source code
├── LICENSE
└── README.md
```

The [scanner source](scanners/README.md) documents collection operations. Benchmark execution uses the released records offline and does not run the Internet scanners.
