# ICSLibrary

ICSLibrary is a dataset of anonymized network traffic, scanning logs, and device information collected from industrial control system (ICS) devices that are reachable from the public Internet.

It is designed for studying whether an exposed ICS device can be recognized from its network behavior. In practice, that means using real Internet-facing network traffic to build and evaluate methods for identifying a device's vendor, device type, or model.

This repository contains both the dataset itself and the protocol-specific scanner code used to collect it. The release covers `Modbus/TCP`, `EtherNet/IP`, and `S7comm`.

## Model-identification benchmark

The [benchmark](benchmark/README.md) provides fixed endpoint folds, sample indices,
paired traffic views, and runnable method adapters. The task uses 1,505 endpoints
and 71 models from the full resource. Follow the documented commands to compute
new experimental results from the released data. Data archives are described in
[benchmark/DATA.md](benchmark/DATA.md).

## At A Glance

- Covers `13,002` responsive Internet-facing ICS endpoints
- Includes `2,205` labeled endpoints spanning `20` vendors, `8` device types, and `165` device models
- Supports `3` ICS protocols: `Modbus/TCP`, `EtherNet/IP`, and `S7comm`
- Organizes the measurements into `3` collections: `collection_A`, `collection_B`, and `collection_C`
- Provides `60` scanning rounds per protocol and `180` released PCAP files in total
- Uses consistent prefix-preserving anonymization of IP addresses across device information, network traffic, and scanning logs

## Dataset Organization

The dataset is organized into three collections:

- `collection_A`
  - region: `Region A`
  - study role: the earlier `Region A` collection, used with `collection_B` for cross-time comparison
  - `modbus_ra`: rounds `21-40`
  - `enip_ra`: rounds `3-22`
  - `s7_ra`: rounds `21-40`
- `collection_B`
  - region: `Region A`
  - study role: the later `Region A` collection, gathered `28` days after `collection_A`, used with `collection_A` for cross-time comparison and with `collection_C` for cross-location comparison
  - `modbus_ra`: rounds `41-60`
  - `enip_ra`: rounds `50-69`
  - `s7_ra`: rounds `41-60`
- `collection_C`
  - region: `Region B`
  - study role: the `Region B` collection aligned with the later collection stage represented by `collection_B`, used with `collection_B` for cross-location comparison
  - `modbus_rb`: rounds `41-60`
  - `enip_rb`: rounds `50-69`
  - `s7_rb`: rounds `41-60`

The three collections are designed to capture temporal and location-based variation: `collection_A` and `collection_B` are two `Region A` collections gathered `28` days apart, while `collection_C` is collected from `Region B`. This organization supports cross-time comparison between `collection_A` and `collection_B`, and cross-location comparison between `collection_B` and `collection_C`. In this release, `collection_A` and `collection_B` include both PCAP files and scanning-log CSV files, while `collection_C` provides PCAP files.

## Repository Layout

```text
ICSLibrary/
|-- device_information/
|   |-- enip_device_information.csv
|   |-- modbus_device_information.csv
|   `-- s7_device_information.csv
|-- ics scanners/
|   |-- ScannersMoreTest.java
|   |-- scanners/
|   |-- schedulers/
|   `-- sqls/
|-- network_traffic/
|   |-- collection_A/
|   |-- collection_B/
|   `-- collection_C/
|-- scanning_logs/
|   |-- collection_A/
|   `-- collection_B/
`-- README.md
```

## What You'll Find In This Repository

### `device_information/`

Protocol-specific device information for labeled endpoints. The tables contain both protocol-reported identity fields and normalized labels so that users can either work with the original returned values or directly use the benchmark labels.

The main fields can be interpreted as follows:

- `vendor`, `product_code`, `product_name`, and `model_name` are the original identity fields extracted from protocol-specific responses.
- `vendor_label`, `type_label`, and `model_label` are normalized labels intended for vendor-, type-, and model-level identification tasks.
- `model_label` is a canonical model identifier derived from the extracted identity fields, using the form `vendor_label::product_code::product_name::model_name`; empty segments are preserved when some protocol-specific fields are unavailable.
- `valid` indicates that the entry is retained as a reliable labeled endpoint; in the released tables, all rows have `valid = 1`.

### `network_traffic/`

Anonymized network traffic in PCAP format grouped by collection, protocol, and round. File names encode the protocol, scanning round, and region suffix:

- `ra`: Region A
- `rb`: Region B

### `scanning_logs/`

Per-round scanning logs corresponding to the released network traffic in `collection_A` and `collection_B`. These CSV files include timestamps, response summaries, scan modes, and extracted metadata when available.

### `ics scanners/`

Protocol-specific scanner and scheduler source files used during data collection. These files are included to document the probing logic behind the released measurements.

## Anonymization

All released IP addresses are anonymized with a prefix-preserving transformation. The anonymized addresses remain consistent across the device information, network traffic, and scanning logs, allowing cross-file linkage without exposing the original public endpoints.

## Notes

- The scanner source files are provided for transparency and code inspection.
- Some source files depend on components from the original collection environment and may require additional project context to run directly.
- The released data are intended for research on ICS device fingerprinting, label extraction, temporal variation, and cross-location robustness under Internet-facing measurement conditions.
