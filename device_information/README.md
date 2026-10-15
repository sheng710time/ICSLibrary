# Device information

This directory provides the protocol-reported device information and the normalized labels used by ICSLibrary.

| File | Records | Contents |
| --- | ---: | --- |
| `modbus_device_information.csv` | 919 | Modbus/TCP source device information |
| `enip_device_information.csv` | 784 | EtherNet/IP source device information |
| `s7_device_information.csv` | 516 | S7comm source device information |
| `labels.csv` | 2,205 | Unified endpoint, protocol, anonymous address, port, vendor, device-type, and model labels |

The source tables contain 2,219 records. When a Modbus address has records for both ports 502 and 503, the resource retains port 502. Removing these 14 paired port-503 records yields the 2,205 endpoints in `labels.csv`; the 12 endpoints available only on port 503 remain included.

Source tables retain protocol-specific identity fields alongside normalized labels. Empty fields indicate that the corresponding information was not provided. The unified table covers 20 vendors, 8 device types, and 165 canonical model labels.

Addresses are consistently anonymized across device tables, [packet captures](../network_traffic/), and [scanning logs](../scanning_logs/). For the 1,505-endpoint model-identification subset, the [benchmark data archive](https://github.com/sheng710time/ICSLibrary/releases/latest/download/ICSLibrary_benchmark_data_20261015.zip) provides endpoint folds and sample assignments.

The complete-collection archive contains the same three source tables under `device_information/` and the unified table under `metadata/labels.csv`.
