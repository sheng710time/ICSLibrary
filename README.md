# Collecting Industrial Control System Device Data on the Internet: A Dataset for Domain Benchmark

This repository includes all data and the implementation of compared methods mentiond in our paper.

## Directory Structure
The directory structure of this repository is as follows:
```bash
├── codes
│   ├── data
│   │   ├── csv
│   │   ├── device_information
│   │   ├── ip_list
│   │   └── pcap
│   ├── device_identification
│   │   ├── IoTDevID
│   │   └── attack_classification
│   └── ics_scanner
│       ├── scanners
│       │   ├── enip
│       │   ├── modbus
│       │   └── s7
│       └── schedulers
│           ├── enip
│           ├── modbus
│           └── s7
├── device_information
│   └── device_information_anonymized.csv
├── network_traffic
│   ├── enip
│   │   ├── Australia
│   │   │   └── enip_YYYYMMDD_roundX_Australia_anonymized.pcap
│   │   └── China
│   │       └── enip_YYYYMMDD_roundX_China_anonymized.pcap
│   ├── modbus
│   │   ├── Australia
│   │   │   └── modbus_YYYYMMDD_roundX_Australia_anonymized.pcap
│   │   └── China
│   │       └── modbus_YYYYMMDD_roundX_China_anonymized.pcap
│   └── s7comm
│       ├── Australia
│       │   └── s7_YYYYMMDD_roundX_Australia_anonymized.pcap
│       └── China
│           └── s7_YYYYMMDD_roundX_China_anonymized.pcap
├── scanning_logs
│   ├── enip
│   │   ├── Australia
│   │   │   └── enip_YYYYMMDD_roundX_Australia_anonymized_log.csv
│   │   └── China
│   │       └── enip_YYYYMMDD_roundX_China_anonymized_log.csv
│   ├── modbus
│   │   ├── Australia
│   │   │   └── modbus_YYYYMMDD_roundX_Australia_anonymized_log.csv
│   │   └── China
│   │       └── modbus_YYYYMMDD_roundX_China_anonymized_log.csv
│   └── s7comm
│       ├── Australia
│       │   └── s7_YYYYMMDD_roundX_Australia_anonymized_log.csv
│       └── China
│           └── s7_YYYYMMDD_roundX_China_anonymized_log.csv
├── vendor_product
│   ├── product_list.csv
│   ├── product_list.xlsx
│   ├── vendor_list.csv
│   └── vendor_list.xlsx
└── README.md
```

## Directory Description
* The "codes" folder includes all necessary data and programs for studying existing device fingerprinting methods using ICSLibrary, as well as ICS scanners for the Modbus/TCP, EtherNet/IP, and S7comm protocols.

* The "device_information" folder contains all device information including IP addresses, corporations, vendors, device types, models, etc..

* The "network_traffic" folder stores all captured network traffic of ICS devices in the form of .pcap files. The name of the .pcap file provides some useful information, such as ICS protocol, scanning time, country and so on.

* The "scanning_logs" folder records the scanning results of all ICS devices on our scanning list, at which all .csv files correspond to the .pcap files in the folder "network_traffic".

* The "vendor_product" folder provides two lists of the device vendors and the device models to which our detected ICS devices belong.

## Security & Privacy
Considering security and privacy concerns, all IP addresses have been anonymized using a prefix-preserving anonymization algorithm. As a result, the IP addresses do not correspond to the real-world IP addresses of exposed ICS devices, and any matches with existing ICS devices should be considered incidental. Despite the anonymization, the IP addresses remain consistent across all files, including network traffic, scanning logs, and device information. The prefix-preserving anonymization algorithm alters the IP addresses while maintaining the original prefix structure. This preservation ensures that anonymized addresses sharing the same prefix group together, which is essential for subsequent network traffic analysis, such as calculating network distance and inferring device groups.


