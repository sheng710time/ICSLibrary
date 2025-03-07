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
* All the scanning requests conform to the corresponding ICS protocol specifications to reduce their potential influence.
* We anonymize all IP addresses of our detected ICS devices through a prefix-preserving anonymization algorithm. 
* Any IP addresses that apprear in ICSLibrary do not represent the real-world IP addresses of ICS devices. In other words, the individual IP address in ICSLibrary is meaningless, but the relationships between IP addresses are remained for further analysis.


