# Collecting Industrial Control System Device Data on the Internet: A Dataset for Domain Benchmark

Due to the limited understanding of Industrial Control Systems (ICSs), device identification has become increasingly vital for threat detection and security defense in ICS environments. However, the narrow range of device types and models in the existing datasets has significantly hindered the effectiveness and scalability of current device identification methods. To address this gap, we introduce a novel data collection framework specifically designed for ICS devices and present the resulting dataset, ICSLibrary, which we have made publicly available. To the best of the authors' knowledge, ICSLibrary is the first dataset dedicated to device identification in ICS security. It encompasses the most extensive range of device types, models and instances from 27 industrial vendors, collected across two countries over a 21-month period. Furthermore, we use ICSLibrary as a benchmark to evaluate several typical device fingerprinting methods, revealing a notable 16% drop in accuracy in the device model identification task, which highlights the unique challenges posed by ICSLibrary.

## Directory Structure
The directory structure of this repository is as follows:
```bash
ICSLibrary/
├── codes/
│   ├── data/
│   │   ├── csv/
│   │   ├── device_information/
│   │   ├── ip_list/
│   │   └── pcap/
│   ├── device_identification/
│   │   ├── attack_classification/
│   │   ├── IoTDevID/
│   │   └── pcap_parsing_samples/
│   └── ics_scanner/
│       ├── scanners/
│       │   ├── enip/
│       │   ├── modbus/
│       │   └── s7/
│       └── schedulers/
│           ├── enip/
│           ├── modbus/
│           └── s7/
├── device_information/
│   └── device_information_anonymized.csv
├── network_traffic/
│   ├── enip/
│   │   ├── Australia/
│   │   │   └── enip_YYYYMMDD_roundX_Australia_anonymized.pcap
│   │   └── China/
│   │       └── enip_YYYYMMDD_roundX_China_anonymized.pcap
│   ├── modbus/
│   │   ├── Australia/
│   │   │   └── modbus_YYYYMMDD_roundX_Australia_anonymized.pcap
│   │   └── China/
│   │       └── modbus_YYYYMMDD_roundX_China_anonymized.pcap
│   └── s7comm/
│       ├── Australia/
│       │   └── s7_YYYYMMDD_roundX_Australia_anonymized.pcap
│       └── China/
│           └── s7_YYYYMMDD_roundX_China_anonymized.pcap
├── network_traffic_encrypted/
│   ├── enip/
│   │   ├── Australia/
│   │   │   └── enip_YYYYMMDD_roundX_Australia_anonymized_encrypted.pcap
│   │   └── China/
│   │       └── enip_YYYYMMDD_roundX_China_anonymized_encrypted.pcap
│   ├── modbus/
│   │   ├── Australia/
│   │   │   └── modbus_YYYYMMDD_roundX_Australia_anonymized_encrypted.pcap
│   │   └── China/
│   │       └── modbus_YYYYMMDD_roundX_China_anonymized_encrypted.pcap
│   └── s7comm/
│       ├── Australia/
│       │   └── s7_YYYYMMDD_roundX_Australia_anonymized_encrypted.pcap
│       └── China/
│           └── s7_YYYYMMDD_roundX_China_anonymized_encrypted.pcap
├── scanning_logs/
│   ├── enip/
│   │   ├── Australia/
│   │   │   └── enip_YYYYMMDD_roundX_Australia_anonymized_log.csv
│   │   └── China/
│   │       └── enip_YYYYMMDD_roundX_China_anonymized_log.csv
│   ├── modbus/
│   │   ├── Australia/
│   │   │   └── modbus_YYYYMMDD_roundX_Australia_anonymized_log.csv
│   │   └── China/
│   │       └── modbus_YYYYMMDD_roundX_China_anonymized_log.csv
│   └── s7comm/
│       ├── Australia/
│       │   └── s7_YYYYMMDD_roundX_Australia_anonymized_log.csv
│       └── China/
│           └── s7_YYYYMMDD_roundX_China_anonymized_log.csv
├── vendor_product/
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


