# ICSLibrary: A Versatile Dataset for Network-Traffic-Based CPS Device Identification

This repository includes all data and the implementation of compared methods mentiond in our paper.

## Directory Structure
The directory structure of this repository is as follows:
```bash
├── device_information
│   └── device_information_anonymized.csv
├── network_traffic
│   ├── enip_YYYYMMDD_roundX_China_anonymized.pcap
│   ├── enip_YYYYMMDD_roundX_Australia_anonymized.pcap
│   ├── modbus_YYYYMMDD_roundX_China_anonymized.pcap
│   └── modbus_YYYYMMDD_roundX_Australia_anonymized.pcap
├── projects
│   ├── data
│   │   ├── csv
│   │   ├── device_information
│   │   ├── ip_list
│   │   └── pcap
│   └── device_identification
│       ├── IoTDevID
│       └── attack_classification
├── scanning_logs
│   ├── enip_YYYYMMDD_roundX_China_anonymized_log.csv
│   ├── enip_YYYYMMDD_roundX_Australia_anonymized_log.csv
│   ├── modbus_YYYYMMDD_roundX_China_anonymized_log.csv
│   └── modbus_YYYYMMDD_roundX_Australia_anonymized_log.csv
├── vendor_product
│   ├── product_list.csv
│   ├── product_list.xlsx
│   ├── vendor_list.csv
│   └── vendor_list.xlsx
├── .gitignore
├── LICENSE
└── README.md
```

## Directory Description
* The folder "device_information" contains all device information including IP addresses, corporations, vendors, device types, models, etc..

* The folder "network_traffic" stores all captured network traffic of ICS devices in the form of .pcap files. The name of the .pcap file provides some useful information, such as ICS protocol, scanning time, country and so on.

* The folder "projects" involves all necessary data and programs to study some existing device fingerprinting methods by ICSLibrary.

* The folder "scanning_logs" records the scanning results of all ICS devices on our scanning list, at which all .csv files correspond to the .pcap files in the folder "network_traffic".

* The folder "vendor_product" provides two lists of the device vendors and the device models to which our detected ICS devices belong.

## Security & Privacy
