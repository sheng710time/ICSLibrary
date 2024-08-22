# ICSLibrary: A Versatile Dataset for Network-Traffic-Based CPS Device Identification

This repository includes all data and the implementation of compared methods mentiond in our paper.

## Directory Structure
The directory structure of this repository is as follows:
>device_information  
>>device_information_anonymized.csv

>network_traffic  
>>enip_YYYYMMDD_roundX_Country_anonymized.pcap  
>>modbus_YYYYMMDD_roundX_Country_anonymized.pcap

>projects  
>>data  
>>>csv  
>>>device_information  
>>>ip_list  
>>>pcap  
>>device_identification  
>>>IoTDevID  
>>>attack_classification

>scanning_logs  
>>enip_YYYYMMDD_roundX_Country_anonymized_log.pcap  
>>modbus_YYYYMMDD_roundX_Country_anonymized_log.pcap  
>vendor_product  
>>product_list  
>>vendor_list  

├── src
│   ├── main.py
│   ├── utils.py
│   └── ...
├── data
│   ├── raw
│   ├── processed
│   └── ...
├── tests
│   ├── test_main.py
│   └── ...
└── README.md
