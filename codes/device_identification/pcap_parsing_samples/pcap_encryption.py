"""
Coding: UTF-8
Author: Chuan Sheng
Date: 2025/7/2 8:52
Description:
"""
from Crypto.Util.Padding import pad
from scapy.all import *
import copy
from Crypto.Cipher import AES
from scapy.layers.inet import TCP, IP
from scapy.layers.l2 import Ether
import glob

from device_identification.pcap_parsing_samples.pcap_process import is_ics_port_by_protocol


def defense_different_encryption_packets(train_device_packets, protocol):
    """
    Apply AES encryption (CBC mode) to Raw payloads of ICS response packets.
    A new AES key/IV is randomly generated for each source IP per function call.

    Args:
        train_device_packets (list): List of Scapy packets
        protocol (str): Protocol name, e.g., "Modbus"

    Returns:
        list: List of packets with encrypted payloads
    """
    encrypted_packets = []
    encrypted_count = 0
    # Per-function-call random AES key/IV per IP
    ip_keys = {}  # src_ip: (key, iv)

    for pkt in train_device_packets:
        pkt_copy = copy.deepcopy(pkt)

        if pkt_copy.haslayer(TCP) and pkt_copy.haslayer(Raw) and is_ics_port_by_protocol(pkt_copy[TCP].sport, protocol):
            ics_ip = pkt_copy[IP].src
            # Assign a new key/iv per IP in this call
            if ics_ip not in ip_keys:
                key = os.urandom(16)  # 128-bit AES key
                iv = os.urandom(16)   # 128-bit IV
                ip_keys[ics_ip] = (key, iv)

            key, iv = ip_keys[ics_ip]

            raw_payload = pkt_copy[Raw].load
            padded_data = pad(raw_payload, AES.block_size)

            cipher = AES.new(key, AES.MODE_CBC, iv)
            encrypted_payload = cipher.encrypt(padded_data)
            pkt_copy[Raw].load = encrypted_payload

            # Invalidate headers for recalculation
            pkt_copy[IP].len = None
            pkt_copy[IP].chksum = None
            pkt_copy[TCP].chksum = None

            # Force rebuild
            pkt_copy = Ether(bytes(pkt_copy)) if pkt_copy.haslayer(Ether) else pkt_copy.__class__(bytes(pkt_copy))
            pkt_copy.time = pkt.time  # Restore timestamp

            encrypted_count += 1

        encrypted_packets.append(pkt_copy)

    print(f"Encrypted {encrypted_count} packets (protocol={protocol}) with new keys per IP.")
    return encrypted_packets


def encrypt_tcp_payloads_by_ip_pair(train_device_packets):
    """
    Encrypt Raw payloads of all TCP packets.
    Each (src_ip, dst_ip) pair uses a unique AES key and IV (CBC mode).

    Args:
        train_device_packets (list): List of Scapy packets

    Returns:
        list: List of packets with encrypted TCP Raw payloads
    """
    encrypted_packets = []
    encrypted_count = 0
    ip_pair_keys = {}  # (src_ip, dst_ip): (key, iv)

    for pkt in train_device_packets:
        pkt_copy = copy.deepcopy(pkt)

        if pkt_copy.haslayer(IP) and pkt_copy.haslayer(TCP) and pkt_copy.haslayer(Raw):
            src_ip = pkt_copy[IP].src
            dst_ip = pkt_copy[IP].dst
            ip_pair = (src_ip, dst_ip)

            if ip_pair not in ip_pair_keys:
                key = os.urandom(16)  # AES-128
                iv = os.urandom(16)
                ip_pair_keys[ip_pair] = (key, iv)

            key, iv = ip_pair_keys[ip_pair]
            raw_payload = pkt_copy[Raw].load
            padded_data = pad(raw_payload, AES.block_size)

            cipher = AES.new(key, AES.MODE_CBC, iv)
            encrypted_payload = cipher.encrypt(padded_data)
            pkt_copy[Raw].load = encrypted_payload

            # Invalidate headers
            pkt_copy[IP].len = None
            pkt_copy[IP].chksum = None
            pkt_copy[TCP].chksum = None

            # Rebuild the packet
            pkt_copy = Ether(bytes(pkt_copy)) if pkt_copy.haslayer(Ether) else pkt_copy.__class__(bytes(pkt_copy))
            pkt_copy.time = pkt.time

            encrypted_count += 1

        encrypted_packets.append(pkt_copy)

    print(f"Encrypted {encrypted_count} TCP packets with Raw payloads using unique keys per (src_ip, dst_ip) pair.")
    return encrypted_packets


def encrypt_pcaps_in_folder(input_folder, output_folder, protocol):
    """
    Encrypt all pcap files in input_folder using AES encryption and save to output_folder.

    Args:
        input_folder (str): Path to folder containing .pcap files.
        output_folder (str): Path to folder where encrypted pcaps will be saved.
        protocol (str): ICS protocol to filter/encrypt.
    """
    os.makedirs(output_folder, exist_ok=True)
    pcap_files = glob.glob(os.path.join(input_folder, '*.pcap'))

    for pcap_path in pcap_files:
        print(f"Processing: {pcap_path}")
        packets = rdpcap(pcap_path)
        encrypted_packets = encrypt_tcp_payloads_by_ip_pair(packets)

        filename = os.path.basename(pcap_path)
        name, ext = os.path.splitext(filename)
        new_filename = f"{name}_encrypted{ext}"
        output_path = os.path.join(output_folder, new_filename)

        wrpcap(output_path, encrypted_packets)
        print(f"Saved encrypted pcap to: {output_path}")


if __name__ == '__main__':
    protocols = ["modbus", "enip", "s7comm"]
    countries = ["Australia", "China"]
    for protocol in protocols:
        for country in countries:
            print("="*60)
            print(f"Protocol: {protocol}, Country: {country}")
            input_folder = f"D:\\Desktop\\ICSLibrary Zenodo\\network_traffic\\{protocol}\\{country}"
            output_folder = f"D:\\Desktop\\ICSLibrary Zenodo\\network_traffic_encrypted\\{protocol}\\{country}"
            encrypt_pcaps_in_folder( input_folder, output_folder, protocol)
