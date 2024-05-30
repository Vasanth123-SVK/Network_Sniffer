#importing the necessary libraries
import os
import sys
import ctypes
from scapy.all import sniff, Packet, IP, TCP, UDP, ARP
from scapy.layers.http import HTTPRequest
from datetime import datetime

# Log file
logfile = "network_traffic_log.txt"

# Function to write packet details to the log file
def log_packet(packet_info):
    with open(logfile, 'a') as f:
        f.write(f"{packet_info}\n")

# Callback function to process packets
def packet_callback(packet):
    # Timestamp
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    
    # Checking for IP packets
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        protocol = packet[IP].proto
        
        # Handling the TCP packets
        if TCP in packet:
            tcp_sport = packet[TCP].sport
            tcp_dport = packet[TCP].dport
            flags = packet[TCP].flags
            packet_info = (f"{timestamp} - TCP Packet: {ip_src}:{tcp_sport} -> "
                           f"{ip_dst}:{tcp_dport} Flags: {flags}")
            print(packet_info)
            log_packet(packet_info)
        
        # Handling UDP packets
        elif UDP in packet:
            udp_sport = packet[UDP].sport
            udp_dport = packet[UDP].dport
            packet_info = (f"{timestamp} - UDP Packet: {ip_src}:{udp_sport} -> "
                           f"{ip_dst}:{udp_dport}")
            print(packet_info)
            log_packet(packet_info)
        
        # Handling HTTP requests
        elif packet.haslayer(HTTPRequest):
            http_layer = packet[HTTPRequest]
            packet_info = (f"{timestamp} - HTTP Request: {ip_src} -> {ip_dst} "
                           f"Method: {http_layer.Method.decode()} "
                           f"Host: {http_layer.Host.decode()} "
                           f"Path: {http_layer.Path.decode()}")
            print(packet_info)
            log_packet(packet_info)
        
        else:
            packet_info = f"{timestamp} - Other IP Packet: {ip_src} -> {ip_dst} Protocol: {protocol}"
            print(packet_info)
            log_packet(packet_info)
    
    # Handling ARP packets
    elif ARP in packet:
        arp_src = packet[ARP].psrc
        arp_dst = packet[ARP].pdst
        packet_info = f"{timestamp} - ARP Packet: {arp_src} -> {arp_dst}"
        print(packet_info)
        log_packet(packet_info)
    
    else:
        packet_info = f"{timestamp} - Non-IP Packet"
        print(packet_info)
        log_packet(packet_info)

# Function to check for admin privileges on Windows
def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

# Starting sniffing packets
if __name__ == "__main__":
    if not is_admin():
        sys.exit("Please run as administrator")

    print("Starting advanced network sniffer...")
    sniff(prn=packet_callback, store=0)
