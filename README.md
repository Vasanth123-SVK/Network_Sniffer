
# Basic Network Sniffer

## Overview

This project is an advanced network sniffer implemented in Python using the Scapy library. The sniffer captures various types of network packets including TCP, UDP, HTTP, and ARP packets, logs the packet details to a file, and prints them to the console.

## Features

- Captures and logs TCP packets with source and destination IP addresses, ports, and flags.
- Captures and logs UDP packets with source and destination IP addresses and ports.
- Captures and logs HTTP requests with source and destination IP addresses, request method, host, and path.
- Captures and logs ARP packets with source and destination IP addresses.
- Logs non-IP packets and other IP packets with unknown protocols.

## Prerequisites

- Python 3.x
- Scapy library
- Administrative privileges to run the script (required for network sniffing)

## Installation

1. **Create the Folder:**

   ```bash
   mkdir network-sniffer
   cd network-sniffer
   ```

2. **Install dependencies:**

   Install the Scapy library if you haven't already:

   ```bash
   pip install scapy
   ```

## Usage

1. **Run the script with administrative privileges:**

   On Windows, you need to run the script as an administrator. You can do this by right-clicking on the Visual Studio Code shortcut and selecting "Run as administrator", then navigating to the directory where the script is located and running:

   ```bash
   python task_1.py
   ```

2. **Log file:**

   The script logs all captured packet details into `network_traffic_log.txt` located in the same directory as the script.

## Code Explanation

- **`log_packet(packet_info)`**:
  A helper function that writes packet details to the log file.

- **`packet_callback(packet)`**:
  A callback function that processes each packet and extracts relevant details based on the packet type (TCP, UDP, HTTP, ARP, etc.).

- **`is_admin()`**:
  A function to check if the script is being run with administrative privileges on Windows.

- **Main script**:
  The main script checks for administrative privileges and starts the packet sniffing process using Scapy's `sniff` function with `packet_callback` as the callback function.

## Example Output

Example of logged packet details:

```
2024-05-30 18:01:41 - ARP Packet: 192.168.0.228 -> 192.168.0.190
2024-05-30 18:01:42 - ARP Packet: 192.168.0.228 -> 192.168.0.190
2024-05-30 18:01:42 - UDP Packet: 192.168.0.103:137 -> 192.168.0.255:137
2024-05-30 18:01:42 - UDP Packet: 192.168.0.103:54935 -> 192.168.0.1:53
2024-05-30 18:01:42 - UDP Packet: 192.168.0.103:56196 -> 192.168.0.1:53
2024-05-30 18:01:43 - UDP Packet: 192.168.0.1:53 -> 192.168.0.103:56196
2024-05-30 18:01:43 - UDP Packet: 192.168.0.1:53 -> 192.168.0.103:54935
2024-05-30 18:01:43 - TCP Packet: 192.168.0.103:54389 -> 104.208.16.90:443 Flags: S
```

## Contribution

Feel free to fork this repository and contribute by submitting a pull request. For major changes, please open an issue first to discuss what you would like to change.

