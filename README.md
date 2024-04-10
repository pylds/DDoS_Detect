# DDoS Detection Script

This script is designed to capture and analyze network traffic in order to detect potential Distributed Denial of Service (DDoS) attacks. It uses a raw socket to capture packets on a specified network interface, and then analyzes the IP and TCP headers of each packet to look for potential DDoS indicators.

## Requirements

- Python 3.x

## Usage

To run the script, use the following command:
It requires the necessary permissions to run this script.

```bash
python3 ddos_detection.py <interface>
