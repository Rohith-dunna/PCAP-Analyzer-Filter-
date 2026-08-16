# PacketScope – PCAP Analyzer & Packet Filter

PacketScope is a Python-based network traffic analysis and packet filtering tool designed to analyze `.pcap` and `.pcapng` files using **Scapy**.

The tool allows users to load captured network traffic and filter packets based on different parameters such as **IP addresses, protocols, and ports**. It provides a simple command-line interface for examining network traffic and identifying specific packets of interest.

## Features

* Analyze `.pcap` and `.pcapng` files
* Filter packets by source IP
* Filter packets by destination IP
* Filter packets by IP address
* Filter packets by source/destination port
* Filter TCP, UDP, ICMP, and DNS traffic
* Display source and destination information
* Display detected protocols
* Export filtered packets to a new PCAP file

## Technologies Used

* **Python**
* **Scapy**
* **PCAP / PCAPNG**

## Purpose

This project was developed as a mini project for learning and demonstrating practical concepts in **network traffic analysis, packet inspection, and cybersecurity**.

## Future Improvements

* Web-based interface
* Network traffic statistics and visualizations
* Advanced Wireshark-style filtering
* DNS analysis
* Suspicious traffic detection
* Port scanning detection
* Security alerts and threat indicators
* CSV/JSON report generation

## Disclaimer

This tool is intended for educational and authorized network-analysis purposes only. Analyze only PCAP files that you have permission to inspect.
