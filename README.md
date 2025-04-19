# Web-based-PCAP-analyzer

# PCAP Analyzer with VirusTotal Integration

This project provides a web-based tool for analyzing PCAP (Packet Capture) files and checking for malicious activity using VirusTotal. The tool can analyze different types of network traffic, such as HTTP, DNS, and TCP packets, and check domains, IPs, and hosts for potential security threats.

## Features
- **HTTP Requests Analysis**: Extracts HTTP request details like method, URI, and host.
- **VirusTotal Integration**: Check hosts, domains, and IPs against VirusTotal's database for malicious activity.
- **Traffic Type Selection**: Analyze specific traffic types or a combination of HTTP, DNS, and TCP traffic.

## Requirements
- Python 3.x
- Flask
- PyShark (for analyzing PCAP files)
- Requests (for interacting with the VirusTotal API)
- A valid VirusTotal API key

### Install Dependencies

First, install the required libraries:

```bash
pip install flask pyshark requests
