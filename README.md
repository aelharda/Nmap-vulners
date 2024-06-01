# Nmap Vulnerability Scanner + Vulners

This project provides an automated script to perform Nmap scans with the vulners script enabled and parses the scan results to identify vulnerabilities. The parsed results are saved in CSV files.

## Features

- Executes Nmap scans with the vulners script
- Parses Nmap scan results using `libnmap`
- Categorizes vulnerabilities based on their severity
- Saves parsed scan results to CSV files
- Uses color coding for terminal output based on severity

## Requirements

- Python 3.x
- `nmapparser`
- `python-libnmap`
- `colorama`
- `termcolor`

## Installation

1. Clone the repository:

```bash
git clone https://github.com/yourusername/nmap-vulnerability-scanner.git
cd nmap-vulnerability-scanner
pip install -r requirements.txt

## Usage python Nmap_scan.py
