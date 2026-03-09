# Threat Intelligence Feed Aggregator

![Python](https://img.shields.io/badge/Python-3.8%2B-blue)
![License](https://img.shields.io/badge/License-MIT-green)
![Security](https://img.shields.io/badge/Security-Threat%20Intel-red)

A Python-based threat intelligence aggregation tool that collects, normalizes, and analyzes threat indicators from multiple open-source intelligence feeds. Built for SOC analysts, threat hunters, and cybersecurity professionals.

## Overview

This tool automates the collection and analysis of threat intelligence data from various sources including malicious IP addresses, domains, URLs, and malware hashes. It produces actionable intelligence reports that security teams can use to update detection systems, block malicious infrastructure, and support incident response activities.

## Problem Statement

Security Operations Centers (SOCs) need to continuously monitor and ingest threat intelligence from multiple sources to stay ahead of emerging threats. Manually collecting and correlating this data is time-consuming and error-prone. This tool solves that problem by:

- Automating feed collection from multiple sources
- Normalizing indicators into a consistent format
- Analyzing patterns and categorizing threats
- Generating actionable recommendations

## Features

- **Multi-source Collection**: Aggregates data from AbuseIPDB, AlienVault OTX, MalwareBazaar, and OpenPhish
- **Indicator Extraction**: Parses IPs, domains, URLs, and file hashes (MD5/SHA256)
- **Data Normalization**: Standardizes indicators from different feed formats
- **Threat Analysis**: Categorizes threats and identifies patterns
- **CLI Reports**: Generates formatted intelligence reports in the terminal
- **Demo Mode**: Includes sample data for testing without API keys
- **Modular Design**: Easy to extend with new feed sources

## Technical Architecture

```
┌─────────────────┐     ┌──────────────────┐     ┌────────────────┐
│  Threat Feeds   │─────│  Feed Collector  │─────│ Indicator      │
│  (APIs/Files)   │     │  (feed_collector)│     │ Parser         │
└─────────────────┘     └──────────────────┘     └────────┬───────┘
                                                        │
                                                        ▼
┌─────────────────┐     ┌──────────────────┐     ┌────────────────┐
│  CLI Report     │─────│  Threat Analyzer │─────│ Normalized     │
│  (Terminal)     │     │  (analyzer.py)   │     │ Indicators     │
└─────────────────┘     └──────────────────┘     └────────────────┘
```

## Project Structure

```
threat-intelligence-feed-aggregator/
├── app.py                 # Main CLI application
├── feed_collector.py      # Collects threat feeds from sources
├── indicator_parser.py    # Extracts and normalizes indicators
├── analyzer.py            # Analyzes threats and generates reports
├── utils.py               # Helper functions
├── requirements.txt       # Python dependencies
├── README.md              # This file
├── LICENSE                # MIT License
├── .gitignore             # Git ignore rules
├── docs/                  # Documentation
│   ├── threat_intelligence_workflow.md
│   └── data_sources.md
├── examples/              # Sample data files
│   ├── example_threat_feed.json
│   └── example_report.txt
├── model/                 # Threat classification logic
│   └── threat_classifier.py
└── screenshots/           # Tool screenshots
```

## Technologies Used

- **Python 3.8+** - Core programming language
- **Requests** - HTTP library for API calls
- **Colorama** - Terminal color output
- **Regular Expressions** - Pattern matching for indicator extraction

## Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/threat-intelligence-feed-aggregator.git
cd threat-intelligence-feed-aggregator
```

2. Create a virtual environment (recommended):
```bash
python -m venv venv
source venv/bin/activate  # Linux/Mac
venv\Scripts\activate     # Windows
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

4. (Optional) Set up API keys for live feeds:
```bash
export ABUSEIPDB_KEY="your_key_here"
export OTX_KEY="your_key_here"
export VT_KEY="your_key_here"
```

## Usage

Run the tool:
```bash
python app.py
```

Command line options:
```bash
python app.py --help          # Show help
python app.py --live          # Use live API feeds
python app.py --no-banner     # Skip the banner
python app.py --version       # Show version
```

## Example Output

```
============================================================
THREAT INTELLIGENCE REPORT
============================================================
Generated: 2026-03-10 01:30:45
Sources: Demo Data

[INDICATOR SUMMARY]
  Total Indicators: 15
  - IP Addresses:   5
  - Domains:        5
  - URLs:           2
  - MD5 Hashes:     2
  - SHA256 Hashes:  1

[MALICIOUS IP ADDRESSES]
  • 185.220.101.34
  • 45.155.205.233
  • 103.144.240.29
  • 194.26.192.64
  • 91.240.118.172

[MALICIOUS DOMAINS]
  • secure-paypal-login.com
  • microsoft-verify.net
  • update-chrome-browser.com
  • free-bitcoin-generator.xyz
  • login-bankofamerica.com

[MALWARE HASHES]
  • e99a18c428cb38d5...
  • 5d41402abc4b2a76...
  • 2cf24dba5fb0a30e...

[PATTERNS DETECTED]
  • Most common TLDs: .com (4), .net (1), .xyz (1)
  • 3 malware samples identified

[RECOMMENDATIONS]
  • Block malicious IPs in firewall/IDS rules
  • Check network logs for connections to these IPs
  • Add malicious domains to DNS sinkhole/blocklist
  • Review proxy logs for domain access
  • Block URLs in web proxy/content filter
  • Update endpoint detection with new malware hashes
  • Scan endpoints for matching file hashes
============================================================
```

## Screenshots

### Tool Startup
<img width="1484" height="768" alt="image" src="https://github.com/user-attachments/assets/d8e3810b-16fe-4220-8c49-189b9729c70f" />


### Threat Collection
<img width="665" height="337" alt="image" src="https://github.com/user-attachments/assets/e80c0bf0-1f4d-4632-8855-e5e69cae4848" />


### Intelligence Report
<img width="520" height="758" alt="image" src="https://github.com/user-attachments/assets/74868c5e-4aad-4b62-b5ff-7bd6056c3ea8" />


## Future Improvements

- [ ] Add support for STIX/TAXII feeds
- [ ] Implement indicator enrichment (WHOIS, GeoIP)
- [ ] Add export options (CSV, JSON, STIX)
- [ ] Create web dashboard interface
- [ ] Add historical tracking and trending
- [ ] Implement indicator deduplication across time
- [ ] Add confidence scoring for indicators
- [ ] Support for custom feed sources

## Use Cases

- **SOC Monitoring**: Daily threat feed ingestion for detection updates
- **Incident Response**: Quick lookup of IOCs during investigations
- **Threat Hunting**: Proactive search for malicious infrastructure
- **Security Research**: Analysis of threat actor infrastructure

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Disclaimer

This tool is for educational and authorized security testing purposes only. Always ensure you have proper authorization before using threat intelligence data in production environments.
