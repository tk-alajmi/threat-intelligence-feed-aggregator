# Data Sources

This document describes the threat intelligence sources supported by this tool.

## Supported Sources

### AbuseIPDB

**Website:** https://www.abuseipdb.com

**Description:** AbuseIPDB is a project dedicated to helping combat the spread of hackers, spammers, and abusive activity on the internet. Users can report and check IP addresses that have been associated with malicious activity.

**Data Provided:**
- Malicious IP addresses
- Abuse confidence scores
- Report categories (SSH brute force, web spam, etc.)
- Geographic information

**API Requirements:**
- Free API key required
- Rate limits apply
- Set `ABUSEIPDB_KEY` environment variable

---

### AlienVault OTX

**Website:** https://otx.alienvault.com

**Description:** Open Threat Exchange (OTX) is the world's largest open threat intelligence community. Security researchers share threat data through "pulses" containing indicators and context.

**Data Provided:**
- IP addresses
- Domains
- URLs
- File hashes
- CVE references
- YARA rules

**API Requirements:**
- Free API key required
- Set `OTX_KEY` environment variable

---

### MalwareBazaar

**Website:** https://bazaar.abuse.ch

**Description:** MalwareBazaar is a project from abuse.ch that collects and shares malware samples with the security community. It provides hashes and metadata for known malware.

**Data Provided:**
- Malware file hashes (MD5, SHA256)
- Malware family names
- File types
- First seen timestamps
- Tags and signatures

**API Requirements:**
- No API key required for basic queries
- Rate limits apply

---

### OpenPhish

**Website:** https://openphish.com

**Description:** OpenPhish is a fully automated phishing intelligence platform that identifies phishing sites in real-time without human intervention.

**Data Provided:**
- Phishing URLs
- Updated frequently

**API Requirements:**
- Public feed available (limited)
- Premium feed requires subscription

---

## Data Quality Considerations

- **Freshness**: Some feeds update hourly, others daily
- **Accuracy**: False positives can occur; validate before blocking
- **Coverage**: No single feed covers all threats
- **Context**: Some feeds provide more context than others

## Recommended Feed Combinations

For comprehensive coverage, combine:

1. **IP-focused**: AbuseIPDB + Emerging Threats
2. **Domain-focused**: OTX + URLhaus
3. **Malware-focused**: MalwareBazaar + VirusTotal
4. **Phishing-focused**: OpenPhish + PhishTank
