# utils.py - Helper functions for threat intelligence aggregator

import re
import ipaddress
from urllib.parse import urlparse

# regex patterns we use throughout
IP_PATTERN = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
DOMAIN_PATTERN = re.compile(r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b')
HASH_MD5 = re.compile(r'\b[a-fA-F0-9]{32}\b')
HASH_SHA256 = re.compile(r'\b[a-fA-F0-9]{64}\b')
URL_PATTERN = re.compile(r'https?://[^\s<>"\')]+', re.IGNORECASE)


def validate_ip(ip_str):
    """Check if string is a valid IP address"""
    try:
        ipaddress.ip_address(ip_str)
        return True
    except ValueError:
        return False


def is_private_ip(ip_str):
    # skip private/internal IPs - not useful for threat intel
    try:
        ip = ipaddress.ip_address(ip_str)
        return ip.is_private or ip.is_loopback or ip.is_reserved
    except:
        return False


def extract_ips(text):
    """Pull all IPs from text, filter out private ones"""
    matches = IP_PATTERN.findall(text)
    valid_ips = []
    for ip in matches:
        if validate_ip(ip) and not is_private_ip(ip):
            valid_ips.append(ip)
    return list(set(valid_ips))  # dedupe


def extract_domains(text):
    """Extract domain names from text"""
    matches = DOMAIN_PATTERN.findall(text)
    # filter out common false positives
    skip_list = ['example.com', 'localhost.localdomain', 'test.local']
    domains = [d.lower() for d in matches if d.lower() not in skip_list]
    return list(set(domains))


def extract_urls(text):
    matches = URL_PATTERN.findall(text)
    # clean up trailing punctuation that gets caught
    cleaned = []
    for url in matches:
        url = url.rstrip('.,;:)')
        cleaned.append(url)
    return list(set(cleaned))


def extract_hashes(text):
    """Get MD5 and SHA256 hashes from text"""
    md5s = HASH_MD5.findall(text)
    sha256s = HASH_SHA256.findall(text)
    
    # sha256 matches will also match as md5 substrings, so filter those
    md5_clean = [h for h in md5s if h not in ''.join(sha256s)]
    
    return {
        'md5': list(set(md5_clean)),
        'sha256': list(set(sha256s))
    }


def get_domain_from_url(url):
    """Parse domain out of a URL"""
    try:
        parsed = urlparse(url)
        return parsed.netloc.lower()
    except:
        return None


def format_header(text, char='='):
    """Make a nice header for CLI output"""
    line = char * 60
    return f"\n{line}\n{text}\n{line}"


def format_list(items, prefix='  • '):
    """Format a list for terminal display"""
    if not items:
        return "  (none)"
    return '\n'.join([f"{prefix}{item}" for item in items])


def truncate(text, max_len=50):
    """Shorten text if too long"""
    if len(text) <= max_len:
        return text
    return text[:max_len-3] + '...'


# color codes for terminal (basic ANSI)
class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    RESET = '\033[0m'
    BOLD = '\033[1m'


def colorize(text, color):
    return f"{color}{text}{Colors.RESET}"
