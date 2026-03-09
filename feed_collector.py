# feed_collector.py - Collect threat intelligence from various sources

import json
import os
import requests
from datetime import datetime

# timeout for API requests
REQUEST_TIMEOUT = 30

class FeedCollector:
    """
    Collects threat intel from multiple sources.
    Supports both live API feeds and local sample files.
    """
    
    def __init__(self, use_sample_data=True):
        self.use_sample_data = use_sample_data
        self.collected_feeds = []
        self.errors = []
        
        # API keys would go here in production
        # for demo purposes we use sample data
        self.api_keys = {
            'abuseipdb': os.environ.get('ABUSEIPDB_KEY', ''),
            'otx': os.environ.get('OTX_KEY', ''),
            'virustotal': os.environ.get('VT_KEY', '')
        }
    
    def collect_all(self):
        """Gather data from all configured sources"""
        print("[*] Starting threat intelligence collection...")
        
        if self.use_sample_data:
            self._load_sample_feeds()
        else:
            # try live feeds
            self._fetch_abuseipdb()
            self._fetch_otx_pulses()
            self._fetch_malwarebazaar()
            self._fetch_openphish()
        
        print(f"[+] Collection complete. {len(self.collected_feeds)} feeds loaded.")
        return self.collected_feeds
    
    def _load_sample_feeds(self):
        """Load example threat data for demo/testing"""
        print("[*] Loading sample threat feeds...")
        
        # check if sample file exists
        sample_path = os.path.join('examples', 'example_threat_feed.json')
        
        if os.path.exists(sample_path):
            try:
                with open(sample_path, 'r') as f:
                    data = json.load(f)
                self.collected_feeds.append({
                    'source': 'Sample Feed',
                    'type': 'json',
                    'data': data,
                    'timestamp': datetime.now().isoformat()
                })
                print("[+] Loaded sample threat feed")
            except Exception as e:
                self.errors.append(f"Failed to load sample: {e}")
        else:
            # generate some demo data if no file
            demo_data = self._generate_demo_data()
            self.collected_feeds.append({
                'source': 'Demo Data',
                'type': 'json',
                'data': demo_data,
                'timestamp': datetime.now().isoformat()
            })
            print("[+] Generated demo threat data")
    
    def _generate_demo_data(self):
        """Create realistic looking threat data for demonstration"""
        return {
            'results': [
                {'ip': '185.220.101.34', 'threat_type': 'tor_exit', 'confidence': 90},
                {'ip': '45.155.205.233', 'threat_type': 'scanner', 'confidence': 85},
                {'ip': '103.144.240.29', 'threat_type': 'botnet_c2', 'confidence': 95},
                {'ip': '194.26.192.64', 'threat_type': 'bruteforce', 'confidence': 80},
                {'ip': '91.240.118.172', 'threat_type': 'malware_host', 'confidence': 88},
                {'domain': 'secure-paypal-login.com', 'threat_type': 'phishing'},
                {'domain': 'microsoft-verify.net', 'threat_type': 'phishing'},
                {'domain': 'update-chrome-browser.com', 'threat_type': 'malware'},
                {'domain': 'free-bitcoin-generator.xyz', 'threat_type': 'scam'},
                {'domain': 'login-bankofamerica.com', 'threat_type': 'phishing'},
                {'url': 'http://malware-download.ru/payload.exe', 'threat_type': 'malware'},
                {'url': 'https://phishing-site.com/login.php', 'threat_type': 'phishing'},
                {'hash': 'e99a18c428cb38d5f260853678922e03', 'threat_type': 'trojan', 'hash_type': 'md5'},
                {'hash': '5d41402abc4b2a76b9719d911017c592', 'threat_type': 'ransomware', 'hash_type': 'md5'},
                {'hash': '2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824', 'threat_type': 'backdoor', 'hash_type': 'sha256'},
            ]
        }
    
    def _fetch_abuseipdb(self):
        """Fetch blacklisted IPs from AbuseIPDB"""
        if not self.api_keys['abuseipdb']:
            print("[!] AbuseIPDB API key not configured, skipping...")
            return
        
        print("[*] Fetching AbuseIPDB blacklist...")
        try:
            url = 'https://api.abuseipdb.com/api/v2/blacklist'
            headers = {
                'Key': self.api_keys['abuseipdb'],
                'Accept': 'application/json'
            }
            params = {'confidenceMinimum': 90, 'limit': 100}
            
            resp = requests.get(url, headers=headers, params=params, timeout=REQUEST_TIMEOUT)
            if resp.status_code == 200:
                self.collected_feeds.append({
                    'source': 'AbuseIPDB',
                    'type': 'json',
                    'data': resp.json(),
                    'timestamp': datetime.now().isoformat()
                })
                print("[+] AbuseIPDB data collected")
            else:
                self.errors.append(f"AbuseIPDB returned {resp.status_code}")
        except Exception as e:
            self.errors.append(f"AbuseIPDB error: {str(e)}")
    
    def _fetch_otx_pulses(self):
        """Fetch threat pulses from AlienVault OTX"""
        if not self.api_keys['otx']:
            print("[!] OTX API key not configured, skipping...")
            return
        
        print("[*] Fetching AlienVault OTX pulses...")
        try:
            url = 'https://otx.alienvault.com/api/v1/pulses/subscribed'
            headers = {'X-OTX-API-KEY': self.api_keys['otx']}
            
            resp = requests.get(url, headers=headers, timeout=REQUEST_TIMEOUT)
            if resp.status_code == 200:
                self.collected_feeds.append({
                    'source': 'AlienVault OTX',
                    'type': 'json',
                    'data': resp.json(),
                    'timestamp': datetime.now().isoformat()
                })
                print("[+] OTX data collected")
            else:
                self.errors.append(f"OTX returned {resp.status_code}")
        except Exception as e:
            self.errors.append(f"OTX error: {str(e)}")
    
    def _fetch_malwarebazaar(self):
        """Fetch recent malware samples from MalwareBazaar"""
        print("[*] Fetching MalwareBazaar recent samples...")
        try:
            url = 'https://mb-api.abuse.ch/api/v1/'
            data = {'query': 'get_recent', 'selector': '100'}
            
            resp = requests.post(url, data=data, timeout=REQUEST_TIMEOUT)
            if resp.status_code == 200:
                self.collected_feeds.append({
                    'source': 'MalwareBazaar',
                    'type': 'json',
                    'data': resp.json(),
                    'timestamp': datetime.now().isoformat()
                })
                print("[+] MalwareBazaar data collected")
            else:
                self.errors.append(f"MalwareBazaar returned {resp.status_code}")
        except Exception as e:
            self.errors.append(f"MalwareBazaar error: {str(e)}")
    
    def _fetch_openphish(self):
        """Fetch phishing URLs from OpenPhish"""
        print("[*] Fetching OpenPhish feed...")
        try:
            url = 'https://openphish.com/feed.txt'
            resp = requests.get(url, timeout=REQUEST_TIMEOUT)
            if resp.status_code == 200:
                self.collected_feeds.append({
                    'source': 'OpenPhish',
                    'type': 'text',
                    'data': resp.text,
                    'timestamp': datetime.now().isoformat()
                })
                print("[+] OpenPhish data collected")
            else:
                self.errors.append(f"OpenPhish returned {resp.status_code}")
        except Exception as e:
            self.errors.append(f"OpenPhish error: {str(e)}")
    
    def get_errors(self):
        return self.errors
