# indicator_parser.py - Extract and normalize threat indicators

import json
from utils import extract_ips, extract_domains, extract_urls, extract_hashes

class IndicatorParser:
    """
    Parses raw threat feed data and extracts IOCs (Indicators of Compromise)
    Handles different feed formats and normalizes everything
    """
    
    def __init__(self):
        self.indicators = {
            'ips': [],
            'domains': [],
            'urls': [],
            'hashes': {'md5': [], 'sha256': []}
        }
        self.sources = []  # track where data came from
    
    def parse_json_feed(self, data, source_name):
        """Parse JSON formatted threat feed"""
        if source_name not in self.sources:
            self.sources.append(source_name)
        
        # handle different JSON structures we might see
        if isinstance(data, list):
            for item in data:
                self._extract_from_item(item)
        elif isinstance(data, dict):
            # some feeds wrap data in a results key
            if 'results' in data:
                for item in data['results']:
                    self._extract_from_item(item)
            elif 'data' in data:
                for item in data['data']:
                    self._extract_from_item(item)
            else:
                self._extract_from_item(data)
    
    def _extract_from_item(self, item):
        """Pull indicators from a single feed item"""
        if not isinstance(item, dict):
            # might just be a raw indicator string
            self._parse_raw_text(str(item))
            return
        
        # common field names across different feeds
        ip_fields = ['ip', 'ip_address', 'ipv4', 'src_ip', 'dst_ip', 'indicator']
        domain_fields = ['domain', 'hostname', 'host', 'fqdn']
        url_fields = ['url', 'uri', 'link']
        hash_fields = ['hash', 'md5', 'sha256', 'sha1', 'file_hash']
        
        for field in ip_fields:
            if field in item and item[field]:
                ips = extract_ips(str(item[field]))
                self.indicators['ips'].extend(ips)
        
        for field in domain_fields:
            if field in item and item[field]:
                domains = extract_domains(str(item[field]))
                self.indicators['domains'].extend(domains)
        
        for field in url_fields:
            if field in item and item[field]:
                urls = extract_urls(str(item[field]))
                self.indicators['urls'].extend(urls)
        
        for field in hash_fields:
            if field in item and item[field]:
                hashes = extract_hashes(str(item[field]))
                self.indicators['hashes']['md5'].extend(hashes['md5'])
                self.indicators['hashes']['sha256'].extend(hashes['sha256'])
    
    def parse_text_feed(self, text, source_name):
        """Parse plain text feed (one indicator per line usually)"""
        if source_name not in self.sources:
            self.sources.append(source_name)
        
        self._parse_raw_text(text)
    
    def _parse_raw_text(self, text):
        """Extract all indicator types from raw text"""
        # get IPs
        ips = extract_ips(text)
        self.indicators['ips'].extend(ips)
        
        # get domains
        domains = extract_domains(text)
        self.indicators['domains'].extend(domains)
        
        # get URLs
        urls = extract_urls(text)
        self.indicators['urls'].extend(urls)
        
        # get hashes
        hashes = extract_hashes(text)
        self.indicators['hashes']['md5'].extend(hashes['md5'])
        self.indicators['hashes']['sha256'].extend(hashes['sha256'])
    
    def get_normalized_indicators(self):
        """Return deduplicated and cleaned indicators"""
        return {
            'ips': list(set(self.indicators['ips'])),
            'domains': list(set(self.indicators['domains'])),
            'urls': list(set(self.indicators['urls'])),
            'hashes': {
                'md5': list(set(self.indicators['hashes']['md5'])),
                'sha256': list(set(self.indicators['hashes']['sha256']))
            },
            'sources': self.sources
        }
    
    def get_total_count(self):
        """Quick count of all indicators"""
        data = self.get_normalized_indicators()
        total = len(data['ips']) + len(data['domains']) + len(data['urls'])
        total += len(data['hashes']['md5']) + len(data['hashes']['sha256'])
        return total
    
    def clear(self):
        """Reset parser for fresh run"""
        self.indicators = {
            'ips': [],
            'domains': [],
            'urls': [],
            'hashes': {'md5': [], 'sha256': []}
        }
        self.sources = []
