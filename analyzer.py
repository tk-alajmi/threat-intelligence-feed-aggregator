# analyzer.py - Analyze threat indicators and generate reports

from collections import Counter
from datetime import datetime
from utils import Colors, colorize, format_header, format_list

class ThreatAnalyzer:
    """
    Analyzes collected threat indicators and produces
    actionable intelligence reports for SOC teams.
    """
    
    def __init__(self):
        self.indicators = None
        self.analysis_results = {}
    
    def analyze(self, indicators):
        """Run full analysis on indicator set"""
        self.indicators = indicators
        
        # run different analysis modules
        self._count_indicators()
        self._categorize_threats()
        self._identify_patterns()
        self._generate_recommendations()
        
        return self.analysis_results
    
    def _count_indicators(self):
        """Basic stats on what we collected"""
        self.analysis_results['counts'] = {
            'total_ips': len(self.indicators.get('ips', [])),
            'total_domains': len(self.indicators.get('domains', [])),
            'total_urls': len(self.indicators.get('urls', [])),
            'total_md5': len(self.indicators.get('hashes', {}).get('md5', [])),
            'total_sha256': len(self.indicators.get('hashes', {}).get('sha256', [])),
        }
        
        # grand total
        counts = self.analysis_results['counts']
        total = sum(counts.values())
        self.analysis_results['counts']['total'] = total
    
    def _categorize_threats(self):
        """Group indicators by threat category"""
        categories = {
            'malware': [],
            'phishing': [],
            'c2_servers': [],
            'scanners': [],
            'unknown': []
        }
        
        # for now just do basic categorization based on patterns
        # in real tool this would use threat intel enrichment
        
        for domain in self.indicators.get('domains', []):
            d_lower = domain.lower()
            if any(kw in d_lower for kw in ['login', 'verify', 'secure', 'account', 'bank']):
                categories['phishing'].append(domain)
            elif any(kw in d_lower for kw in ['update', 'download', 'free']):
                categories['malware'].append(domain)
            else:
                categories['unknown'].append(domain)
        
        for url in self.indicators.get('urls', []):
            u_lower = url.lower()
            if any(kw in u_lower for kw in ['login', 'signin', 'verify', 'account']):
                categories['phishing'].append(url)
            elif any(kw in u_lower for kw in ['.exe', '.dll', 'payload', 'malware']):
                categories['malware'].append(url)
            else:
                categories['unknown'].append(url)
        
        self.analysis_results['categories'] = categories
    
    def _identify_patterns(self):
        """Look for interesting patterns in the data"""
        patterns = []
        
        # check for common TLDs in malicious domains
        domains = self.indicators.get('domains', [])
        if domains:
            tlds = [d.split('.')[-1] for d in domains if '.' in d]
            tld_counts = Counter(tlds)
            common_tlds = tld_counts.most_common(3)
            if common_tlds:
                patterns.append(f"Most common TLDs: {', '.join([f'.{t[0]} ({t[1]})' for t in common_tlds])}")
        
        # check for IP ranges
        ips = self.indicators.get('ips', [])
        if len(ips) > 5:
            # look for IPs in same /24
            subnets = Counter(['.'.join(ip.split('.')[:3]) for ip in ips])
            common_subnets = [(s, c) for s, c in subnets.items() if c > 1]
            if common_subnets:
                patterns.append(f"Multiple IPs from same subnet detected")
        
        # check hash counts
        hashes = self.indicators.get('hashes', {})
        total_hashes = len(hashes.get('md5', [])) + len(hashes.get('sha256', []))
        if total_hashes > 0:
            patterns.append(f"{total_hashes} malware samples identified")
        
        self.analysis_results['patterns'] = patterns
    
    def _generate_recommendations(self):
        """Create actionable recommendations based on findings"""
        recs = []
        counts = self.analysis_results['counts']
        
        if counts['total_ips'] > 0:
            recs.append("Block malicious IPs in firewall/IDS rules")
            recs.append("Check network logs for connections to these IPs")
        
        if counts['total_domains'] > 0:
            recs.append("Add malicious domains to DNS sinkhole/blocklist")
            recs.append("Review proxy logs for domain access")
        
        if counts['total_urls'] > 0:
            recs.append("Block URLs in web proxy/content filter")
        
        if counts['total_md5'] > 0 or counts['total_sha256'] > 0:
            recs.append("Update endpoint detection with new malware hashes")
            recs.append("Scan endpoints for matching file hashes")
        
        if not recs:
            recs.append("No immediate actions required")
        
        self.analysis_results['recommendations'] = recs
    
    def generate_report(self):
        """Create formatted threat intelligence report"""
        if not self.analysis_results:
            return "No analysis results available. Run analyze() first."
        
        report = []
        
        # header
        report.append(colorize(format_header("THREAT INTELLIGENCE REPORT"), Colors.CYAN))
        report.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report.append(f"Sources: {', '.join(self.indicators.get('sources', ['Unknown']))}")
        
        # summary stats
        report.append(colorize("\n[INDICATOR SUMMARY]", Colors.YELLOW))
        counts = self.analysis_results['counts']
        report.append(f"  Total Indicators: {colorize(str(counts['total']), Colors.WHITE)}")
        report.append(f"  - IP Addresses:   {counts['total_ips']}")
        report.append(f"  - Domains:        {counts['total_domains']}")
        report.append(f"  - URLs:           {counts['total_urls']}")
        report.append(f"  - MD5 Hashes:     {counts['total_md5']}")
        report.append(f"  - SHA256 Hashes:  {counts['total_sha256']}")
        
        # malicious IPs
        ips = self.indicators.get('ips', [])
        if ips:
            report.append(colorize("\n[MALICIOUS IP ADDRESSES]", Colors.RED))
            for ip in ips[:10]:  # show first 10
                report.append(f"  \u2022 {ip}")
            if len(ips) > 10:
                report.append(f"  ... and {len(ips) - 10} more")
        
        # malicious domains
        domains = self.indicators.get('domains', [])
        if domains:
            report.append(colorize("\n[MALICIOUS DOMAINS]", Colors.RED))
            for domain in domains[:10]:
                report.append(f"  \u2022 {domain}")
            if len(domains) > 10:
                report.append(f"  ... and {len(domains) - 10} more")
        
        # malware hashes
        hashes = self.indicators.get('hashes', {})
        all_hashes = hashes.get('md5', []) + hashes.get('sha256', [])
        if all_hashes:
            report.append(colorize("\n[MALWARE HASHES]", Colors.RED))
            for h in all_hashes[:5]:
                # truncate long hashes for display
                display_hash = h[:16] + '...' if len(h) > 20 else h
                report.append(f"  \u2022 {display_hash}")
            if len(all_hashes) > 5:
                report.append(f"  ... and {len(all_hashes) - 5} more")
        
        # patterns
        patterns = self.analysis_results.get('patterns', [])
        if patterns:
            report.append(colorize("\n[PATTERNS DETECTED]", Colors.YELLOW))
            for p in patterns:
                report.append(f"  \u2022 {p}")
        
        # recommendations
        report.append(colorize("\n[RECOMMENDATIONS]", Colors.GREEN))
        for rec in self.analysis_results.get('recommendations', []):
            report.append(f"  \u2022 {rec}")
        
        report.append(colorize(format_header(""), Colors.CYAN))
        
        return '\n'.join(report)
