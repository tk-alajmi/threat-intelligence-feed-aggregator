# threat_classifier.py - Classify and categorize threat indicators

# Keywords used to identify threat categories
PHISHING_KEYWORDS = [
    'login', 'signin', 'verify', 'account', 'secure', 'update',
    'confirm', 'banking', 'password', 'credential', 'authenticate',
    'paypal', 'amazon', 'microsoft', 'apple', 'google', 'netflix',
    'bank', 'wallet', 'suspended', 'locked', 'unusual'
]

MALWARE_KEYWORDS = [
    'download', 'update', 'install', 'setup', 'patch', 'crack',
    'keygen', 'free', 'exe', 'dll', 'payload', 'dropper', 'loader'
]

SCAM_KEYWORDS = [
    'bitcoin', 'crypto', 'winner', 'prize', 'lottery', 'gift',
    'free', 'money', 'investment', 'profit', 'earn'
]

# Known malicious TLDs (higher risk)
SUSPICIOUS_TLDS = [
    'xyz', 'top', 'club', 'online', 'site', 'website', 'space',
    'fun', 'icu', 'buzz', 'tk', 'ml', 'ga', 'cf', 'gq'
]


class ThreatClassifier:
    """
    Classifies indicators into threat categories based on
    patterns, keywords, and known threat intelligence.
    """
    
    def __init__(self):
        self.classifications = []
    
    def classify_domain(self, domain):
        """Determine threat category for a domain"""
        domain_lower = domain.lower()
        
        # check for phishing patterns
        for kw in PHISHING_KEYWORDS:
            if kw in domain_lower:
                return {
                    'indicator': domain,
                    'type': 'domain',
                    'category': 'phishing',
                    'confidence': 75,
                    'matched_keyword': kw
                }
        
        # check for malware patterns
        for kw in MALWARE_KEYWORDS:
            if kw in domain_lower:
                return {
                    'indicator': domain,
                    'type': 'domain',
                    'category': 'malware',
                    'confidence': 70,
                    'matched_keyword': kw
                }
        
        # check TLD
        tld = domain.split('.')[-1].lower()
        if tld in SUSPICIOUS_TLDS:
            return {
                'indicator': domain,
                'type': 'domain',
                'category': 'suspicious',
                'confidence': 50,
                'reason': f'suspicious TLD: .{tld}'
            }
        
        return {
            'indicator': domain,
            'type': 'domain',
            'category': 'unknown',
            'confidence': 30
        }
    
    def classify_ip(self, ip, context=None):
        """Classify IP address based on context"""
        result = {
            'indicator': ip,
            'type': 'ip',
            'category': 'malicious',
            'confidence': 60
        }
        
        if context:
            if context.get('reports', 0) > 100:
                result['confidence'] = min(95, result['confidence'] + 20)
            if context.get('threat_type'):
                result['subcategory'] = context['threat_type']
        
        return result
    
    def classify_hash(self, file_hash, hash_type='md5'):
        """Classify file hash - if in threat feed, it's malware"""
        return {
            'indicator': file_hash,
            'type': 'hash',
            'hash_type': hash_type,
            'category': 'malware',
            'confidence': 90
        }


def get_threat_severity(category):
    """Return severity level for a threat category"""
    severity_map = {
        'malware': 'HIGH',
        'phishing': 'HIGH',
        'c2': 'CRITICAL',
        'scam': 'MEDIUM',
        'suspicious': 'LOW',
        'unknown': 'INFO'
    }
    return severity_map.get(category, 'INFO')
