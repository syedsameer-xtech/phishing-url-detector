import re
import tldextract
from urllib.parse import urlparse

def detect_phishing(url):
    """
    Analyzes a URL for potential phishing indicators.
    Returns a classification string with emoji indicator.
    """
    suspicious_keywords = [
        'login', 'verify', 'update', 'secure', 'account', 'webscr',
        'signin', 'wp', 'dropbox', 'bank', 'confirm', 'validate'
    ]
    bad_tlds = ['.tk', '.ga', '.ml', '.cf', '.gq', '.ru', '.xyz', '.top']
    
    # Basic URL validation
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url  # Try to normalize
    
    try:
        parsed = urlparse(url)
        if not parsed.netloc:
            return "❌ Invalid URL format"
    except Exception:
        return "❌ Invalid URL format"
    
    try:
        extracted = tldextract.extract(url)
    except Exception:
        return "⚠️ Error analyzing URL (tldextract failed)"
    
    # Reconstruct domain properly
    if extracted.suffix:
        domain = f"{extracted.domain}.{extracted.suffix}"
    else:
        domain = extracted.domain  # Fallback if no suffix found
    
    subdomain = extracted.subdomain
    score = 0
    reasons = []

    # 1. Check for IP address instead of domain
    if re.match(r'^https?://(\d{1,3}\.){3}\d{1,3}(:\d+)?(/.*)?$', url):
        score += 2
        reasons.append("IP address used instead of domain")
    
    # 2. Check for excessive subdomains (potential homograph attack)
    if subdomain and subdomain.count('.') >= 2:
        score += 1
        reasons.append("Multiple subdomains detected")
    
    # 3. Check for suspicious keywords in path or query (not domain to reduce false positives)
    path_and_query = f"{parsed.path}?{parsed.query}".lower()
    if any(keyword in path_and_query for keyword in suspicious_keywords):
        score += 2
        reasons.append("Suspicious keywords in URL path/query")
    
    # 4. Check for known malicious TLDs
    if extracted.suffix and any(f".{extracted.suffix}".endswith(tld) for tld in bad_tlds):
        score += 2
        reasons.append(f"Suspicious TLD: .{extracted.suffix}")
    
    # 5. Check for brand impersonation via typosquatting
    typosquat_patterns = [
        r'paypa[1l]', r'faceb[0o]0k', r'g[0o][0o]gle', 
        r'micros[0o]ft', r'app[1l]e', r'amaz[0o]n', r'netf1ix'
    ]
    full_url_lower = url.lower()
    if any(re.search(pattern, full_url_lower) for pattern in typosquat_patterns):
        score += 2
        reasons.append("Possible brand impersonation (typosquatting)")
    
    # 6. Check for URL shorteners (often abused)
    shortener_domains = ['bit.ly', 'tinyurl', 't.co', 'ow.ly', 'short.link']
    if any(short in domain.lower() for short in shortener_domains):
        score += 1
        reasons.append("URL shortener detected")
    
    # 7. Check for @ symbol (can be used to hide real destination)
    if '@' in parsed.netloc:
        score += 2
        reasons.append("URL contains '@' symbol (credential phishing tactic)")
    
    # Final classification with detailed feedback
    if score >= 5:
        return f"🚨 Likely phishing\n   Reasons: {', '.join(reasons)}"
    elif score >= 3:
        return f"⚠️ Suspicious\n   Reasons: {', '.join(reasons) if reasons else 'Heuristic score'}"
    else:
        return "✅ Likely safe"

# -------------------------------
# Main execution
# -------------------------------
if __name__ == "__main__":
    print("🛡️  Phishing URL Detector")
    print("Tip: Enter URLs like 'https://example.com/login'")
    print("Type 'quit' to exit\n")
    
    while True:
        url = input("Enter URL to check: ").strip()
        if url.lower() in ['quit', 'exit', 'q']:
            print("👋 Stay safe online!")
            break
        if not url:
            continue
        print("\nResult:", detect_phishing(url), "\n")
