import requests
import re
from bs4 import BeautifulSoup

# Proxy for Tor (Dark Web Scraping)
proxies = {
    "http": "socks5h://127.0.0.1:9050",
    "https": "socks5h://127.0.0.1:9050",
}

# Regex Patterns for Threat Detection
PII_PATTERNS = {
    "Emails": r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
    "Phone Numbers": r"\b\d{10,12}\b",
    "Credit Cards": r"\b(?:\d[ -]*?){13,16}\b",
}

THREAT_KEYWORDS = ["malware", "hacked", "ransomware", "carding", "breach", "leaked", "exploit", "phishing", "stealer"]

SUSPICIOUS_DOMAINS = ["pastebin.com", "anonfiles.com", "darkwebmarket", "tor2web", "leakeddata"]


# Scrape Dark Web
def scrape_dark_web(url):
    try:
        response = requests.get(url, proxies=proxies, timeout=15)
        soup = BeautifulSoup(response.text, 'html.parser')
        return soup.get_text()
    except requests.exceptions.RequestException as e:
        print("[ERROR] Dark Web Scraping Failed:", e)
        return None


# Scrape Surface Web
def scrape_surface_web(url):
    try:
        response = requests.get(url, timeout=15)
        soup = BeautifulSoup(response.text, 'html.parser')
        return soup.get_text()
    except requests.exceptions.RequestException as e:
        print("[ERROR] Surface Web Scraping Failed:", e)
        return None


# Analyze Text for Threats
def analyze_text(text):
    results = {category: re.findall(pattern, text) for category, pattern in PII_PATTERNS.items()}
    detected_keywords = [word for word in THREAT_KEYWORDS if word in text.lower()]
    detected_domains = [domain for domain in SUSPICIOUS_DOMAINS if domain in text.lower()]

    # Assigning Risk Level
    risk_level = "LOW"
    if results["Emails"] or results["Credit Cards"]:
        risk_level = "HIGH"
    elif results["Phone Numbers"] or detected_keywords:
        risk_level = "MEDIUM"
    elif detected_domains:
        risk_level = "MEDIUM"

    return {
        "PII": results,
        "Keywords": detected_keywords,
        "Suspicious Domains": detected_domains,
        "Risk Level": risk_level
    }


# Main Execution
dark_web_url = "http://yq5jjvr7drkjrelzhut7kgclfuro65jjlivyzfmxiq2kyv5lickrl4qd.onion/"
surface_web_url = "https://example.com"

print("🔍 Scraping Dark Web...")
dark_web_data = scrape_dark_web(dark_web_url)
dark_web_analysis = analyze_text(dark_web_data) if dark_web_data else None

print("\n🔍 Scraping Surface Web...")
surface_web_data = scrape_surface_web(surface_web_url)
surface_web_analysis = analyze_text(surface_web_data) if surface_web_data else None

# Display Results
print("\n🕵️ Dark Web Analysis:", dark_web_analysis)
print("\n🌍 Surface Web Analysis:", surface_web_analysis)
