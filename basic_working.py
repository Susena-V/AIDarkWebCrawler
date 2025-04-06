from flask import Flask, render_template, request
import requests
import re
from bs4 import BeautifulSoup

app = Flask(__name__)

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
        return f"Dark Web Scraping Failed: {e}"


# Scrape Surface Web
def scrape_surface_web(url):
    try:
        response = requests.get(url, timeout=15)
        soup = BeautifulSoup(response.text, 'html.parser')
        return soup.get_text()
    except requests.exceptions.RequestException as e:
        return f"Surface Web Scraping Failed: {e}"


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


# Flask Routes
@app.route("/", methods=["GET", "POST"])
def index():
    result = None
    if request.method == "POST":
        url = request.form.get("url")

        if ".onion" in url:
            scraped_data = scrape_dark_web(url)
        else:
            scraped_data = scrape_surface_web(url)

        if scraped_data:
            result = analyze_text(scraped_data)
        else:
            result = {"Error": "No data scraped. The website may be down or inaccessible."}

    return render_template("index.html", result=result)


if __name__ == "__main__":
    app.run(debug=True)
