from flask import Flask, render_template, request
import psycopg2
import requests
import re
from bs4 import BeautifulSoup

app = Flask(__name__)

# Database Connection
conn = psycopg2.connect(
    dbname="threat_analysis",
    user="cyberadmin",
    password="securepassword",
    host="localhost",
    port="5432"
)
cursor = conn.cursor()

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

# Save Scraped Data
def save_scraped_data(url, content):
    cursor.execute("INSERT INTO scraped_data (url, content) VALUES (%s, %s)", (url, content))
    conn.commit()

# Save Analysis Results
def save_analysis_results(url, pii, keywords, domains, risk):
    cursor.execute(
        "INSERT INTO analysis_results (url, pii_detected, keywords_detected, suspicious_domains, risk_level) VALUES (%s, %s, %s, %s, %s)",
        (url, str(pii), str(keywords), str(domains), risk)
    )
    conn.commit()

# Scrape Web Data
def scrape_web(url):
    try:
        if ".onion" in url:
            response = requests.get(url, proxies=proxies, timeout=15)
        else:
            response = requests.get(url, timeout=15)
        soup = BeautifulSoup(response.text, 'html.parser')
        text = soup.get_text()
        save_scraped_data(url, text)
        return text
    except requests.exceptions.RequestException as e:
        return f"[ERROR] Scraping Failed: {e}"

# Analyze Text for Threats
def analyze_text(url, text):
    results = {category: re.findall(pattern, text) for category, pattern in PII_PATTERNS.items()}
    detected_keywords = [word for word in THREAT_KEYWORDS if word in text.lower()]
    detected_domains = [domain for domain in SUSPICIOUS_DOMAINS if domain in text.lower()]

    risk_level = "LOW"
    if results["Emails"] or results["Credit Cards"]:
        risk_level = "HIGH"
    elif results["Phone Numbers"] or detected_keywords:
        risk_level = "MEDIUM"
    elif detected_domains:
        risk_level = "MEDIUM"

    save_analysis_results(url, results, detected_keywords, detected_domains, risk_level)

    return {
        "PII": results,
        "Keywords": detected_keywords,
        "Suspicious Domains": detected_domains,
        "Risk Level": risk_level
    }

@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        url = request.form.get("url")
        scraped_data = scrape_web(url)
        if "ERROR" not in scraped_data:
            analysis_result = analyze_text(url, scraped_data)
        else:
            analysis_result = {"error": scraped_data}
        return render_template("index.html", url=url, analysis=analysis_result)
    return render_template("index.html")

if __name__ == "__main__":
    app.run(debug=True)
