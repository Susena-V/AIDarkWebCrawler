import psycopg2
import requests
import re
import os
from bs4 import BeautifulSoup
from datetime import datetime
from flask import Flask, request, render_template
from groq import Groq  # Groq LLM API

# Flask App
app = Flask(__name__)

# Database Connection (Using Root User)
conn = psycopg2.connect(
    dbname="threat_analysis",
    user="susenavenkateshnathan",  # Root user (default PostgreSQL superuser)
    password="1845",  # Replace with your root password
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

# Groq API Setup
GROQ_API_KEY = os.getenv("GROQ_API_KEY")
groq_client = Groq(api_key=GROQ_API_KEY)

# Scrape Dark Web
def scrape_dark_web(url):
    try:
        response = requests.get(url, proxies=proxies, timeout=15)
        soup = BeautifulSoup(response.text, 'html.parser')
        text = soup.get_text()
        save_scraped_data(url, text)
        return text
    except requests.exceptions.RequestException as e:
        print("[ERROR] Dark Web Scraping Failed:", e)
        return None

# Scrape Surface Web
def scrape_surface_web(url):
    try:
        response = requests.get(url, timeout=15)
        soup = BeautifulSoup(response.text, 'html.parser')
        text = soup.get_text()
        save_scraped_data(url, text)
        return text
    except requests.exceptions.RequestException as e:
        print("[ERROR] Surface Web Scraping Failed:", e)
        return None

# Save Scraped Data
def save_scraped_data(url, content):
    cursor.execute("INSERT INTO scraped_data (url, content) VALUES (%s, %s)", (url, content))
    conn.commit()

# Analyze Text for Threats
def analyze_text(url, text):
    # Detect patterns
    results = {category: re.findall(pattern, text) for category, pattern in PII_PATTERNS.items()}
    detected_keywords = [word for word in THREAT_KEYWORDS if word in text.lower()]
    detected_domains = [domain for domain in SUSPICIOUS_DOMAINS if domain in text.lower()]

    # Calculate severity score
    severity_score = 1  # Base score

    # Add points for detected PII
    severity_score += len(results["Emails"]) * 3
    severity_score += len(results["Credit Cards"]) * 5
    severity_score += len(results["Phone Numbers"]) * 2

    # Add points for detected keywords and domains
    severity_score += len(detected_keywords)
    severity_score += len(detected_domains) * 2

    # Increase severity score if URL contains "http" or "https"
    if "http://" in url:
        severity_score += 3

    # Cap the severity score at 10
    severity_score = min(severity_score, 10)

    # Map severity score to risk level
    if severity_score <= 3:
        risk_level = "LOW"
    elif severity_score <= 7:
        risk_level = "MEDIUM"
    else:
        risk_level = "HIGH"

    # Save scraped data
    save_scraped_data(url, text)

    # Save analysis results
    save_analysis_results(
        url,
        results,
        detected_keywords,
        detected_domains,
        risk_level  # Pass the risk level instead of severity score
    )

    # Save dashboard metrics
    save_dashboard_metrics(
        url,
        len(results["Emails"]),
        len(results["Phone Numbers"]),
        len(results["Credit Cards"]),
        len(detected_keywords),
        len(detected_domains),
        severity_score
    )

    return {
        "PII": results,
        "Keywords": detected_keywords,
        "Suspicious Domains": detected_domains,
        "Severity Score": severity_score,
        "Risk Level": risk_level  # Add Risk Level to the returned dictionary
    }

def save_dashboard_metrics(url, email_count, phone_count, credit_card_count, keyword_count, domain_count, severity_score):
    try:
        cursor.execute(
            """
            INSERT INTO dashboard_metrics (
                url, email_count, phone_count, credit_card_count, keyword_count, domain_count, severity_score
            ) VALUES (%s, %s, %s, %s, %s, %s, %s)
            """,
            (
                url,
                email_count,
                phone_count,
                credit_card_count,
                keyword_count,
                domain_count,
                severity_score
            )
        )
        conn.commit()
    except Exception as e:
        print(f"[ERROR] Failed to save dashboard metrics: {e}")
        conn.rollback()
        
        
# Save Analysis Results
def save_analysis_results(url, pii, keywords, domains, risk):
    cursor.execute(
        "INSERT INTO analysis_results (url, pii_detected, keywords_detected, suspicious_domains, risk_level) VALUES (%s, %s, %s, %s, %s)",
        (url, str(pii), str(keywords), str(domains), risk)
    )
    conn.commit()

# Generate LLM Insights Using Groq
def generate_llm_insights(scraped_text):
    try:
        response = groq_client.chat.completions.create(
            model="llama3-8b-8192",  # Use a suitable Groq model
            messages=[
                {"role": "system", "content": "You are a cybersecurity expert analyzing dark web data for threats."},
                {"role": "user", "content": f"Analyze this text and provide cybersecurity insights:\n\n{scraped_text[:4000]}"}  # Limit input size
            ]
        )
        return response.choices[0].message.content  # Correct syntax for accessing the response
    except Exception as e:
        print(f"[ERROR] LLM Analysis Failed: {e}")
        return "⚠️ LLM analysis failed."

# Flask Routes
@app.route("/", methods=["GET", "POST"])
def index():
    url = None
    analysis = None
    llm_insights = None

    if request.method == "POST":
        url = request.form["url"]
        if ".onion" in url:
            data = scrape_dark_web(url)
        else:
            data = scrape_surface_web(url)

        if data:
            analysis = analyze_text(url, data)  # Ensure this includes "Severity Score"
            llm_insights = generate_llm_insights(data)

    return render_template("index.html", url=url, analysis=analysis, llm_insights=llm_insights)

if __name__ == "__main__":
    app.run(debug=True)