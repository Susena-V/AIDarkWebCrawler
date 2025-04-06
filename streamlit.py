import streamlit as st
import psycopg2
import requests
import re
import os
from bs4 import BeautifulSoup
from groq import Groq  # Groq LLM API

# Database Connection
conn = psycopg2.connect(
    dbname="threat_analysis",
    user="susenavenkateshnathan",
    password="1845",
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
    "Emails": r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}",
    "Phone Numbers": r"\\b\\d{10,12}\\b",
    "Credit Cards": r"\\b(?:\\d[ -]*?){13,16}\\b",
}

THREAT_KEYWORDS = ["malware", "hacked", "ransomware", "carding", "breach", "leaked", "exploit", "phishing", "stealer", "drugs", "porn", "hack", "murder"]
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
        return text
    except requests.exceptions.RequestException as e:
        st.error(f"[ERROR] Dark Web Scraping Failed: {e}")
        return None

# Scrape Surface Web
def scrape_surface_web(url):
    try:
        response = requests.get(url, timeout=15)
        soup = BeautifulSoup(response.text, 'html.parser')
        text = soup.get_text()
        return text
    except requests.exceptions.RequestException as e:
        st.error(f"[ERROR] Surface Web Scraping Failed: {e}")
        return None

# Analyze Text for Threats
def analyze_text(url, text):
    results = {category: re.findall(pattern, text) for category, pattern in PII_PATTERNS.items()}
    detected_keywords = [word for word in THREAT_KEYWORDS if word in text.lower()]
    detected_domains = [domain for domain in SUSPICIOUS_DOMAINS if domain in text.lower()]
    severity_score = 1 + len(results["Emails"]) * 3 + len(results["Credit Cards"]) * 5 + len(results["Phone Numbers"]) * 2 + len(detected_keywords) + len(detected_domains) * 2
    
    if "http://" in url:
        severity_score += 3
    
    severity_score = min(severity_score, 10)
    
    risk_level = "LOW" if severity_score <= 3 else "MEDIUM" if severity_score <= 6 else "HIGH"
    
    
    return {
        "PII": results,
        "Keywords": detected_keywords,
        "Suspicious Domains": detected_domains,
        "Severity Score": severity_score,
        "Risk Level": risk_level
    }

# Generate LLM Insights Using Groq
def generate_llm_insights(scraped_text):
    try:
        response = groq_client.chat.completions.create(
            model="llama3-8b-8192",
            messages=[
                {"role": "system", "content": "You are a cybersecurity expert analyzing dark web data. Identify any threats in the following text. Must the user be concerned about this site? Generate a threat report."},
                {"role": "user", "content": f"Analyze this text: {scraped_text[:4000]}"}
            ]
        )
        return response.choices[0].message.content
    except Exception as e:
        st.error(f"[ERROR] LLM Analysis Failed: {e}")
        return "⚠️ LLM analysis failed."
    
# Save Analysis Results
# Save Analysis Results
def save_analysis_results(url, analysis, llm_insights):
    try:
        cursor.execute(
            "INSERT INTO analysis_results (url, pii_detected, keywords_detected, suspicious_domains, risk_level) VALUES (%s, %s, %s, %s, %s)",
            (
                url,
                str(analysis["PII"]),
                str(analysis["Keywords"]),
                str(analysis["Suspicious Domains"]),
                analysis["Risk Level"],
            )
        )
        conn.commit()
        print("Data saved successfully.")
    except Exception as e:
        st.error(f"[ERROR] Database Insertion Failed: {e}")




# Streamlit App
st.title("Threat Analysis Tool")
url = st.text_input("Enter URL:")
if st.button("Analyze"):
    if url:
        data = scrape_dark_web(url) if ".onion" in url else scrape_surface_web(url)
        if data:
            analysis = analyze_text(url, data)
            llm_insights = generate_llm_insights(data)
            
            st.subheader("Analysis Results")
            st.write(analysis)
            
            st.subheader("Danger Gauge")
            st.progress(analysis["Severity Score"] / 10)
            
            st.subheader("LLM Insights")
            st.write(llm_insights)
            save_analysis_results(url, analysis, llm_insights)

    else:
        st.error("Please enter a valid URL.")