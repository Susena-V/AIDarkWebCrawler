import requests
from bs4 import BeautifulSoup

# Proxy for Tor (Dark Web Scraping)
proxies = {
    "http": "socks5h://127.0.0.1:9050",
    "https": "socks5h://127.0.0.1:9050",
}

# Scrape Dark Web
def scrape_dark_web(url):
    try:
        response = requests.get(url, proxies=proxies, timeout=15)
        soup = BeautifulSoup(response.text, 'html.parser')
        return soup.get_text()
    except requests.exceptions.RequestException as e:
        print("[ERROR] Dark Web Scraping Failed:", e)
        return None

# Scrape Surface Web (Normal Web Scraping)
def scrape_surface_web(url):
    try:
        headers = {'User-Agent': 'Mozilla/5.0'}
        response = requests.get(url, headers=headers, timeout=15)
        soup = BeautifulSoup(response.text, 'html.parser')
        return soup.get_text()
    except requests.exceptions.RequestException as e:
        print("[ERROR] Surface Web Scraping Failed:", e)
        return None

# URLs to Scrape
dark_web_url = "http://yq5jjvr7drkjrelzhut7kgclfuro65jjlivyzfmxiq2kyv5lickrl4qd.onion/"
surface_web_url = "https://example.com"

# Scraping
print("Dark Web Data:", scrape_dark_web(dark_web_url))
print("Surface Web Data:", scrape_surface_web(surface_web_url))
