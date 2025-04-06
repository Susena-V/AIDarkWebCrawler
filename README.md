# AI Based Dark Web Crawler

This is the official repository of an AI Based Dark Web Crawler created for a CyberSecurity Project.

The Application works as follows.

- You enter a URL in the streamlit UI
- The scraper, visits the URL and scrapes said content and stores it temporarily in a JSON.
- The scraped data is then passed to RegEx and NER models for labelling.
	- The data is checked for any PII, Malware/Phishing links or Keywords.
- Based on predefined rules and based on the labels and tags a threat level is assigned.
- In parallel the scraped data is also passed to an LLM for Threat Report Generation.
- The insights and the labels are then stored in a database for visualization in a dashboard.

There are two dashboards present:
- One based on historical data
- The other based on scraped data
- They present insights such as attack frequency and threat levels


