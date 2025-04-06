# import requests

# proxies = {
#     "http": "socks5h://127.0.0.1:9050",
#     "https": "socks5h://127.0.0.1:9050",
# }

# url = "http://yq5jjvr7drkjrelzhut7kgclfuro65jjlivyzfmxiq2kyv5lickrl4qd.onion/"

# try:
#     response = requests.get(url, proxies=proxies, timeout=15)
#     print(response.text[:10000])  # Print first 500 characters
# except requests.exceptions.RequestException as e:
#     print("Error:", e)

# import os

# GROQ_API_KEY = os.getenv("GROQ_API_KEY")  # Fetch from environment

# if not GROQ_API_KEY:
#     print("[ERROR] GROQ_API_KEY is not set. Please check your environment variables.")
#     exit(1)

import os
from groq import Groq

# Ensure the API key is correctly set
GROQ_API_KEY = os.getenv("GROQ_API_KEY")
if not GROQ_API_KEY:
    raise ValueError("GROQ_API_KEY is not set. Set it in your environment variables.")

# Initialize Groq client
groq_client = Groq(api_key=GROQ_API_KEY)

# Make a test chat completion request
try:
    response = groq_client.chat.completions.create(
        model="llama3-8b-8192",
        messages=[
            {"role": "system", "content": "You are a helpful AI assistant."},
            {"role": "user", "content": "What is the capital of France?"}
        ]
    )

    # Correct way to extract the response
    print(response.choices[0].message.content)

except Exception as e:
    print(f"[ERROR] Failed to get response: {e}")

