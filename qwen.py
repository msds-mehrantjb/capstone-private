import requests
import json

OLLAMA_URL = "http://localhost:11434/api/generate"
MODEL_NAME = "qwen3:14b"   # ✅ FIXED

prompt = """
Answer this clearly and briefly:

How many ISO/IEC 27001:2022 Annex A controls are there, and how many controls are in each category?
"""

payload = {
    "model": MODEL_NAME,
    "prompt": prompt,
    "stream": False
}

try:
    response = requests.post(OLLAMA_URL, json=payload, timeout=300)  # ⬅️ increased timeout
    response.raise_for_status()

    result = response.json()
    print("Model response:\n")
    print(result["response"])

except requests.exceptions.RequestException as e:
    print(f"Request failed: {e}")
except KeyError:
    print("Unexpected response format:")
    print(response.text)