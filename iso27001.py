import requests
import json

def ask_llama3(prompt, model="llama3"):
    url = "http://localhost:11434/api/generate"

    payload = {
        "model": model,
        "prompt": prompt,
        "stream": False
    }

    response = requests.post(url, json=payload)
    response.raise_for_status()

    result = response.json()
    return result["response"]

if __name__ == "__main__":
    prompt = "How many controls does ISO/IEC 27001:2022 Annex A have?"
    
    try:
        answer = ask_llama3(prompt)
        print("Llama 3 answer:")
        print(answer)
    except Exception as e:
        print("Error:", e)