import os
import requests
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

API_KEY = os.getenv('VIRUSTOTAL_API_KEY')
BASE_URL = 'https://www.virustotal.com/api/v3/domains/'

def domain_lookup(domain):
    headers = {
        "x-apikey": API_KEY
    }
    response = requests.get(BASE_URL + domain, headers=headers)
    if response.status_code == 200:
        return response.json()
    else:
        return None