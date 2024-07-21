import os
import requests
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

API_KEY = os.getenv('VIRUSTOTAL_API_KEY')
DOMAIN_BASE_URL = 'https://www.virustotal.com/api/v3/domains/'
FILE_BASE_URL = 'https://www.virustotal.com/api/v3/files/'
URL_SCAN_BASE_URL = 'https://www.virustotal.com/api/v3/urls'


def domain_lookup(domain):
    headers = {"x-apikey": API_KEY}
    response = requests.get(DOMAIN_BASE_URL + domain, headers=headers)
    return response.json() if response.status_code == 200 else None


def upload_file_to_virustotal(file_path):
    headers = {
        "accept": "application/json",
        "x-apikey": API_KEY
    }
    files = {"file": (file_path, open(file_path, 'rb'))}
    response = requests.post(FILE_BASE_URL, headers=headers, files=files)
    if response.status_code == 200:
        return response.json()['data']['id']
    return None


def get_file_report(analysis_id):
    url = f"{FILE_BASE_URL}{analysis_id}"
    headers = {"accept": "application/json", "x-apikey": API_KEY}
    response = requests.get(url, headers=headers)
    return response.json() if response.status_code == 200 else None


def scan_url_with_virustotal(url):
    headers = {
        "accept": "application/json",
        "x-apikey": API_KEY
    }
    response = requests.post(URL_SCAN_BASE_URL, headers=headers, data={'url': url})
    if response.status_code == 200:
        return response.json()
    return None