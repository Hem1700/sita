import os
import requests
from dotenv import load_dotenv
import json

# Load environment variables from .env file
load_dotenv()

VIRUSTOTAL_API_KEY = os.getenv('VIRUSTOTAL_API_KEY')
URLSCAN_API_KEY = os.getenv('URLSCAN_API_KEY')

DOMAIN_BASE_URL = 'https://www.virustotal.com/api/v3/domains/'
FILE_BASE_URL = 'https://www.virustotal.com/api/v3/files/'

def domain_lookup(domain):
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    response = requests.get(DOMAIN_BASE_URL + domain, headers=headers)
    return response.json() if response.status_code == 200 else None

def upload_file_to_virustotal(file_path):
    url = FILE_BASE_URL
    headers = {
        "accept": "application/json",
        "x-apikey": VIRUSTOTAL_API_KEY,
        "content-type": "multipart/form-data"
    }
    try:
        with open(file_path, 'rb') as file:
            files = {"file": (os.path.basename(file_path), file)}
            response = requests.post(url, headers=headers, files=files)
        if response.status_code == 200:
            return response.json()['data']['id']
        else:
            print(f"Failed to upload file. Status code: {response.status_code}, Response: {response.text}")
            return None
    except Exception as e:
        print(f"An error occurred while uploading the file: {e}")
        return None

def get_file_report(file_id):
    url = f"{FILE_BASE_URL}{file_id}"
    headers = {
        "accept": "application/json",
        "x-apikey": VIRUSTOTAL_API_KEY
    }
    response = requests.get(url, headers=headers)
    return response.json() if response.status_code == 200 else None

def scan_url_with_urlscan(url):
    headers = {
        'API-Key': URLSCAN_API_KEY,
        'Content-Type': 'application/json'
    }
    data = {"url": url, "visibility": "public"}
    response = requests.post('https://urlscan.io/api/v1/scan/', headers=headers, data=json.dumps(data))
    if response.status_code == 200:
        return response.json()
    else:
        print(f"Failed to scan URL. Status code: {response.status_code}, Response: {response.text}")
        return None