
import email
import hashlib
import os
import re
from email.policy import default

# Global variables
FROM_HEADER = None
ATTACHMENT_HASHES = []
URLS = []


def extract_eml_details(eml_file_path):
    global FROM_HEADER, ATTACHMENT_HASHES, URLS

    # Open and parse the EML file
    with open(eml_file_path, 'rb') as eml_file:
        msg = email.message_from_binary_file(eml_file, policy=default)

    headers = _extract_headers(msg)
    FROM_HEADER = headers.get('From', None)
    x_headers = _extract_x_headers(msg)
    attachments = _extract_attachments(msg)
    filtered_urls = _extract_urls(msg)

    return {
        'headers': headers,
        'x_headers': x_headers,
        'attachments': attachments,
        'urls': filtered_urls
    }


def _extract_headers(msg):
    headers_to_extract = [
        'Delivered-To', 'ARC-Authentication-Results', 'Return-Path',
        'Date', 'From', 'Subject'
    ]
    return {key: value for key, value in msg.items() if key in headers_to_extract}


def _extract_x_headers(msg):
    return {key: value for key, value in msg.items() if key.lower().startswith('x-')}


def _extract_attachments(msg):
    global ATTACHMENT_HASHES
    attachments = []

    for part in msg.iter_attachments():
        content_disposition = part.get("Content-Disposition")
        if content_disposition and 'attachment' in content_disposition:
            filename = part.get_filename()
            if filename:
                attachment = _save_attachment(part, filename)
                attachments.append(attachment)

    return attachments


def _save_attachment(part, filename):
    global ATTACHMENT_HASHES

    with open(filename, 'wb') as f:
        f.write(part.get_payload(decode=True))

    hashes = _calculate_hashes(filename)

    ATTACHMENT_HASHES.append({
        'filename': filename,
        **hashes
    })

    os.remove(filename)

    return {'filename': filename, **hashes}


def _calculate_hashes(filename):
    md5_hash = hashlib.md5()
    sha1_hash = hashlib.sha1()
    sha256_hash = hashlib.sha256()

    with open(filename, 'rb') as f:
        while chunk := f.read(8192):
            md5_hash.update(chunk)
            sha1_hash.update(chunk)
            sha256_hash.update(chunk)

    return {
        'md5': md5_hash.hexdigest(),
        'sha1': sha1_hash.hexdigest(),
        'sha256': sha256_hash.hexdigest()
    }


def _extract_urls(msg):
    global URLS
    urls = []

    for part in msg.walk():
        if part.get_content_type() in ['text/plain', 'text/html']:
            content = part.get_payload(decode=True).decode('utf-8', errors='ignore')
            urls.extend(re.findall(r'http[s]?://\S+', content))

    image_extensions = ('.jpg', '.jpeg', '.png', '.gif', '.bmp', '.svg', '.webp', '.tiff')
    filtered_urls = [url for url in urls if not url.lower().endswith(image_extensions)]

    URLS.extend(list(set(filtered_urls)))

    return filtered_urls