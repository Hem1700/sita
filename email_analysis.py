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

    # Extract specific headers
    headers_to_extract = [
        'Delivered-To',
        'ARC-Authentication-Results',
        'Return-Path',
        'Date',
        'From',
        'Subject'
    ]
    headers = {key: value for key, value in msg.items() if key in headers_to_extract}

    # Store the 'From' header in the global variable
    if 'From' in headers:
        FROM_HEADER = headers['From']

    # Extract X-headers
    x_headers = {key: value for key, value in headers.items() if key.lower().startswith('x-')}

    # Extract attachments and their hashes
    attachments = []
    for part in msg.iter_attachments():
        attachment = {}
        content_disposition = part.get("Content-Disposition")
        if content_disposition and 'attachment' in content_disposition:
            filename = part.get_filename()
            if filename:
                attachment['filename'] = filename

                # Save attachment to a temporary file
                with open(filename, 'wb') as f:
                    f.write(part.get_payload(decode=True))

                # Calculate hashes
                md5_hash = hashlib.md5()
                sha1_hash = hashlib.sha1()
                sha256_hash = hashlib.sha256()

                with open(filename, 'rb') as f:
                    while chunk := f.read(8192):
                        md5_hash.update(chunk)
                        sha1_hash.update(chunk)
                        sha256_hash.update(chunk)

                attachment['md5'] = md5_hash.hexdigest()
                attachment['sha1'] = sha1_hash.hexdigest()
                attachment['sha256'] = sha256_hash.hexdigest()

                # Store hashes in the global variable
                ATTACHMENT_HASHES.append({
                    'filename': filename,
                    'md5': md5_hash.hexdigest(),
                    'sha1': sha1_hash.hexdigest(),
                    'sha256': sha256_hash.hexdigest()
                })

                # Clean up temporary file
                os.remove(filename)

                attachments.append(attachment)

    # Extract URLs from the email body
    urls = []
    for part in msg.walk():
        if part.get_content_type() == 'text/plain':
            text = part.get_payload(decode=True).decode('utf-8', errors='ignore')
            urls.extend(re.findall(r'http[s]?://\S+', text))
        elif part.get_content_type() == 'text/html':
            html = part.get_payload(decode=True).decode('utf-8', errors='ignore')
            urls.extend(re.findall(r'http[s]?://\S+', html))

    # Store unique URLs in the global variable
    URLS.extend(list(set(urls)))

    return {
        'headers': headers,
        'x_headers': x_headers,
        'attachments': attachments,
        'urls': urls
    }