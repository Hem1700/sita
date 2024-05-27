import argparse
import re

from email_analysis import  email_analysis


def main():
    # Set up argument parser
    parser = argparse.ArgumentParser(description="Extract details from an EML file.")
    parser.add_argument('eml_file_path', type=str, help="Path to the EML file.")

    # Parse arguments
    args = parser.parse_args()

    # Extract details from the EML file
    eml_details = email_analysis.extract_eml_details(args.eml_file_path)

    # Print specific headers in the desired order
    headers = eml_details['headers']
    ordered_headers = [
        'Delivered-To',
        'ARC-Authentication-Results',
        'Return-Path',
        'Date',
        'From',
        'Subject'
    ]

    # ARC-Authentication-Results specific sub-headers
    arc_sub_headers = ['dkim', 'spf', 'dmarc']

    print('\n\033[1m\033[4mHEADERS:\033[0m')
    for key in ordered_headers:
        if key in headers:
            if key == 'ARC-Authentication-Results':
                for sub_header in arc_sub_headers:
                    pattern = rf'{sub_header}=[^\s;]+'
                    match = re.search(pattern, headers[key])
                    if match:
                        print(f'{sub_header.upper()}: {match.group(0)}')
            else:
                print(f'{key}: {headers[key]}')

    # Print 'From' header stored in the global variable
    print(f'\n\033[1mFrom Header (Global):\033[0m {email_analysis.FROM_HEADER}')

    # Print X-Headers
    print('\n\033[1m\033[4mX-HEADERS:\033[0m')
    for key, value in eml_details['x_headers'].items():
        print(f'{key}: {value}')

    # Print Attachments
    print('\n\033[1m\033[4mATTACHMENTS:\033[0m')
    for attachment in email_analysis.ATTACHMENT_HASHES:
        print(
            f"Filename: {attachment['filename']}, MD5: {attachment['md5']}, SHA1: {attachment['sha1']}, SHA256: {attachment['sha256']}")

    # Print URLs
    print('\n\033[1m\033[4mURLS:\033[0m')
    for i, url in enumerate(email_analysis.URLS, 1):
        print(f'{i}. {url}')


if __name__ == '__main__':
    main()