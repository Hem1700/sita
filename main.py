import tkinter as tk
from tkinter import filedialog, scrolledtext
from tkinter import ttk
import re

from email_analysis import email_analysis

class EMLAnalyzerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("EML Analyzer")

        self.notebook = ttk.Notebook(root)
        self.notebook.pack(expand=1, fill='both')

        self.create_tabs()
        self.create_upload_button()

    def create_tabs(self):
        self.tab_headers = ttk.Frame(self.notebook)
        self.tab_attachments = ttk.Frame(self.notebook)
        self.tab_urls = ttk.Frame(self.notebook)

        self.notebook.add(self.tab_headers, text='Headers')
        self.notebook.add(self.tab_attachments, text='Attachments')
        self.notebook.add(self.tab_urls, text='URLs')

        self.headers_text = scrolledtext.ScrolledText(self.tab_headers, wrap=tk.WORD, width=100, height=30)
        self.headers_text.pack(pady=10)

        self.attachments_text = scrolledtext.ScrolledText(self.tab_attachments, wrap=tk.WORD, width=100, height=30)
        self.attachments_text.pack(pady=10)

        self.urls_text = scrolledtext.ScrolledText(self.tab_urls, wrap=tk.WORD, width=100, height=30)
        self.urls_text.pack(pady=10)

    def create_upload_button(self):
        self.upload_button = tk.Button(self.root, text="Upload EML File", command=self.upload_file)
        self.upload_button.pack(pady=10)

    def upload_file(self):
        eml_file_path = filedialog.askopenfilename(filetypes=[("EML files", "*.eml")])
        if eml_file_path:
            self.analyze_eml(eml_file_path)

    def analyze_eml(self, eml_file_path):
        # Extract details from the EML file
        eml_details = email_analysis.extract_eml_details(eml_file_path)

        # Clear previous results
        self.headers_text.delete(1.0, tk.END)
        self.attachments_text.delete(1.0, tk.END)
        self.urls_text.delete(1.0, tk.END)

        # Display Headers
        headers = eml_details['headers']
        ordered_headers = [
            'Delivered-To',
            'ARC-Authentication-Results',
            'Return-Path',
            'Date',
            'From',
            'Subject'
        ]

        arc_sub_headers = ['dkim', 'spf', 'dmarc']

        self.headers_text.insert(tk.END, '\nHEADERS:\n')
        for key in ordered_headers:
            if key in headers:
                if key == 'ARC-Authentication-Results':
                    for sub_header in arc_sub_headers:
                        pattern = rf'{sub_header}=[^\s;]+'
                        match = re.search(pattern, headers[key])
                        if match:
                            self.headers_text.insert(tk.END, f'{sub_header.upper()}: {match.group(0)}\n')
                else:
                    self.headers_text.insert(tk.END, f'{key}: {headers[key]}\n')

        self.headers_text.insert(tk.END, f'\nFrom Header (Global): {email_analysis.FROM_HEADER}\n')

        # Display Attachments
        self.attachments_text.insert(tk.END, '\nATTACHMENTS:\n')
        for attachment in email_analysis.ATTACHMENT_HASHES:
            self.attachments_text.insert(tk.END, f"Filename: {attachment['filename']}, MD5: {attachment['md5']}, SHA1: {attachment['sha1']}, SHA256: {attachment['sha256']}\n")

        # Display URLs
        self.urls_text.insert(tk.END, '\nURLS:\n')
        for i, url in enumerate(email_analysis.URLS, 1):
            self.urls_text.insert(tk.END, f'{i}. {url}\n')

if __name__ == '__main__':
    root = tk.Tk()
    app = EMLAnalyzerApp(root)
    root.mainloop()