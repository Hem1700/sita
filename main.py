import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext, ttk
import webbrowser
from email_analysis import email_analysis
from virustotal_api import domain_lookup
from ui_helpers import configure_styles, create_tab, create_scrolled_text, create_html_label
import re

class EMLAnalyzerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("EML Analyzer")
        self.root.geometry("1000x700")

        configure_styles(self.root)
        self._create_widgets()

        self.sender_domain = None

    def _create_widgets(self):
        self._create_buttons()
        self._create_notebook()

    def _create_buttons(self):
        button_frame = ttk.Frame(self.root, padding="10 10 10 10")
        button_frame.pack(fill='x')

        self.upload_button = ttk.Button(button_frame, text="Upload EML File", command=self.upload_file)
        self.upload_button.pack(side='left', pady=10, padx=5)

        self.lookup_button = ttk.Button(button_frame, text="Domain Lookup", command=self.domain_lookup)
        self.lookup_button.pack(side='left', pady=10, padx=5)

    def _create_notebook(self):
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(expand=1, fill='both', padx=10, pady=10)

        self._create_tabs()

    def _create_tabs(self):
        self.tab_headers = create_tab(self.notebook, 'Headers')
        self.tab_attachments = create_tab(self.notebook, 'Attachments')
        self.tab_urls = create_tab(self.notebook, 'URLs')
        self.tab_preview = create_tab(self.notebook, 'Preview')
        self.tab_lookup = create_tab(self.notebook, 'Lookup')

        self.headers_text = create_scrolled_text(self.tab_headers)
        self.attachments_text = create_scrolled_text(self.tab_attachments)
        self._create_urls_tab()
        self.preview_html = create_html_label(self.tab_preview, "<p>Preview will appear here after uploading an email file.</p>")
        self.lookup_text = create_scrolled_text(self.tab_lookup)

    def _create_urls_tab(self):
        columns = ('#', 'URL')
        self.urls_tree = ttk.Treeview(self.tab_urls, columns=columns, show='headings')
        self.urls_tree.heading('#', text='#')
        self.urls_tree.heading('URL', text='URL')
        self.urls_tree.column('#', width=30, anchor=tk.CENTER)
        self.urls_tree.column('URL', width=800, anchor=tk.W)
        self.urls_tree.pack(expand=True, fill='both', padx=10, pady=10)
        self.urls_tree.bind('<Double-1>', self.open_selected_url)

    def upload_file(self):
        eml_file_path = filedialog.askopenfilename(filetypes=[("EML files", "*.eml")])
        if eml_file_path:
            self.analyze_eml(eml_file_path)

    def analyze_eml(self, eml_file_path):
        eml_details = email_analysis.extract_eml_details(eml_file_path)
        self._clear_previous_results()
        self._display_headers(eml_details['headers'])
        self._display_attachments()
        self._display_urls(eml_details['urls'])
        self._display_email_preview(eml_file_path)

    def _clear_previous_results(self):
        self.headers_text.delete(1.0, tk.END)
        self.attachments_text.delete(1.0, tk.END)
        self.urls_tree.delete(*self.urls_tree.get_children())
        self.preview_html.set_html("<p>Loading preview...</p>")
        self.lookup_text.delete(1.0, tk.END)

    def _display_headers(self, headers):
        ordered_headers = [
            'Delivered-To', 'ARC-Authentication-Results', 'Return-Path',
            'Date', 'From', 'Subject'
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
        self.sender_domain = re.search("@[\w.]+", email_analysis.FROM_HEADER)
        if self.sender_domain:
            self.sender_domain = self.sender_domain.group()[1:]

    def _display_attachments(self):
        self.attachments_text.insert(tk.END, '\nATTACHMENTS:\n')
        for attachment in email_analysis.ATTACHMENT_HASHES:
            self.attachments_text.insert(tk.END, f"Filename: {attachment['filename']}, MD5: {attachment['md5']}, SHA1: {attachment['sha1']}, SHA256: {attachment['sha256']}\n")

    def _display_urls(self, urls):
        for i, url in enumerate(urls, 1):
            self.urls_tree.insert('', 'end', values=(i, url))

    def _display_email_preview(self, eml_file_path):
        with open(eml_file_path, 'rb') as eml_file:
            msg = email_analysis.email.message_from_binary_file(eml_file)
        subject = msg['subject']
        from_ = msg['from']
        date = msg['date']
        to = msg['to']
        html_content = f"""
        <h2>{subject}</h2>
        <p><strong>From:</strong> {from_}</p>
        <p><strong>Date:</strong> {date}</p>
        <p><strong>To:</strong> {to}</p>
        <hr>
        """
        for part in msg.walk():
            if part.get_content_type() in ['text/plain', 'text/html']:
                content = part.get_payload(decode=True).decode('utf-8', errors='ignore')
                html_content += f"<pre>{content}</pre>" if part.get_content_type() == 'text/plain' else content
        self.preview_html.set_html(html_content)

    def open_selected_url(self, event):
        item = self.urls_tree.selection()[0]
        url = self.urls_tree.item(item, 'values')[1]
        webbrowser.open(url)

    def domain_lookup(self):
        if not self.sender_domain:
            messagebox.showerror("Error", "No sender domain found.")
            return
        result = domain_lookup(self.sender_domain)
        if result:
            self.lookup_text.delete(1.0, tk.END)
            self.lookup_text.insert(tk.END, f"Results for domain: {self.sender_domain}\n\n")
            for key, value in result['data']['attributes'].items():
                self.lookup_text.insert(tk.END, f"{key}: {value}\n")
        else:
            messagebox.showerror("Error", "Failed to retrieve data from VirusTotal.")


if __name__ == '__main__':
    root = tk.Tk()
    app = EMLAnalyzerApp(root)
    root.mainloop()