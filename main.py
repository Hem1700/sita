import tkinter as tk
from tkinter import filedialog, scrolledtext, font
from tkinter import ttk
import webbrowser
import re
import email
from tkhtmlview import HTMLLabel

from email_analysis import email_analysis


class EMLAnalyzerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("EML Analyzer")
        self.root.geometry("1000x700")

        self.style = ttk.Style()
        self.style.configure('TNotebook.Tab', font=('Kanit', '12', 'bold'), padding=[10, 10])
        self.style.configure('TLabel', font=('Kanit', 12), foreground='black')
        self.style.configure('TButton', font=('Kanit', 12), padding=[5, 5])
        self.style.configure('TFrame', background='#f5f5f5')

        # Adding color to the UI
        self.style.configure('Header.TLabel', background='#f5f5f5', foreground='black', font=('Kanit', 12, 'bold'))
        self.style.map('TButton', background=[('active', '#d9d9d9')])
        self.root.configure(bg='#f5f5f5')

        self.create_upload_button()
        self.create_notebook()

    def create_upload_button(self):
        button_frame = ttk.Frame(self.root, padding="10 10 10 10")
        button_frame.pack(fill='x')

        self.upload_button = ttk.Button(button_frame, text="Upload EML File", command=self.upload_file)
        self.upload_button.pack(pady=10)

    def create_notebook(self):
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(expand=1, fill='both', padx=10, pady=10)

        self.create_tabs()

    def create_tabs(self):
        self.tab_headers = ttk.Frame(self.notebook, padding="10 10 10 10")
        self.tab_attachments = ttk.Frame(self.notebook, padding="10 10 10 10")
        self.tab_urls = ttk.Frame(self.notebook, padding="10 10 10 10")
        self.tab_preview = ttk.Frame(self.notebook, padding="10 10 10 10")

        self.notebook.add(self.tab_headers, text='Headers')
        self.notebook.add(self.tab_attachments, text='Attachments')
        self.notebook.add(self.tab_urls, text='URLs')
        self.notebook.add(self.tab_preview, text='Preview')

        self.headers_text = scrolledtext.ScrolledText(self.tab_headers, wrap=tk.WORD, font=("Kanit", 10), bg='#ffffff',
                                                      fg='#000000')
        self.headers_text.pack(expand=True, fill='both', padx=10, pady=10)

        self.attachments_text = scrolledtext.ScrolledText(self.tab_attachments, wrap=tk.WORD, font=("Kanit", 10),
                                                          bg='#ffffff', fg='#000000')
        self.attachments_text.pack(expand=True, fill='both', padx=10, pady=10)

        self.create_urls_tab()

        self.preview_frame = ttk.Frame(self.tab_preview)
        self.preview_frame.pack(expand=True, fill='both', padx=10, pady=10)
        self.preview_html = HTMLLabel(self.preview_frame,
                                      html="<p>Preview will appear here after uploading an email file.</p>")
        self.preview_html.pack(expand=True, fill='both')

    def create_urls_tab(self):
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
        # Extract details from the EML file
        eml_details = email_analysis.extract_eml_details(eml_file_path)

        # Clear previous results
        self.headers_text.delete(1.0, tk.END)
        self.attachments_text.delete(1.0, tk.END)
        self.urls_tree.delete(*self.urls_tree.get_children())
        self.preview_html.set_html("<p>Loading preview...</p>")

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
            self.attachments_text.insert(tk.END,
                                         f"Filename: {attachment['filename']}, MD5: {attachment['md5']}, SHA1: {attachment['sha1']}, SHA256: {attachment['sha256']}\n")

        # Display URLs
        self.display_urls(eml_details['urls'])

        # Display Email Preview
        self.display_email_preview(eml_file_path)

    def display_urls(self, urls):
        for i, url in enumerate(urls, 1):
            self.urls_tree.insert('', 'end', values=(i, url))

    def display_email_preview(self, eml_file_path):
        with open(eml_file_path, 'rb') as eml_file:
            msg = email.message_from_binary_file(eml_file)

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
            if part.get_content_type() == 'text/plain':
                text = part.get_payload(decode=True).decode('utf-8', errors='ignore')
                html_content += f"<pre>{text}</pre>"
            elif part.get_content_type() == 'text/html':
                html = part.get_payload(decode=True).decode('utf-8', errors='ignore')
                html_content += html

        self.preview_html.set_html(html_content)

    def open_selected_url(self, event):
        item = self.urls_tree.selection()[0]
        url = self.urls_tree.item(item, 'values')[1]
        webbrowser.open(url)


if __name__ == '__main__':
    root = tk.Tk()
    app = EMLAnalyzerApp(root)
    root.mainloop()
