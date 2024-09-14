import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext, ttk, simpledialog
import webbrowser
import re
import boto3
from email_analysis import email_analysis
from security_api import domain_lookup, upload_file_to_virustotal, get_file_report, scan_url_with_urlscan
from ui_helpers import configure_styles, create_tab, create_scrolled_text, create_html_label
from botocore.exceptions import NoCredentialsError, PartialCredentialsError

class EMLAnalyzerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("SITA")
        self.root.geometry("1000x700")

        configure_styles(self.root)
        self._create_widgets()

        self.sender_domain = None
        self.virustotal_file_id = None

    def _create_widgets(self):
        self._create_title()
        self._create_buttons()
        self._create_notebook()

    def _create_title(self):
        # Define a style with white text color
        style = ttk.Style()
        style.configure("Title.TLabel", foreground="white")

        # Create a frame for the title
        title_frame = ttk.Frame(self.root, padding="10 10 10 10")
        title_frame.pack(fill='x')

        # Create the label with the defined style
        title_label = ttk.Label(title_frame, text="SITA", style="Title.TLabel")
        title_label.pack(side='left', pady=10, padx=5)

    def _create_buttons(self):
        button_frame = ttk.Frame(self.root, padding="10 10 10 10")
        button_frame.pack(fill='x')

        self.upload_button = ttk.Button(button_frame, text="Upload EML File", command=self.upload_file)
        self.upload_button.pack(side='left', pady=10, padx=5)

        self.lookup_button = ttk.Button(button_frame, text="Domain Lookup", command=self.domain_lookup)
        self.lookup_button.pack(side='left', pady=10, padx=5)

        self.upload_attachment_button = ttk.Button(button_frame, text="Upload Attachment to VirusTotal", command=self.upload_attachment)
        self.upload_attachment_button.pack(side='left', pady=10, padx=5)

        self.get_attachment_report_button = ttk.Button(button_frame, text="Get Attachment Report", command=self.get_attachment_report)
        self.get_attachment_report_button.pack(side='left', pady=10, padx=5)

        self.url_scan_button = ttk.Button(button_frame, text="URL Scan", command=self.url_scan)
        self.url_scan_button.pack(side='left', pady=10, padx=5)

        self.start_sandbox_button = ttk.Button(button_frame, text="Start Sandbox", command=self.start_sandbox)
        self.start_sandbox_button.pack(side='left', pady=10, padx=5)

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
        arc_sub_headers = {'dkim': 'DKIM', 'spf': 'SPF', 'dmarc': 'DMARC'}
        self.headers_text.insert(tk.END, '\nHEADERS:\n', 'bold')
        for key in ordered_headers:
            if key in headers:
                if key == 'ARC-Authentication-Results':
                    for sub_header, display_name in arc_sub_headers.items():
                        pattern = rf'{sub_header}=(\w+)'
                        match = re.search(pattern, headers[key])
                        if match:
                            self.headers_text.insert(tk.END, f'{display_name}: ', 'header_key')
                            self.headers_text.insert(tk.END, f'{match.group(1)}\n')
                else:
                    self.headers_text.insert(tk.END, f'{key}: ', 'header_key')
                    self.headers_text.insert(tk.END, f'{headers[key]}\n')
        self.headers_text.insert(tk.END, f'\nFrom Header (Global): {email_analysis.FROM_HEADER}\n', 'header_key')
        self.sender_domain = re.search("@[\w.]+", email_analysis.FROM_HEADER)
        if self.sender_domain:
            self.sender_domain = self.sender_domain.group()[1:]

    def _display_attachments(self):
        self.attachments_text.insert(tk.END, '\nATTACHMENTS:\n', 'bold')
        for i, attachment in enumerate(email_analysis.ATTACHMENT_HASHES, start=1):
            self.attachments_text.insert(tk.END, f" {i}. Filename: {attachment['filename']},\n 2. MD5: {attachment['md5']},\n 3. SHA1:{attachment['sha1']},\n 4. SHA256:{attachment['sha256']}\n")

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

    def upload_attachment(self):
        file_path = filedialog.askopenfilename()
        if not file_path:
            return

        self.virustotal_file_id = upload_file_to_virustotal(file_path)

        if self.virustotal_file_id:
            messagebox.showinfo("Success", "Attachment uploaded successfully. You can now get the report.")
        else:
            messagebox.showerror("Error", "Failed to upload the attachment.")

    def get_attachment_report(self):
        if not self.virustotal_file_id:
            messagebox.showerror("Error", "No file uploaded to VirusTotal.")
            return

        report = get_file_report(self.virustotal_file_id)
        if report:
            self._display_attachment_report(report)
        else:
            messagebox.showerror("Error", "Failed to retrieve the report.")

    def _display_attachment_report(self, report):
        self.lookup_text.delete(1.0, tk.END)
        self.lookup_text.insert(tk.END, "Attachment Report:\n\n")
        for key, value in report['data']['attributes'].items():
            self.lookup_text.insert(tk.END, f"{key}: {value}\n")

    def url_scan(self):
        selected_url = simpledialog.askstring("URL Scan", "Enter the URL you want to scan:")
        if not selected_url:
            return
        scan_result = scan_url_with_urlscan(selected_url)
        if scan_result:
            self._display_url_scan_result(scan_result)
        else:
            messagebox.showerror("Error", "Failed to scan the URL.")

    def _display_url_scan_result(self, scan_result):
        result_window = tk.Toplevel(self.root)
        result_window.title("URL Scan Result")
        result_window.geometry("800x600")

        result_text = scrolledtext.ScrolledText(result_window, wrap=tk.WORD, font=("Kanit", 10), bg='#ffffff',
                                                fg='#000000')
        result_text.pack(expand=True, fill='both', padx=10, pady=10)

        result_text.insert(tk.END, "URL Scan Report:\n\n")
        for key, value in scan_result.items():
            result_text.insert(tk.END, f"{key}: {value}\n")

    def start_sandbox(self):
        try:
            ec2 = boto3.resource('ec2')
            instance = ec2.create_instances(
                ImageId='ami-0e86e20dae9224db8',  # Replace with your desired AMI ID
                MinCount=1,
                MaxCount=1,
                InstanceType='t2.micro',  # Replace with your desired instance type
                KeyName='sita',  # Replace with your key pair name
                TagSpecifications=[{
                    'ResourceType': 'instance',
                    'Tags': [{'Key': 'Name', 'Value': 'SandboxInstance'}]
                }]
            )
            instance_id = instance[0].id
            messagebox.showinfo("Success", f"EC2 instance created with ID: {instance_id}")
        except NoCredentialsError:
            messagebox.showerror("Error", "AWS credentials not found.")
        except PartialCredentialsError:
            messagebox.showerror("Error", "Incomplete AWS credentials.")
        except Exception as e:
            messagebox.showerror("Error", f"An error occurred: {e}")


if __name__ == "__main__":
    root = tk.Tk()
    app = EMLAnalyzerApp(root)
    root.mainloop()
