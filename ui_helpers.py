from tkinter import ttk, scrolledtext
from tkhtmlview import HTMLLabel

def configure_styles(root):
    style = ttk.Style()
    style.configure('TNotebook.Tab', font=('Kanit', '12', 'bold'), padding=[10, 10])
    style.configure('TLabel', font=('Kanit', 12), foreground='black')
    style.configure('TButton', font=('Kanit', 12), padding=[5, 5])
    style.configure('TFrame', background='#f5f5f5')
    style.configure('Header.TLabel', background='#f5f5f5', foreground='black', font=('Kanit', 12, 'bold'))
    style.configure('Title.TLabel', font=('Kanit', 20, 'bold'), foreground='black')
    style.map('TButton', background=[('active', '#d9d9d9')])
    root.configure(bg='#f5f5f5')

def create_tab(notebook, text):
    tab = ttk.Frame(notebook, padding="10 10 10 10")
    notebook.add(tab, text=text)
    return tab

def create_scrolled_text(parent):
    text_widget = scrolledtext.ScrolledText(parent, wrap='word', font=("Kanit", 10), bg='#ffffff', fg='#000000')
    text_widget.pack(expand=True, fill='both', padx=10, pady=10)
    text_widget.tag_configure('header_key', font=("Kanit", 12, 'bold'), foreground='#000000')
    text_widget.tag_configure('bold', font=("Kanit", 12, 'bold'))
    return text_widget

def create_html_label(parent, initial_html):
    frame = ttk.Frame(parent)
    frame.pack(expand=True, fill='both', padx=10, pady=10)
    html_label = HTMLLabel(frame, html=initial_html)
    html_label.pack(expand=True, fill='both')
    return html_label