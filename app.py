from flask import Flask, render_template, flash
import imaplib
import email
import requests
import os
import hashlib

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Set your secret key for message flashing

# Your email credentials
EMAIL = 'somelife48@gmail.com'
PASSWORD = 'rdxm fasv tzsz nuno'

# IMAP Configuration
IMAP_SERVER = 'imap.gmail.com'
IMAP_PORT = 993

# VirusTotal API Key
API_KEY = '658a08fb4bfed92acd52df9f5a02b66405e984f0e85cb0f0a7804bd6fd4c9913'

# Function to fetch emails
def fetch_emails():
    imap = imaplib.IMAP4_SSL(IMAP_SERVER, IMAP_PORT)
    imap.login(EMAIL, PASSWORD)
    imap.select('inbox')

    status, messages = imap.search(None, 'ALL')
    messages = messages[0].split()
    
    for message_id in messages:
        _, msg = imap.fetch(message_id, '(RFC822)')
        email_message = email.message_from_bytes(msg[0][1])
        yield email_message

    imap.close()
    imap.logout()

# Function to scan URLs
def scan_url(url):
    params = {
        'apikey': API_KEY,
        'resource': url
    }
    response = requests.get('https://www.virustotal.com/vtapi/v2/url/report', params=params)
    result = response.json()
    return result

# Function to save attachments and scan with VirusTotal
def process_attachments(email_message):
    attachments_info = []
    for part in email_message.walk():
        if part.get_content_maintype() == 'multipart':
            continue
        if part.get('Content-Disposition') is None:
            continue
        filename = part.get_filename()
        if not filename:
            continue
        file_path = os.path.join('attachments', filename)
        with open(file_path, 'wb') as f:
            f.write(part.get_payload(decode=True))
        file_hash = calculate_file_hash(file_path)
        file_scan_result = scan_file(file_hash)
        attachments_info.append({'filename': filename, 'scan_result': file_scan_result})
    return attachments_info

# Function to calculate file hash
def calculate_file_hash(file_path):
    hasher = hashlib.sha256()
    with open(file_path, 'rb') as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hasher.update(chunk)
    return hasher.hexdigest()

# Function to scan file with VirusTotal
def scan_file(file_hash):
    params = {
        'apikey': API_KEY,
        'resource': file_hash
    }
    response = requests.get('https://www.virustotal.com/vtapi/v2/file/report', params=params)
    result = response.json()
    return result


# Function to delete email
def delete_email(email_message):
    imap = imaplib.IMAP4_SSL(IMAP_SERVER, IMAP_PORT)
    imap.login(EMAIL, PASSWORD)
    imap.select('inbox')
    # Fetch email message ID
    status, messages = imap.search(None, '(HEADER Message-ID "%s")' % email_message['Message-ID'])
    message_ids = messages[0].split()
    email_details = []
    for message_id in message_ids:
        _, msg = imap.fetch(message_id, '(RFC822)')
        email_message = email.message_from_bytes(msg[0][1])
        sender = email_message['From']
        receiver = email_message['To']
        subject = email_message['Subject']
        email_details.append({'sender': sender, 'receiver': receiver, 'subject': subject})
        imap.store(message_id, '+FLAGS', '\\Deleted')  # Mark email for deletion
    imap.expunge()  # Delete marked emails
    imap.close()
    imap.logout()
    return email_details

@app.route('/')
def index():
    emails = fetch_emails()
    email_details = []
    total_scanned = 0
    total_malicious = 0
    total_safe = 0
    removed_emails = []  # List to store removed emails
    for email_message in emails:
        sender = email_message['From']
        receiver = email_message['To']
        subject = email_message['Subject']
        body = ""
        attachments_info = []
        malicious_email = False  # Flag to check if the email is malicious
        for part in email_message.walk():
            if part.get_content_type() == 'text/plain':
                body = part.get_payload(decode=True).decode()
            elif part.get_content_maintype() != 'multipart' and part.get('Content-Disposition'):
                filename = part.get_filename()
                if filename:
                    file_path = os.path.join('attachments', filename)
                    with open(file_path, 'wb') as f:
                        f.write(part.get_payload(decode=True))
                    file_hash = calculate_file_hash(file_path)
                    file_scan_result = scan_file(file_hash)
                    if file_scan_result['response_code'] == 1 and file_scan_result['positives'] > 0:
                        malicious_email = True  # Mark email as malicious if attachment is detected as malicious
                        os.remove(file_path)  # Remove malicious attachment from disk
                        continue  # Skip further processing for this attachment
                    attachments_info.append({'filename': filename, 'scan_result': file_scan_result})
        url_scan_results = []
        for url in body.split():
            if 'http' in url:
                result = scan_url(url)
                if result['response_code'] == 1 and result['positives'] > 0:
                    malicious_email = True  # Mark email as malicious if URL is detected as malicious
                    continue  # Skip further processing for this URL
                url_scan_results.append((url, result))
        if not malicious_email:  # If email is not malicious, add it to the list
            total_safe += 1
            email_details.append({'sender': sender, 'receiver': receiver, 'subject': subject, 'body': body, 'attachments': attachments_info, 'url_scan_results': url_scan_results})
        else:
            total_malicious += 1
            # Delete malicious email from inbox
            deleted_email_details = delete_email(email_message)
            removed_emails.extend(deleted_email_details)  # Add removed emails to the list
    total_scanned = total_safe + total_malicious  # Total scanned emails is the sum of safe and malicious
    return render_template('index.html', email_details=email_details, total_scanned=total_scanned, total_malicious=total_malicious, total_safe=total_safe, removed_emails=removed_emails)

if __name__ == '__main__':
    app.run(debug=False,host='0.0.0.0')
