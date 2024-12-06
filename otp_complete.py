import re
import os
import base64
import json
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from google.auth.transport.requests import Request

# Define the scope of the access (read-only for Gmail)
SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']

# Authenticate and create the Gmail API service.
def authenticate_gmail():
    creds = None
    if os.path.exists('token.json'):
        creds = Credentials.from_authorized_user_file('token.json', SCOPES)
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file('credentials.json', SCOPES)
            creds = flow.run_local_server(port=0)
        with open('token.json', 'w') as token:
            token.write(creds.to_json())
    try:
        service = build('gmail', 'v1', credentials=creds)
        return service
    except HttpError as error:
        print(f'An error occurred: {error}')
        return None

# List the recent email messages.
def list_recent_messages(service, max_results=1):
    try:
        results = service.users().messages().list(userId='me', maxResults=max_results, labelIds=['INBOX']).execute()
        messages = results.get('messages', [])
        
        if not messages:
            print('No recent messages found.')
            return []
        return messages
    except HttpError as error:
        print(f'An error occurred: {error}')
        return []

# Extract the plain text body from the email.
def extract_otp(body):
    # Regex pattern to find a 6-digit OTP
    otp_pattern = r'\b\d{6}\b'
    match = re.search(otp_pattern, body)
    if match:
        return match.group(0)  # Return the matched OTP
    return None
def get_message_body(service, msg_id):
    try:
        message = service.users().messages().get(userId='me', id=msg_id).execute()
        payload = message['payload']
        headers = payload['headers']
        OTP = extract_otp(message['snippet'])
        from_ = ""        
        # Extract subject, from, and date from headers
        for header in headers:
            if header['name'] == 'From':
                from_ = header['value']
        if(from_ == 'VFS Global <donotreply@vfshelpline.com>'):
            print(f'OTP: {OTP}')
    
    except HttpError as error:
        print(f'An error occurred: {error}')

# Main function to run the program
def main():
    service = authenticate_gmail()
    
    if not service:
        print('Authentication failed.')
        return

    # Fetch the most recent 1 emails
    messages = list_recent_messages(service, max_results=1)

    # Get the plain text body for each of the recent messages
    if messages:
        for msg in messages:
            msg_id = msg['id']
            get_message_body(service, msg_id)

if __name__ == '__main__':
    main()
