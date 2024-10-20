from google.oauth2.credentials import Credentials
from google.auth.transport.requests import Request
from googleapiclient.discovery import build
from google_auth_oauthlib.flow import Flow

from rest_framework.views import APIView
from rest_framework.views import APIView
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework import status

from django.shortcuts import redirect

from .models import GmailAccount

import json
import base64
import requests
from decouple import config
import json
import os
import re

# Define where the credentials file will be saved (same level as your view)
CREDENTIALS_FILE_PATH = os.path.join(os.path.dirname(__file__), 'credentials.json')

# Build the credentials dictionary using decouple.config
GOOGLE_CREDENTIALS = {
    "installed": {
        "client_id": config("GOOGLE_CLIENT_ID"),
        "project_id": config("GOOGLE_PROJECT_ID"),
        "auth_uri": config("GOOGLE_AUTH_URI"),
        "token_uri": config("GOOGLE_TOKEN_URI"),
        "auth_provider_x509_cert_url": config("GOOGLE_CERT_URL"),
        "client_secret": config("GOOGLE_CLIENT_SECRET"),
        "redirect_uris": config("GOOGLE_REDIRECT_URIS").split(",")  # Split into a list
    }
}

# Save the credentials as a JSON file
with open(CREDENTIALS_FILE_PATH, 'w') as f:
    json.dump(GOOGLE_CREDENTIALS, f)

# Now you can use the credentials.json in your OAuth flow



SCOPES = [
    'https://www.googleapis.com/auth/gmail.readonly',
    'openid',
    'https://www.googleapis.com/auth/userinfo.email',  # Use the full URL for email
    'https://www.googleapis.com/auth/spreadsheets',
    'https://www.googleapis.com/auth/drive'
]

# Path to the Google Sheet
SPREADSHEET_ID = '1jPKJPZjMig4nazbdr_L38DroLr8qYaIFkLKnME1Kucw'
RANGE_NAME = 'Sheet1!A1:D1000'  # Adjust the range as needed

class GoogleOAuthInitiateView(APIView):
    permission_classes = [AllowAny]
    def get(self, request, *args, **kwargs):
        """Initiate OAuth flow to authorize a Gmail account."""
        flow = Flow.from_client_secrets_file(CREDENTIALS_FILE_PATH, SCOPES)
        flow.redirect_uri = 'https://localhost:8000/oauth2callback'

        # Generate the authorization URL
        authorization_url, _ = flow.authorization_url(
            access_type='offline',
            include_granted_scopes='true'
        )

        # Redirect the user to Google's OAuth page for login
        return redirect(authorization_url)


class GoogleOAuthCallbackView(APIView):
    permission_classes = [AllowAny]
    def get(self, request, *args, **kwargs):
        """Handle the callback from Google and save the credentials."""
        flow = Flow.from_client_secrets_file(CREDENTIALS_FILE_PATH, SCOPES)
        flow.redirect_uri = 'https://localhost:8000/oauth2callback'

        # Get the authorization code from the URL query parameters
        authorization_response = request.build_absolute_uri()
        flow.fetch_token(authorization_response=authorization_response)

        # Get credentials and store them in the database
        credentials = flow.credentials
        email = None
        if credentials.id_token and isinstance(credentials.id_token, dict):
            email = credentials.id_token.get('email')  # Safe access
        else:
            email = self.get_email_from_userinfo(credentials)

        if not email:
            return Response({"error": "Failed to retrieve email."}, status=status.HTTP_400_BAD_REQUEST)

        self.save_credentials(email, credentials)

        return Response({"message": f"OAuth completed for {email}"}, status=status.HTTP_200_OK)

    def get_email_from_userinfo(self, credentials):
        """Retrieve the user's email from the userinfo endpoint if id_token is not available or invalid."""
        userinfo_endpoint = 'https://openidconnect.googleapis.com/v1/userinfo'
        headers = {'Authorization': f'Bearer {credentials.token}'}
        response = requests.get(userinfo_endpoint, headers=headers)

        if response.status_code == 200:
            return response.json().get('email')
        else:
            return None

    def save_credentials(self, email, credentials):
        """Save the OAuth tokens to the database."""
        GmailAccount.objects.update_or_create(
            email=email,
            defaults={
                'access_token': credentials.token,
                'refresh_token': credentials.refresh_token,
                'token_uri': credentials.token_uri,
                'client_id': credentials.client_id,
                'client_secret': credentials.client_secret,
                'scopes': json.dumps(credentials.scopes),
                'expiry': credentials.expiry
            }
        )



class FetchEmailsAndWriteToSheet(APIView):
    permission_classes = [AllowAny]
    def get_credentials(self, email):
        """Retrieve stored OAuth credentials for the specified Gmail account."""
        try:
            creds_obj = GmailAccount.objects.get(email=email)
            creds = Credentials(
                token=creds_obj.access_token,
                refresh_token=creds_obj.refresh_token,
                token_uri=creds_obj.token_uri,
                client_id=creds_obj.client_id,
                client_secret=creds_obj.client_secret,
                scopes=json.loads(creds_obj.scopes)
            )

            # Refresh the token if it's expired
            if not creds.valid and creds.expired and creds.refresh_token:
                creds.refresh(Request())

                # Update the refreshed token in the database
                creds_obj.access_token = creds.token
                creds_obj.expiry = creds.expiry
                creds_obj.save()

            return creds
        except GmailAccount.DoesNotExist:
            raise Exception(f"No credentials found for {email}")

    def fetch_emails(self, gmail_service, query='subject:"Your funds of"'):
        """Fetch emails based on a specific query."""
        try:
            results = gmail_service.users().messages().list(userId='me', q=query).execute()
            messages = results.get('messages', [])
            email_data = []

            for msg in messages:
                msg_detail = gmail_service.users().messages().get(userId='me', id=msg['id']).execute()
                email_data.append(self.parse_email(msg_detail))

            return email_data
        except Exception as error:
            print(f"An error occurred: {error}")
            return None



    def parse_email(self, message):
        """Extract email details like date, from, subject, body, funds, and currency."""
        headers = message['payload']['headers']
        email_data = {}

        for header in headers:
            if header['name'] == 'Date':
                email_data['date'] = header['value']
            elif header['name'] == 'From':
                email_data['from'] = header['value']
            elif header['name'] == 'Subject':
                email_data['subject'] = header['value']

                # Extract funds and currency from the subject using regex
                funds, currency = self.extract_funds_and_currency(header['value'])
                email_data['funds'] = funds
                email_data['currency'] = currency

        body = message['payload'].get('body', {}).get('data', '')
        if not body:
            parts = message['payload'].get('parts', [])
            for part in parts:
                if part['mimeType'] == 'text/plain':
                    body = part['body']['data']
                    break

        if body:
            email_data['body'] = base64.urlsafe_b64decode(body.encode('UTF-8')).decode('UTF-8')
        else:
            email_data['body'] = 'No body available'

        return email_data

    def extract_funds_and_currency(self, subject):
        """Extract funds and currency from the subject line using regex."""
        # Pattern to match the funds and currency in the subject line
        sub_list = subject.split(' ')

        if sub_list:
            funds = sub_list[3].strip('$') # The numeric value
            currency = sub_list[4]  # The currency (letters or symbols)
            return funds, currency
        else:
            return None, None


    def clear_sheet(self, sheets_service, spreadsheet_id, range_name):
        """Clear the data in the specified range of the Google Sheet."""
        sheet = sheets_service.spreadsheets()
        sheet.values().clear(spreadsheetId=spreadsheet_id, range=range_name).execute()

    # def create_new_sheet(self, sheets_service):
    #     """Create a new Google Sheet programmatically and return its spreadsheet ID."""
    #     # Request body for creating a new spreadsheet
    #     sheet_body = {
    #         'properties': {
    #             'title': 'New Email Data Sheet'  # Set the title for the new sheet
    #         }
    #     }

    #     # Create the new spreadsheet
    #     sheet = sheets_service.spreadsheets().create(body=sheet_body).execute()

    #     # Get the spreadsheet ID of the new sheet
    #     spreadsheet_id = sheet['spreadsheetId']
    #     print(f"New spreadsheet created with ID: {spreadsheet_id}")

    #     # Construct the Google Sheet URL
    #     sheet_url = f"https://docs.google.com/spreadsheets/d/{spreadsheet_id}"
    #     print(f"New spreadsheet URL: {sheet_url}")

    #     return spreadsheet_id

    def write_to_sheet(self, sheets_service, data, spreadsheet_id):
        """Write email data to a newly created Google Sheet, including column titles."""
        sheet = sheets_service.spreadsheets()

        # Define the headers (titles for columns)
        headers = ['Date', 'From', 'Subject', 'Body', 'Funds', 'Currency', 'Email Address']

        # Prepare the data with headers first
        body = {
            'values': [headers] + data  # Add the headers as the first row
        }

        # Write data to the new sheet (using 'Sheet1' by default for a new sheet)
        # RANGE_NAME = 'Sheet1!A1'  # This writes to the first sheet in the new spreadsheet

        self.clear_sheet(sheets_service, SPREADSHEET_ID, RANGE_NAME)

        # Write the data
        sheet.values().append(
            spreadsheetId=spreadsheet_id,
            range=RANGE_NAME,
            valueInputOption='RAW',
            body=body
        ).execute()

    def get_drive_service(self, credentials):
        """Create and return the Google Drive API service."""
        return build('drive', 'v3', credentials=credentials)

    def share_google_sheet(self, drive_service, spreadsheet_id):
        """Share the Google Sheet with the Gmail accounts from the database."""
        # Fetch Gmail accounts from the database
        gmail_accounts = GmailAccount.objects.all()


        for account in gmail_accounts:
            user_email = account.email
            if not account.shared:
                try:
                    permission = {
                        'type': 'user',
                        'role': 'writer',
                        'emailAddress': user_email
                    }

                    drive_service.permissions().create(
                        fileId=spreadsheet_id,
                        body=permission,
                        fields='id'
                    ).execute()
                    account.shared = True
                    account.save()

                    print(f"Google Sheet shared with {user_email}")
                except Exception as e:
                    print(f"An error occurred while sharing the Google Sheet with {user_email}: {e}")
            else:
                print(f"Google Sheet already shared with {user_email}")

    def get(self, request, *args, **kwargs):
        """Fetch emails from all stored Gmail accounts and write them to a Google Sheet."""
        all_emails = []

        # Fetch credentials for all Gmail accounts in the database
        gmail_accounts = GmailAccount.objects.all()

        for account in gmail_accounts:
            creds = self.get_credentials(account.email)

            # Initialize the Gmail service with the credentials
            gmail_service = build('gmail', 'v1', credentials=creds)

            # Fetch emails from the Gmail account
            emails = self.fetch_emails(gmail_service)

            if emails:
                # Format the data for Google Sheets
                formatted_data = [
                [email['date'], email['from'], email['subject'], email['body'], email['funds'], email['currency'], account.email]
                for email in emails
                ]
                all_emails.extend(formatted_data)

        # If emails were fetched, write them to Google Sheets
        if all_emails:
            # Initialize the Google Sheets service
            sheets_service = build('sheets', 'v4', credentials=creds)

            # # Create a new sheet and get its spreadsheet ID
            # new_spreadsheet_id = self.create_new_sheet(sheets_service)

            self.write_to_sheet(sheets_service, all_emails, SPREADSHEET_ID)

            # Now share the Google Sheet programmatically with the user
            drive_service = self.get_drive_service(creds)
            self.share_google_sheet(drive_service, SPREADSHEET_ID)

            # Return the fetched emails and the sheet URL
            sheet_url = f"https://docs.google.com/spreadsheets/d/{SPREADSHEET_ID}"
            return Response({
                "message": "Emails fetched, written to the sheet, and sheet shared successfully.",
                "emails": all_emails,  # Return the emails as part of the response
                "sheet_url": sheet_url
            }, status=status.HTTP_200_OK)
        else:
            return Response({"message": "No emails found."}, status=status.HTTP_404_NOT_FOUND)


