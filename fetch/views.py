from google.oauth2.credentials import Credentials
from google.auth.transport.requests import Request
from googleapiclient.discovery import build
from google_auth_oauthlib.flow import Flow
from googleapiclient.errors import HttpError

from rest_framework.views import APIView
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework import status

from django.shortcuts import render, redirect
from django.db import IntegrityError

from .models import GmailAccount

import json
import base64
import requests
from decouple import config
import os
from dateutil import parser


# Define where the credentials file will be saved (same level as your view)
CREDENTIALS_FILE_PATH = os.path.join(os.path.dirname(__file__), 'credentials.json')
BASE_URL = config('BASE_URL')

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

SCOPES = [
    'https://www.googleapis.com/auth/gmail.readonly',
    'openid',
    'https://www.googleapis.com/auth/userinfo.email',
    'https://www.googleapis.com/auth/spreadsheets',
    'https://www.googleapis.com/auth/drive'
]

# Path to the Google Sheet
SPREADSHEET_ID = '1jPKJPZjMig4nazbdr_L38DroLr8qYaIFkLKnME1Kucw'
# SPREADSHEET_ID = '1_DMosMgIrXZdnrm9ff36XmuppyJstu38lTrS7WSMS9c'
RANGE_NAME = 'Sheet1!A1:H10000'  # Adjust the range as needed

class GoogleOAuthInitiateView(APIView):
    permission_classes = [AllowAny]

    def get(self, request, *args, **kwargs):
        try:
            flow = Flow.from_client_secrets_file(CREDENTIALS_FILE_PATH, SCOPES)
            flow.redirect_uri = f'{BASE_URL}/oauth2callback'

            # Generate the authorization URL
            authorization_url, _ = flow.authorization_url(
                access_type='offline',
                prompt='consent',
                include_granted_scopes='true'
            )

            return redirect(authorization_url)
        except Exception as e:
            return Response({"error": f"Failed to initiate OAuth: {str(e)}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class GoogleOAuthCallbackView(APIView):
    permission_classes = [AllowAny]

    def get(self, request, *args, **kwargs):
        try:
            flow = Flow.from_client_secrets_file(CREDENTIALS_FILE_PATH, SCOPES)
            flow.redirect_uri = f'{BASE_URL}/oauth2callback'

            authorization_response = request.build_absolute_uri()
            flow.fetch_token(authorization_response=authorization_response)

            credentials = flow.credentials
            email = self.get_email_from_userinfo(credentials)

            if not email:
                return Response({"error": "Failed to retrieve email."}, status=status.HTTP_400_BAD_REQUEST)

            self.save_credentials(email, credentials)

            success_message = f"OAuth completed for {email}"
            return render(request, 'frontend/success.html', {'message': success_message})

        except HttpError as http_error:
            return Response({"error": f"Google API error: {str(http_error)}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        except Exception as e:
            return Response({"error": f"Failed during OAuth callback: {str(e)}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def get_email_from_userinfo(self, credentials):
        try:
            userinfo_endpoint = 'https://openidconnect.googleapis.com/v1/userinfo'
            headers = {'Authorization': f'Bearer {credentials.token}'}
            response = requests.get(userinfo_endpoint, headers=headers)

            if response.status_code == 200:
                return response.json().get('email')
            return None
        except Exception as e:
            print(f"Error fetching user info: {e}")
            return None

    def save_credentials(self, email, credentials):
        try:
            gmail_account, _ = GmailAccount.objects.get_or_create(email=email)
            refresh_token = credentials.refresh_token if credentials.refresh_token else gmail_account.refresh_token

            gmail_account.access_token = credentials.token
            gmail_account.refresh_token = refresh_token
            gmail_account.token_uri = credentials.token_uri
            gmail_account.client_id = credentials.client_id
            gmail_account.client_secret = credentials.client_secret
            gmail_account.scopes = json.dumps(credentials.scopes)
            gmail_account.expiry = credentials.expiry
            gmail_account.save()
        except IntegrityError as e:
            print(f"Error saving credentials: {e}")
            raise Exception("Database error while saving credentials.")
        except Exception as e:
            print(f"Error saving credentials: {e}")
            raise Exception("Unknown error while saving credentials.")


class FetchEmailsAndWriteToSheet(APIView):
    permission_classes = [AllowAny]

    def get_credentials(self, email):
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

            if not creds.valid and creds.expired and creds.refresh_token:
                creds.refresh(Request())

                creds_obj.access_token = creds.token
                creds_obj.expiry = creds.expiry
                creds_obj.save()

            return creds
        except GmailAccount.DoesNotExist:
            raise Exception(f"No credentials found for {email}")
        except Exception as e:
            print(f"Error retrieving credentials: {e}")
            raise

    def fetch_emails(self, gmail_service, query='subject:"Your funds of"', batch_size=100):
        try:
            email_data = []
            page_token = None

            for _ in range(batch_size):
                results = gmail_service.users().messages().list(
                    userId='me',
                    q=query,
                    maxResults=100,  # Fetch up to 100 messages per batch
                    pageToken=page_token
                ).execute()

                messages = results.get('messages', [])
                for msg in messages:
                    msg_detail = gmail_service.users().messages().get(userId='me', id=msg['id']).execute()
                    email_data.append(self.parse_email(msg_detail))

                page_token = results.get('nextPageToken')
                if not page_token:
                    break

            return email_data
        except HttpError as error:
            print(f"An error occurred while fetching emails: {error}")
            raise Exception("Error fetching emails from Gmail API.")

    def parse_email(self, message):
        """Extract email details like date, from, subject, body, funds, and currency."""
        headers = message['payload']['headers']
        email_data = {}

        # Extract the relevant headers
        for header in headers:
            if header['name'] == 'Date':
                raw_date = header['value']  # Original date string
                try:
                    # Parse the original date string
                    parsed_date = parser.parse(raw_date)
                    # Format the date to "16 Dec 2024"
                    email_data['date'] = parsed_date.strftime('%d %b %Y')
                except Exception as e:
                    print(f"Error parsing date: {raw_date}. Error: {e}")
                    # Fallback to the raw date if parsing fails
                    email_data['date'] = raw_date
            elif header['name'] == 'From':
                email_data['from'] = header['value']
            elif header['name'] == 'Subject':
                email_data['subject'] = header['value']

                # Extract funds and currency from the subject using regex
                funds, currency = self.extract_funds_and_currency(header['value'])
                email_data['funds'] = funds
                email_data['currency'] = currency

        # Get the body of the email
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
        """Extract funds and currency from the subject line using regex or basic string manipulation."""
        try:
            # Split the subject into parts
            sub_list = subject.split(' ')

            # Check if the subject has enough parts to extract funds and currency
            if len(sub_list) >= 5:
                funds = sub_list[3].strip('$')  # The numeric value
                currency = sub_list[4]  # The currency (letters or symbols)
                return funds, currency
            else:
                raise ValueError("Subject format is invalid for funds and currency extraction")

        except ValueError as e:
            print(f"Value error while extracting funds and currency: {e}")
            return "N/A", "N/A"  # Return "N/A" if the funds or currency could not be extracted

        except Exception as e:
            print(f"An unknown error occurred while extracting funds and currency: {e}")
            return "N/A", "N/A"


    def clear_sheet(self, sheets_service, spreadsheet_id, range_name):
        try:
            sheets_service.spreadsheets().values().clear(
                spreadsheetId=spreadsheet_id,
                range=range_name
            ).execute()
        except HttpError as error:
            print(f"An error occurred while clearing the sheet: {error}")
            raise Exception("Google Sheets API error during sheet clear operation.")
        except Exception as e:
            print(f"An error occurred: {e}")
            raise

    def write_to_sheet(self, sheets_service, data, spreadsheet_id):
        try:
            sheet = sheets_service.spreadsheets()

            # Define headers and the body of data
            headers = ['Date', 'From', 'Subject', 'Body', 'Funds', 'Currency', 'Email Address']
            body = {'values': [headers] + data}

            # Append data to the spreadsheet
            sheet.values().append(
                spreadsheetId=spreadsheet_id,
                range=RANGE_NAME,
                valueInputOption='RAW',
                body=body
            ).execute()

            # Format the "Funds" column (E column, index starts at 4 in 0-based index)
            self.format_funds_column(sheets_service, spreadsheet_id)

        except HttpError as error:
            print(f"An error occurred while writing to the sheet: {error}")
            raise Exception("Google Sheets API error during data write operation.")
        except Exception as e:
            print(f"An unknown error occurred: {e}")
            raise

    def format_funds_column(self, sheets_service, spreadsheet_id):
        try:
            # Define the request to format the column as a number
            requests = [
                {
                    "repeatCell": {
                        "range": {
                            "sheetId": 0,  # Default sheet ID is usually 0; update if necessary
                            "startRowIndex": 0,  # Skip the header row
                            "startColumnIndex": 4,  # E column (0-based index)
                            "endColumnIndex": 5
                        },
                        "cell": {
                            "userEnteredFormat": {
                                "numberFormat": {
                                    "type": "NUMBER",
                                    "pattern": "#,##0.00"  # Adjust pattern if needed
                                }
                            }
                        },
                        "fields": "userEnteredFormat.numberFormat"
                    }
                }
            ]

            # Execute the batch update request
            sheets_service.spreadsheets().batchUpdate(
                spreadsheetId=spreadsheet_id,
                body={"requests": requests}
            ).execute()

        except HttpError as error:
            print(f"An error occurred while formatting the 'Funds' column: {error}")
            raise Exception("Google Sheets API error during column formatting.")
        except Exception as e:
            print(f"An unknown error occurred: {e}")
            raise

    def share_google_sheet(self, drive_service, spreadsheet_id):
        try:
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
                    except HttpError as e:
                        print(f"Google Sheets API error: {e}")
                    except Exception as e:
                        print(f"An unknown error occurred while sharing with {user_email}: {e}")
                else:
                    print(f"Google Sheet already shared with {user_email}")
        except Exception as e:
            print(f"Error sharing Google Sheet: {e}")
            raise

    def get(self, request, *args, **kwargs):
        try:
            all_emails = []

            # Fetch credentials for all Gmail accounts in the database
            gmail_accounts = GmailAccount.objects.all()

            for account in gmail_accounts:
                creds = self.get_credentials(account.email)

                # Initialize the Gmail service with the credentials
                gmail_service = build('gmail', 'v1', credentials=creds)

                # Fetch emails from the Gmail account
                emails = self.fetch_emails(gmail_service)
                print(len(emails), "emails fetched from", account.email)

                if emails:
                    # Format the data for Google Sheets
                    formatted_data = [
                        [email['date'], email['from'], email['subject'], email['body'], float(email['funds'].replace(',', '')), email['currency'], account.email]
                        for email in emails
                    ]
                    all_emails.extend(formatted_data)
            print(len(all_emails), "all emails fetched")

            if all_emails:
                print('**********************************')
                # Initialize the Google Sheets and Google Drive services
                sheets_service = build('sheets', 'v4', credentials=creds)
                drive_service = build('drive', 'v3', credentials=creds)
                print('111**********************************')

                # # Ensure the sheet exists by checking permissions or ownership
                # try:
                #     # Check if the file exists and is accessible to the authenticated user
                #     sheet = drive_service.files().get(fileId=SPREADSHEET_ID).execute()
                # except HttpError as e:
                #     if e.resp.status == 404:
                #         return Response({"error": "Google Sheet not found."}, status=status.HTTP_404_NOT_FOUND)
                #     else:
                #         raise

                print('222**********************************')
                # Share the Google Sheet programmatically with the necessary users before writing
                self.share_google_sheet(drive_service, SPREADSHEET_ID)

                # Clear the sheet before writing the new data
                try:
                    self.clear_sheet(sheets_service, SPREADSHEET_ID, RANGE_NAME)
                except HttpError as e:
                    if e.resp.status == 403:
                        return Response({"error": "The caller does not have permission to modify the sheet."}, status=status.HTTP_403_FORBIDDEN)
                    else:
                        raise

                print('333**********************************')
                # Write data to the sheet after sharing
                self.write_to_sheet(sheets_service, all_emails, SPREADSHEET_ID)

                # Return the fetched emails and the sheet URL
                sheet_url = f"https://docs.google.com/spreadsheets/d/{SPREADSHEET_ID}"
                return Response({
                    "message": "Emails fetched, written to the sheet, and sheet shared successfully.",
                    "emails": all_emails,
                    "sheet_url": sheet_url
                }, status=status.HTTP_200_OK)
            else:
                return Response({"message": "No emails found."}, status=status.HTTP_404_NOT_FOUND)

        except HttpError as e:
            return Response({"error": f"Google API error: {str(e)}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        except Exception as e:
            return Response({"error": f"An error occurred: {str(e)}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

