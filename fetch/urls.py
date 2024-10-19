from django.urls import path
from .views import GoogleOAuthInitiateView, GoogleOAuthCallbackView, FetchEmailsAndWriteToSheet

urlpatterns = [
    path('oauth2initiate', GoogleOAuthInitiateView.as_view(), name='oauth2_initiate'),
    path('oauth2callback', GoogleOAuthCallbackView.as_view(), name='oauth2_callback'),
    path('fetch-emails/', FetchEmailsAndWriteToSheet.as_view(), name='fetch_emails'),
]
