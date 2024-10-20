from django.db import models

class GmailAccount(models.Model):
    """Model to store OAuth tokens for each Gmail account."""
    email = models.EmailField(unique=True)  # Gmail address for each account
    access_token = models.TextField(blank=True)
    refresh_token = models.CharField(max_length=255, null=True, blank=True)  # Allow null values
    token_uri = models.TextField(blank=True)
    client_id = models.TextField(blank=True)
    client_secret = models.TextField(blank=True)
    scopes = models.TextField(blank=True)
    expiry = models.DateTimeField(blank=True, null=True)  # Optional: Store token expiry for better management
    shared = models.BooleanField(default=False)

    def __str__(self):
        return f"Credentials for {self.email}"