from django.shortcuts import render
from decouple import config
from fetch.models import GmailAccount

def index(request):
    authorized_emails = GmailAccount.objects.all()
    return render(request, 'frontend/index.html', {'base_url': config('BASE_URL'), 'authorized_emails': authorized_emails})

