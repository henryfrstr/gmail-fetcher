from django.shortcuts import render
from decouple import config

def index(request):
    return render(request, 'frontend/index.html', {'base_url': config('BASE_URL')})

