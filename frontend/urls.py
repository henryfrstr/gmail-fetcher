from django.urls import path
from .views import index

urlpatterns = [
    path('', index, name='index'),  # This serves the 'index.html' page at the root URL
]
