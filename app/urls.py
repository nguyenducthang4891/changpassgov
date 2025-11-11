from django.urls import path
from . import views

app_name = 'password_change'

urlpatterns = [
    path('', views.change_password, name='change_password'),
]