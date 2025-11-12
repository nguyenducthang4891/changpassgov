from django.urls import path
from . import views

app_name = 'password_change'

urlpatterns = [
    path('change-password/', views.change_password, name='change_password'),
     path('', views.login_view, name='login'),
]