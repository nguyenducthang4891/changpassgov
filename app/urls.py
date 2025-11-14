from django.urls import path
from . import views

app_name = 'app'

urlpatterns = [
    path('change-password/', views.change_password, name='change_password'),
    path('', views.login_view, name='login'),
    path('auth/redirect/<str:token>/', views.redirect_intermediate_view, name='redirect_intermediate_view'),

]
