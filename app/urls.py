from django.urls import path
from . import views
from . import view_security

app_name = 'app'

urlpatterns = [
    path('change-password/', views.change_password, name='change_password'),
    path('', view_security.login_view, name='login'),
    path('auth/redirect/<str:token>/', view_security.redirect_intermediate_view, name='redirect_intermediate_view'),

]
