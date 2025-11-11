from django.urls import path, include

urlpatterns = [
    #    path('admin/', admin.site.urls),
    path('change-password/', include(('app.urls', 'app'), namespace='app')),
]
