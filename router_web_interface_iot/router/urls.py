from django.urls import path

from . import views

urlpatterns = [
    path("", views.dashboard, name="dashboard"),
    path("login", views.login_view, name="login"),
    path("logout", views.logout_view, name="logout"),
    path("dns", views.dns_view, name="dns"),
    path("passwd", views.password_view, name="passwd"),
    path("reboot", views.reboot_view, name="reboot"),
    path("api/status", views.status_view, name="status"),
]
