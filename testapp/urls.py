from django.urls import path

from . import views

urlpatterns = [
    path("simple/", views.simple_view),
    path("redirect/", views.simple_redirect),
    path("error/", views.error_view),
    path("log/", views.logging_view),
]
