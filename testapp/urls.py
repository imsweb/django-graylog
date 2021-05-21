from django.urls import path

from . import views

urlpatterns = [
    path("simple/", views.simple_view),
    path("error/", views.error_view),
]
