from django.http import HttpResponse


def simple_view(request):
    return HttpResponse("Hello, world!")


def error_view(request):
    raise ValueError("An error occurred.")
