import logging

from django.http import HttpResponse

logger = logging.getLogger(__name__)


def simple_view(request):
    return HttpResponse("Hello, world!")


def error_view(request):
    raise ValueError("An error occurred.")


def logging_view(request):
    request.graylog.info("This message was logged with GraylogProxy.")
    logger.debug("This message was logged with GraylogRequestHandler.")
    return HttpResponse()
