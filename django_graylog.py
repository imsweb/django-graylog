import contextvars
import enum
import gzip
import json
import logging
import os
import re
import socket
import struct
import textwrap
import time
import traceback
import urllib.parse

from django.conf import settings
from django.core.exceptions import ImproperlyConfigured, MiddlewareNotUsed

try:
    import requests

    has_requests = True
except ImportError:
    has_requests = False

try:
    from ua_parser import user_agent_parser

    has_ua_parser = True
except ImportError:
    has_ua_parser = False

__version__ = "0.7.0"
__version_info__ = tuple(int(num) for num in __version__.split("."))


current_request = contextvars.ContextVar("current_request")


class Severity(enum.IntEnum):
    EMERGENCY = 0
    ALERT = 1
    CRITICAL = 2
    ERROR = 3
    WARNING = 4
    NOTICE = 5
    INFO = 6
    DEBUG = 7

    @classmethod
    def from_level(cls, level):
        return getattr(cls, logging.getLevelName(level), cls.ALERT)


IP_REGEX = re.compile(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}")

GELF_FIELD_REGEX = re.compile(r"^[\w\.\-]+$")
GELF_RESERVED_FIELDS = set(
    [
        "id",
        "version",
        "host",
        "short_message",
        "full_message",
        "timestamp",
        "level",
        "facility",
        "line",
        "file",
        "logs",
    ]
)

SENSITIVE_HEADERS = set(
    [
        "authorization",
        "cookie",
        "proxy-authorization",
    ]
)


def get_ip(request):
    ip_address = request.META.get("HTTP_X_FORWARDED_FOR", "").strip()
    if ip_address:
        ip_address = ip_address.split(",")[0].strip()
    if not ip_address:
        ip_address = request.META.get("REMOTE_ADDR", "127.0.0.1").strip()
    if not IP_REGEX.match(ip_address):
        ip_address = ""
    return ip_address


class GraylogRequestHandler(logging.Handler):
    def emit(self, record):
        try:
            request = current_request.get()
            if request and hasattr(request, "graylog"):
                request.graylog.log(
                    Severity.from_level(record.levelno),
                    self.format(record),
                    _name=record.name,
                )
        except LookupError:
            # No current request, nothing for this handler to do.
            pass


class GraylogProxy:
    def __init__(self, name=None):
        self.default_name = name
        self.logs = []
        self.extra = getattr(settings, "GRAYLOG_FIELDS", {}).copy()

    def __setitem__(self, name, value):
        if name.startswith("_"):
            raise KeyError(
                "Invalid key ({}). Keys will automatically be prefixed with an "
                "underscore.".format(name)
            )
        if not GELF_FIELD_REGEX.match(name):
            raise KeyError(
                "Invalid key ({}). Keys must match [\\w\\.\\-]+.".format(name)
            )
        if name in GELF_RESERVED_FIELDS:
            raise KeyError("Invalid key ({}). This key name is reserved.".format(name))
        self.extra[name] = value

    def log(self, level, message, *args, **kwargs):
        name = kwargs.get("_name", self.default_name)
        entry = {
            "level": int(level),
            "message": message.format(*args, **kwargs),
        }
        if name:
            entry["name"] = name
        self.logs.append(entry)

    def debug(self, message, *args, **kwargs):
        self.log(Severity.DEBUG, message, *args, **kwargs)

    def info(self, message, *args, **kwargs):
        self.log(Severity.INFO, message, *args, **kwargs)

    def warning(self, message, *args, **kwargs):
        self.log(Severity.WARNING, message, *args, **kwargs)

    def error(self, message, *args, **kwargs):
        self.log(Severity.ERROR, message, *args, **kwargs)

    def critical(self, message, *args, **kwargs):
        self.log(Severity.CRITICAL, message, *args, **kwargs)

    def additional_fields(self):
        fields = {}
        if self.logs:
            fields["_logs"] = self.logs
        for name, value in self.extra.items():
            fields["_" + name] = value
        return fields


class RequestsTransport:
    def __init__(self, endpoint):
        self.endpoint = endpoint
        self.timeout = float(getattr(settings, "GRAYLOG_TIMEOUT", 0.25))
        self.session = requests.Session()
        self.session.headers["content-type"] = "application/json"
        self.session.headers["content-encoding"] = "gzip"

    def send(self, record):
        compressed = gzip.compress(json.dumps(record).encode("utf-8"))
        try:
            self.session.post(self.endpoint, data=compressed, timeout=self.timeout)
        except requests.exceptions.RequestException:
            pass  # What to do here?


class UDPTransport:
    def __init__(self, endpoint):
        parts = urllib.parse.urlparse(endpoint)
        self.address = (parts.hostname, parts.port)
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.mtu = getattr(settings, "GRAYLOG_MTU", 1024)

    def chunked(self, data):
        message_id = os.urandom(8)
        chunk_size = self.mtu - 12
        chunks = [
            data[pos : pos + chunk_size] for pos in range(0, len(data), chunk_size)
        ]
        chunk_count = len(chunks)
        for chunk_index, chunk in enumerate(chunks):
            yield b"".join(
                (
                    b"\x1e\x0f",
                    message_id,
                    struct.pack("!BB", chunk_index, chunk_count),
                    chunk,
                )
            )

    def send(self, record):
        compressed = gzip.compress(json.dumps(record).encode("utf-8"))
        if len(compressed) > self.mtu:
            for chunk in self.chunked(compressed):
                self.socket.sendto(chunk, self.address)
        else:
            self.socket.sendto(compressed, self.address)


class TCPTransport:
    def __init__(self, endpoint):
        parts = urllib.parse.urlparse(endpoint)
        self.address = (parts.hostname, parts.port)
        self.timeout = float(getattr(settings, "GRAYLOG_TIMEOUT", 0.25))
        self.delim = getattr(settings, "GRAYLOG_TCP_DELIMITER", b"\x00")

    def send(self, record):
        # Graylog over TCP does not support compression.
        payload = json.dumps(record).encode("utf-8")
        # TODO: have an option to keep a socket open and reconnect as needed?
        with socket.create_connection(self.address, timeout=self.timeout) as sock:
            sock.sendall(payload)


class TestTransport:
    def __init__(self, endpoint):
        self.attribute = urllib.parse.urlparse(endpoint).hostname
        self.messages = []

    def send(self, record):
        self.messages.append(record)


def compile_filters(filters):
    compiled = {}
    for name, regexes in filters.items():
        if name not in ("version", "host", "short_message", "level"):
            name = "_" + name.lstrip("_")
        if isinstance(regexes, str):
            regexes = [regexes]
        patterns = []
        for regex in regexes:
            if isinstance(regex, re.Pattern):
                patterns.append(regex)
            elif isinstance(regex, str):
                patterns.append(re.compile(regex))
            elif isinstance(regex, (list, tuple)) and len(regex) == 2:
                patterns.append(re.compile(*regex))
        compiled[name] = patterns
    return compiled


class GraylogMiddleware:
    scheme_transports = {
        "http": RequestsTransport,
        "https": RequestsTransport,
        "udp": UDPTransport,
        "tcp": TCPTransport,
        "test": TestTransport,
    }

    def __init__(self, get_response):
        self.endpoint = getattr(settings, "GRAYLOG_ENDPOINT", "")
        self.filters = compile_filters(getattr(settings, "GRAYLOG_FILTERS", {}))
        self.facility = getattr(settings, "GRAYLOG_FACILITY", "django-graylog")
        if not self.endpoint:
            raise MiddlewareNotUsed()
        if getattr(settings, "GRAYLOG_USER_AGENT", False) and not has_ua_parser:
            raise ImproperlyConfigured(
                "The `ua_parser` library is required when GRAYLOG_USER_AGENT is True."
            )
        scheme = urllib.parse.urlparse(self.endpoint).scheme
        if scheme.startswith("http") and not has_requests:
            raise ImproperlyConfigured(
                "The `requests` library is required to use HTTP[S] endpoints."
            )
        self.transport = self.scheme_transports[scheme](self.endpoint)
        self.get_response = get_response

    def __call__(self, request):
        start = time.time()
        setattr(request, "graylog", GraylogProxy(self.facility))
        token = current_request.set(request)
        response = self.get_response(request)
        elapsed = time.time() - start
        try:
            record = self.make_record(request, response, elapsed)
            if self.filter(record, request, response):
                self.transport.send(record)
                if isinstance(self.transport, TestTransport):
                    setattr(response, self.transport.attribute, record)
        except Exception:
            if getattr(settings, "DEBUG", False):
                raise
        finally:
            current_request.reset(token)
        return response

    def process_exception(self, request, exception):
        # Always log the exception class if an exception occurs.
        fields = {
            "_exception_class": exception.__class__.__name__,
        }
        lines = traceback.format_tb(exception.__traceback__)
        if getattr(settings, "GRAYLOG_EXCEPTION_MESSAGES", True):
            # Split out the exception message into a separate field by default.
            fields["_exception_message"] = str(exception)
        else:
            # If not logging exception messages, chop off the last line of the stack
            # trace, and don't include the _exception_message field.
            lines.pop()
        fields["full_message"] = textwrap.dedent("".join(lines)).rstrip()
        setattr(request, "_graylog_exception", fields)

    def filter(self, record, request, response):
        for field_name, regexes in self.filters.items():
            if field_name not in record:
                continue
            value = str(record[field_name])
            for regex in regexes:
                if regex.match(value):
                    return False
        return True

    def parse_agent(self, agent):
        if not agent:
            return {}
        ua = user_agent_parser.Parse(agent)
        is_spider = ua["device"]["family"] == "Spider"
        is_unknown = (
            (ua["user_agent"]["family"] == "Other")
            and (ua["os"]["family"] == "Other")
            and (ua["device"]["family"] == "Other")
        )
        fields = {"_agent": agent}
        if not is_spider and not is_unknown:
            fields.update(
                {
                    "_browser": ua["user_agent"]["family"],
                    "_browser_version": ua["user_agent"]["major"],
                    "_os": ua["os"]["family"],
                    "_os_version": ua["os"]["major"],
                }
            )
        return fields

    def parse_referer(self, referer):
        if not referer:
            return {}
        try:
            fields = {"_referer": referer}
            domain = urllib.parse.urlparse(referer).netloc
            if domain:
                fields["_referer_domain"] = domain
            return fields
        except ValueError:
            return {}

    def request_headers(self, request):
        headers = {}
        include_headers = getattr(settings, "GRAYLOG_HEADERS", [])
        exclude_headers = set(
            name.lower()
            for name in getattr(settings, "GRAYLOG_EXCLUDE_HEADERS", SENSITIVE_HEADERS)
        )
        if include_headers is True:
            # User-Agent and Referer are not included by default, since they will either
            # be in separate fields if requested via settings, or can be explicitly
            # requested in GRAYLOG_HEADERS otherwise.
            include_headers = [
                name
                for name in sorted(request.headers.keys())
                if name.lower() not in ("user-agent", "referer")
            ]
        for name in include_headers:
            if name.lower() in exclude_headers:
                continue
            value = request.headers.get(name)
            if value is not None:
                headers[name] = value
        return {"_headers": headers}

    def make_record(self, request, response, elapsed):
        record = {
            "version": "1.1",
            "host": request.get_host(),
            "short_message": request.get_full_path(),
            "level": getattr(settings, "GRAYLOG_LEVEL", Severity.INFO),
            "_node": getattr(settings, "GRAYLOG_NODE", socket.gethostname()),
            "_status": response.status_code,
            "_method": request.method,
            "_path": request.path,
            "_content_type": response.get("content-type", "").split(";")[0],
        }
        if not response.streaming:
            record["_content_length"] = len(response.content)
        if self.facility:
            record["_facility"] = self.facility
        if getattr(settings, "GRAYLOG_TIMESTAMP", True):
            record["timestamp"] = time.time()
        if getattr(settings, "GRAYLOG_IP", True):
            record["_ip"] = get_ip(request)
        if hasattr(request, "_graylog_exception"):
            record.update(request._graylog_exception)
        if getattr(settings, "GRAYLOG_TIMING", True):
            record.update(
                {
                    "_elapsed": elapsed,
                    "_elapsed_ms": round(elapsed * 1000),
                }
            )
        if getattr(settings, "GRAYLOG_USERNAME", False) and hasattr(request, "user"):
            try:
                if request.user.is_authenticated:
                    record["_username"] = request.user.get_username()
            except Exception:
                pass
        if getattr(settings, "GRAYLOG_HEADERS", False):
            record.update(self.request_headers(request))
        if getattr(settings, "GRAYLOG_USER_AGENT", False) and has_ua_parser:
            record.update(self.parse_agent(request.headers.get("user-agent")))
        if getattr(settings, "GRAYLOG_REFERER", False):
            record.update(self.parse_referer(request.headers.get("referer")))
        graylog = getattr(request, "graylog", None)
        if graylog:
            record.update(graylog.additional_fields())
        return record
