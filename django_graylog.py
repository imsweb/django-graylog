import enum
import gzip
import json
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

__version__ = "0.5.0"
__version_info__ = tuple(int(num) for num in __version__.split("."))


class Severity(enum.IntEnum):
    EMERGENCY = 0
    ALERT = 1
    CRITICAL = 2
    ERROR = 3
    WARNING = 4
    NOTICE = 5
    INFO = 6
    DEBUG = 7


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


class GraylogProxy:
    def __init__(self):
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
        self.logs.append({"message": message.format(*args, **kwargs), "level": level})

    def debug(self, message, *args, **kwargs):
        self.log(Severity.DEBUG, message, *args, **kwargs)

    def info(self, message, *args, **kwargs):
        self.log(Severity.INFO, message, *args, **kwargs)

    def warning(self, message, *args, **kwargs):
        self.log(Severity.WARNING, message, *args, **kwargs)

    def error(self, message, *args, **kwargs):
        self.log(Severity.ERROR, message, *args, **kwargs)

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
        self.timeout = getattr(settings, "GRAYLOG_TIMEOUT", 0.25)
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
        self.timeout = getattr(settings, "GRAYLOG_TIMEOUT", 0.25)
        self.delim = getattr(settings, "GRAYLOG_TCP_DELIMITER", b"\x00")

    def send(self, record):
        # Graylog over TCP does not support compression.
        payload = json.dumps(record).encode("utf-8")
        # TODO: have an option to keep a socket open and reconnect as needed?
        with socket.create_connection(self.address, timeout=self.timeout) as sock:
            sock.sendall(payload)


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
    }

    def __init__(self, get_response):
        self.endpoint = getattr(settings, "GRAYLOG_ENDPOINT", "")
        self.filters = compile_filters(getattr(settings, "GRAYLOG_FILTERS", {}))
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
        setattr(request, "graylog", GraylogProxy())
        response = self.get_response(request)
        elapsed = time.time() - start
        try:
            record = self.make_record(request, response, elapsed)
            if self.filter(record):
                self.transport.send(record)
        except Exception:
            if getattr(settings, "DEBUG", False):
                raise
        return response

    def process_exception(self, request, exception):
        tb = "".join(traceback.format_tb(exception.__traceback__))
        setattr(request, "_graylog_traceback", textwrap.dedent(tb))

    def filter(self, record):
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
        if ua["device"]["family"] == "Spider" or (
            (ua["user_agent"]["family"] == "Other")
            and (ua["os"]["family"] == "Other")
            and (ua["device"]["family"] == "Other")
        ):
            return {}
        return {
            "_browser": ua["user_agent"]["family"],
            "_browser_version": ua["user_agent"]["major"],
            "_os": ua["os"]["family"],
            "_os_version": ua["os"]["major"],
        }

    def parse_referer(self, referer):
        if not referer:
            return {}
        try:
            domain = urllib.parse.urlparse(referer).netloc
            return {"_referer": domain} if domain else {}
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
            include_headers = list(sorted(request.headers.keys()))
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
            # "timestamp": time.time(),
            "level": getattr(settings, "GRAYLOG_LEVEL", Severity.INFO),
            "_facility": "django-graylog",
            "_node": getattr(settings, "GRAYLOG_NODE", socket.gethostname()),
            "_status": response.status_code,
            "_method": request.method,
            "_ip": get_ip(request),
            "_path": request.path,
        }
        if hasattr(request, "_graylog_traceback"):
            record["full_message"] = request._graylog_traceback
        if getattr(settings, "GRAYLOG_TIMING", True):
            record.update(
                {
                    "_elapsed": str(elapsed),
                    "_elapsed_ms": round(elapsed * 1000),
                }
            )
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
