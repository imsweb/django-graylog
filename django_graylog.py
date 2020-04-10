import enum
import gzip
import json
import os
import re
import socket
import struct
import time
import urllib.parse

import requests

from django.conf import settings
from django.core.exceptions import MiddlewareNotUsed
from ua_parser import user_agent_parser

__version__ = "0.3.0"
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
            raise KeyError("Invalid key ({}). Keys will automatically be prefixed with an underscore.".format(name))
        if not GELF_FIELD_REGEX.match(name):
            raise KeyError("Invalid key ({}). Keys must match [\\w\\.\\-]+.".format(name))
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
        chunks = [data[pos : pos + chunk_size] for pos in range(0, len(data), chunk_size)]
        chunk_count = len(chunks)
        for chunk_index, chunk in enumerate(chunks):
            yield b"".join((b"\x1e\x0f", message_id, struct.pack("!BB", chunk_index, chunk_count), chunk))

    def send(self, record):
        compressed = gzip.compress(json.dumps(record).encode("utf-8"))
        if len(compressed) > self.mtu:
            for chunk in self.chunked(compressed):
                self.socket.sendto(chunk, self.address)
        else:
            self.socket.sendto(compressed, self.address)


class GraylogMiddleware:
    scheme_transports = {
        "http": RequestsTransport,
        "https": RequestsTransport,
        "udp": UDPTransport,
    }

    def __init__(self, get_response):
        self.endpoint = getattr(settings, "GRAYLOG_ENDPOINT", "")
        if not self.endpoint:
            raise MiddlewareNotUsed()
        scheme = urllib.parse.urlparse(self.endpoint).scheme
        self.transport = self.scheme_transports[scheme](self.endpoint)
        self.get_response = get_response

    def __call__(self, request):
        start = time.time()
        setattr(request, "graylog", GraylogProxy())
        response = self.get_response(request)
        elapsed = time.time() - start
        record = self.make_record(request, response, elapsed)
        if self.filter(record):
            self.transport.send(record)
        return response

    def filter(self, record):
        return not record["_path"].startswith("/_")

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

    def make_record(self, request, response, elapsed):
        record = {
            "version": "1.1",
            "host": request.get_host(),
            "short_message": request.get_full_path(),
            # "full_message": "Backtrace here\n\nmore stuff",
            # "timestamp": time.time(),
            "level": getattr(settings, "GRAYLOG_LEVEL", Severity.INFO),
            "_facility": "django-graylog",
            "_node": getattr(settings, "GRAYLOG_NODE", socket.gethostname()),
            "_status": response.status_code,
            "_method": request.method,
            "_ip": get_ip(request),
            "_elapsed": str(elapsed),
            "_elapsed_ms": round(elapsed * 1000),
            "_path": request.path,
            "_headers": {key: value for key, value in request.headers.items() if key.lower() != "cookie"},
        }
        graylog = getattr(request, "graylog", None)
        if graylog:
            record.update(graylog.additional_fields())
        record.update(self.parse_agent(request.headers.get("user-agent")))
        record.update(self.parse_referer(request.headers.get("referer")))
        return record
