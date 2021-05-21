# django-graylog

A Django middleware for logging requests to [Graylog](https://www.graylog.org).


## Installation

`pip install django-graylog`

Using an HTTP/HTTPS requires the [requests](https://requests.readthedocs.io/en/master/)
module, which can be included with `pip install django-graylog[http]`.

Parsing user agents requires the [ua_parser](https://github.com/ua-parser/uap-python)
module, which can be included with `pip install django-graylog[ua]`.

All optional libraries may be included using `pip install django-graylog[all]`.


## Configuration

Simply add `django_graylog.GraylogMiddleware` to your `MIDDLEWARE` setting, after
`django.middleware.common.CommonMiddleware`. By default, the middleware does nothing
unless `GRAYLOG_ENDPOINT` is set (see below).


### Settings

* `GRAYLOG_ENDPOINT` - An HTTP, HTTPS, UDP, or TCP endpoint to send GELF logs to. For
  example:
    - `http://yourserver:12201/gelf`
    - `udp://yourserver:12201`
    - `tcp://yourserver:12201`
* `GRAYLOG_NODE` - The middleware sends a `_node` field that defaults to
  `socket.gethostname`. Set this to override it.
* `GRAYLOG_LEVEL` - The default `level` to send for log entries. Defaults to 6 (INFO).
* `GRAYLOG_TIMEOUT` - Timeout (in seconds) for sending log entries to Graylog. Defaults
  to `0.25` seconds.
* `GRAYLOG_FIELDS` - Extra fields to send for each request (not prefixed with
  underscores). Defaults to `{}`.
* `GRAYLOG_HEADERS` - `True` to include all HTTP request headers (except sensitive
  headers like `Authorization` and `Cookie` - see below), otherwise a list of headers to
  be included. Defaults to `[]`.
* `GRAYLOG_EXCLUDE_HEADERS` - A list of headers to exclude when `GRAYLOG_HEADERS` is
  `True`. Defaults to `["authorization", "cookie", "proxy-authorization"]`.
* `GRAYLOG_USER_AGENT` - `True` to parse out User-Agent header into separate fields
  using [ua_parser](https://github.com/ua-parser/uap-python) (default is `False`).
* `GRAYLOG_REFERER` - `True` to parse out the referer domain (default is `False`) into a
  separate field.
* `GRAYLOG_USERNAME` - `True` to include `request.user.get_username()` (default is
  `False`).
* `GRAYLOG_TIMING` - `True` to include request timing information (the default), `False`
  to disable.
* `GRAYLOG_FILTERS` - A dictionary of filters to exclude records from being logged. Each
  key is a field name, and each value is a list of regegular expressions to exclude. For
  example:
    - `{"host": [r"media.example.com"]}` - Skips logging of requests to the
      `media.example.com` domain.
    - `{"path": [r"^/_"]}` - Skips logging of requests to paths starting with `_`.
    - `{"ip": "192\.168\."}` - Skips logging of requests from `192.168.*` addresses.
      Using a string instead of a list works for a single regular expression.
* `GRAYLOG_EXCEPTION_MESSAGES` - Whether to include exception messages in data sent to
  Graylog. Setting to `False` will strip the last line from stack traces (in case the
  line includes a literal message), and not send the `_exception_message` field.
  Defaults to `True`.
* `GRAYLOG_FACILITY` - Sent as `_facility`, and used as the default logger name for
  logging messages sent via `request.graylog`.
* `GRAYLOG_TIMESTAMP` - Whether to include a `timestamp` field in data sent to Graylog.
  Setting to `False` means Graylog will infer the current time when it receives log
  entries. Defaults to `True`.
* `GRAYLOG_IP` - Whether to include the IP address of requests. Defaults to `True`.


## Advanced Usage

In addition to the standard logging middleware, `django_graylog` installs an object on
your request objects (`request.graylog`) that has standard logging methods for recording
per-request logs. You may also set custom keys on this object
(`request.graylog["key"] = "value"`) that will be included in log entries. For example:

```python
def homepage(request):
    request.graylog["user"] = request.user.user_name
    request.graylog.info("Rendered homepage for {user}", user=request.user.user_name)
```

If you want standard Python logging calls during a request to be logged into Graylog as
well, `django_graylog` comes with a `GraylogRequestHandler` logging handler that tracks
the current request and associates logging to it.
