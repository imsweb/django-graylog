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

* `GRAYLOG_ENDPOINT` - An HTTP/HTTPS/UDP endpoint to send GELF logs to. For example,
  `http://yourserver:12201/gelf` or `udp://yourserver:12201`.
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
* `GRAYLOG_TIMING` - `True` to include request timing information (the default), `False`
  to disable.


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
