# django-graylog

A Django middleware for logging requests to [Graylog](https://www.graylog.org).


## Installation

`pip install django-graylog`


## Configuration

Simply add `django_graylog.GraylogMiddleware` to your `MIDDLEWARE` setting, after
`django.middleware.common.CommonMiddleware`. By default, the middleware does nothing unless `GRAYLOG_ENDPOINT` is set
(see below).


### Settings

* `GRAYLOG_ENDPOINT` - An HTTP/HTTPS endpoint to send GELF logs to. For example, `http://yourserver:12201/gelf`.
* `GRAYLOG_NODE` - The middleware sends a `_node` field that defaults to `socket.gethostname`. Set this to override it.
* `GRAYLOG_LEVEL` - The default `level` to send for log entries. Defaults to 6 (INFO).
* `GRAYLOG_TIMEOUT` - Timeout for sending log entries to Graylog. Defaults to `0.25` seconds.
* `GRAYLOG_FIELDS` - Extra fields to send for each request (not prefixed with underscores). Defaults to `{}`.


## Advanced Usage

In addition to the standard logging middleware, `django_graylog` installs an object on your request objects
(`request.graylog`) that has standard logging methods for recording per-request logs. You may also set custom keys on
this object (`request.graylog["key"] = "value"`) that will be included in log entries. For example:

```python
def homepage(request):
    request.graylog["user"] = request.user.user_name
    request.graylog.info("Rendered the homepage for {user}", user=request.user.user_name)
```
