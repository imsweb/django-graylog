import unittest

from django.test import Client, TestCase, override_settings


class GraylogMiddlewareTests(TestCase):
    def setUp(self):
        self.client = Client(raise_request_exception=False)

    def test_basics(self):
        r = self.client.get("/simple/")
        self.assertEqual(r.gelf["_status"], 200)
        self.assertEqual(r.gelf["_method"], "GET")
        self.assertEqual(r.gelf["_path"], "/simple/")
        self.assertEqual(r.gelf["_content_type"], "text/html")
        self.assertEqual(r.gelf["_content_length"], 13)

    def test_exception_message(self):
        r = self.client.get("/error/")
        errmsg = "An error occurred."
        self.assertEqual(r.gelf["_exception_class"], "ValueError")
        self.assertEqual(r.gelf["_exception_message"], errmsg)
        self.assertIn(errmsg, r.gelf["full_message"].splitlines()[-1])
        with self.settings(GRAYLOG_EXCEPTION_MESSAGES=False):
            r = self.client.get("/error/")
            self.assertEqual(r.gelf["_exception_class"], "ValueError")
            self.assertNotIn("_exception_message", r.gelf)
            self.assertNotIn(errmsg, r.gelf["full_message"].splitlines()[-1])

    def test_logging_handler(self):
        r = self.client.get("/log/")
        self.assertEqual(
            r.gelf["_logs"],
            [
                {
                    "name": "django-graylog",
                    "level": 6,
                    "message": "This message was logged with GraylogProxy.",
                },
                {
                    "name": "testapp.views",
                    "level": 7,
                    "message": "This message was logged with GraylogRequestHandler.",
                },
            ],
        )

    @override_settings(GRAYLOG_FILTERS={"path": r"^/simp", "method": r"POST|PUT"})
    def test_filters(self):
        # Check that URLs starting with "/simp" are not logged.
        r = self.client.get("/simple/")
        self.assertFalse(hasattr(r, "gelf"))
        # This one should be logged.
        r = self.client.get("/redirect/")
        self.assertEqual(r.gelf["_status"], 302)
        # Check that POST and PUT requests are not logged.
        r = self.client.post("/redirect/")
        self.assertFalse(hasattr(r, "gelf"))
        r = self.client.put("/redirect/")
        self.assertFalse(hasattr(r, "gelf"))
