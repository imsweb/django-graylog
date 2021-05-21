import unittest

import django
from django.test import Client, TestCase

has_exception_flag = django.VERSION[0] > 2


class GraylogMiddlewareTests(TestCase):
    def setUp(self):
        if has_exception_flag:
            self.client = Client(raise_request_exception=False)

    def test_basics(self):
        r = self.client.get("/simple/")
        self.assertEqual(r.gelf["_status"], 200)
        self.assertEqual(r.gelf["_method"], "GET")
        self.assertEqual(r.gelf["_path"], "/simple/")
        self.assertEqual(r.gelf["_content_type"], "text/html")
        self.assertEqual(r.gelf["_content_length"], 13)

    @unittest.skipUnless(has_exception_flag, "Django < 3.0 raises client exceptions.")
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
