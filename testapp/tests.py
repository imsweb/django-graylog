from django.test import Client, TestCase


class GraylogMiddlewareTests(TestCase):
    def setUp(self):
        self.client = Client(raise_request_exception=False)

    def test_basics(self):
        r = self.client.get("/simple/")
        self.assertEqual(r.gelf["_status"], 200)

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
