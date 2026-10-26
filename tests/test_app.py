import re
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from app import app


class FindXSmokeTests(unittest.TestCase):
    def setUp(self):
        app.config["TESTING"] = True
        self.client = app.test_client()

    def test_homepage(self):
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"/analyze", response.data)

    def test_health(self):
        response = self.client.get("/health")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["status"], "ok")

    def test_analyze_and_download(self):
        html = "<html><head><title>Example</title></head><body><h1>Welcome</h1><p>Example paragraph long enough for report</p><a href='/'>Home</a></body></html>"
        with patch("app.safe_get_html", return_value=SimpleNamespace(text=html)):
            response = self.client.post("/analyze", data={"url": "https://example.org"})
        self.assertEqual(response.status_code, 200)
        self.assertIn("Welcome", response.get_data(as_text=True))
        match = re.search(r"/download/(findx_[0-9a-f]{32}\.txt)", response.get_data(as_text=True))
        self.assertIsNotNone(match)
        download = self.client.get("/download/" + match.group(1))
        self.assertEqual(download.status_code, 200)
        self.assertIn("Welcome", download.get_data(as_text=True))
        self.assertIn("attachment", download.headers["Content-Disposition"])

    def test_private_target_rejected(self):
        response = self.client.post("/analyze", data={"url": "http://127.0.0.1"})
        self.assertEqual(response.status_code, 400)
        self.assertIn("forbidden", response.get_data(as_text=True).lower())

    def test_fake_download_blocked(self):
        self.assertEqual(self.client.get("/download/not-a-report.txt").status_code, 404)


if __name__ == "__main__":
    unittest.main()
