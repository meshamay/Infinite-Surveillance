import http.cookiejar
import json
import tempfile
import threading
import unittest
import uuid
from http.server import ThreadingHTTPServer
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import HTTPCookieProcessor, Request, build_opener

import portal_backend
from server import PortalHandler


class PortalBackendIntegrationTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp_dir = tempfile.TemporaryDirectory()
        portal_backend.DATA_DIR = Path(cls.temp_dir.name)
        portal_backend.DB_PATH = portal_backend.DATA_DIR / "test.sqlite3"
        portal_backend.UPLOAD_DIR = portal_backend.DATA_DIR / "uploads"
        portal_backend.initialize()
        cls.httpd = ThreadingHTTPServer(("127.0.0.1", 0), PortalHandler)
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()
        cls.base_url = "http://127.0.0.1:" + str(cls.httpd.server_port)

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()
        cls.thread.join(timeout=3)
        cls.temp_dir.cleanup()

    def opener(self):
        return build_opener(HTTPCookieProcessor(http.cookiejar.CookieJar()))

    def request(self, opener, path, body=None, method=None, headers=None, expected=200):
        data = body
        request_headers = dict(headers or {})
        if isinstance(body, dict):
            data = json.dumps(body).encode()
            request_headers.setdefault("Content-Type", "application/json")
        request = Request(self.base_url + path, data=data, headers=request_headers, method=method)
        try:
            with opener.open(request, timeout=5) as response:
                status = response.status
                payload = response.read()
                content_type = response.headers.get("Content-Type", "")
        except HTTPError as error:
            status = error.code
            payload = error.read()
            content_type = error.headers.get("Content-Type", "")
        self.assertEqual(status, expected)
        return json.loads(payload) if "application/json" in content_type else payload

    def test_admin_employee_storage_and_protected_report(self):
        anonymous = self.opener()
        status = self.request(anonymous, "/api/portal/status")
        self.assertTrue(status["setupRequired"])

        admin = self.opener()
        setup = self.request(admin, "/api/portal/setup", {
            "name": "Test Admin",
            "email": "owner@example.test",
            "password": "A-long-test-password-42",
        }, method="POST")
        self.assertEqual(setup["user"]["role"], "admin")
        self.request(self.opener(), "/api/portal/setup", {
            "name": "Unexpected Admin",
            "email": "other@example.test",
            "password": "Another-test-password-42",
        }, method="POST", expected=409)
        self.request(anonymous, "/server.py", expected=404)

        created = self.request(admin, "/api/portal/staff", {
            "name": "Test Employee",
            "role": "Technician",
            "email": "worker@example.test",
            "salary": 28000,
        }, method="POST", expected=201)
        employee_id = created["staff"]["id"]
        temporary_password = created["temporaryPassword"]
        self.assertGreaterEqual(len(temporary_password), 12)

        self.request(admin, "/api/portal/payroll", {
            "staffId": employee_id, "period": "2026-10", "amount": 28000, "status": "Pending"
        }, method="POST", expected=201)
        self.request(admin, "/api/portal/expenses", {
            "staffId": employee_id, "category": "Transport", "description": "Site visit", "amount": 350
        }, method="POST", expected=201)
        self.request(admin, "/api/portal/schedules", {
            "staffId": employee_id, "date": "2026-10-09", "start": "08:00", "end": "17:00", "site": "Customer site"
        }, method="POST", expected=201)
        self.request(admin, "/api/portal/tasks", {
            "staffId": employee_id, "date": "2026-10-09", "title": "Inspect cameras", "details": "Check views"
        }, method="POST", expected=201)

        employee = self.opener()
        self.request(employee, "/api/portal/login", {
            "email": "worker@example.test", "password": temporary_password
        }, method="POST")
        employee_data = self.request(employee, "/api/portal/data")
        self.assertEqual([person["id"] for person in employee_data["staff"]], [employee_id])
        self.assertEqual(len(employee_data["payroll"]), 1)
        self.assertEqual(employee_data["tasks"][0]["title"], "Inspect cameras")
        self.request(employee, "/api/portal/staff", {
            "name": "Not Allowed", "role": "Admin", "email": "bad@example.test", "salary": 0
        }, method="POST", expected=403)

        self.request(employee, "/api/portal/time/clock", {"action": "in"}, method="POST")
        self.request(employee, "/api/portal/time/clock", {"action": "out"}, method="POST")
        boundary = "----portal-test-" + uuid.uuid4().hex
        png = b"\x89PNG\r\n\x1a\nexample"
        fields = [("date", "2026-10-08"), ("site", "Customer site"), ("task", "Camera inspection"),
                  ("work", "Inspected four cameras"), ("next", "Return for testing")]
        chunks = []
        for name, value in fields:
            chunks.append(("--" + boundary + "\r\nContent-Disposition: form-data; name=\"" + name + "\"\r\n\r\n" + value + "\r\n").encode())
        chunks.append(("--" + boundary + "\r\nContent-Disposition: form-data; name=\"media\"; filename=\"check.png\"\r\nContent-Type: image/png\r\n\r\n").encode() + png + b"\r\n")
        chunks.append(("--" + boundary + "--\r\n").encode())
        report = self.request(employee, "/api/portal/reports", b"".join(chunks), method="POST", headers={"Content-Type": "multipart/form-data; boundary=" + boundary}, expected=201)
        employee_data = self.request(employee, "/api/portal/data")
        entry = employee_data["timeEntries"][0]
        self.assertTrue(entry["timeIn"])
        self.assertTrue(entry["timeOut"])
        self.assertEqual(employee_data["reports"][0]["id"], report["id"])
        file_url = employee_data["reports"][0]["files"][0]["url"]
        self.assertEqual(self.request(employee, file_url), png)

        restored_admin = self.opener()
        self.request(restored_admin, "/api/portal/login", {
            "email": "owner@example.test", "password": "A-long-test-password-42"
        }, method="POST")
        admin_data = self.request(restored_admin, "/api/portal/data")
        self.assertEqual(len(admin_data["staff"]), 1)
        self.assertEqual(len(admin_data["timeEntries"]), 1)
        self.assertEqual(admin_data["reports"][0]["files"][0]["name"], "check.png")


if __name__ == "__main__":
    unittest.main()