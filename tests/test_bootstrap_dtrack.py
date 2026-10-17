"""Unit tests for scripts/bootstrap_dtrack.py against a fake DT API."""

import http.server
import importlib.util
import json
import os
import stat
import subprocess
import tempfile
import threading
import unittest
import unittest.mock


def _load():
    path = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "scripts", "bootstrap_dtrack.py",
    )
    spec = importlib.util.spec_from_file_location("bootstrap_dtrack", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


TEAM_UUID = "11111111-1111-1111-1111-111111111111"
API_KEY = "odt_ABCDEFGHijklmnopqrstuvwxyz0123456789"


class _FakeDtrack(http.server.BaseHTTPRequestHandler):
    """Dependency-Track 4.14 fresh-install behaviour for bootstrap."""

    state = None  # set per-test

    def log_message(self, fmt, *args):
        pass

    def _read_form(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length).decode() if length else ""
        out = {}
        for part in body.split("&"):
            if "=" in part:
                k, v = part.split("=", 1)
                out[k] = v
        return out

    def _send(self, code, body=b"", content_type="text/plain"):
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if body:
            self.wfile.write(body)

    def do_POST(self):
        st = type(self).state
        st["paths"].append(("POST", self.path))
        if self.path == "/api/v1/configProperty/aggregate":
            if not self.headers.get("Authorization", "").startswith("Bearer "):
                self._send(401, b"UNAUTHORIZED")
                return
            length = int(self.headers.get("Content-Length", 0))
            items = json.loads(self.rfile.read(length).decode())
            st["config_posts"].append(items)
            self._send(200, json.dumps(items).encode(), "application/json")
            return
        form = self._read_form()

        if self.path == "/api/v1/user/login":
            st["logins"].append(dict(form))
            password = form.get("password", "")
            if not st.get("password_changed") and password == st["old_password"]:
                self._send(401, b"FORCE_PASSWORD_CHANGE")
                return
            if st.get("password_changed") and password == st["new_password"]:
                self._send(200, b"eyJhbGciOiJIUzI1NiJ9.fake.token")
                return
            self._send(401, b"UNAUTHORIZED")
            return

        if self.path == "/api/v1/user/forceChangePassword":
            st["force_change"] = dict(form)
            # Copilot finding: password_out must already hold the new password.
            pw_path = st.get("password_out_path")
            if pw_path:
                st["password_file_before_change"] = (
                    os.path.isfile(pw_path)
                    and open(pw_path).read().splitlines() == [
                        "admin", form.get("newPassword", ""),
                    ]
                )
            if form.get("password") != st["old_password"]:
                self._send(401, b"UNAUTHORIZED")
                return
            st["password_changed"] = True
            st["new_password"] = form.get("newPassword", "")
            self._send(200, b"")
            return

        if self.path.startswith("/api/v1/permission/") and "/team/" in self.path:
            # /api/v1/permission/PROJECT_CREATION_UPLOAD/team/{uuid}
            st["permission_posts"].append(self.path)
            auth = self.headers.get("Authorization", "")
            if not auth.startswith("Bearer "):
                self._send(401, b"UNAUTHORIZED")
                return
            if "PROJECT_CREATION_UPLOAD" in self.path:
                if st.get("permission_already"):
                    self._send(304, b"")
                else:
                    st["permission_granted"] = True
                    team = {
                        "uuid": TEAM_UUID,
                        "name": "Automation",
                        "permissions": [
                            {"name": "BOM_UPLOAD"},
                            {"name": "VIEW_PORTFOLIO"},
                            {"name": "PROJECT_CREATION_UPLOAD"},
                        ],
                    }
                    self._send(200, json.dumps(team).encode(), "application/json")
                return
            self._send(404, b"")
            return

        self._send(404, b"not found")

    def do_GET(self):
        st = type(self).state
        st["paths"].append(("GET", self.path))
        auth = self.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            self._send(401, b"UNAUTHORIZED")
            return
        if self.path == "/api/v1/team":
            team = {
                "uuid": TEAM_UUID,
                "name": "Automation",
                "permissions": [
                    {"name": "BOM_UPLOAD"},
                    {"name": "VIEW_PORTFOLIO"},
                ],
            }
            if st.get("permission_granted"):
                team["permissions"].append({"name": "PROJECT_CREATION_UPLOAD"})
            self._send(200, json.dumps([team]).encode(), "application/json")
            return
        self._send(404, b"")

    def do_PUT(self):
        st = type(self).state
        st["paths"].append(("PUT", self.path))
        auth = self.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            self._send(401, b"UNAUTHORIZED")
            return
        if self.path == f"/api/v1/team/{TEAM_UUID}/key":
            st["key_created"] = True
            body = json.dumps({
                "publicId": API_KEY[4:12] if API_KEY.startswith("odt_") else API_KEY[:8],
                "key": API_KEY,
                "maskedKey": "odt_********",
            }).encode()
            self._send(201, body, "application/json")
            return
        self._send(404, b"")


class BootstrapDtrackTests(unittest.TestCase):
    def setUp(self):
        self._state = {
            "paths": [],
            "logins": [],
            "old_password": "admin",
            "new_password": None,
            "password_changed": False,
            "permission_posts": [],
            "permission_granted": False,
            "key_created": False,
            "config_posts": [],
        }
        _FakeDtrack.state = self._state
        self.server = http.server.HTTPServer(("127.0.0.1", 0), _FakeDtrack)
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.url = f"http://127.0.0.1:{self.port}"

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()

    def test_fresh_install_force_change_grants_permission_and_creates_key(self):
        mod = _load()
        with tempfile.TemporaryDirectory() as tmp:
            pw_out = os.path.join(tmp, "dtrack-admin.txt")
            key_out = os.path.join(tmp, "dtrack-api-key.txt")
            self._state["password_out_path"] = pw_out
            os.environ["DTRACK_ADMIN_PASSWORD"] = "admin"
            try:
                rc = mod.main([
                    "--url", self.url,
                    "--password-out", pw_out,
                    "--key-out", key_out,
                    "--no-aws",
                ])
            finally:
                os.environ.pop("DTRACK_ADMIN_PASSWORD", None)

            self.assertEqual(rc, 0)
            self.assertIsNotNone(self._state["force_change"])
            self.assertEqual(self._state["force_change"]["password"], "admin")
            self.assertTrue(self._state["force_change"]["newPassword"])
            self.assertEqual(
                self._state["force_change"]["newPassword"],
                self._state["force_change"]["confirmPassword"],
            )
            self.assertTrue(
                self._state.get("password_file_before_change"),
                "password_out must be written before forceChangePassword",
            )
            self.assertTrue(any(
                p.endswith(f"/permission/PROJECT_CREATION_UPLOAD/team/{TEAM_UUID}")
                for method, p in self._state["paths"] if method == "POST"
            ))
            self.assertTrue(self._state["key_created"])
            self.assertEqual(stat.S_IMODE(os.stat(pw_out).st_mode), 0o600)
            lines = open(pw_out).read().splitlines()
            self.assertEqual(lines[0], "admin")
            self.assertEqual(lines[1], self._state["new_password"])
            # Never leave the default password in the out file.
            self.assertNotEqual(lines[1], "admin")
            # Local / --no-aws path must persist the API key (never print it).
            self.assertEqual(stat.S_IMODE(os.stat(key_out).st_mode), 0o600)
            self.assertEqual(open(key_out).read().strip(), API_KEY)
            self._assert_cost_settings_posted()

    def _assert_cost_settings_posted(self):
        self.assertEqual(len(self._state["config_posts"]), 1)
        posted = {
            (i["groupName"], i["propertyName"]): i["propertyValue"]
            for i in self._state["config_posts"][0]
        }
        self.assertEqual(posted, {
            ("task-scheduler", "portfolio.metrics.update.cadence"): "24",
            ("task-scheduler", "vulnerability.metrics.update.cadence"): "24",
            ("vuln-source", "nvd.enabled"): "false",
            ("vuln-source", "nvd.api.enabled"): "false",
            ("vuln-source", "epss.enabled"): "false",
            ("scanner", "internal.enabled"): "false",
            ("scanner", "ossindex.enabled"): "false",
        })

    def test_settings_only_applies_settings_without_key_or_password_change(self):
        mod = _load()
        self._state["password_changed"] = True
        self._state["new_password"] = "already-rotated"
        with tempfile.TemporaryDirectory() as tmp:
            pw_out = os.path.join(tmp, "dtrack-admin.txt")
            key_out = os.path.join(tmp, "dtrack-api-key.txt")
            os.environ["DTRACK_ADMIN_PASSWORD"] = "already-rotated"
            try:
                rc = mod.main([
                    "--url", self.url,
                    "--password-out", pw_out,
                    "--key-out", key_out,
                    "--settings-only",
                ])
            finally:
                os.environ.pop("DTRACK_ADMIN_PASSWORD", None)

            self.assertEqual(rc, 0)
            self._assert_cost_settings_posted()
            self.assertFalse(self._state["key_created"])
            self.assertEqual(self._state["permission_posts"], [])
            self.assertFalse(os.path.exists(pw_out))
            self.assertFalse(os.path.exists(key_out))

    def test_settings_only_refuses_fresh_install(self):
        mod = _load()
        os.environ["DTRACK_ADMIN_PASSWORD"] = "admin"
        try:
            with self.assertRaises(RuntimeError) as ctx:
                mod.main(["--url", self.url, "--settings-only"])
        finally:
            os.environ.pop("DTRACK_ADMIN_PASSWORD", None)
        self.assertIn("full bootstrap", str(ctx.exception))
        self.assertNotIn("force_change", self._state)
        self.assertEqual(self._state["config_posts"], [])

    def test_put_secret_uses_file_uri_and_unlinks(self):
        """The API key must not appear on the aws argv; the temp file is gone after."""
        mod = _load()
        captured = {}

        def fake_run(cmd, capture_output=True, text=True, timeout=None):
            captured["cmd"] = list(cmd)
            captured["timeout"] = timeout
            uri = cmd[cmd.index("--secret-string") + 1]
            self.assertTrue(uri.startswith("file://"), uri)
            path = uri[len("file://"):]
            captured["path"] = path
            self.assertTrue(os.path.isfile(path))
            self.assertEqual(stat.S_IMODE(os.stat(path).st_mode), 0o600)
            self.assertEqual(open(path).read(), API_KEY)
            return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

        with unittest.mock.patch("subprocess.run", side_effect=fake_run):
            mod.put_secret("lde/dtrack-api-key", API_KEY, "us-east-1")

        cmd = captured["cmd"]
        self.assertEqual(captured["timeout"], 60)
        self.assertNotIn(API_KEY, cmd)
        self.assertTrue(any(
            arg.startswith("file://") for arg in cmd
        ))
        self.assertFalse(os.path.exists(captured["path"]))


if __name__ == "__main__":
    unittest.main()
