"""Unit tests for scripts/start_fresh.py against a fake DT API."""

import contextlib
import http.server
import importlib.util
import io
import json
import os
import sqlite3
import stat
import tempfile
import threading
import unittest
import urllib.parse
from unittest import mock


def _load():
    path = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "scripts", "start_fresh.py",
    )
    spec = importlib.util.spec_from_file_location("start_fresh", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


sf = _load()

PASSWORD = "S3cretAdminPassw0rdForTestsOnly!"
TOKEN = "eyJhbGciOiJIUzI1NiJ9.fake.sessiontoken"


class _FakeDtrack(http.server.BaseHTTPRequestHandler):
    """Dependency-Track 4.14 login, project listing and project deletion."""

    state = None  # set per-test

    def log_message(self, fmt, *args):
        pass

    def _send(self, code, body=b"", content_type="text/plain"):
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if body:
            self.wfile.write(body)

    def _authed(self):
        return self.headers.get("Authorization", "") == f"Bearer {TOKEN}"

    def do_POST(self):
        st = type(self).state
        length = int(self.headers.get("Content-Length", 0))
        form = dict(urllib.parse.parse_qsl(self.rfile.read(length).decode()))
        if self.path == "/api/v1/user/login":
            password = form.get("password")
            if st.get("factory") and password == "admin":
                self._send(401, b"FORCE_PASSWORD_CHANGE")
                return
            if not st.get("factory") and password == st["password"]:
                self._send(200, TOKEN.encode())
                return
            self._send(401, b"INVALID_CREDENTIALS")
            return
        self._send(404)

    def do_GET(self):
        st = type(self).state
        if self.path == "/api/version":
            self._send(200, b"{}", "application/json")
            return
        if not self._authed():
            self._send(401, b"UNAUTHORIZED")
            return
        if self.path.startswith("/api/v1/project?"):
            query = dict(p.split("=", 1) for p in self.path.split("?", 1)[1].split("&"))
            size, page = int(query["pageSize"]), int(query["pageNumber"])
            projects = list(st["projects"].values())
            batch = projects[(page - 1) * size: page * size]
            self._send(200, json.dumps(batch).encode(), "application/json")
            return
        self._send(404)

    def do_DELETE(self):
        st = type(self).state
        st["deletes"].append(self.path)
        if not self._authed():
            self._send(401, b"UNAUTHORIZED")
            return
        uuid = self.path.rsplit("/", 1)[-1]
        if uuid not in st["projects"]:
            self._send(404)
            return
        # Deleting a parent removes its children, like DT does.
        for child, proj in list(st["projects"].items()):
            if (proj.get("parent") or {}).get("uuid") == uuid:
                del st["projects"][child]
        del st["projects"][uuid]
        self._send(204)


def _project(uuid, name, parent=None):
    p = {"uuid": uuid, "name": name, "version": "main"}
    if parent:
        p["parent"] = {"uuid": parent}
    return p


class _Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        _FakeDtrack.state = {
            "password": PASSWORD, "projects": {}, "deletes": [], "factory": False,
        }
        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _FakeDtrack)
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"
        thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)

        self.data_dir = os.path.join(self.tmp.name, "data")
        os.makedirs(os.path.join(self.data_dir, "runs", "abc123"))
        conn = sqlite3.connect(os.path.join(self.data_dir, "depexplorer.db"))
        conn.execute("CREATE TABLE runs (id TEXT)")
        conn.execute("CREATE TABLE run_repos (id TEXT)")
        conn.executemany("INSERT INTO runs VALUES (?)", [("r1",), ("r2",)])
        conn.execute("INSERT INTO run_repos VALUES ('x')")
        conn.commit()
        conn.close()
        self.backup_root = os.path.join(self.tmp.name, "backups")
        self.pw_file = os.path.join(self.tmp.name, "dtrack-admin.txt")
        with open(self.pw_file, "w") as fh:
            fh.write(f"admin\n{PASSWORD}\n")

    def _run_main(self, *extra, yes=True, confirm=None):
        """Run main() with docker, the port and the LDE process stubbed out."""
        out = io.StringIO()
        argv = [
            "--dtrack-url", self.url,
            "--dtrack-password-file", self.pw_file,
            "--backup-root", self.backup_root, *extra,
        ]
        if yes:
            argv = ["--yes", *argv]
        with contextlib.ExitStack() as stack:
            stack.enter_context(mock.patch.object(sf, "docker_ready", return_value=True))
            stack.enter_context(mock.patch.object(sf, "ensure_docker"))
            self.ensure_dtrack = stack.enter_context(mock.patch.object(sf, "ensure_dtrack"))
            stack.enter_context(mock.patch.object(sf, "port_listeners", return_value=[]))
            proc = mock.Mock()
            proc.wait.return_value = 0
            self.start = stack.enter_context(mock.patch.object(sf, "start_lde", return_value=proc))
            stack.enter_context(mock.patch.object(sf, "check_lde", return_value=[]))
            stack.enter_context(mock.patch.object(sf.lde_db, "DATA_DIR", self.data_dir))
            stack.enter_context(mock.patch.object(
                sf, "SETTINGS_PATH", os.path.join(self.tmp.name, ".settings.json")))
            stack.enter_context(mock.patch.object(
                sf, "API_KEY_PATH", os.path.join(self.tmp.name, "dtrack-api-key.txt")))
            if confirm is not None:
                stack.enter_context(mock.patch.object(sf, "confirm", return_value=confirm))
            stack.enter_context(contextlib.redirect_stdout(out))
            stack.enter_context(contextlib.redirect_stderr(out))
            try:
                code = sf.main(argv)
            except RuntimeError as exc:
                print(f"start_fresh: {exc}", file=out)
                code = 1
        return code, out.getvalue()


class TestFullRun(_Base):
    def test_clears_lde_and_dtrack(self):
        _FakeDtrack.state["projects"] = {
            "u1": _project("u1", "org/a"),
            "u2": _project("u2", "org/b"),
        }
        code, out = self._run_main()
        self.assertEqual(code, 0, out)
        self.assertEqual(_FakeDtrack.state["projects"], {})
        self.assertIn("2 run(s), 1 repo result(s)", out)
        self.start.assert_called_once()
        self.ensure_dtrack.assert_called_once()

    def test_starts_dtrack_then_deletes_when_api_was_down(self):
        _FakeDtrack.state["projects"] = {"u1": _project("u1", "org/a")}
        with mock.patch.object(sf, "dtrack_ready", return_value=False):
            code, out = self._run_main()
        self.assertEqual(code, 0, out)
        self.assertIn("count unknown until then", out)
        self.ensure_dtrack.assert_called_once()
        self.assertEqual(_FakeDtrack.state["projects"], {})

    def test_declined_confirm_does_not_start_dtrack(self):
        _FakeDtrack.state["projects"] = {"u1": _project("u1", "org/a")}
        code, out = self._run_main(yes=False, confirm=False)
        self.assertEqual(code, 1, out)
        self.assertIn("Aborted. Nothing was changed.", out)
        self.ensure_dtrack.assert_not_called()
        self.start.assert_not_called()
        self.assertEqual(_FakeDtrack.state["deletes"], [])
        self.assertTrue(os.path.exists(os.path.join(self.data_dir, "depexplorer.db")))

    def test_deletes_lde_state_by_default(self):
        code, out = self._run_main()
        self.assertEqual(code, 0, out)
        self.assertIn("permanently delete LDE data", out)
        self.assertFalse(os.path.exists(os.path.join(self.data_dir, "depexplorer.db")))
        self.assertFalse(os.path.exists(os.path.join(self.data_dir, "runs")))
        self.assertFalse(os.path.exists(self.backup_root))

    def test_backup_moves_lde_state(self):
        code, out = self._run_main("--backup")
        self.assertEqual(code, 0, out)
        self.assertFalse(os.path.exists(os.path.join(self.data_dir, "depexplorer.db")))
        self.assertFalse(os.path.exists(os.path.join(self.data_dir, "runs")))
        [backup] = os.listdir(self.backup_root)
        dest = os.path.join(self.backup_root, backup)
        self.assertTrue(backup.startswith("lde-local-"))
        self.assertTrue(os.path.exists(os.path.join(dest, "depexplorer.db")))
        self.assertTrue(os.path.isdir(os.path.join(dest, "runs", "abc123")))
        self.assertEqual(stat.S_IMODE(os.stat(dest).st_mode), 0o700)

    def test_output_has_no_secrets(self):
        _FakeDtrack.state["projects"] = {"u1": _project("u1", "org/a")}
        code, out = self._run_main()
        self.assertEqual(code, 0, out)
        self.assertNotIn(PASSWORD, out)
        self.assertNotIn(TOKEN, out)

    def test_keep_data_touches_nothing(self):
        _FakeDtrack.state["projects"] = {"u1": _project("u1", "org/a")}
        code, out = self._run_main("--keep-data")
        self.assertEqual(code, 0, out)
        self.assertIn("u1", _FakeDtrack.state["projects"])
        self.assertEqual(_FakeDtrack.state["deletes"], [])
        self.assertTrue(os.path.exists(os.path.join(self.data_dir, "depexplorer.db")))

    def test_keep_dtrack_clears_only_lde(self):
        _FakeDtrack.state["projects"] = {"u1": _project("u1", "org/a")}
        os.remove(self.pw_file)  # login is not needed, so a missing file is fine
        code, out = self._run_main("--keep-dtrack")
        self.assertEqual(code, 0, out)
        self.assertIn("u1", _FakeDtrack.state["projects"])
        self.assertFalse(os.path.exists(os.path.join(self.data_dir, "depexplorer.db")))


class TestDeleteLdeState(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.data_dir = os.path.join(self.tmp.name, "data")
        os.makedirs(self.data_dir)

    def test_refuses_name_not_in_allowlist(self):
        path = os.path.join(self.data_dir, ".settings.json")
        open(path, "w").close()
        with self.assertRaises(RuntimeError):
            sf.delete_lde_state([path], self.data_dir)
        self.assertTrue(os.path.exists(path))

    def test_refuses_path_outside_data_dir(self):
        other = os.path.join(self.tmp.name, "elsewhere")
        os.makedirs(os.path.join(other, "runs"))
        with self.assertRaises(RuntimeError):
            sf.delete_lde_state([os.path.join(other, "runs")], self.data_dir)
        self.assertTrue(os.path.isdir(os.path.join(other, "runs")))

    def test_refuses_symlinked_runs(self):
        target = os.path.join(self.tmp.name, "precious")
        os.makedirs(target)
        open(os.path.join(target, "keep.txt"), "w").close()
        link = os.path.join(self.data_dir, "runs")
        os.symlink(target, link)
        with self.assertRaises(RuntimeError):
            sf.delete_lde_state([link], self.data_dir)
        self.assertTrue(os.path.exists(os.path.join(target, "keep.txt")))

    def test_checks_all_paths_before_deleting_any(self):
        db = os.path.join(self.data_dir, "depexplorer.db")
        open(db, "w").close()
        bad = os.path.join(self.data_dir, "notes.txt")
        open(bad, "w").close()
        with self.assertRaises(RuntimeError):
            sf.delete_lde_state([db, bad], self.data_dir)
        self.assertTrue(os.path.exists(db))


class TestLoginFailure(_Base):
    def test_mismatch_aborts_before_changing_anything(self):
        _FakeDtrack.state["projects"] = {"u1": _project("u1", "org/a")}
        _FakeDtrack.state["password"] = "something-else"
        code, out = self._run_main()
        self.assertEqual(code, 1)
        self.assertIn("INVALID_CREDENTIALS", out)
        self.assertIn("already bootstrapped, not factory", out)
        self.assertNotIn("already changed", out.lower())
        self.assertNotIn("never bootstrapped", out)
        self.assertIn("Nothing was changed", out)
        self.assertEqual(_FakeDtrack.state["deletes"], [])
        self.assertTrue(os.path.exists(os.path.join(self.data_dir, "depexplorer.db")))
        self.assertFalse(os.path.exists(self.backup_root))
        self.start.assert_not_called()
        self.ensure_dtrack.assert_not_called()
        self.assertNotIn(PASSWORD, out)

    def test_factory_with_stale_password_file(self):
        _FakeDtrack.state["factory"] = True
        _FakeDtrack.state["projects"] = {"u1": _project("u1", "org/a")}
        code, out = self._run_main()
        self.assertEqual(code, 1, out)
        self.assertIn("factory / never bootstrapped", out)
        self.assertIn("FORCE_PASSWORD_CHANGE", out)
        self.assertIn("bootstrap_dtrack.py", out)
        self.assertIn("--password-out", out)
        self.assertIn("dtrack-admin.local.txt", out)
        self.assertNotIn("admin login failed", out)
        self.assertNotIn("already changed", out.lower())
        self.assertEqual(_FakeDtrack.state["deletes"], [])
        self.assertTrue(os.path.exists(os.path.join(self.data_dir, "depexplorer.db")))
        self.start.assert_not_called()
        self.ensure_dtrack.assert_not_called()
        self.assertNotIn(PASSWORD, out)

    def test_missing_password_file_when_api_down(self):
        os.remove(self.pw_file)
        with mock.patch.object(sf, "dtrack_ready", return_value=False):
            code, out = self._run_main()
        self.assertEqual(code, 1, out)
        self.assertIn("factory / never bootstrapped", out)
        self.assertIn("bootstrap_dtrack.py", out)
        self.assertIn("dtrack-admin.local.txt", out)
        self.start.assert_not_called()
        self.ensure_dtrack.assert_not_called()

    def test_factory_without_password_file(self):
        _FakeDtrack.state["factory"] = True
        os.remove(self.pw_file)
        code, out = self._run_main()
        self.assertEqual(code, 1, out)
        self.assertIn("factory / never bootstrapped", out)
        self.assertIn("DTRACK_ADMIN_PASSWORD=admin", out)
        self.assertIn("--no-aws", out)
        self.start.assert_not_called()
        self.ensure_dtrack.assert_not_called()

    def test_matching_password_still_clears(self):
        _FakeDtrack.state["projects"] = {"u1": _project("u1", "org/a")}
        code, out = self._run_main()
        self.assertEqual(code, 0, out)
        self.assertEqual(_FakeDtrack.state["projects"], {})
        self.start.assert_called_once()

    def test_wires_api_key_when_settings_key_empty(self):
        settings = os.path.join(self.tmp.name, ".settings.json")
        key_path = os.path.join(self.tmp.name, "dtrack-api-key.txt")
        with open(settings, "w") as fh:
            json.dump({"dtrack_url": "http://127.0.0.1:8081", "dtrack_api_key": ""}, fh)
        with open(key_path, "w") as fh:
            fh.write("odt_fromFileNotPrinted\n")
        with mock.patch.object(sf, "SETTINGS_PATH", settings), \
             mock.patch.object(sf, "API_KEY_PATH", key_path):
            code, out = self._run_main()
        self.assertEqual(code, 0, out)
        wired = json.load(open(settings))
        self.assertEqual(wired["dtrack_api_key"], "odt_fromFileNotPrinted")
        self.assertIn("wired dtrack_api_key", out)
        self.assertNotIn("odt_fromFileNotPrinted", out)

    def test_does_not_overwrite_existing_settings_key(self):
        settings = os.path.join(self.tmp.name, ".settings.json")
        key_path = os.path.join(self.tmp.name, "dtrack-api-key.txt")
        with open(settings, "w") as fh:
            json.dump({"dtrack_api_key": "odt_alreadyInSettings"}, fh)
        with open(key_path, "w") as fh:
            fh.write("odt_fromFile\n")
        with mock.patch.object(sf, "SETTINGS_PATH", settings), \
             mock.patch.object(sf, "API_KEY_PATH", key_path):
            code, out = self._run_main()
        self.assertEqual(code, 0, out)
        self.assertEqual(json.load(open(settings))["dtrack_api_key"], "odt_alreadyInSettings")
        self.assertNotIn("wired dtrack_api_key", out)


class TestDtrackProjects(_Base):
    def test_paginates_and_tolerates_child_404(self):
        projects = {f"u{i}": _project(f"u{i}", f"org/p{i}") for i in range(5)}
        projects["child"] = _project("child", "org/child", parent="u0")
        _FakeDtrack.state["projects"] = projects
        with mock.patch.object(sf, "PAGE_SIZE", 2), contextlib.redirect_stdout(io.StringIO()):
            listed = sf.list_projects(self.url, TOKEN)
            self.assertEqual(len(listed), 6)
            sf.delete_projects(self.url, TOKEN, listed)  # child is gone once u0 is deleted
        self.assertEqual(_FakeDtrack.state["projects"], {})
        self.assertEqual(len(_FakeDtrack.state["deletes"]), 6)


class TestPortOwner(unittest.TestCase):
    repo = sf.SERVE_DIR

    def test_relative_server_py_in_repo(self):
        self.assertTrue(sf.is_lde_server("/usr/bin/python3 server.py", self.repo))

    def test_absolute_server_py(self):
        cmd = f"python3 {os.path.join(self.repo, 'server.py')} --port 8003"
        self.assertTrue(sf.is_lde_server(cmd, "/"))

    def test_other_repo_server_py(self):
        self.assertFalse(sf.is_lde_server("python3 server.py", "/tmp/elsewhere"))

    def test_unrelated_process(self):
        self.assertFalse(sf.is_lde_server("python3 -m http.server 8002", self.repo))

    def test_check_port_owner_names_the_process(self):
        with self.assertRaises(RuntimeError) as ctx:
            sf.check_port_owner([(4242, "python3 -m http.server 8002", self.repo)], 8002)
        self.assertIn("4242", str(ctx.exception))
        self.assertIn("http.server", str(ctx.exception))


class TestDtrackUrlIsLocal(unittest.TestCase):
    def test_accepts_loopback_ipv4(self):
        sf.check_dtrack_url_is_local("http://127.0.0.1:8081")

    def test_accepts_loopback_ipv6(self):
        sf.check_dtrack_url_is_local("http://[::1]:8081")

    def test_rejects_url_with_no_hostname(self):
        with self.assertRaises(RuntimeError) as ctx:
            sf.check_dtrack_url_is_local("not-a-url")
        self.assertIn("no hostname", str(ctx.exception))

    def test_rejects_host_resolving_to_a_remote_address(self):
        fake_addrinfo = [(2, 1, 6, "", ("93.184.216.34", 8081))]
        with mock.patch.object(sf.socket, "getaddrinfo", return_value=fake_addrinfo):
            with self.assertRaises(RuntimeError) as ctx:
                sf.check_dtrack_url_is_local("http://dtrack.example.com:8081")
        self.assertIn("not loopback", str(ctx.exception))
        self.assertIn("93.184.216.34", str(ctx.exception))

    def test_rejects_unresolvable_host(self):
        with mock.patch.object(
            sf.socket, "getaddrinfo", side_effect=sf.socket.gaierror("name or service not known"),
        ):
            with self.assertRaises(RuntimeError) as ctx:
                sf.check_dtrack_url_is_local("http://no-such-host.invalid:8081")
        self.assertIn("did not resolve", str(ctx.exception))

    def test_rejects_when_any_resolved_address_is_remote(self):
        # A multi-homed name where only one of several addresses is remote
        # must still fail closed.
        fake_addrinfo = [
            (2, 1, 6, "", ("127.0.0.1", 8081)),
            (2, 1, 6, "", ("203.0.113.9", 8081)),
        ]
        with mock.patch.object(sf.socket, "getaddrinfo", return_value=fake_addrinfo):
            with self.assertRaises(RuntimeError):
                sf.check_dtrack_url_is_local("http://multi-homed.example:8081")


class TestDtrackReady(unittest.TestCase):
    def test_true_on_200(self):
        with mock.patch.object(sf._bootstrap, "_request", return_value=(200, b"{}", {})):
            self.assertTrue(sf.dtrack_ready("http://127.0.0.1:8081"))

    def test_false_on_network_error(self):
        with mock.patch.object(sf._bootstrap, "_request", side_effect=sf.urllib.error.URLError("down")):
            self.assertFalse(sf.dtrack_ready("http://127.0.0.1:8081"))


if __name__ == "__main__":
    unittest.main()
