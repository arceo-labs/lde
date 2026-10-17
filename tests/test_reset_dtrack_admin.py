"""Unit tests for scripts/reset_dtrack_admin.py. Docker is never called."""

import hashlib
import importlib.util
import os
import shutil
import stat
import subprocess
import tempfile
import unittest
import zipfile
from unittest import mock


def _load():
    path = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "scripts", "reset_dtrack_admin.py",
    )
    spec = importlib.util.spec_from_file_location("reset_dtrack_admin", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


rd = _load()

GOOD_2Y = "$2y$14$" + "a" * 53
GOOD_2A = "$2a$14$" + "a" * 53


class TestLocalUrl(unittest.TestCase):
    def test_accepts_local(self):
        for url in ("http://127.0.0.1:8081", "http://localhost:8081", "http://[::1]:8081"):
            rd.check_local_url(url)

    def test_rejects_remote(self):
        for url in ("https://dtrack.example.com", "http://10.0.0.5:8081", "http://127.0.0.1.evil.com"):
            with self.assertRaises(ValueError):
                rd.check_local_url(url)


class TestHash(unittest.TestCase):
    def test_2y_becomes_2a(self):
        self.assertEqual(rd.to_2a(GOOD_2Y), GOOD_2A)

    def test_rejects_wrong_cost_or_shape(self):
        for bad in ("$2a$10$" + "a" * 53, "$2a$14$" + "a" * 52, "$2a$14$" + "a" * 52 + "'", ""):
            with self.assertRaises(RuntimeError):
                rd.to_2a(bad)

    @unittest.skipUnless(shutil.which("htpasswd"), "htpasswd not installed")
    def test_htpasswd_hash_verifies_sha512_hex(self):
        htpasswd = shutil.which("htpasswd")
        hashed = rd.dtrack_hash(htpasswd, "s3cret")
        self.assertRegex(hashed, rd.HASH_RE)
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "htfile")
            with open(path, "w") as fh:
                fh.write(f"admin:{hashed}\n")
            digest = hashlib.sha512(b"s3cret").hexdigest()
            ok = subprocess.run([htpasswd, "-vi", path, "admin"], input=digest + "\n",
                                capture_output=True, text=True, timeout=60)
            self.assertEqual(ok.returncode, 0, ok.stderr)
            bad = subprocess.run([htpasswd, "-vi", path, "admin"], input="s3cret\n",
                                 capture_output=True, text=True, timeout=60)
            self.assertNotEqual(bad.returncode, 0)


class TestSql(unittest.TestCase):
    def test_sql_contains_hash(self):
        sql = rd.reset_sql(GOOD_2A)
        self.assertIn(f"PASSWORD='{GOOD_2A}'", sql)
        self.assertIn("FORCE_PASSWORD_CHANGE=FALSE", sql)
        self.assertIn("WHERE USERNAME='admin'", sql)

    def test_sql_refuses_invalid_hash(self):
        with self.assertRaises(ValueError):
            rd.reset_sql("x'; DROP TABLE MANAGEDUSER; --")


class TestExtractH2(unittest.TestCase):
    def test_extracts_h2_only(self):
        with tempfile.TemporaryDirectory() as d:
            jar = os.path.join(d, "app.jar")
            with zipfile.ZipFile(jar, "w") as zf:
                zf.writestr("WEB-INF/lib/other-1.0.jar", b"x")
                zf.writestr("WEB-INF/lib/h2-2.2.224.jar", b"h2")
            lib = os.path.join(d, "lib")
            os.mkdir(lib)
            self.assertEqual(rd.extract_h2(jar, lib), "h2-2.2.224.jar")
            self.assertEqual(os.listdir(lib), ["h2-2.2.224.jar"])

    def test_missing_h2(self):
        with tempfile.TemporaryDirectory() as d:
            jar = os.path.join(d, "app.jar")
            with zipfile.ZipFile(jar, "w") as zf:
                zf.writestr("WEB-INF/lib/other-1.0.jar", b"x")
            with self.assertRaises(RuntimeError):
                rd.extract_h2(jar, d)


class TestSaveOther(unittest.TestCase):
    def test_absent_file(self):
        with tempfile.TemporaryDirectory() as d:
            self.assertIsNone(rd.save_other_password_file(os.path.join(d, "dtrack-admin.txt")))

    def test_copies_without_overwrite(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "dtrack-admin.txt")
            other = os.path.join(d, "dtrack-admin.other.txt")
            with open(path, "w") as fh:
                fh.write("admin\nnew\n")
            self.assertEqual(rd.save_other_password_file(path), other)
            self.assertEqual(stat.S_IMODE(os.stat(other).st_mode), 0o600)
            with open(path, "w") as fh:
                fh.write("admin\nnewer\n")
            rd.save_other_password_file(path)
            with open(other) as fh:
                self.assertEqual(fh.read(), "admin\nnew\n")


class TestMain(unittest.TestCase):
    def test_decline_changes_nothing(self):
        with mock.patch.object(rd, "require_tool", return_value="/bin/true"), \
             mock.patch.object(rd, "preflight"), \
             mock.patch.object(rd, "confirm", return_value=False), \
             mock.patch.object(rd, "run") as run, \
             mock.patch.object(rd, "save_other_password_file") as save:
            self.assertEqual(rd.main([]), 1)
            run.assert_not_called()
            save.assert_not_called()

    def _run_main(self, extra):
        with tempfile.TemporaryDirectory() as d:
            out = os.path.join(d, "dtrack-admin.txt")
            with mock.patch.object(rd, "require_tool", return_value="/bin/true"), \
                 mock.patch.object(rd, "preflight"), \
                 mock.patch.object(rd, "dtrack_hash", return_value=GOOD_2A), \
                 mock.patch.object(rd, "run"), \
                 mock.patch.object(rd, "extract_h2", return_value="h2-2.2.224.jar"), \
                 mock.patch.object(rd, "apply_sql"), \
                 mock.patch.object(rd, "wait_for_api"), \
                 mock.patch.object(rd._bootstrap, "login", return_value=(200, "token")), \
                 mock.patch.object(rd, "backup_volume") as backup:
                backup.return_value = os.path.join(d, "dtrack_data.tar")
                self.assertEqual(rd.main(extra + ["--yes", "--password-out", out]), 0)
                self.assertEqual(stat.S_IMODE(os.stat(out).st_mode), 0o600)
                return backup

    def test_no_backup_by_default(self):
        self._run_main([]).assert_not_called()

    def test_backup_is_opt_in(self):
        self._run_main(["--backup"]).assert_called_once()

    def test_remote_url_refused_before_docker(self):
        with mock.patch.object(rd, "preflight") as pre:
            with self.assertRaises(ValueError):
                rd.main(["--dtrack-url", "https://dtrack.example.com"])
            pre.assert_not_called()


if __name__ == "__main__":
    unittest.main()
