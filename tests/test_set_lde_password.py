"""The LDE password file is a mode-0600 JSON object of username to sha256 hex."""

import hashlib
import importlib.util
import json
import os
import stat
import tempfile
import unittest


def _load():
    path = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "scripts", "set_lde_password.py",
    )
    spec = importlib.util.spec_from_file_location("set_lde_password", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class SetLdePasswordTests(unittest.TestCase):
    def test_writes_username_and_sha256_hex_mode_0600(self):
        mod = _load()
        with tempfile.TemporaryDirectory() as tmp:
            dest = os.path.join(tmp, "basic-auth.json")
            mod.write_credential_file(dest, "admin", "correct horse")
            self.assertEqual(stat.S_IMODE(os.stat(dest).st_mode), 0o600)
            stored = json.loads(open(dest).read())
            self.assertEqual(list(stored), ["admin"])
            self.assertEqual(stored["admin"], hashlib.sha256(b"correct horse").hexdigest())
            self.assertNotIn("correct horse", open(dest).read())

    def test_rejects_an_empty_password(self):
        mod = _load()
        with tempfile.TemporaryDirectory() as tmp:
            dest = os.path.join(tmp, "basic-auth.json")
            with self.assertRaises(ValueError):
                mod.write_credential_file(dest, "admin", "")
            self.assertFalse(os.path.exists(dest))

    def test_plaintext_file_is_0600_two_lines(self):
        """lde-admin.txt must be mode 0600 and contain username on line 1, password on line 2."""
        mod = _load()
        with tempfile.TemporaryDirectory() as tmp:
            dest = os.path.join(tmp, "lde-admin.txt")
            mod.write_plaintext_file(dest, "alice", "s3cr3t!")
            self.assertEqual(stat.S_IMODE(os.stat(dest).st_mode), 0o600)
            lines = open(dest).read().splitlines()
            self.assertEqual(lines[0], "alice")
            self.assertEqual(lines[1], "s3cr3t!")

    def test_rejects_username_with_colon(self):
        mod = _load()
        with tempfile.TemporaryDirectory() as tmp:
            dest = os.path.join(tmp, "basic-auth.json")
            with self.assertRaises(ValueError) as ctx:
                mod.write_credential_file(dest, "user:name", "pw")
            self.assertIn("colon", str(ctx.exception).lower())
            self.assertFalse(os.path.exists(dest))

    def test_rejects_username_or_password_with_line_breaks(self):
        mod = _load()
        with tempfile.TemporaryDirectory() as tmp:
            dest = os.path.join(tmp, "basic-auth.json")
            with self.assertRaises(ValueError):
                mod.write_credential_file(dest, "user\nname", "pw")
            with self.assertRaises(ValueError):
                mod.write_credential_file(dest, "user", "pw\nword")
            with self.assertRaises(ValueError):
                mod.write_plaintext_file(os.path.join(tmp, "out.txt"), "a:b", "pw")
            self.assertFalse(os.path.exists(dest))


if __name__ == "__main__":
    unittest.main()
