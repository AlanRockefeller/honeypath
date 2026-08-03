"""Target-user resolution (§3)."""

from __future__ import annotations

import getpass
import os
import unittest

from . import support  # noqa: F401  (inserts the repo root on sys.path)

from honeypath.target_user import (  # noqa: E402
    TargetUserError,
    resolve_target_user,
)


class ResolveTargetUserTests(unittest.TestCase):
    def setUp(self):
        self.me = getpass.getuser()

    def test_explicit_user_wins(self):
        ctx = resolve_target_user(self.me, environ={"SUDO_USER": "root"})
        self.assertEqual(ctx.username, self.me)

    def test_sudo_user_used_when_present(self):
        ctx = resolve_target_user(None, environ={"SUDO_USER": self.me})
        self.assertEqual(ctx.username, self.me)
        self.assertEqual(ctx.uid, os.getuid())

    def test_sudo_user_root_is_ignored(self):
        # SUDO_USER=root must fall through to the effective user, not to /root.
        ctx = resolve_target_user(None, environ={"SUDO_USER": "root"})
        self.assertEqual(ctx.uid, os.geteuid())

    def test_plain_user_falls_back_to_effective_user(self):
        ctx = resolve_target_user(None, environ={})
        self.assertEqual(ctx.uid, os.geteuid())

    def test_root_is_refused_without_allow_root(self):
        with self.assertRaises(TargetUserError) as caught:
            resolve_target_user("root", environ={})
        self.assertIn("refusing to operate on root", str(caught.exception))

    def test_root_allowed_with_flag(self):
        ctx = resolve_target_user("root", allow_root=True, environ={})
        self.assertEqual(ctx.username, "root")

    def test_unknown_user_raises(self):
        with self.assertRaises(TargetUserError):
            resolve_target_user("definitely-not-a-real-user-honeypath", environ={})


if __name__ == "__main__":
    unittest.main()
