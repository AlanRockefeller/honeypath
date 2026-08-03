"""Shared test scaffolding."""

from __future__ import annotations

import argparse
import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from honeypath import alerts as _alerts  # noqa: E402
from honeypath.database import Database  # noqa: E402
from honeypath.target_user import TargetUserContext  # noqa: E402

# A bare ``Pushover()`` reads /etc/honeypath, so on a machine where Honeypath is
# actually configured, any test that forgets to inject a fake pushes a synthetic
# alert to the operator's real phone.  Point the credentials somewhere that
# cannot exist before a single test constructs one.
_NO_CREDENTIALS = Path(tempfile.gettempdir()) / "honeypath-tests-no-credentials"
_alerts.CONFIG_DIR = _NO_CREDENTIALS
_alerts.TOKEN_FILE = _NO_CREDENTIALS / "pushover-token"
_alerts.USER_FILE = _NO_CREDENTIALS / "pushover-user"


class TempHomeCase(unittest.TestCase):
    """A test case with a throwaway home directory and database."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory(prefix="honeypath-test-")
        self.root = Path(self._tmp.name)
        self.home = self.root / "home" / "tester"
        self.home.mkdir(parents=True)
        self.target = TargetUserContext(
            username="tester",
            uid=os.getuid(),
            gid=os.getgid(),
            home=self.home,
        )
        self.db = Database(self.root / "events.sqlite3")
        self.db.initialize()
        self.log_lines: list[str] = []

    def tearDown(self) -> None:
        # The writer thread and its connection outlive the temp directory
        # otherwise, and a test that leaves the queue running can have its
        # writes land after the files it wrote them for are gone.
        try:
            self.db.close()
        except Exception:
            pass
        self._tmp.cleanup()

    def log(self, *args) -> None:
        self.log_lines.append(" ".join(str(a) for a in args))

    def quiet(self, stderr: bool = False):
        """Swallow a command's stdout so test output stays readable."""
        import contextlib
        import io

        if not stderr:
            return contextlib.redirect_stdout(io.StringIO())

        @contextlib.contextmanager
        def both():
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(
                io.StringIO()
            ):
                yield

        return both()

    def logged(self) -> str:
        return "\n".join(self.log_lines)

    def write(self, relative: str, content: str, mode: int = 0o600) -> Path:
        path = self.home / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)
        os.chmod(path, mode)
        return path


def namespace(**kwargs) -> argparse.Namespace:
    defaults = dict(
        user=None,
        top_user=None,
        allow_root=False,
        top_allow_root=False,
        db=None,
        top_db=None,
        log_file=None,
        top_log_file=None,
        no_log_file=False,
        top_no_log_file=False,
        windows_home=None,
        top_windows_home=None,
        yes=True,
        top_yes=False,
        dry_run=False,
        top_dry_run=False,
        force=False,
        top_force=False,
        profiles=None,
        include_crypto=False,
        include_noisy=False,
        include_active_config=False,
        refresh_managed=False,
        canarytoken_aws_file=None,
    )
    defaults.update(kwargs)
    return argparse.Namespace(**defaults)
