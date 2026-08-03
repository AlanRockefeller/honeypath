"""Symlink-safe atomic writes (§3).

These tests simulate the attacks the module exists to defeat.  Honeypath
frequently runs under sudo while writing into a directory the target user
owns, so every one of these scenarios is reachable by an unprivileged
attacker who merely has write access to their own home.
"""

from __future__ import annotations

import os
import stat
import unittest
from pathlib import Path
from unittest import mock

from .support import TempHomeCase

from honeypath import safe_write  # noqa: E402


class ValidateDestinationTests(TempHomeCase):
    def test_accepts_an_ordinary_path_under_the_root(self):
        path = self.home / ".aws" / "credentials"
        self.assertEqual(safe_write.validate_destination(path, self.home), path)

    def test_rejects_a_relative_path(self):
        with self.assertRaises(safe_write.SafeWriteError):
            safe_write.validate_destination(Path(".netrc"), self.home)

    def test_rejects_a_dotdot_component(self):
        path = self.home / ".." / "elsewhere" / "file"
        with self.assertRaises(safe_write.SafeWriteError) as caught:
            safe_write.validate_destination(path, self.home)
        self.assertIn("'..'", str(caught.exception))

    def test_rejects_a_path_outside_the_root(self):
        outside = self.root / "not-the-home" / "file"
        with self.assertRaises(safe_write.SafeWriteError) as caught:
            safe_write.validate_destination(outside, self.home)
        self.assertIn("outside", str(caught.exception))

    def test_rejects_a_symlinked_parent_directory(self):
        """A symlinked parent pointing outside the home must be refused."""
        outside = self.root / "attacker-controlled"
        outside.mkdir()
        link = self.home / ".aws"
        link.symlink_to(outside)
        with self.assertRaises(safe_write.SafeWriteError) as caught:
            safe_write.validate_destination(link / "credentials", self.home)
        self.assertIn("symlink", str(caught.exception))

    def test_rejects_a_symlinked_parent_even_when_it_stays_inside(self):
        """Refused regardless of where it points: the check is structural."""
        inside = self.home / "real-dir"
        inside.mkdir()
        link = self.home / ".aws"
        link.symlink_to(inside)
        with self.assertRaises(safe_write.SafeWriteError):
            safe_write.validate_destination(link / "credentials", self.home)

    def test_rejects_a_symlinked_final_destination(self):
        outside = self.root / "real-secrets"
        outside.write_text("SECRET\n")
        link = self.home / ".netrc"
        link.symlink_to(outside)
        with self.assertRaises(safe_write.SafeWriteError) as caught:
            safe_write.validate_destination(link, self.home)
        self.assertIn("symlink", str(caught.exception))

    def test_allows_a_symlinked_destination_when_explicitly_permitted(self):
        link = self.home / ".netrc"
        link.symlink_to(self.root / "target")
        safe_write.validate_destination(link, self.home, allow_symlink_destination=True)

    def test_rejects_a_parent_that_is_a_regular_file(self):
        blocker = self.home / ".aws"
        blocker.write_text("not a directory\n")
        with self.assertRaises(safe_write.SafeWriteError) as caught:
            safe_write.validate_destination(blocker / "credentials", self.home)
        self.assertIn("not a directory", str(caught.exception))

    def test_a_symlinked_root_itself_is_allowed(self):
        """/home/alan may legitimately be a symlink; only children are checked."""
        real_home = self.root / "real-home"
        real_home.mkdir()
        linked_home = self.root / "linked-home"
        linked_home.symlink_to(real_home)
        path = linked_home / ".netrc"
        safe_write.validate_destination(path, linked_home)


class AtomicWriteTests(TempHomeCase):
    def test_writes_content_mode_and_leaves_no_temporary(self):
        path = self.home / ".netrc"
        safe_write.atomic_write(path, "body\n", mode=0o600, root=self.home)
        self.assertEqual(path.read_text(), "body\n")
        self.assertEqual(stat.S_IMODE(os.lstat(path).st_mode), 0o600)
        self.assertEqual(self._temporaries(self.home), [])

    def test_exclusive_create_fallback_supports_filesystems_without_otmpfile(self):
        path = self.home / ".netrc"
        unavailable = safe_write.SafeWriteError("O_TMPFILE unsupported")
        with mock.patch.object(
            safe_write, "_open_unnamed_temporary", side_effect=unavailable
        ):
            safe_write.atomic_write(
                path,
                "canary\n",
                mode=0o600,
                root=self.home,
                allow_exclusive_create_fallback=True,
            )
        self.assertEqual(path.read_text(), "canary\n")
        self.assertEqual(stat.S_IMODE(os.lstat(path).st_mode), 0o600)

    def test_exclusive_create_fallback_is_opt_in(self):
        path = self.home / ".netrc"
        unavailable = safe_write.SafeWriteError("O_TMPFILE unsupported")
        with mock.patch.object(
            safe_write, "_open_unnamed_temporary", side_effect=unavailable
        ):
            with self.assertRaises(safe_write.SafeWriteError):
                safe_write.atomic_write(path, "canary\n", mode=0o600, root=self.home)
        self.assertFalse(path.exists())

    def test_exclusive_create_fallback_cleans_partial_file_on_failure(self):
        path = self.home / ".netrc"
        unavailable = safe_write.SafeWriteError("O_TMPFILE unsupported")
        with mock.patch.object(
            safe_write, "_open_unnamed_temporary", side_effect=unavailable
        ), mock.patch.object(safe_write, "_write_all", side_effect=OSError("boom")):
            with self.assertRaises(OSError):
                safe_write.atomic_write(
                    path,
                    "canary\n",
                    mode=0o600,
                    root=self.home,
                    allow_exclusive_create_fallback=True,
                )
        self.assertFalse(path.exists())

    def test_replaces_an_existing_file_atomically(self):
        path = self.home / ".netrc"
        path.write_text("old\n")
        original_inode = os.lstat(path).st_ino
        safe_write.atomic_write(path, "new\n", mode=0o600, root=self.home)
        self.assertEqual(path.read_text(), "new\n")
        # A genuine replace, not an in-place truncate-and-rewrite.
        self.assertNotEqual(os.lstat(path).st_ino, original_inode)

    def test_refuses_to_write_through_a_symlinked_destination(self):
        outside = self.root / "real-secrets"
        outside.write_text("SECRET\n")
        link = self.home / ".netrc"
        link.symlink_to(outside)
        with self.assertRaises(safe_write.SafeWriteError):
            safe_write.atomic_write(link, "canary\n", mode=0o600, root=self.home)
        self.assertEqual(outside.read_text(), "SECRET\n")

    def test_refuses_a_symlinked_parent_pointing_outside_the_home(self):
        outside = self.root / "attacker-dir"
        outside.mkdir()
        link = self.home / ".config"
        link.symlink_to(outside)
        with self.assertRaises(safe_write.SafeWriteError):
            safe_write.atomic_write(
                link / "creds", "canary\n", mode=0o600, root=self.home
            )
        self.assertEqual(list(outside.iterdir()), [])

    def test_a_symlink_at_the_old_predictable_temp_name_is_not_followed(self):
        """The pre-fix code opened `<name>.honeypath-tmp` with O_CREAT|O_TRUNC."""
        outside = self.root / "victim"
        outside.write_text("UNTOUCHED\n")
        path = self.home / ".netrc"
        trap = self.home / ".netrc.honeypath-tmp"
        trap.symlink_to(outside)

        safe_write.atomic_write(path, "canary\n", mode=0o600, root=self.home)
        self.assertEqual(path.read_text(), "canary\n")
        self.assertEqual(outside.read_text(), "UNTOUCHED\n")
        self.assertTrue(trap.is_symlink())

    def test_temporary_names_are_unpredictable_and_distinct(self):
        seen = set()
        directory = self.home / "probe"
        directory.mkdir()
        for index in range(5):
            target = directory / f"file{index}"
            target.write_text("old")
            original = safe_write._random_temp_name

            captured: list[str] = []

            def spy():
                name = original()
                captured.append(name)
                return name

            safe_write._random_temp_name = spy
            try:
                safe_write.atomic_write(target, "x", mode=0o600, root=self.home)
            finally:
                safe_write._random_temp_name = original
            seen.add(captured[0])
        self.assertEqual(len(seen), 5)
        for name in seen:
            self.assertIn(safe_write.TEMP_PREFIX, Path(name).name)

    def test_writes_every_byte_of_a_large_payload(self):
        """Guards the short-write loop."""
        path = self.home / "big.bin"
        payload = os.urandom(3 * 1024 * 1024)
        safe_write.atomic_write(path, payload, mode=0o600, root=self.home)
        self.assertEqual(path.read_bytes(), payload)

    def test_a_failure_mid_write_leaves_no_temporary_behind(self):
        path = self.home / ".netrc"
        original = safe_write._write_all

        def explode(fd, data):
            raise OSError("simulated disk failure")

        safe_write._write_all = explode
        try:
            with self.assertRaises(OSError):
                safe_write.atomic_write(path, "x", mode=0o600, root=self.home)
        finally:
            safe_write._write_all = original
        self.assertFalse(path.exists())
        self.assertEqual(self._temporaries(self.home), [])

    def test_a_failure_during_replace_leaves_no_temporary_behind(self):
        path = self.home / ".netrc"
        path.write_text("old")

        def explode(*args, **kwargs):
            raise OSError("simulated rename failure")

        with mock.patch.object(safe_write, "_renameat_exchange", side_effect=explode):
            with self.assertRaises(OSError):
                safe_write.atomic_write(path, "x", mode=0o600, root=self.home)
        self.assertEqual(path.read_text(), "old")
        self.assertEqual(self._temporaries(self.home), [])

    def test_destination_appearing_during_install_is_not_clobbered(self):
        path = self.home / "race"
        original = safe_write._link_open_fd_noreplace

        def appear(fd, parent_fd, name):
            attacker = os.open(
                name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600, dir_fd=parent_fd
            )
            os.write(attacker, b"ATTACKER")
            os.close(attacker)
            return original(fd, parent_fd, name)

        with mock.patch.object(
            safe_write, "_link_open_fd_noreplace", side_effect=appear
        ):
            with self.assertRaises(safe_write.SafeWriteError):
                safe_write.atomic_write(
                    path, "canary", mode=0o600, root=self.home, replace=False
                )
        self.assertEqual(path.read_text(), "ATTACKER")
        self.assertEqual(self._temporaries(self.home), [])

    def test_parent_swapped_to_external_symlink_after_validation_is_refused(self):
        parent = self.home / ".config"
        parent.mkdir()
        path = parent / "credential"
        safe_write.validate_destination(path, self.home)
        moved = self.home / ".config-old"
        parent.rename(moved)
        outside = self.root / "outside"
        outside.mkdir()
        parent.symlink_to(outside)
        with self.assertRaises(safe_write.SafeWriteError):
            safe_write.atomic_write(
                path, "canary", mode=0o600, root=self.home, replace=False
            )
        self.assertEqual(list(outside.iterdir()), [])

    def test_refresh_symlink_race_never_touches_symlink_target(self):
        path = self.home / "managed"
        path.write_text("old")
        victim = self.root / "victim"
        victim.write_text("SECRET")
        expected = __import__("hashlib").sha256(b"old").hexdigest()
        real_exchange = safe_write._renameat_exchange

        def race(parent_fd, stage, destination):
            os.unlink(destination, dir_fd=parent_fd)
            os.symlink(victim, destination, dir_fd=parent_fd)
            return real_exchange(parent_fd, stage, destination)

        with mock.patch.object(safe_write, "_renameat_exchange", side_effect=race):
            with self.assertRaises(safe_write.SafeWriteError):
                safe_write.atomic_write(
                    path,
                    "new",
                    mode=0o600,
                    root=self.home,
                    replace=True,
                    expected_sha256=expected,
                )
        self.assertTrue(path.is_symlink())
        self.assertEqual(victim.read_text(), "SECRET")

    def test_observed_staging_name_cannot_substitute_payload(self):
        path = self.home / "managed"
        path.write_text("old")
        expected = __import__("hashlib").sha256(b"old").hexdigest()
        real_exchange = safe_write._renameat_exchange
        attacked = False

        def substitute(parent_fd, stage, destination):
            nonlocal attacked
            if attacked:
                return real_exchange(parent_fd, stage, destination)
            attacked = True
            os.unlink(stage, dir_fd=parent_fd)
            fd = os.open(
                stage, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600, dir_fd=parent_fd
            )
            os.write(fd, b"ATTACKER")
            os.close(fd)
            return real_exchange(parent_fd, stage, destination)

        with mock.patch.object(
            safe_write, "_renameat_exchange", side_effect=substitute
        ):
            with self.assertRaises(safe_write.SafeWriteError):
                safe_write.atomic_write(
                    path,
                    "expected",
                    mode=0o600,
                    root=self.home,
                    expected_sha256=expected,
                )
        self.assertEqual(path.read_text(), "old")
        # The substituted entry belongs to the attacker, not Honeypath; fail
        # closed without deleting it under a merely familiar temp prefix.
        leftovers = self._temporaries(self.home)
        self.assertEqual(len(leftovers), 1)
        self.assertEqual(leftovers[0].read_text(), "ATTACKER")

    def test_destination_changed_after_hash_is_restored_not_overwritten(self):
        path = self.home / "managed"
        path.write_text("old")
        expected = __import__("hashlib").sha256(b"old").hexdigest()
        real_exchange = safe_write._renameat_exchange
        attacked = False

        def change_destination(parent_fd, stage, destination):
            nonlocal attacked
            if attacked:
                return real_exchange(parent_fd, stage, destination)
            attacked = True
            os.unlink(destination, dir_fd=parent_fd)
            attacker = os.open(
                destination,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                0o600,
                dir_fd=parent_fd,
            )
            os.write(attacker, b"ATTACKER")
            os.close(attacker)
            return real_exchange(parent_fd, stage, destination)

        with mock.patch.object(
            safe_write, "_renameat_exchange", side_effect=change_destination
        ):
            with self.assertRaises(safe_write.SafeWriteError):
                safe_write.atomic_write(
                    path,
                    "new",
                    mode=0o600,
                    root=self.home,
                    expected_sha256=expected,
                )
        self.assertEqual(path.read_text(), "ATTACKER")

    def test_exception_closes_fds_and_removes_temporary(self):
        before = len(list(Path("/proc/self/fd").iterdir()))
        path = self.home / "failure"
        with mock.patch.object(safe_write, "_write_all", side_effect=OSError("boom")):
            with self.assertRaises(OSError):
                safe_write.atomic_write(
                    path, "x", mode=0o600, root=self.home, replace=False
                )
        after = len(list(Path("/proc/self/fd").iterdir()))
        self.assertEqual(after, before)
        self.assertEqual(self._temporaries(self.home), [])

    def test_ownership_failure_is_a_warning_not_an_error(self):
        """WSL/DrvFS best-effort behaviour: report, never abort."""
        path = self.home / ".netrc"
        original = os.fchmod

        def refuse(fd, mode):
            raise OSError("Operation not permitted")

        os.fchmod = refuse
        try:
            warnings = safe_write.atomic_write(
                path,
                "canary\n",
                mode=0o600,
                root=self.home,
                best_effort_metadata=True,
            )
        finally:
            os.fchmod = original
        self.assertTrue(any("chmod" in w for w in warnings))
        # The content still landed; only the metadata was refused.
        self.assertEqual(path.read_text(), "canary\n")

    def test_ownership_failure_can_be_made_fatal(self):
        path = self.home / ".netrc"
        original = os.fchmod

        def refuse(fd, mode):
            raise OSError("Operation not permitted")

        os.fchmod = refuse
        try:
            with self.assertRaises(OSError):
                safe_write.atomic_write(
                    path,
                    "canary\n",
                    mode=0o600,
                    root=self.home,
                    best_effort_metadata=False,
                )
        finally:
            os.fchmod = original
        self.assertEqual(self._temporaries(self.home), [])

    def test_fsync_data_is_honoured(self):
        path = self.home / "durable"
        calls: list[int] = []
        original = os.fsync

        def spy(fd):
            calls.append(fd)
            return original(fd)

        os.fsync = spy
        try:
            safe_write.atomic_write(
                path, "x", mode=0o600, root=self.home, fsync_data=True
            )
        finally:
            os.fsync = original
        self.assertTrue(calls)

    def test_a_directory_fsync_failure_is_only_a_warning(self):
        path = self.home / ".netrc"
        original = os.fsync

        def refuse(fd):
            raise OSError("not supported on this filesystem")

        os.fsync = refuse
        try:
            warnings = safe_write.atomic_write(
                path, "canary\n", mode=0o600, root=self.home
            )
        finally:
            os.fsync = original
        self.assertTrue(any("fsync" in w for w in warnings))
        self.assertEqual(path.read_text(), "canary\n")

    @staticmethod
    def _temporaries(directory: Path) -> list[Path]:
        return [
            p for p in directory.rglob("*") if p.name.startswith(safe_write.TEMP_PREFIX)
        ]


class AtomicCopyTests(TempHomeCase):
    def test_copies_bytes_exactly(self):
        source = self.root / "id_ed25519"
        payload = os.urandom(4096)
        source.write_bytes(payload)
        destination = self.home / "relocated" / "id_ed25519"
        destination.parent.mkdir(parents=True)
        safe_write.atomic_copy(source, destination, mode=0o600, root=self.home)
        self.assertEqual(destination.read_bytes(), payload)
        self.assertEqual(stat.S_IMODE(os.lstat(destination).st_mode), 0o600)

    def test_refuses_to_read_through_a_symlinked_source(self):
        real = self.root / "somebody-elses-key"
        real.write_text("SECRET\n")
        source = self.root / "link"
        source.symlink_to(real)
        destination = self.home / "copy"
        with self.assertRaises(safe_write.SafeWriteError):
            safe_write.atomic_copy(source, destination, mode=0o600, root=self.home)
        self.assertFalse(destination.exists())


class SafeMkdirTests(TempHomeCase):
    def test_creates_nested_directories_with_the_mode(self):
        path = self.home / ".local" / "share" / "honeypath" / "real-ssh"
        safe_write.safe_mkdir(path, self.home, mode=0o700)
        self.assertTrue(path.is_dir())
        self.assertEqual(stat.S_IMODE(os.lstat(path).st_mode), 0o700)

    def test_refuses_to_traverse_a_symlinked_component(self):
        outside = self.root / "attacker"
        outside.mkdir()
        link = self.home / ".local"
        link.symlink_to(outside)
        with self.assertRaises(safe_write.SafeWriteError) as caught:
            safe_write.safe_mkdir(link / "share" / "honeypath", self.home)
        self.assertIn("symlink", str(caught.exception))
        self.assertEqual(list(outside.iterdir()), [])

    def test_refuses_a_path_outside_the_root(self):
        with self.assertRaises(safe_write.SafeWriteError):
            safe_write.safe_mkdir(self.root / "elsewhere", self.home)

    def test_is_idempotent(self):
        path = self.home / ".config" / "honeypath"
        safe_write.safe_mkdir(path, self.home, mode=0o700)
        safe_write.safe_mkdir(path, self.home, mode=0o700)
        self.assertTrue(path.is_dir())

    def test_refuses_when_a_component_is_a_regular_file(self):
        blocker = self.home / ".config"
        blocker.write_text("in the way\n")
        with self.assertRaises(safe_write.SafeWriteError):
            safe_write.safe_mkdir(blocker / "honeypath", self.home)

    def test_directory_replaced_between_mkdir_and_metadata_is_detected(self):
        path = self.home / "newdir"
        real_fchmod = os.fchmod

        def swap(fd, mode):
            os.rename(path, self.home / "moved-newdir")
            path.mkdir()
            return real_fchmod(fd, mode)

        with mock.patch("honeypath.safe_write.os.fchmod", side_effect=swap):
            with self.assertRaises(safe_write.SafeWriteError):
                safe_write.safe_mkdir(path, self.home)


class NofollowReadTests(TempHomeCase):
    def test_reads_a_regular_file(self):
        path = self.write("plain.txt", "hello\n")
        self.assertEqual(safe_write.read_text_nofollow(path), "hello\n")

    def test_refuses_a_symlink(self):
        real = self.write("real.txt", "secret\n")
        link = self.home / "link.txt"
        link.symlink_to(real)
        with self.assertRaises(safe_write.SafeWriteError):
            safe_write.read_text_nofollow(link)

    def test_missing_file_raises_oserror(self):
        with self.assertRaises(OSError):
            safe_write.read_bytes_nofollow(self.home / "nope")


class CleanupTests(TempHomeCase):
    def test_does_not_delete_unverified_prefix_matches(self):
        keep = self.home / "keep.txt"
        keep.write_text("keep\n")
        (self.home / f"{safe_write.TEMP_PREFIX}abc").write_text("junk\n")
        (self.home / f"{safe_write.TEMP_PREFIX}def").write_text("junk\n")
        removed = safe_write.cleanup_stale_temporaries(self.home)
        self.assertEqual(removed, 0)
        self.assertTrue(keep.exists())
        self.assertTrue((self.home / f"{safe_write.TEMP_PREFIX}abc").exists())
        self.assertTrue((self.home / f"{safe_write.TEMP_PREFIX}def").exists())


if __name__ == "__main__":
    unittest.main()
