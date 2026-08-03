"""WSL detection, Windows-home detection, filesystem facts (§4)."""

from __future__ import annotations

import unittest
from unittest import mock

from .support import TempHomeCase

from honeypath import platform_detect as pd  # noqa: E402


class WslSignalTests(unittest.TestCase):
    def test_env_signals(self):
        with mock.patch.object(pd.Path, "read_text", side_effect=OSError):
            self.assertEqual(
                pd.wsl_signals({"WSL_DISTRO_NAME": "Ubuntu"}), ["env:WSL_DISTRO_NAME"]
            )
            self.assertEqual(
                pd.wsl_signals({"WSL_INTEROP": "/run/WSL/1"}), ["env:WSL_INTEROP"]
            )
            self.assertEqual(pd.wsl_signals({"WSLENV": "PATH/l"}), ["env:WSLENV"])
            self.assertEqual(pd.wsl_signals({}), [])

    def test_proc_version_signal(self):
        def fake_read_text(self, *args, **kwargs):
            if str(self) == "/proc/version":
                return "Linux version 6.6-microsoft-standard-WSL2"
            raise OSError

        with mock.patch.object(pd.Path, "read_text", fake_read_text):
            self.assertEqual(pd.wsl_signals({}), ["file:/proc/version"])

    def test_any_single_signal_is_enough(self):
        with mock.patch.object(pd, "wsl_signals", return_value=["env:WSLENV"]):
            self.assertEqual(pd.detect_os_name(), pd.OS_WSL)

    def test_plain_linux(self):
        with mock.patch.object(pd, "wsl_signals", return_value=[]):
            self.assertIn(
                pd.detect_os_name(), {pd.OS_LINUX, pd.OS_MACOS, pd.OS_UNKNOWN}
            )


class WindowsHomeDetectionTests(TempHomeCase):
    def make_drives(self, layout):
        """layout: {"c": ["alanr", "Public"], ...} -> list of /mnt-like roots."""
        roots = []
        for drive, users in layout.items():
            root = self.root / "mnt" / drive
            (root / "Users").mkdir(parents=True)
            for user in users:
                profile = root / "Users" / user
                profile.mkdir()
                if user not in ("Public", "Default"):
                    (profile / "NTUSER.DAT").write_text("hive")
            roots.append(str(root))
        return roots

    def test_finds_the_single_profile(self):
        roots = self.make_drives({"c": ["alanr", "Public", "Default"]})
        with mock.patch.object(pd, "windows_username", return_value="alanr"):
            homes, notes = pd.detect_windows_homes(None, roots=roots)
        self.assertEqual([p.name for p in homes], ["alanr"])

    def test_system_profiles_are_excluded(self):
        roots = self.make_drives({"c": ["Public", "Default", "All Users"]})
        with mock.patch.object(pd, "windows_username", return_value=None):
            homes, _ = pd.detect_windows_homes(None, roots=roots)
        self.assertEqual(homes, [])

    def test_username_match_is_ranked_first(self):
        roots = self.make_drives({"c": ["other", "alanr"]})
        with mock.patch.object(pd, "windows_username", return_value="alanr"):
            homes, notes = pd.detect_windows_homes(None, roots=roots)
        self.assertEqual(homes[0].name, "alanr")
        self.assertEqual(len(homes), 2)
        self.assertTrue(any("multiple candidate" in n for n in notes))

    def test_directories_without_a_hive_are_dropped(self):
        roots = self.make_drives({"c": ["alanr"], "d": []})
        stale = self.root / "mnt" / "d" / "Users" / "alanr"
        stale.mkdir(parents=True)  # no NTUSER.DAT
        with mock.patch.object(pd, "windows_username", return_value="alanr"):
            homes, notes = pd.detect_windows_homes(None, roots=roots)
        self.assertEqual(
            [str(p) for p in homes], [str(self.root / "mnt" / "c" / "Users" / "alanr")]
        )
        self.assertTrue(any("NTUSER.DAT" in n for n in notes))

    def test_multiple_real_profiles_are_all_reported(self):
        roots = self.make_drives({"c": ["alanr"], "d": ["alanr"]})
        with mock.patch.object(pd, "windows_username", return_value="alanr"):
            homes, notes = pd.detect_windows_homes(None, roots=roots)
        self.assertEqual(len(homes), 2)
        self.assertTrue(any("multiple candidate" in n for n in notes))

    def test_explicit_windows_home_wins(self):
        explicit = self.root / "explicit"
        explicit.mkdir()
        homes, notes = pd.detect_windows_homes(explicit, roots=[])
        self.assertEqual(homes, [explicit])
        self.assertTrue(any("supplied explicitly" in n for n in notes))

    def test_explicit_windows_home_that_does_not_exist(self):
        homes, notes = pd.detect_windows_homes(self.root / "nope", roots=[])
        self.assertEqual(homes, [])
        self.assertTrue(any("does not exist" in n for n in notes))

    def test_no_drives_at_all(self):
        with mock.patch.object(pd, "windows_username", return_value=None):
            homes, notes = pd.detect_windows_homes(
                None, roots=[str(self.root / "none")]
            )
        self.assertEqual(homes, [])
        self.assertTrue(any("no Windows user profile" in n for n in notes))


class DefaultProfileTests(unittest.TestCase):
    def test_native_linux(self):
        self.assertEqual(
            pd.default_profiles_for(pd.OS_LINUX, has_windows_home=False),
            ["linux-developer", "linux-supply-chain"],
        )

    def test_native_linux_with_crypto(self):
        self.assertEqual(
            pd.default_profiles_for(
                pd.OS_LINUX, has_windows_home=False, include_crypto=True
            ),
            ["linux-developer", "linux-supply-chain", "linux-crypto"],
        )

    def test_wsl_with_windows_home(self):
        self.assertEqual(
            pd.default_profiles_for(pd.OS_WSL, has_windows_home=True),
            [
                "linux-developer",
                "linux-supply-chain",
                "wsl-windows-developer",
                "wsl-windows-supply-chain",
            ],
        )

    def test_wsl_with_windows_home_and_crypto(self):
        self.assertEqual(
            pd.default_profiles_for(
                pd.OS_WSL, has_windows_home=True, include_crypto=True
            ),
            [
                "linux-developer",
                "linux-supply-chain",
                "wsl-windows-developer",
                "wsl-windows-supply-chain",
                "linux-crypto",
                "wsl-windows-crypto",
            ],
        )

    def test_wsl_without_windows_home_matches_native_linux(self):
        self.assertEqual(
            pd.default_profiles_for(pd.OS_WSL, has_windows_home=False),
            pd.default_profiles_for(pd.OS_LINUX, has_windows_home=False),
        )

    def test_macos(self):
        self.assertEqual(
            pd.default_profiles_for(pd.OS_MACOS, has_windows_home=False),
            ["macos-developer", "macos-supply-chain"],
        )

    def test_unknown_falls_back_to_linux(self):
        self.assertEqual(
            pd.default_profiles_for(pd.OS_UNKNOWN, has_windows_home=False),
            ["linux-developer", "linux-supply-chain"],
        )


class MountTests(unittest.TestCase):
    def test_mount_for_picks_the_most_specific(self):
        mounts = [
            pd.MountInfo("/", "ext4", ["rw", "relatime"]),
            pd.MountInfo("/mnt/c", "9p", ["rw", "noatime"]),
        ]
        from pathlib import Path

        self.assertEqual(pd.mount_for(Path("/mnt/c/Users/x"), mounts).fstype, "9p")
        self.assertEqual(pd.mount_for(Path("/home/x"), mounts).fstype, "ext4")

    def test_atime_policy(self):
        self.assertEqual(
            pd.MountInfo("/", "ext4", ["rw", "relatime"]).atime_policy, "relatime"
        )
        self.assertEqual(
            pd.MountInfo("/", "ext4", ["rw", "noatime"]).atime_policy, "noatime"
        )
        self.assertIn("kernel default", pd.MountInfo("/", "ext4", ["rw"]).atime_policy)

    def test_windows_filesystems_are_recognised(self):
        for fstype in ("9p", "drvfs", "virtiofs", "ntfs"):
            self.assertTrue(
                pd.is_windows_filesystem(pd.MountInfo("/mnt/c", fstype, []))
            )
        self.assertFalse(pd.is_windows_filesystem(pd.MountInfo("/", "ext4", [])))
        self.assertFalse(pd.is_windows_filesystem(None))

    def test_read_mounts_returns_something_on_linux(self):
        mounts = pd.read_mounts()
        self.assertTrue(any(m.mountpoint == "/" for m in mounts))


class InteropTests(unittest.TestCase):
    def test_missing_executable_degrades_cleanly(self):
        result = pd.run_interop(["definitely-not-a-real-binary.exe"])
        self.assertFalse(result.ok)
        self.assertIn("not found", result.error)

    def test_resolve_non_exe_names_pass_through(self):
        self.assertEqual(pd.resolve_windows_exe("wslpath"), "wslpath")

    def test_powershell_failure_is_reported_not_raised(self):
        with mock.patch.object(pd, "resolve_windows_exe", return_value=None):
            result = pd.run_powershell("Write-Host hi")
        self.assertFalse(result.ok)


if __name__ == "__main__":
    unittest.main()
