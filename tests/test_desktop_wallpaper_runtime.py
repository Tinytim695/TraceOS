from __future__ import annotations
import json
import struct
import sys
import tempfile
import unittest
from pathlib import Path
from subprocess import CompletedProcess

ROOT = Path(__file__).resolve().parents[1]
LIB = ROOT / "config/includes.chroot/usr/local/lib/traceos"
sys.path.insert(0, str(LIB))
import desktop_wallpaper as branding  # noqa: E402

WALLPAPER = "/usr/share/backgrounds/traceos/traceos-wallpaper.png"


def fake_png(path: Path) -> None:
    path.write_bytes(b"\x89PNG\r\n\x1a\n" + b"\x00\x00\x00\x0dIHDR"
                     + struct.pack(">II", 1920, 1080) + b"\x08\x02\x00\x00\x00IEND")


def image(monitor: int, workspace: int = 0) -> str:
    return f"/backdrop/screen0/monitor{monitor}/workspace{workspace}/last-image"


def style(monitor: int, workspace: int = 0) -> str:
    return f"/backdrop/screen0/monitor{monitor}/workspace{workspace}/image-style"

def named_image(monitor_name: str, workspace: int = 0) -> str:
    return f"/backdrop/screen0/monitor{monitor_name}/workspace{workspace}/last-image"


def named_style(monitor_name: str, workspace: int = 0) -> str:
    return f"/backdrop/screen0/monitor{monitor_name}/workspace{workspace}/image-style"


class FakeRunner:
    def __init__(self, monitors=((0, "Virtual-1"),), properties=None):
        self.monitors = tuple(monitors)
        self.properties = dict(properties or {})
        self.fail_set = set()
        self.ignore_set = set()
        self.calls = []
        self.dump_calls = 0
        self.delayed_properties = None
        self.after_reload = {}
        self.reload_calls = 0

    def __call__(self, argv):
        args = list(argv)
        self.calls.append(args)
        if args[:3] == ["pgrep", "-x", "xfdesktop"]:
            return CompletedProcess(args, 0, "11\n", "")
        if args[:2] == ["xrandr", "--listmonitors"]:
            rows = [f" {i}: +*{name} 1280/340x800/210+0+0 {name}" for i, name in self.monitors]
            return CompletedProcess(args, 0, f"Monitors: {len(rows)}\n" + "\n".join(rows) + "\n", "")
        if args[:2] == ["xrandr", "--query"]:
            outputs = "".join(f"{name} connected primary 1280x800+0+0 (normal)\n" for _, name in self.monitors)
            return CompletedProcess(args, 0, "Screen 0: minimum 1 x 1, current 1280 x 800\n" + outputs, "")
        if args[:3] == ["xfconf-query", "-c", "xfce4-desktop"] and args[3:] == ["-lv"]:
            self.dump_calls += 1
            if self.delayed_properties and self.dump_calls >= self.delayed_properties[0]:
                self.properties.update(self.delayed_properties[1])
                self.delayed_properties = None
            return CompletedProcess(args, 0, "".join(f"{k} {v}\n" for k, v in self.properties.items()), "")
        if args[:3] == ["xfconf-query", "-c", "xsettings"] and args[3:] == ["-p", "/Net/ThemeName"]:
            return CompletedProcess(args, 0, "TraceOS\n", "")
        if args and args[0] == "xfconf-query" and "-p" in args:
            path = args[args.index("-p") + 1]
            if "-s" not in args:
                return CompletedProcess(args, 0, self.properties[path] + "\n", "") if path in self.properties else CompletedProcess(args, 1, "", "missing")
            value = args[-1]
            if (path, value) in self.fail_set:
                return CompletedProcess(args, 1, "", "mocked set failure")
            if (path, value) not in self.ignore_set:
                self.properties[path] = value
            return CompletedProcess(args, 0, "", "")
        if args == ["xfdesktop", "--reload"]:
            self.reload_calls += 1
            if self.reload_calls == 1:
                self.properties.update(self.after_reload)
            return CompletedProcess(args, 0, "", "")
        return CompletedProcess(args, 0, "", "")


class DesktopWallpaperRuntimeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.home = Path(self.temp.name) / "home"
        self.home.mkdir()
        self.wallpaper = Path(self.temp.name) / "wallpaper.png"
        fake_png(self.wallpaper)
        self.logs = []

    def tearDown(self):
        self.temp.cleanup()

    def run_setup(self, runner, attempts=8):
        return branding.setup_wallpaper(home=self.home, wallpaper=self.wallpaper,
            runner=runner, sleeper=lambda _seconds: None, logger=self.logs.append,
            ready_attempts=attempts, stable_samples=3, poll_seconds=0)

    def test_skeleton_monitor0_does_not_satisfy_connected_monitor1(self):
        runner = FakeRunner(monitors=((1, "HDMI-1"),),
            properties={image(0): "/usr/share/backgrounds/xfce/xfce-blue.jpg", style(0): "5"})
        self.assertTrue(self.run_setup(runner))
        self.assertEqual(runner.properties[image(0)], "/usr/share/backgrounds/xfce/xfce-blue.jpg")
        self.assertEqual(runner.properties[named_image("HDMI-1")], str(self.wallpaper))
        self.assertTrue(any("stage=TRACEOS_DESKTOP_BACKDROP_DISCOVERY result=READY" in line
                            and "target_modes=created-exact-output-name" in line
                            for line in self.logs))

    def test_qemu_virtual_output_does_not_fall_back_to_seeded_monitor0(self):
        stock = "/usr/share/backgrounds/xfce/xfce-blue.jpg"
        runner = FakeRunner(monitors=((0, "Virtual-1"),),
            properties={image(0): stock, style(0): "5"})
        self.assertTrue(self.run_setup(runner))
        self.assertEqual(runner.properties[image(0)], stock)
        self.assertEqual(runner.properties[named_image("Virtual-1")], str(self.wallpaper))
        summary = next(line for line in self.logs if "stage=TRACEOS_DESKTOP_BRANDING_RESULT result=PASS" in line)
        self.assertIn("backdrop_targets=/backdrop/screen0/monitorVirtual-1/workspace0/last-image", summary)

    def test_stock_wallpaper_outside_old_allowlist_migrates_legacy_state(self):
        state = self.home / branding.STATE_RELATIVE
        state.parent.mkdir(parents=True)
        state.write_text("\n", encoding="utf-8")
        runner = FakeRunner(properties={named_image("Virtual-1"): "/usr/share/images/desktop-base/desktop-background"})
        self.assertTrue(self.run_setup(runner))
        self.assertEqual(runner.properties[named_image("Virtual-1")], str(self.wallpaper))
        self.assertEqual(runner.properties[named_style("Virtual-1")], "5")
        saved = json.loads(state.read_text(encoding="utf-8"))
        self.assertEqual(saved["version"], branding.STATE_VERSION)

    def test_missing_style_is_created_and_read_back(self):
        runner = FakeRunner(properties={named_image("Virtual-1"): "/usr/share/backgrounds/xfce4/xfce-blue.jpg"})
        self.assertTrue(self.run_setup(runner))
        self.assertEqual(runner.properties[named_style("Virtual-1")], "5")
        self.assertTrue(any("-n" in c and "-t" in c and "int" in c for c in runner.calls))

    def test_partial_multi_output_failure_does_not_complete(self):
        runner = FakeRunner(monitors=((0, "Virtual-1"), (1, "HDMI-1")),
            properties={named_image("Virtual-1"): "/usr/share/backgrounds/xfce/xfce-blue.jpg",
                        named_style("Virtual-1"): "5",
                        named_image("HDMI-1"): "/usr/share/images/desktop-base/desktop-background",
                        named_style("HDMI-1"): "5"})
        runner.fail_set.add((named_image("HDMI-1"), str(self.wallpaper)))
        self.assertFalse(self.run_setup(runner))
        self.assertFalse((self.home / branding.STATE_RELATIVE).exists())

    def test_failed_image_readback_does_not_complete(self):
        runner = FakeRunner(properties={named_image("Virtual-1"): "/usr/share/backgrounds/xfce/xfce-blue.jpg",
                                        named_style("Virtual-1"): "5"})
        runner.ignore_set.add((named_image("Virtual-1"), str(self.wallpaper)))
        self.assertFalse(self.run_setup(runner))
        self.assertFalse((self.home / branding.STATE_RELATIVE).exists())

    def test_failed_style_readback_does_not_complete(self):
        runner = FakeRunner(properties={named_image("Virtual-1"): "/usr/share/backgrounds/xfce/xfce-blue.jpg"})
        runner.ignore_set.add((named_style("Virtual-1"), "5"))
        self.assertFalse(self.run_setup(runner))
        self.assertFalse((self.home / branding.STATE_RELATIVE).exists())
        self.assertIn("reason=wallpaper_or_style_readback_failed", self.logs[-1])

    def test_no_connected_output_is_retryable(self):
        runner = FakeRunner(monitors=(), properties={image(0): "/usr/share/backgrounds/xfce/xfce-blue.jpg"})
        self.assertFalse(self.run_setup(runner, attempts=3))
        self.assertFalse((self.home / branding.STATE_RELATIVE).exists())
        self.assertIn("reason=runtime_targets_not_ready", self.logs[-1])

    def test_incomplete_setup_succeeds_on_retry(self):
        runner = FakeRunner(properties={named_image("Virtual-1"): "/usr/share/backgrounds/xfce/xfce-blue.jpg",
                                        named_style("Virtual-1"): "5"})
        runner.fail_set.add((named_image("Virtual-1"), str(self.wallpaper)))
        self.assertFalse(self.run_setup(runner))
        runner.fail_set.clear()
        self.assertTrue(self.run_setup(runner))

    def test_later_custom_wallpaper_is_preserved(self):
        state = self.home / branding.STATE_RELATIVE
        state.parent.mkdir(parents=True)
        state.write_text(branding.STATE_VERSION + "\n", encoding="utf-8")
        chosen = "/home/traceos/Pictures/my-wallpaper.jpg"
        runner = FakeRunner(properties={named_image("Virtual-1"): chosen, named_style("Virtual-1"): "1"})
        self.assertTrue(self.run_setup(runner))
        self.assertEqual(runner.properties[named_image("Virtual-1")], chosen)
        self.assertEqual(runner.properties[named_style("Virtual-1")], "1")

    def test_later_system_wallpaper_choice_is_preserved_with_versioned_state(self):
        state = self.home / branding.STATE_RELATIVE
        state.parent.mkdir(parents=True)
        state.write_text(json.dumps({"version": branding.STATE_VERSION,
            "targets": {named_image("Virtual-1"): {"image": WALLPAPER, "style": "5"}}}), encoding="utf-8")
        chosen = "/usr/share/images/desktop-base/desktop-background"
        runner = FakeRunner(properties={named_image("Virtual-1"): chosen, named_style("Virtual-1"): "2"})
        self.assertTrue(self.run_setup(runner))
        self.assertEqual(runner.properties[named_image("Virtual-1")], chosen)
        self.assertEqual(runner.properties[named_style("Virtual-1")], "2")

    def test_user_style_survives_xfce_reload_override(self):
        state = self.home / branding.STATE_RELATIVE
        state.parent.mkdir(parents=True)
        state.write_text(branding.STATE_VERSION + "\n", encoding="utf-8")
        chosen = "/home/traceos/Pictures/my-wallpaper.jpg"
        runner = FakeRunner(properties={named_image("Virtual-1"): chosen, named_style("Virtual-1"): "1"})
        runner.after_reload = {named_style("Virtual-1"): "4"}
        self.assertTrue(self.run_setup(runner))
        self.assertEqual(runner.properties[named_image("Virtual-1")], chosen)
        self.assertEqual(runner.properties[named_style("Virtual-1")], "1")
        self.assertGreaterEqual(runner.reload_calls, 2)

    def test_summary_contains_asset_and_theme_evidence(self):
        runner = FakeRunner(properties={named_image("Virtual-1"): "/usr/share/backgrounds/xfce/xfce-blue.jpg",
                                        named_style("Virtual-1"): "5"})
        self.assertTrue(self.run_setup(runner))
        summary = self.logs[-1]
        self.assertIn("result=PASS", summary)
        self.assertIn("xsettings_theme=TraceOS", summary)
        self.assertIn("png_width=1920", summary)
        self.assertIn("png_height=1080", summary)
        self.assertRegex(summary, r"png_sha256=[0-9a-f]{64}")


if __name__ == "__main__":
    unittest.main()
