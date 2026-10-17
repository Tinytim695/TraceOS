from __future__ import annotations
import ast
import re
import xml.etree.ElementTree as ET
from pathlib import Path
import unittest

ROOT=Path(__file__).resolve().parents[1]
INCLUDES=ROOT/"config/includes.chroot"

def value(path: Path,key: str) -> str:
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.startswith(key+"="): return line.split("=",1)[1]
    return ""

class TraceOSDesktopBrandingTests(unittest.TestCase):
    def test_launcher_is_a_real_autostarted_home_screen(self):
        launcher=INCLUDES/"usr/local/bin/traceos-launcher"
        self.assertTrue(launcher.is_file())
        text=launcher.read_text(encoding="utf-8")
        for expected in ("TraceOS Launcher", 'self.root.attributes("-fullscreen", True)',
                         "TRACEOS_LAUNCHER_SESSION_READY",
                         "TRACEOS_LAUNCHER_ACTION_INVOKED","OPEN CONTROL CENTRE",
                         "#050811","#72f1e8"):
            self.assertIn(expected,text)
        entry=INCLUDES/"etc/xdg/autostart/traceos-launcher.desktop"
        self.assertEqual(value(entry,"Exec"),"/usr/local/bin/traceos-launcher")
        self.assertEqual(value(entry,"X-GNOME-Autostart-enabled"),"true")

    def test_control_centre_is_manual_not_the_only_home_screen(self):
        for relative in ("etc/xdg/autostart/traceos-control.desktop",
                         "etc/skel/.config/autostart/traceos-control.desktop"):
            entry=INCLUDES/relative
            self.assertEqual(value(entry,"Hidden"),"true")
            self.assertEqual(value(entry,"X-GNOME-Autostart-enabled"),"false")

    def test_branding_setup_has_traceos_panel_and_desktop_shortcuts(self):
        setup=(INCLUDES/"usr/local/bin/traceos-desktop-setup").read_text(encoding="utf-8")
        for expected in ("traceos-wallpaper.png","preserving user wallpaper","button-title",
                         "TraceOS","show-home","show-filesystem","TraceOS Launcher.desktop",
                         "TraceOS Control Centre.desktop"):
            self.assertIn(expected,setup)
        entry=INCLUDES/"etc/xdg/autostart/traceos-desktop-setup.desktop"
        self.assertEqual(value(entry,"Exec"),"/usr/local/bin/traceos-desktop-setup")

    def test_apps_have_traceos_category_and_distinct_icons(self):
        apps={"traceos-launcher.desktop":"traceos-launcher",
              "traceos-control.desktop":"traceos-control",
              "traceos-osint.desktop":"traceos-osint",
              "traceos-shade.desktop":"traceos-shade",
              "traceos.desktop":"traceos-console"}
        for filename,icon_name in apps.items():
            entry=INCLUDES/"usr/share/applications"/filename
            text=entry.read_text(encoding="utf-8")
            self.assertIn("Categories=TraceOS;",text)
            self.assertEqual(value(entry,"Icon"),icon_name)
            self.assertIn("Exec=",text)
            icon=INCLUDES/"usr/share/icons/hicolor/scalable/apps"/(icon_name+".svg")
            self.assertTrue(icon.is_file(),icon)
            self.assertEqual(ET.parse(icon).getroot().tag,"{http://www.w3.org/2000/svg}svg")

    def test_wallpaper_and_default_icons_are_branded(self):
        path=INCLUDES/"etc/skel/.config/xfce4/xfconf/xfce-perchannel-xml/xfce4-desktop.xml"
        root=ET.parse(path).getroot()
        values=[node.attrib.get("value","") for node in root.iter("property")]
        self.assertIn("/usr/share/backgrounds/traceos/traceos-wallpaper.png",values)
        names=[node.attrib.get("name") for node in root.iter("property")]
        for name in ("show-home","show-filesystem","show-trash","show-removable"):
            self.assertIn(name,names)


    def test_qemu_hmp_error_regex_rejects_real_error_responses(self):
        qemu=(ROOT/"scripts/qemu-ui-smoke.sh").read_text(encoding="utf-8")
        embedded=qemu.split("python3 - \"$monitor\" \"$command\" \"$log_path\" <<'PY'\n",1)[1].split("\nPY\n}",1)[0]
        module=ast.parse(embedded)
        pattern=None
        for node in ast.walk(module):
            if isinstance(node,ast.Assign) and any(isinstance(t,ast.Name) and t.id=="error_pattern" for t in node.targets):
                pattern=ast.literal_eval(node.value.args[0])
                break
        self.assertIsNotNone(pattern)
        compiled=re.compile(pattern)
        self.assertIsNotNone(compiled.search("Error: unknown command 'mouse_move'"))
        self.assertIsNotNone(compiled.search("  invalid parameter"))
        self.assertIsNone(compiled.search("succeeded"))
        self.assertIsNone(compiled.search("command accepted"))

    def test_qemu_launcher_click_uses_measured_geometry_and_absolute_tablet(self):
        qemu=(ROOT/"scripts/qemu-ui-smoke.sh").read_text(encoding="utf-8")
        self.assertIn("-device usb-tablet",qemu)
        self.assertIn('mouse_move 32767 32767',qemu)
        self.assertIn('pointer_args=(-usb -device usb-tablet)',qemu)
        self.assertIn("TRACEOS_LAUNCHER_PRIMARY_TILE_GEOM",qemu)
        self.assertIn("abs_x=$(( (px * 32767) / screen_w ))",qemu)
        self.assertIn("abs_y=$(( (py * 32767) / screen_h ))",qemu)
        self.assertNotIn('mouse_move 414 784',qemu)
        self.assertIn("launcher_action_seen",qemu)
        self.assertIn("nonce=$expected_nonce",qemu)
        self.assertIn("traceos-launcher-control-centre-failure.png",qemu)

    def test_qemu_captures_launcher_and_uncovered_desktop(self):
        qemu=(ROOT/"scripts/qemu-ui-smoke.sh").read_text(encoding="utf-8")
        for expected in ("traceos-launcher-home.png","traceos-desktop-home.png",
                         "TRACEOS_LAUNCHER_SESSION_READY",
                         "Applications menu visible in popup region"):
            self.assertIn(expected,qemu)

if __name__=="__main__": unittest.main()
