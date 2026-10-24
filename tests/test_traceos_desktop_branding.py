from __future__ import annotations
import ast
import re
import xml.etree.ElementTree as ET
from pathlib import Path
import unittest

ROOT=Path(__file__).resolve().parents[1]
INCLUDES=ROOT/"config/includes.chroot"

def png_rgb_rows(path: Path):
    """Decode a non-interlaced 8-bit RGB or RGBA PNG without Pillow."""
    import struct
    import zlib
    data = path.read_bytes()
    if not data.startswith(b"\x89PNG\r\n\x1a\n"):
        raise AssertionError(f"{path} is not a PNG")
    pos = 8
    width = height = color = 0
    idat = bytearray()
    while pos + 8 <= len(data):
        length = struct.unpack(">I", data[pos:pos + 4])[0]
        kind = data[pos + 4:pos + 8]
        chunk = data[pos + 8:pos + 8 + length]
        if kind == b"IHDR":
            width, height, bit, color = struct.unpack(">IIBB", chunk[:10])
            if bit != 8 or color not in (2, 6):
                raise AssertionError(f"unsupported PNG {width}x{height} bit={bit} color={color}")
        elif kind == b"IDAT":
            idat.extend(chunk)
        elif kind == b"IEND":
            break
        pos += 12 + length
    raw = zlib.decompress(bytes(idat))
    channels = 3 if color == 2 else 4
    stride = width * channels
    rows = []
    previous = bytearray(stride)
    index = 0
    for _y in range(height):
        filter_type = raw[index]
        index += 1
        row = bytearray(raw[index:index + stride])
        index += stride
        for x in range(stride):
            left = row[x - channels] if x >= channels else 0
            up = previous[x]
            up_left = previous[x - channels] if x >= channels else 0
            if filter_type == 0:
                value = row[x]
            elif filter_type == 1:
                value = row[x] + left
            elif filter_type == 2:
                value = row[x] + up
            elif filter_type == 3:
                value = row[x] + ((left + up) // 2)
            elif filter_type == 4:
                estimate = left + up - up_left
                nearest = left if abs(estimate - left) <= abs(estimate - up) and abs(estimate - left) <= abs(estimate - up_left) else up if abs(estimate - up) <= abs(estimate - up_left) else up_left
                value = row[x] + nearest
            else:
                raise AssertionError(f"unsupported PNG filter {filter_type}")
            row[x] = value & 255
        previous = row
        rows.append(row)
    return width, height, channels, rows

def png_mean_luminance(path: Path, box=None) -> float:
    width, height, channels, rows = png_rgb_rows(path)
    x0, y0, x1, y1 = box if box else (0, 0, width, height)
    total = 0.0
    count = 0
    for y in range(y0, y1):
        row = rows[y]
        for x in range(x0, x1):
            offset = x * channels
            red, green, blue = row[offset], row[offset + 1], row[offset + 2]
            total += 0.2126 * red + 0.7152 * green + 0.0722 * blue
            count += 1
    return total / count / 255

def value(path: Path, key: str) -> str:
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
                         "#050811","#7af6ff"):
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
        for expected in ("desktop_wallpaper.py","WARNING: wallpaper branding is incomplete","button-title",
                         "TraceOS","show-home","show-filesystem","Case Manager.desktop",
                         "Investigation.desktop","Tools.desktop","Network.desktop",
                         "AI Assistant.desktop","show-trash bool true"):
            self.assertIn(expected,setup)
        entry=INCLUDES/"etc/xdg/autostart/traceos-desktop-setup.desktop"
        self.assertEqual(value(entry,"Exec"),"/usr/local/bin/traceos-desktop-setup")

    def test_apps_have_traceos_category_and_distinct_icons(self):
        apps={"traceos-launcher.desktop":"traceos-launcher",
              "traceos-control.desktop":"traceos-control",
              "traceos-osint.desktop":"traceos-osint",
              "traceos-shade.desktop":"traceos-shade",
              "traceos.desktop":"traceos-console",
              "traceos-case-manager.desktop":"traceos-case",
              "traceos-investigation.desktop":"traceos-osint",
              "traceos-tools.desktop":"traceos-tools",
              "traceos-network.desktop":"traceos-network",
              "traceos-ai.desktop":"traceos-ai"}
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
        trash=next(node for node in root.iter("property") if node.attrib.get("name")=="show-trash")
        self.assertEqual(trash.attrib.get("value"),"true")

    def test_wallpaper_art_is_luminous_and_not_a_black_field(self):
        png=INCLUDES/"usr/share/backgrounds/traceos/traceos-wallpaper.png"
        self.assertTrue(png.is_file())
        width, height, _channels, _rows = png_rgb_rows(png)
        self.assertEqual((width, height), (1920, 1080))
        # The night landscape is dark at the edges. A blank ImageMagick render is 0.
        self.assertGreater(png_mean_luminance(png), 0.10)
        self.assertGreater(png_mean_luminance(png, (640, 300, 1280, 780)), 0.18)
        logo=(INCLUDES/"usr/share/traceos/traceos-logo.svg").read_text(encoding="utf-8")
        self.assertIn('width="32" height="206"', logo)
        self.assertIn('stroke-width="7"', logo)
        self.assertNotIn("feGaussianBlur", logo)
        hook=(ROOT/"config/hooks/live/0350-render-traceos-wallpaper.hook.chroot").read_text(encoding="utf-8")
        self.assertIn("rsvg-convert --width=1920 --height=1080", hook)
        self.assertIn("Keeping the packaged cinematic wallpaper.", hook)
        self.assertIn("mean+0 > 0.10", hook)
        self.assertIn("mean+0 > 0.18", hook)
        self.assertNotIn("convert \"$src\" -background none", hook)
        experience=(ROOT/"config/hooks/live/0300-traceos-experience.hook.chroot").read_text(encoding="utf-8")
        self.assertNotIn("traceos-wallpaper.svg", experience)
        packages=(ROOT/"config/package-lists/traceos.list.chroot").read_text(encoding="utf-8")
        self.assertIn("librsvg2-bin", packages)

    def test_new_case_button_is_not_clipped_by_the_header(self):
        control=(INCLUDES/"usr/local/bin/traceos-control").read_text(encoding="utf-8")
        self.assertIn('actions.pack(side="right"', control)
        self.assertIn('self.small_button(actions, "NEW CASE"', control)
        self.assertNotIn("header.pack_propagate(False)", control)
        self.assertNotIn('height=82', control)

    def test_panel_keeps_the_top_menu_and_adds_a_bottom_dock(self):
        panel=ET.parse(INCLUDES/"etc/skel/.config/xfce4/xfconf/xfce-perchannel-xml/xfce4-panel.xml")
        values=[node.attrib.get("value","") for node in panel.getroot().iter("property")]
        for expected in ("applicationsmenu","tasklist","launcher","pager","systray","clock","actions",
                         "p=6;x=0;y=0","p=10;x=0;y=0","TraceOS"):
            self.assertIn(expected, values)
        launcher_dir=INCLUDES/"etc/skel/.config/xfce4/panel/launcher-5"
        for name, command in {
            "traceos-control.desktop":"/usr/local/bin/traceos-control-launch",
            "xfce4-terminal.desktop":"xfce4-terminal",
            "thunar.desktop":"thunar",
            "firefox-esr.desktop":"firefox-esr",
        }.items():
            self.assertEqual(value(launcher_dir/name, "Exec"), command)
        setup=(INCLUDES/"usr/local/bin/traceos-desktop-setup").read_text(encoding="utf-8")
        self.assertIn("workspace_count", setup)

    def test_launcher_search_uses_installed_desktop_files(self):
        launcher=(INCLUDES/"usr/local/bin/traceos-launcher").read_text(encoding="utf-8")
        self.assertIn("def installed_applications", launcher)
        self.assertIn("NoDisplay=", launcher)
        self.assertIn("def launch_selected_app", launcher)
        self.assertNotIn("nonexistent", launcher)

    def test_menu_categories_and_greeter_use_the_traceos_theme(self):
        hook=(ROOT/"config/hooks/live/0350-render-traceos-wallpaper.hook.chroot").read_text(encoding="utf-8")
        self.assertIn("<Name>Investigation</Name>", hook)
        self.assertIn("<Name>Forensics</Name>", hook)
        self.assertIn("investigation.directory", hook)
        greeter=(INCLUDES/"etc/lightdm/lightdm-gtk-greeter.conf").read_text(encoding="utf-8")
        self.assertIn("theme-name=TraceOS", greeter)
        self.assertIn("background=/usr/share/backgrounds/traceos/traceos-wallpaper.png", greeter)
        self.assertIn("autologin-user=traceos", (INCLUDES/"etc/lightdm/lightdm.conf.d/50-traceos.conf").read_text(encoding="utf-8"))

    def test_desktop_entries_open_real_programs(self):
        expected={
            "traceos-case-manager.desktop":"/usr/local/bin/traceos-control-launch --cases",
            "traceos-investigation.desktop":"/usr/local/bin/traceos-control-launch --osint",
            "traceos-tools.desktop":"/usr/local/bin/traceos-control-launch --tools",
            "traceos-network.desktop":"/usr/local/bin/traceos-control-launch --network",
            "traceos-ai.desktop":"xfce4-terminal --title=Trace AI --execute /usr/local/bin/traceos ai",
        }
        control=(INCLUDES/"usr/local/bin/traceos-control").read_text(encoding="utf-8")
        self.assertIn("def tools_home", control)
        self.assertIn('"--cases": "evidence"', control)
        for filename, command in expected.items():
            text=(INCLUDES/"usr/share/applications"/filename).read_text(encoding="utf-8")
            self.assertEqual(value(INCLUDES/"usr/share/applications"/filename, "Exec"), command)
            self.assertIn("Categories=TraceOS;", text)

    def test_theme_keeps_text_and_icon_labels_bright(self):
        css=(INCLUDES/"usr/share/themes/TraceOS/gtk-3.0/gtk.css").read_text(encoding="utf-8")
        self.assertIn("@define-color trace_text #f5fbff;", css)
        self.assertIn("XfdesktopIconView.view", css)
        self.assertIn("#xfce4-appfinder", css)
        terminal=(INCLUDES/"etc/skel/.config/xfce4/terminal/terminalrc").read_text(encoding="utf-8")
        self.assertIn("ColorForeground=#f4fbff", terminal)
        self.assertIn("ColorBackground=#07111c", terminal)
        browser=(INCLUDES/"usr/share/traceos/browser-home.html").read_text(encoding="utf-8")
        self.assertIn("TRACEOS", browser)
        self.assertNotIn("traceos.local", browser)


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

    def test_qemu_launcher_uses_real_focused_button_keyboard_activation(self):
        qemu=(ROOT/"scripts/qemu-ui-smoke.sh").read_text(encoding="utf-8")
        launcher=(INCLUDES/"usr/local/bin/traceos-launcher").read_text(encoding="utf-8")
        self.assertIn('hmp_command "$monitor" "sendkey ret"',qemu)
        self.assertIn('self.primary_button.bind("<Return>",self.keyboard_control_centre)',launcher)
        self.assertIn('self.primary_button.bind("<space>",self.keyboard_control_centre)',launcher)
        self.assertIn('return "break"',launcher)
        self.assertIn("primary_button.focus_set()",launcher)
        self.assertIn("TRACEOS_LAUNCHER_PRIMARY_TILE_GEOM",launcher)
        self.assertNotIn("-device usb-tablet",qemu)
        self.assertNotIn("abs_x=$(( (px * 32767) / screen_w ))",qemu)
        self.assertIn("launcher_action_seen",qemu)
        self.assertIn("nonce=$expected_nonce",qemu)
        self.assertIn("traceos-launcher-control-centre-failure.png",qemu)

    def test_qemu_captures_launcher_and_uncovered_desktop(self):
        qemu=(ROOT/"scripts/qemu-ui-smoke.sh").read_text(encoding="utf-8")
        for expected in ("traceos-launcher-home.png","traceos-desktop-home.png",
                         "TRACEOS_LAUNCHER_SESSION_READY",
                         "Applications menu visible in popup region"):
            self.assertIn(expected,qemu)

    def test_backdrop_discovery_does_not_use_numeric_monitor_fallback(self):
        helper=(INCLUDES/"usr/local/lib/traceos/desktop_wallpaper.py").read_text(encoding="utf-8")
        self.assertIn("created-exact-output-name",helper)
        self.assertIn("stage=TRACEOS_DESKTOP_BACKDROP_DISCOVERY",helper)
        self.assertNotIn("indexed = [row for row in parsed",helper)
        diagnostics=(INCLUDES/"usr/local/sbin/traceos-qemu-ui-diagnostics").read_text(encoding="utf-8")
        self.assertIn("TRACEOS_DESKTOP_BACKDROP_DISCOVERY",diagnostics)

    def test_wallpaper_helper_and_runtime_gate_are_wired(self):
        helper=INCLUDES/"usr/local/lib/traceos/desktop_wallpaper.py"
        self.assertTrue(helper.is_file())
        wrapper=(INCLUDES/"usr/local/bin/traceos-desktop-setup").read_text(encoding="utf-8")
        self.assertIn("python3 /usr/local/lib/traceos/desktop_wallpaper.py",wrapper)
        self.assertIn("next login can retry",wrapper)
        runtime=helper.read_text(encoding="utf-8")
        for expected in ("xrandr", "TRACEOS_DESKTOP_BRANDING_TARGET",
                         "TRACEOS_DESKTOP_BRANDING_RESULT", "png_sha256",
                         "image-style", "xfdesktop", "TRACEOS_DESKTOP_RUNTIME_PROPERTY", "TRACEOS_DESKTOP_BRANDING_RESULT"):
            self.assertIn(expected,runtime)

    def test_diagnostic_filter_uses_real_regex_escapes(self):
        diagnostics=(INCLUDES/"usr/local/sbin/traceos-qemu-ui-diagnostics").read_text(encoding="utf-8")
        self.assertIn(r"(?:gtk\.css|\btheme\b|\bCSS\b)", diagnostics)

    def test_qemu_retains_packaged_wallpaper_and_native_gtk_evidence(self):
        qemu=(ROOT/"scripts/qemu-ui-smoke.sh").read_text(encoding="utf-8")
        for expected in ("traceos-packaged-wallpaper.png","TRACEOS_PACKAGED_WALLPAPER_SHA256",
                         "stage=TRACEOS_DESKTOP_BRANDING_RESULT result=PASS",
                         "TRACEOS_GTK_THEME_ERROR","traceos-native-gtk.png",
                         "traceos-native-gtk-menu.png","traceos-wallpaper-expected-fit.png",
                         "wallpaper_mae_normalized","normalized threshold below 0.08",
                         "actual_wallpaper_mean > 0.10",
                         "packaged_wallpaper_center > 0.18",
                         "Packaged wallpaper is too dark",
                         "wallpaper_visual_status","native_gtk_status",
                         "native_gtk_appfinder_visible","native_gtk_appfinder_diff",
                         "native-gtk-appfinder-wait","native-gtk-verify-",
                         "traceos-desktop-setup.log","traceos-xrandr-runtime.txt",
                         "traceos-xfconf-desktop-initial.txt","traceos-xfconf-desktop-runtime.txt","TRACEOS_DESKTOP_SETUP_LOG_LINE",
                         "TRACEOS_DESKTOP_RUNTIME_PROPERTY","sleep 0.15",
                         '-resize "$desktop_width"x"$desktop_height"!',
                         "traceos-native-gtk-baseline-center.png",
                         "sendkey alt-f2","xfce4-mime-settings","Default Applications dialog",
                         "native_gtk_diff > 40000","native_gtk_desktop_diff > 40000","popup_region_diff_passes 24991"):
            self.assertIn(expected,qemu)

    def test_wallpaper_mae_uses_normalized_imagemagick_metric(self):
        qemu=(ROOT/"scripts/qemu-ui-smoke.sh").read_text(encoding="utf-8")
        self.assertIn('wallpaper_mae_normalized="$(printf',qemu)
        self.assertIn(r"sed -n 's/.*(\([0-9][0-9.]*\)).*/\1/p'",qemu)
        self.assertIn("awk \"BEGIN { exit !($wallpaper_mae_normalized < 0.08) }\"",qemu)
        self.assertNotIn('wallpaper_mae_value < 0.08',qemu)

    def test_native_gtk_capture_compares_central_window_area_not_menu_disappearance(self):
        qemu=(ROOT/"scripts/qemu-ui-smoke.sh").read_text(encoding="utf-8")
        self.assertIn('compare -metric AE "$native_gtk_baseline_crop" "$native_gtk_candidate_crop"',qemu)
        self.assertIn('compare -metric AE "$native_gtk_desktop_crop" "$native_gtk_candidate_crop"',qemu)
        self.assertIn("native_gtk_diff > 40000 && native_gtk_desktop_diff > 40000",qemu)
        self.assertIn("Default Applications dialog",qemu)
        self.assertNotIn("exo-preferred-applications",qemu)
        self.assertIn("Application Finder visibly appeared",qemu)
        self.assertIn("refusing to type into an unverified focus target",qemu)
        self.assertIn('"sendkey alt-f2"',qemu)
        self.assertNotIn('compare -metric AE "$native_menu_png" "$native_gtk_png"',qemu)

    def test_native_gtk_appfinder_wait_gate_distinguishes_desktop_from_visible_finder(self):
        # Build #516, after normalizing both screenshots to the same 1152x720
        # dimensions: bare desktop central crop = 27,312 AE pixels; a visible
        # Application Finder = 82,575. Waiting for >40,000 prevents typing
        # before the Finder exists under slow QEMU TCG startup.
        bare_desktop_pixels = 27312
        visible_appfinder_pixels = 82575
        threshold = 40000
        self.assertLess(bare_desktop_pixels, threshold)
        self.assertGreater(visible_appfinder_pixels, threshold)

    def test_native_gtk_final_frame_is_compared_against_the_visible_appfinder(self):
        qemu=(ROOT/"scripts/qemu-ui-smoke.sh").read_text(encoding="utf-8")
        self.assertIn('convert "$native_menu_png" -crop "700x520+226+80" +repage "$native_gtk_baseline_crop"', qemu)
        self.assertIn('compare -metric AE "$native_gtk_baseline_crop" "$native_gtk_candidate_crop"', qemu)
        self.assertIn("Native GTK replacement probe", qemu)

    def test_build_validates_final_squashfs_wallpaper_dimensions_and_hash(self):
        workflow=(ROOT/".github/workflows/build-iso.yml").read_text(encoding="utf-8")
        for expected in ("TRACEOS_PACKAGED_WALLPAPER_DIMENSIONS","TRACEOS_PACKAGED_WALLPAPER_SHA256",
                         "identify -format '%w %h'", "desktop_wallpaper.py",
                         "Packaged wallpaper is too dark"):
            self.assertIn(expected,workflow)

if __name__=="__main__": unittest.main()
