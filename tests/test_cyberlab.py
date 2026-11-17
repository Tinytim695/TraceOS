from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MODULE = ROOT / "config/includes.chroot/usr/local/lib/traceos/cyberlab.py"
SPEC = importlib.util.spec_from_file_location("traceos_cyberlab", MODULE)
assert SPEC and SPEC.loader
cyberlab = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = cyberlab
SPEC.loader.exec_module(cyberlab)


class CyberLabHostDetectionTests(unittest.TestCase):
    def test_meminfo_parses_total_and_available(self):
        total, available = cyberlab.parse_meminfo(
            "MemTotal:       16384000 kB\nMemAvailable:    8192000 kB\n"
        )
        self.assertEqual(total, 16384000 * 1024)
        self.assertEqual(available, 8192000 * 1024)

    def test_meminfo_falls_back_to_memfree(self):
        total, available = cyberlab.parse_meminfo(
            "MemTotal:       4096000 kB\nMemFree:        1024000 kB\n"
        )
        self.assertEqual(total, 4096000 * 1024)
        self.assertEqual(available, 1024000 * 1024)

    def test_meminfo_rejects_impossible_available_memory(self):
        self.assertEqual(
            cyberlab.parse_meminfo("MemTotal: 100 kB\nMemAvailable: 200 kB\n"),
            (0, 0),
        )

    def test_cpu_virtualization_flags_are_architecture_aware(self):
        self.assertTrue(
            cyberlab.parse_cpu_virtualization("flags : fpu vmx sse4_2\n", "x86_64")
        )
        self.assertTrue(
            cyberlab.parse_cpu_virtualization("Features : fp simd virt\n", "aarch64")
        )
        self.assertFalse(
            cyberlab.parse_cpu_virtualization("flags : fpu sse2\n", "x86_64")
        )

    def test_resource_profiles_are_conservative(self):
        gib = cyberlab.GIB
        self.assertEqual(cyberlab.classify_resource_profile(4 * gib, 2, 12 * gib), "lightweight")
        self.assertEqual(cyberlab.classify_resource_profile(8 * gib, 4, 30 * gib), "portable")
        self.assertEqual(cyberlab.classify_resource_profile(16 * gib, 6, 60 * gib), "standard")
        self.assertEqual(cyberlab.classify_resource_profile(32 * gib, 8, 100 * gib), "full")
        self.assertEqual(cyberlab.classify_resource_profile(2 * gib, 2, 8 * gib), "limited")


class CyberLabIsolationTests(unittest.TestCase):
    def test_default_policy_fails_closed_until_snapshot_exists(self):
        result = cyberlab.evaluate_isolation(cyberlab.LabIsolationPolicy())
        self.assertFalse(result.allowed)
        self.assertIn("A clean rollback snapshot is required before launch.", result.findings)

    def test_network_free_policy_passes_after_snapshot(self):
        result = cyberlab.evaluate_isolation(
            cyberlab.LabIsolationPolicy(snapshot_present=True)
        )
        self.assertTrue(result.allowed)
        self.assertEqual(result.findings, ())
        self.assertEqual(cyberlab.qemu_no_network_args(), ["-nic", "none"])

    def test_each_host_escape_path_is_rejected(self):
        unsafe_fields = (
            "external_uplink",
            "nat_enabled",
            "bridged_network",
            "host_port_forwarding",
            "host_route",
            "dns_forwarding",
            "shared_host_paths",
            "clipboard_sharing",
            "usb_passthrough",
            "host_device_passthrough",
        )
        for field in unsafe_fields:
            with self.subTest(field=field):
                result = cyberlab.evaluate_isolation(
                    cyberlab.LabIsolationPolicy(
                        snapshot_present=True,
                        **{field: True},
                    )
                )
                self.assertFalse(result.allowed, field)

    def test_unknown_network_mode_is_rejected(self):
        result = cyberlab.evaluate_isolation(
            cyberlab.LabIsolationPolicy(
                network_mode="user",
                snapshot_present=True,
            )
        )
        self.assertFalse(result.allowed)
        self.assertIn("Unsupported network mode.", result.findings)

    def test_private_network_requires_cyberlab_owned_identifier(self):
        valid = cyberlab.LabIsolationPolicy(
            network_mode="private_internal",
            snapshot_present=True,
            network_owner="cyberlab",
            network_id="cyberlab-12abcdef",
        )
        self.assertTrue(cyberlab.evaluate_isolation(valid).allowed)

        invalid = cyberlab.LabIsolationPolicy(
            network_mode="private_internal",
            snapshot_present=True,
            network_owner="host",
            network_id="br0",
        )
        self.assertFalse(cyberlab.evaluate_isolation(invalid).allowed)

    def test_private_network_cannot_have_an_external_uplink(self):
        policy = cyberlab.LabIsolationPolicy(
            network_mode="private_internal",
            snapshot_present=True,
            network_owner="cyberlab",
            network_id="cyberlab-12abcdef",
            external_uplink=True,
        )
        result = cyberlab.evaluate_isolation(policy)
        self.assertFalse(result.allowed)
        self.assertIn("External uplink is prohibited.", result.findings)

    def test_snapshot_requirement_cannot_be_disabled(self):
        result = cyberlab.evaluate_isolation(
            cyberlab.LabIsolationPolicy(
                snapshot_required=False,
                snapshot_present=True,
            )
        )
        self.assertFalse(result.allowed)
        self.assertIn(
            "The clean rollback snapshot requirement cannot be disabled.",
            result.findings,
        )

    def test_network_free_policy_cannot_reference_a_network(self):
        policy = cyberlab.LabIsolationPolicy(
            snapshot_present=True,
            network_owner="cyberlab",
            network_id="cyberlab-12abcdef",
        )
        self.assertFalse(cyberlab.evaluate_isolation(policy).allowed)


class CyberLabPresentationTests(unittest.TestCase):
    def test_report_is_honest_about_unimplemented_launch(self):
        report = cyberlab.HostCapabilities(
            operating_mode="live_usb",
            architecture="x86_64",
            cpu_cores=4,
            total_ram_bytes=8 * cyberlab.GIB,
            available_ram_bytes=4 * cyberlab.GIB,
            free_storage_bytes=32 * cyberlab.GIB,
            storage_path="/media/lab",
            qemu_binary=None,
            qemu_version=None,
            kvm_device_present=False,
            kvm_accessible=False,
            cpu_virtualization=True,
            resource_profile="portable",
            warnings=("qemu-system-x86_64 is not installed.",),
        )
        text = cyberlab.format_capability_report(report)
        self.assertIn("Basic prerequisites:  INCOMPLETE", text)
        self.assertIn("VM launch remains disabled", text)
        self.assertIn("No host network settings are modified.", text)

    def test_control_centre_exposes_cyberlab_page(self):
        source = (
            ROOT / "config/includes.chroot/usr/local/bin/traceos-control"
        ).read_text(encoding="utf-8")
        self.assertIn('("CyberLab", self.cyberlab_page)', source)
        self.assertIn('"cyberlab": self.cyberlab_page', source)
        self.assertIn("def cyberlab_page(self)", source)
        page = source.split("def cyberlab_page(self)", 1)[1].split("\n    def ", 1)[0]
        self.assertIn("inspect_storage()", page)
        self.assertNotIn("prepare_storage(", page)
        self.assertNotIn("import_local_clone(", page)
        self.assertNotIn("serve_clone_loopback(", page)
        self.assertIn('"PREPARE STORAGE"', source)
        self.assertIn('"IMPORT WEBSITE"', source)
        self.assertIn('"IMPORT APP"', source)


class CyberLabOfflineCloneTests(unittest.TestCase):
    def setUp(self):
        self._tmp = __import__("tempfile").TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.root = Path(self._tmp.name)
        self.storage = self.root / "lab"
        self.source = self.root / "site"
        self.source.mkdir()
        (self.source / "index.html").write_text("<h1>offline</h1>\n", encoding="utf-8")
        nested = self.source / "assets"
        nested.mkdir()
        (nested / "app.js").write_text("console.log('local');\n", encoding="utf-8")

    def test_storage_inspection_does_not_create_directories(self):
        status = cyberlab.inspect_storage(self.storage)
        self.assertFalse(status.prepared)
        self.assertFalse(self.storage.exists())
        self.assertIn("has not been prepared", status.findings[0])

    def test_prepare_storage_is_private_and_rejects_system_roots(self):
        status = cyberlab.prepare_storage(self.storage)
        self.assertTrue(status.prepared)
        self.assertEqual(status.sandbox_count, 0)
        for name in ("golden", "overlays", "evidence", "sandboxes"):
            child = self.storage / name
            self.assertTrue(child.is_dir())
            self.assertEqual(child.stat().st_mode & 0o777, 0o700)
        self.assertEqual(self.storage.stat().st_mode & 0o777, 0o700)
        with self.assertRaises(cyberlab.CyberLabError):
            cyberlab.prepare_storage(Path("/tmp"))

    def test_local_website_clone_never_needs_a_network(self):
        cyberlab.prepare_storage(self.storage)
        manifest = cyberlab.import_local_clone(
            self.source,
            kind="website",
            name="demo-shop",
            origin_label="https://shop.example/admin",
            storage_path=self.storage,
        )
        self.assertEqual(manifest.kind, "website")
        self.assertEqual(manifest.name, "demo-shop")
        self.assertEqual(manifest.file_count, 2)
        self.assertEqual(manifest.bind_host, "127.0.0.1")
        self.assertEqual(manifest.execution, "stored_only")
        copied = Path(manifest.path) / "content" / "index.html"
        self.assertEqual(copied.read_text(encoding="utf-8"), "<h1>offline</h1>\n")
        self.assertEqual(copied.stat().st_mode & 0o777, 0o600)
        inventory = cyberlab.list_sandboxes(self.storage)
        self.assertEqual(len(inventory.manifests), 1)
        report = cyberlab.format_sandbox_report(
            cyberlab.inspect_storage(self.storage), inventory
        )
        self.assertIn("URLs are not fetched", report)
        self.assertIn("served=no", report)
        self.assertIn(manifest.sandbox_id, report)

    def test_symlink_clone_is_rejected_without_leaving_a_sandbox(self):
        cyberlab.prepare_storage(self.storage)
        outside = self.root / "secret.txt"
        outside.write_text("secret", encoding="utf-8")
        (self.source / "leak").symlink_to(outside)
        with self.assertRaises(cyberlab.CyberLabError):
            cyberlab.import_local_clone(
                self.source,
                kind="app",
                name="app",
                storage_path=self.storage,
            )
        self.assertEqual(list((self.storage / "sandboxes").iterdir()), [])

    def test_origin_and_non_loopback_targets_are_rejected(self):
        cyberlab.prepare_storage(self.storage)
        manifest = cyberlab.import_local_clone(
            self.source,
            kind="app",
            name="app",
            origin_label="https://shop.example/login",
            storage_path=self.storage,
        )
        allowed = cyberlab.evaluate_test_target(manifest, "127.0.0.1")
        self.assertTrue(allowed.allowed)
        self.assertTrue(cyberlab.evaluate_test_target(manifest, "localhost").allowed)
        for host in ("shop.example", "www.shop.example", "8.8.8.8", "0.0.0.0", ""):
            with self.subTest(host=host):
                self.assertFalse(cyberlab.evaluate_test_target(manifest, host).allowed)
        with self.assertRaises(cyberlab.CyberLabError):
            cyberlab.assert_loopback_bind("0.0.0.0")

    def test_loopback_server_serves_the_clone_only(self):
        cyberlab.prepare_storage(self.storage)
        manifest = cyberlab.import_local_clone(
            self.source,
            kind="website",
            name="site",
            origin_label="https://shop.example",
            storage_path=self.storage,
        )
        server = cyberlab.serve_clone_loopback(manifest)
        self.addCleanup(server.close)
        self.assertTrue(server.url.startswith("http://127.0.0.1:"))
        self.assertEqual(server.httpd.socket.getsockname()[0], "127.0.0.1")
        import time
        import urllib.error
        import urllib.request

        deadline = time.time() + 2
        body = b""
        last_error: Exception | None = None
        while time.time() < deadline:
            try:
                with urllib.request.urlopen(server.url + "index.html", timeout=1) as response:
                    body = response.read()
                    self.assertEqual(response.headers["X-TraceOS-Sandbox"], manifest.sandbox_id)
                break
            except (OSError, urllib.error.URLError) as exc:
                last_error = exc
                time.sleep(0.05)
        else:
            raise AssertionError(last_error)
        self.assertEqual(body, b"<h1>offline</h1>\n")
        import http.client

        port = int(server.httpd.server_address[1])
        connection = http.client.HTTPConnection("127.0.0.1", port, timeout=2)
        connection.request("GET", "/../secret")
        denied = connection.getresponse()
        denied.read()
        self.assertEqual(denied.status, 400)
        connection.close()


if __name__ == "__main__":
    unittest.main()
