import importlib.util
import os
import pathlib
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


MODULE = pathlib.Path(__file__).parents[1] / "config/includes.chroot/usr/local/lib/traceos/investigation.py"


def load_module():
    spec = importlib.util.spec_from_file_location("traceos_investigation", MODULE)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class InvestigationAdapterTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mod = load_module()
        cls.repo = pathlib.Path(__file__).parents[1]
        cls.osint_launcher = cls.repo / "config/includes.chroot/usr/local/bin/traceos-osint"
        cls.traceos_cli = cls.repo / "config/includes.chroot/usr/local/bin/traceos"

    def test_basic_lookup_builder_accepts_domain_and_ip(self):
        self.assertEqual(
            self.mod.build_basic_lookup_command("whois", "example.com"),
            ["whois", "example.com"],
        )
        self.assertEqual(
            self.mod.build_basic_lookup_command("dns", "127.0.0.1"),
            ["dig", "127.0.0.1"],
        )
        self.assertEqual(
            self.mod.build_basic_lookup_command("dns", "2001:db8::1"),
            ["dig", "2001:db8::1"],
        )
        self.assertEqual(
            self.mod.build_basic_lookup_command("whois", "münich.example"),
            ["whois", "xn--mnich-kva.example"],
        )

    def test_basic_lookup_builder_rejects_unsafe_or_malformed_targets(self):
        invalid = (
            "-example.com",
            "example.com other",
            "http://example.com",
            "user:pass@example.com",
            "example.com/path",
            "example.com?query=1",
            "example.com#fragment",
            "bad..example",
            "bad_label.example",
            "example.com\x00",
        )
        for target in invalid:
            with self.subTest(target=target):
                with self.assertRaises(ValueError):
                    self.mod.build_basic_lookup_command("whois", target)

        with self.assertRaises(ValueError):
            self.mod.build_basic_lookup_command("unsupported", "example.com")

    def test_basic_lookup_request_factory_normalizes_and_sets_scope(self):
        request = self.mod.create_basic_lookup_request(
            "whois",
            "münich.example",
            authorization_state="CONFIRMED",
            case_id="CASE-123",
            timeout_seconds=42,
        )
        self.assertEqual(request.adapter_key, "whois")
        self.assertEqual(request.target, "xn--mnich-kva.example")
        self.assertEqual(request.scope.mode, "passive_lookup")
        self.assertEqual(request.scope.target, "xn--mnich-kva.example")
        self.assertEqual(request.authorization_state, "CONFIRMED")
        self.assertEqual(request.case_id, "CASE-123")
        self.assertEqual(request.timeout_seconds, 42)

    def test_basic_lookup_request_factory_rejects_invalid_target(self):
        with self.assertRaises(ValueError):
            self.mod.create_basic_lookup_request(
                "dns",
                "http://example.com",
                authorization_state="CONFIRMED",
            )

    def test_basic_lookup_adapters_expose_expected_contract(self):
        whois = self.mod.get_adapter("whois")
        dns = self.mod.get_adapter("dns")
        self.assertEqual(
            (whois.key, whois.command, whois.network, whois.version_argv()),
            ("whois", "whois", True, ["whois", "--version"]),
        )
        self.assertEqual(
            (dns.key, dns.command, dns.network, dns.version_argv()),
            ("dns", "dig", True, ["dig", "-v"]),
        )

    def test_basic_lookup_adapter_metadata_is_immutable(self):
        adapter = self.mod.get_adapter("whois")
        with self.assertRaises(AttributeError):
            adapter.command = "nmap"

    def test_inventory_is_read_only_and_reports_availability(self):
        with mock.patch.object(self.mod.shutil, "which", side_effect=lambda command: "/usr/bin/" + command if command in {"whois", "dig"} else None):
            inventory = self.mod.inventory()
        available = {spec.key: present for spec, present in inventory}
        self.assertTrue(available["whois"])
        self.assertTrue(available["dns"])
        self.assertFalse(available["nmap"])

    def _fake_tool(self, directory: pathlib.Path, name: str) -> pathlib.Path:
        script = directory / name
        script.write_text(
            "#!/bin/sh\n"
            "set -eu\n"
            'printf \'%s\\n\' "$@" > "$TRACEOS_TEST_LOG"\n',
            encoding="utf-8",
        )
        script.chmod(stat.S_IRWXU)
        return script

    def test_shell_launcher_interactive_whois_dns_and_list_dispatch(self):
        with tempfile.TemporaryDirectory() as temp:
            root = pathlib.Path(temp)
            log = root / "argv.txt"
            self._fake_tool(root, "whois")
            self._fake_tool(root, "dig")
            env = os.environ.copy()
            env["PATH"] = f"{root}{os.pathsep}{env['PATH']}"
            env["TRACEOS_TEST_LOG"] = str(log)

            result = subprocess.run(
                ["bash", str(self.osint_launcher)],
                input="5\nexample.com\n",
                text=True,
                capture_output=True,
                env=env,
                timeout=10,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(log.read_text(encoding="utf-8").splitlines(), ["example.com"])

            log.unlink()
            result = subprocess.run(
                ["bash", str(self.osint_launcher)],
                input="6\nexample.com\n",
                text=True,
                capture_output=True,
                env=env,
                timeout=10,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(log.read_text(encoding="utf-8").splitlines(), ["example.com"])

            log.unlink()
            result = subprocess.run(
                ["bash", str(self.osint_launcher)],
                input="7\n",
                text=True,
                capture_output=True,
                env=env,
                timeout=10,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertFalse(log.exists())

    def test_shell_launcher_preserves_target_as_one_argument(self):
        with tempfile.TemporaryDirectory() as temp:
            root = pathlib.Path(temp)
            log = root / "argv.txt"
            self._fake_tool(root, "whois")
            env = os.environ.copy()
            env["PATH"] = f"{root}{os.pathsep}{env['PATH']}"
            env["TRACEOS_TEST_LOG"] = str(log)
            target = "$(touch /tmp/traceos-shell-should-not-exist)"
            marker = pathlib.Path("/tmp/traceos-shell-should-not-exist")
            marker.unlink(missing_ok=True)

            result = subprocess.run(
                ["bash", str(self.osint_launcher), "whois", target],
                text=True,
                capture_output=True,
                env=env,
                timeout=10,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(log.read_text(encoding="utf-8").splitlines(), [target])
            self.assertFalse(marker.exists())

    def test_traceos_python_cli_routes_whois_and_dns_without_external_lookup(self):
        with tempfile.TemporaryDirectory() as temp:
            root = pathlib.Path(temp)
            log = root / "argv.txt"
            self._fake_tool(root, "whois")
            self._fake_tool(root, "dig")
            env = os.environ.copy()
            env["HOME"] = str(root / "home")
            env["XDG_CONFIG_HOME"] = str(root / "home" / ".config")
            env["PATH"] = f"{root}{os.pathsep}{env['PATH']}"
            env["TRACEOS_TEST_LOG"] = str(log)

            for tool in ("whois", "dig"):
                log.unlink(missing_ok=True)
                result = subprocess.run(
                    [sys.executable, str(self.traceos_cli), "osint", tool, "example.com"],
                    text=True,
                    capture_output=True,
                    env=env,
                    timeout=15,
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(log.read_text(encoding="utf-8").splitlines(), ["example.com"])

            log.unlink(missing_ok=True)
            result = subprocess.run(
                [sys.executable, str(self.traceos_cli), "osint", "whois", "-example.com"],
                text=True,
                capture_output=True,
                env=env,
                timeout=15,
            )
            self.assertEqual(result.returncode, 2)
            self.assertIn("Invalid whois target", result.stderr)
            self.assertFalse(log.exists())

    def test_traceos_python_cli_interactive_whois_dispatch(self):
        with tempfile.TemporaryDirectory() as temp:
            root = pathlib.Path(temp)
            log = root / "argv.txt"
            self._fake_tool(root, "whois")
            env = os.environ.copy()
            env["HOME"] = str(root / "home")
            env["XDG_CONFIG_HOME"] = str(root / "home" / ".config")
            env["PATH"] = f"{root}{os.pathsep}{env['PATH']}"
            env["TRACEOS_TEST_LOG"] = str(log)

            result = subprocess.run(
                [sys.executable, str(self.traceos_cli), "osint"],
                input="5\nexample.com\n",
                text=True,
                capture_output=True,
                env=env,
                timeout=15,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(log.read_text(encoding="utf-8").splitlines(), ["example.com"])

    def test_run_uses_argv_without_shell_and_preserves_timeout(self):
        completed = mock.Mock(returncode=0, stdout="ok\n", stderr="")
        with mock.patch.object(self.mod.subprocess, "run", return_value=completed) as run:
            result = self.mod.run(self.mod.ToolSpec("fake", "tool", "test"), ["--safe"], timeout=17)
        self.assertIs(result, completed)
        run.assert_called_once_with(
            ["tool", "--safe"],
            capture_output=True,
            text=True,
            check=False,
            timeout=17,
            shell=False,
        )


if __name__ == "__main__":
    unittest.main()
