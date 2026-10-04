import importlib.util
import pathlib
import unittest
from unittest import mock


MODULE = pathlib.Path(__file__).parents[1] / "config/includes.chroot/usr/local/lib/traceos/investigation.py"


def load_module():
    spec = importlib.util.spec_from_file_location("traceos_investigation", MODULE)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


class InvestigationAdapterTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mod = load_module()

    def test_inventory_is_read_only_and_reports_availability(self):
        with mock.patch.object(self.mod.shutil, "which", side_effect=lambda command: "/usr/bin/" + command if command in {"whois", "dig"} else None):
            inventory = self.mod.inventory()
        available = {spec.key: present for spec, present in inventory}
        self.assertTrue(available["whois"])
        self.assertTrue(available["dns"])
        self.assertFalse(available["nmap"])

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
