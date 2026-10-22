from __future__ import annotations

import ast
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
HOOK = ROOT / "config/hooks/live/0270-traceos-redteam-depth.hook.chroot"
CONTROL = ROOT / "config/includes.chroot/usr/local/bin/traceos-control"
VALIDATOR = ROOT / "scripts/validate-toolchain.sh"

PINS = {
    "adalanche": "1f2b0765df54362f886d3089e5263994ec5fb6d1bea666c84af4620069bfedb5",
    "ldeep": "ldeep==2.0.3",
    "sliver-client": "a1bfe9ee9807017b83689384d9a169db497643d5b2385d24a942d6d05c5ef701",
    "sliver-server": "e70ae77590f5f0a8aafe8e11685f2cd17b11e0e02d37534412b99a411fd6e3e0",
    "azurehound": "b814116a9850658ef36be54c3f8e2d1560a0560ca377052206defac064e5a68d",
    "lsassy": "3.1.16",
    "pretender": "c6d359a95211f2d5f2e87c4bd17cab183971aa82b889a45d64f46b4bf434916e",
    "ligolo-proxy": "6c683c403502d366276595197749e620c975908dae7314c21079ec8ebee4e5d0",
    "ligolo-agent": "714534917a4a58812669619667cc57dfad03d34d0de5b0d7c468d76819f84111",
    "bloodyAD": "2.5.5",
    "coercer": "2.4.3",
    "mitm6": "0.3.0",
    "pre2k": "7b9b86fdbc9c13a1ab962e1e5ab5633b778e81cf",
    "sccmhunter": "274ff48a1b56870d713e5bd029dcf2c1abbb71b8",
}

CONSOLES = {
    "Adalanche Console": "adalanche",
    "ldeep Console": "ldeep",
    "Pretender Console": "pretender",
    "Ligolo Proxy Console": "ligolo-proxy",
    "Ligolo Agent Console": "ligolo-agent",
    "bloodyAD Console": "bloodyAD",
    "Coercer Console": "coercer",
    "mitm6 Console": "mitm6",
    "pre2k Console": "pre2k",
    "SCCMHunter Console": "sccmhunter.py",
    "Sliver Client Console": "sliver-client",
    "Sliver Server Console": "sliver-server",
    "AzureHound Console": "azurehound",
    "lsassy Console": "lsassy",
}


class RedTeamDepthTests(unittest.TestCase):
    def test_hook_pins_checksums_and_commits(self):
        text = HOOK.read_text(encoding="utf-8")
        self.assertTrue(text.startswith("#!/bin/sh\n"))
        for name, pin in PINS.items():
            with self.subTest(name=name):
                self.assertIn(pin, text)
        self.assertIn("redteam-depth-tools.txt", text)
        self.assertNotIn("{target}", text)

    def test_validator_requires_the_new_commands(self):
        text = VALIDATOR.read_text(encoding="utf-8")
        for command in CONSOLES.values():
            with self.subTest(command=command):
                self.assertIn(command, text)

    def test_control_centre_opens_help_not_a_target(self):
        module = ast.parse(CONTROL.read_text(encoding="utf-8"))
        specs = None
        for node in module.body:
            if isinstance(node, ast.Assign) and any(
                isinstance(target, ast.Name) and target.id == "ASSESSMENT_TOOL_SPECS"
                for target in node.targets
            ):
                specs = ast.literal_eval(node.value)
        self.assertIsNotNone(specs)
        for name, command in CONSOLES.items():
            with self.subTest(name=name):
                spec = specs[name]
                self.assertEqual(spec["command"], command)
                self.assertEqual(spec["mode"], "launch")
                self.assertTrue(spec["replace"])
                self.assertEqual(spec["argv"][0], "bash")
                self.assertNotIn("{target}", spec["argv"])
                self.assertNotIn("-u", " ".join(spec["argv"]))


if __name__ == "__main__":
    unittest.main()
