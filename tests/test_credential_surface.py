from __future__ import annotations

import ast
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
HOOK = ROOT / "config/hooks/live/0280-traceos-credential-defence.hook.chroot"
CONTROL = ROOT / "config/includes.chroot/usr/local/bin/traceos-control"
VALIDATOR = ROOT / "scripts/validate-toolchain.sh"

PINS = (
    "029b182e0ed35fd5b02cd1eadc2a94bd457ab14ad22a9380b6e5d9652261d28d",
    "013b06f1f29271150585cb35d2a150929871126f51715744714ad5843179f57c",
    "fc25f1eafbbff3e858d8dfba508d5e227bb56ef4dccc4d5cd0bbd6e49798cb4f",
    "05d1031f537e830b76da53bae2400c5814c89165",
    "96cb5115f495024a478b0e9f9f77f9027058155589235fbd4c50e7382055fcca",
    "8ae0416d85336a1aea6883920ae9c2751a98538fe0bb624822e92934d3be5592",
    "b4699d7ecfd5c0d656d86379e41f0eb34b0f12c3cb45398f1e747f10844d7930",
    "pypykatz==0.6.13",
    "donpapi==2.0.1",
    "21af4f9b0899bebb8f0b6dd4c0839eec33d2bb19",
)


def _assignments(tree: ast.AST) -> dict:
    found = {}
    for node in tree.body:
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id in {
                    "CREDENTIAL_TOOL_SPECS",
                    "DEFENCE_TOOL_SPECS",
                    "OSINT_TOOL_COMMANDS",
                }:
                    found[target.id] = ast.literal_eval(node.value)
    return found


class CredentialSurfaceTests(unittest.TestCase):
    def test_hook_pins_are_present(self):
        text = HOOK.read_text(encoding="utf-8")
        control = CONTROL.read_text(encoding="utf-8")
        self.assertTrue(text.startswith("#!/bin/sh\n"))
        self.assertIn("--no-verification", control)
        self.assertNotIn("velociraptor frontend", text)
        self.assertNotIn("systemctl enable", text)
        self.assertNotIn("systemctl start", text)
        self.assertIn("osqueryd.service", text)
        self.assertIn("filedialog.askdirectory", control)
        self.assertIn("ExifTool version", text)
        self.assertNotIn("exiftool ExifTool -h", text)
        for pin in PINS:
            with self.subTest(pin=pin[:12]):
                self.assertIn(pin, text)

    def test_validator_requires_the_new_commands(self):
        text = VALIDATOR.read_text(encoding="utf-8")
        for command in (
            "trufflehog",
            "noseyparker",
            "pypykatz",
            "donpapi",
            "chainsaw",
            "capa",
            "osqueryi",
            "velociraptor",
            "exiftool",
            "cloud_enum",
        ):
            with self.subTest(command=command):
                self.assertIn(command, text)

    def test_dashboard_actions_are_scoped(self):
        tree = ast.parse(CONTROL.read_text(encoding="utf-8"))
        specs = _assignments(tree)
        credentials = specs["CREDENTIAL_TOOL_SPECS"]
        defence = specs["DEFENCE_TOOL_SPECS"]
        self.assertEqual(credentials["TruffleHog Folder"]["argv"][2:4], ["--no-update", "--no-verification"])
        self.assertEqual(credentials["DonPAPI Console"]["mode"], "launch")
        self.assertTrue(credentials["DonPAPI Console"]["replace"])
        self.assertNotIn("collect", credentials["DonPAPI Console"]["argv"])
        self.assertEqual(defence["Chainsaw Sigma Hunt"]["mode"], "directory")
        self.assertIn("/opt/traceos-sigma/rules/windows", defence["Chainsaw Sigma Hunt"]["argv"])
        self.assertEqual(defence["Velociraptor Host Identity"]["mode"], "local")
        self.assertNotIn("frontend", defence["Velociraptor Host Identity"]["argv"])
        self.assertEqual(defence["osquery Process Sample"]["mode"], "local")
        self.assertEqual(specs["OSINT_TOOL_COMMANDS"]["Cloud Enum"], "cloud_enum")
        self.assertIn("READ METADATA", CONTROL.read_text(encoding="utf-8"))
        self.assertIn("def credentials", CONTROL.read_text(encoding="utf-8"))

    def test_directory_target_rejects_a_file_and_an_option(self):
        source = CONTROL.read_text(encoding="utf-8")
        tree = ast.parse(source)
        wanted = {}
        for node in tree.body:
            if isinstance(node, ast.FunctionDef) and node.name in {
                "_existing_directory",
                "normalize_catalog_target",
            }:
                wanted[node.name] = node
        namespace = {"Path": Path}
        for name in ("_existing_directory", "normalize_catalog_target"):
            exec(compile(ast.Module(body=[wanted[name]], type_ignores=[]), str(CONTROL), "exec"), namespace)
        with tempfile.TemporaryDirectory() as directory:
            folder = Path(directory) / "logs"
            folder.mkdir()
            secret = folder / "note.txt"
            secret.write_text("not a directory\n", encoding="utf-8")
            self.assertEqual(namespace["normalize_catalog_target"]("directory", str(folder)), str(folder))
            with self.assertRaises(ValueError):
                namespace["normalize_catalog_target"]("directory", str(secret))
        with self.assertRaises(ValueError):
            namespace["normalize_catalog_target"]("directory", "-rf")


if __name__ == "__main__":
    unittest.main()
