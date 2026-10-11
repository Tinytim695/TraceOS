import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[1] / "config/includes.chroot/usr/local/lib/traceos"))
from engagement import FORBIDDEN_COMMANDS, PLAYBOOKS, build_playbook, list_playbooks


class EngagementPlaybookTests(unittest.TestCase):
    def test_every_playbook_is_listed_once(self):
        listed = [item["id"] for item in list_playbooks()]
        self.assertEqual(listed, list(PLAYBOOKS))
        self.assertIn("red-web", listed)
        self.assertIn("blue-host-audit", listed)
        self.assertIn("purple-canary", listed)

    def test_web_playbook_excludes_denial_of_service_tags(self):
        steps = build_playbook("red-web", "https://example.test/app")
        nuclei = next(step for step in steps if step["name"] == "Nuclei")
        self.assertIn("-exclude-tags", nuclei["argv"])
        self.assertIn("dos,fuzz,intrusive", nuclei["argv"])
        self.assertNotIn("critical", nuclei["argv"])

    def test_no_playbook_contains_a_flood_tool(self):
        for playbook_id, spec in PLAYBOOKS.items():
            if spec["mode"] == "url":
                target = "https://example.test"
            elif spec["mode"] == "email":
                target = "alice@example.test"
            elif spec["mode"] == "phone":
                target = "+15555550100"
            elif spec["mode"] == "person":
                target = "alice"
            else:
                target = "example.test"
            users = passwords = ""
            service = "ssh"
            if spec["mode"] in {"auth", "crack"}:
                with tempfile.TemporaryDirectory() as directory:
                    users_path = Path(directory) / "users.txt"
                    passwords_path = Path(directory) / "passwords.txt"
                    users_path.write_text("alice\n", encoding="utf-8")
                    passwords_path.write_text("synthetic\n", encoding="utf-8")
                    steps = build_playbook(
                        playbook_id,
                        "10.0.0.5",
                        str(users_path),
                        str(passwords_path),
                        "0" if spec["mode"] == "crack" else service,
                    )
                    if spec["mode"] == "auth":
                        hydra = steps[0]["argv"]
                        self.assertEqual(hydra[:4], ["hydra", "-t", "4", "-f"])
                        self.assertIn("ssh://10.0.0.5", hydra)
                    else:
                        self.assertEqual(steps[0]["argv"][0], "john")
                        self.assertEqual(steps[1]["argv"][:3], ["hashcat", "-m", "0"])
            else:
                steps = build_playbook(
                    playbook_id,
                    target,
                    rule_path="/tmp/purple-canary.yar",
                    canary_path="/tmp/purple-canary.txt",
                )
            for step in steps:
                self.assertNotIn(Path(step["argv"][0]).name, FORBIDDEN_COMMANDS)
                if step["argv"][0] == "masscan":
                    self.assertIn("--rate", step["argv"])
                    self.assertIn("1000", step["argv"])

    def test_password_crack_defaults_to_the_packaged_rockyou_list(self):
        with tempfile.TemporaryDirectory() as directory:
            hashes = Path(directory) / "hashes.txt"
            hashes.write_text("synthetic\n", encoding="utf-8")
            steps = build_playbook("red-password-crack", "", str(hashes), "", "0")
            self.assertEqual(
                steps[0]["argv"],
                ["john", "--wordlist=/usr/share/traceos/wordlists/rockyou.txt", str(hashes)],
            )
            self.assertEqual(steps[1]["argv"][-1], "/usr/share/traceos/wordlists/rockyou.txt")
            bundled = build_playbook(
                "red-password-crack",
                "",
                str(hashes),
                "/usr/share/traceos/wordlists/10k-most-common.txt",
                "1000",
            )
            self.assertIn(
                "--wordlist=/usr/share/traceos/wordlists/10k-most-common.txt",
                bundled[0]["argv"],
            )
            with self.assertRaises(ValueError):
                build_playbook(
                    "red-password-crack",
                    "",
                    str(hashes),
                    "/usr/share/traceos/wordlists/../../etc/passwd",
                    "0",
                )

    def test_credential_audit_rejects_ranges_links_and_unknown_services(self):
        with tempfile.TemporaryDirectory() as directory:
            users = Path(directory) / "users.txt"
            passwords = Path(directory) / "passwords.txt"
            users.write_text("alice\n", encoding="utf-8")
            passwords.write_text("synthetic\n", encoding="utf-8")
            with self.assertRaises(ValueError):
                build_playbook("red-credential-audit", "10.0.0.0/24", str(users), str(passwords))
            link = Path(directory) / "linked.txt"
            link.symlink_to(passwords)
            with self.assertRaises(ValueError):
                build_playbook("red-credential-audit", "10.0.0.5", str(users), str(link))
            with self.assertRaises(ValueError):
                build_playbook("red-credential-audit", "10.0.0.5", str(users), str(passwords), "all")

    def test_tls_and_recon_targets_stay_scoped(self):
        with self.assertRaises(ValueError):
            build_playbook("red-tls", "https://user:secret@example.test")
        with self.assertRaises(ValueError):
            build_playbook("red-external-recon", "https://example.test")
        recon = build_playbook("red-external-recon", "example.test")
        self.assertEqual(recon[0]["argv"][:3], ["subfinder", "-d", "example.test"])
        self.assertEqual(recon[-1]["argv"][-1], "https://example.test")
        ports = build_playbook("red-port-scan", "10.0.0.5")
        self.assertEqual(
            ports[1]["argv"],
            ["masscan", "10.0.0.5", "-p", "1-1024", "--rate", "1000", "--wait", "2"],
        )

    def test_people_osint_commands_match_the_installed_tools(self):
        username = build_playbook("osint-username", "alice")
        self.assertEqual(username[0]["argv"][:2], ["sherlock", "alice"])
        self.assertEqual(username[1]["argv"], ["maigret", "alice"])
        self.assertEqual(username[2]["argv"], ["blackbird", "--username", "alice"])
        email = build_playbook("osint-email", "alice@example.test")
        self.assertEqual(email[0]["argv"], ["holehe", "alice@example.test"])
        self.assertEqual(email[1]["argv"], ["h8mail", "-t", "alice@example.test"])
        self.assertEqual(email[2]["argv"], ["blackbird", "--email", "alice@example.test"])
        phone = build_playbook("osint-phone", "+15555550100")
        self.assertEqual(phone[0]["argv"], ["phoneinfoga", "scan", "-n", "+15555550100"])
        with self.assertRaises(ValueError):
            build_playbook("osint-email", "alice")
        with self.assertRaises(ValueError):
            build_playbook("osint-phone", "alice")

    def test_local_blue_and_purple_need_no_network_target(self):
        blue = build_playbook("blue-detection")
        self.assertEqual(blue[0]["argv"][:2], ["suricata", "-T"])
        self.assertEqual(blue[1]["argv"][:4], ["tcpdump", "-i", "any", "-c"])
        purple = build_playbook(
            "purple-canary",
            rule_path="/usr/share/traceos/rules/purple-canary.yar",
            canary_path="/tmp/case/notes/purple-canary.txt",
        )
        self.assertEqual(
            purple[0]["argv"],
            ["yara", "/usr/share/traceos/rules/purple-canary.yar", "/tmp/case/notes/purple-canary.txt"],
        )

    def test_secret_list_cannot_be_a_fifo(self):
        with tempfile.TemporaryDirectory() as directory:
            users = Path(directory) / "users.txt"
            passwords = Path(directory) / "passwords.fifo"
            users.write_text("alice\n", encoding="utf-8")
            os.mkfifo(passwords, 0o600)
            self.assertTrue(stat.S_ISFIFO(passwords.stat().st_mode))
            with self.assertRaises(ValueError):
                build_playbook("red-credential-audit", "10.0.0.5", str(users), str(passwords))


if __name__ == "__main__":
    unittest.main(verbosity=2)
