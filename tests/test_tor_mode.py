from __future__ import annotations

import os
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
LIB = ROOT / "config/includes.chroot/usr/local/lib/traceos"
sys.path.insert(0, str(LIB))
import tor_mode


def ready(**overrides):
    base = {
        "requested": "on",
        "default_route": True,
        "table_present": True,
        "filter_policy_drop": True,
        "redirect_trans": True,
        "redirect_dns": True,
        "trans_listening": True,
        "dns_listening": True,
        "tor_running": True,
        "bootstrap": 100,
    }
    base.update(overrides)
    return base


class TorModeTests(unittest.TestCase):
    def test_rules_redirect_tcp_and_drop_everything_else(self):
        rules = tor_mode.render_nft()
        self.assertIn("policy drop", rules)
        self.assertIn("redirect to :9040", rules)
        self.assertIn("redirect to :5353", rules)
        self.assertIn('meta skuid "debian-tor"', rules)
        self.assertIn("udp dport 67", rules)
        self.assertNotIn("ct state established", rules)
        self.assertIn("delete table inet traceos_tor", rules)

    def test_normal_route_is_not_described_as_protected(self):
        result = tor_mode.decide_status({"requested": "off", "default_route": True, "table_present": False})
        self.assertEqual(result["status"], "normal")
        self.assertEqual(result["label"], "THEY'RE WATCHING")
        self.assertFalse(result["fail_closed"])

    def test_tor_sshh_requires_every_check(self):
        self.assertEqual(tor_mode.decide_status(ready())["status"], "tor_active")
        for key in ("trans_listening", "dns_listening", "redirect_trans", "redirect_dns", "filter_policy_drop", "tor_running"):
            self.assertNotEqual(tor_mode.decide_status(ready(**{key: False}))["status"], "tor_active", key)
        self.assertNotEqual(tor_mode.decide_status(ready(bootstrap=80))["status"], "tor_active")
        self.assertEqual(tor_mode.decide_status(ready(default_route=False))["status"], "offline")
        self.assertTrue(tor_mode.decide_status(ready(default_route=False))["fail_closed"])

    def test_missing_enforcement_is_blocked_not_open(self):
        result = tor_mode.decide_status(ready(table_present=False, filter_policy_drop=False))
        self.assertEqual(result["status"], "tor_blocked")
        self.assertFalse(result["fail_closed"])

    def test_bootstrap_without_a_percentage_stays_connecting(self):
        self.assertEqual(tor_mode.decide_status(ready(bootstrap=None))["status"], "connecting")
        self.assertEqual(tor_mode.parse_bootstrap('Bootstrapped 80%\nPROGRESS=100'), 100)
        self.assertIsNone(tor_mode.parse_bootstrap("no progress"))

    def test_stale_status_cannot_keep_a_protected_label(self):
        self.assertEqual(tor_mode.fresh_status("tor_active", 21), "unknown")
        self.assertEqual(tor_mode.fresh_status("tor_active", 5), "tor_active")
        self.assertIn("Tor Sshh", tor_mode.bubble_markup("tor_active"))
        self.assertIn("THEY'RE WATCHING", tor_mode.bubble_markup("normal"))

    def test_recovery_action_reblocks_or_removes_only_our_table(self):
        self.assertEqual(tor_mode.enforcement_action("on", False, False), "reapply-block")
        self.assertEqual(tor_mode.enforcement_action("off", True, True), "remove-block")
        self.assertEqual(tor_mode.enforcement_action("off", False, False), "none")

    def test_helper_refuses_to_touch_a_machine_without_the_marker(self):
        helper = ROOT / "config/includes.chroot/usr/local/sbin/traceos-tor-apply"
        env = os.environ.copy()
        env["TRACEOS_TOR_MARKER"] = "/tmp/traceos-tor-marker-missing"
        result = subprocess.run([sys.executable, str(helper), "on"], text=True, capture_output=True, env=env, check=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Refusing", result.stderr)
        printed = subprocess.run([sys.executable, str(helper), "--print-rules"], text=True, capture_output=True, check=False)
        self.assertEqual(printed.returncode, 0)
        self.assertIn("policy drop", printed.stdout)


if __name__ == "__main__":
    unittest.main()
