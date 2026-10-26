"""Decide TraceOS Tor status and render the firewall policy.

The functions in this module do not change the host. The privileged helper is
the only program that applies them, and only after an explicit request.
"""
from __future__ import annotations

import re
from typing import Mapping

TABLE = "traceos_tor"
TRANS_PORT = 9040
DNS_PORT = 5353
SOCKS_PORT = 9050
CONTROL_PORT = 9051
STATUS_MAX_AGE_S = 20

LABELS = {
    "normal": ("THEY'RE WATCHING", "#2fce6a"),
    "tor_active": ("Tor Sshh", "#ff5a6a"),
    "offline": ("OFFLINE", "#8aa0b8"),
    "tor_blocked": ("TOR BLOCKED", "#f0a04b"),
    "connecting": ("CONNECTING TOR…", "#7af6ff"),
    "unknown": ("NETWORK UNKNOWN", "#f0a04b"),
}


def render_nft() -> str:
    """Fail-closed policy. TCP from ordinary programs is redirected to Tor.

    Packets from the debian-tor user are the only ones allowed onto the real
    network, plus DHCP and IPv6 neighbour discovery. There is no broad accept
    for established connections, because that would keep a direct session alive
    after the switch.
    """
    return f"""table inet {TABLE}
delete table inet {TABLE}
table inet {TABLE} {{
  chain output_nat {{
    type nat hook output priority -100; policy accept;
    meta skuid "debian-tor" return
    udp dport {DNS_PORT} return
    tcp dport {{ {TRANS_PORT}, {SOCKS_PORT}, {CONTROL_PORT}, {DNS_PORT} }} return
    tcp dport 53 redirect to :{DNS_PORT}
    udp dport 53 redirect to :{DNS_PORT}
    ip daddr 127.0.0.0/8 return
    ip6 daddr ::1 return
    meta l4proto tcp redirect to :{TRANS_PORT}
  }}
  chain output_filter {{
    type filter hook output priority 0; policy drop;
    meta skuid "debian-tor" accept
    oifname "lo" accept
    udp sport 68 udp dport 67 accept
    udp sport 67 udp dport 68 accept
    ip6 daddr fe80::/10 icmpv6 type {{ nd-router-solicit, nd-router-advert, nd-neighbor-solicit, nd-neighbor-advert }} accept
  }}
}}
"""


def parse_bootstrap(text: str) -> int | None:
    values = [int(match) for match in re.findall(r"Bootstrapped (\d+)%", text)]
    values.extend(int(match) for match in re.findall(r"PROGRESS=(\d+)", text))
    return values[-1] if values else None


def decide_status(obs: Mapping[str, object]) -> dict[str, object]:
    requested = str(obs.get("requested") or "off")
    default_route = bool(obs.get("default_route"))
    table_present = bool(obs.get("table_present"))
    filter_drop = bool(obs.get("filter_policy_drop"))
    enforced = table_present and filter_drop and bool(obs.get("redirect_trans")) and bool(obs.get("redirect_dns"))
    if requested not in {"on", "off"}:
        return _result("unknown", False, "The requested Tor mode is not on or off.")
    if requested == "off":
        if table_present:
            return _result("unknown", True, "Tor was requested off, but the TraceOS firewall table is still loaded.")
        if not default_route:
            return _result("offline", False, "No default route. Tor is off.")
        return _result("normal", False, "Normal route is usable. Traffic is not going through Tor.")
    if not enforced:
        return _result("tor_blocked", False, "Tor was requested, but the fail-closed rules are not all active.")
    if not default_route:
        return _result("offline", True, "No default route. The fail-closed block is still loaded.")
    bootstrap = obs.get("bootstrap")
    ready = (
        bool(obs.get("tor_running"))
        and bool(obs.get("trans_listening"))
        and bool(obs.get("dns_listening"))
        and bootstrap == 100
    )
    if ready:
        return _result("tor_active", True, "Tor, DNS and the direct-egress block all checked out.")
    if bool(obs.get("tor_running")) and (not isinstance(bootstrap, int) or bootstrap < 100):
        progress = f"{bootstrap} percent" if isinstance(bootstrap, int) else "not reported yet"
        return _result("connecting", True, f"Tor progress is {progress}. Direct egress stays blocked.")
    return _result("tor_blocked", True, "The block is up, but Tor is not ready. Direct egress stays blocked.")


def fresh_status(status: str, age_s: float | None, max_age: float = STATUS_MAX_AGE_S) -> str:
    if status not in LABELS or age_s is None or age_s < 0 or age_s > max_age:
        return "unknown"
    return status


def enforcement_action(requested: str, table_present: bool, filter_policy_drop: bool) -> str:
    if requested == "on" and not (table_present and filter_policy_drop):
        return "reapply-block"
    if requested != "on" and table_present:
        return "remove-block"
    return "none"


def bubble_markup(status: str) -> str:
    label, colour = LABELS.get(status, LABELS["unknown"])
    safe = label.replace("&", "&").replace("<", "<").replace(">", ">")
    return f'<txt><span foreground="{colour}">● {safe}</span></txt>'


def _result(status: str, fail_closed: bool, detail: str) -> dict[str, object]:
    label, _colour = LABELS[status]
    return {"status": status, "label": label, "fail_closed": fail_closed, "detail": detail}
