#!/usr/bin/env python3
"""
Cisco Device Compliance Checker

Requirements satisfied:
1) Uses Netmiko to connect to a Cisco device.
2) Collects running-configuration ("show running-config").
3) Calls another package/library to do compliance checks -> uses `ciscoconfparse` to parse and evaluate the config.
   (pip install ciscoconfparse)
4) Writes results to CSV or HTML (select via --output csv|html).

Checks included:
- Logging configuration
- AAA configuration
- Banner configuration
- ACL configuration
- NTP configuration
- SNMP configuration

Install prerequisites:
    pip install netmiko ciscoconfparse pyyaml

Example usage:
    python cisco_compliance_checker.py \
        --host 192.0.2.10 --username admin --password 'p@ss' \
        --device-type cisco_ios --output html --outfile results.html

Optional policy file (YAML) to customize checks; sample:

---
policy_name: "Global Baseline v1"
logging:
  require_buffered: true
  min_buffer_size: 16384
  require_hosts: true
  require_trap_level: "warnings"
  forbid_console_logging: true
aaa:
  require_new_model: true
  require_auth_login_default: true
  allowed_auth_methods: ["group tacacs+ local", "local"]
banner:
  require_motd: true
  forbid_empty: true
acls:
  check_standard_and_extended: true
  forbid_permit_ip_any_any: true
ntp:
  require_servers: true
  require_authenticate: false
snmp:
  forbid_public_private: true
  require_snmpv3: false

"""
from __future__ import annotations

import argparse
import csv
import datetime as dt
import os
import re
import sys
from typing import Any, Dict, List

from netmiko import ConnectHandler
from netmiko.exceptions import NetmikoTimeoutException, AuthenticationException
from ciscoconfparse import CiscoConfParse

try:
    import yaml  # type: ignore
except Exception:
    yaml = None


class ComplianceChecker:
    def __init__(self, running_config: str, policy: Dict[str, Any]):
        self.raw = running_config
        self.policy = policy or {}
        self.parse = CiscoConfParse(self.raw.splitlines(), factory=True)

    def _result(self, check: str, status: str, details: str, evidence: str = "") -> Dict[str, str]:
        return {
            "check": check,
            "status": status,
            "details": details,
            "evidence": evidence.strip(),
        }

    def check_logging(self) -> List[Dict[str, str]]:
        p = self.policy.get("logging", {})
        results: List[Dict[str, str]] = []
        buffered = self.parse.find_objects(r"^logging buffered")
        if p.get("require_buffered", True):
            if buffered:
                size = int(buffered[0].text.split()[-1]) if buffered[0].text.split()[-1].isdigit() else 0
                if size >= p.get("min_buffer_size", 4096):
                    results.append(self._result("Logging - buffered", "PASS", f"size {size}", buffered[0].text))
                else:
                    results.append(self._result("Logging - buffered", "FAIL", f"buffer size too small ({size})", buffered[0].text))
            else:
                results.append(self._result("Logging - buffered", "FAIL", "not configured"))

        if p.get("require_hosts", True):
            hosts = self.parse.find_objects(r"^logging host")
            if hosts:
                results.append(self._result("Logging - host", "PASS", f"{len(hosts)} host(s) configured", "\n".join(h.text for h in hosts)))
            else:
                results.append(self._result("Logging - host", "FAIL", "no logging hosts configured"))

        if "require_trap_level" in p:
            trap = self.parse.find_objects(r"^logging trap")
            if trap and p["require_trap_level"] in trap[0].text:
                results.append(self._result("Logging - trap level", "PASS", trap[0].text, trap[0].text))
            else:
                results.append(self._result("Logging - trap level", "FAIL", "not configured properly"))

        if p.get("forbid_console_logging", True):
            cons = self.parse.find_objects(r"^logging console")
            if cons:
                results.append(self._result("Logging - console", "FAIL", "console logging enabled", cons[0].text))
            else:
                results.append(self._result("Logging - console", "PASS", "console logging disabled"))
        return results

    def check_aaa(self) -> List[Dict[str, str]]:
        p = self.policy.get("aaa", {})
        results: List[Dict[str, str]] = []
        if p.get("require_new_model", True):
            nm = self.parse.find_objects(r"^aaa new-model")
            if nm:
                results.append(self._result("AAA - new model", "PASS", "aaa new-model configured", nm[0].text))
            else:
                results.append(self._result("AAA - new model", "FAIL", "aaa new-model missing"))

        if p.get("require_auth_login_default", True):
            login = self.parse.find_objects(r"^aaa authentication login default")
            if login:
                cfg = login[0].text
                allowed = p.get("allowed_auth_methods", [])
                if any(method in cfg for method in allowed):
                    results.append(self._result("AAA - login default", "PASS", cfg, cfg))
                else:
                    results.append(self._result("AAA - login default", "FAIL", f"not in allowed methods: {cfg}", cfg))
            else:
                results.append(self._result("AAA - login default", "FAIL", "not configured"))
        return results

    def check_banner(self) -> List[Dict[str, str]]:
        p = self.policy.get("banner", {})
        results: List[Dict[str, str]] = []
        banners = self.parse.find_objects(r"^banner motd")
        if p.get("require_motd", True):
            if banners:
                content = banners[0].text
                if p.get("forbid_empty", True) and len(content.split()) <= 2:
                    results.append(self._result("Banner - MOTD", "FAIL", "banner MOTD empty or too short", content))
                else:
                    results.append(self._result("Banner - MOTD", "PASS", "configured", content))
            else:
                results.append(self._result("Banner - MOTD", "FAIL", "missing"))
        return results

    def check_acls(self) -> List[Dict[str, str]]:
        p = self.policy.get("acls", {})
        results: List[Dict[str, str]] = []
        if p.get("check_standard_and_extended", True):
            acls = self.parse.find_objects(r"^access-list")
            if acls:
                results.append(self._result("ACLs - defined", "PASS", f"{len(acls)} ACL entries", "\n".join(a.text for a in acls)))
            else:
                results.append(self._result("ACLs - defined", "FAIL", "no ACLs configured"))
        if p.get("forbid_permit_ip_any_any", True):
            bad = self.parse.find_objects(r"^access-list.*permit ip any any")
            if bad:
                results.append(self._result("ACLs - permit any any", "FAIL", "permit ip any any found", "\n".join(b.text for b in bad)))
            else:
                results.append(self._result("ACLs - permit any any", "PASS", "no 'permit ip any any' found"))
        return results

    def check_ntp(self) -> List[Dict[str, str]]:
        p = self.policy.get("ntp", {})
        results: List[Dict[str, str]] = []
        servers = [o.text for o in self.parse.find_objects(r"^ntp server ")]
        if p.get("require_servers", True):
            if servers:
                results.append(self._result("NTP - servers", "PASS", f"found {len(servers)} server(s)", "\n".join(servers)))
            else:
                results.append(self._result("NTP - servers", "FAIL", "no NTP servers configured"))
        auth = self.parse.find_objects(r"^ntp authenticate")
        if p.get("require_authenticate", False):
            if auth:
                results.append(self._result("NTP - authentication", "PASS", "ntp authenticate configured", auth[0].text))
            else:
                results.append(self._result("NTP - authentication", "FAIL", "'ntp authenticate' missing"))
        return results

    def check_snmp(self) -> List[Dict[str, str]]:
        p = self.policy.get("snmp", {})
        results: List[Dict[str, str]] = []
        communities = [o.text for o in self.parse.find_objects(r"^snmp-server community ")]
        if p.get("forbid_public_private", True):
            bad = [c for c in communities if re.search(r"\\b(public|private)\\b", c, re.IGNORECASE)]
            if bad:
                results.append(self._result("SNMP - community strings", "FAIL", "uses 'public' or 'private'", "\n".join(bad)))
            else:
                results.append(self._result("SNMP - community strings", "PASS", "no default 'public/private' found"))
        if p.get("require_snmpv3", False):
            snmpv3 = [o.text for o in self.parse.find_objects(r"^snmp-server user ")]
            if snmpv3:
                results.append(self._result("SNMP - v3 users", "PASS", f"found {len(snmpv3)} SNMPv3 user(s)", "\n".join(snmpv3)))
            else:
                results.append(self._result("SNMP - v3 users", "FAIL", "no SNMPv3 users configured"))
        return results

    def run_all(self) -> List[Dict[str, str]]:
        results: List[Dict[str, str]] = []
        results.extend(self.check_logging())
        results.extend(self.check_aaa())
        results.extend(self.check_banner())
        results.extend(self.check_acls())
        results.extend(self.check_ntp())
        results.extend(self.check_snmp())
        return results


def write_csv(outfile: str, results: List[Dict[str, str]]):
    with open(outfile, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["check", "status", "details", "evidence"])
        writer.writeheader()
        for r in results:
            writer.writerow(r)


def write_html(outfile: str, results: List[Dict[str, str]]):
    with open(outfile, "w") as f:
        f.write("<html><head><style>")
        f.write("table{border-collapse:collapse}td,th{border:1px solid #ccc;padding:4px}")
        f.write(".PASS{background:#cfc}.FAIL{background:#fcc}.WARN{background:#ffc}.INFO{background:#ccf}")
        f.write("</style></head><body>")
        f.write("<h2>Cisco Compliance Report</h2>")
        f.write(f"<p>Generated {dt.datetime.now().isoformat()}</p>")
        f.write("<table><tr><th>Check</th><th>Status</th><th>Details</th><th>Evidence</th></tr>")
        for r in results:
            f.write(f"<tr class='{r['status']}'><td>{r['check']}</td><td>{r['status']}</td><td>{r['details']}</td><td><pre>{r['evidence']}</pre></td></tr>")
        f.write("</table></body></html>")


def get_running_config(args) -> str:
    device = {
        "device_type": args.device_type,
        "host": args.host,
        "username": args.username,
        "password": args.password,
        "secret": args.secret,
    }
    try:
        conn = ConnectHandler(**device)
        if args.secret:
            conn.enable()
        output = conn.send_command("show running-config")
        conn.disconnect()
        return output
    except (NetmikoTimeoutException, AuthenticationException) as e:
        sys.exit(f"Connection failed: {e}")


def load_policy(policy_file: str) -> Dict[str, Any]:
    if not policy_file:
        return {}
    if not yaml:
        sys.exit("PyYAML not installed")
    with open(policy_file) as f:
        return yaml.safe_load(f)


def main() -> int:
    parser = argparse.ArgumentParser(description="Cisco Compliance Checker")
    parser.add_argument("--host", required=True)
    parser.add_argument("--username", required=True)
    parser.add_argument("--password", required=True)
    parser.add_argument("--secret", default="")
    parser.add_argument("--device-type", default="cisco_ios")
    parser.add_argument("--output", choices=["csv", "html"], required=True)
    parser.add_argument("--outfile", required=True)
    parser.add_argument("--policy", help="YAML policy file", default="")
    args = parser.parse_args()

    raw_cfg = get_running_config(args)
    policy = load_policy(args.policy)
    checker = ComplianceChecker(raw_cfg, policy)
    results = checker.run_all()

    if args.output == "csv":
        write_csv(args.outfile, results)
    else:
        write_html(args.outfile, results)

    fails = [r for r in results if r["status"] == "FAIL"]
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
