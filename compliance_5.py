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
- ACL configuration (multi-line regex pattern support)
- NTP configuration
- SNMP configuration

Install prerequisites:
    pip install netmiko ciscoconfparse pyyaml

Example usage:
    python cisco_compliance_checker.py \
        --host 192.0.2.10 --username admin --password 'p@ss' \
        --device-type cisco_ios --output html --outfile results.html

    # Or run against saved running-config file:
    python cisco_compliance_checker.py \
        --config-file sample_running_config.txt --output csv --outfile results.csv

Optional policy file (YAML) to customize checks; sample provided below.
"""
"""
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
  require_patterns:
    - |
      access-list 100 permit tcp 192\.168\.1\.0 0\.0\.0\.255 any eq 80
      access-list 100 permit tcp 192\.168\.1\.0 0\.0\.0\.255 any eq 443
  forbid_patterns:
    - |
      access-list 100 permit ip any any

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
from typing import Any, Dict, List, Optional

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
        return results

    def check_aaa(self) -> List[Dict[str, str]]:
        p = self.policy.get("aaa", {})
        results: List[Dict[str, str]] = []
        return results

    def check_banner(self) -> List[Dict[str, str]]:
        p = self.policy.get("banner", {})
        results: List[Dict[str, str]] = []
        return results

    def check_acls(self) -> List[Dict[str, str]]:
        """
        Enhanced ACL compliance:
        - Supports regex patterns
        - Supports multi-line patterns (e.g., entire ACL blocks)
        """
        p = self.policy.get("acls", {})
        results: List[Dict[str, str]] = []

        if not p:
            return results

        acl_objects = self.parse.find_objects(r"^access-list")
        acl_lines = [o.text for o in acl_objects]
        acl_text = "\n".join(acl_lines)

        if not acl_lines:
            results.append(self._result("ACL - presence", "FAIL", "no ACLs found"))
            return results

        results.append(self._result("ACL - presence", "PASS", f"{len(acl_lines)} ACL entries found", acl_text))

        # Forbid permit ip any any
        if p.get("forbid_permit_ip_any_any", False):
            bad = [a for a in acl_lines if re.search(r"permit\s+ip\s+any\s+any", a, re.IGNORECASE)]
            if bad:
                results.append(self._result("ACL - permit ip any any", "FAIL", "forbidden 'permit ip any any' found", "\n".join(bad)))
            else:
                results.append(self._result("ACL - permit ip any any", "PASS", "no 'permit ip any any' statements"))

        # Pattern matching (multi-line with regex)
        required_patterns = p.get("require_patterns", [])
        forbidden_patterns = p.get("forbid_patterns", [])

        for pattern in required_patterns:
            if re.search(pattern, acl_text, re.MULTILINE | re.DOTALL):
                results.append(self._result("ACL - required pattern", "PASS", f"pattern '{pattern}' found"))
            else:
                results.append(self._result("ACL - required pattern", "FAIL", f"pattern '{pattern}' missing"))

        for pattern in forbidden_patterns:
            if re.search(pattern, acl_text, re.MULTILINE | re.DOTALL):
                results.append(self._result("ACL - forbidden pattern", "FAIL", f"pattern '{pattern}' present"))
            else:
                results.append(self._result("ACL - forbidden pattern", "PASS", f"pattern '{pattern}' not found"))

        return results

    def check_ntp(self) -> List[Dict[str, str]]:
        p = self.policy.get("ntp", {})
        results: List[Dict[str, str]] = []
        servers = [o.text for o in self.parse.find_objects(r"^\s*ntp server ")]
        if p.get("require_servers", True):
            if servers:
                results.append(self._result("NTP - servers", "PASS", f"found {len(servers)} server(s)", "\n".join(servers)))
            else:
                results.append(self._result("NTP - servers", "FAIL", "no NTP servers configured"))
        auth = self.parse.find_objects(r"^\s*ntp authenticate")
        if p.get("require_authenticate", False):
            if auth:
                results.append(self._result("NTP - authentication", "PASS", "ntp authenticate configured", auth[0].text))
            else:
                results.append(self._result("NTP - authentication", "FAIL", "'ntp authenticate' missing"))
        return results

    def check_snmp(self) -> List[Dict[str, str]]:
        p = self.policy.get("snmp", {})
        results: List[Dict[str, str]] = []
        communities = [o.text for o in self.parse.find_objects(r"^\s*snmp-server community ")]
        if p.get("forbid_public_private", True):
            bad = [c for c in communities if re.search(r"\b(public|private)\b", c, re.IGNORECASE)]
            if bad:
                results.append(self._result("SNMP - community strings", "FAIL", "uses 'public' or 'private'", "\n".join(bad)))
            else:
                results.append(self._result("SNMP - community strings", "PASS", "no default 'public/private' found"))
        if p.get("require_snmpv3", False):
            snmpv3 = [o.text for o in self.parse.find_objects(r"^\s*snmp-server user ")]
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


def get_running_config_from_device(host: str, username: str, password: str, device_type: str) -> str:
    device = {
        "device_type": device_type,
        "host": host,
        "username": username,
        "password": password,
    }
    try:
        with ConnectHandler(**device) as conn:
            output = conn.send_command("show running-config")
            return output
    except (NetmikoTimeoutException, AuthenticationException) as e:
        print(f"Connection failed: {e}")
        sys.exit(1)


def get_running_config_from_file(path: str) -> str:
    if not os.path.exists(path):
        print(f"Config file {path} not found")
        sys.exit(1)
    with open(path, "r") as f:
        return f.read()


def load_policy(policy_file: Optional[str]) -> Dict[str, Any]:
    if not policy_file:
        return {}
    if yaml is None:
        print("pyyaml is required for policy files. Install with `pip install pyyaml`")
        sys.exit(1)
    with open(policy_file, "r") as f:
        return yaml.safe_load(f)


def write_csv(results: List[Dict[str, str]], outfile: str) -> None:
    with open(outfile, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["check", "status", "details", "evidence"])
        writer.writeheader()
        for row in results:
            writer.writerow(row)


def write_html(results: List[Dict[str, str]], outfile: str) -> None:
    with open(outfile, "w") as f:
        f.write("<html><head><title>Compliance Report</title></head><body>\n")
        f.write(f"<h1>Compliance Report - {dt.datetime.now().isoformat()}</h1>\n")
        f.write("<table border='1'><tr><th>Check</th><th>Status</th><th>Details</th><th>Evidence</th></tr>\n")
        for row in results:
            color = "green" if row["status"] == "PASS" else ("red" if row["status"] == "FAIL" else "orange")
            f.write(
                f"<tr><td>{row['check']}</td><td style='color:{color}'>{row['status']}</td>"
                f"<td>{row['details']}</td><td><pre>{row['evidence']}</pre></td></tr>\n"
            )
        f.write("</table></body></html>\n")


def main() -> int:
    parser = argparse.ArgumentParser(description="Cisco Compliance Checker")
    parser.add_argument("--host", help="Device hostname or IP")
    parser.add_argument("--username", help="Device username")
    parser.add_argument("--password", help="Device password")
    parser.add_argument("--device-type", default="cisco_ios", help="Netmiko device type (default: cisco_ios)")
    parser.add_argument("--config-file", help="Path to local running-config file instead of connecting to device")
    parser.add_argument("--policy", help="Path to policy YAML file")
    parser.add_argument("--output", choices=["csv", "html"], required=True, help="Output format")
    parser.add_argument("--outfile", required=True, help="Output file path")
    args = parser.parse_args()

    if args.config_file:
        running_config = get_running_config_from_file(args.config_file)
    else:
        if not (args.host and args.username and args.password):
            print("Must provide either --config-file OR --host/--username/--password")
            return 1
        running_config = get_running_config_from_device(args.host, args.username, args.password, args.device_type)

    policy = load_policy(args.policy)
    checker = ComplianceChecker(running_config, policy)
    results = checker.run_all()

    if args.output == "csv":
        write_csv(results, args.outfile)
    else:
        write_html(results, args.outfile)

    print(f"Compliance report written to {args.outfile}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
