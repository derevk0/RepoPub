#!/usr/bin/env python3
"""
Cisco Device Compliance Checker

Requirements satisfied:
1) Uses Netmiko to connect to a Cisco device.
2) Collects running-configuration ("show running-config").
3) Calls another package/library to do compliance checks -> uses `ciscoconfparse` to parse and evaluate the config.
   (pip install ciscoconfparse)
4) Writes results to CSV or HTML (select via --output csv|html).

Extended checks:
- Logging configuration
- AAA configuration
- Banner configuration
- ACL configuration
- NTP configuration
- SNMP configuration

Install prerequisites:
    pip install netmiko ciscoconfparse pyyaml

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
        # (existing code unchanged)
        results: List[Dict[str, str]] = []
        # ...
        return results

    def check_aaa(self) -> List[Dict[str, str]]:
        results: List[Dict[str, str]] = []
        # ...
        return results

    def check_banner(self) -> List[Dict[str, str]]:
        results: List[Dict[str, str]] = []
        # ...
        return results

    def check_acls(self) -> List[Dict[str, str]]:
        results: List[Dict[str, str]] = []
        # ...
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


# (rest of the script remains the same: write_csv, write_html, get_running_config, load_policy, main)

if __name__ == "__main__":
    sys.exit(main())
