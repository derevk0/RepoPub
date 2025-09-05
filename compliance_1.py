#!/usr/bin/env python3
"""
Cisco Device Compliance Checker

Requirements satisfied:
1) Uses Netmiko to connect to a Cisco device.
2) Collects running-configuration ("show running-config").
3) Calls another package/library to do compliance checks -> uses `ciscoconfparse` to parse and evaluate the config.
   (pip install ciscoconfparse)
4) Writes results to CSV or HTML (select via --output csv|html).

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
  min_buffer_size: 16384       # bytes; pass if configured size >= this
  require_hosts: true          # at least one logging host
  require_trap_level: "warnings"  # one of: emergencies, alerts, critical, errors, warnings, notifications, informational, debugging
  forbid_console_logging: true # flag if 'logging console' is present
  allow_host_substrings: []    # optional: host substrings allowed, e.g., ["10.10.", "syslog.company.com"]
aaa:
  require_new_model: true
  require_auth_login_default: true   # require 'aaa authentication login default ...'
  allowed_auth_methods: ["group tacacs+ local", "local"]  # any of these must appear on the default method list
  require_authorization_commands_default: false
  require_accounting_commands_default: false
banner:
  require_motd: true
  forbid_empty: true
acls:
  check_standard_and_extended: true
  forbid_permit_ip_any_any: true
  allowlist_acls: []     # ACL names exempt from the 'any any' rule

Save the above as policy.yaml and run with: --policy policy.yaml
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
    yaml = None  # We'll handle no YAML gracefully


# -----------------------------
# Compliance checker (library)
# -----------------------------
class ComplianceChecker:
    """Wrapper around CiscoConfParse that evaluates a config against a policy.

    This class is designed as a separable library-like component that the main
    script calls. It returns a flat list of dicts suitable for CSV/HTML export.
    """

    def __init__(self, running_config: str, policy: Dict[str, Any]):
        self.raw = running_config
        self.policy = policy or {}
        self.parse = CiscoConfParse(self.raw.splitlines(), factory=True)

    # ---------- Utility ----------
    def _result(self, check: str, status: str, details: str, evidence: str = "") -> Dict[str, str]:
        return {
            "check": check,
            "status": status,  # PASS | FAIL | WARN | INFO
            "details": details,
            "evidence": evidence.strip(),
        }

    # ---------- Checks ----------
    def check_logging(self) -> List[Dict[str, str]]:
        p = self.policy.get("logging", {})
        results: List[Dict[str, str]] = []

        # logging buffered <size> <level?>
        buf_lines = self.parse.find_objects(r"^\s*logging buffered")
        if p.get("require_buffered", True):
            if not buf_lines:
                results.append(self._result("Logging - buffered", "FAIL", "'logging buffered' is not configured"))
            else:
                # parse size
                line = buf_lines[0].text
                m = re.search(r"logging buffered\s+(\d+)", line)
                size = int(m.group(1)) if m else 0
                min_size = int(p.get("min_buffer_size", 16384))
                if size >= min_size:
                    results.append(self._result("Logging - buffered size", "PASS", f"configured size {size} >= {min_size}", line))
                else:
                    results.append(self._result("Logging - buffered size", "FAIL", f"configured size {size} < {min_size}", line))
        else:
            if buf_lines:
                results.append(self._result("Logging - buffered", "INFO", "present", buf_lines[0].text))

        # logging host
        hosts = [o.text for o in self.parse.find_objects(r"^\s*logging host ")]
        if p.get("require_hosts", True):
            if hosts:
                allow_subs = p.get("allow_host_substrings", []) or []
                if allow_subs:
                    ok = any(any(sub in h for sub in allow_subs) for h in hosts)
                    status = "PASS" if ok else "WARN"
                    detail = "at least one host matches allowlist substrings" if ok else "no logging host matches allowlist substrings"
                else:
                    status = "PASS"
                    detail = "at least one logging host configured"
                results.append(self._result("Logging - hosts", status, detail, "\n".join(hosts)))
            else:
                results.append(self._result("Logging - hosts", "FAIL", "no 'logging host' configured"))
        elif hosts:
            results.append(self._result("Logging - hosts", "INFO", "present", "\n".join(hosts)))

        # logging trap <level>
        trap = self.parse.find_objects(r"^\s*logging trap ")
        wanted = p.get("require_trap_level")
        if wanted:
            if trap:
                lvl = trap[0].text.split()[-1]
                if lvl.lower() == str(wanted).lower():
                    results.append(self._result("Logging - trap level", "PASS", f"trap level is '{lvl}'", trap[0].text))
                else:
                    results.append(self._result("Logging - trap level", "FAIL", f"trap level is '{lvl}', expected '{wanted}'", trap[0].text))
            else:
                results.append(self._result("Logging - trap level", "FAIL", "'logging trap' not configured"))
        elif trap:
            results.append(self._result("Logging - trap level", "INFO", "present", trap[0].text))

        # logging console - often discouraged
        forbid_console = bool(p.get("forbid_console_logging", True))
        cons = self.parse.find_objects(r"^\s*logging console")
        if forbid_console and cons:
            results.append(self._result("Logging - console", "WARN", "'logging console' present (often discouraged)", cons[0].text))
        elif forbid_console:
            results.append(self._result("Logging - console", "PASS", "console logging not present"))

        return results

    def check_aaa(self) -> List[Dict[str, str]]:
        p = self.policy.get("aaa", {})
        results: List[Dict[str, str]] = []

        has_new_model = bool(self.parse.find_objects(r"^\s*aaa new-model"))
        if p.get("require_new_model", True):
            results.append(self._result("AAA - new-model", "PASS" if has_new_model else "FAIL", "'aaa new-model' required", "present" if has_new_model else "missing"))
        else:
            if has_new_model:
                results.append(self._result("AAA - new-model", "INFO", "present"))

        # authentication login default
        auth_default = self.parse.find_objects(r"^\s*aaa authentication login default ")
        if p.get("require_auth_login_default", True):
            if not auth_default:
                results.append(self._result("AAA - authentication default", "FAIL", "'aaa authentication login default' is missing"))
            else:
                line = auth_default[0].text
                allowed = [m.lower() for m in (p.get("allowed_auth_methods") or [])]
                if allowed:
                    ok = any(method in line.lower() for method in allowed)
                    if ok:
                        results.append(self._result("AAA - authentication default", "PASS", "method matches allowed list", line))
                    else:
                        results.append(self._result("AAA - authentication default", "FAIL", f"method not in allowed list: {allowed}", line))
                else:
                    results.append(self._result("AAA - authentication default", "PASS", "present", line))
        elif auth_default:
            results.append(self._result("AAA - authentication default", "INFO", "present", auth_default[0].text))

        # authorization/accounting (optional based on policy flags)
        if p.get("require_authorization_commands_default"):
            authz = self.parse.find_objects(r"^\s*aaa authorization commands 15 default ")
            results.append(
                self._result(
                    "AAA - authorization default",
                    "PASS" if authz else "FAIL",
                    "'aaa authorization commands 15 default' required",
                    authz[0].text if authz else "missing",
                )
            )

        if p.get("require_accounting_commands_default"):
            acct = self.parse.find_objects(r"^\s*aaa accounting commands 15 default ")
            results.append(
                self._result(
                    "AAA - accounting default",
                    "PASS" if acct else "FAIL",
                    "'aaa accounting commands 15 default' required",
                    acct[0].text if acct else "missing",
                )
            )

        return results

    def check_banner(self) -> List[Dict[str, str]]:
        p = self.policy.get("banner", {})
        results: List[Dict[str, str]] = []

        # Banner parsing: look for 'banner motd <delim>...<delim>'
        text = self.raw
        motd_match = re.search(r"^banner\s+motd\s+(.)([\s\S]*?)\1\s*$", text, flags=re.MULTILINE)
        require_motd = bool(p.get("require_motd", True))
        forbid_empty = bool(p.get("forbid_empty", True))

        if require_motd:
            if not motd_match:
                results.append(self._result("Banner - MOTD", "FAIL", "'banner motd' not configured"))
            else:
                content = motd_match.group(2).strip()
                if forbid_empty and not content:
                    results.append(self._result("Banner - MOTD", "FAIL", "banner content is empty"))
                else:
                    # Optional: flag presence of legal terms like 'authorized' and 'monitoring'
                    results.append(self._result("Banner - MOTD", "PASS", "configured", content[:120] + ("..." if len(content) > 120 else "")))
        else:
            if motd_match:
                results.append(self._result("Banner - MOTD", "INFO", "present"))

        return results

    def check_acls(self) -> List[Dict[str, str]]:
        p = self.policy.get("acls", {})
        results: List[Dict[str, str]] = []

        if not p.get("check_standard_and_extended", True):
            return results

        lines = [o.text for o in self.parse.find_objects(r"^\s*access-list ")]
        named_ext = self.parse.find_objects(r"^\s*ip access-list extended ")
        named_std = self.parse.find_objects(r"^\s*ip access-list standard ")

        all_acl_texts: List[str] = []
        all_acl_texts.extend(lines)
        for obj in named_ext + named_std:
            all_acl_texts.append(obj.text)
            all_acl_texts.extend([c.text for c in obj.children])

        if not all_acl_texts:
            results.append(self._result("ACLs - presence", "WARN", "no ACLs found"))
            return results

        results.append(self._result("ACLs - presence", "PASS", f"found {len(all_acl_texts)} ACL lines", "\n".join(all_acl_texts[:10]) + ("\n..." if len(all_acl_texts) > 10 else "")))

        if p.get("forbid_permit_ip_any_any", True):
            allowlist = set([a.lower() for a in (p.get("allowlist_acls") or [])])

            violations: List[str] = []
            # Simple regexes for dangerous lines
            danger_patterns = [
                r"permit\s+ip\s+any\s+any",
                r"permit\s+tcp\s+any\s+any\b",
                r"permit\s+udp\s+any\s+any\b",
                r"permit\s+ipv6\s+any\s+any",
            ]
            danger_re = re.compile("|".join(danger_patterns), re.IGNORECASE)

            # Check numbered ACL lines
            for line in lines:
                if danger_re.search(line):
                    violations.append(line)

            # Check named ACL blocks (collect ACL name and child lines)
            for block in named_ext + named_std:
                header = block.text.strip()
                # extract name
                m = re.search(r"ip access-list (?:extended|standard)\s+(\S+)", header, re.IGNORECASE)
                acl_name = m.group(1).lower() if m else ""
                if acl_name and acl_name in allowlist:
                    continue
                for child in block.children:
                    if danger_re.search(child.text):
                        violations.append(f"{header}: {child.text.strip()}")

            if violations:
                results.append(self._result("ACLs - overly permissive", "FAIL", "Found broad 'permit any any' entries", "\n".join(violations)))
            else:
                results.append(self._result("ACLs - overly permissive", "PASS", "No 'permit any any' found"))

        return results

    def run_all(self) -> List[Dict[str, str]]:
        results: List[Dict[str, str]] = []
        results.extend(self.check_logging())
        results.extend(self.check_aaa())
        results.extend(self.check_banner())
        results.extend(self.check_acls())
        return results


# -----------------------------
# Output helpers
# -----------------------------

def write_csv(results: List[Dict[str, str]], outfile: str, metadata: Dict[str, str]) -> None:
    fieldnames = ["check", "status", "details", "evidence"]
    with open(outfile, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        # header block
        w.writerow(["Cisco Compliance Report"])
        for k, v in metadata.items():
            w.writerow([k, v])
        w.writerow([])
        w.writerow(fieldnames)
        for row in results:
            w.writerow([row.get(h, "") for h in fieldnames])


def write_html(results: List[Dict[str, str]], outfile: str, metadata: Dict[str, str]) -> None:
    # Simple, dependency-free HTML report with light styling
    now = dt.datetime.now().isoformat(sep=" ", timespec="seconds")
    status_colors = {
        "PASS": "#2e7d32",
        "FAIL": "#c62828",
        "WARN": "#f9a825",
        "INFO": "#1565c0",
    }

    def esc(s: str) -> str:
        return (s or "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")

    rows = []
    for r in results:
        color = status_colors.get(r.get("status", "INFO"), "#444")
        rows.append(
            f"<tr>\n"
            f"  <td class='check'>{esc(r.get('check',''))}</td>\n"
            f"  <td class='status' style='color:{color};font-weight:700'>{esc(r.get('status',''))}</td>\n"
            f"  <td class='details'>{esc(r.get('details',''))}</td>\n"
            f"  <td class='evidence'><pre>{esc(r.get('evidence',''))}</pre></td>\n"
            f"</tr>"
        )

    meta_html = "".join(f"<div><b>{esc(k)}</b>: {esc(v)}</div>" for k, v in metadata.items())

    html = f"""
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>Cisco Compliance Report</title>
<style>
  body {{ font-family: system-ui, -apple-system, Segoe UI, Roboto, Helvetica, Arial, sans-serif; margin: 24px; }}
  h1 {{ margin: 0 0 4px 0; }}
  .meta {{ margin: 8px 0 16px 0; color: #444; }}
  table {{ width: 100%; border-collapse: collapse; }}
  th, td {{ border: 1px solid #ddd; padding: 8px; vertical-align: top; }}
  th {{ background: #f3f4f6; text-align: left; }}
  tr:nth-child(even) {{ background: #fafafa; }}
  pre {{ white-space: pre-wrap; word-wrap: break-word; margin: 0; }}
</style>
</head>
<body>
  <h1>Cisco Compliance Report</h1>
  <div class="meta">
    <div><b>Generated</b>: {now}</div>
    {meta_html}
  </div>
  <table>
    <thead>
      <tr>
        <th>Check</th>
        <th>Status</th>
        <th>Details</th>
        <th>Evidence</th>
      </tr>
    </thead>
    <tbody>
      {''.join(rows)}
    </tbody>
  </table>
</body>
</html>
"""
    with open(outfile, "w", encoding="utf-8") as f:
        f.write(html)


# -----------------------------
# Device connection & main
# -----------------------------

def get_running_config(args: argparse.Namespace) -> str:
    device = {
        "device_type": args.device_type,
        "host": args.host,
        "username": args.username,
        "password": args.password,
        "port": args.port,
        "secret": args.secret or None,
        "fast_cli": False,
    }
    conn = None
    try:
        conn = ConnectHandler(**device)
        if args.secret:
            try:
                conn.enable()
            except Exception:
                # Some platforms treat enable as no-op if already privileged
                pass
        output = conn.send_command("show running-config", use_textfsm=False)
        return output
    finally:
        if conn:
            try:
                conn.disconnect()
            except Exception:
                pass


def load_policy(path: Optional[str]) -> Dict[str, Any]:
    if not path:
        return {}
    if yaml is None:
        raise RuntimeError("pyyaml is required to load a policy file. pip install pyyaml")
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def main() -> int:
    parser = argparse.ArgumentParser(description="Cisco device compliance checker (Netmiko + CiscoConfParse)")
    parser.add_argument("--host", required=True, help="Device IP/DNS")
    parser.add_argument("--username", required=True)
    parser.add_argument("--password", required=True)
    parser.add_argument("--device-type", default="cisco_ios", help="Netmiko device_type (e.g., cisco_ios, cisco_xe, cisco_xr)")
    parser.add_argument("--port", default=22, type=int)
    parser.add_argument("--secret", default=None, help="Enable password (if needed)")

    parser.add_argument("--output", choices=["csv", "html"], default="html", help="Output format")
    parser.add_argument("--outfile", default=None, help="Output file path (default: ./compliance_<host>.<ext>)")
    parser.add_argument("--policy", default=None, help="Path to YAML policy file to customize checks")

    args = parser.parse_args()

    # Acquire running-config
    try:
        running = get_running_config(args)
    except AuthenticationException as e:
        print(f"Authentication failed: {e}", file=sys.stderr)
        return 2
    except NetmikoTimeoutException as e:
        print(f"Connection timed out: {e}", file=sys.stderr)
        return 3
    except Exception as e:
        print(f"Error collecting running-config: {e}", file=sys.stderr)
        return 1

    # Load policy
    try:
        policy = load_policy(args.policy)
    except Exception as e:
        print(f"Failed to load policy file: {e}", file=sys.stderr)
        return 4

    # Run compliance
    checker = ComplianceChecker(running, policy)
    results = checker.run_all()

    # Metadata block for reports
    now = dt.datetime.now().isoformat(sep=" ", timespec="seconds")
    metadata = {
        "Device": args.host,
        "Device Type": args.device_type,
        "Generated": now,
        "Policy": policy.get("policy_name", os.path.basename(args.policy) if args.policy else "Default"),
    }

    # Determine output path
    ext = args.output
    outfile = args.outfile or f"compliance_{args.host.replace(':','_').replace('/','_')}.{ext}"

    # Write report
    if args.output == "csv":
        write_csv(results, outfile, metadata)
    else:
        write_html(results, outfile, metadata)

    print(f"Wrote {args.output.upper()} report to: {outfile}")
    # Return nonzero if any FAIL present
    has_fail = any(r.get("status") == "FAIL" for r in results)
    return 10 if has_fail else 0


if __name__ == "__main__":
    sys.exit(main())
