"""
YAML:
logging:
  enabled: true
  name: "Logging Configuration"
  patterns:
    - "^logging buffered"
    - "^logging host"
    - "^no logging console"

aaa:
  enabled: true
  name: "AAA Configuration"
  patterns:
    - "^aaa new-model$"
    - "^aaa authentication login default"

banner:
  enabled: true
  name: "Banner Configuration"
  patterns:
    - "^banner motd"

vty_0_4:
  enabled: true
  name: "VTY 0-4 Configuration"
  section_match: "^line vty 0 4$"
  patterns:
    - "logging synchronous"
    - "transport input all"
    - "login local"
    - "^eddy 123$"
#    - |
#      (?ms)^line vty 0 4
#      \n\s*logging synchronous
#      \n\s*exec-timeout 0 0

vty_5_15:
  enabled: true
  name: "VTY 5-15 Configuration"
  section_match: "^line vty 5 15$"
  patterns:
    - "login local"
    - "transport input all"

routing:
  enabled: true
  name: "EIGRP 10 Configuration"
  section_match: "^router eigrp 10$"
  patterns:
    - "^no passive-interface Tunnel0$"
    - "^network 10\\.10\\.37\\.0 0\\.0\\.0\\.255$"
    - "passive-interface default"

acls:
  enabled: true
  name: "ACL 100 - Web Access"
  patterns:
    - |-
      (?ms)^ip access-list extended 100\n\s*10 permit tcp 192\.168\.1\.0 0\.0\.0\.255 any eq www\n\s*20 permit tcp 192\.168\.1\.0 0\.0\.0\.255 any eq 443\n(?=^!|\Z)

acls2:
  enabled: true
  name: "ACL 100 - Web Access - 2"
  patterns:
    - |-
      (?ms)^ip access-list extended 100
      \s*10 permit tcp 192\.168\.1\.0 0\.0\.0\.255 any eq www
      \s*20 permit tcp 192\.168\.1\.0 0\.0\.0\.255 any eq 443
      (?=^!|\Z)
"""
import argparse
import csv
from datetime import datetime
import os
import re
import sys
from typing import Any, Dict, List, Optional
import logging

from netmiko import ConnectHandler
from netmiko.exceptions import NetmikoTimeoutException, AuthenticationException

try:
    import yaml  # type: ignore
except Exception:
    yaml = None

logging.basicConfig(
    filename="compliance_debug.log",
    level=logging.ERROR,
    format="%(asctime)s [%(levelname)s] %(message)s",
)


class ComplianceChecker:
    def __init__(self, running_config: str, policy: Dict[str, Any]):
        self.raw = running_config
        self.policy = policy or {}

    def _result(self, section: str, name: str, status: str, details: str) -> Dict[str, str]:
        return {
            "section": section,
            "name": name,
            "status": status,
            "details": details.strip(),
        }

    def _extract_section(self, section_match: str) -> Optional[str]:
        lines = self.raw.splitlines()
        inside = False
        collected = []

        for line in lines:
            if not inside:
                if re.match(section_match, line.strip()):
                    inside = True
                    collected.append(line)
            else:
                if line.startswith(" "):  # inside section
                    collected.append(line)
                elif line.strip() == "!":  # explicit section end
                    break
                else:  # another top-level command starts
                    break

        if collected:
            return "\n".join(collected)
        return None

    def _prettify_pattern(self, pattern: str) -> str:
        """
        Convert regex-like patterns into a user-friendly config-like string.
        Handles escaped whitespace, \n, and indentation.
        """
        pretty = pattern
        pretty = pretty.replace(r"\n", "\n")
        pretty = re.sub(r"\\s\*", " ", pretty)
        pretty = pretty.replace(r"\.", ".")
        pretty = pretty.replace(r"\Z", "")
        pretty = pretty.replace(r"(?ms)", "")
        pretty = pretty.replace(r"(?=^!|\Z)", "")
        return pretty.strip()

    def check_section(
        self, section: str, name: str, patterns: List[str], section_match: Optional[str] = None
    ) -> List[Dict[str, str]]:
        results: List[Dict[str, str]] = []

        target_config = self.raw
        if section_match:
            extracted = self._extract_section(section_match)
            if not extracted:
                results.append(self._result(section, name, "FAIL", f"Section '{section_match}' not found"))
                return results
            target_config = "\n".join(line.lstrip() for line in extracted.splitlines())

        for pattern in patterns:
            try:
                match = re.search(pattern, target_config, re.MULTILINE | re.DOTALL)
                if match:
                    matched_text = match.group(0).strip()
                    results.append(
                        self._result(section, name, "PASS", f"Found required config:\n{matched_text}")
                    )
                else:
                    pretty = self._prettify_pattern(pattern)
                    results.append(
                        self._result(section, name, "FAIL", f"Expected command(s) missing:\n{pretty}")
                    )
            except re.error as e:
                results.append(self._result(section, name, "ERROR", f"Invalid regex: {e}"))
        return results

    def run_all(self) -> List[Dict[str, str]]:
        results: List[Dict[str, str]] = []
        for section, config in self.policy.items():
            if not config.get("enabled", False):
                continue
            name = config.get("name", section)
            patterns = config.get("patterns", [])
            if isinstance(patterns, str):
                patterns = [patterns]
            section_match = config.get("section_match")
            results.extend(self.check_section(section, name, patterns, section_match))
        return results


def get_running_config_from_device(
    host: str, username: str, password: str, device_type: str, secret: Optional[str] = None
) -> str:
    device = {
        "device_type": device_type,
        "host": host,
        "username": username,
        "password": password,
    }
    if secret:
        device["secret"] = secret

    try:
        with ConnectHandler(**device) as conn:
            if secret:
                conn.enable()
            output = conn.send_command("show running-config")

            filename = f"running-config-{host}.txt"
            with open(filename, "w") as f:
                f.write(output)

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


def group_results(results: List[Dict[str, str]]) -> Dict[tuple, List[Dict[str, str]]]:
    grouped: Dict[tuple, List[Dict[str, str]]] = {}
    for row in results:
        key = (row["section"], row["name"])
        grouped.setdefault(key, []).append(row)
    return grouped


def write_csv(results: List[Dict[str, str]], outfile: str, suffix: str) -> str:
    base, ext = os.path.splitext(outfile)
    final_file = f"{base}_{suffix}{ext}"

    grouped = group_results(results)

    with open(final_file, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["section", "name", "status", "details"])
        for (section, name), rows in grouped.items():
            for i, row in enumerate(rows):
                if i == 0:
                    writer.writerow([section, name, row["status"], row["details"]])
                else:
                    writer.writerow(["", "", row["status"], row["details"]])

    return final_file


def write_html(results: List[Dict[str, str]], outfile: str, suffix: str, source_info: str) -> str:
    base, ext = os.path.splitext(outfile)
    final_file = f"{base}_{suffix}{ext}"

    grouped = group_results(results)

    with open(final_file, "w") as f:
        f.write("<html><head><title>Device Compliance Report</title>\n")
        f.write("<style>\n")
        f.write("""
            body { font-family: Arial, sans-serif; margin: 20px; background-color: #f9f9f9; }
            h1 { color: #333333; }
            table { border-collapse: collapse; width: 100%; margin-top: 20px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }
            th, td { border: 1px solid #dddddd; text-align: left; padding: 10px; word-wrap: break-word; white-space: pre-wrap; }
            th { background-color: #4CAF50; color: white; }
            tr:nth-child(even) { background-color: #f2f2f2; }
            tr:hover { background-color: #ddd; }
        """)
        f.write("</style></head><body>\n")
        f.write(
            f"<h1>Device Compliance Report<br>"
            f"<span style='font-size:20px; color:#555;'>{datetime.now().strftime('%A, %d %B %Y %I:%M %p')}</span></h1>\n"
        )
        f.write(f"<p><strong>Configuration Source:</strong> {source_info}</p>\n")
        f.write("<table><tr><th>Section</th><th>Name</th><th>Status</th><th>Details</th></tr>\n")

        for (section, name), rows in grouped.items():
            rowspan = len(rows)
            for i, row in enumerate(rows):
                color = "green" if row["status"] == "PASS" else ("red" if row["status"] == "FAIL" else "orange")
                f.write("<tr>")
                if i == 0:
                    f.write(f"<td rowspan='{rowspan}'>{section}</td>")
                    f.write(f"<td rowspan='{rowspan}'>{name}</td>")
                f.write(f"<td style='color:{color}; font-weight:bold'>{row['status']}</td>")
                f.write(f"<td>{row['details']}</td>")
                f.write("</tr>\n")

        f.write("</table></body></html>\n")

    return final_file


def main() -> int:
    parser = argparse.ArgumentParser(description="Cisco Compliance Checker (Regex-based, Named Sections)")
    parser.add_argument("--host", help="Device hostname or IP")
    parser.add_argument("--username", help="Device username")
    parser.add_argument("--password", help="Device password")
    parser.add_argument("--secret", help="Enable password for device if required")
    parser.add_argument("--device-type", default="cisco_ios", help="Netmiko device type (default: cisco_ios)")
    parser.add_argument("--config-file", help="Path to local running-config file instead of connecting to device")
    parser.add_argument("--policy", required=True, help="Path to policy YAML file")
    parser.add_argument("--output", choices=["csv", "html"], required=True, help="Output format")
    parser.add_argument("--outfile", required=True, help="Output file path")
    args = parser.parse_args()

    if args.config_file:
        running_config = get_running_config_from_file(args.config_file)
        source_info = f"Local File ({os.path.basename(args.config_file)})"
        suffix = os.path.splitext(os.path.basename(args.config_file))[0]
    else:
        if not (args.host and args.username and args.password):
            print("Must provide either --config-file OR --host/--username/--password")
            return 1
        running_config = get_running_config_from_device(
            args.host, args.username, args.password, args.device_type, args.secret
        )
        source_info = f"{args.host}"
        suffix = args.host

    policy = load_policy(args.policy)
    checker = ComplianceChecker(running_config, policy)
    results = checker.run_all()

    if args.output == "csv":
        final_file = write_csv(results, args.outfile, suffix)
        print(f"Compliance report written to {final_file}")
    else:
        final_file = write_html(results, args.outfile, suffix, source_info)
        print(f"Compliance report written to {final_file}")

    return 0


if __name__ == "__main__":
    sys.exit(main())


