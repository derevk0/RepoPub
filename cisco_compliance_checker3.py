"""
This is the yaml policy:
-----------------------
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

#acl_check:
#  enabled: true
#  name: "Extended ACL 100 regex"
#  patterns:
#    - |
#      (?ms)^ip access-list extended 100
#      \n\s*10 permit tcp 192\.168\.1\.0 0\.0\.0\.255 any eq www
#      \n\s*20 permit tcp 192\.168\.1\.0 0\.0\.0\.255 any eq 443
#      \n(?=^ip access-list|^interface|^router|\Z)

# acls:
  # enabled: true
  # name: "ACL 100 - Web Access"
  # patterns:
    # - |-
      # (?ms)^ip access-list extended 100\n\s*10 permit tcp 192\.168\.1\.0 0\.0\.0\.255 any eq www\n\s*20 permit tcp 192\.168\.1\.0 0\.0\.0\.255 any eq 443\n(?=^ip access-list|^interface|^router|\Z)

acls:
  enabled: true
  name: "ACL 100 - Web Access"
  patterns:
    - |-
      (?ms)^ip access-list extended 100\n\s*10 permit tcp 192\.168\.1\.0 0\.0\.0\.255 any eq www\n\s*20 permit tcp 192\.168\.1\.0 0\.0\.0\.255 any eq 443\n(?=^!|\Z)

ntp:
  enabled: true
  name: "NTP Configuration"
  patterns:
    - "^ntp server"
    - "^ntp authenticate"

snmp:
  enabled: true
  name: "SNMP Configuration"
  patterns:
    - "^snmp-server community"
    - "^snmp-server user"

http_server:
  enabled: true
  name: "HTTP Server Configuration"
  patterns:
    - "^no ip http server$"
-----------------------
"""
#!/usr/bin/env python3
"""
Cisco Device Compliance Checker (Regex-based, Named Sections)

Requirements:
1) Uses Netmiko to connect to a Cisco device, OR a saved running-config file.
2) Collects running-config ("show running-config") if connecting to device.
3) Checks compliance by matching regex patterns defined in a policy.yaml.
   - Each section has:
        enabled: true|false
        name: <custom name>
        patterns: <list of regex>
4) Results saved to CSV or HTML with fields:
   Section | Name | Status | Details

Install prerequisites:
    pip install netmiko pyyaml

Example usage:
1.    python cisco_compliance_checker.py \
        --host 192.0.2.10 --username admin --password 'p@ss' \
        --device-type cisco_ios --output html --outfile results.html --policy policy.yaml --secret 'p@ss'

      oneline example: python3 cisco_compliance_checker2.py --host 172.31.35.3 --username admin --password 'cisco' --device-type cisco_xe --output html --outfile results.html --policy policy.yml --secret 'cisco'

2. Or run against a saved running-config file:
      python cisco_compliance_checker.py \
        --config-file sample_running_config.txt --output csv --outfile results.csv --policy policy.yaml

      oneline example: python3 cisco_compliance_checker2.py --config-file running_config.txt --policy policy.yml --output html --outfile results.html
"""
import argparse
import csv
from datetime import datetime
import os
import re
import sys
from typing import Any, Dict, List, Optional
import logging  # Added for debug logging

from netmiko import ConnectHandler
from netmiko.exceptions import NetmikoTimeoutException, AuthenticationException

try:
    import yaml  # type: ignore
except Exception:
    yaml = None

# -----------------------------
# Setup debug logging
# -----------------------------
logging.basicConfig(
    filename="compliance_debug.log",
    level=logging.DEBUG,
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
            "details": details,
        }

    def check_section(self, section: str, name: str, patterns: List[str]) -> List[Dict[str, str]]:
        results: List[Dict[str, str]] = []
        for pattern in patterns:
            try:
                if re.search(pattern, self.raw, re.MULTILINE | re.DOTALL):
                    results.append(self._result(section, name, "PASS", f"Pattern '{pattern}' found"))
                else:
                    results.append(self._result(section, name, "FAIL", f"Pattern '{pattern}' missing"))
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
            results.extend(self.check_section(section, name, patterns))
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
        logging.debug(f"Connecting to device {host} with device_type {device_type}")
        with ConnectHandler(**device) as conn:
            if secret:
                logging.debug(f"Entering enable mode on {host}")
                conn.enable()

            output = conn.send_command("show running-config")
            logging.debug(f"Retrieved running-config from {host}, length={len(output)}")

            # Save running-config to file
            filename = f"running-config-{host}.txt"
            with open(filename, "w") as f:
                f.write(output)
            logging.debug(f"Saved running-config to {filename}")

            return output
    except (NetmikoTimeoutException, AuthenticationException) as e:
        logging.error(f"Connection failed: {e}")
        print(f"Connection failed: {e}")
        sys.exit(1)


def get_running_config_from_file(path: str) -> str:
    if not os.path.exists(path):
        logging.error(f"Config file {path} not found")
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


def write_csv(results: List[Dict[str, str]], outfile: str, suffix: str) -> str:
    base, ext = os.path.splitext(outfile)
    final_file = f"{base}_{suffix}{ext}"
    with open(final_file, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["section", "name", "status", "details"])
        writer.writeheader()
        for row in results:
            writer.writerow(row)
    logging.debug(f"CSV report saved as {final_file}")
    return final_file


def write_html(results: List[Dict[str, str]], outfile: str, suffix: str, source_info: str) -> str:
    base, ext = os.path.splitext(outfile)
    final_file = f"{base}_{suffix}{ext}"
    with open(final_file, "w") as f:
        f.write("<html><head><title>Device Compliance Report</title>\n")
        f.write("<style>\n")
        f.write("""
            body {
                font-family: Arial, sans-serif;
                margin: 20px;
                background-color: #f9f9f9;
            }
            h1 {
                color: #333333;
            }
            table {
                border-collapse: collapse;
                width: 100%;
                margin-top: 20px;
                box-shadow: 0 2px 5px rgba(0,0,0,0.1);
            }
            th, td {
                border: 1px solid #dddddd;
                text-align: left;
                padding: 10px;
                word-wrap: break-word;
            }
            th {
                background-color: #4CAF50;
                color: white;
            }
            tr:nth-child(even) {
                background-color: #f2f2f2;
            }
            tr:hover {
                background-color: #ddd;
            }
        """)
        f.write("</style></head><body>\n")
        f.write(
            f"<h1>Device Compliance Report<br>"
            f"<span style='font-size:20px; color:#555;'>{datetime.now().strftime('%A, %d %B %Y %I:%M %p')}</span></h1>\n"
        )
        f.write(f"<p><strong>Configuration Source:</strong> {source_info}</p>\n")
        f.write("<table><tr><th>Section</th><th>Name</th><th>Status</th><th>Details</th></tr>\n")
        for row in results:
            color = "green" if row["status"] == "PASS" else ("red" if row["status"] == "FAIL" else "orange")
            f.write(
                f"<tr><td>{row['section']}</td><td>{row['name']}</td>"
                f"<td style='color:{color}; font-weight:bold'>{row['status']}</td>"
                f"<td>{row['details']}</td></tr>\n"
            )
        f.write("</table></body></html>\n")
    logging.debug(f"HTML report saved as {final_file}")
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
        logging.debug(f"Loading running-config from file: {args.config_file}")
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

    logging.debug(f"Loading policy from {args.policy}")
    policy = load_policy(args.policy)
    checker = ComplianceChecker(running_config, policy)
    results = checker.run_all()

    if args.output == "csv":
        final_file = write_csv(results, args.outfile, suffix)
        print(f"Compliance report written to {final_file}")
    else:
        final_file = write_html(results, args.outfile, suffix, source_info)
        print(f"Compliance report written to {final_file}")

    logging.debug(f"Compliance report written to {final_file}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
