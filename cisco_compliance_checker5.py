import argparse
import csv
from datetime import datetime
import os
import re
import sys
from typing import Any, Dict, List, Optional, Union
import logging

from netmiko import ConnectHandler
from netmiko.exceptions import NetmikoTimeoutException, AuthenticationException

try:
    import yaml  # type: ignore
    from yaml.loader import SafeLoader
except Exception:
    yaml = None

logging.basicConfig(
    filename="compliance_debug.log",
    level=logging.ERROR,
    format="%(asctime)s [%(levelname)s] %(message)s",
)


# -------- YAML Loader that supports duplicate keys --------
class LoaderWithDuplicates(SafeLoader):
    pass


def construct_mapping(loader, node, deep=False):
    mapping = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        value = loader.construct_object(value_node, deep=deep)
        if key in mapping:
            # If duplicate key exists, merge into a list
            if not isinstance(mapping[key], list):
                mapping[key] = [mapping[key]]
            mapping[key].append(value)
        else:
            mapping[key] = value
    return mapping


LoaderWithDuplicates.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, construct_mapping
)


# -------- Compliance Checker --------
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
                if line.startswith(" "):  # still inside section
                    collected.append(line)
                elif line.strip() == "!":  # explicit end
                    break
                else:  # another section begins
                    break

        if collected:
            return "\n".join(collected)
        return None

    def _prettify_pattern(self, pattern: str) -> str:
        """Convert regex patterns into user-friendly CLI-like text."""
        pretty = pattern
        pretty = pretty.replace(r"\n", "\n")
        pretty = re.sub(r"\\s\*", " ", pretty)
        pretty = pretty.replace(r"\.", ".")
        pretty = pretty.replace(r"\Z", "")
        pretty = pretty.replace(r"(?ms)", "")
        pretty = re.sub(r"\(\?[=!].*?\)", "", pretty)  # remove lookaheads/lookbehinds
        pretty = pretty.replace("^", "")
        pretty = pretty.replace("$", "")
        pretty = re.sub(r"\n\s*\n", "\n", pretty)
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
                    # Add newline after colon for better readability
                    pretty = re.sub(r":\s*", ":\n", pretty)
                    results.append(
                        self._result(section, name, "FAIL", f"Expected command(s) missing:\n{pretty}")
                    )
            except re.error as e:
                results.append(self._result(section, name, "ERROR", f"Invalid regex: {e}"))
        return results

    def run_all(self) -> List[Dict[str, str]]:
        results: List[Dict[str, str]] = []
        for section, config in self.policy.items():
            if isinstance(config, list):
                for idx, sub_config in enumerate(config, 1):
                    if not sub_config.get("enabled", False):
                        continue
                    name = sub_config.get("name", f"{section}_{idx}")
                    patterns = sub_config.get("patterns", [])
                    if isinstance(patterns, str):
                        patterns = [patterns]
                    section_match = sub_config.get("section_match")
                    results.extend(self.check_section(section, name, patterns, section_match))
            else:
                if not config.get("enabled", False):
                    continue
                name = config.get("name", section)
                patterns = config.get("patterns", [])
                if isinstance(patterns, str):
                    patterns = [patterns]
                section_match = config.get("section_match")
                results.extend(self.check_section(section, name, patterns, section_match))
        return results


# -------- Device Config Retrieval --------
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
        return yaml.load(f, Loader=LoaderWithDuplicates)


# -------- Results Grouping --------
def group_results(results: List[Dict[str, str]]) -> Dict[str, List[Dict[str, str]]]:
    grouped: Dict[str, List[Dict[str, str]]] = {}
    for row in results:
        grouped.setdefault(row["section"], []).append(row)
    return grouped


# -------- Writers --------
def write_csv(results: List[Dict[str, str]], outfile: str, suffix: str) -> str:
    base, ext = os.path.splitext(outfile)
    final_file = f"{base}_{suffix}{ext}"

    grouped = group_results(results)

    with open(final_file, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["section", "name", "status", "details"])
        for section, rows in grouped.items():
            for row in rows:
                writer.writerow([section, row["name"], row["status"], row["details"]])

    return final_file


def write_html(results: List[Dict[str, str]], outfile: str, suffix: str, source_info: str) -> str:
    base, ext = os.path.splitext(outfile)
    final_file = f"{base}_{suffix}{ext}"

    grouped = group_results(results)

    with open(final_file, "w") as f:
        f.write("<html><head><title>Compliance Report</title>\n")
        f.write("<style>\n")
        f.write("""
            body { font-family: Arial, sans-serif; margin: 20px; background: #ffffff; color: #333; }
            h1 { margin-bottom: 5px; }
            h1 span { font-size: 16px; font-weight: normal; color: #666; }
            table { border-collapse: collapse; width: 100%; margin-top: 10px; table-layout: fixed; }
            th, td { border: 1px solid #ccc; padding: 4px 8px; text-align: left; vertical-align: top; word-wrap: break-word; }
            th { background: #6fa8dc; color: #fff; position: sticky; top: 0; z-index: 2; width: auto; }
            td:nth-child(1) { width: 200px; }  /* Section Name */
            td:nth-child(2) { width: 60px; }   /* Status */
            td:nth-child(3) { width: auto; }   /* Details */
            tr:nth-child(even) { background: #f9f9f9; }
            tr:hover { background: #f1f1f1; }
            .status-pass { color: green; font-weight: bold; }
            .status-fail { color: red; font-weight: bold; }
            .status-error { color: orange; font-weight: bold; }
            summary { cursor: pointer; font-size: 16px; font-weight: bold; margin-bottom: 5px; }
        """)
        f.write("</style></head><body>\n")
        f.write(f"<h1>Device Compliance Report<br><span>{datetime.now().strftime('%A, %d %B %Y %I:%M %p')}</span></h1>\n")
        f.write(f"<p><strong>Source:</strong> {source_info}</p>\n")

        for section, rows in grouped.items():
            f.write(f"<details open><summary>{section}</summary>\n")
            f.write("<table><tr><th>Section Name</th><th>Status</th><th>Details</th></tr>\n")
            for row in rows:
                css_class = "status-pass" if row["status"] == "PASS" else (
                    "status-fail" if row["status"] == "FAIL" else "status-error"
                )
                # Replace any embedded newlines for HTML readability
                details_html = row["details"].replace("\n", "<br>")
                f.write(f"<tr><td>{row['name']}</td><td class='{css_class}'>{row['status']}</td><td>{details_html}</td></tr>\n")
            f.write("</table></details><br>\n")

        f.write("</body></html>\n")

    return final_file


# -------- Main --------
def main() -> int:
    parser = argparse.ArgumentParser(description="Cisco Compliance Checker")
    parser.add_argument("--host", help="Device hostname or IP")
    parser.add_argument("--username", help="Device username")
    parser.add_argument("--password", help="Device password")
    parser.add_argument("--secret", help="Enable password for device if required")
    parser.add_argument("--device-type", default="cisco_ios", help="Netmiko device type")
    parser.add_argument("--config-file", help="Path to local running-config file")
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
        source_info = args.host
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
