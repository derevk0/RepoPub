import os
import csv
import difflib
import argparse
import logging
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from netmiko import ConnectHandler
from netmiko.exceptions import NetmikoTimeoutException, AuthenticationException
from io import StringIO

# Argument Parsing
def parse_arguments():
    parser = argparse.ArgumentParser(
        description="Run pre/post checks on network devices and generate diffs."
    )
    parser.add_argument("devices_file", help="List of devices in csv file format")
    parser.add_argument("commands_file", help="List of commands file")
    parser.add_argument("change_number", help="Change or Service Request number")
    parser.add_argument("--output-dir", help="Optional custom output directory")
    return parser.parse_args()

# Timestamp
hour_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

# Logging Setup
def setup_logging(output_dir):
    log_file = os.path.join(output_dir, "debug_libraries.log")
    logger = logging.getLogger()
    logger.setLevel(logging.INFO)
    fh = logging.FileHandler(log_file, mode='a')
    fh.setLevel(logging.INFO)
    formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    fh.setFormatter(formatter)
    logger.handlers = []
    logger.addHandler(fh)

# Utility Functions
def read_devices(file_path):
    with open(file_path, newline="") as f:
        return list(csv.DictReader(f))

def read_commands(file_path):
    with open(file_path, "r") as f:
        return [line.strip() for line in f if line.strip()]

def sanitize_filename(command):
    return command.replace(" ", "_").replace("/", "_").replace("|", "_")

def get_output_path(host, command, stage, output_dir):
    command_name = sanitize_filename(command)
    return os.path.join(output_dir, f"{host}_{command_name}_{stage}.txt")

def get_diff_html_path(host, command, output_dir):
    command_name = sanitize_filename(command)
    return os.path.join(output_dir, f"{host}_{command_name}_diff.html")

def connect_and_execute(device, command, log_buf):
    host = device['host']
    try:
        log_buf.write(f"    ↪ Connecting to {host}...\n")
        logging.info(f"{host} - Connecting to device")
        conn = ConnectHandler(
            device_type=device["device_type"],
            host=host,
            username=device["username"],
            password=device["password"],
            secret=device.get("secret", "")
        )
        conn.enable()
        output = conn.send_command(command)
        conn.disconnect()
        log_buf.write(f"    ✔ Connected and command executed.\n")
        logging.info(f"{host} - Command executed: {command}")
        return output
    except (AuthenticationException, NetmikoTimeoutException) as e:
        log_buf.write(f"    ❌ Connection error: {e}\n")
        logging.info(f"{host} - Connection failed: {e}")
        return f"[ERROR] Connection failed: {e}"
    except Exception as e:
        log_buf.write(f"    ❌ Unexpected error: {e}\n")
        logging.info(f"{host} - Unexpected error: {e}")
        return f"[ERROR] Unexpected error: {e}"

def save_output(path, content):
    with open(path, "w") as f:
        f.write(hour_time + '\n')
        f.write("=" * 20 + '\n')
        f.write(content)

def read_output(path):
    if not os.path.exists(path):
        return None
    with open(path, "r") as f:
        return f.readlines()

def generate_diff_html(pre_lines, post_lines, host, command, output_dir, log_buf):
    differ = difflib.HtmlDiff(wrapcolumn=80)
    html = differ.make_file(pre_lines, post_lines, fromdesc="Pre-Test", todesc="Post-Test")
    html_path = get_diff_html_path(host, command, output_dir)
    with open(html_path, "w") as f:
        f.write(f"<h3>{host} - {command}</h3>\n")
        f.write(html)
    log_buf.write(f"    🧾 Diff generated: {html_path}\n")
    logging.info(f"{host} - Diff saved: {html_path}")

def process_device_command(device, command, output_dir):
    host = device['host']
    log_buf = StringIO()
    log_buf.write(f"\n🔧 Device: {host}\n")
    log_buf.write(f"    ⤷ Command: '{command}'\n")

    output = connect_and_execute(device, command, log_buf)
    if output is None or "[ERROR]" in output:
        log_buf.write(f"    ⛔ Skipping due to error.\n")
        return log_buf.getvalue()

    pre_path = get_output_path(host, command, "pre", output_dir)
    post_path = get_output_path(host, command, "post", output_dir)

    if not os.path.exists(pre_path):
        save_output(pre_path, output)
        log_buf.write(f"    💾 PRE-test saved to: {pre_path}\n")
        logging.info(f"{host} - Pre-test saved")
    else:
        save_output(post_path, output)
        log_buf.write(f"    💾 POST-test saved to: {post_path}\n")
        logging.info(f"{host} - Post-test saved")

        pre_lines = read_output(pre_path)
        post_lines = read_output(post_path)

        if pre_lines and post_lines:
            log_buf.write(f"    🔍 Generating diff...\n")
            generate_diff_html(pre_lines, post_lines, host, command, output_dir, log_buf)

    return log_buf.getvalue()

def main():
    args = parse_arguments()

    output_dir = args.output_dir or f"diff_outputs_{args.change_number}"
    os.makedirs(output_dir, exist_ok=True)
    setup_logging(output_dir)

    devices = read_devices(args.devices_file)
    commands = read_commands(args.commands_file)

    print(f"\n🚀 Starting diff script at {hour_time}...\n")
    logging.info("=== Script started ===")

    futures = []
    all_console_output = []

    with ThreadPoolExecutor(max_workers=10) as executor:
        for device in devices:
            for command in commands:
                futures.append(executor.submit(process_device_command, device, command, output_dir))

        for future in as_completed(futures):
            output = future.result()
            print(output)
            all_console_output.append(output)

    # Save all console outputs to file
    console_log_path = os.path.join(output_dir, "console_output.log")
    with open(console_log_path, "w") as f:
        for entry in all_console_output:
            f.write(entry + "\n")

    finish_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    print(f"\n✅ Finished at {finish_time}\n")
    logging.info("=== Script finished ===")

if __name__ == "__main__":
    main()
