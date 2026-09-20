__version__ = "0.2.2"
import subprocess
import sys
import json
import datetime
from pathlib import Path
from audit import ubuntu_checklist
from audit import centos_checklist


def get_id_distro():
    """Read /etc/os-release manually to determine the Linux distribution ID.

    This replaces platform.freedesktop_os_release() to support older Python versions.
    """
    try:
        with open("/etc/os-release", "r", encoding="utf-8") as f:
            for line in f:
                if line.startswith("ID="):
                    # Extract the value after '=' and remove quotes/whitespace
                    return line.split("=")[1].strip().strip('"').lower()
    except OSError:
        return "unknown"
    return "unknown"


# Main routing switch using the CLI flag barrier
if "--inside-vm" in sys.argv:
    # --- THIS ROOM EXECUTES ONLY INSIDE THE VIRTUAL MACHINES ---
    distro = get_id_distro()

    if "ubuntu" in distro:
        results = ubuntu_checklist()
    elif "centos" in distro or "rhel" in distro:
        results = centos_checklist()
    else:
        results = f"Incorrect OS: Distribution '{distro}' is not supported."

    json_report = json.dumps(results, indent=2)
    print(json_report)

else:
    # --- THIS ROOM EXECUTES ONLY ON YOUR LIVE HOST COMPUTER ---
    print("Orchestrator started. Raising and auditing virtual infrastructure...")

    # 1. Fire up and audit the Ubuntu Web Server (web01)
    print("\n--- Auditing web01 (Ubuntu) ---")
    subprocess.run(["vagrant", "up", "web01"])
    web01_json = subprocess.run(
        [
            "vagrant",
            "ssh",
            "web01",
            "-c",
            "sudo python3 /vagrant/checker.py --inside-vm",
        ],
        capture_output=True,
        text=True,
    )
    web01_output = json.loads(web01_json.stdout)

    # 2. Fire up and audit the CentOS Database Server (db01)
    print("\n--- Auditing db01 (CentOS) ---")
    subprocess.run(["vagrant", "up", "db01"])
    db01_json = subprocess.run(
        [
            "vagrant",
            "ssh",
            "db01",
            "-c",
            "sudo python3 /vagrant/checker.py --inside-vm",
        ],
        capture_output=True,
        text=True,
    )
    db01_output = json.loads(db01_json.stdout)

    # 3. Creating nested dictionary with outputs form VM's
    vm_output = {"web01": {"web01": web01_output}, "db01": {"db01": db01_output}}

    # Setting up --json flag and saving file.json into a local host
    if "--json" in sys.argv:
        now = datetime.datetime.now()
        timestamp = now.strftime("%b-%d-%Y")
        Path(
            "/home/mateusz/DATA/gitrepos/server-compliance-checker/MultiVM/audit_reports"
        ).mkdir(exist_ok=True)
        report_filepath = Path(
            f"/home/mateusz/DATA/gitrepos/server-compliance-checker/MultiVM/audit_reports/{timestamp} audit_report.json"
        )
        print(timestamp)

        with open(report_filepath, "w", encoding="utf-8") as report:
            json.dump(vm_output, report)
    else:
        print("Invalid output.")

    print("\nAll virtual environments audited successfully.")
