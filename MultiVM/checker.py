import subprocess
import sys
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
        ubuntu_checklist()
    elif "centos" in distro or "rhel" in distro:
        centos_checklist()
    else:
        print(f"Incorrect OS: Distribution '{distro}' is not supported.")

else:
    # --- THIS ROOM EXECUTES ONLY ON YOUR LIVE HOST COMPUTER ---
    print("Orchestrator started. Raising and auditing virtual infrastructure...")

    # 1. Fire up and audit the Ubuntu Web Server (web01)
    print("\n--- Auditing web01 (Ubuntu) ---")
    subprocess.run(["vagrant", "up", "web01"])
    subprocess.run(
        [
            "vagrant",
            "ssh",
            "web01",
            "-c",
            "sudo python3 /vagrant/checker.py --inside-vm",
        ]
    )

    # 2. Fire up and audit the CentOS Database Server (db01)
    print("\n--- Auditing db01 (CentOS) ---")
    subprocess.run(["vagrant", "up", "db01"])
    subprocess.run(
        [
            "vagrant",
            "ssh",
            "db01",
            "-c",
            "sudo python3 /vagrant/checker.py --inside-vm",
        ]
    )

    print("\nAll virtual environments audited successfully.")
