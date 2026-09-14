import subprocess
import platform
import sys
from pathlib import Path
from audit import ubuntu_checklist
from audit import centos_checklist


def get_id_distro():
    """Execute Linux Distribution check by entering to /etc/os-release and retrieving Operating System ID."""
    os_release = platform.freedesktop_os_release()
    os_id = [os_release["ID"]]
    if "ID_LIKE" in os_release:
        os_id.extend(os_release["ID_LIKE"].split())
    return os_id


# Main routing switch using the CLI flag barrier
if "--inside-vm" in sys.argv:
    # --- THIS ROOM EXECUTES ONLY INSIDE THE VIRTUAL MACHINES ---
    try:
        # Single switch checking the OS of the current VM
        if "ubuntu" in get_id_distro():
            ubuntu_checklist()
        elif "centos" in get_id_distro() or "rhel" in get_id_distro():
            centos_checklist()
        else:
            print("Incorrect OS: This Linux distribution is not supported.")
    except OSError:
        print("Neither /etc/os-release nor /usr/lib/os-release can be read.")

else:
    # --- THIS ROOM EXECUTES ONLY ON YOUR LIVE HOST COMPUTER ---
    print("Orchestrator started. Raising and auditing virtual infrastructure...")

    # 1. Fire up and audit the Ubuntu Web Server (web01)
    print("\n--- Auditing web01 (Ubuntu) ---")
    subprocess.run(["vagrant", "up", "web01"], capture_output=True, text=True)
    subprocess.run(
        [
            "vagrant",
            "ssh",
            "web01",
            "-c",
            "python3 /vagrant/checker.py --inside-vm",
        ],
        capture_output=True,
        text=True,
    )

    # 2. Fire up and audit the CentOS Database Server (db01)
    print("\n--- Auditing db01 (CentOS) ---")
    subprocess.run(["vagrant", "up", "db01"], capture_output=True, text=True)
    subprocess.run(
        [
            "vagrant",
            "ssh",
            "db01",
            "-c",
            "python3 /vagrant/checker.py --inside-vm",
        ],
        capture_output=True,
        text=True,
    )
    print("\nAll virtual environments audited successfully.")
