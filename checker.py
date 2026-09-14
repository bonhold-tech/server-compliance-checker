import subprocess
import platform
import sys


from pathlib import Path
from audit import ubuntu_checklist
from audit import centos_checklist


def get_id_distro():
    """Execute Linux Distrubution check by entering to /etc/os-release and retreving Operating System ID"""
    # Check Linux Distrubtion
    os_release = platform.freedesktop_os_release()
    os_id = [os_release["ID"]]
    if "ID_LIKE" in os_release:
        os_id.extend(os_release["ID_LIKE"].split())
    return os_id


# Turning on VM web01 and accessing the VM
if "--inside-vm" in sys.argv:
    # Importing checklists from audit.py
    try:
        if get_id_distro() == "ubuntu":
            ubuntu_checklist()
        elif get_id_distro() == "centos":
            centos_checklist()
        else:
            print("Incorrect OS.")
    except OSError:
        print("Neither /etc/os-release nor /usr/lib/os-release can be read.")
else:
    # Turning on VM for the first time when accessing through host
    ubuntu_up = subprocess.run(
        ["vagrant", "up", "web01"], capture_output=True, text=True
    )
    ubuntu = subprocess.run(
        ["vagrant", "ssh", "web01", "-c", "python3 /vagrant/checker.py --inside-vm"],
        capture_output=True,
        text=True,
    )
