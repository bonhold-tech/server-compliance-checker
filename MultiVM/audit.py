__version__ = "0.2.3"
import os
import subprocess
import datetime
import sys

from pathlib import Path

SSHD_FILEPATH = Path("/etc/ssh/sshd_config")
MISSING_FILE = "File not found."


def file_verify(filepath, expected_line, expected_value):
    """Open a file and check if a specific key line matches the expected value.

    Skips commented lines starting with '#'. Returns 'Pass' or 'Fail'.
    """
    with open(filepath, "r", encoding="utf-8") as permission:
        for line in permission:
            if expected_line.lower() in line.lower():
                if not line.strip().startswith("#"):
                    if expected_value.lower() in line.lower():
                        return "Pass"
                    else:
                        return "Fail"
        return "Fail"


def ubuntu_checklist():
    """Execute the full security compliance audit checklist tailored for Ubuntu systems."""
    ubuntu_results = {}
    # Checking access and permissions for SSH and OS configuration
    try:
        ubuntu_sshd = file_verify(SSHD_FILEPATH, "PermitRootLogin", "no")
        ubuntu_results["sshd"] = ubuntu_sshd
    except FileNotFoundError:
        ubuntu_results["sshd"] = MISSING_FILE

    try:
        ubuntu_os = file_verify("/etc/os-release", "NAME", "Ubuntu")
        ubuntu_results["os"] = ubuntu_os
    except FileNotFoundError:
        ubuntu_results["os"] = MISSING_FILE

    try:
        ubuntu_pass = file_verify(SSHD_FILEPATH, "PasswordAuthentication", "no")
        ubuntu_results["password"] = ubuntu_pass
    except FileNotFoundError:
        ubuntu_results["password"] = MISSING_FILE

    # Verifying Firewall status via UFW
    ubuntu_ufw = subprocess.run(["ufw", "status"], capture_output=True, text=True)
    print("Firewall status:", ubuntu_ufw.stdout, file=sys.stderr)

    if "active" in ubuntu_ufw.stdout:
        firewall_status = "Pass"
    else:
        firewall_status = "Fail"

    ubuntu_results["firewall"] = firewall_status

    # Checking restictiveness of file permissions for /etc/shadow
    try:
        ubuntu_shadow = Path("/etc/shadow")
        ubuntu_perm = os.stat(ubuntu_shadow)
        ubuntu_restrict = oct(ubuntu_perm.st_mode)[-3:]
        print("Permissions:", ubuntu_restrict, file=sys.stderr)
        if "600" in ubuntu_restrict:
            print("Pass", file=sys.stderr)
        else:
            print(
                "Fail, possible secuirty breach, due to file accessible for many groups/users.",
                file=sys.stderr,
            )
        ubuntu_results["restrict"] = ubuntu_restrict
    except PermissionError as e:
        ubuntu_results["restrict"] = f"Error, access denied, {e}."

    # Checking fail2ban service operational state
    try:
        ubuntu_fail2ban = subprocess.run(
            ["systemctl", "status", "fail2ban"], capture_output=True, text=True
        )
        print("File2ban status:", ubuntu_fail2ban.stdout, file=sys.stderr)
        ubuntu_split = ubuntu_fail2ban.stdout.splitlines()
        if "could not be found" in ubuntu_fail2ban.stderr:
            fail2ban_status = "Unit fail2ban.service could not be found."
        else:
            print("Fail2ban installed.", file=sys.stderr)

            for line in ubuntu_split:
                if "active" in line.lower():
                    if "active (running)" in line.lower():
                        fail2ban_status = "Fail2ban active"
                    else:
                        fail2ban_status = "Fail2ban inactive (dead), possible security issue. Please enable service."
                    break
        ubuntu_results["fail2ban"] = fail2ban_status
    except FileNotFoundError:
        ubuntu_results["fail2ban"] = (
            "Error - systemctl could not be found or it is damaged."
        )

    # Checking system update availability
    ubuntu_update = subprocess.run(
        ["apt", "list", "--upgradable"], capture_output=True, text=True
    )
    if ubuntu_update.stdout == "":
        update_status = "OS updated"
    else:
        update_list = ubuntu_update.stdout.splitlines()
        update_status = len(update_list) - 1

    ubuntu_results["update"] = update_status

    # Checking if the 'consultant' account has an expiration date set
    ubuntu_accexpiry = subprocess.run(
        ["chage", "-l", "consultant"], capture_output=True, text=True
    )
    consultant_status = "Could not determin expiration status."
    ubuntu_accsplit = ubuntu_accexpiry.stdout.splitlines()
    ubuntu_now = datetime.datetime.now()
    for line in ubuntu_accsplit:
        if "account expires" in line.lower():
            if "never" in line.lower():
                consultant_status = "Pass. Account never expires."
            else:
                ubuntu_colon = line.split(":")
                ubuntu_index = ubuntu_colon[1]
                ubuntu_split = ubuntu_index.strip()
                ubuntu_consultant = datetime.datetime.strptime(
                    ubuntu_split, "%b %d, %Y"
                )
                if ubuntu_consultant >= ubuntu_now:
                    consultant_status = f"Account expiration date:{ubuntu_consultant}"
                else:
                    consultant_status = f"Account expired:{ubuntu_consultant}"
    ubuntu_results["consultant"] = consultant_status

    return ubuntu_results


def centos_checklist():
    """Execute the full security compliance audit checklist tailored for CentOS systems."""

    centos_results = {}

    # Checking access and permissions for SSH and OS configuration
    try:
        centos_sshd = file_verify(SSHD_FILEPATH, "PermitRootLogin", "no")
        centos_results["sshd"] = centos_sshd
    except FileNotFoundError:
        centos_results["sshd"] = MISSING_FILE

    try:
        centos = file_verify("/etc/os-release", "NAME", "CentOS")
        centos_results["os"] = centos
    except FileNotFoundError:
        centos_results["os"] = MISSING_FILE

    try:
        centos_pass = file_verify(SSHD_FILEPATH, "PasswordAuthentication", "no")
        centos_results["password"] = centos_pass
    except FileNotFoundError:
        centos_results["password"] = MISSING_FILE

    # Verifying Firewall status via firewalld
    centos_firewalld = subprocess.run(
        ["systemctl", "status", "firewalld"], capture_output=True, text=True
    )
    print("Firewall status:", centos_firewalld.stdout, file=sys.stderr)

    if "active" in centos_firewalld.stdout:
        firewall_status = "Pass"
    else:
        firewall_status = "Fail"

    centos_results["firewall"] = firewall_status

    # Checking restictiveness of file permissions for /etc/shadow
    try:
        centos_shadow = Path("/etc/shadow")
        centos_perm = os.stat(centos_shadow)
        centos_restrict = oct(centos_perm.st_mode)[-3:]
        centos_results["restrict"] = centos_restrict
    except PermissionError as e:
        centos_results["restrict"] = f"Error, access denied, {e}."

    # Checking fail2ban service operational state
    try:
        centos_fail2ban = subprocess.run(
            ["systemctl", "status", "fail2ban"], capture_output=True, text=True
        )
        print("File2ban status:", centos_fail2ban.stdout, file=sys.stderr)
        centos_split = centos_fail2ban.stdout.splitlines()
        if "could not be found" in centos_fail2ban.stderr:
            fail2ban_status = "Unit fail2ban.service could not be found."
        else:
            print("Fail2ban installed.", file=sys.stderr)

            for line in centos_split:
                if "active" in line.lower():
                    if "active (running)" in line.lower():
                        fail2ban_status = "Fail2ban active"
                    else:
                        fail2ban_status = "Fail2ban inactive (dead), possible security issue. Please enable service."
                    break
        centos_results["fail2ban"] = fail2ban_status
    except FileNotFoundError:
        centos_results["fail2ban"] = (
            "Unit fail2ban.service could not be found. Please install fail2ban service."
        )

    # Checking system update availability via security channel
    centos_update = subprocess.run(
        ["dnf", "check-update", "--security"], capture_output=True, text=True
    )
    print("Update status:", centos_update.stdout, file=sys.stderr)

    if centos_update.returncode == 0:
        update_status = "OS updated"
    elif centos_update.returncode == 1:
        update_status = "Failed during checking process."
    else:
        update_list = centos_update.stdout.splitlines()
        update_status = len(update_list)

    centos_results["update"] = update_status

    # Checking if the 'consultant' account has an expiration date set
    centos_accexpiry = subprocess.run(
        ["chage", "-l", "consultant"], capture_output=True, text=True
    )
    consultant_status = "Could not determin expiration status."
    centos_accsplit = centos_accexpiry.stdout.splitlines()
    centos_now = datetime.datetime.now()
    for line in centos_accsplit:
        if "account expires" in line.lower():
            if "never" in line.lower():
                consultant_status = "Pass. Account never expires."
            else:
                centos_colon = line.split(":")
                centos_index = centos_colon[1]
                centos_split = centos_index.strip()
                centos_consultant = datetime.datetime.strptime(
                    centos_split, "%b %d, %Y"
                )
                if centos_consultant >= centos_now:
                    consultant_status = f"Account expiration date:{centos_consultant}"
                else:
                    consultant_status = f"Account expired:{centos_consultant}"
    centos_results["consultant"] = consultant_status

    return centos_results


if __name__ == "__main__":
    ubuntu_checklist()
    centos_checklist()
