__version__ = "0.2.6"
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
        if ubuntu_sshd == "Pass":
            sshd_needs_fix = False
            sshd_comment = "PermitRootLogin turned off."
            sshd_state = "No further action required."

        else:
            sshd_needs_fix = True
            sshd_comment = "PermitRootLogin turned on."
            sshd_state = "Action required."

        ubuntu_results["sshd"] = {
            "needs_fix": sshd_needs_fix,
            "comment": sshd_comment,
            "state": sshd_state,
        }

    except FileNotFoundError as e:
        ubuntu_results["sshd"] = {
            "needs_fix": True,
            "comment": "PermitRootLogin not found.",
            "state": f"Action required, {e}",
        }

    try:
        ubuntu_os = file_verify("/etc/os-release", "NAME", "Ubuntu")
        ubuntu_results["os"] = ubuntu_os
    except FileNotFoundError:
        ubuntu_results["os"] = MISSING_FILE

    try:
        ubuntu_pass = file_verify(SSHD_FILEPATH, "PasswordAuthentication", "no")
        if ubuntu_pass == "Pass":
            pass_needs_fix = False
            pass_comment = "PasswordAuthentication turned off."
            pass_state = "No further action required."
        else:
            pass_needs_fix = True
            pass_comment = "PasswordAuthentication turned on."
            pass_state = "Action required."

        ubuntu_results["password"] = {
            "needs_fix": pass_needs_fix,
            "comment": pass_comment,
            "state": pass_state,
        }
    except FileNotFoundError as e:
        ubuntu_results["password"] = {
            "needs_fix": True,
            "comment": "PasswordAuthentication not found.",
            "state": f"Action required, {e}",
        }

    # Verifying Firewall status via UFW
    try:
        ubuntu_ufw = subprocess.run(["ufw", "status"], capture_output=True, text=True)
        print("Firewall status:", ubuntu_ufw.stdout, file=sys.stderr)

        if "active" in ubuntu_ufw.stdout:
            ufw_needs_fix = False
            ufw_comment = "ufw enabled."
            ufw_active_state = "Firewall active (running)"
        else:
            ufw_needs_fix = True
            ufw_comment = "ufw disabled."
            ufw_active_state = "Firewall inactive (dead)"

        ubuntu_results["firewall"] = {
            "needs_fix": ufw_needs_fix,
            "comment": ufw_comment,
            "state": ufw_active_state,
        }

    except FileNotFoundError as e:
        ubuntu_results["firewall"] = {
            "needs_fix": True,
            "comment": f"ufw not found {e}",
            "state": "Error",
        }

    # Checking restictiveness of file permissions for /etc/shadow
    try:
        ubuntu_shadow = Path("/etc/shadow")
        ubuntu_perm = os.stat(ubuntu_shadow)
        ubuntu_restrict = oct(ubuntu_perm.st_mode)[-3:]
        print("Permissions:", ubuntu_restrict, file=sys.stderr)
        if "600" in ubuntu_restrict:
            perm_needs_fix = False
            perm_comment = "Restrictions correct"
            perm_state = "No further action required."
        else:
            perm_needs_fix = True
            perm_comment = "Restrictions incorrect, please review it and adjust them as per documentation."
            perm_state = "Further action required."

        ubuntu_results["restrict"] = {
            "needs_fix": perm_needs_fix,
            "comment": perm_comment,
            "state": perm_state,
        }
    except PermissionError as e:
        ubuntu_results["restrict"] = {
            "needs_fix": True,
            "comment": f"Cannot acces /etc/shadow {e}",
            "state": "Error",
        }

    # Checking fail2ban service operational state
    try:
        ubuntu_fail2ban = subprocess.run(
            ["systemctl", "status", "fail2ban"], capture_output=True, text=True
        )
        print("File2ban status:", ubuntu_fail2ban.stdout, file=sys.stderr)
        ubuntu_split = ubuntu_fail2ban.stdout.splitlines()

        if "could not be found" in ubuntu_fail2ban.stderr:
            fail2ban_needs_fix = True
            fail2ban_comment = "Unit fail2ban.service could not be found."
            fail2ban_active_state = "not installed"
        else:
            print("Fail2ban installed.", file=sys.stderr)
            fail2ban_needs_fix = True
            fail2ban_comment = (
                "Could not determine fail2ban status from systemctl output."
            )
            fail2ban_active_state = "Unknown"

            for line in ubuntu_split:
                if "active" in line.lower():
                    if "active (running)" in line.lower():
                        fail2ban_needs_fix = False
                        fail2ban_comment = "Unit fail2ban.service installed."
                        fail2ban_active_state = "Fail2ban active"
                    else:
                        fail2ban_needs_fix = True
                        fail2ban_comment = (
                            "Unit fail2ban.service installed but inactive."
                        )
                        fail2ban_active_state = "Fail2ban inactive (dead)."
                    break

        ubuntu_results["fail2ban"] = {
            "needs_fix": fail2ban_needs_fix,
            "comment": fail2ban_comment,
            "state": fail2ban_active_state,
        }
    except FileNotFoundError as e:
        ubuntu_results["fail2ban"] = {
            "needs_fix": True,
            "comment": f"fail2ban not found {e}",
            "state": "Error",
        }

    # Checking system update availability
    ubuntu_update = subprocess.run(
        ["apt", "list", "--upgradable"], capture_output=True, text=True
    )
    if ubuntu_update.stdout == "":
        update_needs_fix = False
        update_comment = "OS updated"
        update_status = "No further action required."
    else:
        update_needs_fix = True
        update_comment = "There are updates available."
        update_list = ubuntu_update.stdout.splitlines()
        update_status = len(update_list)

    ubuntu_results["update"] = {
        "needs_fix": update_needs_fix,
        "comment": update_comment,
        "state": update_status,
    }

    # Checking if the 'consultant' account has an expiration date set
    ubuntu_accexpiry = subprocess.run(
        ["chage", "-l", "consultant"], capture_output=True, text=True
    )
    consultant_needs_fix = True
    consultant_comment = "Could not determin expiration status."
    consultant_status = "Action required, please check if account exists."

    ubuntu_accsplit = ubuntu_accexpiry.stdout.splitlines()
    ubuntu_now = datetime.datetime.now()
    for line in ubuntu_accsplit:
        if "account expires" in line.lower():
            if "never" in line.lower():
                consultant_needs_fix = True
                consultant_comment = "Fail. Account never expires."
                consultant_status = "Please set an expiration date."
            else:
                ubuntu_colon = line.split(":")
                ubuntu_index = ubuntu_colon[1]
                ubuntu_split = ubuntu_index.strip()
                ubuntu_consultant = datetime.datetime.strptime(
                    ubuntu_split, "%b %d, %Y"
                )
                if ubuntu_consultant >= ubuntu_now:
                    consultant_needs_fix = False
                    consultant_comment = "Pass. Account has expiration date set."
                    consultant_status = f"Account expiration date:{ubuntu_consultant}"
                else:
                    consultant_needs_fix = False
                    consultant_comment = "Please check the account and if has expired, please remove it from our system."
                    consultant_status = f"Account expired:{ubuntu_consultant}"
    ubuntu_results["consultant"] = {
        "needs_fix": consultant_needs_fix,
        "comment": consultant_comment,
        "state": consultant_status,
    }

    return ubuntu_results


def centos_checklist():
    """Execute the full security compliance audit checklist tailored for CentOS systems."""

    centos_results = {}

    # Checking access and permissions for SSH and OS configuration
    try:
        centos_sshd = file_verify(SSHD_FILEPATH, "PermitRootLogin", "no")
        if centos_sshd == "Pass":
            sshd_needs_fix = False
            sshd_comment = "PermitRootLogin turned off."
            sshd_state = "No further action required."

        else:
            sshd_needs_fix = True
            sshd_comment = "PermitRootLogin turned on."
            sshd_state = "Action required."

        centos_results["sshd"] = {
            "needs_fix": sshd_needs_fix,
            "comment": sshd_comment,
            "state": sshd_state,
        }
    except FileNotFoundError as e:
        centos_results["sshd"] = {
            "needs_fix": True,
            "comment": "PermitRootLogin not found.",
            "state": f"Action required, {e}",
        }

    try:
        centos = file_verify("/etc/os-release", "NAME", "CentOS")
        centos_results["os"] = centos
    except FileNotFoundError:
        centos_results["os"] = MISSING_FILE

    try:
        centos_pass = file_verify(SSHD_FILEPATH, "PasswordAuthentication", "no")
        if centos_pass == "Pass":
            pass_needs_fix = False
            pass_comment = "PasswordAuthentication turned off."
            pass_state = "No further action required."
        else:
            pass_needs_fix = True
            pass_comment = "PasswordAuthentication turned on."
            pass_state = "Action required."

        centos_results["password"] = {
            "needs_fix": pass_needs_fix,
            "comment": pass_comment,
            "state": pass_state,
        }
    except FileNotFoundError as e:
        centos_results["password"] = {
            "needs_fix": True,
            "comment": "PasswordAuthentication not found.",
            "state": f"Action required, {e}",
        }

    # Verifying Firewall status via firewalld
    try:
        centos_firewalld = subprocess.run(
            ["systemctl", "status", "firewalld"], capture_output=True, text=True
        )
        print("Firewall status:", centos_firewalld.stdout, file=sys.stderr)

        if "active (running)" in centos_firewalld.stdout:
            firewalld_needs_fix = False
            firewalld_comment = "firewalld enabled."
            firewalld_active_state = "Firewall active (running)"
        else:
            firewalld_needs_fix = True
            firewalld_comment = "firewalld disabled."
            firewalld_active_state = "Firewall inactive (dead)"

        centos_results["firewall"] = {
            "needs_fix": firewalld_needs_fix,
            "comment": firewalld_comment,
            "state": firewalld_active_state,
        }

    except FileNotFoundError as e:
        centos_results["firewall"] = {
            "needs_fix": True,
            "comment": f"firewalld not found {e}",
            "state": "Error",
        }

    # Checking restictiveness of file permissions for /etc/shadow
    try:
        centos_shadow = Path("/etc/shadow")
        centos_perm = os.stat(centos_shadow)
        centos_restrict = oct(centos_perm.st_mode)[-3:]
        if "600" in centos_restrict:
            perm_needs_fix = False
            perm_comment = "Restrictions correct"
            perm_state = "No further action required."
        else:
            perm_needs_fix = True
            perm_comment = "Restrictions incorrect, please review it and adjust them as per documentation."
            perm_state = "Further action required."

        centos_results["restrict"] = {
            "needs_fix": perm_needs_fix,
            "comment": perm_comment,
            "state": perm_state,
        }

    except PermissionError as e:
        centos_results["restrict"] = {
            "needs_fix": True,
            "comment": f"Cannot acces /etc/shadow {e}",
            "state": "Error",
        }

    # Checking fail2ban service operational state
    try:
        centos_fail2ban = subprocess.run(
            ["systemctl", "status", "fail2ban"], capture_output=True, text=True
        )
        print("File2ban status:", centos_fail2ban.stdout, file=sys.stderr)
        centos_split = centos_fail2ban.stdout.splitlines()
        if "could not be found" in centos_fail2ban.stderr:
            fail2ban_needs_fix = True
            fail2ban_comment = "Unit fail2ban.service could not be found."
            fail2ban_active_state = "not installed"
        else:
            print("Fail2ban installed.", file=sys.stderr)
            fail2ban_needs_fix = True
            fail2ban_comment = (
                "Could not determine fail2ban status from systemctl output."
            )
            fail2ban_active_state = "Unknown"

            for line in centos_split:
                if "active" in line.lower():
                    if "active (running)" in line.lower():
                        fail2ban_needs_fix = False
                        fail2ban_comment = "Unit fail2ban.service installed."
                        fail2ban_active_state = "Fail2ban active"
                    else:
                        fail2ban_needs_fix = True
                        fail2ban_comment = (
                            "Unit fail2ban.service installed but inactive."
                        )
                        fail2ban_active_state = "Fail2ban inactive (dead)."
                    break
        centos_results["fail2ban"] = {
            "needs_fix": fail2ban_needs_fix,
            "comment": fail2ban_comment,
            "state": fail2ban_active_state,
        }
    except FileNotFoundError as e:
        centos_results["fail2ban"] = {
            "needs_fix": True,
            "comment": f"fail2ban not found {e}",
            "state": "Error",
        }

    # Checking system update availability via security channel
    centos_update = subprocess.run(
        ["dnf", "check-update", "--security"], capture_output=True, text=True
    )
    print("Update status:", centos_update.stdout, file=sys.stderr)

    if centos_update.returncode == 0:
        update_needs_fix = False
        update_comment = "OS updated"
        update_status = "No further action required."
    elif centos_update.returncode == 1:
        update_needs_fix = False
        update_comment = "Failed during checking process."
        update_status = "Please check your operating system."
    else:
        update_needs_fix = True
        update_comment = "There are updates available."
        update_list = centos_update.stdout.splitlines()
        update_status = len(update_list)

    centos_results["update"] = {
        "needs_fix": update_needs_fix,
        "comment": update_comment,
        "state": update_status,
    }

    # Checking if the 'consultant' account has an expiration date set
    centos_accexpiry = subprocess.run(
        ["chage", "-l", "consultant"], capture_output=True, text=True
    )
    consultant_needs_fix = True
    consultant_comment = "Could not determin expiration status."
    consultant_status = "Action required, please check if account exists."
    centos_accsplit = centos_accexpiry.stdout.splitlines()
    centos_now = datetime.datetime.now()
    for line in centos_accsplit:
        if "account expires" in line.lower():
            if "never" in line.lower():
                consultant_needs_fix = True
                consultant_comment = "Fail. Account never expires."
                consultant_status = "Please set an expiration date."
            else:
                centos_colon = line.split(":")
                centos_index = centos_colon[1]
                centos_split = centos_index.strip()
                centos_consultant = datetime.datetime.strptime(
                    centos_split, "%b %d, %Y"
                )
                if centos_consultant >= centos_now:
                    consultant_needs_fix = False
                    consultant_comment = "Pass. Account has expiration date set."
                    consultant_status = f"Account expiration date:{centos_consultant}"
                else:
                    consultant_needs_fix = False
                    consultant_comment = "Please check the account and if has expired, please remove it from our system."
                    consultant_status = f"Account expired:{centos_consultant}"

    centos_results["consultant"] = {
        "needs_fix": consultant_needs_fix,
        "comment": consultant_comment,
        "state": consultant_status,
    }

    return centos_results


if __name__ == "__main__":
    ubuntu_checklist()
    centos_checklist()
