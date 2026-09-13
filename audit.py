import os
import subprocess
from pathlib import Path
import datetime


def file_verify(filepath, expected_line, expected_value):
    """Open a file and check if a specific key line matches the expected value.

    Skips commented lines starting with '#'. Returns 'Pass' or 'Fail'.
    """
    with open(filepath, "r", encoding="utf-8") as permission:
        for line in permission:
            if expected_line.lower() in line.lower():
                if line.lower().startswith("#"):
                    continue
                if expected_value.lower() in line.lower():
                    return "Pass"
                else:
                    return "Fail"


def ubuntu_checklist():
    """Execute the full security compliance audit checklist tailored for Ubuntu systems."""
    # Checking access and permissions for SSH and OS configuration
    try:
        ubuntu_sshd = file_verify("/etc/ssh/sshd_config", "PermitRootLogin", "no")
        ubuntu_os = file_verify("/etc/os-release", "NAME", "Ubuntu")
        ubuntu_pass = file_verify(
            "/etc/ssh/sshd_config", "PasswordAuthentication", "no"
        )
    except FileNotFoundError:
        print("Error: File not found, please check file name")
        ubuntu_sshd = "Error"
        ubuntu_os = "Error"
        ubuntu_pass = "Error"

    print(ubuntu_sshd)
    print(ubuntu_os)
    print(ubuntu_pass)

    # Verifying Firewall status via UFW
    ubuntu_ufw = subprocess.run(["ufw", "status"], capture_output=True, text=True)
    print("Firewall status:", ubuntu_ufw.stdout)

    if "active" in ubuntu_ufw.stdout:
        firewall_status = "Pass"
    else:
        firewall_status = "Fail"

    print(firewall_status)

    # Checking restictiveness of file permissions for /etc/shadow
    try:
        ubuntu_shadow = Path("/etc/shadow")
        ubuntu_perm = os.stat(ubuntu_shadow)
        ubuntu_restrict = oct(ubuntu_perm.st_mode)[-3:]
        print("Permissions:", ubuntu_restrict)
        if "600" in ubuntu_restrict:
            print("Pass")
        else:
            print(
                "Fail, possible secuirty breach, due to file accessible for many groups/users."
            )
    except PermissionError:
        print("You don't have permission to open this file")
        ubuntu_shadow = "Error, access denied"
        ubuntu_perm = "Error, access denied"
        ubuntu_restrict = "Error, access denied."

    # Checking fail2ban service operational state
    try:
        ubuntu_fail2ban = subprocess.run(
            ["systemctl", "status", "fail2ban"], capture_output=True, text=True
        )
        print("File2ban status:", ubuntu_fail2ban.stdout)
        ubuntu_split = ubuntu_fail2ban.stdout.splitlines()
        if "could not be found" in ubuntu_fail2ban.stderr:
            print(
                "Unit fail2ban.service could not be found. Please install fail2ban service."
            )
        else:
            print("Fail2ban installed.")

            for line in ubuntu_split:
                if "active" in line.lower():
                    if "active (running)" in line.lower():
                        print("Fail2ban active")
                    else:
                        print(
                            "Fail2ban inactive (dead), possible security issue. Please enable service."
                        )
                    break
    except FileNotFoundError:
        ubuntu_fail2ban = (
            "Unit fail2ban.service could not be found. Please install fail2ban service."
        )

    # Checking system update availability
    ubuntu_update = subprocess.run(
        ["apt", "list", "--upgradable"], capture_output=True, text=True
    )
    print("Update status:", ubuntu_update.stdout)

    if ubuntu_update.stdout == "":
        print("OS updated")
    else:
        print("Available updates:", ubuntu_update.stdout)

    # Checking if the 'consultant' account has an expiration date set
    ubuntu_accexpiry = subprocess.run(
        ["chage", "-l", "consultant"], capture_output=True, text=True
    )
    print("Account status:", ubuntu_accexpiry.stdout)
    ubuntu_accsplit = ubuntu_accexpiry.stdout.splitlines()
    ubuntu_now = datetime.datetime.now()
    for line in ubuntu_accsplit:
        if "account expires" in line.lower():
            if "never" in line.lower():
                print("Pass. Account never expires.")
            else:
                ubuntu_colon = line.split(":")
                ubuntu_index = ubuntu_colon[1]
                ubuntu_split = ubuntu_index.strip()
                ubuntu_consultant = datetime.datetime.strptime(
                    ubuntu_split, "%b %d, %Y"
                )
                if ubuntu_consultant >= ubuntu_now:
                    print("Account expiration date:", ubuntu_consultant)
                else:
                    print("Account expired:", ubuntu_consultant)


def cent_checklist():
    """Execute the full security compliance audit checklist tailored for CentOS systems."""
    # Checking access and permissions for SSH and OS configuration
    try:
        centos_sshd = file_verify("/etc/ssh/sshd_config", "PermitRootLogin", "no")
        centos = file_verify("/etc/os-release", "NAME", "CentOS")
        centos_pass = file_verify(
            "/etc/ssh/sshd_config", "PasswordAuthentication", "no"
        )
    except FileNotFoundError:
        print("Error: File not found, please check file name")
        centos_sshd = "Error"
        centos = "Error"
        centos_pass = "Error"

    print(centos_sshd)
    print(centos)
    print(centos_pass)

    # Verifying Firewall status via firewalld
    centos_firewalld = subprocess.run(
        ["systemctl", "status", "firewalld"], capture_output=True, text=True
    )
    print("Firewall status:", centos_firewalld.stdout)

    if "active" in centos_firewalld.stdout:
        firewall_status = "Pass"
    else:
        firewall_status = "Fail"

    print(firewall_status)

    # Checking restictiveness of file permissions for /etc/shadow
    try:
        centos_shadow = Path("/etc/shadow")
        centos_perm = os.stat(centos_shadow)
        print("Permissions:", oct(centos_perm.st_mode)[2:][-4:])
    except PermissionError:
        print("You don't have permission to open this file")
        centos_shadow = "Error, access denied"
        centos_perm = "Error, access denied"

    # Checking fail2ban service operational state
    try:
        centos_fail2ban = subprocess.run(
            ["systemctl", "status", "fail2ban"], capture_output=True, text=True
        )
        print("File2ban status:", centos_fail2ban.stdout)
        centos_split = centos_fail2ban.stdout.splitlines()
        if "could not be found" in centos_fail2ban.stderr:
            print(
                "Unit fail2ban.service could not be found. Please install fail2ban service."
            )
        else:
            print("Fail2ban installed.")

            for line in centos_split:
                if "active" in line.lower():
                    if "active (running)" in line.lower():
                        print("Fail2ban active")
                    else:
                        print(
                            "Fail2ban inactive (dead), possible security issue. Please enable service."
                        )
                    break
    except FileNotFoundError:
        centos_fail2ban = (
            "Unit fail2ban.service could not be found. Please install fail2ban service."
        )

    # Checking system update availability via security channel
    centos_update = subprocess.run(
        ["dnf", "check-update", "--security"], capture_output=True, text=True
    )
    print("Update status:", centos_update.stdout)

    if centos_update.returncode == 0:
        print("OS updated")
    else:
        print("Available updates:", centos_update.stdout)

    # Checking if the 'consultant' account has an expiration date set
    centos_accexpiry = subprocess.run(
        ["chage", "-l", "consultant"], capture_output=True, text=True
    )
    print("Account status:", centos_accexpiry.stdout)
    centos_accsplit = centos_accexpiry.stdout.splitlines()
    centos_now = datetime.datetime.now()
    for line in centos_accsplit:
        if "account expires" in line.lower():
            if "never" in line.lower():
                print("Pass. Account never expires.")
            else:
                centos_colon = line.split(":")
                centos_index = centos_colon[1]
                centos_split = centos_index.strip()
                centos_consultant = datetime.datetime.strptime(
                    centos_split, "%b %d, %Y"
                )
                if centos_consultant >= centos_now:
                    print("Account expiration date:", centos_consultant)
                else:
                    print("Account expired:", centos_consultant)


if __name__ == "__main__":
    ubuntu_checklist()
    cent_checklist()
