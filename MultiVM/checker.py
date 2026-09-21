__version__ = "0.2.4"
import subprocess
import sys
import json
import datetime
import os
import smtplib
from pathlib import Path
from audit import ubuntu_checklist
from audit import centos_checklist
from dotenv import load_dotenv
from email.mime.text import MIMEText


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
            "sudo python3 /vagrant/checker.py --inside-vm 2>/dev/null",
        ],
        capture_output=True,
        text=True,
    )
    print(
        "STDOUT:",
        web01_json.stdout,
        "STDERR:",
        web01_json.stderr,
        "RETURNCODE:",
        web01_json.returncode,
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
            "sudo python3 /vagrant/checker.py --inside-vm 2>/dev/null",
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

    if "--notify" in sys.argv:
        dotenv_file = Path(__file__)
        vm_file = dotenv_file.parent
        env_file = vm_file.parent / ".env"
        load_dotenv(env_file)
        json_report = json.dumps(vm_output, indent=2)

        subject = "Audit report"
        body = json_report
        sender = os.environ["EMAIL_FROM"]
        recipients = os.environ["EMAIL_TO"]
        password = os.environ["SMTP_PASSWORD"]

        def send_email(subject, body, sender, recipients, password):
            msg = MIMEText(body)
            msg["Subject"] = subject
            msg["From"] = sender
            msg["To"] = recipients
            with smtplib.SMTP_SSL(
                os.environ["SMTP_SERVER"], os.environ["SMTP_PORT"]
            ) as smtp_server:
                smtp_server.login(sender, password)
                smtp_server.sendmail(sender, recipients, msg.as_string())
            print("Message sent!")

        send_email(subject, body, sender, recipients, password)
