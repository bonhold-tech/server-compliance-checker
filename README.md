# Server Compliance Checker

⚠️ Educational / portfolio project - built while learning Linux system administration and automation in Python.
It has not been tested in production environments. Before running it on a real server,
review the code carefully, especially the `--fix` mode, which modifies system configuration files directly.
See [Known issues](#known-issues) for the current list of open problems.

A cross-platform security audit tool for Linux servers. It automatically detects
the operating system (Ubuntu/Debian or CentOS/RHEL) and runs a compliance check
adapted to that distribution's specific tooling and package management.

## Why this project?

Organizations often run mixed Linux infrastructure (Debian-based and RHEL-based
systems side by side). Manually auditing each server for basic security baselines
is slow and inconsistent between distributions. This tool standardizes that check
into a single, repeatable script that adapts itself to whichever OS it's running on.

## What it checks

1. **Firewall status** - `ufw` (Ubuntu) / `firewalld` (CentOS)
2. **SSH root login disabled** - `PermitRootLogin no` in the effective sshd
   configuration (`sshd -T` on Ubuntu; CentOS still reads `/etc/ssh/sshd_config`,
   see [Known issues](#known-issues))
3. **SSH password authentication disabled** - `PasswordAuthentication no`, read the
   same way as above
4. **Permissions on sensitive files** - `/etc/shadow` (currently expects exactly `0600`)
5. **Brute-force protection** - `fail2ban` installed and running (on CentOS, requires
   the EPEL repository - the check accounts for this)
6. **Pending security updates** - `apt list --upgradable` (Ubuntu) / `dnf check-update
   --security` (CentOS)
7. **Temporary account expiry** - checks that the `consultant` account has an
   expiration date set (`chage`) and flags it if it has already expired

Each check returns `needs_fix`:

- `false` - the check passed
- `true` - the configuration needs attention
- `null` - the state could not be determined (for example, the audit ran without
  root or a command failed); the reason is in `comment`

## How it works

`checker.py` runs on the host. It starts each VM with Vagrant, then runs itself
inside the VM (`vagrant ssh <vm> -c "sudo python3 /vagrant/checker.py --inside-vm"`).
Inside the VM, the script detects the operating system by parsing `/etc/os-release`,
runs the matching checklist from `audit.py` and prints the result as JSON. The host
collects the JSON from both VMs and handles the optional flags.

## Usage

Run from the `MultiVM/` directory on the host:

```bash
python3 checker.py --json            # audit both VMs and save the report to audit_reports/
python3 checker.py --json --notify   # also email the report (requires .env configuration)
python3 checker.py --json --fix      # also attempt automatic remediation based on the report
```

- The report is saved as `audit_reports/<Mon-DD-YYYY> audit_report.json`.
- `--fix` reads the report with today's date, so run it together with `--json`.
- Without `--json`, the results are only printed to the screen.

## Environment

Tested on a multi-VM setup (Vagrant + libvirt): Ubuntu Server 20.04 (`generic/ubuntu2004`)
and CentOS Stream 9 (`generic/centos9s`). The `Vagrantfile` in this repo can be used
to reproduce the test environment.

## Server user layout

| User | Role | Privileges | SSH | Notes |
|---|---|---|---|---|
| `root` | Built-in system account | Full | Disabled (`PermitRootLogin no`) | Never logged into directly |
| `vagrant` | Administrator | Full `sudo` | Key-only | Primary account for server management |
| `deploy` | Service account | Restricted `sudo` - can only restart/check status of nginx/httpd | Key-only | Simulates a CI/CD deployment account |
| `consultant` | External consultant (temporary) | Minimal/no `sudo`, read-only access to `/var/log/<app>/` | Key-only | Account has an automatic expiration date (`chage`) |

## Tech stack

Python 3.x - standard library only (`os`, `subprocess`, `pathlib`, `json`, `datetime`,
`smtplib`), plus `python-dotenv` for the optional email notification feature.

## Project structure

```
server-compliance-checker/
├── .env
├── .env.example
├── .gitignore
├── LICENSE
├── README.md
└── MultiVM/
    ├── checker.py          # entry point - CLI args, orchestration + OS detection
    ├── audit.py            # shared audit logic and commands for Ubuntu and CentOS
    └── Vagrantfile         # multi-VM setup (Ubuntu + CentOS) to reproduce the test environment
```

## Security notes

- Credentials (SMTP login for `--notify`) live exclusively in `.env`, which is
  git-ignored. `.env.example` documents the required variables without real values.
- `--fix` creates a `.bak` copy of `sshd_config` before editing it (see
  [Known issues](#known-issues) - the backup can be overwritten).
- Follows the principle of least privilege: the `deploy` and `consultant` accounts
  above are scoped to the minimum access needed for their role.

## Known issues

An external review (Docker lab on Ubuntu 20.04, Ubuntu 24.04 and CentOS Stream 9,
October 2026) found several false results and unsafe behaviours in v0.2.6.
Fixes are in progress. Current status:

### Fixed (Ubuntu)

- Disabled UFW was reported as active (`"active"` matched inside `"inactive"`).
- SSH checks read only `/etc/ssh/sshd_config`, so inline comments, `Include`
  files and the first-value-wins rule could produce a false pass. Ubuntu now
  uses the effective configuration from `sshd -T`.
- The account expiry check crashed the whole audit under a non-English locale.
  `chage` now runs with `LC_ALL=C`, and an unknown date format only affects
  this check. An expired account is now reported as `needs_fix: true`.
- When a check cannot determine the state (for example, the audit runs
  without root), it now reports `needs_fix: null` with the reason, instead of
  a pass or a fail.

### Not fixed yet

- **CentOS (db01):** the SSH, locale and "unknown state" fixes above are not
  ported yet. The old checks are still in place.
- **Updates:** on Ubuntu, `apt list --upgradable` always prints a header line
  (`Listing... Done`), which is counted as an update, so a fully updated system
  reports `needs_fix: true` with a count of 1. `apt` errors with empty output are
  reported as "OS updated". On CentOS, a failed `dnf check-update` gives
  `needs_fix: false`.
- **/etc/shadow:** only the exact mode `600` passes (stricter `400` fails), and
  the file owner is not checked.
- **`--fix`:**
  - sshd is not reloaded after changing `sshd_config`, so password login
    keeps working until the next restart;
  - the second `sed -i.bak` overwrites the first backup;
  - exit codes of remediation commands are not checked;
  - it reads the report file named with today's date (missing file → crash,
    old report → unnecessary changes);
  - the report path is hard-coded to the author's home directory;
  - it edits only the main `sshd_config`, so an override in
    `/etc/ssh/sshd_config.d/` is not fixed.
- **`--notify`:** the SMTP connection does not verify the server certificate.

### Known limitations (by design, for now)

- **Firewall:** only checks whether UFW/firewalld is running, not its rules.
  A firewall that allows all incoming traffic passes.
- **fail2ban:** only checks whether the service is running, not whether any
  jail is active.
- **SSH `Match` blocks:** `sshd -T` shows global settings. Options set only
  inside a `Match` block are not evaluated.

Do not use this tool as the only source of truth for production audits yet.

## Planned enhancements (not implemented yet)

- Automatic publishing of audit reports to a WordPress instance via the REST API
  (Application Passwords), enabling centralized report storage across environments
- A lightweight status page (hosted separately) that surfaces links to the latest
  reports, pulled automatically after each audit run via SSH/SFTP
- This would extend the tool from a local compliance checker into a small
  distributed reporting pipeline across multiple servers

## License
MIT