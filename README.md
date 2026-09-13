# Server Compliance Checker

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
2. **SSH root login disabled** - `PermitRootLogin no` in `/etc/ssh/sshd_config`
3. **SSH password authentication disabled** - `PasswordAuthentication no`
4. **Permissions on sensitive files** - `/etc/shadow` (expects `0600` or stricter)
5. **Brute-force protection** - `fail2ban` installed and running (on CentOS, requires
   the EPEL repository - the check accounts for this)
6. **Pending security updates** - `apt list --upgradable` (Ubuntu) / `dnf check-update
   --security` (CentOS)
7. **Expired temporary accounts** - flags any account past its expiration date
   (`chage`) that should have already been locked out

## How it works

The script first detects the operating system by parsing `/etc/os-release`, then
loads the matching command set for that distribution and runs the same seven
checks with distribution-specific logic underneath.

## Usage

```bash
sudo python3 checker.py              # report mode (prints to screen)
sudo python3 checker.py --fix        # attempts safe automatic remediation
sudo python3 checker.py --json       # exports the report to report-<timestamp>.json
sudo python3 checker.py --notify     # emails the report (requires .env configuration)
```

## Example output

```
[OS Detected: Ubuntu]
====================================
 SERVER COMPLIANCE AUDIT
====================================
[✓] Firewall (ufw): active
[✗] SSH root login: permitted (should be disabled)
[✓] SSH password authentication: disabled
[✓] /etc/shadow permissions: 0600
[✗] fail2ban: not installed
[✓] Security updates: up to date
[✓] Temporary accounts: none expired
====================================
5 passed / 2 failed
```

```
[OS Detected: CentOS]
====================================
 SERVER COMPLIANCE AUDIT
====================================
[✓] Firewall (firewalld): active
[✓] SSH root login: disabled
[✓] SSH password authentication: disabled
[✓] /etc/shadow permissions: 0600
[✗] fail2ban: EPEL repo not enabled, service not found
[✓] Security updates: up to date
[✓] Temporary accounts: none expired
====================================
6 passed / 1 failed
```

## Environment

Tested on a multi-VM setup (Vagrant + libvirt): Ubuntu Server and CentOS Stream.
The `Vagrantfile` in this repo can be used to reproduce the test environment.

## Server user layout

| User | Role | Privileges | SSH | Notes |
|---|---|---|---|---|
| `root` | Built-in system account | Full | Disabled (`PermitRootLogin no`) | Never logged into directly |
| `vagrant` | Administrator | Full `sudo` | Key-only | Primary account for server management |
| `deploy` | Service account | Restricted `sudo` - can only restart/check status of nginx/httpd | Key-only | Simulates a CI/CD deployment account |
| `consultant` | External consultant (temporary) | Minimal/no `sudo`, read-only access to `/var/log/<app>/` | Key-only | Account has an automatic expiration date (`chage`) |

## Tech stack

Python 3.x - standard library only (`os`, `subprocess`, `pathlib`), plus
`python-dotenv` for the optional email notification feature.

## Project structure

```
server-compliance-checker/
├── .env
├── .env.example
├── .gitignore
├── LICENSE
├── README.md
├── checker.py          # entry point - CLI args, orchestration + OS detection
├── audit.py             # shared audit logic and commands for Ubuntu and CentOS
└── Vagrantfile             # multi-VM setup (Ubuntu + CentOS) to reproduce the test environment
```

## Security notes

- Credentials (SMTP login for `--notify`) live exclusively in `.env`, which is
  git-ignored. `.env.example` documents the required variables without real values.
- `--fix` creates a `.bak` copy of any configuration file before modifying it.
- Follows the principle of least privilege: the `deploy` and `consultant` accounts
  above are scoped to the minimum access needed for their role.

## Planned enhancements (not implemented yet)

- Automatic publishing of audit reports to a WordPress instance via the REST API
  (Application Passwords), enabling centralized report storage across environments
- A lightweight status page (hosted separately) that surfaces links to the latest
  reports, pulled automatically after each audit run via SSH/SFTP
- This would extend the tool from a local compliance checker into a small
  distributed reporting pipeline across multiple servers

## License
MIT