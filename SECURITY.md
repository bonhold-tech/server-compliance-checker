# Security Policy

## Supported Versions

This project is developed as a portfolio/educational tool. Support applies
only to the latest version on the `main` branch.

| Version | Supported          |
| ------- | ------------------ |
| main    | :white_check_mark: |
| < 1.0   | :x:                 |

## Reporting a Vulnerability

If you find a security vulnerability in this project, please report it
**privately** instead of opening a public issue - this gives time to fix
the problem before the information becomes publicly available.

**How to report:**
- Email: bonhold0@gmail.com
- Alternatively: GitHub Security Advisories (repo "Security" tab → "Report a vulnerability")

**What to expect:**
- Acknowledgement of your report within 5 business days
- An assessment and follow-up within 14 days
- Credit in the release notes after the fix (if you'd like)

## Known Limitations / Disclaimer

This project is an educational/portfolio tool built while learning Linux
system administration and automation in Python. It is not intended for use
in production environments without additional security review.

The `--fix` mode modifies system configuration files - it always creates a
backup (`.bak`) before making changes, but testing on a non-production
environment (like the Vagrant/VM setup used in this project) is strongly
recommended before applying it to a real server.
