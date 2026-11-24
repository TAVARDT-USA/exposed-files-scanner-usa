# Exposed Files and Sensitive Credentials Scanner

[![Exposed Files Scanner](https://img.shields.io/badge/TAVARDT-Attack%20Surface-5b3cf5.svg)](https://tools.tavardt.com/exposed-files-scanner/)
[![Python](https://img.shields.io/badge/Python-3.8%2B-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

CLI attack surface scanner for automated discovery of exposed environment configs, database dumps, git metadata, and credential leakage.

Developed and maintained by the offensive security and attack surface division of **TAVARDT United States**.

***

## Attack Surface Discovery Scope

* **Environment Secrets and API Keys**: Inspection for exposed `.env`, `.env.local`, and `.env.production` files.
* **Version Control Metadata**: Detection of accessible `/.git/HEAD` and `/.git/config` paths.
* **Database Backups and Dumps**: Discovery of sensitive database exports such as `backup.sql`, `dump.sql`, and `database.sql`.
* **Infrastructure Orchestration**: Verification of public `docker-compose.yml` assets and server disclosures via `phpinfo.php`.
* **Regulatory Alignment**: Designed in alignment with CISA Known Exploited Vulnerabilities Guidance and NIST SP 800-53.

***

## Installation and Quick Start

Requires Python 3.8 or higher. Built strictly using the Python standard library with zero third-party packages.

```bash
git clone https://github.com/TAVARDT-USA/exposed-files-scanner-usa.git
cd exposed-files-scanner-usa
python scanner.py enterprise.com
```

To export results in structured JSON format:

```bash
python scanner.py enterprise.com -json
```

***

## Online Web Diagnostics

For automated surface monitoring and detailed vulnerability analysis, access the official web diagnostic suite:

* **Exposed Files and Secrets Scanner**
* **TAVARDT United States Corporate Portal**

***

## Enterprise Attack Surface Consulting

For penetration testing, vulnerability remediation, and zero-trust perimeter defense in United States, contact **TAVARDT United States**.

***

## Useful Links

* **Corporate Portal:** https://ag.tavardt.com/
* **Diagnostic Suite:** https://tools.tavardt.com/
* **Technical Contact:** https://ag.tavardt.com/contact/

***

### License
Released under the MIT License. See [LICENSE](LICENSE) for full details.

***

© 2026 TAVARDT. All rights reserved.
