<p align="center">
  <a href="https://ag.tavardt.com/">
    <img src="https://ag.tavardt.com/img/tavardt-banner.png" alt="TAVARDT" width="1024" />
  </a>
</p>

# Exposed Files and Sensitive Credentials Scanner

[![Exposed Files Scanner](https://img.shields.io/badge/TAVARDT-Attack%20Surface-5b3cf5.svg)](https://tools.tavardt.com/exposed-files-scanner/)
[![Python](https://img.shields.io/badge/Python-3.8%2B-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

Automated attack surface discovery utility for detecting publicly exposed environment secrets, database SQL backups, git repository metadata, container definitions, and cloud provider credentials.

The engine probes web perimeters to identify misconfigured web roots and unintentional file disclosures before malicious actors can exploit them. Designed with zero third-party dependencies, the scanner executes natively in Python CLI environments and automated security pipelines.

***

## Attack Surface Discovery Scope and Threat Architecture

Inadvertent exposure of sensitive assets on public web servers represents one of the most critical Initial Access vectors across modern web infrastructure. Misconfigured Nginx, Apache, Caddy, or S3-backed deployments frequently serve sensitive dotfiles and SQL dumps directly to unauthenticated web clients.

* **Environment Secrets and API Keys**: Active inspection of `/.env`, `/.env.local`, and `/.env.production` files containing live database credentials, encryption salts, and third-party API tokens.
* **Version Control Metadata**: Probing for accessible `/.git/HEAD` and `/.git/config` paths, preventing adversaries from cloning entire proprietary codebases from public web roots.
* **Database Backups and Dumps**: Discovery of exposed SQL dumps including `backup.sql`, `dump.sql`, and `database.sql`, which disclose full relational database contents.
* **Infrastructure Orchestration**: Detection of container definitions in `docker-compose.yml` and diagnostic disclosures via `phpinfo.php` and `config.json`.
* **Cloud Provider Access Keys**: Verification of exposed `/.aws/credentials`, mitigating catastrophic administrative takeovers across cloud estates.
* **Regulatory Alignment**: Engineered in strict alignment with CISA Known Exploited Vulnerabilities Guidance and NIST SP 800-53.

***

## Attack Surface Inspection Matrix

<table>
  <thead>
    <tr>
      <th align="left">Monitored Route</th>
      <th align="left">Severity</th>
      <th align="left">Threat Vector and Asset Type</th>
      <th align="left">Defensive Hardening Control</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><code>/.env</code></td>
      <td>CRITICAL</td>
      <td>Environment variables, database passwords, and private API keys.</td>
      <td>Deny web server location block for dotfiles or move outside document root.</td>
    </tr>
    <tr>
      <td><code>/.env.local</code></td>
      <td>CRITICAL</td>
      <td>Local developer overrides and staging secrets committed into production.</td>
      <td>Enforce strict .gitignore rules and reject dotfile requests at edge reverse proxy.</td>
    </tr>
    <tr>
      <td><code>/.env.production</code></td>
      <td>CRITICAL</td>
      <td>Production system credentials and live third-party service tokens.</td>
      <td>Utilize vault-based secret managers instead of static filesystem environment files.</td>
    </tr>
    <tr>
      <td><code>/.git/HEAD</code></td>
      <td>CRITICAL</td>
      <td>Git repository pointer disclosing active branch and repository structure.</td>
      <td>Block access to all /.git paths via web server rules and purge git folders from deploy images.</td>
    </tr>
    <tr>
      <td><code>/.git/config</code></td>
      <td>CRITICAL</td>
      <td>Remote git repository URLs, internal domain paths, and potential embedded tokens.</td>
      <td>Restrict web access to hidden version control metadata across all virtual hosts.</td>
    </tr>
    <tr>
      <td><code>/backup.sql</code></td>
      <td>CRITICAL</td>
      <td>Complete database dump containing user tables, password hashes, and business data.</td>
      <td>Store database backups in encrypted, private cloud object storage with zero public egress.</td>
    </tr>
    <tr>
      <td><code>/dump.sql</code></td>
      <td>CRITICAL</td>
      <td>Raw database export left behind by manual migration or staging scripts.</td>
      <td>Enforce automated post-deployment cleanup scripts to remove ephemeral database dumps.</td>
    </tr>
    <tr>
      <td><code>/database.sql</code></td>
      <td>CRITICAL</td>
      <td>Application database schema and seed data containing sensitive structures.</td>
      <td>Prohibit database creation scripts within public HTML document directories.</td>
    </tr>
    <tr>
      <td><code>/docker-compose.yml</code></td>
      <td>HIGH</td>
      <td>Container topology, internal network aliases, and environment variables.</td>
      <td>Exclude container manifests from web publication artifacts during CI/CD builds.</td>
    </tr>
    <tr>
      <td><code>/phpinfo.php</code></td>
      <td>MEDIUM</td>
      <td>PHP runtime environment, installed extensions, server paths, and loaded modules.</td>
      <td>Disable phpinfo() calls in production php.ini and delete ad-hoc diagnostic files.</td>
    </tr>
    <tr>
      <td><code>/config.json</code></td>
      <td>HIGH</td>
      <td>Internal application configuration, database endpoints, and feature flags.</td>
      <td>Restrict web access to json configuration files or compile configs into application binaries.</td>
    </tr>
    <tr>
      <td><code>/.aws/credentials</code></td>
      <td>CRITICAL</td>
      <td>AWS access key IDs and secret access keys granting cloud infrastructure access.</td>
      <td>Use IAM roles and instance profiles rather than persisting static cloud credentials on disk.</td>
    </tr>
  </tbody>
</table>

***

## Installation and Quick Start

The utility requires Python 3.8 or higher using strictly standard library modules (`sys`, `json`, `ssl`, `argparse`, `urllib.request`). Zero external packages or third-party dependencies are required.

Clone the repository and inspect a target web domain:

```bash
git clone https://github.com/TAVARDT-USA/exposed-files-scanner-usa.git
cd exposed-files-scanner-usa
python scanner.py example.com
```

To export results in clean JSON format for automated pipelines:

```bash
python scanner.py example.com -j
```

Inspect target domains utilizing specific protocols:

```bash
python scanner.py https://example.com -j
```

Sample JSON response payload:

```json
{
  "target": "https://example.com",
  "status": "Critical (Severe secret or data exposure detected)",
  "inspected_routes": 12,
  "exposed_count": 1,
  "exposed_files": [
    {
      "path": "/.env",
      "url": "https://example.com/.env",
      "status_code": 200,
      "severity": "CRITICAL",
      "description": "Environment variables and API secrets"
    }
  ],
  "recommendation": "Immediately decommission exposed files and enforce web server hardening controls."
}
```

***

## Frequently Asked Questions

### How does the scanner differentiate between genuine file exposure and custom 404 error handlers?
The engine checks for an HTTP 200 OK status code when requesting targeted asset paths. If a web server returns HTTP 200 for missing pages instead of HTTP 404 or HTTP 403, security teams should inspect the response body length or configure deterministic status codes on their web server to prevent false positive detections.

### What specific risks arise from public exposure of the `/.git/` directory?
Public access to `/.git/HEAD` and `/.git/config` allows adversaries to download git object files using tools like GitTools or rip-git. Attackers can reconstruct the complete source code repository, review historic commit messages, extract hardcoded secrets, and discover zero-day application flaws.

### Why does the audit engine use unverified SSL contexts during initial discovery?
The scanner configures an unverified SSL context (`ssl.CERT_NONE`) with hostname verification disabled to ensure security teams can audit staging domains, internal development hosts, and systems undergoing SSL certificate rotation without throwing fatal connection errors.

### How can the JSON output payload be integrated into automated DevSecOps pipelines?
By passing the `-j` flag, `scanner.py` streams clean JSON directly to standard output. CI/CD pipelines can evaluate the `exposed_count` field using tools like jq, triggering automated build failures or alerting web administrators if any sensitive asset returns an HTTP 200 status code.

### What immediate server hardening actions mitigate exposed file vulnerabilities?
Engineers should immediately remove sensitive files from public document roots and implement global server block rules in Nginx (`location ~ /\.(?!well-known).* { deny all; }`) or Apache (`RedirectMatch 404 /\.(git|env)`). Additionally, static database dumps and container definitions must never be placed inside the web root.

***

## Attack Surface Security Consulting

For penetration testing, vulnerability remediation, and zero-trust perimeter defense in United States, contact **TAVARDT United States**.

***

## Useful Links

* **Corporate Portal:** https://ag.tavardt.com/
* **Diagnostic Suite:** https://tools.tavardt.com/
* **Technical Contact:** https://ag.tavardt.com/contact/

***

### License
Released under the MIT License.

***

© 2026 TAVARDT. All rights reserved.
