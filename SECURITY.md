# Security policy

netSoldier watches a home network and can block devices on it, so a flaw in
it can hurt the people who run it. Thank you for taking the time to report
one privately.

## Reporting a vulnerability

Report it through GitHub's private vulnerability reporting:

1. Open the repository's **Security** tab and choose **Report a vulnerability**
   (the "Advisories" page, <https://github.com/migel9090/netSoldier/security/advisories/new>).
2. Describe the issue, the affected version or commit, and how to reproduce
   it. A proof of concept, the deployment profile (`lite` or `soc`) and the
   configuration involved help a lot.

The report is visible only to you and the maintainers. Please do **not** open
a public issue, pull request or discussion for a vulnerability, and do not
send reports by e-mail: the advisory keeps the report, the discussion and the
fix in one private place, and lets us credit you and request a CVE.

## What to expect

- An acknowledgement within 7 days.
- An assessment (accepted or not, and how severe) within 14 days.
- For an accepted report, a fix developed in a private fork of the advisory,
  released together with the published advisory. We aim to fix critical and
  high-severity issues within 30 days and will tell you if we need longer.
- Credit in the advisory, unless you prefer not to be named.

We ask you to give us that time before disclosing publicly, and to test only
against installations you own: never scan, spoof ARP or DHCP on, or replay
traffic into, a network you do not control.

## Scope

In scope: everything in this repository: the services under `apps/`, the
shared libraries, the deployment profiles under `deploy/` and the installer,
the infrastructure code, the CI workflows and the release artefacts they
produce (container images, signatures, SBOMs).

Especially interesting: bypassing the killswitch's safeguards (allowlist,
human approval, automatic revert), forging or replaying events between the
services, reaching the web UI or a service API without credentials,
privilege escalation out of a container, and anything that lets traffic on
the home network influence netSoldier beyond what it is meant to observe.

Out of scope: vulnerabilities in third-party components (AdGuard Home,
Suricata, Zeek, ClickHouse, Kubernetes, Podman, ...) that netSoldier does
not make worse — please report those upstream; findings that need an
attacker who already has root on the host; and denial of service by flooding
the LAN the host sits on.

## Supported versions

netSoldier has not reached 1.0. Until it does, only the latest release and
the `main` branch receive security fixes.
