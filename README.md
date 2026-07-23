# DNSearcher

**From DNS records to DNS intelligence.**

[![CI](https://github.com/Joneskau/dnsearcher/actions/workflows/ci.yml/badge.svg)](https://github.com/Joneskau/dnsearcher/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)](pyproject.toml)

> Pronounced **D-N-Searcher** -- spelled **DNSearcher**, not **DNSSearcher**.

## What is DNSearcher?

DNSearcher is a professional, defensive DNS intelligence toolkit for IT technicians,
security analysts, sysadmins, incident responders, and learners. Fetching DNS records
is easy; the hard part is understanding what those answers *imply* about infrastructure,
providers, and risk. Unlike simple wrappers around `dig`, `host`, or `nslookup`,
DNSearcher focuses on **interpretation and decision support**.

It supports three related jobs:

- **Troubleshooting** -- why isn't this resolving? Where does delegation break?
- **Security review** -- what does this domain expose, and is it configured safely?
- **Monitoring & evidence** -- what changed, when, and why does it matter?

## Why it matters

DNS can reveal mail providers, cloud platforms, SaaS services, nameservers, and
security policy -- MITRE ATT&CK tracks this under *Gather Victim Network Information: DNS*.
DNS compromise has driven real incidents, including the Sea Turtle DNS-hijacking
campaign and the 2016 Dyn attack. DNSearcher helps defenders understand and monitor
this attack surface.

## Core capabilities (v0.1 focus)

The moat is the interpretation layer -- everything else is supporting cast.

**Tier 1 -- invest polish here**
- `posture` -- DNS security posture audit (findings model + report)
- `snapshot` / `diff` -- baseline and drift detection
- SPF / DMARC interpretation (inside posture + `diagnose`)

**Tier 2 -- solid & fast**
- `query`, `reverse`, `trace`, `batch`

**Tier 3 -- round out v1**
- `whois` (RDAP-first, WHOIS fallback), `score`, `compare`, `diagnose`, `report`

**Deferred post-MVP:** `monitor`, `timeline`, `graph`, `fingerprint`, `subdomains`,
`axfr`, plugin architecture, `learn`, alerting, full DNSSEC chain validation.

## Example

```bash
dnsearcher posture example.com
```
```text
DNS Security Posture: example.com
Overall Grade: B+   Score: 82/100

Email Security
  SPF      PASS       Strong SPF policy found
  DMARC    WARNING    DMARC exists but policy is p=none
Domain Controls
  DNSSEC   PASS       DNSSEC appears enabled
  CAA      WARNING    No CAA record found
```

## Findings model

Every check emits a stable, IDed, severity-tagged finding:

```json
{
  "id": "DNS-EMAIL-DMARC-WEAK",
  "title": "DMARC policy is not enforced",
  "severity": "medium",
  "category": "email_security",
  "description": "The domain has a DMARC record, but the policy is set to p=none.",
  "impact": "Spoofed email may not be rejected or quarantined by receiving mail servers.",
  "recommendation": "Move from p=none to p=quarantine after reviewing reports, then consider p=reject."
}
```

Severity: `INFO` * `LOW` * `MEDIUM` * `HIGH` * `CRITICAL`
Grades: A+ 95-100 * A 90-94 * B+ 80-89 * B 70-79 * C 60-69 * D 50-59 * F 0-49

## Architecture

```text
dnsearcher/
  cli.py  resolver.py  output.py  whois_rdap.py
  models/     records.py  findings.py  snapshots.py
  analysis/   posture.py  scoring.py  email_security.py  dnssec.py
  data/       provider_fingerprints.yaml  dangling_cname_targets.yaml
  reporting/  markdown.py  html.py
tests/        fixtures/  conftest.py  test_findings.py  test_posture.py
```

## Getting started

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -e .
pip install pytest
pytest -q
```

## Status

v0.1 scaffold: records + resolver spine, findings model backbone, and an
email-security posture engine stub (SPF/DMARC). See the `# TODO` markers in
`dnsearcher/analysis/` and `dnsearcher/models/snapshots.py` for what's next.

## Engineering ground rules

- **Test against fixtures, not the live internet.** Deterministic, offline CI.
- **Be a good netizen.** Rate limits/backoff/concurrency caps for `batch` and `subdomains`.
- **Handle IDN / punycode** everywhere a domain is accepted.
- **Data over hardcode.** Provider fingerprints and dangling-CNAME target lists live
  in versioned YAML (`dnsearcher/data/`), not in code.

## Positioning

DNSearcher is a **defensive and educational** tool. It is intended for authorized DNS
analysis, infrastructure troubleshooting, posture review, incident response, and
education -- not for unauthorized recon, harassment, or abuse.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

[MIT](LICENSE)