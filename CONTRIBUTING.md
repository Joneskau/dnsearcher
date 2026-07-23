# Contributing to DNSearcher

Thanks for your interest in DNSearcher. This project is in early v0.1 scaffolding,
so contributions are especially impactful right now.

## Development setup

```powershell
git clone https://github.com/Joneskau/dnsearcher.git
cd dnsearcher
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -e .
pip install pytest
pytest -q
```

(macOS/Linux: use `source .venv/bin/activate` instead of the `.venv\Scripts\Activate.ps1` line.)

## Ground rules

- **Fixtures, not live DNS, in tests.** Use the `FakeResolver` pattern in
  `tests/conftest.py` so CI stays deterministic and offline. Do not add tests
  that hit real resolvers or WHOIS/RDAP servers.
- **Data over hardcode.** Provider fingerprints and dangling-CNAME target lists
  belong in `dnsearcher/data/*.yaml`, not inline in analysis code.
- **Findings are the backbone.** New checks should emit `Finding` objects
  (`dnsearcher/models/findings.py`) with a stable `id`, `severity`, `category`,
  `description`, `impact`, and `recommendation` -- this is what reporting and
  JSON output render from.
- **Be a good netizen.** Anything that queries many domains or resolvers
  (`batch`, `subdomains`) needs sane default concurrency, timeouts, and backoff.

## Priorities right now

See the `# TODO` comments in `dnsearcher/analysis/` for the current focus:

1. SPF recursive include/redirect lookup counter (`DNS-EMAIL-SPF-EXCESSIVE-LOOKUP`)
2. DNSSEC presence check + CAA/AXFR/NS/SOA/TTL checks in `posture.py`
3. `models/snapshots.py` snapshot + diff
4. `reporting/markdown.py`, then `reporting/html.py`

## Pull requests

- Keep PRs focused on one change.
- Add or update tests under `tests/` for any behavior change.
- Make sure `pytest -q` passes before opening a PR.
- Describe the security/behavioral impact of the change, especially for anything
  touching `dnsearcher/analysis/`.

## Reporting issues

Use the issue templates for bug reports and feature requests.