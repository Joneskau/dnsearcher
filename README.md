# DNSearcher

From DNS records to DNS intelligence.

## Setup

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -e .
pip install pytest
pytest -q
```

## Status

v0.1 scaffold: records + resolver spine, findings model backbone, and an
email-security posture engine stub (SPF/DMARC). See the TODOs in
`dnsearcher/analysis/` and `dnsearcher/models/snapshots.py` for next steps.