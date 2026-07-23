import asyncio
from dnsearcher.resolver import resolve_all
from dnsearcher.analysis.posture import run_posture


def test_weak_domain_flags_soft_spf(weak_domain):
    rs = asyncio.run(resolve_all(weak_domain, "example.com"))
    result = asyncio.run(run_posture(rs, dmarc_txt=None, resolver=weak_domain))
    ids = {f["id"] for f in result["findings"]}
    assert "DNS-EMAIL-SPF-WEAK" in ids
    assert "DNS-EMAIL-DMARC-MISSING" in ids
    assert result["grade"] in {"C", "D", "F", "B", "B+"}


def test_excessive_spf_lookups_flagged(excessive_spf_domain):
    rs = asyncio.run(resolve_all(excessive_spf_domain, "bigsender.example.com"))
    result = asyncio.run(run_posture(rs, dmarc_txt=None, resolver=excessive_spf_domain))
    ids = {f["id"] for f in result["findings"]}
    assert "DNS-EMAIL-SPF-EXCESSIVE-LOOKUP" in ids