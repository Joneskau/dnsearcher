from __future__ import annotations
from ..models.records import RecordSet
from ..models.findings import Finding
from ..resolver import Resolver
from . import email_security, dnssec, domain_health, operational_health, scoring


async def run_posture(rs: RecordSet, dmarc_txt: str | None, resolver: Resolver) -> dict:
    findings: list[Finding] = []
    findings += email_security.check_spf(rs)
    findings += await email_security.check_spf_excessive_lookups(resolver, rs)
    findings += email_security.check_dmarc(dmarc_txt, rs.domain, rs.resolver)
    findings += dnssec.check_dnssec_presence(rs)
    findings += domain_health.check_caa(rs)
    findings += domain_health.check_soa(rs)
    findings += domain_health.check_ns_consistency(rs)
    findings += await domain_health.check_axfr(resolver, rs)
    findings += operational_health.check_ttl_consistency(rs)
    findings += operational_health.check_ip_availability(rs)

    passed = _derive_passed(findings, rs)
    score, g = scoring.score_findings(passed)
    return {
        "domain": rs.domain,
        "grade": g,
        "score": score,
        "findings": [f.to_dict() for f in findings],
    }


def _derive_passed(findings: list[Finding], rs: RecordSet) -> set[str]:
    ids = {f.id for f in findings}
    passed: set[str] = set()
    if not any(i.startswith("DNS-EMAIL-SPF") for i in ids):
        passed.add("spf")
    if not any(i.startswith("DNS-EMAIL-DMARC") for i in ids):
        passed.add("dmarc")
    if "DNS-DOMAIN-NS-INCONSISTENT" not in ids:
        passed.add("ns")
    if "DNS-DOMAIN-CAA-MISSING" not in ids:
        passed.add("caa")
    if "DNS-DOMAIN-DNSSEC-ABSENT" not in ids:
        passed.add("dnssec")
    if "DNS-DOMAIN-AXFR-OPEN" not in ids:
        passed.add("axfr")
    # NOTE: "dangling" (no dangling CNAMEs) intentionally not awarded yet --
    # dangling-CNAME detection is planned alongside snapshot/diff.
    return passed