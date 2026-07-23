from __future__ import annotations
from ..models.records import RecordSet
from ..models.findings import Finding
from ..resolver import Resolver
from . import email_security, scoring


async def run_posture(rs: RecordSet, dmarc_txt: str | None, resolver: Resolver) -> dict:
    findings: list[Finding] = []
    findings += email_security.check_spf(rs)
    findings += await email_security.check_spf_excessive_lookups(resolver, rs)
    findings += email_security.check_dmarc(dmarc_txt, rs.domain, rs.resolver)
    # TODO: dnssec presence, caa, axfr, ns consistency, soa, ttl checks

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
    if len(rs.of_type("NS")) > 1:
        passed.add("ns")
    if rs.of_type("CAA"):
        passed.add("caa")
    return passed