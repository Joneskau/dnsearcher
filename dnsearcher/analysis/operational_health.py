from __future__ import annotations
from ..models.records import RecordSet
from ..models.findings import Finding, Severity, Category


def check_ttl_consistency(rs: RecordSet) -> list[Finding]:
    findings: list[Finding] = []
    for rtype in ("A", "AAAA", "NS", "MX"):
        ttls = {r.ttl for r in rs.of_type(rtype)}
        if len(ttls) > 1:
            findings.append(Finding(
                id="DNS-OPS-TTL-INCONSISTENT",
                title=f"Inconsistent TTLs across {rtype} records",
                severity=Severity.INFO,
                category=Category.OPS,
                description=f"{rtype} records for {rs.domain} report different TTLs: {sorted(ttls)}.",
                impact="Inconsistent TTLs can cause uneven cache expiry and confusing propagation during changes.",
                recommendation=f"Align TTLs across all {rtype} records at the authoritative source.",
            ))
    return findings


def check_ip_availability(rs: RecordSet) -> list[Finding]:
    if rs.of_type("AAAA"):
        return []
    return [Finding(
        id="DNS-OPS-IPV6-ABSENT",
        title="No IPv6 (AAAA) records",
        severity=Severity.INFO,
        category=Category.OPS,
        description=f"No AAAA records were found for {rs.domain}.",
        impact="Informational: IPv4-only reachability. Not a security issue by itself.",
        recommendation="Consider adding IPv6 (AAAA) records as dual-stack adoption grows.",
    )]