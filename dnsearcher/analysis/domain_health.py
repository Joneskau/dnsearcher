from __future__ import annotations
from ..models.records import RecordSet
from ..models.findings import Finding, Severity, Category, Evidence
from ..resolver import Resolver


def check_caa(rs: RecordSet) -> list[Finding]:
    if rs.of_type("CAA"):
        return []
    return [Finding(
        id="DNS-DOMAIN-CAA-MISSING",
        title="No CAA record",
        severity=Severity.LOW,
        category=Category.DOMAIN,
        description="No CAA record was found for this domain.",
        impact="Any publicly trusted CA can issue certificates for this domain without restriction.",
        recommendation="Publish a CAA record naming only the CA(s) you actually use.",
    )]


def check_soa(rs: RecordSet) -> list[Finding]:
    if rs.of_type("SOA"):
        return []
    return [Finding(
        id="DNS-DOMAIN-SOA-MISSING",
        title="No SOA record returned",
        severity=Severity.MEDIUM,
        category=Category.DOMAIN,
        description="No SOA record was returned for this domain.",
        impact="This usually indicates a delegation or resolution problem; zone health cannot be assessed.",
        recommendation="Verify delegation at the registrar and confirm the authoritative nameservers answer for SOA.",
    )]


def check_ns_consistency(rs: RecordSet) -> list[Finding]:
    nameservers = {r.value for r in rs.of_type("NS")}
    if len(nameservers) >= 2:
        return []
    return [Finding(
        id="DNS-DOMAIN-NS-INCONSISTENT",
        title="Fewer than two authoritative nameservers",
        severity=Severity.MEDIUM,
        category=Category.DOMAIN,
        description=(
            f"Only {len(nameservers)} unique NS record(s) were observed: "
            f"{', '.join(nameservers) or 'none'}."
        ),
        impact=(
            "A single nameserver (or none) is a single point of failure and "
            "cannot be checked for delegation consistency."
        ),
        recommendation="Delegate to at least two independent, geographically diverse nameservers.",
    )]


async def check_axfr(resolver: Resolver, rs: RecordSet) -> list[Finding]:
    nameservers = [r.value for r in rs.of_type("NS")]
    if not nameservers:
        return []

    open_ns: list[str] = []
    for ns in nameservers:
        try:
            allowed = await resolver.attempt_axfr(ns, rs.domain)
        except Exception:
            allowed = False
        if allowed:
            open_ns.append(ns)

    if not open_ns:
        return []

    return [Finding(
        id="DNS-DOMAIN-AXFR-OPEN",
        title="Zone transfer (AXFR) is allowed",
        severity=Severity.CRITICAL,
        category=Category.DOMAIN,
        description=f"The following nameserver(s) allowed a full zone transfer: {', '.join(open_ns)}.",
        impact="An attacker can dump the entire zone, exposing internal hostnames and infrastructure.",
        recommendation="Restrict AXFR to authorized secondary nameservers only (ACL by IP / TSIG).",
        evidence=Evidence(rs.domain, "AXFR", ", ".join(open_ns), rs.resolver),
    )]