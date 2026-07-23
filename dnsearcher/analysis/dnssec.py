from __future__ import annotations
from ..models.records import RecordSet
from ..models.findings import Finding, Severity, Category, Evidence


def check_dnssec_presence(rs: RecordSet) -> list[Finding]:
    """Presence-only check: were DNSKEY/DS records observed for this domain?

    This intentionally does NOT validate the chain of trust (that is
    deferred post-v0.1). It only reports whether DNSSEC signing appears
    to be turned on at all.
    """
    if rs.of_type("DNSKEY") or rs.of_type("DS"):
        return []
    return [Finding(
        id="DNS-DOMAIN-DNSSEC-ABSENT",
        title="DNSSEC presence not detected",
        severity=Severity.MEDIUM,
        category=Category.DOMAIN,
        description=(
            "No DNSKEY or DS records were observed for this domain "
            "(presence check only; chain-of-trust validation is not performed)."
        ),
        impact=(
            "Responses cannot be cryptographically validated, leaving the "
            "domain open to cache poisoning and spoofed responses."
        ),
        recommendation="Enable DNSSEC signing and publish a DS record at the registrar/parent zone.",
        evidence=Evidence(rs.domain, "DNSKEY/DS", "absent", rs.resolver),
    )]