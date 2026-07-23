from __future__ import annotations
from ..models.records import RecordSet
from ..models.findings import Finding, Severity, Category, Evidence

SPF_LOOKUP_LIMIT = 10


def check_spf(rs: RecordSet) -> list[Finding]:
    spf = next((v for v in rs.txt_values() if v.lower().startswith("v=spf1")), None)
    if not spf:
        return [Finding(
            id="DNS-EMAIL-SPF-MISSING", title="No SPF record",
            severity=Severity.MEDIUM, category=Category.EMAIL,
            description="No v=spf1 TXT record was found.",
            impact="Receivers cannot verify authorized senders; spoofing is easier.",
            recommendation="Publish an SPF record ending in -all once senders are enumerated.",
        )]
    findings: list[Finding] = []
    if "~all" in spf or "?all" in spf:
        findings.append(Finding(
            id="DNS-EMAIL-SPF-WEAK", title="SPF policy is soft/neutral",
            severity=Severity.LOW, category=Category.EMAIL,
            description=f"SPF ends in a soft/neutral qualifier: {spf}",
            impact="Spoofed mail may still pass; enforcement is limited.",
            recommendation="Move toward -all after verifying all legitimate senders.",
            evidence=Evidence(rs.domain, "TXT", spf, rs.resolver),
        ))
    # TODO: implement recursive include/redirect lookup counter ->
    #       DNS-EMAIL-SPF-EXCESSIVE-LOOKUP (HIGH) when count > SPF_LOOKUP_LIMIT
    return findings


def check_dmarc(dmarc_txt: str | None, domain: str, resolver: str) -> list[Finding]:
    if not dmarc_txt:
        return [Finding(
            id="DNS-EMAIL-DMARC-MISSING", title="No DMARC record",
            severity=Severity.MEDIUM, category=Category.EMAIL,
            description="No _dmarc TXT record was found.",
            impact="Receivers get no guidance on handling unaligned mail.",
            recommendation="Publish _dmarc with p=none, then tighten to quarantine/reject.",
        )]
    if "p=none" in dmarc_txt:
        return [Finding(
            id="DNS-EMAIL-DMARC-WEAK", title="DMARC policy is not enforced",
            severity=Severity.MEDIUM, category=Category.EMAIL,
            description="DMARC exists but policy is p=none.",
            impact="Spoofed mail may not be quarantined or rejected.",
            recommendation="Move p=none -> p=quarantine -> p=reject after reviewing reports.",
            evidence=Evidence(f"_dmarc.{domain}", "TXT", dmarc_txt, resolver),
        )]
    return []