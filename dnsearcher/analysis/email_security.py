from __future__ import annotations
from dataclasses import dataclass
from ..models.records import RecordSet
from ..models.findings import Finding, Severity, Category, Evidence
from ..resolver import Resolver

SPF_LOOKUP_LIMIT = 10
LOOKUP_MECHANISMS = ("include", "a", "mx", "ptr", "exists")
MAX_RECURSION_DEPTH = 10


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


@dataclass
class SpfLookupResult:
    """Result of recursively counting SPF DNS-lookup-costing mechanisms."""
    count: int
    truncated: bool  # True if a recursion-depth or loop guard cut counting short


async def _spf_txt_for(resolver: Resolver, domain: str) -> str | None:
    records = await resolver.query(domain, "TXT")
    return next(
        (r.value for r in records if r.value.lower().startswith("v=spf1")),
        None,
    )


def _spf_lookup_terms(spf_record: str) -> list[tuple[str, str | None]]:
    """Extract (mechanism_or_modifier, target_domain) pairs that cost a DNS lookup.

    Per RFC 7208 4.6.4, the include/a/mx/ptr/exists mechanisms and the
    redirect modifier each cost one DNS lookup. ip4/ip6/all/exp and
    qualifiers (+/-/~/?) do not.
    """
    terms: list[tuple[str, str | None]] = []
    for raw in spf_record.split():
        term = raw.lower()
        if term.startswith("v=spf1"):
            continue
        if term.startswith("redirect="):
            terms.append(("redirect", term.split("=", 1)[1] or None))
            continue
        if "=" in term:
            continue  # other modifiers (e.g. exp=) are not counted here
        body = term.lstrip("+-~?")
        for mech in LOOKUP_MECHANISMS:
            if body == mech or body.startswith(mech + ":") or body.startswith(mech + "/"):
                target = body.split(":", 1)[1] if ":" in body else None
                terms.append((mech, target))
                break
    return terms


async def count_spf_lookups(
    resolver: Resolver,
    domain: str,
    spf_record: str | None = None,
    *,
    _visited: set[str] | None = None,
    _depth: int = 0,
) -> SpfLookupResult:
    """Recursively count SPF lookup-costing mechanisms, following include/redirect chains."""
    visited = _visited if _visited is not None else set()

    if spf_record is None:
        spf_record = await _spf_txt_for(resolver, domain)
    if not spf_record:
        return SpfLookupResult(count=0, truncated=False)

    if domain in visited:
        return SpfLookupResult(count=0, truncated=True)
    visited.add(domain)

    if _depth > MAX_RECURSION_DEPTH:
        return SpfLookupResult(count=0, truncated=True)

    count = 0
    truncated = False
    for mechanism, target in _spf_lookup_terms(spf_record):
        count += 1
        if mechanism in ("include", "redirect") and target:
            nested = await count_spf_lookups(
                resolver, target, _visited=visited, _depth=_depth + 1
            )
            count += nested.count
            truncated = truncated or nested.truncated

    return SpfLookupResult(count=count, truncated=truncated)


async def check_spf_excessive_lookups(resolver: Resolver, rs: RecordSet) -> list[Finding]:
    spf = next((v for v in rs.txt_values() if v.lower().startswith("v=spf1")), None)
    if not spf:
        return []

    result = await count_spf_lookups(resolver, rs.domain, spf_record=spf)
    if result.count <= SPF_LOOKUP_LIMIT:
        return []

    note = ""
    if result.truncated:
        note = " (count may be a lower bound; a recursion/loop guard was hit)"

    return [Finding(
        id="DNS-EMAIL-SPF-EXCESSIVE-LOOKUP",
        title="SPF record exceeds the 10-lookup limit",
        severity=Severity.HIGH,
        category=Category.EMAIL,
        description=(
            f"Evaluating this domain's SPF chain requires {result.count} DNS "
            f"lookups (include/a/mx/ptr/exists/redirect), exceeding the RFC "
            f"7208 limit of {SPF_LOOKUP_LIMIT}{note}."
        ),
        impact=(
            "Resolvers must treat SPF as a PermError once the lookup limit "
            "is exceeded, which can cause legitimate mail to fail SPF checks."
        ),
        recommendation=(
            "Flatten or trim SPF includes (consolidate third-party senders, "
            "remove unused includes/redirects) to bring the lookup count "
            "back under 10."
        ),
        evidence=Evidence(rs.domain, "TXT", spf, rs.resolver),
    )]