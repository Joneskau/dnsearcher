"""DNSSEC presence checks (TODO: DNSKEY/DS validation, CAA/AXFR/NS/SOA/TTL checks)."""
from __future__ import annotations
from ..models.records import RecordSet
from ..models.findings import Finding


def check_dnssec(rs: RecordSet) -> list[Finding]:
    # TODO: flag missing DNSKEY/DS, validate chain of trust
    return []