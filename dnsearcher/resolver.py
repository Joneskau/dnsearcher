from __future__ import annotations
import asyncio
from typing import Protocol
import dns.asyncresolver
import dns.asyncquery
import dns.zone
from .models.records import Record, RecordSet

RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CAA", "DNSKEY", "DS"]


def _rdata_text(rdata, rtype: str) -> str:
    """Render an rdata value as plain text.

    dnspython's default to_text() wraps TXT character-strings in double
    quotes, and splits long values into multiple quoted segments (e.g.
    '"part1" "part2"'). That breaks simple prefix checks like
    str.startswith("v=spf1"). For TXT records, join the decoded character
    strings instead so callers see the plain, unquoted value.
    """
    if rtype == "TXT" and hasattr(rdata, "strings"):
        return "".join(
            s.decode("utf-8", "replace") if isinstance(s, bytes) else s
            for s in rdata.strings
        )
    return rdata.to_text()


class Resolver(Protocol):
    async def query(self, name: str, rtype: str) -> list[Record]: ...
    async def attempt_axfr(self, nameserver: str, domain: str) -> bool: ...


class LiveResolver:
    def __init__(self, server: str = "1.1.1.1", timeout: float = 5.0):
        self.server = server
        self._timeout = timeout
        self._r = dns.asyncresolver.Resolver(configure=False)
        self._r.nameservers = [server]
        self._r.lifetime = timeout

    async def query(self, name: str, rtype: str) -> list[Record]:
        try:
            ans = await self._r.resolve(name, rtype, raise_on_no_answer=False)
        except Exception:
            return []
        ttl = ans.rrset.ttl if ans.rrset else 0
        return [
            Record(name, rtype, _rdata_text(r, rtype), ttl) for r in (ans.rrset or [])
        ]

    async def attempt_axfr(self, nameserver: str, domain: str) -> bool:
        """Best-effort AXFR probe against one nameserver.

        Returns True only if the transfer was allowed and returned zone data
        (bad). Any refusal, resolution failure, or timeout is treated as
        blocked (good) -- the safe default for a security scanner.
        """
        try:
            ns_host = nameserver.rstrip(".")
            ns_answer = await self._r.resolve(ns_host, "A", raise_on_no_answer=False)
            if not ns_answer.rrset:
                return False
            ns_ip = ns_answer.rrset[0].to_text()
            xfr = dns.asyncquery.xfr(ns_ip, domain, lifetime=self._timeout)
            zone = await dns.zone.from_xfr(xfr)
            return len(zone.nodes) > 0
        except Exception:
            return False


async def resolve_all(resolver: Resolver, domain: str) -> RecordSet:
    rs = RecordSet(domain=domain, resolver=getattr(resolver, "server", "mock"))
    results = await asyncio.gather(
        *(resolver.query(domain, t) for t in RECORD_TYPES)
    )
    for recs in results:
        rs.records.extend(recs)
    return rs