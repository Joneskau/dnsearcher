from __future__ import annotations
import asyncio
from typing import Protocol
import dns.asyncresolver
from .models.records import Record, RecordSet

RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CAA", "DNSKEY", "DS"]


class Resolver(Protocol):
    async def query(self, name: str, rtype: str) -> list[Record]: ...


class LiveResolver:
    def __init__(self, server: str = "1.1.1.1", timeout: float = 5.0):
        self.server = server
        self._r = dns.asyncresolver.Resolver(configure=False)
        self._r.nameservers = [server]
        self._r.lifetime = timeout

    async def query(self, name: str, rtype: str) -> list[Record]:
        try:
            ans = await self._r.resolve(name, rtype, raise_on_no_answer=False)
        except Exception:
            return []
        ttl = ans.rrset.ttl if ans.rrset else 0
        return [Record(name, rtype, r.to_text(), ttl) for r in (ans.rrset or [])]


async def resolve_all(resolver: Resolver, domain: str) -> RecordSet:
    rs = RecordSet(domain=domain, resolver=getattr(resolver, "server", "mock"))
    results = await asyncio.gather(
        *(resolver.query(domain, t) for t in RECORD_TYPES)
    )
    for recs in results:
        rs.records.extend(recs)
    return rs