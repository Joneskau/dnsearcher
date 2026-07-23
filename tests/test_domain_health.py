import asyncio
from dnsearcher.models.records import Record, RecordSet
from dnsearcher.analysis import domain_health


class FakeAxfrResolver:
    server = "mock"

    def __init__(self, open_nameservers=None):
        self.open_nameservers = set(open_nameservers or [])

    async def query(self, name, rtype):
        return []

    async def attempt_axfr(self, nameserver, domain):
        return nameserver in self.open_nameservers


def test_caa_missing_flagged():
    rs = RecordSet(domain="example.com", resolver="mock", records=[])
    ids = {f.id for f in domain_health.check_caa(rs)}
    assert "DNS-DOMAIN-CAA-MISSING" in ids


def test_caa_present_passes():
    rs = RecordSet(domain="example.com", resolver="mock", records=[
        Record("example.com", "CAA", '0 issue "letsencrypt.org"', 3600),
    ])
    assert domain_health.check_caa(rs) == []


def test_soa_missing_flagged():
    rs = RecordSet(domain="example.com", resolver="mock", records=[])
    ids = {f.id for f in domain_health.check_soa(rs)}
    assert "DNS-DOMAIN-SOA-MISSING" in ids


def test_ns_single_is_inconsistent():
    rs = RecordSet(domain="example.com", resolver="mock", records=[
        Record("example.com", "NS", "ns1.example.net.", 3600),
    ])
    ids = {f.id for f in domain_health.check_ns_consistency(rs)}
    assert "DNS-DOMAIN-NS-INCONSISTENT" in ids


def test_ns_two_or_more_passes():
    rs = RecordSet(domain="example.com", resolver="mock", records=[
        Record("example.com", "NS", "ns1.example.net.", 3600),
        Record("example.com", "NS", "ns2.example.net.", 3600),
    ])
    assert domain_health.check_ns_consistency(rs) == []


def test_axfr_blocked_by_all_nameservers_passes():
    rs = RecordSet(domain="example.com", resolver="mock", records=[
        Record("example.com", "NS", "ns1.example.net.", 3600),
        Record("example.com", "NS", "ns2.example.net.", 3600),
    ])
    resolver = FakeAxfrResolver(open_nameservers=[])
    findings = asyncio.run(domain_health.check_axfr(resolver, rs))
    assert findings == []


def test_axfr_open_on_any_nameserver_is_critical():
    rs = RecordSet(domain="example.com", resolver="mock", records=[
        Record("example.com", "NS", "ns1.example.net.", 3600),
        Record("example.com", "NS", "ns2.example.net.", 3600),
    ])
    resolver = FakeAxfrResolver(open_nameservers=["ns1.example.net."])
    findings = asyncio.run(domain_health.check_axfr(resolver, rs))
    ids = {f.id for f in findings}
    assert "DNS-DOMAIN-AXFR-OPEN" in ids
    assert findings[0].severity.value == "critical"


def test_axfr_no_nameservers_returns_no_finding():
    rs = RecordSet(domain="example.com", resolver="mock", records=[])
    resolver = FakeAxfrResolver()
    findings = asyncio.run(domain_health.check_axfr(resolver, rs))
    assert findings == []