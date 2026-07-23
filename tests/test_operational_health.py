from dnsearcher.models.records import Record, RecordSet
from dnsearcher.analysis import operational_health


def test_ttl_inconsistency_flagged():
    rs = RecordSet(domain="example.com", resolver="mock", records=[
        Record("example.com", "A", "203.0.113.10", 300),
        Record("example.com", "A", "203.0.113.11", 3600),
    ])
    ids = {f.id for f in operational_health.check_ttl_consistency(rs)}
    assert "DNS-OPS-TTL-INCONSISTENT" in ids


def test_ttl_consistent_passes():
    rs = RecordSet(domain="example.com", resolver="mock", records=[
        Record("example.com", "A", "203.0.113.10", 300),
        Record("example.com", "A", "203.0.113.11", 300),
    ])
    assert operational_health.check_ttl_consistency(rs) == []


def test_ipv6_absent_is_informational():
    rs = RecordSet(domain="example.com", resolver="mock", records=[
        Record("example.com", "A", "203.0.113.10", 300),
    ])
    ids = {f.id for f in operational_health.check_ip_availability(rs)}
    assert "DNS-OPS-IPV6-ABSENT" in ids


def test_ipv6_present_passes():
    rs = RecordSet(domain="example.com", resolver="mock", records=[
        Record("example.com", "AAAA", "2001:db8::1", 300),
    ])
    assert operational_health.check_ip_availability(rs) == []