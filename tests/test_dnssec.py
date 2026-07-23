from dnsearcher.models.records import Record, RecordSet
from dnsearcher.analysis.dnssec import check_dnssec_presence


def test_absent_when_no_dnskey_or_ds():
    rs = RecordSet(domain="none.example.com", resolver="mock", records=[])
    ids = {f.id for f in check_dnssec_presence(rs)}
    assert ids == {"DNS-DOMAIN-DNSSEC-ABSENT"}


def test_present_when_dnskey_observed():
    rs = RecordSet(domain="signed.example.com", resolver="mock", records=[
        Record("signed.example.com", "DNSKEY", "257 3 13 examplekey==", 3600),
    ])
    assert check_dnssec_presence(rs) == []


def test_present_when_ds_observed():
    rs = RecordSet(domain="signed.example.com", resolver="mock", records=[
        Record("signed.example.com", "DS", "12345 13 2 ABCDEF", 3600),
    ])
    assert check_dnssec_presence(rs) == []