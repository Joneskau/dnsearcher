import dns.rdata
import dns.rdataclass
import dns.rdatatype

from dnsearcher.resolver import _rdata_text


def test_single_segment_txt_is_unquoted():
    rdata = dns.rdata.from_text(
        dns.rdataclass.IN,
        dns.rdatatype.TXT,
        '"v=spf1 include:_spf.google.com ~all"',
    )
    assert _rdata_text(rdata, "TXT") == "v=spf1 include:_spf.google.com ~all"


def test_multi_segment_txt_is_concatenated_without_separator():
    rdata = dns.rdata.from_text(
        dns.rdataclass.IN,
        dns.rdatatype.TXT,
        '"v=spf1 include:_spf.example.com " "~all"',
    )
    assert _rdata_text(rdata, "TXT") == "v=spf1 include:_spf.example.com ~all"


def test_non_txt_rdata_uses_to_text():
    rdata = dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.A, "203.0.113.10")
    assert _rdata_text(rdata, "A") == "203.0.113.10"