import pytest
from dnsearcher.models.records import Record


class FakeResolver:
    server = "mock"

    def __init__(self, table, axfr_open=None):
        self.table = table  # {(name, rtype): [values]}
        self.axfr_open = set(axfr_open or [])  # nameservers that (badly) allow AXFR

    async def query(self, name, rtype):
        vals = self.table.get((name, rtype), [])
        return [Record(name, rtype, v, 300) for v in vals]

    async def attempt_axfr(self, nameserver, domain):
        return nameserver in self.axfr_open


@pytest.fixture
def weak_domain():
    return FakeResolver({
        ("example.com", "TXT"): ["v=spf1 include:_spf.google.com ~all"],
        ("example.com", "NS"): ["ns1.example.net.", "ns2.example.net."],
        ("example.com", "MX"): ["10 mail.protection.outlook.com."],
    })


@pytest.fixture
def excessive_spf_domain():
    includes = " ".join(f"include:spf{i}.example.net" for i in range(1, 12))
    return FakeResolver({
        ("bigsender.example.com", "TXT"): [f"v=spf1 {includes} ~all"],
        ("bigsender.example.com", "NS"): ["ns1.example.net.", "ns2.example.net."],
    })


@pytest.fixture
def good_domain():
    return FakeResolver({
        ("good.example.com", "TXT"): ["v=spf1 include:_spf.google.com -all"],
        ("good.example.com", "NS"): ["ns1.example.net.", "ns2.example.net."],
        ("good.example.com", "SOA"): [
            "ns1.example.net. hostmaster.good.example.com. 1 7200 3600 1209600 300"
        ],
        ("good.example.com", "CAA"): ['0 issue "letsencrypt.org"'],
        ("good.example.com", "DNSKEY"): ["257 3 13 examplebase64key=="],
        ("good.example.com", "DS"): ["12345 13 2 ABCDEF"],
        ("good.example.com", "A"): ["203.0.113.10"],
        ("good.example.com", "AAAA"): ["2001:db8::10"],
    })


@pytest.fixture
def open_axfr_domain():
    return FakeResolver(
        {
            ("axfr.example.com", "NS"): ["ns1.example.net.", "ns2.example.net."],
            ("axfr.example.com", "SOA"): [
                "ns1.example.net. hostmaster.axfr.example.com. 1 7200 3600 1209600 300"
            ],
        },
        axfr_open={"ns1.example.net."},
    )