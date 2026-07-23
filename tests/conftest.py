import pytest
from dnsearcher.models.records import Record


class FakeResolver:
    server = "mock"

    def __init__(self, table):
        self.table = table  # {(name, rtype): [values]}

    async def query(self, name, rtype):
        vals = self.table.get((name, rtype), [])
        return [Record(name, rtype, v, 300) for v in vals]


@pytest.fixture
def weak_domain():
    return FakeResolver({
        ("example.com", "TXT"): ["v=spf1 include:_spf.google.com ~all"],
        ("example.com", "NS"): ["ns1.example.net.", "ns2.example.net."],
        ("example.com", "MX"): ["10 mail.protection.outlook.com."],
    })