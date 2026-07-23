import asyncio
from dnsearcher.models.records import Record, RecordSet
from dnsearcher.analysis import email_security


class FakeResolver:
    server = "mock"

    def __init__(self, table):
        self.table = table  # {(name, rtype): [values]}

    async def query(self, name, rtype):
        vals = self.table.get((name, rtype), [])
        return [Record(name, rtype, v, 300) for v in vals]


def _spf_resolver(records: dict[str, str]) -> FakeResolver:
    return FakeResolver({(domain, "TXT"): [spf] for domain, spf in records.items()})


def _record_set(domain: str, spf: str) -> RecordSet:
    return RecordSet(domain=domain, resolver="mock", records=[
        Record(domain, "TXT", spf, 300),
    ])


def test_exactly_ten_lookups_is_not_excessive():
    includes = " ".join(f"include:spf{i}.example.net" for i in range(1, 11))
    spf = f"v=spf1 {includes} ~all"
    resolver = _spf_resolver({"ok.example.com": spf})
    rs = _record_set("ok.example.com", spf)

    findings = asyncio.run(email_security.check_spf_excessive_lookups(resolver, rs))

    assert findings == []


def test_eleven_lookups_is_excessive():
    includes = " ".join(f"include:spf{i}.example.net" for i in range(1, 12))
    spf = f"v=spf1 {includes} ~all"
    resolver = _spf_resolver({"many.example.com": spf})
    rs = _record_set("many.example.com", spf)

    findings = asyncio.run(email_security.check_spf_excessive_lookups(resolver, rs))

    ids = {f.id for f in findings}
    assert "DNS-EMAIL-SPF-EXCESSIVE-LOOKUP" in ids
    assert findings[0].severity.value == "high"


def test_nested_includes_count_recursively():
    # top: 5 includes; each mid: 2 more includes -> 5 + (5 * 2) = 15 lookups
    nested = " ".join(f"include:leaf{i}.example.net" for i in range(1, 3))
    top_spf = "v=spf1 " + " ".join(
        f"include:mid{i}.example.net" for i in range(1, 6)
    ) + " ~all"

    records = {"top.example.com": top_spf}
    for i in range(1, 6):
        records[f"mid{i}.example.net"] = f"v=spf1 {nested} ~all"

    resolver = _spf_resolver(records)
    rs = _record_set("top.example.com", top_spf)

    findings = asyncio.run(email_security.check_spf_excessive_lookups(resolver, rs))

    ids = {f.id for f in findings}
    assert "DNS-EMAIL-SPF-EXCESSIVE-LOOKUP" in ids


def test_circular_include_does_not_infinite_loop():
    records = {
        "a.example.com": "v=spf1 include:b.example.com ~all",
        "b.example.com": "v=spf1 include:a.example.com ~all",
    }
    resolver = _spf_resolver(records)
    rs = _record_set("a.example.com", records["a.example.com"])

    # Should complete without hanging and without raising.
    findings = asyncio.run(email_security.check_spf_excessive_lookups(resolver, rs))

    assert isinstance(findings, list)


def test_no_spf_record_returns_no_excessive_finding():
    resolver = _spf_resolver({})
    rs = RecordSet(domain="none.example.com", resolver="mock", records=[])

    findings = asyncio.run(email_security.check_spf_excessive_lookups(resolver, rs))

    assert findings == []