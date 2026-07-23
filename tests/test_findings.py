from dnsearcher.models.findings import Finding, Severity, Category


def test_finding_to_dict_roundtrip():
    f = Finding(
        id="TEST-1",
        title="Test finding",
        severity=Severity.INFO,
        category=Category.OPS,
        description="desc",
        impact="impact",
        recommendation="rec",
    )
    d = f.to_dict()
    assert d["id"] == "TEST-1"
    assert d["severity"] == "info"