import json

from dnsearcher import cli


def test_build_parser_scan_defaults():
    parser = cli.build_parser()
    args = parser.parse_args(["scan", "example.com"])
    assert args.command == "scan"
    assert args.domain == "example.com"
    assert args.resolver == "1.1.1.1"
    assert args.timeout == 5.0
    assert args.json is False


def test_build_parser_scan_overrides():
    parser = cli.build_parser()
    args = parser.parse_args(
        ["scan", "example.com", "--resolver", "8.8.8.8", "--timeout", "2.5", "--json"]
    )
    assert args.resolver == "8.8.8.8"
    assert args.timeout == 2.5
    assert args.json is True


def test_main_json_output_exit_zero(monkeypatch, capsys):
    async def fake_run_scan(domain, server, timeout):
        return {"domain": domain, "grade": "A", "score": 95, "findings": []}

    monkeypatch.setattr(cli, "_run_scan", fake_run_scan)
    exit_code = cli.main(["scan", "example.com", "--json"])
    captured = capsys.readouterr()
    payload = json.loads(captured.out)

    assert exit_code == 0
    assert payload["grade"] == "A"


def test_main_exits_nonzero_on_critical_finding(monkeypatch, capsys):
    async def fake_run_scan(domain, server, timeout):
        return {
            "domain": domain,
            "grade": "F",
            "score": 10,
            "findings": [
                {
                    "id": "DNS-DOMAIN-AXFR-OPEN",
                    "severity": "critical",
                    "title": "Zone transfer allowed",
                    "recommendation": "Restrict AXFR to authorized secondaries.",
                }
            ],
        }

    monkeypatch.setattr(cli, "_run_scan", fake_run_scan)
    exit_code = cli.main(["scan", "example.com"])
    capsys.readouterr()

    assert exit_code == 2