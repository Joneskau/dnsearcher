from __future__ import annotations
import argparse
import asyncio
import sys

from .resolver import LiveResolver, resolve_all
from .analysis.posture import run_posture
from .output import render_json_report, render_text_report


async def _run_scan(domain: str, server: str, timeout: float) -> dict:
    resolver = LiveResolver(server=server, timeout=timeout)
    rs = await resolve_all(resolver, domain)
    dmarc_records = await resolver.query(f"_dmarc.{domain}", "TXT")
    dmarc_txt = next(
        (r.value for r in dmarc_records if r.value.lower().startswith("v=dmarc1")),
        None,
    )
    return await run_posture(rs, dmarc_txt, resolver)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="dnsearcher",
        description="From DNS records to DNS intelligence.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan = subparsers.add_parser("scan", help="Run a posture scan against a domain.")
    scan.add_argument("domain", help="Domain to scan, e.g. example.com")
    scan.add_argument(
        "--resolver", default="1.1.1.1", help="Resolver IP to query (default: 1.1.1.1)"
    )
    scan.add_argument(
        "--timeout", type=float, default=5.0, help="Per-query timeout in seconds (default: 5.0)"
    )
    scan.add_argument(
        "--json", action="store_true", help="Output raw JSON instead of a formatted report"
    )

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "scan":
        result = asyncio.run(_run_scan(args.domain, args.resolver, args.timeout))
        if args.json:
            print(render_json_report(result))
        else:
            render_text_report(result)
        # Non-zero exit on CRITICAL findings so CI/cron jobs can alert.
        if any(f["severity"] == "critical" for f in result["findings"]):
            return 2
        return 0

    parser.print_help()
    return 1


if __name__ == "__main__":
    sys.exit(main())