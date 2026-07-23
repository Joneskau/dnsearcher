from __future__ import annotations
import argparse


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="dnsearcher", description="From DNS records to DNS intelligence."
    )
    parser.add_argument("domain", help="Domain to analyze")
    args = parser.parse_args()
    # TODO: wire up resolver.resolve_all + analysis.posture.run_posture + reporting
    print(f"TODO: analyze {args.domain}")


if __name__ == "__main__":
    main()