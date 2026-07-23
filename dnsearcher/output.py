from __future__ import annotations
import json

from rich.console import Console
from rich.table import Table

_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
_SEVERITY_STYLE = {
    "critical": "bold red",
    "high": "red",
    "medium": "yellow",
    "low": "cyan",
    "info": "dim",
}


def render_text_report(result: dict, console: Console | None = None) -> None:
    console = console or Console()
    console.print(
        f"\n[bold]{result['domain']}[/bold] \u2014 grade [bold]{result['grade']}[/bold] "
        f"(score {result['score']}/100)\n"
    )

    findings = sorted(result["findings"], key=lambda f: _SEVERITY_ORDER.get(f["severity"], 99))
    if not findings:
        console.print("[green]No findings \u2014 all checks passed.[/green]")
        return

    table = Table(show_lines=False)
    table.add_column("Severity")
    table.add_column("ID")
    table.add_column("Title")
    table.add_column("Recommendation")

    for f in findings:
        style = _SEVERITY_STYLE.get(f["severity"], "")
        table.add_row(
            f"[{style}]{f['severity'].upper()}[/{style}]",
            f["id"],
            f["title"],
            f["recommendation"],
        )
    console.print(table)


def render_json_report(result: dict) -> str:
    return json.dumps(result, indent=2, default=str)