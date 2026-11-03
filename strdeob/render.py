"""Human-readable rendering of a deobfuscation report."""

from __future__ import annotations

from rich.console import Console
from rich.table import Table
from rich.text import Text

from .core import DeobReport

_GREEN = "#3fb950"
_DIM = "grey62"
_WARN = "#d29922"
_MAX_CELL = 80


def _clip(value: str, limit: int = _MAX_CELL) -> str:
    return value if len(value) <= limit else value[: limit - 1] + "…"


def render(report: DeobReport, console: Console) -> None:
    """Print ``report`` to ``console`` as dark, terminal-styled tables."""
    header = Text()
    header.append("strdeob ", style=f"bold {_GREEN}")
    header.append(report.path, style="bold")
    header.append(f"  ({report.size} bytes)", style=_DIM)
    console.print(header)

    if report.decodings:
        console.print()
        table = Table(title="decodings", title_style=f"bold {_GREEN}", title_justify="left")
        table.add_column("method", style=_WARN)
        table.add_column("value")
        for item in report.decodings:
            table.add_row(item["method"], _clip(item["value"]))
        console.print(table)

    if report.xor:
        console.print()
        table = Table(title="xor keys", title_style=f"bold {_WARN}", title_justify="left")
        table.add_column("key", style=_WARN)
        table.add_column("len", justify="right", style=_DIM)
        table.add_column("recovered")
        for hit in report.xor:
            recovered = ", ".join(i["value"] for i in hit["iocs"]) or ", ".join(hit["strings"][:5])
            table.add_row(hit["key"], str(hit["keylen"]), _clip(recovered))
        console.print(table)

    if report.stacked:
        console.print()
        table = Table(title="stacked strings", title_style=f"bold {_GREEN}", title_justify="left")
        table.add_column("value")
        for item in report.stacked:
            table.add_row(_clip(item["value"]))
        console.print(table)

    if report.iocs:
        console.print()
        table = Table(title="iocs", title_style=f"bold {_GREEN}", title_justify="left")
        table.add_column("category", style=_DIM)
        table.add_column("value")
        for item in report.iocs:
            table.add_row(item["category"], _clip(item["value"]))
        console.print(table)

    if not report.is_interesting:
        console.print(Text("\nno obfuscated content or IOCs recovered", style=_DIM))
