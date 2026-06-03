from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.columns import Columns
from rich.text import Text
from rich.rule import Rule
from rich.align import Align
from rich import box

console = Console()

# ─────────────────────────────────────────────
#  BANNER
# ─────────────────────────────────────────────

BANNER = r"""
  ██████╗██╗   ██╗███████╗██╗     ███████╗███╗   ██╗███████╗
 ██╔════╝██║   ██║██╔════╝██║     ██╔════╝████╗  ██║██╔════╝
 ██║     ██║   ██║█████╗  ██║     █████╗  ██╔██╗ ██║███████╗
 ██║     ╚██╗ ██╔╝██╔══╝  ██║     ██╔══╝  ██║╚██╗██║╚════██║
 ╚██████╗ ╚████╔╝ ███████╗███████╗███████╗██║ ╚████║███████║
  ╚═════╝  ╚═══╝  ╚══════╝╚══════╝╚══════╝╚═╝  ╚═══╝╚══════╝
"""

TAGLINE = "Vulnerability Intelligence Engine  |  Powered by Groq × GPT-OSS-120B"
VERSION = "v1.0.0"


def print_banner():
    console.print()
    console.print(Align.center(Text(BANNER, style="bold cyan")))
    console.print(Align.center(Text(TAGLINE, style="dim white")))
    console.print(Align.center(Text(VERSION, style="dim cyan")))
    console.print()


# ─────────────────────────────────────────────
#  METADATA HEADER CARD
# ─────────────────────────────────────────────

def print_header(cve_id: str, score, severity: str, exploited: bool, published: str = ""):
    severity = severity or "UNKNOWN"

    # Severity color
    if severity in ("CRITICAL",):
        sev_color = "bold red"
    elif severity == "HIGH":
        sev_color = "bold orange1"
    elif severity == "MEDIUM":
        sev_color = "bold yellow"
    else:
        sev_color = "bold green"

    kev_badge = "[bold red]⚠  ACTIVELY EXPLOITED (CISA KEV)[/]" if exploited else "[bold green]✓  Not in CISA KEV[/]"

    # Build metadata table
    table = Table(box=box.SIMPLE, show_header=False, padding=(0, 2))
    table.add_column(style="dim white", no_wrap=True)
    table.add_column(style="white")

    table.add_row("CVE ID",     f"[bold white]{cve_id}[/]")
    table.add_row("CVSS Score", f"[{sev_color}]{score}[/]")
    table.add_row("Severity",   f"[{sev_color}]{severity}[/]")
    table.add_row("KEV Status", kev_badge)
    if published:
        table.add_row("Published",  published[:10])

    console.print(Panel(
        table,
        title=f"[bold cyan][ {cve_id} ][/]",
        border_style="cyan",
        padding=(1, 2)
    ))
    console.print()


# ─────────────────────────────────────────────
#  SECTION RENDERER
# ─────────────────────────────────────────────

SECTION_STYLES = {
    "executive summary":       ("📋", "cyan",    "bold cyan"),
    "technical classification":("🔬", "blue",    "bold blue"),
    "cvss interpretation":     ("📊", "yellow",  "bold yellow"),
    "affected surface":        ("🎯", "magenta", "bold magenta"),
    "attack preconditions":    ("⚙ ", "orange1", "bold orange1"),
    "exploit mechanics":       ("💥", "red",     "bold red"),
    "exploit logic":           ("🧪", "red",     "bold red"),
    "impact analysis":         ("🔥", "red",     "bold red"),
    "mitigation & remediation":("🛡 ", "green",  "bold green"),
    "threat intelligence":     ("🕵 ", "cyan",   "bold cyan"),
}

DEFAULT_STYLE = ("📌", "white", "bold white")


def _get_style(heading: str):
    key = heading.lower().strip()
    for k, v in SECTION_STYLES.items():
        if k in key:
            return v
    return DEFAULT_STYLE


def render_sections(raw_text: str):
    """
    Parse the streamed report text into sections and render
    each as a styled Rich panel.
    """
    import re

    # Split on markdown headings ## or ###
    parts = re.split(r'\n(?=#{1,3} )', raw_text.strip())

    for part in parts:
        part = part.strip()
        if not part:
            continue

        lines = part.splitlines()
        heading_line = lines[0].lstrip("#").strip()
        body = "\n".join(lines[1:]).strip()

        if not body:
            continue

        icon, border, title_style = _get_style(heading_line)
        title = f"{icon}  [{title_style}]{heading_line}[/]"

        # Render body — clean up markdown bold (**text**) for Rich
        body = re.sub(r'\*\*(.*?)\*\*', r'[bold]\1[/bold]', body)
        body = re.sub(r'\*(.*?)\*',   r'[italic]\1[/italic]', body)
        # Code blocks — keep as-is, Rich handles backtick blocks
        body = re.sub(r'`([^`]+)`', r'[bold yellow]\1[/bold yellow]', body)

        console.print(Panel(
            body,
            title=title,
            border_style=border,
            padding=(1, 2),
        ))
        console.print()


# ─────────────────────────────────────────────
#  STATUS + ERROR
# ─────────────────────────────────────────────

def print_status(message: str):
    console.print(f"  [dim cyan]→[/]  {message}")


def print_error(message: str):
    console.print(Panel(
        f"[red]{message}[/red]",
        title="[bold red]✖  Error[/]",
        border_style="red"
    ))


def print_done(cve_id: str):
    console.print(Rule(f"[dim]CVELens report complete — {cve_id}[/dim]"))
    console.print()