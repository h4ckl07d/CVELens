from rich.console import Console
from rich.panel import Panel
from rich.markdown import Markdown
from rich.rule import Rule

console = Console()

def print_header(cve_id: str, score, severity: str, exploited: bool):
    color = "red" if exploited else ("yellow" if severity in ("HIGH", "CRITICAL") else "green")
    console.print(Rule(f"[bold {color}]CVELens Report: {cve_id}[/]"))
    console.print(f"  CVSS: [bold]{score}[/]  |  Severity: [bold {color}]{severity}[/]  |  "
                  f"KEV: [bold {'red' if exploited else 'green'}]{'⚠ EXPLOITED' if exploited else '✓ Not in KEV'}[/]\n")


def print_report(content: str):
    console.print(Markdown(content))


def print_error(message: str):
    console.print(Panel(f"[red]{message}[/red]", title="Error", border_style="red"))