import typer

from webvuln.scanner import run_scan

app = typer.Typer(help="Scanner de vulnerabilidades web — uso educacional.")

@app.callback()
def main():
    """Scanner de vulnerabilidades web — uso educacional."""

@app.command()
def scan(target: str):
    """Varre o alvo informado (use apenas alvos autorizados)."""
    result = run_scan(target)
    if result is None:
        raise typer.Exit(code=1)
    typer.echo(f"Alvo: {result.target}\n")
    for finding in result.findings:
        typer.echo(f"[{finding.severity.value.upper()}] {finding.title}")
    typer.echo(f"\n{len(result.findings)} achado(s).")


if __name__ == "__main__":
    app()