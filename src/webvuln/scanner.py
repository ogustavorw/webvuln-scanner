import typer

from webvuln.http_client import HttpClient
from webvuln.models import ScanResult
from webvuln.modules.security_headers import SecurityHeadersModule


def run_scan(target: str) -> ScanResult | None:
    client = HttpClient()

    try:
        # Verificação prévia: o alvo está acessível?
        response = client.get(target)
        if response is None:
            typer.echo(
                f"⚠️  Não foi possível conectar ao alvo: {target}\n"
                "   Verifique a URL e o esquema (http:// ou https://)."
            )
            return None

        result = ScanResult(target=target)
        modules = [SecurityHeadersModule(client)]
        for module in modules:
            module.run(result)
    finally:
        client.close()

    return result