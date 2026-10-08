from webvuln.models import Finding, ScanResult, Severity

from .base import ScanModule

REQUIRED_HEADERS = {
    "Content-Security-Policy": (
        Severity.HIGH,
        "Protege contra XSS controlando quais fontes de conteúdo o navegador pode carregar.",
    ),
    "Strict-Transport-Security": (
        Severity.HIGH,
        "Força o navegador a usar HTTPS, evitando downgrade de conexão.",
    ),
    "X-Frame-Options": (
        Severity.MEDIUM,
        "Impede que a página seja embutida em iframes (clickjacking).",
    ),
    "X-Content-Type-Options": (
        Severity.LOW,
        "Impede que o navegador adivinhe o tipo do conteúdo (MIME sniffing).",
    ),
    "Referrer-Policy": (
        Severity.LOW,
        "Controla quanto de informação de referência é enviada a outros sites.",
    ),
    "Permissions-Policy": (
        Severity.LOW,
        "Restringe o uso de APIs do navegador como câmera e microfone.",
    ),
}


class SecurityHeadersModule(ScanModule):
    name = "security_headers"

    def run(self, result: ScanResult) -> None:
        response = self.client.get(result.target)
        if response is None:
            return

        headers = {k.lower(): v for k, v in response.headers.items()}

        for header, (severity, why) in REQUIRED_HEADERS.items():
            if header.lower() not in headers:
                result.add(Finding(
                    module=self.name,
                    title=f"Header ausente: {header}",
                    severity=severity,
                    description=why,
                    recommendation=f"Configure o servidor para enviar o header {header}.",
                ))

        self._check_cookies(result, headers)

    def _check_cookies(self, result: ScanResult, headers: dict[str, str]) -> None:
        raw_cookies = headers.get("set-cookie", "")
        if not raw_cookies:
            return

        # Nota: split simples por vírgula; parsing completo de Set-Cookie
        # (que pode conter vírgulas em Expires) fica como melhoria futura.
        for cookie in raw_cookies.split(","):
            name = cookie.split("=")[0].strip()
            lowered = cookie.lower()
            missing = [
                flag for flag in ("secure", "httponly", "samesite")
                if flag not in lowered
            ]
            if missing:
                result.add(Finding(
                    module=self.name,
                    title=f"Cookie sem flags de segurança: {name}",
                    severity=Severity.MEDIUM,
                    description=f"Faltam as flags: {', '.join(missing)}.",
                    recommendation="Adicione Secure, HttpOnly e SameSite ao cookie.",
                ))