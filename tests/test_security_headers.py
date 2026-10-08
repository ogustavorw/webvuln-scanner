from webvuln.models import ScanResult
from webvuln.modules.security_headers import SecurityHeadersModule


class FakeResponse:
    def __init__(self, headers):
        self.headers = headers


class FakeClient:
    """Duck typing: expõe só o que o módulo usa (método get)."""

    def __init__(self, headers):
        self.headers = headers

    def get(self, url):
        return FakeResponse(self.headers)


def test_detecta_headers_ausentes():
    module = SecurityHeadersModule(client=FakeClient({"content-type": "text/html"}))
    result = ScanResult(target="http://alvo.local")
    module.run(result)

    titles = [f.title for f in result.findings]
    assert any("Content-Security-Policy" in t for t in titles)
    assert any("Strict-Transport-Security" in t for t in titles)


def test_sem_finding_quando_tudo_presente():
    headers = {h.lower(): "ok" for h in [
        "Content-Security-Policy", "Strict-Transport-Security",
        "X-Frame-Options", "X-Content-Type-Options",
        "Referrer-Policy", "Permissions-Policy",
    ]}
    module = SecurityHeadersModule(client=FakeClient(headers))
    result = ScanResult(target="http://alvo.local")
    module.run(result)

    assert result.findings == []