import httpx

USER_AGENT = "webvuln-scanner/0.1 (uso educacional)"


class HttpClient:
    def __init__(self, timeout: float = 10.0):
        self._client = httpx.Client(
            timeout=timeout,
            follow_redirects=True,
            headers={"User-Agent": USER_AGENT},
        )

    def get(self, url: str) -> httpx.Response | None:
        try:
            return self._client.get(url)
        except httpx.HTTPError:
            return None

    def close(self) -> None:
        self._client.close()