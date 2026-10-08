from abc import ABC, abstractmethod

from webvuln.http_client import HttpClient
from webvuln.models import ScanResult


class ScanModule(ABC):
    """Classe base: cada verificação de segurança herda daqui."""

    name: str = "base"

    def __init__(self, client: HttpClient):
        self.client = client

    @abstractmethod
    def run(self, result: ScanResult) -> None:
        """Executa a verificação e adiciona findings ao resultado."""