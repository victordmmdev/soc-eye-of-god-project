"""Leitura de arquivos de log textuais produzidos em sistemas Linux."""

from collections.abc import Iterator
from pathlib import Path


class LinuxLogFileReader:
    """Expõe cada linha não vazia de um arquivo de log como mensagem bruta."""

    def __init__(self, path: Path) -> None:
        self.path = path

    def read(self) -> Iterator[str]:
        with self.path.open(encoding="utf-8", errors="replace") as log_file:
            for line in log_file:
                message = line.rstrip("\n")
                if message.strip():
                    yield message
