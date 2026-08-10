"""Contratos de domínio para eventos de segurança."""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any
from uuid import uuid4


@dataclass(frozen=True, slots=True)
class Event:
    """Um evento normalizado, independente do formato original do log."""

    timestamp: datetime
    source: str
    host: str
    event_type: str
    raw_message: str
    fields: dict[str, Any] = field(default_factory=dict)
    id: str = field(default_factory=lambda: str(uuid4()))

    def __post_init__(self) -> None:
        for name in ("source", "host", "event_type", "raw_message"):
            if not getattr(self, name).strip():
                raise ValueError(f"{name} não pode ser vazio")

        if self.timestamp.tzinfo is None or self.timestamp.utcoffset() is None:
            raise ValueError("timestamp deve incluir fuso horário")
