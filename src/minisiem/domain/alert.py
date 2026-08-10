"""Contratos de domínio para alertas gerados por detecção."""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any
from uuid import uuid4


@dataclass(frozen=True, slots=True)
class Alert:
    """Resultado de uma regra de detecção aplicada a eventos."""

    rule_id: str
    title: str
    severity: str
    created_at: datetime
    event_ids: tuple[str, ...]
    context: dict[str, Any] = field(default_factory=dict)
    id: str = field(default_factory=lambda: str(uuid4()))

    def __post_init__(self) -> None:
        if not self.event_ids:
            raise ValueError("um alerta precisa referenciar ao menos um evento")
