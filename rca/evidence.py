"""Evidence kind tags for RCA statements."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, Optional


class EvidenceKind(str, Enum):
    OBSERVED = "OBSERVED"
    INFERRED = "INFERRED"
    UNKNOWN = "UNKNOWN"
    NOT_AVAILABLE = "NOT_AVAILABLE"


@dataclass(frozen=True)
class EvidenceItem:
    """One RCA evidence statement with explicit epistemic tag."""

    key: str
    statement: str
    kind: str
    value: Optional[Any] = None
    source: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "key": self.key,
            "statement": self.statement,
            "kind": self.kind,
            "value": self.value,
            "source": self.source,
        }
