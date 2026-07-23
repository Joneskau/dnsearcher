from __future__ import annotations
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Category(str, Enum):
    EMAIL = "email_security"
    DOMAIN = "domain_security"
    OPS = "operational_health"


@dataclass
class Evidence:
    queried_name: str
    record_type: str
    record: str
    resolver: str
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )


@dataclass
class Finding:
    id: str
    title: str
    severity: Severity
    category: Category
    description: str
    impact: str
    recommendation: str
    evidence: Evidence | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)