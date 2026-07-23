from __future__ import annotations
from dataclasses import dataclass, field


@dataclass
class Record:
    name: str
    rtype: str
    value: str
    ttl: int


@dataclass
class RecordSet:
    domain: str
    resolver: str
    records: list[Record] = field(default_factory=list)

    def of_type(self, rtype: str) -> list[Record]:
        return [r for r in self.records if r.rtype == rtype]

    def txt_values(self) -> list[str]:
        return [r.value for r in self.of_type("TXT")]