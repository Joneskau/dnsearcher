"""Point-in-time snapshots + diffing (TODO per repo scaffold notes)."""
from __future__ import annotations
from dataclasses import dataclass


@dataclass
class Snapshot:
    domain: str
    taken_at: str
    data: dict


def diff(previous: Snapshot, current: Snapshot) -> dict:
    # TODO: implement structural diff between two snapshots
    raise NotImplementedError