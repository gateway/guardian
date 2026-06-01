"""Thin database facade that composes schema, inventory, finding, policy, and snapshot storage mixins."""

from __future__ import annotations

import sqlite3
from pathlib import Path

from .db_findings import FindingStoreMixin
from .db_inventory import InventoryStoreMixin
from .db_policy import PolicyStoreMixin
from .db_schema import SCHEMA
from .db_snapshots import SnapshotStoreMixin


class Database(InventoryStoreMixin, FindingStoreMixin, SnapshotStoreMixin, PolicyStoreMixin):
    """Small SQLite coordinator; domain-specific methods live in store mixins."""

    def __init__(self, path: str):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(str(self.path))
        self.conn.row_factory = sqlite3.Row

    def close(self) -> None:
        self.conn.close()

    def initialize(self) -> None:
        self.conn.executescript(SCHEMA)
        self.conn.commit()
