"""SQLite schema for Guardian local state, scan snapshots, findings, and remediation data."""

from __future__ import annotations

"""SQLite schema for Guardian's local state database."""


SCHEMA = """
PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS inventory_runs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  started_at TEXT NOT NULL,
  completed_at TEXT,
  root_path TEXT NOT NULL,
  profile TEXT NOT NULL,
  source TEXT NOT NULL,
  ndjson_path TEXT,
  status TEXT NOT NULL,
  package_count INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS inventory_packages (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  run_id INTEGER NOT NULL REFERENCES inventory_runs(id) ON DELETE CASCADE,
  ecosystem TEXT NOT NULL,
  package_name TEXT NOT NULL,
  normalized_name TEXT NOT NULL,
  version TEXT NOT NULL,
  project_path TEXT,
  source_file TEXT,
  source_type TEXT,
  package_manager TEXT,
  root_kind TEXT,
  confidence TEXT,
  direct_dependency INTEGER,
  install_scope TEXT,
  raw_json TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_inventory_packages_run ON inventory_packages(run_id);
CREATE INDEX IF NOT EXISTS idx_inventory_packages_lookup ON inventory_packages(ecosystem, normalized_name, version);

CREATE TABLE IF NOT EXISTS package_state (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  root_path TEXT NOT NULL,
  ecosystem TEXT NOT NULL,
  package_name TEXT NOT NULL,
  normalized_name TEXT NOT NULL,
  version TEXT NOT NULL,
  project_path TEXT,
  source_file TEXT,
  source_type TEXT,
  package_manager TEXT,
  root_kind TEXT,
  confidence TEXT,
  direct_dependency INTEGER,
  install_scope TEXT,
  first_seen_at TEXT NOT NULL,
  last_seen_at TEXT NOT NULL,
  present INTEGER NOT NULL DEFAULT 1,
  last_run_id INTEGER REFERENCES inventory_runs(id) ON DELETE SET NULL,
  raw_json TEXT NOT NULL,
  UNIQUE(root_path, ecosystem, normalized_name, version, source_file)
);

CREATE INDEX IF NOT EXISTS idx_package_state_lookup ON package_state(present, ecosystem, normalized_name, version);

CREATE TABLE IF NOT EXISTS advisories (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  source TEXT NOT NULL,
  advisory_id TEXT NOT NULL,
  summary TEXT,
  severity TEXT,
  details_url TEXT,
  aliases_json TEXT,
  published_at TEXT,
  updated_at TEXT,
  withdrawn_at TEXT,
  raw_json TEXT NOT NULL,
  first_seen_at TEXT NOT NULL,
  last_seen_at TEXT NOT NULL,
  UNIQUE(source, advisory_id)
);

CREATE TABLE IF NOT EXISTS findings (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ecosystem TEXT NOT NULL,
  package_name TEXT NOT NULL,
  normalized_name TEXT NOT NULL,
  version TEXT NOT NULL,
  advisory_source TEXT NOT NULL,
  advisory_id TEXT NOT NULL,
  severity TEXT,
  details_url TEXT,
  evidence TEXT NOT NULL,
  status TEXT NOT NULL,
  first_seen_at TEXT NOT NULL,
  last_seen_at TEXT NOT NULL,
  resolved_at TEXT,
  UNIQUE(normalized_name, version, advisory_source, advisory_id)
);

CREATE INDEX IF NOT EXISTS idx_findings_status ON findings(status, severity);

CREATE TABLE IF NOT EXISTS triage_snapshots (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  created_at TEXT NOT NULL,
  root_path TEXT NOT NULL,
  inventory_run_ids_json TEXT NOT NULL,
  headline TEXT,
  report_path TEXT,
  summary_json TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_triage_snapshots_root_created
ON triage_snapshots(root_path, created_at DESC);

CREATE TABLE IF NOT EXISTS triage_snapshot_packages (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  snapshot_id INTEGER NOT NULL REFERENCES triage_snapshots(id) ON DELETE CASCADE,
  ecosystem TEXT NOT NULL,
  package_name TEXT NOT NULL,
  normalized_name TEXT NOT NULL,
  version TEXT NOT NULL,
  risk_label TEXT,
  highest_severity TEXT,
  advisory_count INTEGER NOT NULL DEFAULT 0,
  role_label TEXT,
  environment_label TEXT,
  recommended_clean_version TEXT,
  first_fixed_version TEXT,
  issue_keys_json TEXT NOT NULL,
  classification_labels_json TEXT NOT NULL,
  notes_json TEXT NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_triage_snapshot_packages_key
ON triage_snapshot_packages(snapshot_id, ecosystem, normalized_name, version);

CREATE TABLE IF NOT EXISTS policy_exceptions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ecosystem TEXT NOT NULL,
  normalized_name TEXT NOT NULL,
  version TEXT,
  advisory_source TEXT,
  canonical_key TEXT,
  action TEXT NOT NULL,
  reason TEXT NOT NULL,
  created_at TEXT NOT NULL,
  expires_at TEXT,
  created_by TEXT,
  active INTEGER NOT NULL DEFAULT 1
);

CREATE INDEX IF NOT EXISTS idx_policy_exceptions_lookup
ON policy_exceptions(active, ecosystem, normalized_name, version);

CREATE TABLE IF NOT EXISTS remediation_items (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  root_path TEXT NOT NULL,
  ecosystem TEXT NOT NULL,
  package_name TEXT NOT NULL,
  normalized_name TEXT NOT NULL,
  version TEXT NOT NULL,
  issue_key TEXT NOT NULL,
  status TEXT NOT NULL,
  risk_label TEXT,
  highest_severity TEXT,
  environment_label TEXT,
  first_seen_snapshot_id INTEGER REFERENCES triage_snapshots(id) ON DELETE SET NULL,
  last_seen_snapshot_id INTEGER REFERENCES triage_snapshots(id) ON DELETE SET NULL,
  resolved_snapshot_id INTEGER REFERENCES triage_snapshots(id) ON DELETE SET NULL,
  first_seen_at TEXT NOT NULL,
  last_seen_at TEXT NOT NULL,
  resolved_at TEXT,
  reintroduced_count INTEGER NOT NULL DEFAULT 0,
  resolution_summary TEXT,
  raw_json TEXT NOT NULL,
  UNIQUE(root_path, ecosystem, normalized_name, version, issue_key)
);

CREATE INDEX IF NOT EXISTS idx_remediation_items_root_status
ON remediation_items(root_path, status, last_seen_at DESC);

CREATE TABLE IF NOT EXISTS remediation_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  item_id INTEGER NOT NULL REFERENCES remediation_items(id) ON DELETE CASCADE,
  event_type TEXT NOT NULL,
  created_at TEXT NOT NULL,
  snapshot_id INTEGER REFERENCES triage_snapshots(id) ON DELETE SET NULL,
  summary TEXT NOT NULL,
  raw_json TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_remediation_events_item_created
ON remediation_events(item_id, created_at DESC);
"""
