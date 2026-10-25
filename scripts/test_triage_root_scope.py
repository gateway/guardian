#!/usr/bin/env python3
"""A shared package must not borrow another project's runtime evidence."""

import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

REPO = Path(__file__).resolve().parents[1]
sys.dont_write_bytecode = True
sys.path.insert(0, str(REPO / "plugins/guardian-security-scan/guardian_runtime/src"))

from guardian.config import GuardianConfig
from guardian.db import Database
from guardian.inventory import scan_roots
from guardian.triage import enriched_issues


class RootScopeTests(unittest.TestCase):
    def test_dev_dependency_does_not_inherit_other_repo_runtime_role(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name).resolve()
        config = GuardianConfig(db_path=str(root / "state/db.sqlite"), scans_dir=str(root / "state/scans"))
        db = Database(config.db_path)
        self.addCleanup(db.close)
        db.initialize()
        projects = []
        for name, scope in (("dev-project", "devDependencies"), ("runtime-project", "dependencies")):
            project = root / name
            project.mkdir()
            (project / "package.json").write_text(json.dumps({"name": name, scope: {"undici": "7.29.0"}}))
            projects.append(str(project))
        scan_roots(config, db, projects, ecosystems=["npm"])
        issue = {"canonical_key": "fixture-advisory", "severity": "high", "summary": "Fixture issue",
                 "aliases": [], "urls": [], "packages": [
                     {"ecosystem": "npm", "package_name": "undici", "normalized_name": "undici", "version": "7.29.0"}]}
        # No npm subprocess or network is needed for project role attribution.
        with patch("guardian.triage_context.npm_explain_summary", return_value=None):
            scoped = enriched_issues(config, db, [issue], root_filter=projects[0], resolve_clean_targets=False)
            global_result = enriched_issues(config, db, [issue], resolve_clean_targets=False)
        package = scoped[0]["packages"][0]
        self.assertEqual(package["root_paths"], [projects[0]])
        self.assertEqual(package["role"], "test-only")
        self.assertTrue(all(p.startswith(projects[0]) for p in package["manifest_paths"]))
        self.assertEqual(set(global_result[0]["packages"][0]["root_paths"]), set(projects))


if __name__ == "__main__":
    unittest.main()
