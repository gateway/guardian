#!/usr/bin/env python3
"""Offline HTML report contract: scope, escaping, evidence and explicit writes."""

import copy
from html.parser import HTMLParser
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

REPO = Path(__file__).resolve().parents[1]
PLUGIN = REPO / "plugins/guardian-security-scan"
sys.dont_write_bytecode = True
sys.path.insert(0, str(PLUGIN / "guardian_runtime/src"))
from guardian import trust_audit
from guardian.trust_audit_html import render_html
from guardian.trust_audit_presentation import evidence_rows, handoff


class Document(HTMLParser):
    def __init__(self, content):
        super().__init__()
        self.rows, self.ids, self.links, self.scripts, self.resources = (
            [],
            [],
            [],
            [],
            [],
        )
        self.feed(content)

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if "id" in attrs:
            self.ids.append(attrs["id"])
        if "data-evidence" in attrs:
            self.rows.append(attrs["data-evidence"])
        if tag == "a":
            self.links.append(attrs.get("href"))
        if tag == "script":
            self.scripts.append(attrs)
        if "src" in attrs or tag == "link":
            self.resources.append(attrs)


class HtmlReportTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.env = self.root / "project/.venv"
        self.site = self.env / "lib/python3.9/site-packages"
        metadata = self.site / "pip-26.0.1.dist-info/METADATA"
        metadata.parent.mkdir(parents=True)
        metadata.write_text("Name: pip\nVersion: 26.0.1\n")
        (self.env / "pyvenv.cfg").write_text("version = 3.9.6\n")
        bundle = self.site / "pip/_vendor/certifi/cacert.pem"
        bundle.parent.mkdir(parents=True)
        bundle.write_bytes(
            (REPO / "tests/fixtures/trust-audit/emsign-g3.pem").read_bytes()
        )
        with (
            patch.object(trust_audit, "known_locations", return_value=([], [])),
            patch.object(trust_audit, "known_node_locations", return_value=[]),
        ):
            self.report = trust_audit.audit(str(self.root / "project"))

    def test_each_item_once_and_payload_unchanged(self):
        original = copy.deepcopy(self.report)
        page = render_html(self.report)
        doc = Document(page)
        self.assertEqual(len(doc.rows), len(self.report["items"]))
        self.assertEqual(len(doc.rows), len(set(doc.rows)))
        self.assertEqual(len(doc.ids), len(set(doc.ids)))
        self.assertEqual(self.report, original)
        self.assertIn('id="view-project"', page)
        self.assertIn('id="view-machine"', page)
        self.assertIn('id="view-release"', page)
        self.assertIn("Not assessed", page)
        self.assertIn("No latest-version lookup", page)
        self.assertIn("replacement Python environment", page)
        self.assertIn("Shares a package-update route", page)
        self.assertEqual(len(doc.scripts), 1)
        self.assertEqual(doc.resources, [])
        self.assertTrue(all(url.startswith("https://") for url in doc.links))
        self.assertIn("Content-Security-Policy", page)
        self.assertIn("sha256-", page)

    def test_root_overlap_and_shared_environment_do_not_imply_app_use(self):
        self.report["roots"] = [
            str(self.root),
            str(self.env),
            str(self.root / "other-project"),
        ]
        rows = evidence_rows(self.report)
        packages = [row for row in rows if row["item"]["kind"] == "package"]
        self.assertEqual(packages[0]["root"], str(self.env))
        prompt = handoff(self.report, str(self.root / "other-project"), "project")
        self.assertIn(str(self.root / "other-project"), prompt)
        self.assertNotIn(str(self.site), prompt)
        self.assertIn("does not prove application ownership", prompt)
        self.assertIn("NOT ASSESSED", handoff(self.report, str(self.env), "release"))

    def test_untrusted_text_and_links_cannot_create_markup(self):
        attack = '</textarea><img src="https://example.test/pixel" onerror="alert(1)"><script>alert(1)</script>'
        self.report["items"][0]["path"] = attack
        self.report["items"][0]["reason"] = attack
        self.report["roots"].append(attack)
        self.report["evidence"]["sources"] += [
            "javascript:alert(1)",
            "data:text/html,test",
            'https://example.test/" onclick="alert(1)',
            "https://user:password@example.test/",
        ]
        page = render_html(self.report)
        doc = Document(page)
        self.assertNotIn(attack, page)
        self.assertEqual(len(doc.scripts), 1)
        self.assertEqual(doc.resources, [])
        self.assertFalse(
            any(url.startswith(("javascript:", "data:")) for url in doc.links)
        )
        self.assertNotIn('href="https://user:password', page)
        self.assertIn("&lt;/textarea&gt;", page)

    def test_no_roots_defaults_to_machine_and_keeps_unknowns(self):
        self.report["roots"] = []
        page = render_html(self.report)
        self.assertIn('data-initial-view="machine"', page)
        self.assertIn("No development roots selected", page)
        self.assertIn("Not verified", page)
        self.assertEqual(len(Document(page).rows), len(self.report["items"]))

    def test_snapshot_recommendations_and_unknown_metadata(self):
        self.report["items"].append(
            {
                "kind": "node_runtime",
                "path": "/tools/bin/node",
                "version": "25.6.1",
                "status": "review_candidate",
                "reason": "Fingerprint matched",
            }
        )
        rows = evidence_rows(self.report)
        self.assertIn("No verified fix for this major", rows[-1]["action"])
        # Ambiguous pip metadata must not attach an invented interpreter recommendation.
        duplicate = copy.deepcopy(
            next(i for i in self.report["items"] if i["kind"] == "package")
        )
        duplicate["version"] = "24.0"
        self.report["items"].append(duplicate)
        bundle = next(
            r for r in evidence_rows(self.report) if r["item"]["kind"] == "bundle"
        )
        self.assertIsNone(bundle["related_package"])

    def test_newer_metadata_with_matching_bundle_does_not_recommend_downgrade(self):
        package = next(i for i in self.report["items"] if i["kind"] == "package")
        package["version"] = "26.2.3"
        package["status"] = "no_matching_findings"
        row = next(
            r for r in evidence_rows(self.report) if r["item"]["kind"] == "bundle"
        )
        self.assertIn("Verify installation provenance", row["action"])
        self.assertNotIn("to the snapshot recommendation", row["action"])
        self.report["items"].append(
            {
                "kind": "node_runtime",
                "path": "/tools/node",
                "version": "24.22.2",
                "status": "review_candidate",
                "version_status": "no_matching_findings",
                "fixed_version": "24.22.1",
                "reason": "Embedded fingerprint match",
            }
        )
        self.assertIn(
            "Verify binary/library provenance", evidence_rows(self.report)[-1]["action"]
        )

    def test_handoff_retains_incomplete_discovery_and_unverified_evidence(self):
        root = self.report["roots"][0]
        self.report["discovery"][0]["complete"] = False
        self.report["items"].append(
            {
                "kind": "discovery",
                "path": root,
                "status": "unverified",
                "reason": "Discovery stopped at configured directory limit",
            }
        )
        prompt = handoff(self.report, root, "project")
        self.assertIn('"complete": false', prompt)
        self.assertIn('"status": "unverified"', prompt)
        self.assertIn("Discovery stopped at configured directory limit", prompt)

    def test_cli_only_writes_requested_html_and_preserves_json(self):
        output = self.root / "report.HTML"
        state = self.root / "guardian-state"
        import os

        env = dict(os.environ, GUARDIAN_STATE_DIR=str(state))
        command = [
            str(PLUGIN / "bin/guardian"),
            "trust-audit",
            "--root",
            str(self.env),
            "--json",
            "--output",
            str(output),
        ]
        before = sorted(str(p.relative_to(self.root)) for p in self.root.rglob("*"))
        result = subprocess.run(
            command, env=env, capture_output=True, text=True, check=False
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(result.stdout)
        self.assertEqual(report["schema_version"], 2)
        self.assertNotIn("handoffs", report)
        self.assertTrue(output.read_text().startswith("<!doctype html>"))
        self.assertFalse(state.exists())
        after = sorted(str(p.relative_to(self.root)) for p in self.root.rglob("*"))
        self.assertEqual(after, sorted(before + ["report.HTML"]))
        saved = output.read_bytes()
        again = subprocess.run(
            command, env=env, capture_output=True, text=True, check=False
        )
        self.assertEqual(again.returncode, 2)
        self.assertEqual(output.read_bytes(), saved)


if __name__ == "__main__":
    unittest.main()
