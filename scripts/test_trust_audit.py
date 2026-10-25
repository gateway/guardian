#!/usr/bin/env python3
"""Offline fixtures and read-only contract for trust-audit (stdlib only)."""
import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import ssl
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

REPO = Path(__file__).resolve().parents[1]
PLUGIN = REPO / "plugins/guardian-security-scan"
sys.dont_write_bytecode = True
sys.path.insert(0, str(PLUGIN / "guardian_runtime/src"))
from guardian import cli, trust_audit as audit
from guardian import trust_audit_node as node_audit

FIXTURE = REPO / "tests/fixtures/trust-audit/emsign-g3.pem"


class TrustAuditTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.evidence = json.loads(audit.EVIDENCE_PATH.read_text())
        # Unit fixtures must not depend on this machine's installed tools.
        for target, value in (("known_locations", ([], [])), ("known_node_locations", [])):
            patcher = patch.object(audit, target, return_value=value)
            patcher.start()
            self.addCleanup(patcher.stop)

    def write(self, path, text):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
        return path

    def environment(self, name="project/nested/.custom-env"):
        env = self.root / name
        self.write(env / "pyvenv.cfg", "include-system-site-packages = false\n")
        site = env / "lib/python3.12/site-packages"
        site.mkdir(parents=True)
        return env, site

    def metadata(self, site, name, version):
        return self.write(site / f"{name}-{version}.dist-info/METADATA", f"Name: {name}\nVersion: {version}\n")

    def test_verified_fingerprint(self):
        der = ssl.PEM_cert_to_DER_cert(FIXTURE.read_text())
        self.assertEqual(hashlib.sha256(der).hexdigest(), self.evidence["certificates"][0]["sha256"])
        item = audit.inspect_bundle(FIXTURE, self.evidence)
        self.assertEqual(item["status"], "review_candidate")

    def test_no_subject_string_matching(self):
        path = self.write(self.root / "fake.pem", "# emSign ECC Root CA - G3\n")
        self.assertEqual(audit.inspect_bundle(path, self.evidence)["status"], "unverified")
        # Another emSign root is not automatically an incident match.
        path.write_text("# emSign ECC Root CA - G3\n" + FIXTURE.with_name("emsign-g1-unaffected.pem").read_text())
        self.assertEqual(audit.inspect_bundle(path, self.evidence)["status"], "no_matching_findings")

    def test_malformed_missing_large_and_special_bundles(self):
        for text in ("", "-----BEGIN CERTIFICATE-----\n???\n-----END CERTIFICATE-----"):
            path = self.write(self.root / "bad.pem", text)
            self.assertEqual(audit.inspect_bundle(path, self.evidence)["status"], "unverified")
        self.assertEqual(audit.inspect_bundle(self.root / "missing", self.evidence)["status"], "unverified")
        path.write_bytes(b"x" * (audit.MAX_BYTES + 1))
        self.assertEqual(audit.inspect_bundle(path, self.evidence)["status"], "unverified")
        fifo = self.root / "fifo"
        os.mkfifo(fifo)
        self.assertEqual(audit.inspect_bundle(fifo, self.evidence)["status"], "unverified")
        with patch.object(audit, "read_file", side_effect=PermissionError("fixture denied")):
            self.assertEqual(audit.inspect_bundle(path, self.evidence)["status"], "unverified")

    def test_package_boundaries(self):
        for name, version, expected in (
            ("certifi", "2018.1.1", "no_matching_findings"),
            ("certifi", "2019.3.9", "review_candidate"),
            ("certifi", "2026.10.17", "review_candidate"),
            ("certifi", "2026.10.18", "no_matching_findings"),
            ("certifi", "2026.10.19", "no_matching_findings"),
            ("pip", "26.2.1", "review_candidate"),
            ("pip", "26.2.2", "no_matching_findings"),
            ("pip", "26.2.2rc1", "unverified"),
            ("pip", "24.0", "review_candidate"),
            ("pip", "9" * 1000 + ".0", "unverified"),
            ("requests", "2.32.0", "unverified"),
        ):
            with self.subTest(name=name, version=version):
                item = audit.inspect_package({"normalized_name": name, "version": version, "source_file": "fixture"}, self.evidence)
                self.assertEqual(item["status"], expected)

    def test_multiple_roots_deduplicate_and_exclude(self):
        first, site = self.environment("one/.env")
        second, _ = self.environment("two/custom")
        self.environment("two/cache/ignored")
        self.metadata(site, "certifi", "2026.10.23")
        report = audit.audit([str(self.root / "one"), str(first), str(self.root / "two")], excludes=["cache"])
        self.assertEqual(report["environments"], [str(first), str(second)])
        self.assertEqual(len([i for i in report["items"] if i.get("name") == "certifi"]), 1)
        self.assertEqual(len(report["environment_details"][0]["roots"]), 2)
        self.assertGreater(report["discovery"][2]["skipped_directories"], 0)
        with self.assertRaises(ValueError):
            audit.audit([str(first), str(self.root / "missing")])
        with self.assertRaises(ValueError):
            audit.audit(str(first), excludes=["../bad"])

    def test_interpreter_compatibility(self):
        env, site = self.environment()
        (env / "pyvenv.cfg").write_text("version = 3.9.6\ninclude-system-site-packages = false\n")
        self.metadata(site, "pip", "26.0.1")
        self.metadata(site, "httpx", "0.28.1")
        report = audit.audit(str(env))
        pip = next(i for i in report["items"] if i.get("name") == "pip")
        self.assertEqual(pip["recommendation_compatibility"], "incompatible")
        self.assertEqual(pip["environment"], str(env))
        self.assertIn("do not apply", pip["reason"])
        self.assertIn("compatibility: incompatible", audit.render_report(report))
        self.assertTrue(any(i.get("name") == "httpx" for i in report["items"]))
        record = {"normalized_name": "pip", "version": "26.0.1", "source_file": "fixture"}
        self.assertEqual(audit.inspect_package(record, self.evidence, "3.10.0")["recommendation_compatibility"], "compatible")
        self.assertEqual(audit.inspect_package(record, self.evidence)["recommendation_compatibility"], "unknown")
        (env / "pyvenv.cfg").write_bytes(b"\xff")
        self.assertIn("error", audit.audit(str(env))["environment_details"][0])

    def test_absent_optional_vs_missing_owned_bundle(self):
        env, site = self.environment()
        self.metadata(site, "certifi", "2026.10.23")
        absent = self.root / "optional.pem"
        with patch.object(audit.sys, "platform", "darwin"), patch.object(audit, "known_locations", return_value=([absent], [])):
            report = audit.audit(str(env))
        self.assertEqual(report["absent_optional_locations"], [str(absent)])
        self.assertFalse(any(i["path"] == str(absent) for i in report["items"]))
        self.assertTrue(any(i["path"].endswith("certifi/cacert.pem") and i["status"] == "unverified" for i in report["items"]))

    def node_installation(self, version="24.22.0", name="node-install"):
        prefix = self.root / name
        node = self.write(prefix / "bin/node", "#!/bin/sh\nexit 99\n")
        self.write(prefix / "include/node/node_version.h", "\n".join(
            f"#define NODE_{part}_VERSION {number}" for part, number in zip(("MAJOR", "MINOR", "PATCH"), version.split("."))))
        return node

    def test_node_embedded_library_no_execution(self):
        node = self.node_installation("25.6.1")
        library = node.parent.parent / "lib/libnode.141.dylib"
        library.parent.mkdir()
        library.write_bytes(b"\x00\xffbinary\x00" + FIXTURE.read_bytes() + b"\x00")
        with patch("subprocess.Popen", side_effect=AssertionError("must not execute")):
            item = node_audit.inspect_node(node, self.evidence)
        self.assertEqual(item["version"], "25.6.1")
        self.assertEqual(item["status"], "review_candidate")
        self.assertEqual(len(item["matches"]), 1)
        self.assertIn(str(library), item["inspected_files"])
        self.assertIn("No verified fixed version", item["reason"])

    def test_node_release_lines_and_unknown_versions(self):
        for version, expected in (("22.23.3", "review_candidate"), ("22.23.4", "unverified"),
                                  ("24.22.0", "review_candidate"), ("24.22.1", "unverified"),
                                  ("26.12.0", "review_candidate"), ("26.12.1", "unverified"),
                                  ("25.6.1", "unverified")):
            node = self.node_installation(version)
            self.assertEqual(node_audit.inspect_node(node, self.evidence)["status"], expected, version)
        (node.parent.parent / "include/node/node_version.h").unlink()
        self.assertEqual(node_audit.inspect_node(node, self.evidence)["status"], "unverified")

    def test_partial_bundle_preserves_positive_evidence(self):
        for data in (FIXTURE.read_bytes() + b"\n-----BEGIN CERTIFICATE-----",
                     b"-----BEGIN CERTIFICATE-----\n???\n" + FIXTURE.read_bytes(),
                     b"\xff" + FIXTURE.read_bytes()):
            path = self.root / "partial.pem"
            path.write_bytes(data)
            item = audit.inspect_bundle(path, self.evidence)
            self.assertEqual(item["status"], "review_candidate")
            self.assertEqual(len(item["matches"]), 1)
            self.assertTrue(item["inspection_errors"])

    def test_recent_node_header_is_not_runtime_clearance(self):
        node = self.node_installation("24.22.1")
        item = node_audit.inspect_node(node, self.evidence)
        self.assertEqual(item["version_status"], "no_matching_findings")
        self.assertEqual(item["status"], "unverified")
        self.assertEqual(item["embedded_pem_status"], "unverified")
        node.write_bytes(b"-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n" + FIXTURE.read_bytes())
        item = node_audit.inspect_node(node, self.evidence)
        self.assertEqual(item["status"], "review_candidate")
        self.assertEqual(item["embedded_certificate_count"], 1)
        self.assertTrue(item["inspection_errors"])

    def test_discovery_budget_and_overview(self):
        self.environment()
        report = audit.audit(str(self.root), max_directories=1)
        self.assertFalse(report["overview"]["discovery_complete"])
        self.assertTrue(any(i["kind"] == "discovery" and i["status"] == "unverified" for i in report["items"]))
        self.assertFalse(report["overview"]["compromise_assessed"])
        self.assertFalse(report["overview"]["tls_acceptance_tested"])
        self.assertEqual(report["overview"]["development_roots"][0]["coverage"], "no_supported_component_evidence")
        with self.assertRaises(ValueError):
            audit.audit(str(self.root), max_directories=0)

    def test_explicit_bundle_and_overview_attribution(self):
        env, site = self.environment()
        bundle = self.write(env / "custom.pem", FIXTURE.read_text())
        report = audit.audit(str(env), bundle_paths=[str(bundle), str(bundle)])
        self.assertEqual(report["overview"]["development_roots"][0]["review_candidates"], 1)
        self.assertEqual(report["overview"]["shared_tooling_review_candidates"], 0)
        self.assertEqual(report["overview"]["inspected_components"]["bundle"], 1)
        self.assertIn("Compromise assessment: not performed", audit.render_report(report))
        with contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(cli.main(["trust-audit", "--bundle", str(bundle), "--max-directories", "1", "--json"]), 0)
        self.assertEqual(json.loads(output.getvalue())["overview"]["shared_tooling_review_candidates"], 1)

    def test_malformed_package_origin_does_not_abort_audit(self):
        env, site = self.environment()
        metadata = self.metadata(site, "certifi", "2026.10.23")
        self.write(metadata.parent / "direct_url.json", '{"url": 123}')
        report = audit.audit(str(env))
        self.assertTrue(any(i["kind"] == "metadata" and i["status"] == "unverified" for i in report["items"]))

    def test_evidence_includes_cross_signed_tls_intermediates(self):
        certs = self.evidence["certificates"]
        self.assertEqual(len({c["sha256"] for c in certs}), 13)
        self.assertEqual(sum(c.get("role") == "compromised_tls_intermediate" for c in certs), 12)
        cross_signed = [c for c in certs if c.get("issuer") == "AAA Certificate Services"]
        self.assertEqual(len(cross_signed), 6)
        self.assertTrue(all(c["source"] == "https://support.apple.com/en-us/149555" for c in cross_signed))
        self.assertFalse(any(c["name"] == "AAA Certificate Services" for c in certs))

    def test_node_root_discovery_and_explicit_alias_deduplication(self):
        node = self.node_installation()
        alias = self.root / "node-alias"
        alias.symlink_to(node)
        report = audit.audit(str(self.root), node_paths=[str(alias)])
        self.assertEqual(len([i for i in report["items"] if i["kind"] == "node_runtime"]), 1)

    def test_node_partial_or_malformed_is_not_clean(self):
        node = self.node_installation("24.22.1")
        with patch.object(node_audit, "MAX_NODE_BYTES", 1):
            self.assertEqual(node_audit.inspect_node(node, self.evidence)["status"], "unverified")
        node.unlink()
        os.mkfifo(node)
        self.assertEqual(node_audit.inspect_node(node, self.evidence)["status"], "unverified")
        node.unlink()
        node.write_bytes(FIXTURE.read_bytes())
        (node.parent.parent / "include/node/node_version.h").write_bytes(b"\xff")
        item = node_audit.inspect_node(node, self.evidence)
        self.assertEqual(item["status"], "review_candidate")
        self.assertTrue(item["inspection_errors"])

    def test_cli_multiple_roots_and_node(self):
        env, _ = self.environment()
        node = self.node_installation()
        with contextlib.redirect_stdout(io.StringIO()) as output:
            result = cli.main(["trust-audit", "--root", str(env), "--root", str(node.parent.parent), "--node", str(node), "--json"])
        self.assertEqual(result, 0)
        report = json.loads(output.getvalue())
        self.assertEqual(len(report["roots"]), 2)
        self.assertEqual(report["schema_version"], 2)

    def test_nested_environments_and_pip_vendor(self):
        env, site = self.environment()
        self.metadata(site, "certifi", "2026.10.19")
        self.metadata(site, "pip", "26.2.1")
        self.write(site / "pip/_vendor/certifi/cacert.pem", FIXTURE.read_text())
        self.write(site / "certifi/__init__.py", "raise RuntimeError('must not execute')")
        self.write(site / "trap/pyvenv.cfg", "")
        self.write(self.root / "node_modules/trap/pyvenv.cfg", "")
        (self.root / "alias").symlink_to(env, target_is_directory=True)
        with patch.object(audit.sys, "platform", "linux"):
            result = audit.audit(str(self.root))
        self.assertEqual(result["environments"], [str(env)])
        self.assertEqual(result["counts"]["review_candidate"], 2)
        self.assertEqual(result["counts"]["demonstrated_failure"], 0)
        self.assertTrue(any(i["path"].endswith("pip/_vendor/certifi/cacert.pem") for i in result["items"]))

    def test_no_source_walk(self):
        env, site = self.environment()
        self.metadata(site, "pip", "26.2.2")
        self.write(site / "large_source/tree/pyvenv.cfg", "")
        real_scandir = os.scandir
        def guard(path):
            self.assertNotIn("large_source", str(path))
            return real_scandir(path)
        with patch("os.scandir", side_effect=guard):
            audit.audit(str(self.root))

    def test_mac_locations_and_symlink_deduplication(self):
        bundle = self.write(self.root / "cert.pem", FIXTURE.read_text())
        alias = self.root / "alias.pem"
        alias.symlink_to(bundle)
        with patch.object(audit.sys, "platform", "darwin"), patch.object(audit, "known_locations", return_value=([bundle, alias], [])):
            result = audit.audit()
        self.assertEqual(result["counts"]["review_candidate"], 1)
        self.assertGreater(result["counts"]["unverified"], 0)

    def test_incomplete_environment_and_metadata(self):
        env, site = self.environment()
        self.write(site / "broken.dist-info/METADATA", "Name: certifi\n")
        self.metadata(site, "certifi", "2026.10.19")
        result = audit.audit(str(self.root))
        self.assertTrue(any(i["kind"] == "metadata" and i["status"] == "unverified" for i in result["items"]))
        self.assertTrue(any(i["kind"] == "bundle" and i["status"] == "unverified" for i in result["items"]))
        other, _ = self.environment("empty")
        shutil.rmtree(other / "lib")
        result = audit.audit(str(self.root))
        self.assertTrue(any(i["kind"] == "environment" and i["path"] == str(other) for i in result["items"]))

    def test_discovery_permission_error(self):
        def walk(root, **kwargs):
            kwargs["onerror"](PermissionError(13, "fixture denied", str(root)))
            return iter(())
        items = []
        with patch.object(audit.os, "walk", side_effect=walk):
            self.assertEqual(audit.discover_environments(self.root, items), [])
        self.assertEqual(items[0]["status"], "unverified")

    def test_cli_no_state_network_or_processes(self):
        self.environment()
        with contextlib.ExitStack() as stack:
            for target in ("guardian.cli.load_config", "guardian.cli.Database", "socket.socket", "subprocess.Popen", "pathlib.Path.write_text", "os.mkdir", "sqlite3.connect"):
                stack.enter_context(patch(target, side_effect=AssertionError(target)))
            output = stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
            self.assertEqual(cli.main(["trust-audit", "--root", str(self.root), "--json"]), 0)
            self.assertTrue(json.loads(output.getvalue())["offline"])

    def test_explicit_markdown_and_error_paths(self):
        target = self.root / "report.md"
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(cli.main(["trust-audit", "--output", str(target), "--json"]), 0)
            original = target.read_bytes()
            self.assertEqual(cli.main(["trust-audit", "--output", str(target), "--json"]), 2)
            self.assertEqual(cli.main(["trust-audit", "--root", str(self.root / "missing"), "--json"]), 2)
        self.assertEqual(original, target.read_bytes())
        self.assertIn(b"# Guardian Trust Audit", original)
        self.assertIn(b"Official guidance", original)

    def test_launcher_no_writes_in_fresh_copy(self):
        copy = self.root / "plugin"
        shutil.copytree(PLUGIN, copy, ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
        home = self.root / "home"
        home.mkdir()
        state = self.root / "state"
        def snapshot():
            return {str(p.relative_to(self.root)): hashlib.sha256(p.read_bytes()).hexdigest() if p.is_file() else None for p in self.root.rglob("*")}
        project = self.root / "project"
        project.mkdir()
        (project / "sitecustomize.py").write_text("raise RuntimeError('project startup executed')")
        (project / "guardian.py").write_text("raise RuntimeError('project shadow module executed')")
        node = self.node_installation()
        bundle = self.write(project / "custom-ca.pem", FIXTURE.read_text())
        before = snapshot()
        env = dict(os.environ, HOME=str(home), GUARDIAN_STATE_DIR=str(state), PYTHONPATH=str(project))
        env.pop("PYTHONDONTWRITEBYTECODE", None)
        for arguments in (["--json"], ["--help"], ["--root", str(self.root / "missing"), "--json"],
                          ["--root", str(project), "--root", str(node.parent.parent), "--node", str(node),
                           "--bundle", str(bundle), "--max-directories", "1", "--json"]):
            result = subprocess.run([str(copy / "bin/guardian"), "trust-audit", *arguments], env=env, cwd=project, text=True, capture_output=True)
            self.assertEqual(result.returncode, 2 if str(self.root / "missing") in arguments else 0, result.stderr)
        self.assertEqual(before, snapshot())
        self.assertFalse(state.exists())
        state.mkdir()
        (state / "config.json").write_text("invalid JSON: must not read")
        (state / "guardian.db").write_bytes(b"existing database: must not open")
        before = snapshot()
        result = subprocess.run([str(copy / "bin/guardian"), "trust-audit", "--json"], env=env, cwd=project, capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(before, snapshot())


if __name__ == "__main__":
    unittest.main()
