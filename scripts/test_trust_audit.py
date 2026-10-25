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

FIXTURE = REPO / "tests/fixtures/trust-audit/emsign-g3.pem"


class TrustAuditTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.evidence = json.loads(audit.EVIDENCE_PATH.read_text())

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
        for text in ("", "-----BEGIN CERTIFICATE-----\n???\n-----END CERTIFICATE-----", FIXTURE.read_text() + "\n-----BEGIN CERTIFICATE-----"):
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
            ("requests", "2.32.0", "unverified"),
        ):
            with self.subTest(name=name, version=version):
                item = audit.inspect_package({"normalized_name": name, "version": version, "source_file": "fixture"}, self.evidence)
                self.assertEqual(item["status"], expected)

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
        before = snapshot()
        env = dict(os.environ, HOME=str(home), GUARDIAN_STATE_DIR=str(state), PYTHONPATH=str(project))
        env.pop("PYTHONDONTWRITEBYTECODE", None)
        for arguments in (["--json"], ["--help"], ["--root", str(self.root / "missing"), "--json"]):
            result = subprocess.run([str(copy / "bin/guardian"), "trust-audit", *arguments], env=env, cwd=project, text=True, capture_output=True)
            self.assertEqual(result.returncode, 2 if "--root" in arguments else 0, result.stderr)
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
