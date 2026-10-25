"""Self-contained offline HTML reports; never access inspected files or network."""

from __future__ import annotations

import base64
import hashlib
from html import escape
import json
from pathlib import Path
from urllib.parse import urlsplit

from .trust_audit_presentation import evidence_rows, handoff, LABELS

ASSETS = Path(__file__).resolve().parents[3] / "data"
VIEWS = (
    ("project", "Project environments"),
    ("machine", "Machine tooling"),
    ("release", "What you ship"),
)


def text(value: object) -> str:
    # Display controls literally; HTML-escape all filesystem and metadata content.
    return escape(
        "".join(
            c if c.isprintable() or c == "\n" else repr(c)[1:-1] for c in str(value)
        )
    )


def _navigation() -> str:
    return "".join(
        f'<button type="button" data-view="{key}" aria-pressed="false">{title}'
        + (' <span class="badge">Not assessed</span>' if key == "release" else "")
        + "</button>"
        for key, title in VIEWS
    )


def _row(row: dict) -> str:
    item = row["item"]
    details = text(json.dumps(item, indent=2, ensure_ascii=True))
    link = "".join(
        f'<a href="{escape(url, quote=True)}" target="_blank" rel="noopener noreferrer">{text(urlsplit(url).hostname)} — {text(url.rstrip("/").split("/")[-1])} ↗</a>'
        for url in row["sources"]
    )
    related = (
        (
            "<p class=small>Shares a package-update route with the metadata entry; "
            "this remains separate certificate evidence.</p><p class=technical>"
            + text(row["related_package"])
            + "</p>"
        )
        if row["related_package"]
        else ""
    )
    return (
        f'<tr data-evidence="{row["id"]}"><td>{row["id"]:02d}</td>'
        f'<td><strong>{text(row["title"])}</strong><span class="badge">{text(row["label"])}</span>'
        f'<details><summary>Technical evidence</summary><pre class="technical">{details}</pre></details></td>'
        f"<td>{text(item['reason'])}</td><td><p>{text(row['action'])}</p>{related}"
        f"<details><summary>Official incident and update guidance ↗</summary>{link}</details></td></tr>"
    )


def _tables(rows: list[dict]) -> str:
    content = []
    for status in (
        "review_candidate",
        "demonstrated_failure",
        "unverified",
        "no_matching_findings",
    ):
        selected = [r for r in rows if r["item"]["status"] == status]
        if not selected:
            continue
        content.append(
            f'<h3>{LABELS[status]} <span class="badge">{len(selected)}</span></h3>'
            '<div class="evidence-wrap"><table><thead><tr><th>#</th><th>Evidence</th>'
            "<th>Observed</th><th>Recommended route</th></tr></thead><tbody>"
            + "".join(_row(row) for row in selected)
            + "</tbody></table></div>"
        )
    return (
        "".join(content)
        or '<p class="scope">No supported evidence in this scope. This is not a clean bill of health.</p>'
    )


def _handoff(
    report: dict, root: str | None, purpose: str, index: int, rows: list[dict]
) -> str:
    key = f"handoff-{purpose}-{index}"
    title = "Release handoff" if purpose == "release" else "Review handoff"
    return (
        f'<aside class="handoff"><h2>{title}</h2><p>{text(root or "Shared machine tooling")}</p>'
        "<hr><p>Identify consumers and prepare a scoped plan. Do not apply changes.</p>"
        f'<button type="button" class="outline copy" data-prompt="{key}" data-status="{key}-status">Copy Codex handoff</button>'
        f'<p class="small" role="status" id="{key}-status">Review only. No upgrades or trust changes.</p>'
        f'<details><summary>Read the full handoff</summary><textarea readonly id="{key}" aria-label="{title}">'
        + text(handoff(report, root, purpose, rows=rows))
        + "</textarea></details></aside>"
    )


def _project_view(report: dict, rows: list[dict]) -> str:
    panels = []
    for index, root in enumerate(report.get("roots", [])):
        local = [row for row in rows if row["root"] == root]
        panels.append(
            '<div class="layout"><section class="panel"><h2>'
            + text(
                (Path(root).parent.name + " / " + Path(root).name)
                if root in report.get("environments", [])
                else (Path(root).name or root)
            )
            + '</h2><p class="context">Selected development scope · Application use unverified</p>'
            '<details><summary>Selected root</summary><p class="technical">'
            + text(root)
            + "</p></details>"
            + _tables(local)
            + "</section>"
            + _handoff(report, root, "project", index, rows)
            + "</div>"
        )
    if not panels:
        panels.append(
            '<section class="panel"><h2>No development roots selected</h2>'
            "<p>Select development folders or shared environments in a future audit. Machine tooling is reported separately.</p></section>"
        )
    return '<section class="view" id="view-project">' + "".join(panels) + "</section>"


def _release_view(report: dict, rows: list[dict]) -> str:
    roots = report.get("roots", [])
    intro = (
        '<section class="panel"><h2>What you ship <span class="badge">Not assessed</span></h2>'
        '<p class="context">A local inventory does not verify public releases or fresh installations.</p>'
        '<div class="release-list">'
    )
    for title, description in (
        (
            "Setup and bootstrap",
            "How fresh installations select Python, pip, certifi and Node.",
        ),
        (
            "Images and bundled runtimes",
            "Whether images, installers or embedded environments preserve older stores.",
        ),
        (
            "Existing-user upgrades",
            "Whether fixes reach environments already created on users’ machines.",
        ),
        (
            "Release verification",
            "Clean-install tests, shipped-version evidence and migration validation.",
        ),
    ):
        intro += f'<div class="release-item"><div><strong>{title}</strong><p>{description}</p></div><span class="badge">Not assessed</span></div>'
    intro += '</div><p class="scope">Proposed review areas, not additional findings. No release artifacts were assessed.</p></section>'
    prompts = "".join(
        _handoff(report, root, "release", index, rows)
        for index, root in enumerate(roots)
    )
    if not roots:
        prompts = '<p class="scope">Select a project root to generate a scoped release handoff.</p>'
    return '<section class="view" id="view-release">' + intro + prompts + "</section>"


def render_html(report: dict) -> str:
    """Render without mutating the audit payload or opening inspected paths."""
    rows = evidence_rows(report)
    css = (ASSETS / "trust_audit_report.css").read_text(encoding="utf-8")
    script = (ASSETS / "trust_audit_report.js").read_text(encoding="utf-8")

    def digest(value):
        return base64.b64encode(hashlib.sha256(value.encode()).digest()).decode()

    policy = (
        "default-src 'none'; base-uri 'none'; form-action 'none'; "
        f"style-src 'sha256-{digest(css)}'; script-src 'sha256-{digest(script)}'"
    )
    initial = "project" if report.get("roots") else "machine"
    parts = [
        '<!doctype html><html lang="en"><head><meta charset="utf-8">',
        f'<meta http-equiv="Content-Security-Policy" content="{escape(policy, quote=True)}">',
        '<meta name="viewport" content="width=device-width,initial-scale=1">',
        "<title>Guardian — Developer trust overview</title><style>",
        css,
        "</style></head>",
        f'<body data-initial-view="{initial}"><aside class="nav"><div class="brand">◇ Guardian</div>',
        '<nav aria-label="Report views">',
        _navigation(),
        '</nav><div class="foot">LOCAL TRUST INVENTORY<br>Read-only · Offline audit</div></aside>',
        '<main><header><div class="topline"><span class="eyebrow">Guardian / Trust audit</span><span class="readonly">Read-only report</span></div>',
        '<h1>Understand what needs attention.</h1><p class="subtitle">Evidence, ownership and a clear next step.</p></header>',
        '<div class="metrics">',
        f'<div class="metric"><strong>{report["counts"].get("review_candidate", 0)}</strong> review entries</div>',
        f'<div class="metric"><strong>{len(rows)}</strong> separate evidence rows</div>',
        '<div class="metric">Release coverage · <span class="muted">Not assessed</span></div></div>',
        '<div class="tabs" aria-label="Choose report view">',
        _navigation(),
        "</div>",
        '<p class="scope">Recommendations are from the evidence snapshot verified on ',
        text(report["evidence"]["verified_on"]),
        ". No latest-version lookup was performed. Reverify official guidance before changes. Selected paths do not establish active use.</p>",
        '<p class="scope">Discovery complete within configured scope: ',
        text(str(report["overview"]["discovery_complete"]).lower()),
        ". Excluded directory names: ",
        text(", ".join(report.get("excluded_directory_names", []))),
        "</p>",
        _project_view(report, rows),
        '<section class="view" id="view-machine"><div class="layout"><section class="panel"><h2>Machine tooling / Shared installations</h2>',
        '<p class="context">Homebrew · User-level packages · OS-managed stores · Coverage context</p>',
        '<p class="scope">User-level Python packages, Homebrew Python and the Apple-managed interpreter are distinct. Do not replace system Python based on package evidence.</p>',
        _tables([r for r in rows if r["root"] is None]),
        "</section>",
        _handoff(report, None, "machine", 0, rows),
        "</div></section>",
        _release_view(report, rows),
        '<div class="release-strip"><h2>What you ship</h2><span class="badge">Not assessed</span>',
        '<p>Setup scripts, images and bundled runtimes need a separate review.</p><button type="button" class="outline" data-view="release">View release handoffs</button></div>',
        '<footer class="footer">',
        text(report["limitations"]),
        "<p>Report files and handoffs contain local paths. Review before sharing. Copy controls only copy text; they never send messages or execute actions.</p></footer>",
        "</main><script>",
        script,
        "</script></body></html>",
    ]
    return "".join(parts)
