"""Render an assessment result as Markdown or self-contained HTML."""

from __future__ import annotations

from html import escape

from .models import AssessmentResult

_STATUS_LABEL = {
    "vulnerable": "VULNERABLE",
    "passed": "passed",
    "skipped": "skipped",
    "error": "error",
}

DISCLAIMER = (
    "No finding for a probe means these specific attacks did not succeed in this run; "
    "it is not proof that the application is secure."
)


def _fence(text: str) -> str:
    """Code-fence text for Markdown, safe even if it contains backtick runs."""
    longest = run = 0
    for char in text:
        run = run + 1 if char == "`" else 0
        longest = max(longest, run)
    fence = "`" * max(3, longest + 1)
    return f"{fence}\n{text}\n{fence}"


def to_markdown(result: AssessmentResult) -> str:
    lines = [
        f"# AI Security Assessment: {result.target_name}",
        "",
        f"- **Risk score:** {result.risk_score}/100 ({result.risk_rating})",
        f"- **Started:** {result.started_at}",
        f"- **Finished:** {result.finished_at}",
        "- **Findings:** "
        + ", ".join(f"{count} {name}" for name, count in result.severity_counts.items() if count)
        if result.findings
        else "- **Findings:** none",
        "",
        f"> {DISCLAIMER}",
        "",
        "## Probe results",
        "",
        "| Probe | Category | Result | Successful attacks | Note |",
        "|---|---|---|---|---|",
    ]
    for outcome in result.outcomes:
        ratio = f"{outcome.hits}/{outcome.runs}" if outcome.runs else "-"
        note = outcome.note.replace("|", "\\|").replace("\n", " ")
        lines.append(
            f"| {outcome.title} (`{outcome.probe_id}`) | {outcome.category} | "
            f"{_STATUS_LABEL[outcome.status]} | {ratio} | {note} |"
        )
    lines += ["", "## Findings", ""]
    if not result.findings:
        lines.append("No attacks succeeded.")
    for index, finding in enumerate(result.findings, 1):
        lines += [
            f"### {index}. {finding.title} [{finding.severity.value.upper()}, score {finding.score}/10]",
            "",
            f"- **Probe:** `{finding.probe_id}`",
            f"- **Success rate:** {finding.hits}/{finding.runs} attempts ({finding.success_rate:.0%})",
            f"- **OWASP LLM Top 10:** {finding.owasp}",
            f"- **MITRE ATLAS:** {finding.atlas}",
            "",
            f"**What happened.** {finding.description}",
            "",
            f"**Impact.** {finding.impact}",
            "",
            f"**Remediation.** {finding.remediation}",
            "",
            "**Evidence**",
            "",
        ]
        for evidence in finding.evidence:
            detected = "; ".join(f"{d.detector}: {d.detail}" for d in evidence.detections)
            lines += [f"*Case `{evidence.case_id}`, attempt {evidence.attempt}* - {detected}", ""]
            for message in evidence.transcript:
                lines += [f"{message['role']}:", "", _fence(message["content"]), ""]
    return "\n".join(lines) + "\n"


_CSS = """
body{font:15px/1.5 system-ui,sans-serif;max-width:960px;margin:2rem auto;padding:0 1rem;color:#1c2330}
h1{margin-bottom:.25rem} table{border-collapse:collapse;width:100%}
th,td{border:1px solid #d5dae2;padding:.4rem .6rem;text-align:left;vertical-align:top}
th{background:#f1f3f7} pre{background:#f1f3f7;padding:.6rem;white-space:pre-wrap;word-break:break-word;border-radius:4px}
.sev{display:inline-block;padding:.1rem .5rem;border-radius:3px;color:#fff;font-size:.8rem;text-transform:uppercase}
.critical{background:#a3122b}.high{background:#d1480f}.medium{background:#a66f00}.low{background:#2f6fb5}.info{background:#667}
.finding{border:1px solid #d5dae2;border-radius:6px;padding:0 1rem;margin:1rem 0}
.note{background:#fff7dd;border-left:4px solid #a66f00;padding:.5rem .8rem}.role{font-weight:600;margin:.5rem 0 0}
"""


def to_html(result: AssessmentResult) -> str:
    e = escape
    rows = "".join(
        f"<tr><td>{e(o.title)}<br><code>{e(o.probe_id)}</code></td><td>{e(o.category)}</td>"
        f"<td>{e(_STATUS_LABEL[o.status])}</td>"
        f"<td>{f'{o.hits}/{o.runs}' if o.runs else '-'}</td><td>{e(o.note)}</td></tr>"
        for o in result.outcomes
    )
    blocks = []
    for index, f in enumerate(result.findings, 1):
        evidence_html = ""
        for ev in f.evidence:
            detected = "; ".join(f"{d.detector}: {d.detail}" for d in ev.detections)
            evidence_html += (
                f"<p><em>Case <code>{e(ev.case_id)}</code>, attempt {ev.attempt}</em> - {e(detected)}</p>"
            )
            for message in ev.transcript:
                evidence_html += (
                    f"<p class='role'>{e(message['role'])}</p><pre>{e(message['content'])}</pre>"
                )
        blocks.append(
            f"<div class='finding'><h3>{index}. {e(f.title)} "
            f"<span class='sev {f.severity.value}'>{f.severity.value}</span> {f.score}/10</h3>"
            f"<p><b>Probe:</b> <code>{e(f.probe_id)}</code> &middot; <b>Success rate:</b> "
            f"{f.hits}/{f.runs} ({f.success_rate:.0%})<br><b>OWASP LLM Top 10:</b> {e(f.owasp)}"
            f"<br><b>MITRE ATLAS:</b> {e(f.atlas)}</p>"
            f"<p><b>What happened.</b> {e(f.description)}</p><p><b>Impact.</b> {e(f.impact)}</p>"
            f"<p><b>Remediation.</b> {e(f.remediation)}</p><h4>Evidence</h4>{evidence_html}</div>"
        )
    findings_html = "".join(blocks) or "<p>No attacks succeeded.</p>"
    return (
        "<!doctype html><html lang='en'><head><meta charset='utf-8'>"
        f"<title>AI Security Assessment: {e(result.target_name)}</title><style>{_CSS}</style></head><body>"
        f"<h1>AI Security Assessment: {e(result.target_name)}</h1>"
        f"<p><b>Risk score:</b> {result.risk_score}/100 ({e(result.risk_rating)}) &middot; "
        f"{e(result.started_at)} to {e(result.finished_at)}</p>"
        f"<p class='note'>{e(DISCLAIMER)}</p>"
        "<h2>Probe results</h2><table><tr><th>Probe</th><th>Category</th><th>Result</th>"
        f"<th>Successful attacks</th><th>Note</th></tr>{rows}</table>"
        f"<h2>Findings</h2>{findings_html}</body></html>"
    )
