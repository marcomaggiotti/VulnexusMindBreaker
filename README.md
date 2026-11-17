# VulnexusMindBreaker

An integrated security platform combining vulnerability intelligence, AI security assessment, and intelligent offensive security testing. Discovers what is vulnerable, challenges the security of AI systems, explores how weaknesses can be exploited, intelligence-driven security validation.

**Status: Phase 1 (AI Security Assessment).** You can register an AI application, run controlled prompt-injection, jailbreak, leakage and unsafe-output attacks against it, and get an evidence-based report. Later phases are listed under [Roadmap](#roadmap).

> Only test systems you own or have written permission to test. Target registration requires an explicit `authorized: true`.

## Quick start

Try it against the built-in simulated chatbot (no model, key or network needed):

```bash
cd backend
python3 -m venv .venv && .venv/bin/pip install -e '.[dev]'
.venv/bin/mindbreaker scan --demo vulnerable
```

Scan a real application:

```bash
.venv/bin/mindbreaker scan --config ../examples/openai-compatible-target.json --format html -o report.html
```

Run the control center (API on :8000, dashboard on :5173):

```bash
.venv/bin/mindbreaker serve
```

```bash
cd frontend && npm install && npm run dev
```

## What it tests

| Probe | Category | OWASP LLM Top 10 (2025) | MITRE ATLAS |
|---|---|---|---|
| `pi.direct` | Direct prompt injection | LLM01 | AML.T0051.000 |
| `pi.indirect` | Injection via documents, pages, emails, tool results | LLM01 | AML.T0051.001 |
| `pi.encoded` | Obfuscated injection (base64, letter spacing) | LLM01 | AML.T0051.000 |
| `jb.persona` | Persona / "developer mode" jailbreak | LLM01 | AML.T0054 |
| `jb.multi_turn` | Multi-turn jailbreak | LLM01 | AML.T0054 |
| `spl.direct` | System prompt disclosure | LLM07 | AML.T0056 |
| `spl.encoded` | System prompt disclosure via encoding | LLM07 | AML.T0056 |
| `sdl.secrets` | Credentials / confidential data disclosure | LLM02 | AML.T0057 |
| `uo.markdown_exfil` | Markdown image exfiltration channel | LLM05 | AML.T0057 |
| `uo.html` | Script / event handler / `javascript:` output | LLM05 | AML.T0051.000 |

## How a finding is decided

Detection is deterministic and based on proof, not on judging the tone of a reply:

- **Injection marker.** Attacks ask the model to output a random string it must assemble from two parts. The whole string never appears in the prompt, so a refusal that quotes the request is not a hit.
- **Canary.** When the engine sends the system prompt (`openai_chat`, `demo`), it plants a random confidential code in it. Seeing that code in output, even base64-encoded, reversed or split by separators, proves leakage.
- **System prompt overlap, registered secrets, credential patterns, active content** (markdown images to an attacker host, `<script>`, event handlers, `javascript:` links outside code blocks).

Each test case is repeated (`--attempts`, default 2) and the success rate is reported, since models are not deterministic.

**Impact is judged in context.** Severity is raised when the target declares sensitive tools an attacker could reach through a hijacked model, and becomes critical when a secret you registered is actually disclosed. A finding's score (0-10) combines severity with attack reliability; the assessment risk score (0-100) combines all findings.

A passed probe means those specific attacks did not succeed in that run. It is not proof the application is secure.

### Known limits

- Paraphrased system-prompt leaks are not detected for black-box (`http_json`) targets; there is no LLM judge yet.
- Jailbreak probes measure whether the model accepts a "rules suspended" persona, using harmless payloads. They do not attempt to elicit harmful content.
- `http_json` targets are treated as stateless: multi-turn probes send each turn as a separate request.
- The demo chatbot is rule-based, written to respond to these probes. It demonstrates the platform, not real model behaviour.

## Target configuration

See [`examples/`](examples). Connectors:

- `openai_chat`: any OpenAI-compatible `/chat/completions` URL. The engine sends your `system_prompt` plus a canary.
- `http_json`: any JSON API. `request_template` is the body with `{{prompt}}` substituted; `response_path` is a dotted path to the reply (for example `data.reply`).
- `demo`: simulated chatbot with `vulnerable`, `partial` or `hardened` profiles.

`secrets`, `tools` (with `sensitive`) and `knowledge_sources` describe what is at stake and drive the impact assessment.

## CI / regression use

```bash
mindbreaker scan --config target.json --fail-on high
```

Exit codes: `0` clean, `1` a finding at or above `--fail-on`, `3` one or more probes could not run (never reported as a pass).

## Server configuration

| Variable | Purpose | Default |
|---|---|---|
| `MINDBREAKER_DATABASE_URL` | SQLAlchemy URL (PostgreSQL needs a driver such as `psycopg` installed) | `sqlite:///mindbreaker.db` |
| `MINDBREAKER_API_KEY` | If set, every API call needs `X-API-Key` | unset (open) |

Security notes for operators:

- Target credentials (`headers`) and `secrets` are stored unencrypted in the database and masked in API responses. Evidence transcripts can contain leaked secrets by design. Protect the database and reports accordingly.
- The server makes HTTP requests to whatever endpoint a target names. Link-local addresses (cloud metadata) are refused; private ranges are allowed because internal applications are legitimate targets. Set `MINDBREAKER_API_KEY` and do not expose the API to untrusted networks. There is no per-user access control yet.
- Assessments run inside the API process; a restart marks in-flight runs as failed.

## Layout

```
backend/mindbreaker/
  models.py       target config and result schemas
  connectors.py   openai_chat / http_json / demo adapters
  probes/         attack catalog (add a Probe to catalog.py to extend)
  detectors.py    proof-based success detection
  engine.py       orchestration, impact assessment, scoring
  report.py       Markdown / HTML reports
  store.py api.py cli.py
frontend/         React control center (dashboard, targets, findings, evidence)
```

Tests: `cd backend && .venv/bin/pytest`

## Roadmap

1. **Phase 1 - AI security assessment** (this release).
2. **Phase 2 - Agentic security testing:** tool-permission and excessive-agency tests that observe real tool calls, RAG retrieval and tenant-isolation tests, document-borne injection through real ingestion paths, multimodal inputs, LLM-judge evaluation, adapters for Garak / PyRIT / Promptfoo.
3. **Phase 3 - Traditional application security:** scanner adapters (OWASP ZAP, Nmap, Trivy, Semgrep, Checkov, OSV-Scanner) and cross-layer finding correlation.
4. **Phase 4 - Enterprise platform:** multi-tenancy, RBAC, scheduled and regression assessments, audit trails, remediation workflows.
