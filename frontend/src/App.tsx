import { FormEvent, useCallback, useEffect, useState } from "react";
import { api, Assessment, Dashboard, Finding, SEVERITIES, Severity, Target } from "./api";

type View = { name: "dashboard" } | { name: "targets" } | { name: "assessment"; id: string };

function useLoader<T>(load: () => Promise<T>, intervalMs?: number) {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState("");
  const reload = useCallback(() => {
    load()
      .then((value) => {
        setData(value);
        setError("");
      })
      .catch((e: Error) => setError(e.message));
  }, [load]);
  useEffect(() => {
    reload();
    if (!intervalMs) return;
    const timer = setInterval(reload, intervalMs);
    return () => clearInterval(timer);
  }, [reload, intervalMs]);
  return { data, error, reload };
}

function Badge({ severity }: { severity: Severity | string }) {
  return <span className={`badge ${severity}`}>{severity}</span>;
}

function when(iso: string | null) {
  return iso ? new Date(iso).toLocaleString() : "-";
}

function StatusCell({ a }: { a: Assessment }) {
  if (a.status === "completed")
    return (
      <>
        <strong>{a.risk_score}</strong>/100 <Badge severity={(a.risk_rating ?? "info").split(" ")[0]} />
      </>
    );
  if (a.status === "failed") return <span className="error-text">failed</span>;
  return (
    <span>
      {a.status} {a.total ? `${a.done}/${a.total}` : ""}
    </span>
  );
}

function AssessmentTable({ rows, open }: { rows: Assessment[]; open: (id: string) => void }) {
  if (!rows.length) return <p className="muted">No assessments yet. Register a target and run one.</p>;
  return (
    <table>
      <thead>
        <tr>
          <th>Target</th>
          <th>Started</th>
          <th>Risk</th>
          <th>Findings</th>
        </tr>
      </thead>
      <tbody>
        {rows.map((a) => (
          <tr key={a.id} className="clickable" onClick={() => open(a.id)}>
            <td>{a.target_name}</td>
            <td>{when(a.created_at)}</td>
            <td>
              <StatusCell a={a} />
            </td>
            <td>
              {a.severity_counts
                ? SEVERITIES.filter((s) => a.severity_counts![s] > 0).map((s) => (
                    <span key={s} className="count">
                      {a.severity_counts![s]} <Badge severity={s} />
                    </span>
                  ))
                : "-"}
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

const loadDashboard = () => api.dashboard();

function DashboardView({ open }: { open: (id: string) => void }) {
  const { data, error } = useLoader<Dashboard>(loadDashboard, 4000);
  if (error) return <p className="error-text">Could not load dashboard: {error}</p>;
  if (!data) return <p className="muted">Loading...</p>;
  return (
    <>
      <h2>Current exposure</h2>
      <p className="muted">Findings from the latest completed assessment of each target.</p>
      <div className="tiles">
        {SEVERITIES.slice(0, 4).map((s) => (
          <div key={s} className={`tile ${s}`}>
            <div className="tile-value">{data.open_findings[s]}</div>
            <div className="tile-label">{s}</div>
          </div>
        ))}
        <div className="tile">
          <div className="tile-value">{data.targets}</div>
          <div className="tile-label">targets</div>
        </div>
        <div className="tile">
          <div className="tile-value">{data.running}</div>
          <div className="tile-label">running</div>
        </div>
      </div>

      <h2>Risk by target</h2>
      {data.target_risk.length ? (
        <table>
          <thead>
            <tr>
              <th>Target</th>
              <th>Risk score</th>
              <th>Last assessed</th>
            </tr>
          </thead>
          <tbody>
            {data.target_risk.map((t) => (
              <tr key={t.target_id} className="clickable" onClick={() => open(t.assessment_id)}>
                <td>{t.target_name}</td>
                <td>
                  <div className="bar">
                    <div className={`bar-fill ${t.risk_rating.split(" ")[0]}`} style={{ width: `${t.risk_score}%` }} />
                  </div>
                  {t.risk_score}/100 ({t.risk_rating})
                </td>
                <td>{when(t.finished_at)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      ) : (
        <p className="muted">No completed assessments yet.</p>
      )}

      <h2>Recent assessments</h2>
      <AssessmentTable rows={data.recent} open={open} />
    </>
  );
}

const EMPTY_FORM = {
  name: "",
  connector: "demo",
  demo_profile: "vulnerable",
  endpoint: "",
  model: "",
  api_key: "",
  system_prompt: "",
  secrets: "",
  tools: "",
  request_template: '{"message": "{{prompt}}"}',
  response_path: "",
  authorized: false,
};

function TargetForm({ onCreated }: { onCreated: () => void }) {
  const [form, setForm] = useState(EMPTY_FORM);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const set = (key: keyof typeof EMPTY_FORM) => (e: { target: { value: string } }) =>
    setForm({ ...form, [key]: e.target.value });
  const lines = (text: string) => text.split("\n").map((l) => l.trim()).filter(Boolean);

  async function submit(event: FormEvent) {
    event.preventDefault();
    setError("");
    const config: Record<string, unknown> = {
      name: form.name,
      connector: form.connector,
      system_prompt: form.system_prompt || null,
      secrets: lines(form.secrets),
      tools: lines(form.tools).map((line) => ({
        name: line.replace(/\*$/, "").trim(),
        sensitive: line.endsWith("*"),
      })),
      authorized: form.authorized,
    };
    if (form.connector === "demo") config.demo_profile = form.demo_profile;
    else {
      config.endpoint = form.endpoint;
      if (form.api_key) config.headers = { Authorization: `Bearer ${form.api_key}` };
    }
    if (form.connector === "openai_chat") config.model = form.model;
    if (form.connector === "http_json") {
      try {
        config.request_template = JSON.parse(form.request_template);
      } catch {
        setError("Request template is not valid JSON.");
        return;
      }
      config.response_path = form.response_path || null;
    }
    setBusy(true);
    try {
      await api.createTarget(config);
      setForm(EMPTY_FORM);
      onCreated();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  }

  const remote = form.connector !== "demo";
  return (
    <form className="card" onSubmit={submit}>
      <h3>Register an AI application</h3>
      <div className="grid">
        <label>
          Name
          <input required value={form.name} onChange={set("name")} placeholder="Support chatbot (staging)" />
        </label>
        <label>
          Connector
          <select value={form.connector} onChange={set("connector")}>
            <option value="demo">Built-in demo chatbot (simulated)</option>
            <option value="openai_chat">OpenAI-compatible chat endpoint</option>
            <option value="http_json">Custom JSON API</option>
          </select>
        </label>
        {form.connector === "demo" && (
          <label>
            Demo profile
            <select value={form.demo_profile} onChange={set("demo_profile")}>
              <option value="vulnerable">vulnerable</option>
              <option value="partial">partial</option>
              <option value="hardened">hardened</option>
            </select>
          </label>
        )}
        {remote && (
          <label>
            Endpoint URL
            <input required type="url" value={form.endpoint} onChange={set("endpoint")}
              placeholder="https://host/v1/chat/completions" />
          </label>
        )}
        {form.connector === "openai_chat" && (
          <label>
            Model
            <input required value={form.model} onChange={set("model")} />
          </label>
        )}
        {remote && (
          <label>
            API key (sent as Bearer token)
            <input type="password" autoComplete="off" value={form.api_key} onChange={set("api_key")} />
          </label>
        )}
        {form.connector === "http_json" && (
          <>
            <label>
              Request template (JSON, use {"{{prompt}}"})
              <textarea rows={3} value={form.request_template} onChange={set("request_template")} />
            </label>
            <label>
              Response path (e.g. data.reply)
              <input value={form.response_path} onChange={set("response_path")} />
            </label>
          </>
        )}
      </div>
      <label>
        System prompt {form.connector === "http_json" ? "(only used to recognise leaks)" : "(sent with a canary added)"}
        <textarea rows={3} value={form.system_prompt} onChange={set("system_prompt")} />
      </label>
      <div className="grid">
        <label>
          Secrets that must never appear in output (one per line)
          <textarea rows={2} value={form.secrets} onChange={set("secrets")} />
        </label>
        <label>
          Tools the application can call (one per line, end with * if sensitive)
          <textarea rows={2} value={form.tools} onChange={set("tools")} placeholder={"search_orders\nissue_refund*"} />
        </label>
      </div>
      <label className="check">
        <input type="checkbox" checked={form.authorized}
          onChange={(e) => setForm({ ...form, authorized: e.target.checked })} />
        I own this system or have written permission to security-test it.
      </label>
      {error && <p className="error-text">{error}</p>}
      <button type="submit" disabled={busy || !form.authorized}>
        {busy ? "Saving..." : "Register target"}
      </button>
    </form>
  );
}

const loadTargets = () => api.targets();

function TargetsView({ open }: { open: (id: string) => void }) {
  const { data, error, reload } = useLoader<Target[]>(loadTargets);
  const [actionError, setActionError] = useState("");

  async function run(target: Target) {
    setActionError("");
    try {
      open((await api.startAssessment(target.id, 2)).id);
    } catch (e) {
      setActionError((e as Error).message);
    }
  }
  async function remove(target: Target) {
    if (!window.confirm(`Delete "${target.config.name}" and all of its assessments?`)) return;
    try {
      await api.deleteTarget(target.id);
      reload();
    } catch (e) {
      setActionError((e as Error).message);
    }
  }

  return (
    <>
      <h2>Targets</h2>
      {(error || actionError) && <p className="error-text">{error || actionError}</p>}
      {data && data.length > 0 && (
        <table>
          <thead>
            <tr>
              <th>Name</th>
              <th>Connector</th>
              <th>Endpoint</th>
              <th />
            </tr>
          </thead>
          <tbody>
            {data.map((t) => (
              <tr key={t.id}>
                <td>{t.config.name}</td>
                <td>{t.config.connector}</td>
                <td className="mono">
                  {t.config.connector === "demo" ? `demo (${t.config.demo_profile})` : t.config.endpoint}
                </td>
                <td className="actions">
                  <button onClick={() => run(t)}>Run assessment</button>
                  <button className="secondary" onClick={() => remove(t)}>
                    Delete
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      {data && data.length === 0 && <p className="muted">No targets registered yet.</p>}
      <TargetForm onCreated={reload} />
    </>
  );
}

function FindingCard({ finding }: { finding: Finding }) {
  const [showEvidence, setShowEvidence] = useState(false);
  return (
    <div className="card finding">
      <h3>
        <Badge severity={finding.severity} /> {finding.title}
        <span className="score">{finding.score}/10</span>
      </h3>
      <p className="muted">
        <span className="mono">{finding.probe_id}</span> · succeeded {finding.hits}/{finding.runs} attempts ·{" "}
        {finding.owasp} · {finding.atlas}
      </p>
      <p>{finding.description}</p>
      <p>
        <strong>Impact.</strong> {finding.impact}
      </p>
      <p>
        <strong>Remediation.</strong> {finding.remediation}
      </p>
      <button className="secondary" onClick={() => setShowEvidence(!showEvidence)}>
        {showEvidence ? "Hide" : "Show"} evidence ({finding.evidence.length})
      </button>
      {showEvidence &&
        finding.evidence.map((ev, i) => (
          <div key={i} className="evidence">
            <p className="muted">
              Case <span className="mono">{ev.case_id}</span>, attempt {ev.attempt} —{" "}
              {ev.detections.map((d) => `${d.detector}: ${d.detail}`).join("; ")}
            </p>
            {ev.transcript.map((m, j) => (
              <div key={j} className={`turn ${m.role}`}>
                <div className="role">{m.role}</div>
                <pre>{m.content}</pre>
              </div>
            ))}
          </div>
        ))}
    </div>
  );
}

function AssessmentView({ id }: { id: string }) {
  const load = useCallback(() => api.assessment(id), [id]);
  const [active, setActive] = useState(true);
  const { data, error } = useLoader<Assessment>(load, active ? 1500 : undefined);
  const [downloadError, setDownloadError] = useState("");
  useEffect(() => {
    if (data && (data.status === "completed" || data.status === "failed")) setActive(false);
  }, [data]);

  if (error) return <p className="error-text">Could not load assessment: {error}</p>;
  if (!data) return <p className="muted">Loading...</p>;
  const result = data.result;
  const download = (format: "html" | "md" | "json") =>
    api.downloadReport(id, format).catch((e: Error) => setDownloadError(e.message));

  return (
    <>
      <h2>Assessment: {data.target_name}</h2>
      <p className="muted">Started {when(data.created_at)}</p>
      {(data.status === "queued" || data.status === "running") && (
        <div className="card">
          <p>
            Running attacks... {data.done}/{data.total || "?"}
          </p>
          <div className="bar">
            <div className="bar-fill low" style={{ width: `${data.total ? (100 * data.done) / data.total : 0}%` }} />
          </div>
        </div>
      )}
      {data.status === "failed" && <p className="error-text">Assessment failed: {data.error}</p>}
      {data.status === "completed" && result && (
        <>
          <div className="tiles">
            <div className={`tile ${(data.risk_rating ?? "").split(" ")[0]}`}>
              <div className="tile-value">{data.risk_score}</div>
              <div className="tile-label">risk / 100 ({data.risk_rating})</div>
            </div>
            <div className="tile">
              <div className="tile-value">{result.findings.length}</div>
              <div className="tile-label">findings</div>
            </div>
            <div className="tile">
              <div className="tile-value">{result.outcomes.filter((o) => o.status === "passed").length}</div>
              <div className="tile-label">probes passed</div>
            </div>
          </div>
          <p className="actions">
            Report:
            <button className="secondary" onClick={() => download("html")}>HTML</button>
            <button className="secondary" onClick={() => download("md")}>Markdown</button>
            <button className="secondary" onClick={() => download("json")}>JSON</button>
          </p>
          {downloadError && <p className="error-text">{downloadError}</p>}

          <h2>Probe results</h2>
          <table>
            <thead>
              <tr>
                <th>Probe</th>
                <th>Category</th>
                <th>Result</th>
                <th>Successful attacks</th>
                <th>Note</th>
              </tr>
            </thead>
            <tbody>
              {result.outcomes.map((o) => (
                <tr key={o.probe_id}>
                  <td>{o.title}</td>
                  <td>{o.category.replace(/_/g, " ")}</td>
                  <td>
                    <span className={`status ${o.status}`}>{o.status}</span>
                  </td>
                  <td>{o.runs ? `${o.hits}/${o.runs}` : "-"}</td>
                  <td>{o.note}</td>
                </tr>
              ))}
            </tbody>
          </table>
          <p className="muted">
            A passed probe means these specific attacks did not succeed in this run. It is not proof the
            application is secure.
          </p>

          <h2>Findings</h2>
          {result.findings.length === 0 && <p className="muted">No attacks succeeded.</p>}
          {result.findings.map((f) => (
            <FindingCard key={f.probe_id} finding={f} />
          ))}
        </>
      )}
    </>
  );
}

export default function App() {
  const [view, setView] = useState<View>({ name: "dashboard" });
  const open = (id: string) => setView({ name: "assessment", id });
  return (
    <>
      <header>
        <h1>MindBreaker</h1>
        <nav>
          <button className={view.name === "dashboard" ? "active" : ""} onClick={() => setView({ name: "dashboard" })}>
            Dashboard
          </button>
          <button className={view.name === "targets" ? "active" : ""} onClick={() => setView({ name: "targets" })}>
            Targets
          </button>
        </nav>
      </header>
      <main>
        {view.name === "dashboard" && <DashboardView open={open} />}
        {view.name === "targets" && <TargetsView open={open} />}
        {view.name === "assessment" && <AssessmentView key={view.id} id={view.id} />}
      </main>
    </>
  );
}
