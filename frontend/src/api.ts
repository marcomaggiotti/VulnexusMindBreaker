export type Severity = "critical" | "high" | "medium" | "low" | "info";
export const SEVERITIES: Severity[] = ["critical", "high", "medium", "low", "info"];

export interface Target {
  id: string;
  created_at: string;
  config: {
    name: string;
    description: string;
    connector: "openai_chat" | "http_json" | "demo";
    endpoint: string | null;
    model: string | null;
    demo_profile: string;
    tools: { name: string; sensitive: boolean }[];
  };
}

export interface Evidence {
  case_id: string;
  attempt: number;
  transcript: { role: string; content: string }[];
  detections: { detector: string; detail: string }[];
}

export interface Finding {
  probe_id: string;
  title: string;
  category: string;
  severity: Severity;
  score: number;
  success_rate: number;
  hits: number;
  runs: number;
  owasp: string;
  atlas: string;
  description: string;
  impact: string;
  remediation: string;
  evidence: Evidence[];
}

export interface Outcome {
  probe_id: string;
  title: string;
  category: string;
  status: "vulnerable" | "passed" | "skipped" | "error";
  runs: number;
  hits: number;
  errors: number;
  note: string;
}

export interface Assessment {
  id: string;
  target_id: string;
  target_name: string;
  status: "queued" | "running" | "completed" | "failed";
  done: number;
  total: number;
  error: string | null;
  created_at: string;
  finished_at: string | null;
  risk_score: number | null;
  risk_rating: string | null;
  severity_counts: Record<Severity, number> | null;
  result?: { outcomes: Outcome[]; findings: Finding[] } | null;
}

export interface Dashboard {
  targets: number;
  assessments: number;
  running: number;
  open_findings: Record<Severity, number>;
  findings_by_category: Record<string, number>;
  target_risk: {
    target_id: string;
    target_name: string;
    assessment_id: string;
    risk_score: number;
    risk_rating: string;
    finished_at: string;
  }[];
  recent: Assessment[];
}

const KEY_STORAGE = "mb_api_key";

function apiKey(): string {
  try {
    return sessionStorage.getItem(KEY_STORAGE) ?? "";
  } catch {
    return "";
  }
}

async function request(path: string, init: RequestInit = {}, retry = true): Promise<Response> {
  const headers: Record<string, string> = { "Content-Type": "application/json" };
  if (apiKey()) headers["X-API-Key"] = apiKey();
  const response = await fetch(`/api${path}`, { ...init, headers });
  if (response.status === 401 && retry) {
    const key = window.prompt("This server requires an API key (X-API-Key):");
    if (key) {
      try {
        sessionStorage.setItem(KEY_STORAGE, key);
      } catch {
        /* storage unavailable: key applies to this request only */
      }
      return request(path, init, false);
    }
  }
  if (!response.ok) {
    let detail = `${response.status} ${response.statusText}`;
    try {
      const body = await response.json();
      if (typeof body.detail === "string") detail = body.detail;
      else if (Array.isArray(body.detail))
        detail = body.detail.map((d: { msg: string }) => d.msg).join("; ");
    } catch {
      /* non-JSON error body */
    }
    throw new Error(detail);
  }
  return response;
}

async function json<T>(path: string, init?: RequestInit): Promise<T> {
  return (await request(path, init)).json() as Promise<T>;
}

export const api = {
  dashboard: () => json<Dashboard>("/dashboard"),
  targets: () => json<Target[]>("/targets"),
  createTarget: (config: unknown) =>
    json<Target>("/targets", { method: "POST", body: JSON.stringify(config) }),
  deleteTarget: (id: string) => request(`/targets/${id}`, { method: "DELETE" }),
  assessments: () => json<Assessment[]>("/assessments"),
  assessment: (id: string) => json<Assessment>(`/assessments/${id}`),
  startAssessment: (target_id: string, attempts: number) =>
    json<Assessment>("/assessments", { method: "POST", body: JSON.stringify({ target_id, attempts }) }),
  async downloadReport(id: string, format: "html" | "md" | "json") {
    const blob = await (await request(`/assessments/${id}/report?format=${format}`)).blob();
    const link = document.createElement("a");
    link.href = URL.createObjectURL(blob);
    link.download = `mindbreaker-${id.slice(0, 8)}.${format}`;
    link.click();
    URL.revokeObjectURL(link.href);
  },
};
