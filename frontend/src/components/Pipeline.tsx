import { CheckCircle2, Circle, XCircle } from "lucide-react";
import { Link } from "react-router-dom";
import { Alert, VersionBadge } from "./ui";

export interface ValidationEntry { message: string; file?: string | null; line?: number | null; object?: string | null; suggestion?: string | null }
export interface Version {
  id: number; status: string; summary: string; created_at: string; errors: ValidationEntry[]; warnings: ValidationEntry[];
  steps: { step: string; status: string; detail: string; time: string }[]; validation_output?: string;
  created_by?: string; applied_by?: string; applied_at?: string; rollback_of_version?: number | null;
}

const FLOW = ["validate", "backup", "install", "validate-live", "reload", "verify"];
const LABEL: Record<string, string> = { validate: "Validate", backup: "Backup", install: "Install", "validate-live": "Validate live", reload: "Reload", verify: "Verify" };

export function PipelineSteps({ steps }: { steps: Version["steps"] }) {
  const byName: Record<string, string> = {};
  for (const s of steps || []) byName[s.step] = s.status;
  const restored = !!byName["restore-previous"];
  return (
    <div className="pipeline" aria-label="Configuration pipeline">
      {FLOW.map((n, i) => {
        const st = byName[n];
        const cls = st === "ok" || st === "skipped" ? "ok" : st === "failed" ? "failed" : "";
        const Icon = cls === "ok" ? CheckCircle2 : cls === "failed" ? XCircle : Circle;
        return <span key={n} className="row" style={{ gap: 6 }}><span className={`p-step ${cls}`}><Icon size={13} />{LABEL[n]}</span>{i < FLOW.length - 1 && <span className="faint">&rarr;</span>}</span>;
      })}
      {restored && <span className="p-step failed">Previous configuration restored</span>}
    </div>
  );
}

export function ValidationList({ items, kind = "error" }: { items: ValidationEntry[]; kind?: "error" | "warning" }) {
  if (!items?.length) return null;
  return (
    <div className="error-list">
      {items.map((e, i) => (
        <div key={i} className={`error-item ${kind === "warning" ? "warning" : ""}`}>
          <div><strong>{kind === "error" ? "Error" : "Warning"}:</strong> {e.message}</div>
          <div className="meta">
            {e.file && <span>File: <code>{e.file}</code></span>}
            {e.line && <span>Line: {e.line}</span>}
            {e.object && <span>Object: {e.object}</span>}
          </div>
          {e.suggestion && <div className="fix">Suggested fix: {e.suggestion}</div>}
        </div>
      ))}
    </div>
  );
}

export function VersionResult({ v }: { v: Version }) {
  const ok = v.status === "applied" || v.status === "validated";
  return (
    <div className="stack">
      <div className="row between">
        <div className="row"><strong>Version {v.id}</strong><VersionBadge status={v.status} /></div>
        <Link to={`/config/versions/${v.id}`}>Open version details</Link>
      </div>
      {v.status === "applied" && <Alert kind="success">Configuration validated, backed up, applied and Nagios reloaded successfully.</Alert>}
      {v.status === "validated" && <Alert kind="success">Configuration is valid. Nothing was applied.</Alert>}
      {v.status === "validation_failed" && <Alert kind="error">Validation failed - the configuration was <strong>not applied</strong>. The running Nagios configuration is unchanged.</Alert>}
      {v.status === "apply_failed" && <Alert kind="error">Apply failed - the previous configuration was restored.</Alert>}
      {v.steps?.length > 0 && <PipelineSteps steps={v.steps} />}
      {!ok && <ValidationList items={v.errors} />}
      {v.warnings?.length > 0 && (
        <details><summary className="muted">{v.warnings.length} warning(s)</summary><div className="mt"><ValidationList items={v.warnings} kind="warning" /></div></details>
      )}
    </div>
  );
}
