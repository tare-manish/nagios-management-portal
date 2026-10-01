import { useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { Link, useNavigate, useParams } from "react-router-dom";
import { Download, GitCompare, RotateCcw } from "lucide-react";
import { api, download } from "../lib/api";
import { useAuth } from "../lib/auth";
import { fmtDate } from "../lib/format";
import { useConfigAction } from "../components/ConfigAction";
import { PipelineSteps, ValidationList } from "../components/Pipeline";
import { Alert, Card, DataTable, Empty, ErrorBox, Loading, Modal, PageHeader, Tabs, VersionBadge, useUi, type Column } from "../components/ui";
import { ChangeDiff } from "./ServerDetail";

export function PendingPage() {
  const { can } = useAuth();
  const cfg = useConfigAction();
  const q = useQuery({ queryKey: ["pending"], queryFn: () => api.get("/api/config/pending"), refetchInterval: 30_000 });
  const d = q.data?.data;
  const cols: Column<any>[] = [
    { key: "time", header: "Date/time", render: (r) => <span className="nowrap">{fmtDate(r.time)}</span> },
    { key: "user", header: "User" }, { key: "action", header: "Change", render: (r) => <span className="badge info">{r.action.replace(/_/g, " ")}</span> },
    { key: "entity_type", header: "Object", render: (r) => <>{r.entity_type.replace(/_/g, " ")}: <strong>{r.entity_type === "server" && r.entity_id ? <Link to={`/servers/${r.entity_id}`}>{r.entity_name}</Link> : r.entity_name}</strong></> },
    { key: "diff", header: "Details", sortable: false, render: (r) => <ChangeDiff old={r.old} next={r.new} /> },
  ];
  return (
    <div className="stack">
      <PageHeader title="Pending changes" subtitle="Saved in the portal but not yet applied to Nagios. Applying runs: generate → validate → backup → install → reload → verify."
        actions={<>{can("config.validate") && <button className="btn" onClick={cfg.validateAll}>Validate</button>}{can("config.apply") && <button className="btn primary" onClick={cfg.applyAll}>Apply to Nagios</button>}</>} />
      <ErrorBox error={q.error} />
      {d?.current_version && <Alert kind="info">Running configuration: <Link to={`/config/versions/${d.current_version.id}`}>version {d.current_version.id}</Link> applied {fmtDate(d.current_version.applied_at)} by {d.current_version.applied_by ?? "-"} - {d.current_version.summary}</Alert>}
      {d?.drafts > 0 && <Alert kind="warning">{d.drafts} server(s) are in Draft and will not be included until saved without draft.</Alert>}
      <Card title={`Changes (${d?.count ?? 0})`} flush>{q.isLoading ? <Loading /> : <DataTable rows={d?.changes ?? []} columns={cols} rowKey={(r) => r.id} empty="No pending changes - Nagios is in sync with the portal." />}</Card>
      {cfg.node}
    </div>
  );
}

export function VersionsPage() {
  const nav = useNavigate();
  const [status, setStatus] = useState("");
  const [page, setPage] = useState(1);
  const [cmp, setCmp] = useState<number[]>([]);
  const q = useQuery({ queryKey: ["versions", status, page], queryFn: () => api.get("/api/config/versions", { status, page, page_size: 25 }) });
  const toggle = (id: number) => setCmp((c) => (c.includes(id) ? c.filter((x) => x !== id) : [...c, id].slice(-2)));
  const cols: Column<any>[] = [
    { key: "cmp", header: "Compare", sortable: false, render: (r) => <input type="checkbox" checked={cmp.includes(r.id)} onClick={(e) => e.stopPropagation()} onChange={() => toggle(r.id)} aria-label="select for compare" /> },
    { key: "id", header: "Version", render: (r) => <strong>{r.id}</strong> },
    { key: "created_at", header: "Date", render: (r) => <span className="nowrap">{fmtDate(r.created_at)}</span> },
    { key: "created_by", header: "User" }, { key: "summary", header: "Change" },
    { key: "change_count", header: "Changes", className: "num" },
    { key: "status", header: "Status", render: (r) => <VersionBadge status={r.status} /> },
  ];
  const meta = q.data?.meta;
  const sorted = [...cmp].sort((a, b) => a - b);
  return (
    <div>
      <PageHeader title="Configuration versions" subtitle="Every generated configuration is versioned with its files, validation result, backup and a restorable snapshot."
        actions={<button className="btn" disabled={cmp.length !== 2} onClick={() => nav(`/config/versions/${sorted[1]}?compare=${sorted[0]}`)}><GitCompare size={15} />Compare selected</button>} />
      <div className="toolbar"><select className="input" value={status} onChange={(e) => { setStatus(e.target.value); setPage(1); }}><option value="">All statuses</option>{["applied", "superseded", "validated", "validation_failed", "apply_failed", "generated"].map((s) => <option key={s} value={s}>{s.replace(/_/g, " ")}</option>)}</select></div>
      <ErrorBox error={q.error} />
      <Card flush>{q.isLoading ? <Loading /> : <DataTable rows={q.data?.data ?? []} columns={cols} rowKey={(r) => r.id} onRowClick={(r) => nav(`/config/versions/${r.id}`)}
        serverPaging={{ page, pages: meta?.pages ?? 1, total: meta?.total ?? 0, pageSize: 25, onPage: setPage }} />}</Card>
    </div>
  );
}

function DiffView({ diff }: { diff: string }) {
  return <pre className="code">{diff.split("\n").map((l, i) => <span key={i} className={l.startsWith("+") && !l.startsWith("+++") ? "diff-add" : l.startsWith("-") && !l.startsWith("---") ? "diff-del" : l.startsWith("@@") ? "diff-hunk" : ""}>{l || " "}{"\n"}</span>)}</pre>;
}

export function VersionDetail() {
  const { id } = useParams();
  const nav = useNavigate();
  const qc = useQueryClient();
  const { can } = useAuth();
  const { confirm, apiError } = useUi();
  const cfg = useConfigAction();
  const params = new URLSearchParams(location.search);
  const [tab, setTab] = useState(params.get("compare") ? "compare" : "summary");
  const [cmpWith, setCmpWith] = useState<string>(params.get("compare") ?? String(Number(id) - 1));
  const [file, setFile] = useState<string | null>(null);
  const q = useQuery({ queryKey: ["version", id], queryFn: () => api.get(`/api/config/versions/${id}`) });
  const diff = useQuery({ queryKey: ["diff", cmpWith, id], queryFn: () => api.get(`/api/config/versions/${cmpWith}/diff/${id}`), enabled: tab === "compare" && Number(cmpWith) > 0 });
  const fileQ = useQuery({ queryKey: ["vfile", id, file], queryFn: () => api.get(`/api/config/versions/${id}/file`, { path: file }), enabled: !!file });
  if (q.isLoading) return <Loading />;
  if (q.error) return <ErrorBox error={q.error} />;
  const v = q.data!.data;
  const rollback = async () => {
    if (!(await confirm({ title: `Roll back to version ${v.id}`, confirmLabel: "Roll back", danger: true,
      message: <>The portal restores the configuration objects (servers, services, credentials, groups) exactly as they were in version {v.id}, regenerates the configuration, validates it, backs up the current configuration and reloads Nagios. Changes made after version {v.id} are undone. Continue?</> }))) return;
    const r = await cfg.run(`Rolling back to version ${v.id}`, () => api.post(`/api/config/versions/${v.id}/rollback`));
    if (r?.data?.id) nav(`/config/versions/${r.data.id}`);
  };
  const applyThis = async () => {
    try { await cfg.run("Apply configuration", () => api.post(`/api/config/versions/${v.id}/apply`)); qc.invalidateQueries({ queryKey: ["version", id] }); } catch (e) { apiError(e); }
  };
  return (
    <div className="stack">
      <PageHeader crumb={<Link to="/config/versions">Configuration versions</Link>} title={<span className="row">Version {v.id}<VersionBadge status={v.status} /></span>} subtitle={v.summary}
        actions={<>
          <button className="btn" onClick={() => download(`/api/config/versions/${v.id}/download`)}><Download size={15} />Download</button>
          {can("config.apply") && ["generated", "validated"].includes(v.status) && <button className="btn" onClick={applyThis}>Apply this version</button>}
          {can("config.rollback") && ["applied", "superseded", "rolled_back"].includes(v.status) && <button className="btn danger" onClick={rollback}><RotateCcw size={15} />Roll back to this version</button>}
        </>} />
      <Tabs active={tab} onChange={setTab} tabs={[{ key: "summary", label: "Summary" }, { key: "files", label: `Files (${v.files.length})` }, { key: "compare", label: "Compare" }, { key: "output", label: "Validation output" }]} />
      {tab === "summary" && (<>
        <div className="grid grid-2">
          <Card title="Details">
            <dl className="dl">
              <dt>Created</dt><dd>{fmtDate(v.created_at, { seconds: true })} by {v.created_by ?? "system"}</dd>
              <dt>Applied</dt><dd>{v.applied_at ? `${fmtDate(v.applied_at, { seconds: true })} by ${v.applied_by ?? "-"}` : "-"}</dd>
              <dt>Status</dt><dd><VersionBadge status={v.status} /></dd>
              <dt>Configuration hash</dt><dd className="mono small">{v.config_hash}</dd>
              {v.rollback_of_version && <><dt>Rollback of</dt><dd><Link to={`/config/versions/${v.rollback_of_version}`}>version {v.rollback_of_version}</Link></dd></>}
              <dt>Backup before apply</dt><dd>{v.backup ? v.backup.name : "-"}</dd>
              {v.legacy_overrides && <><dt>Manual files changed</dt><dd>{v.legacy_overrides.map((o: any) => <div key={o.target} className="mono small">{o.target}</div>)}</dd></>}
            </dl>
          </Card>
          <Card title="Pipeline">
            {v.steps.length ? <PipelineSteps steps={v.steps} /> : <span className="faint">Not applied</span>}
            <table className="table mt"><tbody>{v.steps.map((s: any, i: number) => <tr key={i}><td className="nowrap small">{fmtDate(s.time, { seconds: true })}</td><td>{s.step}</td><td><span className={`badge ${s.status === "ok" ? "good" : s.status === "failed" ? "critical" : ""}`}>{s.status}</span></td><td className="small muted">{s.detail}</td></tr>)}</tbody></table>
          </Card>
        </div>
        {v.errors.length > 0 && <Card title="Errors"><ValidationList items={v.errors} /></Card>}
        {v.warnings.length > 0 && <Card title="Warnings"><ValidationList items={v.warnings} kind="warning" /></Card>}
        <Card title={`Changes included (${v.changes.length})`} flush>
          <DataTable rows={v.changes} rowKey={(r: any) => r.id} empty="No recorded object changes (regeneration)" columns={[
            { key: "time", header: "Time", render: (r: any) => fmtDate(r.time) }, { key: "user", header: "User" },
            { key: "action", header: "Change" }, { key: "entity_name", header: "Object", render: (r: any) => `${r.entity_type}: ${r.entity_name}` },
            { key: "d", header: "Old / new", sortable: false, render: (r: any) => <ChangeDiff old={r.old} next={r.new} /> }]} />
        </Card>
      </>)}
      {tab === "files" && (
        <Card flush>
          <table className="table"><thead><tr><th>File</th><th>SHA-256</th><th className="num">Size</th></tr></thead>
            <tbody>{v.files.map((f: any) => <tr key={f.path} className="clickable" onClick={() => setFile(f.path)}><td className="mono small">{f.path}</td><td className="mono small faint">{f.sha256.slice(0, 16)}</td><td className="num">{f.size}</td></tr>)}</tbody></table>
          {v.files.length === 0 && <Empty>No files (generation failed before files were produced)</Empty>}
        </Card>
      )}
      {tab === "compare" && (
        <div className="stack">
          <div className="row">Compare version <input className="input" style={{ width: 90 }} type="number" value={cmpWith} onChange={(e) => setCmpWith(e.target.value)} /> with version {v.id}</div>
          {diff.isLoading ? <Loading /> : diff.error ? <ErrorBox error={diff.error} /> : (diff.data?.data.files ?? []).length === 0 ? <Empty>No differences</Empty> :
            (diff.data?.data.files ?? []).map((f: any) => <Card key={f.path} title={<span className="row"><span className="mono small">{f.path}</span><span className={`badge ${f.status === "added" ? "good" : f.status === "removed" ? "critical" : "info"}`}>{f.status}</span></span>}><DiffView diff={f.diff} /></Card>)}
        </div>
      )}
      {tab === "output" && <Card><pre className="code">{v.validation_output || "No output recorded"}</pre></Card>}
      {file && <Modal title={file} size="xwide" onClose={() => setFile(null)}>{fileQ.isLoading ? <Loading /> : <pre className="code">{fileQ.data?.data.content}</pre>}</Modal>}
      {cfg.node}
    </div>
  );
}
