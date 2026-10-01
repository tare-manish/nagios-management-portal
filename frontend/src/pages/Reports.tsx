import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Link, useNavigate } from "react-router-dom";
import { Download, Printer } from "lucide-react";
import { api, download } from "../lib/api";
import { ENVIRONMENTS, envLabel, fmtDate, pct } from "../lib/format";
import { Card, DataTable, ErrorBox, Kpi, Loading, Meter, PageHeader, type Column } from "../components/ui";
import { ChangeDiff } from "./ServerDetail";
import { RankBars, StatusBar } from "../components/charts";

const availTone = (v: number) => (v >= 99.9 ? "good" : v >= 99 ? "warning" : "critical") as "good" | "warning" | "critical";
const utilTone = (v: number) => (v >= 90 ? "critical" : v >= 80 ? "warning" : "series") as "critical" | "warning" | "series";

function usePeriod(defDays = 30) {
  const [days, setDays] = useState(String(defDays));
  const [from, setFrom] = useState("");
  const [to, setTo] = useState("");
  const params = days === "custom" ? { from: from ? new Date(from).toISOString() : undefined, to: to ? new Date(to).toISOString() : undefined }
    : { from: new Date(Date.now() - Number(days) * 86400_000).toISOString() };
  const ui = (
    <>
      <select className="input" value={days} onChange={(e) => setDays(e.target.value)}>
        {[["1", "Last 24 hours"], ["7", "Last 7 days"], ["30", "Last 30 days"], ["90", "Last 90 days"], ["365", "Last 12 months"], ["custom", "Custom range"]].map(([v, l]) => <option key={v} value={v}>{l}</option>)}
      </select>
      {days === "custom" && <><input className="input" type="date" value={from} onChange={(e) => setFrom(e.target.value)} /><input className="input" type="date" value={to} onChange={(e) => setTo(e.target.value)} /></>}
    </>
  );
  return { params, ui, key: `${days}-${from}-${to}` };
}

function exportUrl(base: string, params: Record<string, any>) {
  const qs = new URLSearchParams(Object.entries({ ...params, format: "csv" }).filter(([, v]) => v !== undefined && v !== "").map(([k, v]) => [k, String(v)]));
  return `${base}?${qs}`;
}

function ReportActions({ csv }: { csv: string }) {
  return <><button className="btn" onClick={() => download(csv)}><Download size={15} />CSV</button><button className="btn" onClick={() => window.print()}><Printer size={15} />Print / PDF</button></>;
}

export function AvailabilityReport() {
  const nav = useNavigate();
  const p = usePeriod(30);
  const [env, setEnv] = useState("");
  const [view, setView] = useState<"hosts" | "services">("hosts");
  const params = { ...p.params, environment: env };
  const q = useQuery({ queryKey: ["rep-av", view, p.key, env], queryFn: () => api.get(view === "hosts" ? "/api/reports/availability" : "/api/reports/service-availability", params) });
  const rows: any[] = q.data?.data ?? [];
  const hostCols: Column<any>[] = [
    { key: "hostname", header: "Server", render: (r) => <Link to={`/servers/${r.server_id}`}>{r.hostname}</Link> }, { key: "display_name", header: "Name" },
    { key: "environment", header: "Environment", render: (r) => envLabel(r.environment) },
    { key: "availability_pct", header: "Availability", render: (r) => (r.availability_pct == null ? <span className="faint">no data</span> : <span className={r.availability_pct < 99 ? "" : ""}>{pct(r.availability_pct, 3)}</span>) },
    { key: "downtime_minutes", header: "Downtime (min)", className: "num" }, { key: "undetermined_minutes", header: "No data (min)", className: "num" },
  ];
  const svcCols: Column<any>[] = [
    { key: "host", header: "Host" }, { key: "service", header: "Service" },
    { key: "ok_pct", header: "OK %", render: (r) => pct(r.ok_pct) }, { key: "warning_pct", header: "Warning %", render: (r) => pct(r.warning_pct) },
    { key: "critical_pct", header: "Critical %", render: (r) => pct(r.critical_pct) }, { key: "unknown_pct", header: "Unknown %", render: (r) => pct(r.unknown_pct) },
  ];
  const withData = rows.filter((r) => r.availability_pct != null);
  const avg = view === "hosts" && withData.length ? withData.reduce((a, r) => a + r.availability_pct, 0) / withData.length : null;
  return (
    <div className="stack">
      <PageHeader title="Availability report" subtitle="Calculated from Nagios HARD state history (event log and archives)." actions={<ReportActions csv={exportUrl(view === "hosts" ? "/api/reports/availability" : "/api/reports/service-availability", params)} />} />
      <div className="toolbar">
        <div className="btn-group"><button className={`btn sm ${view === "hosts" ? "active" : ""}`} onClick={() => setView("hosts")}>Servers</button><button className={`btn sm ${view === "services" ? "active" : ""}`} onClick={() => setView("services")}>Services</button></div>
        {p.ui}
        <select className="input" value={env} onChange={(e) => setEnv(e.target.value)}><option value="">All environments</option>{ENVIRONMENTS.map((o) => <option key={o.value} value={o.value}>{o.label}</option>)}</select>
      </div>
      <ErrorBox error={q.error} />
      {view === "hosts" && <div className="grid grid-4">
        <Kpi label="Average availability" value={avg != null ? pct(avg, 3) : "-"} color="var(--series-1)" />
        <Kpi label="Servers" value={rows.length} color="var(--accent)" />
        <Kpi label="Servers below 99%" value={withData.filter((r) => r.availability_pct < 99).length} color="var(--warning)" />
        <Kpi label="Total downtime" value={`${rows.reduce((a, r) => a + (r.downtime_minutes || 0), 0).toFixed(0)} min`} color="var(--critical)" />
      </div>}
      {view === "hosts" && withData.length > 0 && <div className="grid grid-2">
        <Card title="Lowest availability" actions={<span className="faint small" title="green ≥ 99.9% · amber ≥ 99% · red below">worst 10</span>}>
          <RankBars uom="%" max={100} rows={[...withData].sort((a, b) => a.availability_pct - b.availability_pct).map((r) => ({
            key: r.server_id, label: r.hostname, sub: `${envLabel(r.environment)} · ${(r.downtime_minutes || 0).toFixed(0)} min down`, value: +r.availability_pct.toFixed(3), tone: availTone(r.availability_pct) }))}
            onClickRow={(r) => nav(`/servers/${r.key}`)} />
        </Card>
        <Card title="Most downtime" actions={<span className="faint small">minutes in period</span>}>
          <RankBars uom="min" empty="No downtime in this period" rows={[...withData].filter((r) => r.downtime_minutes > 0).sort((a, b) => b.downtime_minutes - a.downtime_minutes).map((r) => ({
            key: r.server_id, label: r.hostname, sub: envLabel(r.environment), value: Math.round(r.downtime_minutes), tone: "critical" as const }))}
            onClickRow={(r) => nav(`/servers/${r.key}`)} />
        </Card>
      </div>}
      <Card flush>{q.isLoading ? <Loading /> : <DataTable rows={rows} columns={view === "hosts" ? hostCols : svcCols} rowKey={(r) => r.hostname ?? `${r.host}/${r.service}`} initialSort={{ key: view === "hosts" ? "availability_pct" : "ok_pct", dir: "asc" }} pageSize={50} />}</Card>
    </div>
  );
}

export function SlaReport() {
  const p = usePeriod(30);
  const [env, setEnv] = useState("");
  const params = { ...p.params, environment: env };
  const q = useQuery({ queryKey: ["rep-sla", p.key, env], queryFn: () => api.get("/api/reports/sla", params) });
  const cols: Column<any>[] = [
    { key: "hostname", header: "Server", render: (r) => <Link to={`/servers/${r.server_id}`}>{r.hostname}</Link> },
    { key: "environment", header: "Environment", render: (r) => envLabel(r.environment) },
    { key: "target_pct", header: "Target", render: (r) => pct(r.target_pct, 2) },
    { key: "availability_pct", header: "Actual", render: (r) => pct(r.availability_pct, 3) },
    { key: "downtime_minutes", header: "Downtime (min)", className: "num" }, { key: "allowed_downtime_minutes", header: "Allowed (min)", className: "num" },
    { key: "status", header: "SLA", render: (r) => <span className={`badge ${r.status === "met" ? "good" : r.status === "breached" ? "critical" : ""}`}><span className="dot" />{r.status}</span> },
  ];
  const m = q.data?.meta;
  return (
    <div className="stack">
      <PageHeader title="SLA report" subtitle="Availability against the per-environment targets in System Settings." actions={<ReportActions csv={exportUrl("/api/reports/sla", params)} />} />
      <div className="toolbar">{p.ui}<select className="input" value={env} onChange={(e) => setEnv(e.target.value)}><option value="">All environments</option>{ENVIRONMENTS.map((o) => <option key={o.value} value={o.value}>{o.label}</option>)}</select></div>
      <ErrorBox error={q.error} />
      {m && (m.met + m.breached) > 0 && <Card title="SLA compliance">
        <StatusBar total={(q.data?.data ?? []).length} caption={<span className="muted small">{m.met} of {(q.data?.data ?? []).length} servers met their target</span>} parts={[
          { key: "b", label: "Breached", value: m.breached, tone: "critical" },
          { key: "n", label: "No data", value: Math.max(0, (q.data?.data ?? []).length - m.met - m.breached), tone: "neutral" },
          { key: "m", label: "Met", value: m.met, tone: "good" },
        ]} />
      </Card>}
      {m && <div className="grid grid-3"><Kpi label="SLA met" value={m.met} color="var(--good)" /><Kpi label="SLA breached" value={m.breached} color="var(--critical)" /><Kpi label="Targets" value={<span className="small">{Object.entries(m.targets ?? {}).map(([k, v]) => `${envLabel(k)} ${v}%`).join(" · ")}</span>} color="var(--accent)" /></div>}
      <Card flush>{q.isLoading ? <Loading /> : <DataTable rows={q.data?.data ?? []} columns={cols} rowKey={(r) => r.server_id} initialSort={{ key: "status", dir: "asc" }} pageSize={50} />}</Card>
    </div>
  );
}

export function PerformanceReport() {
  const p = usePeriod(7);
  const [env, setEnv] = useState("");
  const params = { ...p.params, environment: env };
  const q = useQuery({ queryKey: ["rep-perf", p.key, env], queryFn: () => api.get("/api/reports/performance", params) });
  const nav = useNavigate();
  const m = (v: any) => <Meter value={v} />;
  const prow: any[] = q.data?.data ?? [];
  const top = (key: string) => [...prow].filter((r) => r[key] != null).sort((a, b) => b[key] - a[key]).map((r) => ({
    key: r.server_id, label: r.hostname, sub: `avg ${Math.round(r[key.replace("_max", "_avg")] ?? 0)}%`, value: +(+r[key]).toFixed(1), tone: utilTone(r[key]) }));
  const cols: Column<any>[] = [
    { key: "hostname", header: "Server", render: (r) => <Link to={`/servers/${r.server_id}?tab=performance`}>{r.hostname}</Link> },
    { key: "environment", header: "Environment", render: (r) => envLabel(r.environment) },
    { key: "cpu_avg", header: "CPU avg", render: (r) => m(r.cpu_avg) }, { key: "cpu_max", header: "CPU max", render: (r) => m(r.cpu_max) },
    { key: "memory_avg", header: "Memory avg", render: (r) => m(r.memory_avg) }, { key: "memory_max", header: "Memory max", render: (r) => m(r.memory_max) },
    { key: "disk_avg", header: "Disk avg", render: (r) => m(r.disk_avg) }, { key: "disk_max", header: "Disk max", render: (r) => m(r.disk_max) },
  ];
  return (
    <div className="stack">
      <PageHeader title="Performance report" subtitle="Average and peak utilisation from sampled performance data." actions={<ReportActions csv={exportUrl("/api/reports/performance", params)} />} />
      <div className="toolbar">{p.ui}<select className="input" value={env} onChange={(e) => setEnv(e.target.value)}><option value="">All environments</option>{ENVIRONMENTS.map((o) => <option key={o.value} value={o.value}>{o.label}</option>)}</select></div>
      <ErrorBox error={q.error} />
      {prow.length > 0 && <div className="grid grid-3">
        {[["cpu_max", "Peak CPU"], ["memory_max", "Peak memory"], ["disk_max", "Fullest disk"]].map(([k, t]) => (
          <Card key={k} title={t} actions={<span className="faint small">top 8</span>}>
            <RankBars uom="%" max={100} limit={8} rows={top(k)} onClickRow={(r) => nav(`/servers/${r.key}?tab=performance`)} />
          </Card>
        ))}
      </div>}
      <Card flush>{q.isLoading ? <Loading /> : <DataTable rows={q.data?.data ?? []} columns={cols} rowKey={(r) => r.server_id} pageSize={50} />}</Card>
    </div>
  );
}

export function HealthReport() {
  const [days, setDays] = useState(7);
  const q = useQuery({ queryKey: ["rep-health", days], queryFn: () => api.get("/api/reports/health", { days }) });
  const d = q.data?.data;
  const list = (title: string, rows: any[], unit: string) => (
    <Card title={`${title} (${rows.length})`} flush>
      <DataTable rows={rows} rowKey={(r) => r.server_id} empty="None" columns={[
        { key: "hostname", header: "Server", render: (r: any) => <Link to={`/servers/${r.server_id}`}>{r.hostname}</Link> },
        { key: "environment", header: "Environment", render: (r: any) => envLabel(r.environment) },
        { key: "value", header: unit === "%" ? "Current" : "Alerts", render: (r: any) => (unit === "%" ? <Meter value={r.value} warn={0} crit={95} /> : r.value) }]} />
    </Card>
  );
  return (
    <div className="stack">
      <PageHeader title="Infrastructure health" subtitle={d && `Thresholds: CPU ${d.thresholds.cpu}%, memory ${d.thresholds.memory}%, disk ${d.thresholds.disk}% (System Settings)`}
        actions={<ReportActions csv={`/api/reports/health?format=csv&days=${days}`} />} />
      <div className="toolbar"><span className="muted">Repeated failures in the last</span><select className="input" value={days} onChange={(e) => setDays(Number(e.target.value))}>{[1, 7, 30].map((n) => <option key={n} value={n}>{n} day(s)</option>)}</select></div>
      <ErrorBox error={q.error} />
      {q.isLoading ? <Loading /> : <div className="grid grid-2">
        {list("High disk usage", d.high_disk, "%")}{list("High memory usage", d.high_memory, "%")}
        {list("High CPU usage", d.high_cpu, "%")}{list("Repeated failures (3+ HARD alerts)", d.repeated_failures, "n")}
      </div>}
    </div>
  );
}

export function AuditReport() {
  const [f, setF] = useState({ q: "", user: "", action: "", entity_type: "", result: "" });
  const [page, setPage] = useState(1);
  const params = { ...f, page, page_size: 50 };
  const q = useQuery({ queryKey: ["audit", params], queryFn: () => api.get("/api/audit", params) });
  const set = (k: string, v: string) => { setF({ ...f, [k]: v }); setPage(1); };
  const cols: Column<any>[] = [
    { key: "time", header: "Date/time", sortable: false, render: (r) => <span className="nowrap small">{fmtDate(r.time, { seconds: true })}</span> },
    { key: "user", header: "User", sortable: false }, { key: "action", header: "Action", sortable: false, render: (r) => <code>{r.action}</code> },
    { key: "entity", header: "Object", sortable: false, render: (r) => (r.entity_type ? `${r.entity_type}: ${r.entity_name ?? r.entity_id ?? ""}` : "-") },
    { key: "diff", header: "Old / new value", sortable: false, render: (r) => <ChangeDiff old={r.old} next={r.new} /> },
    { key: "ip", header: "IP address", sortable: false },
    { key: "result", header: "Result", sortable: false, render: (r) => <span className={`badge ${r.result === "success" ? "good" : r.result === "denied" ? "serious" : "critical"}`}>{r.result}</span> },
    { key: "detail", header: "Detail", sortable: false, render: (r) => <span className="small muted">{r.detail}</span> },
  ];
  const meta = q.data?.meta;
  return (
    <div className="stack">
      <PageHeader title="Audit log" subtitle="Every important action with user, time, IP, old and new values (secrets are never recorded)." actions={<ReportActions csv={exportUrl("/api/audit", f)} />} />
      <div className="toolbar">
        <input className="input" placeholder="Search object / detail" value={f.q} onChange={(e) => set("q", e.target.value)} />
        <input className="input" placeholder="User" value={f.user} onChange={(e) => set("user", e.target.value)} />
        <input className="input" placeholder="Action prefix (e.g. server.)" value={f.action} onChange={(e) => set("action", e.target.value)} />
        <select className="input" value={f.result} onChange={(e) => set("result", e.target.value)}><option value="">Any result</option><option>success</option><option>failure</option><option>denied</option></select>
      </div>
      <ErrorBox error={q.error} />
      <Card flush>{q.isLoading ? <Loading /> : <DataTable rows={q.data?.data ?? []} columns={cols} rowKey={(r) => r.id} serverPaging={{ page, pages: meta?.pages ?? 1, total: meta?.total ?? 0, pageSize: 50, onPage: setPage }} />}</Card>
    </div>
  );
}
