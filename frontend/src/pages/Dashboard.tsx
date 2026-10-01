import { useQuery } from "@tanstack/react-query";
import { Link, useNavigate } from "react-router-dom";
import { AlertTriangle, CheckCircle2, HelpCircle, Server, XCircle, Activity, Network } from "lucide-react";
import { api } from "../lib/api";
import { ago, dur, envLabel, fmtDate } from "../lib/format";
import { Alert, Card, Empty, ErrorBox, Kpi, Loading, PageHeader, StateBadge } from "../components/ui";
import { RankBars, StatusBar } from "../components/charts";

function Hero({ value, label, tone }: { value: string; label: string; tone: string }) {
  return <div className="hero-figure"><span className="v" style={{ color: tone }}>{value}</span><span className="l">{label}</span></div>;
}
const pctOf = (n: number, d: number) => (d ? `${+((n / d) * 100).toFixed(1)}%` : "-");

function ProblemTable({ rows, host }: { rows: any[]; host?: boolean }) {
  if (!rows.length) return <Empty>None</Empty>;
  return (
    <table className="table"><tbody>
      {rows.map((r, i) => (
        <tr key={i}>
          <td style={{ width: 110 }}><StateBadge state={r.state} small /></td>
          <td style={{ maxWidth: 200 }}>{r.server_id ? <Link to={`/servers/${r.server_id}`}>{r.host_name}</Link> : r.host_name}{!host && <div className="faint small">{r.service_description}</div>}</td>
          <td className="muted small" style={{ maxWidth: 0, width: "100%", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }} title={r.output}>{r.output}</td>
          <td className="faint small nowrap right">{dur(r.duration_seconds)}</td>
        </tr>
      ))}
    </tbody></table>
  );
}

export default function Dashboard() {
  const nav = useNavigate();
  const q = useQuery({ queryKey: ["dashboard"], queryFn: () => api.get("/api/dashboard"), refetchInterval: 30_000 });
  if (q.isLoading) return <Loading />;
  if (q.error) return <ErrorBox error={q.error} />;
  const d = q.data!.data;
  const h = d.hosts, s = d.services;
  const t = d.top_problems;
  const hostProblems = [...t.down, ...t.unreachable];
  return (
    <div className="stack">
      <PageHeader title="Dashboard" subtitle={<>Live state from Nagios{d.nagios.program_start && <> - Nagios running since {fmtDate(d.nagios.program_start)}</>} - refreshes every 30 s</>} />
      {d.nagios.status_error && <Alert kind="error">Nagios status is not available: {d.nagios.status_error}</Alert>}
      {d.pending_changes > 0 && <Alert kind="warning">{d.pending_changes} configuration change(s) are saved but not yet applied to Nagios. <Link to="/config/pending">Review and apply</Link></Alert>}

      <div className="grid grid-2">
        <Card title="Host health">
          <div className="health-hero">
            <Hero value={pctOf(h.UP, h.total)} label={`${h.UP} of ${h.total} hosts up`} tone={h.DOWN || h.UNREACHABLE ? "var(--critical-text)" : "var(--text)"} />
            <StatusBar total={h.total} parts={[
              { key: "down", label: "Down", value: h.DOWN, tone: "critical", icon: <XCircle size={13} color="var(--critical)" />, onClick: () => nav("/monitoring/hosts?state=DOWN") },
              { key: "unr", label: "Unreachable", value: h.UNREACHABLE, tone: "serious", icon: <Network size={13} color="var(--serious)" />, onClick: () => nav("/monitoring/hosts?state=UNREACHABLE") },
              { key: "pend", label: "Pending", value: h.PENDING ?? 0, tone: "neutral", icon: <HelpCircle size={13} color="var(--text-3)" /> },
              { key: "up", label: "Up", value: h.UP, tone: "good", icon: <CheckCircle2 size={13} color="var(--good)" />, onClick: () => nav("/monitoring/hosts?state=UP") },
            ]} />
          </div>
        </Card>
        <Card title="Service health">
          <div className="health-hero">
            <Hero value={pctOf(s.OK, s.total)} label={`${s.OK} of ${s.total} services OK`} tone={s.CRITICAL ? "var(--critical-text)" : "var(--text)"} />
            <StatusBar total={s.total} parts={[
              { key: "crit", label: "Critical", value: s.CRITICAL, tone: "critical", icon: <XCircle size={13} color="var(--critical)" />, onClick: () => nav("/monitoring/services?state=CRITICAL") },
              { key: "warn", label: "Warning", value: s.WARNING, tone: "warning", icon: <AlertTriangle size={13} color="var(--warning)" />, onClick: () => nav("/monitoring/services?state=WARNING") },
              { key: "unk", label: "Unknown", value: s.UNKNOWN, tone: "unknown", icon: <HelpCircle size={13} color="var(--unknown)" />, onClick: () => nav("/monitoring/services?state=UNKNOWN") },
              { key: "pend", label: "Pending", value: s.PENDING ?? 0, tone: "neutral", icon: <HelpCircle size={13} color="var(--text-3)" /> },
              { key: "ok", label: "OK", value: s.OK, tone: "good", icon: <CheckCircle2 size={13} color="var(--good)" />, onClick: () => nav("/monitoring/services?state=OK") },
            ]} />
          </div>
        </Card>
      </div>

      <div>
        <h3 className="muted mb" style={{ marginBottom: 8 }}>Infrastructure summary</h3>
        <div className="grid grid-6">
          <Kpi label="Total servers" icon={<Server size={14} />} value={h.total} sub={`${d.inventory.servers} servers, ${d.inventory.network_devices} network`} color="var(--accent)" onClick={() => nav("/monitoring/hosts")} />
          <Kpi label="Up" icon={<CheckCircle2 size={14} color="var(--good)" />} value={h.UP} color="var(--good)" onClick={() => nav("/monitoring/hosts?state=UP")} />
          <Kpi label="Down" icon={<XCircle size={14} color="var(--critical)" />} value={h.DOWN} color="var(--critical)" onClick={() => nav("/monitoring/hosts?state=DOWN")} />
          <Kpi label="Warning" icon={<AlertTriangle size={14} color="var(--warning)" />} value={h.WARNING} sub="hosts with warning services" color="var(--warning)" />
          <Kpi label="Unknown" icon={<HelpCircle size={14} color="var(--unknown)" />} value={h.UNKNOWN} sub="hosts with unknown services" color="var(--unknown)" />
          <Kpi label="Unreachable" icon={<Network size={14} color="var(--serious)" />} value={h.UNREACHABLE} color="var(--serious)" onClick={() => nav("/monitoring/hosts?state=UNREACHABLE")} />
        </div>
      </div>
      <div>
        <h3 className="muted" style={{ marginBottom: 8 }}>Service summary</h3>
        <div className="grid grid-6">
          <Kpi label="Total services" icon={<Activity size={14} />} value={s.total} color="var(--accent)" onClick={() => nav("/monitoring/services")} />
          <Kpi label="OK" icon={<CheckCircle2 size={14} color="var(--good)" />} value={s.OK} color="var(--good)" onClick={() => nav("/monitoring/services?state=OK")} />
          <Kpi label="Warning" icon={<AlertTriangle size={14} color="var(--warning)" />} value={s.WARNING} color="var(--warning)" onClick={() => nav("/monitoring/services?state=WARNING")} />
          <Kpi label="Critical" icon={<XCircle size={14} color="var(--critical)" />} value={s.CRITICAL} color="var(--critical)" onClick={() => nav("/monitoring/services?state=CRITICAL")} />
          <Kpi label="Unknown" icon={<HelpCircle size={14} color="var(--unknown)" />} value={s.UNKNOWN} color="var(--unknown)" onClick={() => nav("/monitoring/services?state=UNKNOWN")} />
          <Kpi label="Availability (30 days)" value={d.availability_30d != null ? `${d.availability_30d.toFixed(2)}%` : "-"} sub="average host availability" color="var(--series-1)" onClick={() => nav("/reports/availability")} />
        </div>
      </div>

      <div className="grid grid-2">
        <Card title="Top problems - hosts" actions={<Link to="/monitoring/problems">All problems</Link>} flush><ProblemTable rows={hostProblems} host /></Card>
        <Card title="Top problems - critical services" flush><ProblemTable rows={t.critical} /></Card>
        <Card title="Warning services" flush><ProblemTable rows={t.warning} /></Card>
        <Card title="Unknown services" flush><ProblemTable rows={t.unknown} /></Card>
      </div>

      <div className="grid grid-2">
        <Card title="Recent events" actions={<Link to="/monitoring/events">All events</Link>} flush>
          {d.recent_events.length === 0 && <Empty>No recent events</Empty>}
          {d.recent_events.map((e: any, i: number) => (
            <div className="event-row" key={i}>
              <span className="time">{ago(e.time)}</span>
              <span style={{ minWidth: 110 }}>{e.kind === "CONFIG CHANGE" ? <span className="badge info">CONFIG</span> : <StateBadge state={e.state} small />}</span>
              <div style={{ minWidth: 0 }}>
                <div>{e.kind === "CONFIG CHANGE" ? <Link to={`/config/versions/${e.version_id}`}>{e.output}</Link> : <>{e.host}{e.service && <span className="muted"> / {e.service}</span>}</>}</div>
                <div className="faint small">{e.kind === "CONFIG CHANGE" ? `by ${e.contact ?? "system"}` : e.output}</div>
              </div>
            </div>
          ))}
        </Card>
        <Card title="Inventory by environment">
          {Object.keys(d.inventory.by_environment).length === 0 ? <Empty>No servers in inventory yet. <Link to="/servers/new">Add a server</Link></Empty> : (
            <RankBars uom="" rows={Object.entries(d.inventory.by_environment).sort((a: any, b: any) => b[1].total - a[1].total).map(([env, v]: any) => ({
              key: env, label: envLabel(env), sub: v.problems ? `${v.problems} with problems` : "no problems", value: v.total, tone: "series" as const,
            }))} />
          )}
        </Card>
      </div>
    </div>
  );
}
