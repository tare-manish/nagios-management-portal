import { Fragment, useMemo, useState } from "react";
import { keepPreviousData, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link, useNavigate, useParams, useSearchParams } from "react-router-dom";
import { CalendarClock, Pencil, PlugZap, RefreshCw, Trash2 } from "lucide-react";
import { api } from "../lib/api";
import { useAuth } from "../lib/auth";
import { ago, dur, envLabel, fmtDate, methodLabel, osLabel } from "../lib/format";
import { useConfigAction } from "../components/ConfigAction";
import { TimeChart } from "../components/LineChart";
import { Alert, Card, ConfigStateBadge, DataTable, Empty, ErrorBox, Kpi, Loading, Modal, PageHeader, Segmented, StateBadge, Tabs, useUi, type Column } from "../components/ui";
import { AckModal, DowntimeModal } from "./Monitoring";
import { TestResult } from "./Servers";

function Performance({ id, services }: { id: number; services: any[] }) {
  const [hours, setHours] = useState("24");
  const q = useQuery({ queryKey: ["perf", id, hours], queryFn: () => api.get(`/api/servers/${id}/performance`, { hours }), refetchInterval: 120_000, placeholderData: keepPreviousData });
  const series: any[] = q.data?.data ?? [];
  const byCat = useMemo(() => {
    const cats: Record<string, any[]> = { cpu: [], memory: [], disk: [], network: [], availability: [], uptime: [], other: [] };
    for (const s of series) (cats[s.category] ?? cats.other).push(s);
    return cats;
  }, [series]);
  const titles: Record<string, string> = { cpu: "CPU", memory: "Memory", disk: "Disk", network: "Network", availability: "Reachability", uptime: "Uptime", other: "Other metrics" };
  return (
    <div className="stack">
      <div className="row between">
        <span className="faint small">From Nagios performance data after each check. Hover, tap or use the arrow keys on a chart to read values.</span>
        <Segmented value={hours} onChange={setHours} options={[{ value: "6", label: "6h" }, { value: "24", label: "24h" }, { value: "168", label: "7d" }, { value: "720", label: "30d" }]} />
      </div>
      <ErrorBox error={q.error} />
      {q.isLoading ? <Loading /> : series.length === 0 ? <Empty>No performance data yet. Data appears after the first checks run ({services.length} services configured).</Empty> : (
        <div className="grid grid-2">
          {Object.entries(byCat).flatMap(([cat, list]) => list.map((s) => (
            <Card key={`${s.service}-${s.label}`} title={<span className="chart-card-head">{s.service}<span className="faint small" style={{ fontWeight: 400 }}>{titles[cat]}{s.label && s.label !== "value" && s.label !== s.service ? ` · ${s.label}` : ""}</span></span>}>
              <TimeChart series={[{ ...s, label: s.label && s.label !== "value" ? `${s.service} · ${s.label}` : s.service }]} hours={Number(hours)} max={s.uom === "%" ? 100 : undefined} dimmed={q.isPlaceholderData} />
            </Card>
          )))}
        </div>
      )}
    </div>
  );
}

function History({ id }: { id: number }) {
  const q = useQuery({ queryKey: ["history", id], queryFn: () => api.get(`/api/servers/${id}/history`) });
  if (q.isLoading) return <Loading />;
  const d = q.data?.data;
  const cols: Column<any>[] = [
    { key: "time", header: "Date/time", render: (r) => <span className="nowrap">{fmtDate(r.time, { seconds: true })}</span> },
    { key: "user", header: "User" }, { key: "action", header: "Action" }, { key: "ip", header: "IP address" },
    { key: "result", header: "Result", render: (r) => <span className={`badge ${r.result === "success" ? "good" : "critical"}`}>{r.result}</span> },
    { key: "change", header: "Old / new value", sortable: false, render: (r) => <ChangeDiff old={r.old} next={r.new} /> },
  ];
  return <Card flush><DataTable rows={d?.audit ?? []} columns={cols} rowKey={(r) => r.id} empty="No history" /></Card>;
}

export function ChangeDiff({ old, next }: { old: any; next: any }) {
  if (!old && !next) return <span className="faint">-</span>;
  const keys = Array.from(new Set([...Object.keys(old ?? {}), ...Object.keys(next ?? {})]));
  const changed = keys.filter((k) => JSON.stringify(old?.[k]) !== JSON.stringify(next?.[k]));
  const show = (v: any) => (v === undefined ? "-" : typeof v === "object" ? JSON.stringify(v) : String(v));
  if (!old || !next) return <details><summary className="small">{old ? "removed values" : "values"}</summary><pre className="code" style={{ maxHeight: 200 }}>{JSON.stringify(old ?? next, null, 2)}</pre></details>;
  if (!changed.length) return <span className="faint small">no field changes</span>;
  return (
    <div className="small">{changed.slice(0, 6).map((k) => (
      <div key={k}><strong>{k}</strong>: <span className="diff-del" style={{ display: "inline" }}>{show(old[k]).slice(0, 120)}</span> &rarr; <span className="diff-add" style={{ display: "inline" }}>{show(next[k]).slice(0, 120)}</span></div>
    ))}{changed.length > 6 && <div className="faint">+{changed.length - 6} more</div>}</div>
  );
}

export default function ServerDetail() {
  const { id } = useParams();
  const sid = Number(id);
  const nav = useNavigate();
  const qc = useQueryClient();
  const [sp, setSp] = useSearchParams();
  const tab = sp.get("tab") ?? "overview";
  const { can } = useAuth();
  const { confirm, toast, apiError } = useUi();
  const cfg = useConfigAction();
  const [ack, setAck] = useState<any>(null);
  const [dt, setDt] = useState<any>(null);
  const [test, setTest] = useState<any>(null);
  const q = useQuery({ queryKey: ["server", id], queryFn: () => api.get(`/api/servers/${id}`), refetchInterval: 30_000 });
  const events = useQuery({ queryKey: ["server-events", id], queryFn: () => api.get(`/api/servers/${id}/events`), enabled: tab === "events" });
  if (q.isLoading) return <Loading />;
  if (q.error) return <ErrorBox error={q.error} />;
  const s = q.data!.data;
  const live = s.live;
  const portal = s.managed_by === "portal";
  const refresh = () => qc.invalidateQueries({ queryKey: ["server", id] });

  const toggle = async () => {
    const a = s.is_enabled ? "disable" : "enable";
    try { await api.post(`/api/servers/${sid}/${a}`, { action: "save" }); toast("success", `Server ${a}d`, "Apply the configuration to update Nagios."); refresh(); } catch (e) { apiError(e); }
  };
  const del = async () => {
    if (!(await confirm({ title: "Delete server", danger: true, confirmLabel: "Delete", message: <>Delete <strong>{s.hostname}</strong>? It is removed from Nagios at the next apply.</> }))) return;
    try { await api.del(`/api/servers/${sid}`); toast("success", "Server deleted"); nav("/servers"); } catch (e) { apiError(e); }
  };
  const runTest = async () => { setTest({ loading: true }); try { const r = await api.post(`/api/servers/${sid}/test`); setTest({ result: r.data }); refresh(); } catch (e) { setTest(null); apiError(e); } };
  const recheck = async (service?: string) => {
    try { await api.post("/api/monitoring/recheck", { host_name: s.hostname, service_description: service, all_services: !service }); toast("success", "Re-check scheduled"); setTimeout(refresh, 6000); } catch (e) { apiError(e); }
  };

  const svcCols: Column<any>[] = [
    { key: "state", header: "Status", sortValue: (r) => r.live?.state, render: (r) => (r.is_enabled ? <StateBadge state={r.live?.state} small /> : <span className="badge outline">Disabled</span>) },
    { key: "service_description", header: "Service", render: (r) => <>{r.service_description}<div className="faint small">{r.service_name}</div></> },
    { key: "value", header: "Current value", sortable: false, render: (r) => <span className="small">{r.live?.perf?.[0] ? `${r.live.perf[0].value}${r.live.perf[0].uom ?? ""}` : "-"}</span> },
    { key: "warning", header: "Warning", render: (r) => r.warning ?? "-" }, { key: "critical", header: "Critical", render: (r) => r.critical ?? "-" },
    { key: "last_check", header: "Last check", render: (r) => <span className="small nowrap">{ago(r.live?.last_check)}</span> },
    { key: "next_check", header: "Next check", render: (r) => <span className="small nowrap">{ago(r.live?.next_check)}</span> },
    { key: "output", header: "Output / performance data", sortable: false, render: (r) => <><div className="small">{r.live?.output ?? "-"}</div><div className="faint small mono">{r.live?.perf_data}</div></> },
    { key: "a", header: "", sortable: false, className: "actions", render: (r) => (
      <span className="row" style={{ flexWrap: "nowrap", justifyContent: "flex-end" }}>
        {can("monitoring.acknowledge") && r.live && !["OK", "PENDING", "UNMONITORED"].includes(r.live.state) && !r.live.acknowledged &&
          <button className="btn sm ghost" onClick={() => setAck({ host_name: s.hostname, service_description: r.service_description })}>Ack</button>}
        {can("monitoring.control") && live.in_nagios && <button className="btn sm ghost" title="Re-check" onClick={() => recheck(r.service_description)}><RefreshCw size={14} /></button>}
      </span>) },
  ];

  return (
    <div className="stack">
      <PageHeader crumb={<Link to={s.device_type === "network_device" ? "/network" : "/servers"}>{s.device_type === "network_device" ? "Network devices" : "Servers"}</Link>}
        title={<span className="row">{s.hostname}<StateBadge state={s.is_enabled ? live.state : "PENDING"} /><ConfigStateBadge state={s.config_state} />{!s.is_enabled && <span className="badge outline">Disabled</span>}</span>}
        subtitle={`${s.display_name} - ${s.address}`}
        actions={<>
          {can("servers.edit") && portal && <button className="btn" onClick={() => nav(`/servers/${sid}/edit`)}><Pencil size={15} />Edit</button>}
          {can("servers.edit") && portal && <button className="btn" onClick={toggle}>{s.is_enabled ? "Disable" : "Enable"}</button>}
          {can("servers.test") && ["ncpa", "snmp"].includes(s.monitoring_method) && <button className="btn" onClick={runTest}><PlugZap size={15} />Test connection</button>}
          {can("monitoring.downtime") && live.in_nagios && <button className="btn" onClick={() => setDt({ host_name: s.hostname })}><CalendarClock size={15} />Downtime</button>}
          {can("monitoring.control") && live.in_nagios && <button className="btn" onClick={() => recheck()}><RefreshCw size={15} />Re-check</button>}
          {can("config.validate") && <button className="btn" onClick={() => cfg.run("Validate configuration", () => api.post(`/api/servers/${sid}/validate`), (r) => r.data.version)}>Validate</button>}
          {can("config.apply") && <button className="btn primary" onClick={() => cfg.run("Apply configuration", () => api.post(`/api/servers/${sid}/apply`), (r) => r.data.version)}>Apply</button>}
          {can("servers.delete") && <button className="btn ghost icon" title="Delete" onClick={del}><Trash2 size={16} color="var(--critical)" /></button>}
        </>} />
      {!portal && <Alert kind="info">This host is managed in manual Nagios configuration ({s.imported_from}). It is shown read-only. Use <Link to="/admin/import">Import</Link> to take it over.</Alert>}
      {s.config_state === "pending" && <Alert kind="warning">This server has changes that are not yet applied to Nagios.</Alert>}
      {s.config_state === "draft" && <Alert kind="info">Draft - not included in the Nagios configuration until saved without draft.</Alert>}
      {live.state === "UNMONITORED" && s.config_state === "applied" && <Alert kind="warning">The host is not present in the running Nagios status. Validate and apply the configuration.</Alert>}
      <Tabs active={tab} onChange={(k) => setSp({ tab: k })} tabs={[
        { key: "overview", label: "Overview" }, { key: "performance", label: "Performance" },
        { key: "services", label: `Services (${s.services.length})` }, { key: "events", label: "Events" }, { key: "history", label: "History" }]} />

      {tab === "overview" && (
        <div className="stack">
          <div className="grid grid-6">
            <Kpi label="Status" value={<StateBadge state={s.is_enabled ? live.state : "PENDING"} />} sub={live.output} color={live.state === "UP" ? "var(--good)" : live.state === "DOWN" ? "var(--critical)" : "var(--border)"} />
            <Kpi label="Availability (30 days)" value={s.availability_30d != null ? `${s.availability_30d.toFixed(2)}%` : "-"} color="var(--series-1)" />
            <Kpi label="CPU" value={s.metrics.cpu != null ? `${s.metrics.cpu}%` : "-"} color="var(--series-1)" />
            <Kpi label="Memory" value={s.metrics.memory != null ? `${s.metrics.memory}%` : "-"} color="var(--series-1)" />
            <Kpi label="Max disk used" value={s.metrics.disk != null ? `${s.metrics.disk}%` : "-"} color="var(--series-1)" />
            <Kpi label="Uptime" value={dur(s.metrics.uptime_seconds)} color="var(--series-1)" />
          </div>
          <div className="grid grid-2">
            <Card title="Overview">
              <dl className="dl">
                <dt>Hostname</dt><dd>{s.hostname}</dd><dt>Display name</dt><dd>{s.display_name}</dd><dt>IP / FQDN</dt><dd className="mono">{s.address}</dd>
                <dt>Operating system</dt><dd>{osLabel(s.os_type)} {s.os_version}</dd><dt>Location</dt><dd>{s.location_name ?? "Not assigned"}{s.location ? ` · ${s.location}` : ""}</dd>{"company_name" in s && <><dt>Company</dt><dd>{s.company_name ?? "Not assigned"}</dd></>}
                <dt>Environment</dt><dd>{envLabel(s.environment)}</dd><dt>Agent</dt><dd>{methodLabel(s.monitoring_method)} (host check: {s.host_check})</dd>
                <dt>Host groups</dt><dd>{s.groups.map((g: any) => <span className="tag" key={g.id}>{g.name}</span>)}</dd>
                <dt>Contact groups</dt><dd>{s.contact_groups.map((g: any) => <span className="tag" key={g.id}>{g.name}</span>) }{!s.contact_groups.length && <span className="faint">default</span>}</dd>
                <dt>Template</dt><dd>{s.template_name ?? "-"}</dd><dt>Description</dt><dd>{s.description ?? "-"}</dd>
              </dl>
            </Card>
            <Card title="Monitoring">
              <dl className="dl">
                <dt>Last check</dt><dd>{fmtDate(live.last_check, { seconds: true })} ({ago(live.last_check)})</dd>
                <dt>Next check</dt><dd>{fmtDate(live.next_check, { seconds: true })}</dd>
                <dt>Last state change</dt><dd>{fmtDate(live.last_state_change)} ({ago(live.last_state_change)})</dd>
                <dt>Services</dt><dd className="row">{Object.entries(live.service_counts).filter(([, n]) => (n as number) > 0).map(([k, n]) => <span key={k} className="row" style={{ gap: 4 }}><StateBadge state={k} small />{n as number}</span>)}</dd>
                <dt>Acknowledged</dt><dd>{live.acknowledged ? "Yes" : "No"}</dd><dt>In downtime</dt><dd>{live.in_downtime ? "Yes" : "No"}</dd>
                <dt>Intervals</dt><dd>check {s.check_interval}m, retry {s.retry_interval}m, {s.max_check_attempts} attempts</dd>
                <dt>Notifications</dt><dd>{s.notifications_enabled ? `every ${s.notification_interval}m` : "disabled"}</dd>
                {s.credentials.map((c: any) => <Fragment key={c.type}><dt>{c.type.toUpperCase()} credential</dt><dd>{c.secret_set ? "stored (encrypted)" : "not set"}{c.port && `, port ${c.port}`}{c.last_test_result && `, last test: ${c.last_test_result} ${ago(c.last_test_at)}`}</dd></Fragment>)}
              </dl>
            </Card>
          </div>
        </div>
      )}
      {tab === "performance" && <Performance id={sid} services={s.services} />}
      {tab === "services" && <Card flush><DataTable rows={s.services} columns={svcCols} rowKey={(r) => r.id} empty="No services configured" /></Card>}
      {tab === "events" && (
        <Card flush>{events.isLoading ? <Loading /> : (
          <DataTable rows={events.data?.data ?? []} rowKey={(r: any) => `${r.ts}-${r.kind}-${r.service}`} empty="No events for this host in the recent log"
            columns={[
              { key: "ts", header: "Time", render: (r: any) => <span className="nowrap small">{fmtDate(r.time, { seconds: true })}</span> },
              { key: "kind", header: "Type" }, { key: "state", header: "State", render: (r: any) => <StateBadge state={r.state} small /> },
              { key: "state_type", header: "Type" }, { key: "service", header: "Service", render: (r: any) => r.service ?? "(host)" },
              { key: "output", header: "Details", render: (r: any) => <span className="small muted">{r.output}</span> }]} />
        )}</Card>
      )}
      {tab === "history" && <History id={sid} />}
      {ack && <AckModal target={ack} onClose={() => setAck(null)} onDone={refresh} />}
      {dt && <DowntimeModal target={dt} onClose={() => setDt(null)} onDone={refresh} />}
      {test && <Modal title={`Test connection - ${s.hostname}`} onClose={() => setTest(null)}>{test.loading ? <Loading /> : <TestResult r={test.result} />}</Modal>}
      {cfg.node}
    </div>
  );
}
