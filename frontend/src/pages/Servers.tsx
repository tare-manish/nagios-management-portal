import { useEffect, useRef, useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { Link, useNavigate } from "react-router-dom";
import { Download, MoreHorizontal, Plus, Search } from "lucide-react";
import { api } from "../lib/api";
import { useAuth } from "../lib/auth";
import { ENVIRONMENTS, METHODS, OS_TYPES, ago, dur, envLabel, methodLabel, osLabel } from "../lib/format";
import { useConfigAction } from "../components/ConfigAction";
import { Card, ConfigStateBadge, DataTable, ErrorBox, Loading, Meter, Modal, PageHeader, StateBadge, useUi, type Column } from "../components/ui";

export function TestResult({ r }: { r: any }) {
  const ok = r.result === "success";
  return (
    <div className={`test-result ${ok ? "success" : "fail"}`}>
      <StateBadge state={ok ? "OK" : r.result === "timeout" ? "UNKNOWN" : "CRITICAL"} />
      <div><strong>{r.label}</strong><div className="small muted">{r.detail}{r.response_ms != null && ` (${r.response_ms} ms)`}</div></div>
    </div>
  );
}

function RowMenu({ s, onAction }: { s: any; onAction: (a: string, s: any) => void }) {
  const { can } = useAuth();
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => {
    const h = (e: MouseEvent) => { if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false); };
    document.addEventListener("mousedown", h); return () => document.removeEventListener("mousedown", h);
  }, []);
  const portal = s.managed_by === "portal";
  const items: [string, string, boolean][] = [
    ["view", "View", true], ["edit", "Edit", portal && can("servers.edit")],
    [s.is_enabled ? "disable" : "enable", s.is_enabled ? "Disable" : "Enable", portal && can("servers.edit")],
    ["test", "Test connection", can("servers.test") && ["ncpa", "snmp"].includes(s.monitoring_method)],
    ["validate", "Validate configuration", can("config.validate")], ["apply", "Apply configuration", can("config.apply")],
    ["monitoring", "View monitoring", true], ["history", "View history", true],
    ["delete", "Delete", can("servers.delete")],
  ];
  return (
    <div className="rel" ref={ref} onClick={(e) => e.stopPropagation()}>
      <button className="btn sm ghost icon" aria-label="Actions" onClick={() => setOpen(!open)}><MoreHorizontal size={16} /></button>
      {open && <div className="menu">{items.filter((i) => i[2]).map(([k, l]) => (
        <button key={k} onClick={() => { setOpen(false); onAction(k, s); }} style={k === "delete" ? { color: "var(--critical-text)" } : undefined}>{l}</button>
      ))}</div>}
    </div>
  );
}

export default function ServersPage({ deviceType }: { deviceType: "server" | "network_device" }) {
  const nav = useNavigate();
  const qc = useQueryClient();
  const { can } = useAuth();
  const { confirm, toast, apiError } = useUi();
  const cfg = useConfigAction();
  const [f, setF] = useState({ q: "", status: "", os_type: "", environment: "", monitoring_method: "", group_id: "", config_state: "" });
  const [sort, setSort] = useState<{ key: string; dir: "asc" | "desc" }>({ key: "hostname", dir: "asc" });
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(25);
  const [test, setTest] = useState<any>(null);
  const groups = useQuery({ queryKey: ["hostgroups"], queryFn: () => api.get("/api/hostgroups") });
  const params = { ...f, device_type: deviceType, sort: sort.key, order: sort.dir, page, page_size: pageSize };
  const res = useQuery({ queryKey: ["servers", params], queryFn: () => api.get("/api/servers", params), refetchInterval: 30_000 });
  const set = (k: string, v: string) => { setF({ ...f, [k]: v }); setPage(1); };
  const net = deviceType === "network_device";

  const onAction = async (a: string, s: any) => {
    const refresh = () => qc.invalidateQueries({ queryKey: ["servers"] });
    switch (a) {
      case "view": nav(`/servers/${s.id}`); break;
      case "edit": nav(`/servers/${s.id}/edit`); break;
      case "monitoring": nav(`/servers/${s.id}?tab=services`); break;
      case "history": nav(`/servers/${s.id}?tab=history`); break;
      case "enable": case "disable":
        try { await api.post(`/api/servers/${s.id}/${a}`, { action: "save" }); toast("success", `Server ${a}d`, "Apply the configuration to update Nagios."); refresh(); } catch (e) { apiError(e); }
        break;
      case "delete":
        if (!(await confirm({ title: "Delete server", danger: true, confirmLabel: "Delete", message: <>Delete <strong>{s.hostname}</strong>? It is removed from Nagios at the next configuration apply. History is kept.</> }))) return;
        try { await api.del(`/api/servers/${s.id}`); toast("success", "Server deleted", "Apply the configuration to remove it from Nagios."); refresh(); } catch (e) { apiError(e); }
        break;
      case "test":
        setTest({ server: s, loading: true });
        try { const r = await api.post(`/api/servers/${s.id}/test`); setTest({ server: s, result: r.data }); } catch (e) { setTest(null); apiError(e); }
        break;
      case "validate": cfg.run("Validate configuration", () => api.post(`/api/servers/${s.id}/validate`), (r) => r.data.version); break;
      case "apply": cfg.run("Apply configuration", () => api.post(`/api/servers/${s.id}/apply`), (r) => r.data.version); break;
    }
  };

  const cols: Column<any>[] = [
    { key: "status", header: "Status", render: (s) => <StateBadge state={s.is_enabled ? s.live.state : "PENDING"} small />, width: 120 },
    { key: "hostname", header: "Hostname", render: (s) => <><Link to={`/servers/${s.id}`} onClick={(e) => e.stopPropagation()}>{s.hostname}</Link>{!s.is_enabled && <span className="badge outline" style={{ marginLeft: 6 }}>Disabled</span>}<div><ConfigStateBadge state={s.config_state} />{s.managed_by === "external" && <span className="badge outline" style={{ marginLeft: 4 }}>Read-only</span>}</div></> },
    { key: "display_name", header: "Display name" },
    { key: "address", header: "IP address", render: (s) => <span className="mono">{s.address}</span> },
    { key: "os_type", header: net ? "Type" : "Operating system", render: (s) => <>{osLabel(s.os_type)}{s.os_version && <div className="faint small">{s.os_version}</div>}</> },
    { key: "monitoring_method", header: "Agent", render: (s) => methodLabel(s.monitoring_method) },
    { key: "environment", header: "Environment", render: (s) => envLabel(s.environment) },
    { key: "location", header: "Location" },
    { key: "group", header: "Host group", render: (s) => s.groups.map((g: any) => <span className="tag" key={g.id}>{g.name}</span>) },
    { key: "cpu", header: "CPU", render: (s) => <Meter value={s.metrics.cpu} /> },
    { key: "memory", header: "Memory", render: (s) => <Meter value={s.metrics.memory} /> },
    { key: "disk", header: "Disk", render: (s) => <Meter value={s.metrics.disk} /> },
    { key: "uptime", header: "Uptime", sortable: false, render: (s) => dur(s.metrics.uptime_seconds) },
    { key: "last_check", header: "Last check", render: (s) => <span className="small nowrap">{ago(s.live.last_check)}</span> },
    { key: "last_state_change", header: "Last state change", render: (s) => <span className="small nowrap">{ago(s.live.last_state_change)}</span> },
    { key: "availability", header: "Availability", render: (s) => (s.availability_30d != null ? `${s.availability_30d.toFixed(2)}%` : "-") },
    { key: "actions", header: "Actions", sortable: false, className: "actions", render: (s) => <RowMenu s={s} onAction={onAction} /> },
  ];
  const meta = res.data?.meta;
  const exportCsv = () => {
    const rows = res.data?.data ?? [];
    const head = ["hostname", "display_name", "address", "os", "agent", "environment", "location", "status", "cpu", "memory", "disk"];
    const esc = (v: any) => `"${String(v ?? "").replace(/"/g, '""').replace(/^([=+\-@])/, "'$1")}"`;
    const csv = [head.join(","), ...rows.map((s: any) => [s.hostname, s.display_name, s.address, s.os_type, s.monitoring_method, s.environment, s.location, s.live.state, s.metrics.cpu, s.metrics.memory, s.metrics.disk].map(esc).join(","))].join("\n");
    const a = document.createElement("a"); a.href = URL.createObjectURL(new Blob([csv], { type: "text/csv" })); a.download = net ? "network-devices.csv" : "servers.csv"; a.click();
  };
  return (
    <div>
      <PageHeader title={net ? "Network devices" : "Servers"} subtitle={net ? "Switches, routers, firewalls and other SNMP devices." : "Server inventory joined with live Nagios status."}
        actions={<>
          <button className="btn" onClick={exportCsv}><Download size={15} />Export</button>
          {can("config.validate") && <button className="btn" onClick={cfg.validateAll}>Validate configuration</button>}
          {can("config.apply") && <button className="btn" onClick={cfg.applyAll}>Apply configuration</button>}
          {can("servers.create") && <button className="btn primary" onClick={() => nav(net ? "/network/new" : "/servers/new")}><Plus size={15} />{net ? "Add device" : "Add server"}</button>}
        </>} />
      <div className="toolbar">
        <div className="search"><Search size={15} /><input className="input" placeholder="Search hostname, name, IP, location" value={f.q} onChange={(e) => set("q", e.target.value)} /></div>
        <select className="input" value={f.status} onChange={(e) => set("status", e.target.value)}><option value="">All statuses</option>{["UP", "DOWN", "UNREACHABLE", "PENDING", "UNMONITORED"].map((s) => <option key={s}>{s}</option>)}</select>
        {!net && <select className="input" value={f.os_type} onChange={(e) => set("os_type", e.target.value)}><option value="">All OS</option>{OS_TYPES.map((o) => <option key={o.value} value={o.value}>{o.label}</option>)}</select>}
        <select className="input" value={f.environment} onChange={(e) => set("environment", e.target.value)}><option value="">All environments</option>{ENVIRONMENTS.map((o) => <option key={o.value} value={o.value}>{o.label}</option>)}</select>
        <select className="input" value={f.monitoring_method} onChange={(e) => set("monitoring_method", e.target.value)}><option value="">All agents</option>{METHODS.map((o) => <option key={o.value} value={o.value}>{o.label}</option>)}</select>
        <select className="input" value={f.group_id} onChange={(e) => set("group_id", e.target.value)}><option value="">All host groups</option>{(groups.data?.data ?? []).map((g: any) => <option key={g.id} value={g.id}>{g.name}</option>)}</select>
        <select className="input" value={f.config_state} onChange={(e) => set("config_state", e.target.value)}><option value="">Any config state</option><option value="draft">Draft</option><option value="pending">Pending apply</option><option value="applied">Applied</option></select>
      </div>
      <ErrorBox error={res.error} />
      {meta?.status_error && <div className="mb"><ErrorBox error={`Live status unavailable: ${meta.status_error}`} /></div>}
      <Card flush>
        {res.isLoading ? <Loading /> : (
          <DataTable rows={res.data?.data ?? []} columns={cols} rowKey={(s) => s.id} onRowClick={(s) => nav(`/servers/${s.id}`)}
            serverSort={sort} onSort={(key, dir) => setSort({ key, dir })}
            serverPaging={{ page: meta?.page ?? 1, pages: meta?.pages ?? 1, total: meta?.total ?? 0, pageSize, onPage: setPage, onPageSize: (n) => { setPageSize(n); setPage(1); } }}
            empty={<>No {net ? "network devices" : "servers"} found. {can("servers.create") && <Link to={net ? "/network/new" : "/servers/new"}>Add one</Link>}</>} />
        )}
      </Card>
      {test && (
        <Modal title={`Test connection - ${test.server.hostname}`} onClose={() => setTest(null)}>
          {test.loading ? <Loading /> : <TestResult r={test.result} />}
        </Modal>
      )}
      {cfg.node}
    </div>
  );
}
