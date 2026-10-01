import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Link, useSearchParams } from "react-router-dom";
import { BellOff, CalendarClock, RefreshCw, Search, Trash2 } from "lucide-react";
import { api } from "../lib/api";
import { useAuth } from "../lib/auth";
import { ago, dur, fmtDate } from "../lib/format";
import { Card, Checkbox, DataTable, ErrorBox, Field, Loading, Modal, PageHeader, StateBadge, useUi, type Column } from "../components/ui";

export function AckModal({ target, onClose, onDone }: { target: { host_name: string; service_description?: string }; onClose: () => void; onDone: () => void }) {
  const { toast, apiError } = useUi();
  const [comment, setComment] = useState("");
  const [sticky, setSticky] = useState(true);
  const [notify, setNotify] = useState(true);
  const submit = async () => {
    try { await api.post("/api/monitoring/acknowledge", { ...target, comment, sticky, notify }); toast("success", "Problem acknowledged"); onDone(); onClose(); }
    catch (e) { apiError(e, "Acknowledge failed"); }
  };
  return (
    <Modal title="Acknowledge problem" onClose={onClose} footer={<><button className="btn" onClick={onClose}>Cancel</button><button className="btn primary" disabled={!comment.trim()} onClick={submit}>Acknowledge</button></>}>
      <div className="stack">
        <div className="muted">{target.host_name}{target.service_description && ` / ${target.service_description}`}</div>
        <Field label="Comment" required><textarea className="input" value={comment} onChange={(e) => setComment(e.target.value)} maxLength={255} /></Field>
        <Checkbox checked={sticky} onChange={setSticky} label="Sticky (stays until the problem recovers)" />
        <Checkbox checked={notify} onChange={setNotify} label="Send acknowledgement notification" />
      </div>
    </Modal>
  );
}

function toLocalInput(d: Date) { const p = (n: number) => String(n).padStart(2, "0"); return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())}T${p(d.getHours())}:${p(d.getMinutes())}`; }

export function DowntimeModal({ target, onClose, onDone }: { target: { host_name: string; service_description?: string }; onClose: () => void; onDone: () => void }) {
  const { toast, apiError } = useUi();
  const now = new Date();
  const [start, setStart] = useState(toLocalInput(now));
  const [end, setEnd] = useState(toLocalInput(new Date(now.getTime() + 2 * 3600_000)));
  const [comment, setComment] = useState("");
  const [inc, setInc] = useState(true);
  const submit = async () => {
    try {
      await api.post("/api/monitoring/downtime", { ...target, start: new Date(start).toISOString(), end: new Date(end).toISOString(), comment, include_services: inc });
      toast("success", "Downtime scheduled"); onDone(); onClose();
    } catch (e) { apiError(e, "Scheduling downtime failed"); }
  };
  return (
    <Modal title="Schedule downtime" onClose={onClose} footer={<><button className="btn" onClick={onClose}>Cancel</button><button className="btn primary" disabled={!comment.trim()} onClick={submit}>Schedule</button></>}>
      <div className="stack">
        <div className="muted">{target.host_name}{target.service_description && ` / ${target.service_description}`}</div>
        <div className="form-grid">
          <Field label="Start"><input className="input" type="datetime-local" value={start} onChange={(e) => setStart(e.target.value)} /></Field>
          <Field label="End"><input className="input" type="datetime-local" value={end} onChange={(e) => setEnd(e.target.value)} /></Field>
        </div>
        <Field label="Comment" required><textarea className="input" value={comment} onChange={(e) => setComment(e.target.value)} maxLength={255} /></Field>
        {!target.service_description && <Checkbox checked={inc} onChange={setInc} label="Include all services on this host" />}
      </div>
    </Modal>
  );
}

function useActions(refetch: () => void) {
  const { can } = useAuth();
  const { toast, apiError } = useUi();
  const [ack, setAck] = useState<any>(null);
  const [dt, setDt] = useState<any>(null);
  const recheck = async (t: any) => {
    try { await api.post("/api/monitoring/recheck", t); toast("success", "Check scheduled", "Results appear within a few seconds."); setTimeout(refetch, 5000); }
    catch (e) { apiError(e); }
  };
  const buttons = (t: { host_name: string; service_description?: string; state?: string; acknowledged?: boolean }) => (
    <span className="row" style={{ justifyContent: "flex-end", flexWrap: "nowrap" }} onClick={(e) => e.stopPropagation()}>
      {can("monitoring.acknowledge") && t.state && !["OK", "UP", "PENDING"].includes(t.state) && !t.acknowledged &&
        <button className="btn sm ghost" title="Acknowledge" onClick={() => setAck(t)}><BellOff size={14} /></button>}
      {can("monitoring.downtime") && <button className="btn sm ghost" title="Schedule downtime" onClick={() => setDt(t)}><CalendarClock size={14} /></button>}
      {can("monitoring.control") && <button className="btn sm ghost" title="Re-check now" onClick={() => recheck({ host_name: t.host_name, service_description: t.service_description })}><RefreshCw size={14} /></button>}
    </span>
  );
  const modals = <>{ack && <AckModal target={ack} onClose={() => setAck(null)} onDone={refetch} />}{dt && <DowntimeModal target={dt} onClose={() => setDt(null)} onDone={refetch} />}</>;
  return { buttons, modals };
}

function Flags({ r }: { r: any }) {
  return <>{r.acknowledged && <span className="badge info" title="Acknowledged">ACK</span>} {r.in_downtime && <span className="badge unknown" title="In scheduled downtime">DOWNTIME</span>}</>;
}

export function MonHosts() {
  const [sp, setSp] = useSearchParams();
  const [q, setQ] = useState("");
  const state = sp.get("state") ?? "";
  const res = useQuery({ queryKey: ["mon-hosts", state, q], queryFn: () => api.get("/api/monitoring/hosts", { state, q, page_size: 500 }), refetchInterval: 30_000 });
  const { buttons, modals } = useActions(() => res.refetch());
  const cols: Column<any>[] = [
    { key: "state", header: "Status", render: (r) => <StateBadge state={r.state} small />, width: 130 },
    { key: "host_name", header: "Host", render: (r) => <>{r.server_id ? <Link to={`/servers/${r.server_id}`}>{r.host_name}</Link> : r.host_name}<div className="faint small">{r.display_name !== r.host_name ? r.display_name : ""}</div></> },
    { key: "flags", header: "", sortable: false, render: (r) => <Flags r={r} /> },
    { key: "services", header: "Services", sortValue: (r) => r.services_problem, render: (r) => <>{r.services_total}{r.services_problem > 0 && <span className="badge critical" style={{ marginLeft: 6 }}>{r.services_problem} problem</span>}</> },
    { key: "output", header: "Status information", render: (r) => <span className="small muted">{r.output}</span> },
    { key: "last_check", header: "Last check", render: (r) => <span className="small">{ago(r.last_check)}</span> },
    { key: "duration_seconds", header: "Duration", render: (r) => <span className="small">{dur(r.duration_seconds)}</span> },
    { key: "managed", header: "Managed", render: (r) => (r.managed ? <span className="badge info">Portal</span> : <span className="badge outline">Manual</span>) },
    { key: "a", header: "", sortable: false, render: (r) => buttons(r), className: "actions" },
  ];
  return (
    <div>
      <PageHeader title="Hosts" subtitle="Live host status from Nagios, including hosts defined outside the portal." />
      <div className="toolbar">
        <div className="search"><Search size={15} /><input className="input" placeholder="Search hosts" value={q} onChange={(e) => setQ(e.target.value)} /></div>
        <select className="input" value={state} onChange={(e) => setSp(e.target.value ? { state: e.target.value } : {})}>
          <option value="">All states</option>{["UP", "DOWN", "UNREACHABLE", "PENDING"].map((s) => <option key={s}>{s}</option>)}
        </select>
      </div>
      <ErrorBox error={res.error} />
      <Card flush>{res.isLoading ? <Loading /> : <DataTable rows={res.data?.data ?? []} columns={cols} rowKey={(r) => r.host_name} pageSize={50} />}</Card>
      {modals}
    </div>
  );
}

export function MonServices() {
  const [sp, setSp] = useSearchParams();
  const [q, setQ] = useState("");
  const state = sp.get("state") ?? "";
  const res = useQuery({ queryKey: ["mon-svcs", state, q], queryFn: () => api.get("/api/monitoring/services", { state, q, page_size: 1000 }), refetchInterval: 30_000 });
  const { buttons, modals } = useActions(() => res.refetch());
  const cols: Column<any>[] = [
    { key: "state", header: "Status", render: (r) => <StateBadge state={r.state} small />, width: 120 },
    { key: "host_name", header: "Host", render: (r) => (r.server_id ? <Link to={`/servers/${r.server_id}`}>{r.host_name}</Link> : r.host_name) },
    { key: "service_description", header: "Service" },
    { key: "flags", header: "", sortable: false, render: (r) => <Flags r={r} /> },
    { key: "output", header: "Status information", render: (r) => <span className="small muted">{r.output}</span> },
    { key: "attempt", header: "Attempt", render: (r) => <span className="small">{r.attempt} {r.state_type}</span> },
    { key: "last_check", header: "Last check", render: (r) => <span className="small">{ago(r.last_check)}</span> },
    { key: "duration_seconds", header: "Duration", render: (r) => <span className="small">{dur(r.duration_seconds)}</span> },
    { key: "a", header: "", sortable: false, render: (r) => buttons(r), className: "actions" },
  ];
  return (
    <div>
      <PageHeader title="Services" subtitle="Live service status from Nagios." />
      <div className="toolbar">
        <div className="search"><Search size={15} /><input className="input" placeholder="Search host, service or output" value={q} onChange={(e) => setQ(e.target.value)} /></div>
        <select className="input" value={state} onChange={(e) => setSp(e.target.value ? { state: e.target.value } : {})}>
          <option value="">All states</option>{["OK", "WARNING", "CRITICAL", "UNKNOWN", "PENDING"].map((s) => <option key={s}>{s}</option>)}
        </select>
      </div>
      <ErrorBox error={res.error} />
      <Card flush>{res.isLoading ? <Loading /> : <DataTable rows={res.data?.data ?? []} columns={cols} rowKey={(r) => r.host_name + "/" + r.service_description} pageSize={50} />}</Card>
      {modals}
    </div>
  );
}

export function Problems() {
  const [handled, setHandled] = useState(false);
  const res = useQuery({ queryKey: ["problems", handled], queryFn: () => api.get("/api/monitoring/problems", { include_handled: handled }), refetchInterval: 20_000 });
  const { buttons, modals } = useActions(() => res.refetch());
  const d = res.data?.data;
  const hostCols: Column<any>[] = [
    { key: "state", header: "Status", render: (r) => <StateBadge state={r.state} small /> },
    { key: "host_name", header: "Host", render: (r) => (r.server_id ? <Link to={`/servers/${r.server_id}`}>{r.host_name}</Link> : r.host_name) },
    { key: "flags", header: "", sortable: false, render: (r) => <Flags r={r} /> },
    { key: "output", header: "Status information", render: (r) => <span className="small muted">{r.output}</span> },
    { key: "duration_seconds", header: "Duration", render: (r) => dur(r.duration_seconds) },
    { key: "a", header: "", sortable: false, render: (r) => buttons(r), className: "actions" },
  ];
  const svcCols: Column<any>[] = [hostCols[0], hostCols[1], { key: "service_description", header: "Service" }, ...hostCols.slice(2)];
  return (
    <div className="stack">
      <PageHeader title="Problems" subtitle="Current non-OK hosts and services." actions={<Checkbox checked={handled} onChange={setHandled} label="Include acknowledged / in downtime" />} />
      <ErrorBox error={res.error} />
      {res.isLoading ? <Loading /> : <>
        <Card title={`Host problems (${d.hosts.length})`} flush><DataTable rows={d.hosts} columns={hostCols} rowKey={(r) => r.host_name} empty="No host problems" /></Card>
        <Card title={`Service problems (${d.services.length})`} flush><DataTable rows={d.services} columns={svcCols} rowKey={(r) => r.host_name + r.service_description} empty="No service problems" /></Card>
      </>}
      {modals}
    </div>
  );
}

export function Events() {
  const [kind, setKind] = useState("");
  const [hours, setHours] = useState(24);
  const [host, setHost] = useState("");
  const res = useQuery({ queryKey: ["events", kind, hours, host], queryFn: () => api.get("/api/events", { kind, hours, host, limit: 1000 }), refetchInterval: 60_000 });
  const cols: Column<any>[] = [
    { key: "ts", header: "Time", render: (r) => <span className="nowrap small">{fmtDate(r.time, { seconds: true })}</span> },
    { key: "kind", header: "Type", render: (r) => <span className="small">{r.kind}</span> },
    { key: "state", header: "State", render: (r) => (r.kind === "CONFIG CHANGE" ? <span className="badge info">{r.state}</span> : r.state ? <StateBadge state={["STARTED", "STOPPED"].includes(r.state) ? "PENDING" : r.state} small /> : "-") },
    { key: "host", header: "Host", render: (r) => r.host ?? "-" },
    { key: "service", header: "Service", render: (r) => r.service ?? "-" },
    { key: "output", header: "Details", render: (r) => <span className="small muted">{r.kind === "CONFIG CHANGE" ? <Link to={`/config/versions/${r.version_id}`}>{r.output}</Link> : r.output}{r.contact && <span className="faint"> ({r.contact})</span>}</span> },
  ];
  return (
    <div>
      <PageHeader title="Events" subtitle="Host/service failures and recoveries from the Nagios event log, notifications, and configuration changes." />
      <div className="toolbar">
        <select className="input" value={kind} onChange={(e) => setKind(e.target.value)}>
          <option value="">All event types</option>
          <option value="HOST ALERT">Host alerts</option><option value="SERVICE ALERT">Service alerts</option>
          <option value="HOST NOTIFICATION,SERVICE NOTIFICATION">Notifications</option>
          <option value="CONFIG CHANGE">Configuration changes</option><option value="PROGRAM">Nagios program events</option>
        </select>
        <select className="input" value={hours} onChange={(e) => setHours(Number(e.target.value))}>
          {[[1, "Last hour"], [24, "Last 24 hours"], [168, "Last 7 days"], [720, "Last 30 days"]].map(([v, l]) => <option key={v} value={v}>{l}</option>)}
        </select>
        <input className="input" placeholder="Host name" value={host} onChange={(e) => setHost(e.target.value)} />
      </div>
      <ErrorBox error={res.error} />
      <Card flush>{res.isLoading ? <Loading /> : <DataTable rows={res.data?.data ?? []} columns={cols} rowKey={(r) => `${r.ts}-${r.kind}-${r.host}-${r.service}-${r.output}`} pageSize={50} empty="No events in this period" />}</Card>
    </div>
  );
}

export function Downtime() {
  const { can } = useAuth();
  const { confirm, toast, apiError } = useUi();
  const res = useQuery({ queryKey: ["downtimes"], queryFn: () => api.get("/api/monitoring/downtimes"), refetchInterval: 30_000 });
  const [sched, setSched] = useState(false);
  const [hostName, setHostName] = useState("");
  const hosts = useQuery({ queryKey: ["mon-hosts-all"], queryFn: () => api.get("/api/monitoring/hosts", { page_size: 500 }), enabled: sched });
  const cancel = async (d: any) => {
    if (!(await confirm({ title: "Cancel downtime", message: `Cancel downtime for ${d.host_name}${d.service_description ? " / " + d.service_description : ""}?`, danger: true, confirmLabel: "Cancel downtime" }))) return;
    try { await api.del(`/api/monitoring/downtime/${d.kind}/${d.id}`); toast("success", "Downtime cancelled"); setTimeout(() => res.refetch(), 3000); } catch (e) { apiError(e); }
  };
  const cols: Column<any>[] = [
    { key: "host_name", header: "Host" }, { key: "service_description", header: "Service", render: (r) => r.service_description ?? "(host)" },
    { key: "start", header: "Start", render: (r) => fmtDate(r.start) }, { key: "end", header: "End", render: (r) => fmtDate(r.end) },
    { key: "author", header: "Author" }, { key: "comment", header: "Comment" },
    { key: "a", header: "", sortable: false, className: "actions", render: (r) => can("monitoring.downtime") && <button className="btn sm ghost" onClick={() => cancel(r)} title="Cancel"><Trash2 size={14} /></button> },
  ];
  return (
    <div>
      <PageHeader title="Scheduled downtime" actions={can("monitoring.downtime") && <button className="btn primary" onClick={() => setSched(true)}><CalendarClock size={15} />Schedule downtime</button>} />
      <ErrorBox error={res.error} />
      <Card flush>{res.isLoading ? <Loading /> : <DataTable rows={res.data?.data ?? []} columns={cols} rowKey={(r) => `${r.kind}-${r.id}`} empty="No scheduled downtime" />}</Card>
      {sched && !hostName && (
        <Modal title="Schedule downtime - choose host" onClose={() => setSched(false)}>
          <Field label="Host"><select className="input" value={hostName} onChange={(e) => setHostName(e.target.value)}>
            <option value="">Select...</option>{(hosts.data?.data ?? []).map((h: any) => <option key={h.host_name}>{h.host_name}</option>)}
          </select></Field>
        </Modal>
      )}
      {sched && hostName && <DowntimeModal target={{ host_name: hostName }} onClose={() => { setSched(false); setHostName(""); }} onDone={() => setTimeout(() => res.refetch(), 3000)} />}
    </div>
  );
}
