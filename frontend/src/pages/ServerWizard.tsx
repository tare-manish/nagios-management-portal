import { useEffect, useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { useNavigate, useParams } from "react-router-dom";
import { Check, Cpu, Globe, HardDrive, Monitor, Network, Plus, Router, Server, Terminal, Trash2, Wifi, Zap } from "lucide-react";
import { ApiError, api } from "../lib/api";
import { useAuth } from "../lib/auth";
import { ENVIRONMENTS, envLabel, methodLabel, osLabel } from "../lib/format";
import { Alert, Card, Checkbox, ErrorBox, Field, Loading, Modal, PageHeader, Spinner, useUi } from "../components/ui";
import { VersionResult, type Version } from "../components/Pipeline";
import { TestResult } from "./Servers";

interface Item {
  key: string; id?: number; service_id: number; service_description: string; params: Record<string, string>;
  is_enabled: boolean; warning: string; critical: string; check_interval: number; retry_interval: number;
  max_check_attempts: number; notification_interval: number; notifications_enabled: boolean;
}
let seq = 0;
const nextKey = () => `k${++seq}`;

const OS_OPTIONS = [
  { value: "windows", label: "Windows", icon: <Monitor size={18} />, desc: "Windows Server via NCPA" },
  { value: "linux", label: "Linux", icon: <Terminal size={18} />, desc: "Linux via NCPA, NRPE or SNMP" },
  { value: "unix", label: "Unix", icon: <Server size={18} />, desc: "AIX, Solaris, BSD..." },
  { value: "network", label: "Network Device", icon: <Router size={18} />, desc: "Switch, router, firewall via SNMP" },
  { value: "other", label: "Other", icon: <Globe size={18} />, desc: "Any IP device" },
];
const METHOD_OPTIONS = [
  { value: "ncpa", label: "NCPA", icon: <Cpu size={18} />, desc: "Nagios Cross-Platform Agent (recommended for Windows/Linux)", os: ["windows", "linux", "unix", "other"] },
  { value: "snmp", label: "SNMP", icon: <Network size={18} />, desc: "SNMP v2c or v3", os: ["network", "linux", "unix", "other", "windows"] },
  { value: "nrpe", label: "NRPE", icon: <Zap size={18} />, desc: "Nagios Remote Plugin Executor", os: ["linux", "unix", "other"] },
  { value: "ping", label: "Ping only", icon: <Wifi size={18} />, desc: "Reachability, latency and packet loss", os: ["windows", "linux", "unix", "network", "other"] },
  { value: "custom", label: "Custom plugin", icon: <HardDrive size={18} />, desc: "Service definitions using your own commands", os: ["windows", "linux", "unix", "network", "other"] },
];
const STEPS = ["Basic information", "Operating system", "Monitoring method", "Monitoring services", "Thresholds", "Review"];
const SELECTS: Record<string, string[]> = {
  state: ["running", "stopped"], mismatch: ["critical", "warning"], direction: ["recv", "sent"],
  severity: ["ERROR", "WARNING", "INFORMATION", "CRITICAL", "AUDIT_FAILURE"], units: ["", "k", "Ki", "M", "Mi", "G", "Gi", "T", "Ti"],
};

function describe(tpl: string, params: Record<string, string>) {
  return tpl.replace(/\{([a-z_]+)\}/g, (_, k) => params[k] ?? "").replace(/\s+/g, " ").trim();
}

export default function ServerWizard({ network }: { network?: boolean }) {
  const { id } = useParams();
  const editing = !!id;
  const nav = useNavigate();
  const { can } = useAuth();
  const { apiError, toast } = useUi();
  const [step, setStep] = useState(0);
  const [maxStep, setMaxStep] = useState(editing ? 5 : 0);
  const [f, setF] = useState<any>({
    hostname: "", display_name: "", address: "", description: "", location: "", environment: "production",
    os_type: network ? "network" : "windows", os_version: "", device_type: network ? "network_device" : "server",
    monitoring_method: network ? "snmp" : "ncpa", host_check: network ? "ping" : "agent", group_ids: [], contact_group_ids: [],
    template_id: null, check_interval: 5, retry_interval: 1, max_check_attempts: 5, notification_interval: 60,
    notifications_enabled: true, check_period: "24x7", notification_period: "24x7", is_enabled: true,
  });
  const [ncpa, setNcpa] = useState({ port: 5693, token: "", ssl_enabled: true, verify_ssl: false, timeout: 30 });
  const [snmp, setSnmp] = useState<any>({ version: "2c", community: "", username: "", security_level: "authPriv", auth_protocol: "SHA", auth_password: "", priv_protocol: "AES", priv_password: "" });
  const [nrpe, setNrpe] = useState({ port: 5666, timeout: 30 });
  const [items, setItems] = useState<Item[]>([]);
  const [secretSet, setSecretSet] = useState(false);
  const [test, setTest] = useState<any>(null);
  const [testing, setTesting] = useState(false);
  const [errors, setErrors] = useState<Record<string, string>>({});
  const [saving, setSaving] = useState<string | null>(null);
  const [result, setResult] = useState<{ v: Version | null; serverId: number } | null>(null);
  const [picker, setPicker] = useState(false);
  const [loaded, setLoaded] = useState(!editing);

  const catalog = useQuery({ queryKey: ["catalog"], queryFn: () => api.get("/api/services") });
  const templates = useQuery({ queryKey: ["templates"], queryFn: () => api.get("/api/templates") });
  const groups = useQuery({ queryKey: ["hostgroups"], queryFn: () => api.get("/api/hostgroups") });
  const cgroups = useQuery({ queryKey: ["contact-groups"], queryFn: () => api.get("/api/contact-groups") });
  const tps = useQuery({ queryKey: ["timeperiods"], queryFn: () => api.get("/api/timeperiods") });
  const settings = useQuery({ queryKey: ["settings"], queryFn: () => api.get("/api/settings") });
  const existing = useQuery({ queryKey: ["server", id], queryFn: () => api.get(`/api/servers/${id}`), enabled: editing });
  const cat: any[] = catalog.data?.data ?? [];
  const catById = useMemo(() => Object.fromEntries(cat.map((c) => [c.id, c])), [cat]);

  useEffect(() => {
    const s = settings.data?.data;
    if (s && !editing) setNcpa((n) => ({ ...n, port: s.ncpa_default_port ?? 5693, timeout: s.ncpa_default_timeout ?? 30, verify_ssl: !!s.ncpa_default_verify_ssl }));
  }, [settings.data, editing]);

  useEffect(() => {
    const s = existing.data?.data;
    if (!s || loaded) return;
    setF({
      hostname: s.hostname, display_name: s.display_name, address: s.address, description: s.description ?? "", location: s.location ?? "",
      environment: s.environment, os_type: s.os_type, os_version: s.os_version ?? "", device_type: s.device_type,
      monitoring_method: s.monitoring_method, host_check: s.host_check, group_ids: s.groups.map((g: any) => g.id),
      contact_group_ids: s.contact_groups.map((g: any) => g.id), template_id: s.template_id, check_interval: s.check_interval,
      retry_interval: s.retry_interval, max_check_attempts: s.max_check_attempts, notification_interval: s.notification_interval,
      notifications_enabled: s.notifications_enabled, check_period: s.check_period, notification_period: s.notification_period, is_enabled: s.is_enabled,
    });
    for (const c of s.credentials) {
      if (c.type === "ncpa") { setNcpa({ port: c.port ?? 5693, token: "", ssl_enabled: c.ssl_enabled, verify_ssl: c.verify_ssl, timeout: c.timeout }); setSecretSet(c.secret_set); }
      if (c.type === "snmp") { setSnmp((x: any) => ({ ...x, version: c.version ?? "2c", username: c.username ?? "", security_level: c.security_level ?? "authPriv", auth_protocol: c.auth_protocol ?? "SHA", priv_protocol: c.priv_protocol ?? "AES" })); setSecretSet(c.secret_set); }
      if (c.type === "nrpe") setNrpe({ port: c.port ?? 5666, timeout: c.timeout });
    }
    setItems(s.services.map((x: any) => ({ key: nextKey(), id: x.id, service_id: x.service_id, service_description: x.service_description, params: x.params,
      is_enabled: x.is_enabled, warning: x.warning ?? "", critical: x.critical ?? "", check_interval: x.check_interval, retry_interval: x.retry_interval,
      max_check_attempts: x.max_check_attempts, notification_interval: x.notification_interval, notifications_enabled: x.notifications_enabled })));
    setLoaded(true);
  }, [existing.data, loaded]);

  const set = (k: string, v: any) => { setF((x: any) => ({ ...x, [k]: v })); setErrors((e) => ({ ...e, [k]: "" })); };
  const fromCatalog = (svc: any, desc?: string, params: Record<string, string> = {}, over: Partial<Item> = {}): Item => {
    const p: Record<string, string> = {};
    for (const ps of svc.params_schema) p[ps.name] = params[ps.name] ?? ps.default ?? "";
    return { key: nextKey(), service_id: svc.id, service_description: desc || describe(svc.default_description, p), params: p, is_enabled: true,
      warning: svc.default_warning ?? "", critical: svc.default_critical ?? "", check_interval: svc.default_check_interval,
      retry_interval: svc.default_retry_interval, max_check_attempts: 3, notification_interval: svc.default_notification_interval,
      notifications_enabled: true, ...over };
  };
  const applyTemplate = (tid: number | null, replace: boolean) => {
    set("template_id", tid);
    if (!tid) return;
    const t = (templates.data?.data ?? []).find((x: any) => x.id === tid);
    if (!t) return;
    const newItems = t.items.map((i: any) => {
      const svc = catById[i.service_id];
      return fromCatalog(svc, i.service_description, i.params, {
        warning: i.warning ?? "", critical: i.critical ?? "", check_interval: i.check_interval ?? svc.default_check_interval,
        retry_interval: i.retry_interval ?? svc.default_retry_interval,
        notification_interval: i.notification_interval ?? svc.default_notification_interval, notifications_enabled: i.notifications_enabled,
      });
    });
    setItems((cur) => (replace ? newItems : [...cur, ...newItems.filter((n: Item) => !cur.some((c) => c.service_description === n.service_description))]));
  };
  const updItem = (key: string, patch: Partial<Item>) => setItems((cur) => cur.map((i) => (i.key === key ? { ...i, ...patch } : i)));

  const validateStep = (s: number): boolean => {
    const e: Record<string, string> = {};
    if (s === 0) {
      if (!/^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$/.test(f.hostname)) e.hostname = "1-63 characters: letters, digits, . _ - (start with a letter or digit)";
      if (!f.display_name.trim()) e.display_name = "Required";
      if (!f.address.trim()) e.address = "Required";
    }
    if (s === 2) {
      if (f.monitoring_method === "ncpa" && !ncpa.token && !secretSet) e.token = "NCPA token is required";
      if (f.monitoring_method === "snmp") {
        if (snmp.version === "2c" && !snmp.community && !secretSet) e.community = "Community is required";
        if (snmp.version === "3" && !snmp.username) e.username = "Username is required";
      }
    }
    if (s === 3 || s === 4) {
      const seen = new Set<string>();
      for (const i of items) {
        if (seen.has(i.service_description)) e[`svc-${i.key}`] = "Duplicate service description";
        seen.add(i.service_description);
        const svc = catById[i.service_id];
        for (const p of svc?.params_schema ?? []) if (p.required && !i.params[p.name]) e[`svc-${i.key}`] = `${p.label} is required`;
      }
    }
    setErrors(e);
    return Object.values(e).every((x) => !x);
  };
  const go = (n: number) => {
    if (n > step) for (let s = step; s < n; s++) if (!validateStep(s)) { setStep(s); return; }
    setStep(n); setMaxStep((m) => Math.max(m, n));
  };

  const runTest = async () => {
    setTesting(true); setTest(null);
    try {
      const r = await api.post("/api/servers/test-connection", {
        address: f.address, monitoring_method: f.monitoring_method, server_id: editing ? Number(id) : undefined,
        ncpa: f.monitoring_method === "ncpa" ? { ...ncpa, token: ncpa.token || undefined } : undefined,
        snmp: f.monitoring_method === "snmp" ? snmpPayload() : undefined,
      });
      setTest(r.data);
      if (r.data.result === "success" && r.data.os_release && !f.os_version) set("os_version", `${r.data.os ?? ""} ${r.data.os_release}`.trim());
    } catch (e) { apiError(e, "Connection test failed"); } finally { setTesting(false); }
  };
  const snmpPayload = () => {
    const out: any = { version: snmp.version };
    if (snmp.version === "2c") { if (snmp.community) out.community = snmp.community; }
    else { Object.assign(out, { username: snmp.username, security_level: snmp.security_level, auth_protocol: snmp.auth_protocol, priv_protocol: snmp.priv_protocol });
      if (snmp.auth_password) out.auth_password = snmp.auth_password; if (snmp.priv_password) out.priv_password = snmp.priv_password; }
    return out;
  };

  const save = async (action: "draft" | "validate" | "apply") => {
    for (let s = 0; s < 5; s++) if (!validateStep(s)) { setStep(s); return; }
    setSaving(action);
    const body: any = { ...f, action, description: f.description || null, location: f.location || null, os_version: f.os_version || null,
      services: items.map(({ key: _k, ...i }) => ({ ...i, warning: i.warning || null, critical: i.critical || null })) };
    if (f.monitoring_method === "ncpa") body.ncpa = { ...ncpa, token: ncpa.token || undefined };
    if (f.monitoring_method === "snmp") body.snmp = snmpPayload();
    if (f.monitoring_method === "nrpe") body.nrpe = nrpe;
    try {
      const r = editing ? await api.put(`/api/servers/${id}`, body) : await api.post("/api/servers", body);
      const sid = r.data.server.id;
      if (r.data.version) setResult({ v: r.data.version, serverId: sid });
      else { toast("success", action === "draft" ? "Saved as draft" : "Server saved", "Changes are pending until the configuration is applied."); nav(`/servers/${sid}`); }
    } catch (e) {
      if (e instanceof ApiError) {
        const fe = e.fieldErrors();
        const mapped: Record<string, string> = {};
        for (const [k, v] of Object.entries(fe)) mapped[k.replace(/^ncpa\./, "").replace(/^snmp\./, "")] = v;
        setErrors(mapped);
      }
      apiError(e, "Save failed");
    } finally { setSaving(null); }
  };

  if (editing && !loaded) return existing.error ? <ErrorBox error={existing.error} /> : <Loading />;
  const methods = METHOD_OPTIONS.filter((m) => m.os.includes(f.os_type));
  const tplOptions = (templates.data?.data ?? []).filter((t: any) => t.os_type === f.os_type || t.monitoring_method === "ping");
  const pickable = cat.filter((c) => c.os_types.includes(f.os_type) && (c.monitoring_method === f.monitoring_method || c.monitoring_method === "ping" || f.monitoring_method === "custom"));

  return (
    <div>
      <PageHeader crumb={network || f.device_type === "network_device" ? "Infrastructure / Network devices" : "Infrastructure / Servers"}
        title={editing ? `Edit ${f.hostname}` : network ? "Add network device" : "Add server"}
        subtitle="Changes are stored in the portal database; Nagios files are generated, validated and applied safely." />
      <div className="steps">
        {STEPS.map((s, i) => (
          <button key={s} className={`step ${i === step ? "active" : i <= maxStep ? "done" : ""}`} onClick={() => i <= maxStep && go(i)} disabled={i > maxStep}>
            <span className="num">{i < step || (i <= maxStep && i !== step) ? <Check size={13} /> : i + 1}</span>{s}
          </button>
        ))}
      </div>
      <Card>
        {step === 0 && (
          <div className="form-grid">
            <Field label="Hostname" required error={errors.hostname} hint="Nagios host name. Letters, digits, dot, dash, underscore.">
              <input className={`input ${errors.hostname ? "invalid" : ""}`} value={f.hostname} onChange={(e) => set("hostname", e.target.value.trim())} maxLength={63} autoFocus /></Field>
            <Field label="Display name" required error={errors.display_name}><input className="input" value={f.display_name} onChange={(e) => set("display_name", e.target.value)} maxLength={120} /></Field>
            <Field label="IP address / FQDN" required error={errors.address}><input className="input mono" value={f.address} onChange={(e) => set("address", e.target.value.trim())} maxLength={255} /></Field>
            <Field label="Location" error={errors.location}><input className="input" value={f.location} onChange={(e) => set("location", e.target.value)} maxLength={120} placeholder="e.g. Head office DC, Rack 4" /></Field>
            <Field label="Environment" required><select className="input" value={f.environment} onChange={(e) => set("environment", e.target.value)}>{ENVIRONMENTS.map((o) => <option key={o.value} value={o.value}>{o.label}</option>)}</select></Field>
            <Field label="Description" error={errors.description}><input className="input" value={f.description} onChange={(e) => set("description", e.target.value)} maxLength={255} /></Field>
            <Field label="Host groups" span2 hint="Groups marked 'manual' are defined in your existing Nagios files.">
              <div className="row">{(groups.data?.data ?? []).map((g: any) => (
                <Checkbox key={g.id} checked={f.group_ids.includes(g.id)} label={<>{g.name}{!g.is_managed && <span className="faint small"> (manual)</span>}</>}
                  onChange={(v) => set("group_ids", v ? [...f.group_ids, g.id] : f.group_ids.filter((x: number) => x !== g.id))} />))}</div>
            </Field>
            <Field label="Contact groups (notifications)" span2 hint={`If none selected, the default contact group "${settings.data?.data?.default_contact_group ?? "admins"}" is used.`}>
              <div className="row">{(cgroups.data?.data ?? []).map((g: any) => (
                <Checkbox key={g.id} checked={f.contact_group_ids.includes(g.id)} label={g.name}
                  onChange={(v) => set("contact_group_ids", v ? [...f.contact_group_ids, g.id] : f.contact_group_ids.filter((x: number) => x !== g.id))} />))}</div>
            </Field>
          </div>
        )}

        {step === 1 && (
          <div className="stack">
            <div className="option-cards">{OS_OPTIONS.map((o) => (
              <button key={o.value} className={`option-card ${f.os_type === o.value ? "selected" : ""}`} onClick={() => {
                set("os_type", o.value); set("device_type", o.value === "network" ? "network_device" : "server");
                const allowed = METHOD_OPTIONS.filter((m) => m.os.includes(o.value)).map((m) => m.value);
                if (!allowed.includes(f.monitoring_method)) { set("monitoring_method", allowed[0]); set("host_check", allowed[0] === "ncpa" ? "agent" : "ping"); }
              }}><span className="ttl">{o.icon}{o.label}</span><span className="dsc">{o.desc}</span></button>))}</div>
            <div className="form-grid">
              <Field label="OS version" hint="Optional, e.g. Windows Server 2022. Filled automatically by a successful NCPA test."><input className="input" value={f.os_version} onChange={(e) => set("os_version", e.target.value)} maxLength={120} /></Field>
              <Field label="Device type"><select className="input" value={f.device_type} onChange={(e) => set("device_type", e.target.value)}><option value="server">Server</option><option value="network_device">Network device</option></select></Field>
            </div>
          </div>
        )}

        {step === 2 && (
          <div className="stack">
            <div className="option-cards">{methods.map((m) => (
              <button key={m.value} className={`option-card ${f.monitoring_method === m.value ? "selected" : ""}`} onClick={() => { set("monitoring_method", m.value); set("host_check", m.value === "ncpa" ? "agent" : "ping"); setTest(null); }}>
                <span className="ttl">{m.icon}{m.label}</span><span className="dsc">{m.desc}</span></button>))}</div>
            {f.monitoring_method === "ncpa" && (
              <div className="form-grid">
                <Field label="NCPA port" required><input className="input" type="number" value={ncpa.port} onChange={(e) => setNcpa({ ...ncpa, port: Number(e.target.value) })} /></Field>
                <Field label="NCPA token" required={!secretSet} error={errors.token} hint={secretSet ? "A token is stored (encrypted). Leave blank to keep it." : "Stored encrypted; never shown again or written into Nagios files."}>
                  <input className={`input ${errors.token ? "invalid" : ""}`} type="password" autoComplete="new-password" value={ncpa.token} onChange={(e) => { setNcpa({ ...ncpa, token: e.target.value }); setErrors({ ...errors, token: "" }); }} placeholder={secretSet ? "********" : ""} /></Field>
                <Field label="Timeout (seconds)"><input className="input" type="number" min={3} max={120} value={ncpa.timeout} onChange={(e) => setNcpa({ ...ncpa, timeout: Number(e.target.value) })} /></Field>
                <Field label="Host check" hint="How Nagios decides the host is UP"><select className="input" value={f.host_check} onChange={(e) => set("host_check", e.target.value)}><option value="agent">NCPA agent responds</option><option value="ping">ICMP ping</option></select></Field>
                <div className="span-2 row"><Checkbox checked={ncpa.ssl_enabled} onChange={(v) => setNcpa({ ...ncpa, ssl_enabled: v })} label="SSL enabled (HTTPS)" />
                  <Checkbox checked={ncpa.verify_ssl} onChange={(v) => setNcpa({ ...ncpa, verify_ssl: v })} label="Verify certificate (disable for NCPA's default self-signed certificate)" /></div>
              </div>
            )}
            {f.monitoring_method === "snmp" && (
              <div className="form-grid">
                <Field label="SNMP version"><select className="input" value={snmp.version} onChange={(e) => setSnmp({ ...snmp, version: e.target.value })}><option value="2c">v2c</option><option value="3">v3</option></select></Field>
                {snmp.version === "2c" ? (
                  <Field label="Community" required={!secretSet} error={errors.community} hint={secretSet ? "Stored encrypted. Leave blank to keep." : "Stored encrypted."}>
                    <input className="input" type="password" autoComplete="new-password" value={snmp.community} onChange={(e) => setSnmp({ ...snmp, community: e.target.value })} placeholder={secretSet ? "********" : ""} /></Field>
                ) : (<>
                  <Field label="Username" required error={errors.username}><input className="input" value={snmp.username} onChange={(e) => setSnmp({ ...snmp, username: e.target.value })} /></Field>
                  <Field label="Security level"><select className="input" value={snmp.security_level} onChange={(e) => setSnmp({ ...snmp, security_level: e.target.value })}>{["noAuthNoPriv", "authNoPriv", "authPriv"].map((x) => <option key={x}>{x}</option>)}</select></Field>
                  <Field label="Auth protocol"><select className="input" value={snmp.auth_protocol} onChange={(e) => setSnmp({ ...snmp, auth_protocol: e.target.value })}>{["MD5", "SHA", "SHA-224", "SHA-256", "SHA-384", "SHA-512"].map((x) => <option key={x}>{x}</option>)}</select></Field>
                  <Field label="Auth password" hint={secretSet ? "Leave blank to keep" : ""}><input className="input" type="password" autoComplete="new-password" value={snmp.auth_password} onChange={(e) => setSnmp({ ...snmp, auth_password: e.target.value })} /></Field>
                  <Field label="Privacy protocol"><select className="input" value={snmp.priv_protocol} onChange={(e) => setSnmp({ ...snmp, priv_protocol: e.target.value })}>{["DES", "AES", "AES-192", "AES-256"].map((x) => <option key={x}>{x}</option>)}</select></Field>
                  <Field label="Privacy password" hint={secretSet ? "Leave blank to keep" : ""}><input className="input" type="password" autoComplete="new-password" value={snmp.priv_password} onChange={(e) => setSnmp({ ...snmp, priv_password: e.target.value })} /></Field>
                </>)}
                <Field label="Host check"><select className="input" value={f.host_check} onChange={(e) => set("host_check", e.target.value)}><option value="ping">ICMP ping</option><option value="agent">SNMP agent responds</option></select></Field>
              </div>
            )}
            {f.monitoring_method === "nrpe" && (
              <div className="form-grid">
                <Field label="NRPE port"><input className="input" type="number" value={nrpe.port} onChange={(e) => setNrpe({ ...nrpe, port: Number(e.target.value) })} /></Field>
                <Field label="Timeout (seconds)"><input className="input" type="number" value={nrpe.timeout} onChange={(e) => setNrpe({ ...nrpe, timeout: Number(e.target.value) })} /></Field>
                <Field label="Host check"><select className="input" value={f.host_check} onChange={(e) => set("host_check", e.target.value)}><option value="ping">ICMP ping</option><option value="agent">NRPE port open</option></select></Field>
              </div>
            )}
            {["ncpa", "snmp"].includes(f.monitoring_method) && can("servers.test") && (
              <div className="stack">
                <div><button className="btn" onClick={runTest} disabled={testing || !f.address}>{testing ? <Spinner /> : null}Test connection</button>
                  {!f.address && <span className="faint small" style={{ marginLeft: 8 }}>Enter an address in step 1 first</span>}</div>
                {test && <TestResult r={test} />}
              </div>
            )}
          </div>
        )}

        {step === 3 && (
          <div className="stack">
            <div className="row">
              <Field label="Monitoring template"><select className="input" style={{ minWidth: 280 }} value={f.template_id ?? ""} onChange={(e) => applyTemplate(e.target.value ? Number(e.target.value) : null, items.length === 0)}>
                <option value="">No template</option>{tplOptions.map((t: any) => <option key={t.id} value={t.id}>{t.name} ({t.items.length} services)</option>)}</select></Field>
              {f.template_id && items.length > 0 && <button className="btn sm" style={{ alignSelf: "flex-end" }} onClick={() => applyTemplate(f.template_id, true)}>Replace services with template</button>}
              <span style={{ flex: 1 }} />
              <button className="btn primary" style={{ alignSelf: "flex-end" }} onClick={() => setPicker(true)}><Plus size={15} />Add service</button>
            </div>
            {items.length === 0 && <Alert kind="info">No services selected. Choose a template or add services individually. The host check runs regardless.</Alert>}
            <table className="table">
              <thead><tr><th style={{ width: 40 }}>On</th><th>Service description</th><th>Check</th><th>Parameters</th><th /></tr></thead>
              <tbody>{items.map((i) => {
                const svc = catById[i.service_id];
                return (
                  <tr key={i.key}>
                    <td><input type="checkbox" checked={i.is_enabled} onChange={(e) => updItem(i.key, { is_enabled: e.target.checked })} aria-label="enabled" /></td>
                    <td><input className="input sm" value={i.service_description} maxLength={100} onChange={(e) => updItem(i.key, { service_description: e.target.value })} />
                      {errors[`svc-${i.key}`] && <div className="small" style={{ color: "var(--critical-text)" }}>{errors[`svc-${i.key}`]}</div>}</td>
                    <td className="small">{svc?.name}<div className="faint">{methodLabel(svc?.monitoring_method)}</div></td>
                    <td><div className="row">{(svc?.params_schema ?? []).map((p: any) => (
                      <label key={p.name} className="small" style={{ display: "flex", flexDirection: "column", gap: 2 }}>{p.label}
                        {SELECTS[p.type] ? (
                          <select className="input sm" value={i.params[p.name] ?? ""} onChange={(e) => updItem(i.key, { params: { ...i.params, [p.name]: e.target.value } })}>{SELECTS[p.type].map((o) => <option key={o} value={o}>{o || "(none)"}</option>)}</select>
                        ) : (
                          <input className="input sm" style={{ width: p.type === "drive" ? 60 : 150 }} value={i.params[p.name] ?? ""} onChange={(e) => {
                            const params = { ...i.params, [p.name]: e.target.value };
                            const autoDesc = describe(svc.default_description, i.params) === i.service_description;
                            updItem(i.key, { params, ...(autoDesc ? { service_description: describe(svc.default_description, params) } : {}) });
                          }} />
                        )}</label>))}{!(svc?.params_schema ?? []).length && <span className="faint">-</span>}</div></td>
                    <td className="actions"><button className="btn sm ghost" aria-label="Remove" onClick={() => setItems(items.filter((x) => x.key !== i.key))}><Trash2 size={14} /></button></td>
                  </tr>
                );
              })}</tbody>
            </table>
          </div>
        )}

        {step === 4 && (
          <div className="stack">
            <h3>Host settings</h3>
            <div className="grid grid-4">
              <Field label="Check interval (min)"><input className="input" type="number" min={1} value={f.check_interval} onChange={(e) => set("check_interval", Number(e.target.value))} /></Field>
              <Field label="Retry interval (min)"><input className="input" type="number" min={1} value={f.retry_interval} onChange={(e) => set("retry_interval", Number(e.target.value))} /></Field>
              <Field label="Max check attempts"><input className="input" type="number" min={1} max={20} value={f.max_check_attempts} onChange={(e) => set("max_check_attempts", Number(e.target.value))} /></Field>
              <Field label="Notification interval (min)" hint="0 = notify once"><input className="input" type="number" min={0} value={f.notification_interval} onChange={(e) => set("notification_interval", Number(e.target.value))} /></Field>
              <Field label="Check period"><select className="input" value={f.check_period} onChange={(e) => set("check_period", e.target.value)}>{(tps.data?.data ?? ["24x7"]).map((t: string) => <option key={t}>{t}</option>)}</select></Field>
              <Field label="Notification period"><select className="input" value={f.notification_period} onChange={(e) => set("notification_period", e.target.value)}>{(tps.data?.data ?? ["24x7"]).map((t: string) => <option key={t}>{t}</option>)}</select></Field>
              <Field label="Notifications"><Checkbox checked={f.notifications_enabled} onChange={(v) => set("notifications_enabled", v)} label="Enabled" /></Field>
            </div>
            <h3 className="mt">Service thresholds</h3>
            <div className="faint small">Nagios range syntax: <code>80</code> alerts above 80, <code>10:</code> below 10, <code>@5:10</code> inside 5-10. Ping uses <code>rta,loss%</code> e.g. <code>200.0,20%</code>.</div>
            <div className="table-wrap"><table className="table">
              <thead><tr><th>Service</th><th>Warning</th><th>Critical</th><th>Check interval</th><th>Retry interval</th><th>Max attempts</th><th>Notification interval</th><th>Notify</th></tr></thead>
              <tbody>{items.filter((i) => i.is_enabled).map((i) => {
                const svc = catById[i.service_id];
                return (
                  <tr key={i.key}>
                    <td>{i.service_description}{svc?.unit && <span className="faint small"> ({svc.unit})</span>}</td>
                    <td><input className="input sm" style={{ width: 100 }} value={i.warning} onChange={(e) => updItem(i.key, { warning: e.target.value })} /></td>
                    <td><input className="input sm" style={{ width: 100 }} value={i.critical} onChange={(e) => updItem(i.key, { critical: e.target.value })} /></td>
                    <td><input className="input sm" type="number" min={1} style={{ width: 70 }} value={i.check_interval} onChange={(e) => updItem(i.key, { check_interval: Number(e.target.value) })} /></td>
                    <td><input className="input sm" type="number" min={1} style={{ width: 70 }} value={i.retry_interval} onChange={(e) => updItem(i.key, { retry_interval: Number(e.target.value) })} /></td>
                    <td><input className="input sm" type="number" min={1} max={20} style={{ width: 70 }} value={i.max_check_attempts} onChange={(e) => updItem(i.key, { max_check_attempts: Number(e.target.value) })} /></td>
                    <td><input className="input sm" type="number" min={0} style={{ width: 80 }} value={i.notification_interval} onChange={(e) => updItem(i.key, { notification_interval: Number(e.target.value) })} /></td>
                    <td><input type="checkbox" checked={i.notifications_enabled} onChange={(e) => updItem(i.key, { notifications_enabled: e.target.checked })} aria-label="notifications" /></td>
                  </tr>
                );
              })}</tbody>
            </table></div>
          </div>
        )}

        {step === 5 && (
          <div className="stack">
            {Object.values(errors).some(Boolean) && <Alert kind="error">Please correct: {Object.entries(errors).filter(([, v]) => v).map(([k, v]) => `${k}: ${v}`).join("; ")}</Alert>}
            <div className="grid grid-2">
              <dl className="dl">
                <dt>Hostname</dt><dd><strong>{f.hostname}</strong></dd><dt>Display name</dt><dd>{f.display_name}</dd>
                <dt>Address</dt><dd className="mono">{f.address}</dd><dt>Environment</dt><dd>{envLabel(f.environment)}</dd>
                <dt>Location</dt><dd>{f.location || "-"}</dd><dt>Description</dt><dd>{f.description || "-"}</dd>
                <dt>Host groups</dt><dd>{(groups.data?.data ?? []).filter((g: any) => f.group_ids.includes(g.id)).map((g: any) => g.name).join(", ") || "-"}</dd>
                <dt>Contact groups</dt><dd>{(cgroups.data?.data ?? []).filter((g: any) => f.contact_group_ids.includes(g.id)).map((g: any) => g.name).join(", ") || `(default: ${settings.data?.data?.default_contact_group ?? "admins"})`}</dd>
              </dl>
              <dl className="dl">
                <dt>Operating system</dt><dd>{osLabel(f.os_type)} {f.os_version}</dd><dt>Monitoring</dt><dd>{methodLabel(f.monitoring_method)} (host check: {f.host_check})</dd>
                {f.monitoring_method === "ncpa" && <><dt>NCPA</dt><dd>port {ncpa.port}, {ncpa.ssl_enabled ? "HTTPS" : "HTTP"}{ncpa.verify_ssl ? ", verify cert" : ""}, timeout {ncpa.timeout}s, token {ncpa.token ? "new (will be encrypted)" : secretSet ? "stored" : "missing"}</dd></>}
                {f.monitoring_method === "snmp" && <><dt>SNMP</dt><dd>v{snmp.version}{snmp.version === "3" && ` user ${snmp.username} (${snmp.security_level})`}</dd></>}
                <dt>Intervals</dt><dd>check {f.check_interval}m, retry {f.retry_interval}m, {f.max_check_attempts} attempts, notify every {f.notification_interval}m</dd>
                <dt>Connection test</dt><dd>{test ? test.label : "not run"}</dd>
              </dl>
            </div>
            <table className="table">
              <thead><tr><th>Service</th><th>Check</th><th>Warning</th><th>Critical</th><th>Interval</th><th>Notify</th></tr></thead>
              <tbody>{items.map((i) => <tr key={i.key} style={{ opacity: i.is_enabled ? 1 : 0.5 }}><td>{i.service_description}{!i.is_enabled && " (disabled)"}</td><td className="small">{catById[i.service_id]?.name}</td>
                <td>{i.warning || "-"}</td><td>{i.critical || "-"}</td><td>{i.check_interval}m / {i.retry_interval}m</td><td>{i.notifications_enabled ? "Yes" : "No"}</td></tr>)}</tbody>
            </table>
          </div>
        )}

        <hr />
        <div className="row between">
          <button className="btn" onClick={() => nav(-1)}>Cancel</button>
          <div className="row">
            {step > 0 && <button className="btn" onClick={() => setStep(step - 1)}>Back</button>}
            {step < 5 && <button className="btn primary" onClick={() => go(step + 1)}>Next</button>}
            {step === 5 && <>
              <button className="btn" disabled={!!saving} onClick={() => save("draft")}>Save as draft</button>
              {can("config.validate") && <button className="btn" disabled={!!saving} onClick={() => save("validate")}>{saving === "validate" && <Spinner />}Save &amp; validate</button>}
              {can("config.apply") && <button className="btn primary" disabled={!!saving} onClick={() => save("apply")}>{saving === "apply" && <Spinner />}Save &amp; apply</button>}
            </>}
          </div>
        </div>
      </Card>

      {picker && (
        <Modal title="Add monitoring service" size="wide" onClose={() => setPicker(false)}>
          <div className="svc-pick">{pickable.map((c: any) => (
            <button key={c.id} className="svc-card" onClick={() => { setItems([...items, fromCatalog(c)]); setPicker(false); }}>
              <div className="title">{c.name}</div><div className="desc">{methodLabel(c.monitoring_method)} - {c.category}{c.description ? ` - ${c.description}` : ""}</div>
            </button>))}</div>
          {pickable.length === 0 && <div className="empty">No service definitions for this OS / method.</div>}
        </Modal>
      )}
      {saving && <Modal title={saving === "draft" ? "Saving" : saving === "validate" ? "Saving and validating" : "Saving and applying"} onClose={() => { /* busy */ }}><Spinner label="Working... generating and validating the Nagios configuration" /></Modal>}
      {result && (
        <Modal title="Configuration result" size="wide" onClose={() => nav(`/servers/${result.serverId}`)}
          footer={<><button className="btn" onClick={() => setResult(null)}>Stay here</button><button className="btn primary" onClick={() => nav(`/servers/${result.serverId}`)}>Open server</button></>}>
          {result.v ? <VersionResult v={result.v} /> : null}
        </Modal>
      )}
    </div>
  );
}
