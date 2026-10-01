import { useEffect, useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { Archive, Download, Pencil, Plus, RefreshCw, RotateCcw, Send, Trash2, Unlock, Upload } from "lucide-react";
import { api, download } from "../lib/api";
import { useAuth } from "../lib/auth";
import { ENVIRONMENTS, OS_TYPES, bytes, envLabel, fmtDate } from "../lib/format";
import { useConfigAction } from "../components/ConfigAction";
import { VersionResult } from "../components/Pipeline";
import { Alert, Card, Checkbox, DataTable, ErrorBox, Field, Loading, Modal, PageHeader, Spinner, StateBadge, useUi, type Column } from "../components/ui";

function SaveModal({ title, onClose, onSave, children, size }: { title: string; onClose: () => void; onSave: () => Promise<void>; children: React.ReactNode; size?: "wide" | "xwide" }) {
  const [err, setErr] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);
  return (
    <Modal title={title} onClose={onClose} size={size} footer={<><button className="btn" onClick={onClose}>Cancel</button><button className="btn primary" disabled={busy} onClick={async () => { setBusy(true); setErr(null); try { await onSave(); onClose(); } catch (e) { setErr(e); } finally { setBusy(false); } }}>Save</button></>}>
      <div className="stack">{err ? <ErrorBox error={err} /> : null}{children}</div>
    </Modal>
  );
}

const SUPER_ADMIN_ONLY = ["maintenance.cleanup"];

/* Users --------------------------------------------------------------------- */
export function UsersPage() {
  const qc = useQueryClient();
  const { user: me } = useAuth();
  const { confirm, toast, apiError } = useUi();
  const users = useQuery({ queryKey: ["users"], queryFn: () => api.get("/api/users") });
  const roles = useQuery({ queryKey: ["roles"], queryFn: () => api.get("/api/roles") });
  const [edit, setEdit] = useState<any>(null);
  const refresh = () => qc.invalidateQueries({ queryKey: ["users"] });
  const cols: Column<any>[] = [
    { key: "username", header: "Username", render: (u) => <><strong>{u.username}</strong>{u.id === me?.id && <span className="badge info" style={{ marginLeft: 6 }}>You</span>}</> },
    { key: "full_name", header: "Name" }, { key: "email", header: "E-mail" },
    { key: "roles", header: "Roles", sortable: false, render: (u) => u.roles.map((r: any) => <span className="tag" key={r.id}>{r.display_name}</span>) },
    { key: "is_active", header: "Status", render: (u) => (u.locked ? <span className="badge critical">Locked</span> : u.is_active ? <span className="badge good">Active</span> : <span className="badge">Disabled</span>) },
    { key: "last_login_at", header: "Last login", render: (u) => <span className="small">{fmtDate(u.last_login_at)}{u.last_login_ip && <span className="faint"> from {u.last_login_ip}</span>}</span> },
    { key: "a", header: "", sortable: false, className: "actions", render: (u) => (
      <span className="row" style={{ justifyContent: "flex-end", flexWrap: "nowrap" }}>
        {u.locked && <button className="btn sm ghost" title="Unlock" onClick={async () => { try { await api.post(`/api/users/${u.id}/unlock`); toast("success", "User unlocked"); refresh(); } catch (e) { apiError(e); } }}><Unlock size={14} /></button>}
        <button className="btn sm ghost" title="Edit" onClick={() => setEdit(u)}><Pencil size={14} /></button>
        {u.id !== me?.id && <button className="btn sm ghost" title="Delete" onClick={async () => { if (await confirm({ title: "Delete user", message: `Delete ${u.username}?`, danger: true, confirmLabel: "Delete" })) { try { await api.del(`/api/users/${u.id}`); refresh(); } catch (e) { apiError(e); } } }}><Trash2 size={14} /></button>}
      </span>) },
  ];
  return (
    <div>
      <PageHeader title="Users" actions={<button className="btn primary" onClick={() => setEdit({ roles: [], is_active: true })}><Plus size={15} />New user</button>} />
      <ErrorBox error={users.error} />
      <Card flush>{users.isLoading ? <Loading /> : <DataTable rows={users.data?.data ?? []} columns={cols} rowKey={(u) => u.id} />}</Card>
      {edit && <UserForm item={edit} roles={roles.data?.data ?? []} onClose={() => setEdit(null)} onSaved={refresh} />}
    </div>
  );
}
function UserForm({ item, roles, onClose, onSaved }: any) {
  const [v, setV] = useState({ username: item.username ?? "", full_name: item.full_name ?? "", email: item.email ?? "", is_active: item.is_active ?? true, role_ids: item.roles.map((r: any) => r.id), password: "", must_change_password: true });
  return (
    <SaveModal title={item.id ? `Edit ${item.username}` : "New user"} onClose={onClose} onSave={async () => {
      const body = { ...v, email: v.email || null, password: v.password || null };
      if (item.id) await api.put(`/api/users/${item.id}`, body); else await api.post("/api/users", body);
      onSaved();
    }}>
      <div className="form-grid">
        <Field label="Username" required><input className="input" disabled={!!item.id} value={v.username} onChange={(e) => setV({ ...v, username: e.target.value })} /></Field>
        <Field label="Full name"><input className="input" value={v.full_name} onChange={(e) => setV({ ...v, full_name: e.target.value })} /></Field>
        <Field label="E-mail"><input className="input" type="email" value={v.email} onChange={(e) => setV({ ...v, email: e.target.value })} /></Field>
        <Field label={item.id ? "Reset password" : "Initial password"} required={!item.id} hint="12+ characters, 3 of: lower, upper, digit, symbol"><input className="input" type="password" autoComplete="new-password" value={v.password} onChange={(e) => setV({ ...v, password: e.target.value })} /></Field>
        <Field label="Roles" span2><div className="row">{roles.map((r: any) => <Checkbox key={r.id} checked={v.role_ids.includes(r.id)} label={r.display_name} onChange={(c) => setV({ ...v, role_ids: c ? [...v.role_ids, r.id] : v.role_ids.filter((x: number) => x !== r.id) })} />)}</div></Field>
        <Checkbox checked={v.is_active} onChange={(c) => setV({ ...v, is_active: c })} label="Active" />
        {v.password && <Checkbox checked={v.must_change_password} onChange={(c) => setV({ ...v, must_change_password: c })} label="Require password change at next login" />}
      </div>
    </SaveModal>
  );
}

/* Roles ---------------------------------------------------------------------- */
export function RolesPage() {
  const qc = useQueryClient();
  const { can } = useAuth();
  const { confirm, apiError } = useUi();
  const roles = useQuery({ queryKey: ["roles"], queryFn: () => api.get("/api/roles") });
  const perms = useQuery({ queryKey: ["permissions"], queryFn: () => api.get("/api/permissions") });
  const [edit, setEdit] = useState<any>(null);
  const all: any[] = perms.data?.data ?? [];
  const rs: any[] = roles.data?.data ?? [];
  const cats = Array.from(new Set(all.map((p) => p.category)));
  return (
    <div className="stack">
      <PageHeader title="Roles and permissions" subtitle="Built-in roles: Super Admin (full), Administrator (servers & monitoring), Operator (view & acknowledge), Viewer (read-only)."
        actions={can("roles.manage") && <button className="btn primary" onClick={() => setEdit({ permissions: [] })}><Plus size={15} />New role</button>} />
      <ErrorBox error={roles.error} />
      <Card flush>
        {roles.isLoading || perms.isLoading ? <Loading /> : (
          <div className="table-wrap"><table className="table">
            <thead><tr><th>Permission</th>{rs.map((r) => <th key={r.id} style={{ textAlign: "center" }}>{r.display_name}<div className="faint small" style={{ fontWeight: 400 }}>{r.users} user(s)</div>
              {can("roles.manage") && r.name !== "super_admin" && <div className="row" style={{ justifyContent: "center", gap: 2 }}><button className="btn sm ghost icon" onClick={() => setEdit(r)} aria-label="Edit role"><Pencil size={12} /></button>
                {!r.is_system && <button className="btn sm ghost icon" aria-label="Delete role" onClick={async () => { if (await confirm({ title: "Delete role", message: `Delete role ${r.display_name}?`, danger: true })) { try { await api.del(`/api/roles/${r.id}`); qc.invalidateQueries({ queryKey: ["roles"] }); } catch (e) { apiError(e); } } }}><Trash2 size={12} /></button>}</div>}</th>)}</tr></thead>
            <tbody>{cats.map((c) => [
              <tr key={c}><td colSpan={rs.length + 1} style={{ background: "var(--surface-2)", fontWeight: 600 }}>{c}</td></tr>,
              ...all.filter((p) => p.category === c).map((p) => (
                <tr key={p.code}><td>{p.description}<div className="faint small mono">{p.code}</div></td>
                  {rs.map((r) => <td key={r.id} style={{ textAlign: "center" }}>{r.permissions.includes(p.code) ? <span className="badge good" aria-label="granted">✓</span> : <span className="faint">-</span>}</td>)}</tr>
              )),
            ])}</tbody>
          </table></div>
        )}
      </Card>
      {edit && (
        <RoleForm item={edit} all={all} onClose={() => setEdit(null)} onSaved={() => qc.invalidateQueries({ queryKey: ["roles"] })} />
      )}
    </div>
  );
}
function RoleForm({ item, all, onClose, onSaved }: any) {
  const [v, setV] = useState({ name: item.name ?? "", display_name: item.display_name ?? "", description: item.description ?? "", permissions: item.permissions as string[] });
  return (
    <SaveModal size="wide" title={item.id ? `Edit role ${item.display_name}` : "New role"} onClose={onClose} onSave={async () => {
      const body = { ...v, description: v.description || null };
      if (item.id) await api.put(`/api/roles/${item.id}`, body); else await api.post("/api/roles", body);
      onSaved();
    }}>
      <div className="form-grid">
        <Field label="Code" required hint="lowercase, e.g. network_admin"><input className="input" disabled={!!item.id} value={v.name} onChange={(e) => setV({ ...v, name: e.target.value })} /></Field>
        <Field label="Display name" required><input className="input" value={v.display_name} onChange={(e) => setV({ ...v, display_name: e.target.value })} /></Field>
        <Field label="Description" span2><input className="input" value={v.description} onChange={(e) => setV({ ...v, description: e.target.value })} /></Field>
      </div>
      <Alert kind="info">You can only grant permissions you hold yourself.</Alert>
      <div className="perm-grid">{all.filter((p: any) => !SUPER_ADMIN_ONLY.includes(p.code)).map((p: any) => <Checkbox key={p.code} checked={v.permissions.includes(p.code)} label={<span>{p.description} <span className="faint small">({p.code})</span></span>} onChange={(c) => setV({ ...v, permissions: c ? [...v.permissions, p.code] : v.permissions.filter((x) => x !== p.code) })} />)}</div>
    </SaveModal>
  );
}

/* Settings ------------------------------------------------------------------ */
export function SettingsPage() {
  const qc = useQueryClient();
  const { toast, apiError } = useUi();
  const q = useQuery({ queryKey: ["settings"], queryFn: () => api.get("/api/settings") });
  const cg = useQuery({ queryKey: ["contact-groups"], queryFn: () => api.get("/api/contact-groups") });
  const [v, setV] = useState<any>(null);
  useEffect(() => { if (q.data && !v) setV(q.data.data); }, [q.data, v]);
  if (!v) return <Loading />;
  const save = async () => {
    try { await api.put("/api/settings", v); toast("success", "Settings saved"); qc.invalidateQueries({ queryKey: ["settings"] }); } catch (e) { apiError(e, "Save failed"); }
  };
  const set = (k: string, val: any) => setV({ ...v, [k]: val });
  return (
    <div className="stack">
      <PageHeader title="System settings" actions={<button className="btn primary" onClick={save}>Save settings</button>} />
      <div className="grid grid-2">
        <Card title="General"><div className="form-grid">
          <Field label="Display time zone" hint="IANA name, e.g. Asia/Kolkata"><input className="input" value={v.display_timezone} onChange={(e) => set("display_timezone", e.target.value)} /></Field>
          <Field label="Session idle timeout (minutes)"><input className="input" type="number" value={v.session_idle_minutes} onChange={(e) => set("session_idle_minutes", Number(e.target.value))} /></Field>
          <Field label="Performance data retention (days)"><input className="input" type="number" value={v.perf_retention_days} onChange={(e) => set("perf_retention_days", Number(e.target.value))} /></Field>
        </div></Card>
        <Card title="Nagios defaults"><div className="form-grid">
          <Field label="Default contact group"><select className="input" value={v.default_contact_group} onChange={(e) => set("default_contact_group", e.target.value)}>{(cg.data?.data ?? []).map((g: any) => <option key={g.id}>{g.name}</option>)}</select></Field>
          <Field label="Host notification command"><input className="input" value={v.host_notification_command} onChange={(e) => set("host_notification_command", e.target.value)} /></Field>
          <Field label="Service notification command"><input className="input" value={v.service_notification_command} onChange={(e) => set("service_notification_command", e.target.value)} /></Field>
        </div></Card>
        <Card title="NCPA defaults"><div className="form-grid">
          <Field label="Port"><input className="input" type="number" value={v.ncpa_default_port} onChange={(e) => set("ncpa_default_port", Number(e.target.value))} /></Field>
          <Field label="Timeout (s)"><input className="input" type="number" value={v.ncpa_default_timeout} onChange={(e) => set("ncpa_default_timeout", Number(e.target.value))} /></Field>
          <Checkbox checked={!!v.ncpa_default_verify_ssl} onChange={(c) => set("ncpa_default_verify_ssl", c)} label="Verify agent TLS certificates by default" />
        </div></Card>
        <Card title="SLA targets (%)"><div className="form-grid">
          {ENVIRONMENTS.map((e) => <Field key={e.value} label={e.label}><input className="input" type="number" step="0.01" value={v.sla_targets?.[e.value] ?? ""} onChange={(ev) => set("sla_targets", { ...v.sla_targets, [e.value]: Number(ev.target.value) })} /></Field>)}
        </div></Card>
        <Card title="Infrastructure health thresholds (%)"><div className="form-grid">
          {["cpu", "memory", "disk"].map((k) => <Field key={k} label={k.toUpperCase()}><input className="input" type="number" value={v.health_thresholds?.[k] ?? ""} onChange={(e) => set("health_thresholds", { ...v.health_thresholds, [k]: Number(e.target.value) })} /></Field>)}
        </div></Card>
      </div>
    </div>
  );
}

/* Notifications ------------------------------------------------------------- */
export function NotificationsPage() {
  const qc = useQueryClient();
  const { confirm, toast, apiError } = useUi();
  const prov = useQuery({ queryKey: ["providers"], queryFn: () => api.get("/api/notification-providers") });
  const ch = useQuery({ queryKey: ["channels"], queryFn: () => api.get("/api/notification-channels") });
  const rules = useQuery({ queryKey: ["rules"], queryFn: () => api.get("/api/notification-rules") });
  const groups = useQuery({ queryKey: ["hostgroups"], queryFn: () => api.get("/api/hostgroups") });
  const [editCh, setEditCh] = useState<any>(null);
  const [editRule, setEditRule] = useState<any>(null);
  const providers: any[] = prov.data?.data ?? [];
  const events: string[] = prov.data?.meta?.event_types ?? [];
  const inv = () => { qc.invalidateQueries({ queryKey: ["channels"] }); qc.invalidateQueries({ queryKey: ["rules"] }); };
  const test = async (c: any) => {
    try { const r = await api.post(`/api/notification-channels/${c.id}/test`); r.data.ok ? toast("success", "Test notification sent") : toast("error", "Test failed", r.data.error); } catch (e) { apiError(e); }
  };
  return (
    <div className="stack">
      <PageHeader title="Notifications" subtitle="Portal notification rules run alongside Nagios' own contact notifications. Providers are pluggable (e-mail, Teams, WhatsApp/SMS via HTTP gateways, webhooks, in-app)." />
      <Card title="Channels" actions={<button className="btn primary sm" onClick={() => setEditCh({ provider: providers[0]?.key, settings: {}, is_enabled: true })}><Plus size={14} />New channel</button>} flush>
        <DataTable rows={ch.data?.data ?? []} rowKey={(r: any) => r.id} empty="No channels" columns={[
          { key: "name", header: "Name" }, { key: "provider_label", header: "Provider" },
          { key: "is_enabled", header: "Enabled", render: (r: any) => (r.is_enabled ? "Yes" : "No") },
          { key: "a", header: "", sortable: false, className: "actions", render: (r: any) => <span className="row" style={{ justifyContent: "flex-end", flexWrap: "nowrap" }}>
            <button className="btn sm ghost" title="Send test" onClick={() => test(r)}><Send size={14} /></button>
            <button className="btn sm ghost" onClick={() => setEditCh(r)}><Pencil size={14} /></button>
            <button className="btn sm ghost" onClick={async () => { if (await confirm({ title: "Delete channel", message: `Delete ${r.name}? Its rules are deleted too.`, danger: true })) { await api.del(`/api/notification-channels/${r.id}`); inv(); } }}><Trash2 size={14} /></button></span> }]} />
      </Card>
      <Card title="Rules" actions={<button className="btn primary sm" disabled={!(ch.data?.data ?? []).length} onClick={() => setEditRule({ event_types: ["host_down", "service_critical"], environments: [], group_ids: [], server_ids: [], throttle_minutes: 30, skip_acknowledged: true, is_enabled: true, channel_id: ch.data?.data?.[0]?.id })}><Plus size={14} />New rule</button>} flush>
        <DataTable rows={rules.data?.data ?? []} rowKey={(r: any) => r.id} empty="No rules" columns={[
          { key: "name", header: "Rule" }, { key: "event_types", header: "Events", sortable: false, render: (r: any) => r.event_types.map((e: string) => <span className="tag" key={e}>{e.replace(/_/g, " ")}</span>) },
          { key: "channel_name", header: "Channel" }, { key: "environments", header: "Environments", sortable: false, render: (r: any) => r.environments.map(envLabel).join(", ") || "All" },
          { key: "throttle_minutes", header: "Throttle", render: (r: any) => `${r.throttle_minutes} min` },
          { key: "is_enabled", header: "Enabled", render: (r: any) => (r.is_enabled ? "Yes" : "No") },
          { key: "a", header: "", sortable: false, className: "actions", render: (r: any) => <span className="row" style={{ justifyContent: "flex-end", flexWrap: "nowrap" }}>
            <button className="btn sm ghost" onClick={() => setEditRule(r)}><Pencil size={14} /></button>
            <button className="btn sm ghost" onClick={async () => { if (await confirm({ title: "Delete rule", message: `Delete ${r.name}?`, danger: true })) { await api.del(`/api/notification-rules/${r.id}`); inv(); } }}><Trash2 size={14} /></button></span> }]} />
      </Card>
      {editCh && <ChannelForm item={editCh} providers={providers} onClose={() => setEditCh(null)} onSaved={inv} />}
      {editRule && (
        <SaveModal size="wide" title={editRule.id ? "Edit rule" : "New rule"} onClose={() => setEditRule(null)} onSave={async () => {
          const body = { ...editRule }; delete body.id; delete body.channel_name;
          if (editRule.id) await api.put(`/api/notification-rules/${editRule.id}`, body); else await api.post("/api/notification-rules", body);
          inv();
        }}>
          <div className="form-grid">
            <Field label="Name" required><input className="input" value={editRule.name ?? ""} onChange={(e) => setEditRule({ ...editRule, name: e.target.value })} /></Field>
            <Field label="Channel"><select className="input" value={editRule.channel_id} onChange={(e) => setEditRule({ ...editRule, channel_id: Number(e.target.value) })}>{(ch.data?.data ?? []).map((c: any) => <option key={c.id} value={c.id}>{c.name}</option>)}</select></Field>
            <Field label="Events" span2><div className="row">{events.map((e) => <Checkbox key={e} checked={editRule.event_types.includes(e)} label={e.replace(/_/g, " ")} onChange={(c) => setEditRule({ ...editRule, event_types: c ? [...editRule.event_types, e] : editRule.event_types.filter((x: string) => x !== e) })} />)}</div></Field>
            <Field label="Environments (none = all)" span2><div className="row">{ENVIRONMENTS.map((e) => <Checkbox key={e.value} checked={editRule.environments.includes(e.value)} label={e.label} onChange={(c) => setEditRule({ ...editRule, environments: c ? [...editRule.environments, e.value] : editRule.environments.filter((x: string) => x !== e.value) })} />)}</div></Field>
            <Field label="Host groups (none = all)" span2><div className="row">{(groups.data?.data ?? []).map((g: any) => <Checkbox key={g.id} checked={editRule.group_ids.includes(g.id)} label={g.name} onChange={(c) => setEditRule({ ...editRule, group_ids: c ? [...editRule.group_ids, g.id] : editRule.group_ids.filter((x: number) => x !== g.id) })} />)}</div></Field>
            <Field label="Throttle (minutes)" hint="Suppress repeats of the same event for the same object"><input className="input" type="number" value={editRule.throttle_minutes} onChange={(e) => setEditRule({ ...editRule, throttle_minutes: Number(e.target.value) })} /></Field>
            <div className="stack"><Checkbox checked={editRule.skip_acknowledged} onChange={(c) => setEditRule({ ...editRule, skip_acknowledged: c })} label="Skip acknowledged / in downtime" /><Checkbox checked={editRule.is_enabled} onChange={(c) => setEditRule({ ...editRule, is_enabled: c })} label="Enabled" /></div>
          </div>
        </SaveModal>
      )}
    </div>
  );
}
function ChannelForm({ item, providers, onClose, onSaved }: any) {
  const [v, setV] = useState<any>({ name: item.name ?? "", provider: item.provider, settings: { ...(item.settings ?? {}) }, is_enabled: item.is_enabled });
  const p = providers.find((x: any) => x.key === v.provider);
  return (
    <SaveModal size="wide" title={item.id ? `Edit ${item.name}` : "New channel"} onClose={onClose} onSave={async () => {
      if (item.id) await api.put(`/api/notification-channels/${item.id}`, v); else await api.post("/api/notification-channels", v);
      onSaved();
    }}>
      <div className="form-grid">
        <Field label="Name" required><input className="input" value={v.name} onChange={(e) => setV({ ...v, name: e.target.value })} /></Field>
        <Field label="Provider"><select className="input" disabled={!!item.id} value={v.provider} onChange={(e) => setV({ ...v, provider: e.target.value, settings: {} })}>{providers.map((x: any) => <option key={x.key} value={x.key}>{x.label}</option>)}</select></Field>
        {p && <div className="span-2 faint small">{p.description}</div>}
        {p?.fields.map((f: any) => (
          <Field key={f.name} label={f.label} required={f.required} span2={f.type === "textarea"} hint={f.secret ? (item.secrets_set?.[f.name] ? "Stored encrypted. Leave blank to keep." : "Stored encrypted.") : f.help}>
            {f.type === "select" ? <select className="input" value={v.settings[f.name] ?? f.default ?? ""} onChange={(e) => setV({ ...v, settings: { ...v.settings, [f.name]: e.target.value } })}>{f.options.map((o: string) => <option key={o}>{o}</option>)}</select>
              : f.type === "textarea" ? <textarea className="input mono" value={v.settings[f.name] ?? (f.secret ? "" : f.default ?? "")} onChange={(e) => setV({ ...v, settings: { ...v.settings, [f.name]: e.target.value } })} />
                : <input className="input" type={f.secret || f.type === "password" ? "password" : f.type === "number" ? "number" : "text"} autoComplete="new-password" value={v.settings[f.name] ?? (f.secret ? "" : f.default ?? "")} onChange={(e) => setV({ ...v, settings: { ...v.settings, [f.name]: f.type === "number" ? Number(e.target.value) : e.target.value } })} />}
          </Field>
        ))}
        <Checkbox checked={v.is_enabled} onChange={(c) => setV({ ...v, is_enabled: c })} label="Enabled" />
      </div>
    </SaveModal>
  );
}

/* Backups -------------------------------------------------------------------- */
export function BackupsPage() {
  const qc = useQueryClient();
  const { can } = useAuth();
  const { confirm, toast, apiError } = useUi();
  const q = useQuery({ queryKey: ["backups"], queryFn: () => api.get("/api/backups") });
  const [busy, setBusy] = useState<string | null>(null);
  const [restoreRes, setRestoreRes] = useState<any>(null);
  const create = async () => {
    setBusy("Creating backup"); try { await api.post("/api/backups"); toast("success", "Backup created"); qc.invalidateQueries({ queryKey: ["backups"] }); } catch (e) { apiError(e); } finally { setBusy(null); }
  };
  const restore = async (b: any) => {
    if (!(await confirm({ title: "Emergency restore", danger: true, confirmLabel: "Restore files",
      message: <>Restore the Nagios files from backup <strong>{b.name}</strong>? The restore is validated before it is installed and the current files are backed up first. The portal database is <strong>not</strong> changed, so the portal will show configuration drift afterwards. For normal rollbacks use <em>Configuration Versions → Roll back</em>.</> }))) return;
    setBusy("Restoring backup");
    try { const r = await api.post(`/api/backups/${b.id}/restore`); setRestoreRes(r.data); qc.invalidateQueries({ queryKey: ["backups"] }); } catch (e) { apiError(e); } finally { setBusy(null); }
  };
  const cols: Column<any>[] = [
    { key: "created_at", header: "Date", render: (b) => <span className="nowrap">{fmtDate(b.created_at, { seconds: true })}</span> },
    { key: "name", header: "Backup", render: (b) => <span className="mono small">{b.name}</span> },
    { key: "reason", header: "Reason", render: (b) => <span className="badge outline">{b.reason}</span> },
    { key: "version_id", header: "Version", render: (b) => (b.version_id ? <Link to={`/config/versions/${b.version_id}`}>v{b.version_id}</Link> : "-") },
    { key: "created_by", header: "User" }, { key: "size_bytes", header: "Size", className: "num", render: (b) => bytes(b.size_bytes) },
    { key: "a", header: "", sortable: false, className: "actions", render: (b) => can("backups.manage") && <span className="row" style={{ justifyContent: "flex-end", flexWrap: "nowrap" }}>
      <button className="btn sm ghost" title="Download" onClick={() => download(`/api/backups/${b.id}/download`)}><Download size={14} /></button>
      {can("config.rollback") && <button className="btn sm ghost" title="Emergency restore" onClick={() => restore(b)}><RotateCcw size={14} /></button>}</span> },
  ];
  return (
    <div className="stack">
      <PageHeader title="Configuration backups" subtitle="Created automatically before every apply, rollback and install. Includes nagios.cfg, the managed directory and all manually maintained object files. Agent credentials are never stored in backups."
        actions={can("backups.manage") && <button className="btn primary" onClick={create}><Archive size={15} />Create backup now</button>} />
      <ErrorBox error={q.error} />
      <Card flush>{q.isLoading ? <Loading /> : <DataTable rows={q.data?.data ?? []} columns={cols} rowKey={(b) => b.id} empty="No backups yet" />}</Card>
      {busy && <Modal title={busy} onClose={() => { /* busy */ }}><Spinner label="Working..." /></Modal>}
      {restoreRes && <Modal title="Restore result" size="wide" onClose={() => setRestoreRes(null)}>
        {restoreRes.ok ? <Alert kind="success">Backup restored, validated and Nagios reloaded.</Alert> : <Alert kind="error">Restore failed: {restoreRes.error}. The running configuration was kept.</Alert>}
        {restoreRes.validation && <div className="mt"><VersionResult v={{ id: 0, status: restoreRes.ok ? "applied" : "validation_failed", summary: "", created_at: "", errors: restoreRes.validation.errors ?? [], warnings: restoreRes.validation.warnings ?? [], steps: restoreRes.steps ?? [] }} /></div>}
      </Modal>}
    </div>
  );
}

/* Import ------------------------------------------------------------------------ */
export function ImportPage() {
  const qc = useQueryClient();
  const cfg = useConfigAction();
  const { toast } = useUi();
  const q = useQuery({ queryKey: ["import-scan"], queryFn: () => api.get("/api/import/scan") });
  const [sel, setSel] = useState<Record<string, { environment: string; os_type: string; location: string }>>({});
  const [mode, setMode] = useState<"takeover" | "readonly">("takeover");
  const d = q.data?.data;
  const hosts: any[] = d?.hosts ?? [];
  const toggle = (h: any, on: boolean) => setSel((s) => { const n = { ...s }; if (on) n[h.hostname] = { environment: "production", os_type: h.os_guess, location: "" }; else delete n[h.hostname]; return n; });
  const run = async (apply: boolean) => {
    const body = { mode, apply, hosts: Object.entries(sel).map(([hostname, v]) => ({ hostname, ...v, location: v.location || null })) };
    const r = await cfg.run(apply ? "Importing and applying" : "Validating import", () => api.post("/api/import", body), (x) => x.data.version);
    if (r?.data) {
      if (mode === "readonly") toast("success", `Imported ${r.data.imported.length} host(s) read-only`);
      if (r.data.imported?.length) setSel({});
      qc.invalidateQueries({ queryKey: ["import-scan"] });
    }
  };
  const blocked = mode === "takeover" && Object.keys(sel).some((h) => !hosts.find((x) => x.hostname === h)?.can_take_over);
  return (
    <div className="stack">
      <PageHeader title="Import existing Nagios configuration" subtitle="Hosts and services found in your manually maintained Nagios files."
        actions={<button className="btn" onClick={() => q.refetch()}><RefreshCw size={15} />Rescan</button>} />
      <ErrorBox error={q.error} />
      <Alert kind="info">
        <strong>Take over</strong>: hosts become portal-managed. Inline NCPA tokens are encrypted, the portal generates the new definitions, and the original blocks are commented out (<code>#NMP-MIGRATED#</code>) in the <em>same</em> validated change - backed up and reversible. <br />
        <strong>Read-only</strong>: hosts are listed in the inventory with live status but stay managed in the original files.
      </Alert>
      {d && <div className="faint small">Scanned {d.files.length} file(s), {d.object_count} object definitions.</div>}
      <div className="row"><span className="muted">Mode:</span><div className="btn-group">
        <button className={`btn sm ${mode === "takeover" ? "active" : ""}`} onClick={() => setMode("takeover")}>Take over</button>
        <button className={`btn sm ${mode === "readonly" ? "active" : ""}`} onClick={() => setMode("readonly")}>Read-only</button></div></div>
      {q.isLoading ? <Loading /> : hosts.length === 0 ? <Card><div className="empty">Nothing to import - all hosts are already in the portal.</div></Card> : hosts.map((h) => (
        <Card key={h.hostname} title={<span className="row"><input type="checkbox" checked={!!sel[h.hostname]} onChange={(e) => toggle(h, e.target.checked)} aria-label={`select ${h.hostname}`} />{h.hostname}<span className="faint small" style={{ fontWeight: 400 }}>{h.address} - {h.file}:{h.line}</span>
          {h.can_take_over ? <span className="badge good">Ready</span> : <span className="badge warning">Take-over blocked</span>}</span>}>
          <div className="stack">
            <div className="row small"><span>Method: <strong>{h.method.toUpperCase()}</strong></span><span>Token found: <strong>{h.token_found ? "yes (will be encrypted)" : "no"}</strong></span><span>Host groups: {h.hostgroups.join(", ") || "-"}</span></div>
            {h.blockers.length > 0 && <Alert kind="warning">{h.blockers.join("; ")}</Alert>}
            {sel[h.hostname] && <div className="form-grid">
              <Field label="Environment"><select className="input" value={sel[h.hostname].environment} onChange={(e) => setSel({ ...sel, [h.hostname]: { ...sel[h.hostname], environment: e.target.value } })}>{ENVIRONMENTS.map((o) => <option key={o.value} value={o.value}>{o.label}</option>)}</select></Field>
              <Field label="Operating system"><select className="input" value={sel[h.hostname].os_type} onChange={(e) => setSel({ ...sel, [h.hostname]: { ...sel[h.hostname], os_type: e.target.value } })}>{OS_TYPES.map((o) => <option key={o.value} value={o.value}>{o.label}</option>)}</select></Field>
            </div>}
            <table className="table"><thead><tr><th>Service</th><th>Maps to</th><th>Parameters</th><th>Warning</th><th>Critical</th><th /></tr></thead>
              <tbody>{h.services.map((s: any) => <tr key={s.description}><td>{s.description}</td><td>{s.catalog_code ?? "-"}</td><td className="small mono">{Object.entries(s.params).map(([k, v]) => `${k}=${v}`).join(", ")}</td><td>{s.warning ?? "-"}</td><td>{s.critical ?? "-"}</td>
                <td>{s.problem ? <StateBadge state="WARNING" small /> : <StateBadge state="OK" small />}{s.problem && <span className="small faint"> {s.problem}</span>}</td></tr>)}</tbody></table>
          </div>
        </Card>
      ))}
      {Object.keys(sel).length > 0 && (
        <div className="card"><div className="card-body row between">
          <span>{Object.keys(sel).length} host(s) selected {blocked && <span style={{ color: "var(--critical-text)" }}> - some selected hosts cannot be taken over</span>}</span>
          <div className="row">
            {mode === "takeover" && <button className="btn" disabled={blocked} onClick={() => run(false)}>Validate only</button>}
            <button className="btn primary" disabled={blocked} onClick={() => run(true)}><Upload size={15} />{mode === "takeover" ? "Import & apply" : "Import read-only"}</button>
          </div>
        </div></div>
      )}
      {cfg.node}
    </div>
  );
}

/* System health ------------------------------------------------------------------ */
export function SystemHealthPage() {
  const [deep, setDeep] = useState(false);
  const q = useQuery({ queryKey: ["health", deep], queryFn: () => api.get("/api/health", { deep }), refetchInterval: 60_000 });
  const d = q.data?.data;
  const map: Record<string, string> = { ok: "OK", warning: "WARNING", critical: "CRITICAL" };
  return (
    <div className="stack">
      <PageHeader title="System health" subtitle={d && `Portal host ${d.hostname}`} actions={<>
        <button className="btn" onClick={() => { setDeep(true); q.refetch(); }}>Run deep check (validate live config, probe agents)</button>
        <button className="btn" onClick={() => q.refetch()}><RefreshCw size={15} />Refresh</button></>} />
      <ErrorBox error={q.error} />
      {q.isLoading || q.isFetching ? <Loading /> : d && <>
        <Alert kind={d.status === "ok" ? "success" : d.status === "warning" ? "warning" : "error"}>Overall status: <strong>{map[d.status]}</strong></Alert>
        <Card flush><table className="table"><thead><tr><th>Check</th><th>Status</th><th>Details</th></tr></thead>
          <tbody>{d.checks.map((c: any) => (
            <tr key={c.name}><td><strong>{c.name}</strong></td><td><StateBadge state={map[c.status]} small /></td>
              <td><div>{c.detail}</div>
                {c.drift?.length > 0 && <div className="small faint">Drift: {c.drift.join(", ")}</div>}
                {c.agents?.length > 0 && <div className="small">{c.agents.map((a: any) => <span key={a.hostname} className="tag">{a.hostname}: {a.host_state}{a.tcp_reachable === false ? " (port closed)" : a.tcp_reachable ? " (port open)" : ""}</span>)}</div>}
                {c.errors?.length > 0 && <div className="small" style={{ color: "var(--critical-text)" }}>{c.errors.map((e: any) => e.message).join("; ")}</div>}
              </td></tr>))}</tbody></table></Card>
      </>}
    </div>
  );
}

/* Data cleanup (Super Admin only) ------------------------------------------- */
type CleanupCat = { key: string; label: string; description: string; uses_age: boolean; default_days: number; min_days: number };
type CleanupRes = { count: number; protected: number; note: string; errors: string[]; bytes?: number; older_than_days?: number; detail?: Record<string, any> };

function detailText(d?: Record<string, any>) {
  if (!d) return null;
  return Object.entries(d).map(([k, v]) => Array.isArray(v) ? `${k.replace(/_/g, " ")}: ${v.join(", ")}` : `${k.replace(/_/g, " ")}: ${v}`).join(" · ");
}

export function DataCleanupPage() {
  const qc = useQueryClient();
  const { toast, apiError } = useUi();
  const cats = useQuery({ queryKey: ["cleanup-cats"], queryFn: () => api.get<CleanupCat[]>("/api/maintenance/cleanup/categories") });
  const list: CleanupCat[] = cats.data?.data ?? [];
  const [sel, setSel] = useState<Record<string, boolean>>({});
  const [days, setDays] = useState<Record<string, number>>({});
  const [preview, setPreview] = useState<Record<string, CleanupRes> | null>(null);
  const [result, setResult] = useState<{ results: Record<string, CleanupRes>; total: number; errors: number } | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const [confirmOpen, setConfirmOpen] = useState(false);
  const [word, setWord] = useState("");

  useEffect(() => {
    if (!list.length) return;
    setSel((s) => (Object.keys(s).length ? s : Object.fromEntries(list.map((c) => [c.key, ["sessions", "orphan_data", "failed_versions", "staging"].includes(c.key)]))));
    setDays((d) => (Object.keys(d).length ? d : Object.fromEntries(list.map((c) => [c.key, c.default_days]))));
  }, [list]);

  const items = list.filter((c) => sel[c.key]).map((c) => ({ category: c.key, older_than_days: c.uses_age ? Math.max(days[c.key] ?? c.default_days, c.min_days) : 0 }));
  const changed = () => { setPreview(null); setResult(null); };

  const doPreview = async () => {
    setBusy("Calculating"); setResult(null);
    try { const r = await api.post("/api/maintenance/cleanup/preview", { items }); setPreview(r.data.results); } catch (e) { apiError(e); } finally { setBusy(null); }
  };
  const doClean = async () => {
    setConfirmOpen(false); setBusy("Cleaning up");
    try {
      const r = await api.post("/api/maintenance/cleanup", { items, confirm: word });
      setResult(r.data); setPreview(null);
      toast(r.data.errors ? "error" : "success", `Removed ${r.data.total} item(s)${r.data.errors ? ` with ${r.data.errors} error(s)` : ""}`);
      qc.invalidateQueries();
    } catch (e) { apiError(e); } finally { setBusy(null); setWord(""); }
  };
  const total = preview ? Object.values(preview).reduce((a, r) => a + r.count, 0) : 0;
  const shown = result?.results ?? preview;

  return (
    <div className="stack">
      <PageHeader title="Data cleanup" subtitle="Remove junk and stale data from the portal database and work folders. Super Admin only. Always preview first; every cleanup is audited." />
      <Alert kind="warning">Deleted data cannot be recovered except from a database backup. The live Nagios configuration is never touched. The current configuration version, the newest versions and backups, the backup taken before the live version, and the installation backup are always kept.</Alert>
      <ErrorBox error={cats.error} />
      <Card flush>
        {cats.isLoading ? <Loading /> : (
          <div className="table-wrap"><table className="table">
            <thead><tr><th style={{ width: 36 }}></th><th>What to clean</th><th style={{ width: 210 }}>Older than</th><th className="num" style={{ width: 120 }}>{result ? "Removed" : "Will remove"}</th><th className="num" style={{ width: 100 }}>Kept (protected)</th></tr></thead>
            <tbody>{list.map((c) => {
              const r = shown?.[c.key];
              return (
                <tr key={c.key}>
                  <td><input type="checkbox" aria-label={c.label} checked={!!sel[c.key]} onChange={(e) => { setSel({ ...sel, [c.key]: e.target.checked }); changed(); }} /></td>
                  <td><strong>{c.label}</strong><div className="faint small">{c.description}</div>
                    {r && (r.note || r.detail || r.errors.length > 0) && <div className="small" style={{ marginTop: 4 }}>
                      {r.detail && <div className="faint">{detailText(r.detail)}</div>}
                      {r.note && <div className="faint">{r.note}</div>}
                      {r.errors.map((e, i) => <div key={i} style={{ color: "var(--critical)" }}>{e}</div>)}
                    </div>}</td>
                  <td>{c.uses_age ? <span className="row" style={{ flexWrap: "nowrap" }}><input className="input" type="number" min={c.min_days} max={3650} style={{ width: 80 }} value={days[c.key] ?? c.default_days}
                    onChange={(e) => { setDays({ ...days, [c.key]: Number(e.target.value) }); changed(); }} /><span className="small faint nowrap">days{c.min_days ? ` (min ${c.min_days})` : ""}</span></span> : <span className="faint small">any age</span>}</td>
                  <td className="num">{r ? <strong>{r.count.toLocaleString()}</strong> : <span className="faint">-</span>}{r?.bytes ? <div className="faint small">{bytes(r.bytes)}</div> : null}</td>
                  <td className="num">{r ? r.protected.toLocaleString() : <span className="faint">-</span>}</td>
                </tr>);
            })}</tbody>
          </table></div>
        )}
      </Card>
      <div className="row">
        <button className="btn" disabled={!items.length || !!busy} onClick={doPreview}><RefreshCw size={15} />Preview</button>
        <button className="btn danger" disabled={!preview || total === 0 || !!busy} onClick={() => { setWord(""); setConfirmOpen(true); }}><Trash2 size={15} />Clean up {preview ? `${total.toLocaleString()} item(s)` : ""}</button>
        {!preview && !result && <span className="faint small">Select categories, then Preview to see what would be removed.</span>}
        {result && <span className="small">Done: removed {result.total.toLocaleString()} item(s){result.errors ? `, ${result.errors} error(s)` : ""}. See Audit log for the record.</span>}
      </div>
      {confirmOpen && <Modal title="Confirm data cleanup" onClose={() => setConfirmOpen(false)} footer={<><button className="btn" onClick={() => setConfirmOpen(false)}>Cancel</button><button className="btn danger" disabled={word !== "DELETE"} onClick={doClean}>Delete permanently</button></>}>
        <div className="stack">
          <div>This permanently removes <strong>{total.toLocaleString()}</strong> item(s) in {items.length} categor{items.length === 1 ? "y" : "ies"}. Consider a database backup first:<div className="mono small" style={{ marginTop: 6 }}>sudo mariadb-dump nagios_mgmt | gzip &gt; nagios_mgmt-$(date +%F).sql.gz</div></div>
          <Field label={<>Type <strong>DELETE</strong> to confirm</>}><input className="input" autoFocus value={word} onChange={(e) => setWord(e.target.value)} /></Field>
        </div>
      </Modal>}
      {busy && <Modal title={busy} onClose={() => { /* busy */ }}><Spinner label="Working..." /></Modal>}
    </div>
  );
}
