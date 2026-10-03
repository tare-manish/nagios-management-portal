import { useState, type FormEvent } from "react";
import { Navigate, Route, Routes } from "react-router-dom";
import Layout from "./components/Layout";
import { Alert, Field, Loading } from "./components/ui";
import { ApiError, api } from "./lib/api";
import { useAuth } from "./lib/auth";
import Dashboard from "./pages/Dashboard";
import { Downtime, Events, MonHosts, MonServices, Problems } from "./pages/Monitoring";
import ServersPage from "./pages/Servers";
import ServerWizard from "./pages/ServerWizard";
import ServerDetail from "./pages/ServerDetail";
import { CommandsPage, ContactGroupsPage, ContactsPage, HostGroupsPage, ServiceDefsPage, TemplatesPage } from "./pages/Catalog";
import { PendingPage, VersionDetail, VersionsPage } from "./pages/Config";
import { AuditReport, AvailabilityReport, HealthReport, PerformanceReport, SlaReport } from "./pages/Reports";
import { BackupsPage, CompaniesPage, DataCleanupPage, ImportPage, LocationsPage, NotificationsPage, RolesPage, SettingsPage, SystemHealthPage, UsersPage } from "./pages/Admin";

function Login() {
  const { login } = useAuth();
  const [u, setU] = useState("");
  const [p, setP] = useState("");
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const submit = async (e: FormEvent) => {
    e.preventDefault(); setBusy(true); setErr(null);
    try { await login(u, p); } catch (x) { setErr(x instanceof ApiError ? x.message : "Login failed"); } finally { setBusy(false); }
  };
  return (
    <div className="login-page">
      <form className="login-card stack" onSubmit={submit}>
        <div className="row" style={{ gap: 12 }}>
          <svg width="40" height="40" viewBox="0 0 32 32" aria-hidden><rect width="32" height="32" rx="7" fill="#1c5cab" /><path d="M6 17h5l3-8 4 14 3-6h5" fill="none" stroke="#fff" strokeWidth="2.4" strokeLinecap="round" strokeLinejoin="round" /></svg>
          <div><h1>Nagios Manager</h1><div className="muted small">Monitoring Management Portal</div></div>
        </div>
        {err && <Alert kind="error">{err}</Alert>}
        <Field label="Username"><input className="input" autoComplete="username" autoFocus value={u} onChange={(e) => setU(e.target.value)} required maxLength={64} /></Field>
        <Field label="Password"><input className="input" type="password" autoComplete="current-password" value={p} onChange={(e) => setP(e.target.value)} required maxLength={256} /></Field>
        <button className="btn primary w100" style={{ justifyContent: "center" }} disabled={busy}>{busy ? "Signing in..." : "Sign in"}</button>
        <div className="faint small">Authorized administrators only. All actions are audited.</div>
      </form>
    </div>
  );
}

export function ChangePassword({ forced }: { forced?: boolean }) {
  const { refresh, logout } = useAuth();
  const [cur, setCur] = useState(""); const [n1, setN1] = useState(""); const [n2, setN2] = useState("");
  const [err, setErr] = useState<string | null>(null); const [ok, setOk] = useState(false);
  const submit = async (e: FormEvent) => {
    e.preventDefault(); setErr(null);
    if (n1 !== n2) { setErr("New passwords do not match"); return; }
    try { await api.post("/api/auth/change-password", { current_password: cur, new_password: n1 }); setOk(true); setCur(""); setN1(""); setN2(""); await refresh(); }
    catch (x) { setErr(x instanceof ApiError ? x.describe() : String(x)); }
  };
  const form = (
    <form className="stack" onSubmit={submit} style={{ maxWidth: 420 }}>
      {forced && <Alert kind="warning">You must change your password before continuing.</Alert>}
      {err && <Alert kind="error">{err}</Alert>}
      {ok && <Alert kind="success">Password changed. Other sessions were signed out.</Alert>}
      <Field label="Current password"><input className="input" type="password" autoComplete="current-password" value={cur} onChange={(e) => setCur(e.target.value)} required /></Field>
      <Field label="New password" hint="At least 12 characters with 3 of: lowercase, uppercase, digit, symbol."><input className="input" type="password" autoComplete="new-password" value={n1} onChange={(e) => setN1(e.target.value)} required /></Field>
      <Field label="Repeat new password"><input className="input" type="password" autoComplete="new-password" value={n2} onChange={(e) => setN2(e.target.value)} required /></Field>
      <div className="row"><button className="btn primary">Change password</button>{forced && <button type="button" className="btn" onClick={() => logout()}>Sign out</button>}</div>
    </form>
  );
  if (forced) return <div className="login-page"><div className="login-card"><h1 className="mb">Change password</h1>{form}</div></div>;
  return <div><div className="page-header"><div><h1>Change password</h1></div></div><div className="card"><div className="card-body">{form}</div></div></div>;
}

export default function App() {
  const { user, loading, can } = useAuth();
  if (loading) return <Loading />;
  if (!user) return <Login />;
  if (user.must_change_password) return <ChangePassword forced />;
  return (
    <Routes>
      <Route element={<Layout />}>
        <Route index element={can("dashboard.view") ? <Dashboard /> : <Navigate to="/monitoring/hosts" />} />
        <Route path="monitoring/hosts" element={<MonHosts />} />
        <Route path="monitoring/services" element={<MonServices />} />
        <Route path="monitoring/problems" element={<Problems />} />
        <Route path="monitoring/events" element={<Events />} />
        <Route path="monitoring/downtime" element={<Downtime />} />
        <Route path="servers" element={<ServersPage deviceType="server" />} />
        <Route path="servers/new" element={<ServerWizard />} />
        <Route path="servers/:id" element={<ServerDetail />} />
        <Route path="servers/:id/edit" element={<ServerWizard />} />
        <Route path="network" element={<ServersPage deviceType="network_device" />} />
        <Route path="network/new" element={<ServerWizard network />} />
        <Route path="hostgroups" element={<HostGroupsPage />} />
        <Route path="templates" element={<TemplatesPage />} />
        <Route path="config/pending" element={<PendingPage />} />
        <Route path="config/services" element={<ServiceDefsPage />} />
        <Route path="config/commands" element={<CommandsPage />} />
        <Route path="config/contacts" element={<ContactsPage />} />
        <Route path="config/contact-groups" element={<ContactGroupsPage />} />
        <Route path="config/versions" element={<VersionsPage />} />
        <Route path="config/versions/:id" element={<VersionDetail />} />
        <Route path="reports/availability" element={<AvailabilityReport />} />
        <Route path="reports/performance" element={<PerformanceReport />} />
        <Route path="reports/sla" element={<SlaReport />} />
        <Route path="reports/health" element={<HealthReport />} />
        <Route path="reports/audit" element={<AuditReport />} />
        <Route path="admin/users" element={<UsersPage />} />
        <Route path="admin/roles" element={<RolesPage />} />
        <Route path="admin/settings" element={<SettingsPage />} />
        <Route path="admin/notifications" element={<NotificationsPage />} />
        <Route path="admin/backups" element={<BackupsPage />} />
        <Route path="admin/import" element={<ImportPage />} />
        <Route path="admin/health" element={<SystemHealthPage />} />
        <Route path="admin/cleanup" element={<DataCleanupPage />} />
        <Route path="admin/companies" element={<CompaniesPage />} />
        <Route path="admin/locations" element={<LocationsPage />} />
        <Route path="account" element={<ChangePassword />} />
        <Route path="*" element={<div className="empty">Page not found</div>} />
      </Route>
    </Routes>
  );
}
