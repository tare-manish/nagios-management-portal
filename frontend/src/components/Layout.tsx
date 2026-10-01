import { useEffect, useRef, useState, type ReactNode } from "react";
import { NavLink, Outlet, useNavigate } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import {
  Activity, AlertOctagon, Archive, Bell, BookOpen, CalendarClock, ChevronLeft, ClipboardList, Cog, Contact, Database, Eraser,
  FileCheck2, FileClock, FileText, Gauge, GitCompare, HeartPulse, KeyRound, LayoutDashboard, LayoutTemplate, ListChecks,
  LogOut, Menu, Moon, Network, Router, Server, Settings, Shield, Sun, TerminalSquare, Upload, Users, UsersRound,
} from "lucide-react";
import { useAuth } from "../lib/auth";
import { api } from "../lib/api";
import { ago } from "../lib/format";

interface NavItem { to: string; label: string; icon: ReactNode; perm?: string }
interface NavSection { title: string; icon: ReactNode; items: NavItem[] }

const SECTIONS: NavSection[] = [
  { title: "Monitoring", icon: <Activity size={13} />, items: [
    { to: "/monitoring/hosts", label: "Hosts", icon: <Server size={16} />, perm: "monitoring.view" },
    { to: "/monitoring/services", label: "Services", icon: <ListChecks size={16} />, perm: "monitoring.view" },
    { to: "/monitoring/problems", label: "Problems", icon: <AlertOctagon size={16} />, perm: "monitoring.view" },
    { to: "/monitoring/events", label: "Events", icon: <FileClock size={16} />, perm: "monitoring.view" },
    { to: "/monitoring/downtime", label: "Downtime", icon: <CalendarClock size={16} />, perm: "monitoring.view" },
  ] },
  { title: "Infrastructure", icon: <Database size={13} />, items: [
    { to: "/servers", label: "Servers", icon: <Server size={16} />, perm: "servers.view" },
    { to: "/network", label: "Network Devices", icon: <Router size={16} />, perm: "servers.view" },
    { to: "/hostgroups", label: "Host Groups", icon: <Network size={16} />, perm: "servers.view" },
    { to: "/templates", label: "Templates", icon: <LayoutTemplate size={16} />, perm: "templates.view" },
  ] },
  { title: "Configuration", icon: <Cog size={13} />, items: [
    { to: "/config/pending", label: "Pending Changes", icon: <FileCheck2 size={16} />, perm: "config.view" },
    { to: "/config/services", label: "Services", icon: <ClipboardList size={16} />, perm: "templates.view" },
    { to: "/config/commands", label: "Commands", icon: <TerminalSquare size={16} />, perm: "templates.view" },
    { to: "/config/contacts", label: "Contacts", icon: <Contact size={16} />, perm: "servers.view" },
    { to: "/config/contact-groups", label: "Contact Groups", icon: <UsersRound size={16} />, perm: "servers.view" },
    { to: "/config/versions", label: "Configuration Versions", icon: <GitCompare size={16} />, perm: "config.view" },
  ] },
  { title: "Reports", icon: <FileText size={13} />, items: [
    { to: "/reports/availability", label: "Availability", icon: <Gauge size={16} />, perm: "reports.view" },
    { to: "/reports/performance", label: "Performance", icon: <Activity size={16} />, perm: "reports.view" },
    { to: "/reports/sla", label: "SLA", icon: <FileCheck2 size={16} />, perm: "reports.view" },
    { to: "/reports/health", label: "Infrastructure Health", icon: <HeartPulse size={16} />, perm: "reports.view" },
    { to: "/reports/audit", label: "Audit", icon: <BookOpen size={16} />, perm: "audit.view" },
  ] },
  { title: "Administration", icon: <Shield size={13} />, items: [
    { to: "/admin/users", label: "Users", icon: <Users size={16} />, perm: "users.manage" },
    { to: "/admin/roles", label: "Roles", icon: <KeyRound size={16} />, perm: "users.manage" },
    { to: "/admin/notifications", label: "Notifications", icon: <Bell size={16} />, perm: "notifications.manage" },
    { to: "/admin/settings", label: "System Settings", icon: <Settings size={16} />, perm: "settings.manage" },
    { to: "/admin/backups", label: "Backups", icon: <Archive size={16} />, perm: "config.view" },
    { to: "/admin/import", label: "Import Configuration", icon: <Upload size={16} />, perm: "config.import" },
    { to: "/admin/health", label: "System Health", icon: <HeartPulse size={16} />, perm: "health.view" },
    { to: "/admin/cleanup", label: "Data Cleanup", icon: <Eraser size={16} />, perm: "maintenance.cleanup" },
  ] },
];

function useTheme(): [string, () => void] {
  const [theme, setTheme] = useState<string>(() => {
    try { return localStorage.getItem("nmp-theme") || (matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light"); } catch { return "light"; }
  });
  useEffect(() => {
    document.documentElement.dataset.theme = theme;
    try { localStorage.setItem("nmp-theme", theme); } catch { /* ignore */ }
  }, [theme]);
  return [theme, () => setTheme((t) => (t === "dark" ? "light" : "dark"))];
}

function useIdleLogout(minutes: number, onIdle: () => void) {
  useEffect(() => {
    let t: number;
    const reset = () => { clearTimeout(t); t = window.setTimeout(onIdle, minutes * 60_000); };
    const evs = ["mousemove", "keydown", "click", "scroll"];
    evs.forEach((e) => window.addEventListener(e, reset, { passive: true }));
    reset();
    return () => { clearTimeout(t); evs.forEach((e) => window.removeEventListener(e, reset)); };
  }, [minutes, onIdle]);
}

export default function Layout() {
  const { user, can, logout } = useAuth();
  const nav = useNavigate();
  const [theme, toggleTheme] = useTheme();
  const [collapsed, setCollapsed] = useState(false);
  const [mobile, setMobile] = useState(false);
  const [menu, setMenu] = useState<"user" | "bell" | null>(null);
  const menuRef = useRef<HTMLDivElement>(null);
  useIdleLogout(30, () => { logout(); });
  useEffect(() => {
    const h = (e: MouseEvent) => { if (menuRef.current && !menuRef.current.contains(e.target as Node)) setMenu(null); };
    document.addEventListener("mousedown", h);
    return () => document.removeEventListener("mousedown", h);
  }, []);
  const pending = useQuery({ queryKey: ["pending"], queryFn: () => api.get("/api/config/pending"), refetchInterval: 30_000, enabled: can("config.view") });
  const notes = useQuery({ queryKey: ["notifications"], queryFn: () => api.get("/api/notifications", { limit: 15 }), refetchInterval: 60_000, enabled: can("monitoring.view") });
  const pendingCount = pending.data?.data?.count ?? 0;
  const unread = notes.data?.meta?.unread ?? 0;

  return (
    <div className={`app ${collapsed ? "collapsed" : ""} ${mobile ? "mobile-open" : ""}`}>
      <aside className="sidebar" onClick={() => mobile && setMobile(false)}>
        <div className="brand">
          <svg className="brand-logo" viewBox="0 0 32 32" aria-hidden><rect width="32" height="32" rx="7" fill="#1c5cab" /><path d="M6 17h5l3-8 4 14 3-6h5" fill="none" stroke="#fff" strokeWidth="2.4" strokeLinecap="round" strokeLinejoin="round" /></svg>
          <div className="brand-text">Nagios Manager<small>Monitoring Management Portal</small></div>
        </div>
        <nav className="nav">
          {can("dashboard.view") && <NavLink to="/" end><LayoutDashboard size={16} /><span>Dashboard</span></NavLink>}
          {SECTIONS.map((s) => {
            const items = s.items.filter((i) => !i.perm || can(i.perm));
            if (!items.length) return null;
            return (
              <div className="nav-section" key={s.title}>
                <div className="nav-title">{s.icon}<span>{s.title}</span></div>
                {items.map((i) => <NavLink key={i.to} to={i.to}>{i.icon}<span>{i.label}</span></NavLink>)}
              </div>
            );
          })}
        </nav>
      </aside>
      <div className="main">
        <header className="topbar">
          <button className="btn ghost icon" aria-label="Toggle navigation" onClick={() => (window.innerWidth <= 800 ? setMobile(!mobile) : setCollapsed(!collapsed))}>
            {collapsed ? <Menu size={18} /> : <ChevronLeft size={18} />}
          </button>
          <div className="spacer" />
          {pendingCount > 0 && (
            <button className="pending-pill" onClick={() => nav("/config/pending")} title="Changes saved but not yet applied to Nagios">
              <FileCheck2 size={14} />{pendingCount} pending change{pendingCount === 1 ? "" : "s"}
            </button>
          )}
          <div className="rel" ref={menuRef}>
            <button className="btn ghost icon" aria-label="Notifications" onClick={() => setMenu(menu === "bell" ? null : "bell")}>
              <Bell size={18} />{unread > 0 && <span className="badge critical" style={{ position: "absolute", top: 2, right: 0, height: 16, padding: "0 5px", fontSize: 10 }}>{unread}</span>}
            </button>
            {menu === "bell" && (
              <div className="menu" style={{ width: 360, maxHeight: 420, overflowY: "auto" }}>
                <div className="row between" style={{ padding: "4px 8px" }}><strong>Notifications</strong>
                  <button className="btn ghost sm" style={{ width: "auto" }} onClick={async () => { await api.post("/api/notifications/read-all"); notes.refetch(); }}>Mark all read</button></div>
                <div className="sep" />
                {(notes.data?.data ?? []).length === 0 && <div className="faint small" style={{ padding: 10 }}>No notifications</div>}
                {(notes.data?.data ?? []).map((n: any) => (
                  <div key={n.id} style={{ padding: "6px 10px", borderBottom: "1px solid var(--border)" }}>
                    <div className="small" style={{ fontWeight: n.read ? 400 : 600 }}>{n.title}</div>
                    <div className="faint small">{ago(n.time)} - {n.status}</div>
                  </div>
                ))}
              </div>
            )}
          </div>
          <button className="btn ghost icon" aria-label="Toggle dark mode" onClick={toggleTheme} title="Toggle dark / light">{theme === "dark" ? <Sun size={18} /> : <Moon size={18} />}</button>
          <div className="rel">
            <button className="btn ghost" onClick={() => setMenu(menu === "user" ? null : "user")}>
              <span className="badge info" style={{ borderRadius: "50%", width: 26, height: 26, justifyContent: "center", padding: 0 }}>{user?.username.slice(0, 2).toUpperCase()}</span>
              <span className="nowrap">{user?.full_name || user?.username}</span>
            </button>
            {menu === "user" && (
              <div className="menu">
                <div style={{ padding: "6px 10px" }}><div><strong>{user?.username}</strong></div><div className="faint small">{user?.roles.map((r) => r.display_name).join(", ")}</div></div>
                <div className="sep" />
                <button onClick={() => { setMenu(null); nav("/account"); }}><KeyRound size={15} />Change password</button>
                <button onClick={() => { setMenu(null); window.open("/api/docs", "_blank", "noopener"); }}><BookOpen size={15} />API documentation</button>
                <div className="sep" />
                <button onClick={() => logout()}><LogOut size={15} />Sign out</button>
              </div>
            )}
          </div>
        </header>
        <main className="content"><Outlet /></main>
      </div>
    </div>
  );
}
