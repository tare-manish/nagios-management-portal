import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { AlertCircle, AlertTriangle, CheckCircle2, ChevronDown, ChevronUp, HelpCircle, Info, X, XCircle, Clock, MinusCircle } from "lucide-react";
import { ApiError } from "../lib/api";

/* ------------------------------------------------------------------ basics */
export function Spinner({ label }: { label?: string }) {
  return <span className="row"><span className="spinner" aria-hidden />{label && <span className="muted">{label}</span>}</span>;
}
export function Loading() { return <div className="center"><Spinner label="Loading..." /></div>; }
export function Empty({ children }: { children: ReactNode }) { return <div className="empty">{children}</div>; }

export function PageHeader({ title, subtitle, actions, crumb }: { title: ReactNode; subtitle?: ReactNode; actions?: ReactNode; crumb?: ReactNode }) {
  return (
    <div className="page-header">
      <div>
        {crumb && <div className="breadcrumb">{crumb}</div>}
        <h1>{title}</h1>
        {subtitle && <p>{subtitle}</p>}
      </div>
      {actions && <div className="page-actions">{actions}</div>}
    </div>
  );
}

export function Card({ title, actions, children, flush, className }: { title?: ReactNode; actions?: ReactNode; children: ReactNode; flush?: boolean; className?: string }) {
  return (
    <div className={`card ${className ?? ""}`}>
      {(title || actions) && <div className="card-header"><h2>{title}</h2><div className="row">{actions}</div></div>}
      <div className={`card-body ${flush ? "flush" : ""}`}>{children}</div>
    </div>
  );
}

export function Alert({ kind = "info", children }: { kind?: "info" | "warning" | "error" | "success"; children: ReactNode }) {
  const Icon = kind === "error" ? XCircle : kind === "warning" ? AlertTriangle : kind === "success" ? CheckCircle2 : Info;
  return <div className={`alert ${kind}`} role={kind === "error" ? "alert" : undefined}><Icon size={18} /><div>{children}</div></div>;
}

export function ErrorBox({ error }: { error: unknown }) {
  if (!error) return null;
  const msg = error instanceof ApiError ? error.describe() : String(error);
  return <Alert kind="error">{msg}</Alert>;
}

/* ------------------------------------------------------------ status badges */
const STATE_MAP: Record<string, { cls: string; Icon: typeof CheckCircle2; label?: string }> = {
  UP: { cls: "good", Icon: CheckCircle2 }, OK: { cls: "good", Icon: CheckCircle2 },
  WARNING: { cls: "warning", Icon: AlertTriangle }, CRITICAL: { cls: "critical", Icon: XCircle },
  DOWN: { cls: "critical", Icon: XCircle }, UNREACHABLE: { cls: "serious", Icon: AlertCircle },
  UNKNOWN: { cls: "unknown", Icon: HelpCircle }, PENDING: { cls: "", Icon: Clock },
  UNMONITORED: { cls: "", Icon: MinusCircle, label: "NOT IN NAGIOS" },
};
export function StateBadge({ state, small }: { state?: string | null; small?: boolean }) {
  const s = (state || "UNKNOWN").toUpperCase();
  const m = STATE_MAP[s] ?? { cls: "", Icon: HelpCircle };
  return <span className={`badge ${m.cls}`} title={s}><m.Icon size={small ? 12 : 13} />{m.label ?? s}</span>;
}

const CONFIG_STATE: Record<string, [string, string]> = {
  draft: ["", "Draft"], pending: ["warning", "Pending apply"], applied: ["good", "Applied"], error: ["critical", "Error"],
};
export function ConfigStateBadge({ state }: { state: string }) {
  const [cls, label] = CONFIG_STATE[state] ?? ["", state];
  return <span className={`badge ${cls}`}><span className="dot" />{label}</span>;
}

const VERSION_STATE: Record<string, string> = {
  applied: "good", superseded: "", generated: "info", validated: "info", validation_failed: "critical",
  apply_failed: "critical", applying: "warning", rolled_back: "unknown",
};
export function VersionBadge({ status }: { status: string }) {
  return <span className={`badge ${VERSION_STATE[status] ?? ""}`}><span className="dot" />{status.replace(/_/g, " ")}</span>;
}

export function Meter({ value, warn = 80, crit = 90 }: { value?: number | null; warn?: number; crit?: number }) {
  if (value === null || value === undefined) return <span className="faint">-</span>;
  const cls = value >= crit ? "critical" : value >= warn ? "warning" : "";
  return (
    <div className="meter" title={`${value}%`}>
      <div className="track"><div className={`fill ${cls}`} style={{ width: `${Math.min(100, Math.max(0, value))}%` }} /></div>
      <span>{value.toFixed(0)}%</span>
    </div>
  );
}

export function Kpi({ label, value, sub, color, icon, onClick }: { label: ReactNode; value: ReactNode; sub?: ReactNode; color?: string; icon?: ReactNode; onClick?: () => void }) {
  return (
    <div className={`kpi ${onClick ? "clickable" : ""}`} style={{ ["--kpi-color" as any]: color }} onClick={onClick}
      role={onClick ? "button" : undefined} tabIndex={onClick ? 0 : undefined} onKeyDown={(e) => { if (onClick && e.key === "Enter") onClick(); }}>
      <div className="label">{icon}{label}</div>
      <div className="value">{value}</div>
      {sub && <div className="sub">{sub}</div>}
    </div>
  );
}

/* ------------------------------------------------------------------ forms */
export function Field({ label, hint, error, children, span2, required }: { label: ReactNode; hint?: ReactNode; error?: string; children: ReactNode; span2?: boolean; required?: boolean }) {
  return (
    <div className={`field ${span2 ? "span-2" : ""}`}>
      <label>{label}{required && <span style={{ color: "var(--critical)" }}> *</span>}</label>
      {children}
      {error ? <div className="error">{error}</div> : hint ? <div className="hint">{hint}</div> : null}
    </div>
  );
}

export function Checkbox({ checked, onChange, label, disabled }: { checked: boolean; onChange: (v: boolean) => void; label: ReactNode; disabled?: boolean }) {
  return <label className="check"><input type="checkbox" checked={checked} disabled={disabled} onChange={(e) => onChange(e.target.checked)} />{label}</label>;
}

export function Tabs({ tabs, active, onChange }: { tabs: { key: string; label: ReactNode }[]; active: string; onChange: (k: string) => void }) {
  return (
    <div className="tabs" role="tablist">
      {tabs.map((t) => <button key={t.key} role="tab" aria-selected={t.key === active} className={t.key === active ? "active" : ""} onClick={() => onChange(t.key)}>{t.label}</button>)}
    </div>
  );
}

export function Segmented<T extends string>({ value, options, onChange }: { value: T; options: { value: T; label: ReactNode }[]; onChange: (v: T) => void }) {
  return <div className="btn-group">{options.map((o) => <button key={o.value} className={`btn sm ${o.value === value ? "active" : ""}`} onClick={() => onChange(o.value)}>{o.label}</button>)}</div>;
}

/* ------------------------------------------------------------------ modal */
export function Modal({ title, onClose, children, footer, size }: { title: ReactNode; onClose: () => void; children: ReactNode; footer?: ReactNode; size?: "wide" | "xwide" }) {
  useEffect(() => {
    const h = (e: KeyboardEvent) => { if (e.key === "Escape") onClose(); };
    window.addEventListener("keydown", h);
    return () => window.removeEventListener("keydown", h);
  }, [onClose]);
  return (
    <div className="overlay" onMouseDown={(e) => { if (e.target === e.currentTarget) onClose(); }}>
      <div className={`modal ${size ?? ""}`} role="dialog" aria-modal="true">
        <div className="modal-header"><h2>{title}</h2><button className="btn ghost icon sm" onClick={onClose} aria-label="Close"><X size={16} /></button></div>
        <div className="modal-body">{children}</div>
        {footer && <div className="modal-footer">{footer}</div>}
      </div>
    </div>
  );
}

/* ------------------------------------------------------ toast + confirm */
type ToastKind = "success" | "error" | "info" | "warning";
interface ToastItem { id: number; kind: ToastKind; title: string; message?: string }
interface ConfirmOpts { title: string; message: ReactNode; confirmLabel?: string; danger?: boolean }
interface UiCtx {
  toast: (kind: ToastKind, title: string, message?: string) => void;
  confirm: (o: ConfirmOpts) => Promise<boolean>;
  apiError: (e: unknown, title?: string) => void;
}
const Ui = createContext<UiCtx>(null as unknown as UiCtx);

export function UiProvider({ children }: { children: ReactNode }) {
  const [toasts, setToasts] = useState<ToastItem[]>([]);
  const [dlg, setDlg] = useState<(ConfirmOpts & { resolve: (v: boolean) => void }) | null>(null);
  const idRef = useRef(0);
  const toast = useCallback((kind: ToastKind, title: string, message?: string) => {
    const id = ++idRef.current;
    setToasts((t) => [...t, { id, kind, title, message }]);
    setTimeout(() => setToasts((t) => t.filter((x) => x.id !== id)), kind === "error" ? 9000 : 5000);
  }, []);
  const confirm = useCallback((o: ConfirmOpts) => new Promise<boolean>((resolve) => setDlg({ ...o, resolve })), []);
  const apiError = useCallback((e: unknown, title = "Request failed") => {
    toast("error", title, e instanceof ApiError ? e.describe() : String(e));
  }, [toast]);
  const value = useMemo(() => ({ toast, confirm, apiError }), [toast, confirm, apiError]);
  const close = (v: boolean) => { dlg?.resolve(v); setDlg(null); };
  return (
    <Ui.Provider value={value}>
      {children}
      <div className="toasts" aria-live="polite">
        {toasts.map((t) => (
          <div key={t.id} className={`toast ${t.kind}`}>
            {t.kind === "success" ? <CheckCircle2 size={18} color="var(--good)" /> : t.kind === "error" ? <XCircle size={18} color="var(--critical)" /> : t.kind === "warning" ? <AlertTriangle size={18} color="var(--warning)" /> : <Info size={18} color="var(--accent)" />}
            <div><div className="t-title">{t.title}</div>{t.message && <div className="t-msg">{t.message}</div>}</div>
          </div>
        ))}
      </div>
      {dlg && (
        <Modal title={dlg.title} onClose={() => close(false)}
          footer={<><button className="btn" onClick={() => close(false)}>Cancel</button>
            <button className={`btn ${dlg.danger ? "danger" : "primary"}`} autoFocus onClick={() => close(true)}>{dlg.confirmLabel ?? "Confirm"}</button></>}>
          <div className="muted">{dlg.message}</div>
        </Modal>
      )}
    </Ui.Provider>
  );
}
export const useUi = () => useContext(Ui);

/* ---------------------------------------------------------------- table */
export interface Column<T> {
  key: string; header: ReactNode; render?: (row: T) => ReactNode; sortValue?: (row: T) => any;
  sortable?: boolean; className?: string; width?: number | string;
}
export function DataTable<T>({ rows, columns, rowKey, onRowClick, pageSize = 25, empty = "No data", initialSort,
  serverSort, onSort, serverPaging }: {
  rows: T[]; columns: Column<T>[]; rowKey: (r: T) => string | number; onRowClick?: (r: T) => void; pageSize?: number;
  empty?: ReactNode; initialSort?: { key: string; dir: "asc" | "desc" };
  serverSort?: { key: string; dir: "asc" | "desc" }; onSort?: (key: string, dir: "asc" | "desc") => void;
  serverPaging?: { page: number; pages: number; total: number; pageSize: number; onPage: (p: number) => void; onPageSize?: (n: number) => void };
}) {
  const [sort, setSort] = useState(initialSort ?? null);
  const [page, setPage] = useState(1);
  const [size, setSize] = useState(pageSize);
  const effectiveSort = serverSort ?? sort;
  const sorted = useMemo(() => {
    if (serverSort || !sort) return rows;
    const col = columns.find((c) => c.key === sort.key);
    const get = col?.sortValue ?? ((r: any) => r[sort.key]);
    const out = [...rows].sort((a, b) => {
      const va = get(a), vb = get(b);
      if (va === vb) return 0;
      if (va === null || va === undefined) return 1;
      if (vb === null || vb === undefined) return -1;
      return (va > vb ? 1 : -1) * (sort.dir === "asc" ? 1 : -1);
    });
    return out;
  }, [rows, sort, columns, serverSort]);
  const pages = serverPaging ? serverPaging.pages : Math.max(1, Math.ceil(sorted.length / size));
  const cur = serverPaging ? serverPaging.page : Math.min(page, pages);
  const visible = serverPaging ? sorted : sorted.slice((cur - 1) * size, cur * size);
  const total = serverPaging ? serverPaging.total : sorted.length;
  const ps = serverPaging ? serverPaging.pageSize : size;
  const clickSort = (c: Column<T>) => {
    if (c.sortable === false) return;
    const dir = effectiveSort?.key === c.key && effectiveSort.dir === "asc" ? "desc" : "asc";
    if (onSort) onSort(c.key, dir); else setSort({ key: c.key, dir });
  };
  const goto = (p: number) => (serverPaging ? serverPaging.onPage(p) : setPage(p));
  return (
    <div>
      <div className="table-wrap">
        <table className="table">
          <thead><tr>{columns.map((c) => (
            <th key={c.key} className={`${c.sortable === false ? "" : "sortable"} ${c.className ?? ""}`} style={{ width: c.width }} onClick={() => clickSort(c)}>
              <span className="row" style={{ gap: 4, flexWrap: "nowrap", display: "inline-flex" }}>{c.header}
                {effectiveSort?.key === c.key && (effectiveSort.dir === "asc" ? <ChevronUp size={12} /> : <ChevronDown size={12} />)}</span>
            </th>))}</tr></thead>
          <tbody>
            {visible.length === 0 && <tr><td colSpan={columns.length}><Empty>{empty}</Empty></td></tr>}
            {visible.map((r) => (
              <tr key={rowKey(r)} className={onRowClick ? "clickable" : ""} onClick={() => onRowClick?.(r)}>
                {columns.map((c) => <td key={c.key} className={c.className}>{c.render ? c.render(r) : (r as any)[c.key] ?? "-"}</td>)}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {total > Math.min(ps, 10) && (
        <div className="pagination">
          <span>{total === 0 ? 0 : (cur - 1) * ps + 1}-{Math.min(total, cur * ps)} of {total}</span>
          <div className="row">
            <select className="input sm" style={{ width: 90 }} value={ps} onChange={(e) => { const n = Number(e.target.value); if (serverPaging?.onPageSize) serverPaging.onPageSize(n); else { setSize(n); setPage(1); } }}>
              {[10, 25, 50, 100, 250].map((n) => <option key={n} value={n}>{n} / page</option>)}
            </select>
            <button className="btn sm" disabled={cur <= 1} onClick={() => goto(cur - 1)}>Previous</button>
            <span>Page {cur} of {pages}</span>
            <button className="btn sm" disabled={cur >= pages} onClick={() => goto(cur + 1)}>Next</button>
          </div>
        </div>
      )}
    </div>
  );
}
