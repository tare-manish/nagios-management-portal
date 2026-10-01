let tz = "Asia/Kolkata";
export function setTimezone(t: string) { if (t) tz = t; }
export function getTimezone() { return tz; }

export function fmtDate(iso?: string | null, opts: { seconds?: boolean; dateOnly?: boolean } = {}): string {
  if (!iso) return "-";
  const d = new Date(iso);
  if (isNaN(d.getTime())) return "-";
  const o: Intl.DateTimeFormatOptions = opts.dateOnly
    ? { timeZone: tz, day: "2-digit", month: "short", year: "numeric" }
    : { timeZone: tz, day: "2-digit", month: "short", year: "numeric", hour: "2-digit", minute: "2-digit", second: opts.seconds ? "2-digit" : undefined, hour12: false };
  return new Intl.DateTimeFormat("en-GB", o).format(d);
}

export function ago(iso?: string | null): string {
  if (!iso) return "-";
  const s = Math.round((Date.now() - new Date(iso).getTime()) / 1000);
  if (s < 0) return "in " + dur(-s);
  return dur(s) + " ago";
}

export function dur(seconds?: number | null): string {
  if (seconds === null || seconds === undefined) return "-";
  const s = Math.max(0, Math.round(seconds));
  if (s < 60) return `${s}s`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m}m`;
  const h = Math.floor(m / 60);
  if (h < 48) return `${h}h ${m % 60}m`;
  const d = Math.floor(h / 24);
  return `${d}d ${h % 24}h`;
}

export function pct(v?: number | null, digits = 2): string {
  if (v === null || v === undefined) return "-";
  return `${v.toFixed(digits)}%`;
}

export function bytes(n?: number | null): string {
  if (!n && n !== 0) return "-";
  const u = ["B", "KB", "MB", "GB", "TB"];
  let i = 0; let v = n;
  while (v >= 1024 && i < u.length - 1) { v /= 1024; i++; }
  return `${v.toFixed(v < 10 && i ? 1 : 0)} ${u[i]}`;
}

export const ENVIRONMENTS = [
  { value: "production", label: "Production" }, { value: "uat", label: "UAT" },
  { value: "development", label: "Development" }, { value: "dr", label: "DR" }, { value: "test", label: "Test" },
];
export const envLabel = (v?: string) => ENVIRONMENTS.find((e) => e.value === v)?.label ?? v ?? "-";
export const OS_TYPES = [
  { value: "windows", label: "Windows" }, { value: "linux", label: "Linux" }, { value: "unix", label: "Unix" },
  { value: "network", label: "Network Device" }, { value: "other", label: "Other" },
];
export const osLabel = (v?: string) => OS_TYPES.find((e) => e.value === v)?.label ?? v ?? "-";
export const METHODS = [
  { value: "ncpa", label: "NCPA" }, { value: "snmp", label: "SNMP" }, { value: "nrpe", label: "NRPE" },
  { value: "ping", label: "Ping only" }, { value: "custom", label: "Custom Plugin" },
];
export const methodLabel = (v?: string) => METHODS.find((e) => e.value === v)?.label ?? v ?? "-";
