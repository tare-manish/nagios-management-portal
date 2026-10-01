// Fetch wrapper: same-origin cookies, CSRF header on mutations, structured errors.
export interface ApiErrorDetail { field?: string; message: string }
export class ApiError extends Error {
  status: number; code: string; details: unknown;
  constructor(status: number, code: string, message: string, details?: unknown) {
    super(message); this.status = status; this.code = code; this.details = details;
  }
  fieldErrors(): Record<string, string> {
    const out: Record<string, string> = {};
    if (Array.isArray(this.details)) for (const d of this.details as ApiErrorDetail[]) if (d && d.field) out[d.field] = d.message;
    return out;
  }
  describe(): string {
    if (Array.isArray(this.details) && this.details.length) {
      const parts = (this.details as ApiErrorDetail[]).map((d) => (typeof d === "string" ? d : d.field ? `${d.field}: ${d.message}` : d.message));
      return `${this.message} - ${parts.join("; ")}`;
    }
    return this.message;
  }
}

let csrfToken: string | null = null;
export function setCsrf(t: string | null) { csrfToken = t; }
function readCookie(name: string): string | null {
  const m = document.cookie.match(new RegExp("(?:^|; )" + name + "=([^;]*)"));
  return m ? decodeURIComponent(m[1]) : null;
}

type Listener = (e: ApiError) => void;
const authListeners: Listener[] = [];
export function onAuthError(l: Listener) { authListeners.push(l); }

export interface Envelope<T> { data: T; meta?: Record<string, any> }

async function request<T>(method: string, url: string, body?: unknown, opts: { raw?: boolean } = {}): Promise<Envelope<T>> {
  const headers: Record<string, string> = { Accept: "application/json" };
  if (body !== undefined) headers["Content-Type"] = "application/json";
  if (method !== "GET") {
    const t = csrfToken || readCookie("nmp_csrf");
    if (t) headers["X-CSRF-Token"] = t;
  }
  let res: Response;
  try {
    res = await fetch(url, { method, headers, credentials: "same-origin", body: body === undefined ? undefined : JSON.stringify(body) });
  } catch {
    throw new ApiError(0, "network", "Cannot reach the portal server");
  }
  if (opts.raw) return { data: res as unknown as T };
  let json: any = null;
  try { json = await res.json(); } catch { /* empty */ }
  if (!res.ok) {
    const e = json?.error || {};
    const err = new ApiError(res.status, e.code || "http_error", e.message || `HTTP ${res.status}`, e.details);
    if (res.status === 401 || err.code === "password_change_required") authListeners.forEach((l) => l(err));
    throw err;
  }
  return json as Envelope<T>;
}

export const api = {
  get: <T = any>(url: string, params?: Record<string, any>) => {
    const qs = params ? "?" + new URLSearchParams(Object.entries(params).filter(([, v]) => v !== undefined && v !== null && v !== "").map(([k, v]) => [k, String(v)])).toString() : "";
    return request<T>("GET", url + (qs === "?" ? "" : qs));
  },
  post: <T = any>(url: string, body?: unknown) => request<T>("POST", url, body ?? {}),
  put: <T = any>(url: string, body?: unknown) => request<T>("PUT", url, body ?? {}),
  del: <T = any>(url: string) => request<T>("DELETE", url),
};

export function download(url: string) {
  const a = document.createElement("a");
  a.href = url; a.rel = "noopener"; document.body.appendChild(a); a.click(); a.remove();
}
