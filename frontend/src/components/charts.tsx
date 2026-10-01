/* Chart kit: responsive, theme-aware SVG charts (no extra dependencies).
 *
 *  TimeChart   - time series (line + area wash), thresholds, crosshair tooltip, stats, table view
 *  StatusBar   - part-to-whole state distribution (100% stacked bar + legend with icons)
 *  RankBars    - ranked horizontal bars (lowest availability, highest utilisation, ...)
 *
 * All colours come from CSS custom properties, so light/dark themes switch without re-rendering.
 * Every chart works with mouse, touch (drag to scrub, page still scrolls vertically) and keyboard.
 */
import { useCallback, useEffect, useId, useMemo, useRef, useState, type ReactNode } from "react";
import { getTimezone } from "../lib/format";

/* ------------------------------------------------------------- helpers -- */
export function useWidth<T extends HTMLElement>(): [(el: T | null) => void, number] {
  const [w, setW] = useState(0);
  const ro = useRef<ResizeObserver | null>(null);
  const ref = useCallback((el: T | null) => {
    ro.current?.disconnect();
    ro.current = null;
    if (!el) return;
    setW(el.getBoundingClientRect().width);
    ro.current = new ResizeObserver((entries) => setW(entries[0].contentRect.width));
    ro.current.observe(el);
  }, []);
  useEffect(() => () => ro.current?.disconnect(), []);
  return [ref, w];
}

function niceStep(range: number, count: number): number {
  const raw = range / Math.max(1, count);
  const mag = Math.pow(10, Math.floor(Math.log10(raw || 1)));
  const n = raw / mag;
  return (n <= 1 ? 1 : n <= 2 ? 2 : n <= 2.5 ? 2.5 : n <= 5 ? 5 : 10) * mag;
}

export function niceTicks(min: number, max: number, count = 5): number[] {
  if (max <= min) max = min + 1;
  const step = niceStep(max - min, count);
  const out: number[] = [];
  for (let v = Math.floor(min / step) * step; v <= max + step * 1e-6; v += step) out.push(+v.toFixed(10));
  return out;
}

const BYTE_UNITS = ["B", "KB", "MB", "GB", "TB", "PB"];

/** Format a metric value with its Nagios unit of measure. */
export function fmtValue(v: number | null | undefined, uom?: string | null, compact = false): string {
  if (v === null || v === undefined || !isFinite(v)) return "-";
  const u = (uom ?? "").trim();
  if (u === "%") return `${v >= 100 || compact ? Math.round(v) : +v.toFixed(1)}%`;
  const bi = BYTE_UNITS.findIndex((x) => x.toLowerCase() === u.toLowerCase());
  if (bi >= 0) {
    let x = Math.abs(v), i = bi;
    while (x >= 1024 && i < BYTE_UNITS.length - 1) { x /= 1024; i++; }
    while (x > 0 && x < 1 && i > 0) { x *= 1024; i--; }
    return `${v < 0 ? "-" : ""}${x >= 100 ? Math.round(x) : +x.toFixed(1)} ${BYTE_UNITS[i]}`;
  }
  if (u === "s") {
    const s = Math.abs(v);
    if (s >= 86400) return `${+(v / 86400).toFixed(1)} d`;
    if (s >= 3600) return `${+(v / 3600).toFixed(1)} h`;
    if (s >= 60) return `${+(v / 60).toFixed(1)} min`;
    if (s < 1 && s > 0) return `${+(v * 1000).toFixed(0)} ms`;
    return `${+v.toFixed(2)} s`;
  }
  const a = Math.abs(v);
  let num: string;
  if (a >= 1e9) num = `${+(v / 1e9).toFixed(1)}B`;
  else if (a >= 1e6) num = `${+(v / 1e6).toFixed(1)}M`;
  else if (a >= 1e4 || (compact && a >= 1e3)) num = `${+(v / 1e3).toFixed(1)}K`;
  else if (a >= 100) num = String(Math.round(v));
  else num = String(+v.toFixed(a >= 10 ? 1 : 2));
  return u && u !== "c" ? `${num} ${u}` : num;
}

function fmtTime(t: number, spanMs: number, full = false): string {
  const tz = getTimezone();
  const o: Intl.DateTimeFormatOptions = full
    ? { timeZone: tz, day: "2-digit", month: "short", hour: "2-digit", minute: "2-digit", hour12: false }
    : spanMs <= 36 * 3600_000 ? { timeZone: tz, hour: "2-digit", minute: "2-digit", hour12: false }
    : spanMs <= 8 * 86400_000 ? { timeZone: tz, weekday: "short", hour: "2-digit", hour12: false }
    : { timeZone: tz, day: "2-digit", month: "short" };
  const s = new Intl.DateTimeFormat("en-GB", o).format(new Date(t));
  return spanMs > 36 * 3600_000 && spanMs <= 8 * 86400_000 && !full ? s.replace(/,? (\d\d)$/, " $1:00") : s;
}

function timeTicks(min: number, max: number, width: number): number[] {
  const count = Math.max(2, Math.min(8, Math.floor(width / 90)));
  const steps = [5, 10, 15, 30, 60, 120, 180, 360, 720, 1440, 2880, 10080].map((m) => m * 60_000);
  const step = steps.find((s) => (max - min) / s <= count) ?? 30 * 86400_000;
  const off = utcOffset(min); // align to round local times in the display time zone
  const out: number[] = [];
  for (let t = Math.ceil((min + off) / step) * step - off; t <= max; t += step) out.push(t);
  return out;
}

/** Offset of the display time zone from UTC at instant t, in ms. */
function utcOffset(t: number): number {
  try {
    const p = Object.fromEntries(new Intl.DateTimeFormat("en-US", { timeZone: getTimezone(), hourCycle: "h23", year: "numeric", month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit", second: "2-digit" })
      .formatToParts(new Date(t)).map((x) => [x.type, x.value]));
    return Date.UTC(+p.year, +p.month - 1, +p.day, +p.hour, +p.minute, +p.second) - Math.floor(t / 1000) * 1000;
  } catch { return 0; }
}

/* ----------------------------------------------------------- TimeChart -- */
export interface Series { label: string; points: [string, number][]; uom?: string | null; warn?: number | null; crit?: number | null }

type Pt = { x: number; y: number };
const PAD = { top: 10, right: 14, bottom: 26 };

function stateOf(v: number, warn?: number | null, crit?: number | null): "ok" | "warning" | "critical" {
  if (crit != null && warn != null && crit < warn) { // inverted thresholds (e.g. free space: lower is worse)
    if (v <= crit) return "critical";
    if (v <= warn) return "warning";
    return "ok";
  }
  if (crit != null && v >= crit) return "critical";
  if (warn != null && v >= warn) return "warning";
  return "ok";
}
const STATE_LABEL = { ok: "OK", warning: "Warning", critical: "Critical" } as const;

function StateChip({ state }: { state: "ok" | "warning" | "critical" }) {
  const icon = state === "ok" ? "✓" : state === "warning" ? "!" : "✕";
  return <span className={`vz-state vz-${state}`}><span className="vz-state-icon" aria-hidden>{icon}</span>{STATE_LABEL[state]}</span>;
}

/** Time series for one measure (one y-axis). Up to 3 series; thresholds of the first series are drawn as reference lines. */
export function TimeChart({ series, height = 200, max, hours, stats = true, dimmed = false }: {
  series: Series[]; height?: number; max?: number; hours?: number; stats?: boolean; dimmed?: boolean;
}) {
  const [boxRef, width] = useWidth<HTMLDivElement>();
  const gid = useId().replace(/:/g, "");
  const [hover, setHover] = useState<number | null>(null);
  const [table, setTable] = useState(false);
  const list = series.slice(0, 3);
  const first = list[0];
  const uom = first?.uom ?? null;
  const pts: Pt[][] = useMemo(() => list.map((s) => s.points.map(([t, v]) => ({ x: new Date(t).getTime(), y: v })).sort((a, b) => a.x - b.x)), [series]); // eslint-disable-line react-hooks/exhaustive-deps
  const all = pts.flat();
  const now = Date.now();
  const x0 = hours ? now - hours * 3600_000 : Math.min(...all.map((p) => p.x));
  const x1 = hours ? now : Math.max(...all.map((p) => p.x));
  const ys = all.map((p) => p.y);
  const dataMax = ys.length ? Math.max(...ys) : 1;
  const dataMin = ys.length ? Math.min(...ys) : 0;
  const isPct = uom === "%";
  let yMax = Math.max(dataMax, first?.warn ?? -Infinity, first?.crit ?? -Infinity, max ?? -Infinity);
  if (isPct && dataMax <= 100) yMax = 100;
  else yMax = yMax * 1.08 || 1;
  const yMin = Math.min(0, dataMin);
  // byte-like units get ticks on binary boundaries (10 MB, 20 MB...) instead of 19.1 MB
  const bi = BYTE_UNITS.findIndex((u) => u.toLowerCase() === (uom ?? "").toLowerCase());
  const scale = bi >= 0 ? Math.pow(1024, Math.max(0, Math.floor(Math.log(Math.max(1, yMax)) / Math.log(1024)))) : 1;
  const yTicks = niceTicks(yMin / scale, yMax / scale, height < 160 ? 3 : 4).map((t) => t * scale);
  const yTop = yTicks[yTicks.length - 1];
  const labels = yTicks.map((t) => fmtValue(t, uom, true));
  const left = Math.min(64, Math.max(30, Math.max(...labels.map((l) => l.length)) * 6.6 + 10));
  const plotW = Math.max(10, width - left - PAD.right);
  const plotH = height;
  const sx = (x: number) => left + ((x - x0) / Math.max(1, x1 - x0)) * plotW;
  const sy = (y: number) => PAD.top + plotH - ((y - yMin) / Math.max(1e-9, yTop - yMin)) * plotH;
  const xTicks = width ? timeTicks(x0, x1, plotW) : [];
  const span = x1 - x0;

  // split each series where samples are missing (gap > 3x the typical interval)
  const segments = (p: Pt[]): Pt[][] => {
    if (p.length < 2) return p.length ? [p] : [];
    const d = p.slice(1).map((q, i) => q.x - p[i].x).sort((a, b) => a - b);
    const gap = Math.max(d[Math.floor(d.length / 2)] * 3, 10 * 60_000);
    const out: Pt[][] = [[p[0]]];
    for (let i = 1; i < p.length; i++) {
      if (p[i].x - p[i - 1].x > gap) out.push([]);
      out[out.length - 1].push(p[i]);
    }
    return out;
  };
  const linePath = (seg: Pt[]) => seg.map((p, i) => `${i ? "L" : "M"}${sx(p.x).toFixed(1)},${sy(p.y).toFixed(1)}`).join("");
  const areaPath = (seg: Pt[]) => seg.length < 2 ? "" : `${linePath(seg)}L${sx(seg[seg.length - 1].x).toFixed(1)},${sy(Math.max(yMin, 0)).toFixed(1)}L${sx(seg[0].x).toFixed(1)},${sy(Math.max(yMin, 0)).toFixed(1)}Z`;

  const base = pts[0] ?? [];
  const nearest = useCallback((px: number) => {
    if (!base.length) return null;
    const t = x0 + ((px - left) / plotW) * (x1 - x0);
    let lo = 0, hi = base.length - 1;
    while (hi - lo > 1) { const mid = (lo + hi) >> 1; if (base[mid].x < t) lo = mid; else hi = mid; }
    return Math.abs(base[lo].x - t) <= Math.abs(base[hi].x - t) ? lo : hi;
  }, [base, x0, x1, left, plotW]);

  const onMove = (e: React.PointerEvent<SVGRectElement>) => {
    const r = (e.currentTarget.ownerSVGElement as SVGSVGElement).getBoundingClientRect();
    setHover(nearest(e.clientX - r.left));
  };
  const onKey = (e: React.KeyboardEvent) => {
    if (!base.length) return;
    if (e.key === "ArrowLeft" || e.key === "ArrowRight") {
      e.preventDefault();
      setHover((h) => Math.max(0, Math.min(base.length - 1, (h ?? base.length - 1) + (e.key === "ArrowLeft" ? -1 : 1))));
    } else if (e.key === "Home") setHover(0);
    else if (e.key === "End") setHover(base.length - 1);
    else if (e.key === "Escape") setHover(null);
  };

  const vals = base.map((p) => p.y);
  const last = base[base.length - 1];
  const avg = vals.length ? vals.reduce((a, b) => a + b, 0) / vals.length : null;
  const peak = vals.length ? Math.max(...vals) : null;
  const low = vals.length ? Math.min(...vals) : null;
  const hasThr = first?.warn != null || first?.crit != null;
  const cur = last ? stateOf(last.y, first?.warn, first?.crit) : null;

  // threshold labels: keep them apart when the two lines are close
  const thr: { key: "warning" | "critical"; v: number; y: number }[] = [];
  if (first?.warn != null) thr.push({ key: "warning", v: first.warn, y: sy(first.warn) });
  if (first?.crit != null) thr.push({ key: "critical", v: first.crit, y: sy(first.crit) });
  thr.sort((a, b) => a.y - b.y);
  const thrLabelY = thr.map((t) => t.y - 4);
  if (thr.length === 2 && thrLabelY[1] - thrLabelY[0] < 13) thrLabelY[1] = thr[1].y + 12;

  const hp = hover != null ? base[hover] : null;
  const tipLeft = hp ? sx(hp.x) : 0;
  const tipFlip = tipLeft > width - 170;
  const summary = first ? `${first.label}: ${vals.length} samples, latest ${fmtValue(last?.y, uom)}, average ${fmtValue(avg, uom)}, peak ${fmtValue(peak, uom)}` : "No data";
  const totalH = PAD.top + plotH + PAD.bottom;

  return (
    <div className={`vz ${dimmed ? "vz-dim" : ""}`}>
      {stats && first && (
        <div className="vz-stats">
          <div className="vz-now"><span className="vz-now-v">{fmtValue(last?.y, uom)}</span>{hasThr && cur && <StateChip state={cur} />}</div>
          <div className="vz-mini">
            <span><em>Avg</em>{fmtValue(avg, uom)}</span><span><em>Peak</em>{fmtValue(peak, uom)}</span><span><em>Low</em>{fmtValue(low, uom)}</span>
            <button type="button" className="vz-link" onClick={() => setTable((t) => !t)} aria-pressed={table}>{table ? "Chart" : "Table"}</button>
          </div>
        </div>
      )}
      {list.length > 1 && (
        <div className="vz-legend">{list.map((s, i) => <span key={i}><i className={`vz-key-line vz-s${i + 1}`} />{s.label}</span>)}</div>
      )}
      {table ? (
        <div className="vz-table"><table className="table"><thead><tr><th>Time</th>{list.map((s, i) => <th key={i} className="num">{s.label}</th>)}</tr></thead>
          <tbody>{[...base].reverse().slice(0, 500).map((p, i) => {
            const idx = base.length - 1 - i;
            return <tr key={p.x}><td className="nowrap">{fmtTime(p.x, span, true)}</td>{pts.map((sp, j) => <td key={j} className="num">{fmtValue(sp[idx]?.y, uom)}</td>)}</tr>;
          })}</tbody></table></div>
      ) : (
        <div ref={boxRef} className="vz-box" style={{ height: totalH }}>
          {width > 0 && (
            <svg width={width} height={totalH} role="img" aria-label={summary} tabIndex={0} onKeyDown={onKey} onBlur={() => setHover(null)} className="vz-svg">
              <defs>
                {list.map((_, i) => (
                  <linearGradient key={i} id={`${gid}-g${i}`} x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" className={`vz-stop-top vz-s${i + 1}`} />
                    <stop offset="100%" className={`vz-stop-bot vz-s${i + 1}`} />
                  </linearGradient>
                ))}
                <clipPath id={`${gid}-clip`}><rect x={left} y={PAD.top - 2} width={plotW} height={plotH + 4} /></clipPath>
              </defs>
              {/* grid + y axis */}
              {yTicks.map((t, i) => (
                <g key={t}>
                  <line x1={left} x2={left + plotW} y1={sy(t)} y2={sy(t)} className={i === 0 ? "vz-base" : "vz-grid"} />
                  <text x={left - 8} y={sy(t)} dy="0.32em" textAnchor="end" className="vz-tick">{labels[i]}</text>
                </g>
              ))}
              {xTicks.map((t) => (
                <text key={t} x={sx(t)} y={PAD.top + plotH + 18} textAnchor="middle" className="vz-tick">{fmtTime(t, span)}</text>
              ))}
              {/* thresholds */}
              {thr.map((t, i) => (
                <g key={t.key}>
                  <line x1={left} x2={left + plotW} y1={t.y} y2={t.y} className={`vz-thr vz-thr-${t.key}`} />
                  <text x={left + plotW - 4} y={thrLabelY[i]} textAnchor="end" className="vz-thr-label">{t.key === "critical" ? "Critical" : "Warning"} {fmtValue(t.v, uom)}</text>
                </g>
              ))}
              {/* series */}
              <g clipPath={`url(#${gid}-clip)`}>
                {pts.map((p, i) => segments(p).map((seg, k) => (
                  <g key={`${i}-${k}`}>
                    {list.length === 1 && <path d={areaPath(seg)} style={{ fill: `url(#${gid}-g${i})` }} />}
                    <path d={linePath(seg)} className={`vz-line vz-s${i + 1}`} />
                    {seg.length === 1 && <circle cx={sx(seg[0].x)} cy={sy(seg[0].y)} r={2.5} className={`vz-dot vz-s${i + 1}`} />}
                  </g>
                )))}
              </g>
              {/* end marker */}
              {last && hover == null && <circle cx={sx(last.x)} cy={sy(last.y)} r={4} className="vz-dot vz-ring vz-s1" />}
              {/* crosshair */}
              {hp && (
                <g pointerEvents="none">
                  <line x1={sx(hp.x)} x2={sx(hp.x)} y1={PAD.top} y2={PAD.top + plotH} className="vz-cross" />
                  {pts.map((p, i) => p[hover!] && <circle key={i} cx={sx(p[hover!].x)} cy={sy(p[hover!].y)} r={4.5} className={`vz-dot vz-ring vz-s${i + 1}`} />)}
                </g>
              )}
              <rect x={left} y={0} width={plotW} height={PAD.top + plotH} fill="transparent" style={{ touchAction: "pan-y" }}
                onPointerMove={onMove} onPointerDown={onMove} onPointerLeave={() => setHover(null)} onPointerCancel={() => setHover(null)} />
            </svg>
          )}
          {hp && (
            <div className="vz-tip" style={{ left: tipFlip ? undefined : tipLeft + 12, right: tipFlip ? width - tipLeft + 12 : undefined, top: PAD.top }}>
              <div className="vz-tip-time">{fmtTime(hp.x, span, true)}</div>
              {pts.map((p, i) => p[hover!] && (
                <div className="vz-tip-row" key={i}>
                  <i className={`vz-key-line vz-s${i + 1}`} /><strong>{fmtValue(p[hover!].y, uom)}</strong><span>{list[i].label}</span>
                </div>
              ))}
              {hasThr && <div className="vz-tip-state"><StateChip state={stateOf(hp.y, first?.warn, first?.crit)} /></div>}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

/* ----------------------------------------------------------- StatusBar -- */
export interface StatusPart { key: string; label: string; value: number; tone: "good" | "warning" | "serious" | "critical" | "unknown" | "neutral"; icon?: ReactNode; onClick?: () => void }

/** Part-to-whole of states. Problems first (left), healthy last; 2px surface gaps; legend always visible. */
export function StatusBar({ parts, total, caption }: { parts: StatusPart[]; total?: number; caption?: ReactNode }) {
  const sum = total ?? parts.reduce((a, p) => a + p.value, 0);
  const [hover, setHover] = useState<string | null>(null);
  const shown = parts.filter((p) => p.value > 0);
  return (
    <div className="vz-status">
      {caption && <div className="vz-status-cap">{caption}</div>}
      <div className="vz-sbar" role="img" aria-label={parts.map((p) => `${p.label} ${p.value}`).join(", ")}>
        {sum === 0 ? <div className="vz-sseg vz-tone-neutral" style={{ flexGrow: 1 }} /> : shown.map((p) => {
          const share = (p.value / sum) * 100;
          return (
            <div key={p.key} className={`vz-sseg vz-tone-${p.tone} ${hover && hover !== p.key ? "vz-fade" : ""}`} style={{ flexGrow: p.value, minWidth: 6 }}
              onPointerEnter={(e) => e.pointerType === "mouse" && setHover(p.key)} onPointerLeave={() => setHover(null)} onClick={p.onClick}
              title={`${p.label}: ${p.value} (${share.toFixed(1)}%)`}>
              {share >= 12 && <span className="vz-sseg-label">{p.value}</span>}
            </div>
          );
        })}
      </div>
      <div className="vz-slegend">
        {parts.map((p) => (
          <button type="button" key={p.key} className={`vz-sitem ${p.onClick ? "" : "static"} ${hover === p.key ? "on" : ""}`} onClick={p.onClick} disabled={!p.onClick}
            onPointerEnter={(e) => e.pointerType === "mouse" && setHover(p.key)} onPointerLeave={() => setHover(null)} onFocus={() => setHover(p.key)} onBlur={() => setHover(null)}>
            {p.icon ?? <i className={`vz-swatch vz-tone-${p.tone}`} />}<span className="vz-sitem-label">{p.label}</span>
            <strong>{p.value}</strong><span className="vz-sitem-pct">{sum ? `${((p.value / sum) * 100).toFixed(p.value / sum < 0.1 && p.value ? 1 : 0)}%` : "-"}</span>
          </button>
        ))}
      </div>
    </div>
  );
}

/* ------------------------------------------------------------ RankBars -- */
export interface RankRow { key: string | number; label: string; sub?: string; value: number | null; href?: string; tone?: "good" | "warning" | "critical" | "series" }

/** Ranked horizontal bars (one series = one colour; status tone only when the value means good/bad). */
export function RankBars({ rows, max, uom, empty = "No data", onClickRow, limit = 10 }: {
  rows: RankRow[]; max?: number; uom?: string; empty?: string; onClickRow?: (r: RankRow) => void; limit?: number;
}) {
  const data = rows.filter((r) => r.value != null).slice(0, limit);
  const top = max ?? Math.max(1, ...data.map((r) => r.value as number));
  if (!data.length) return <div className="empty">{empty}</div>;
  return (
    <div className="vz-rank" role="list">
      {data.map((r) => {
        const w = Math.max(0.6, Math.min(100, ((r.value as number) / top) * 100));
        return (
          <div role="listitem" key={r.key} className={`vz-rank-row ${onClickRow ? "click" : ""}`} onClick={onClickRow ? () => onClickRow(r) : undefined}
            tabIndex={onClickRow ? 0 : undefined} onKeyDown={(e) => { if (onClickRow && e.key === "Enter") onClickRow(r); }}
            title={`${r.label}: ${fmtValue(r.value, uom)}`}>
            <div className="vz-rank-label"><span className="vz-rank-name">{r.label}</span>{r.sub && <span className="vz-rank-sub">{r.sub}</span>}</div>
            <div className="vz-rank-track"><div className={`vz-rank-bar vz-tone-${r.tone ?? "series"}`} style={{ width: `${w}%` }} /></div>
            <div className="vz-rank-val">{fmtValue(r.value, uom)}</div>
          </div>
        );
      })}
    </div>
  );
}

/* --------------------------------------------------------- Sparkline -- */
/** Tiny trend line for tables and tiles (no axes). */
export function Sparkline({ values, width = 96, height = 28 }: { values: number[]; width?: number; height?: number }) {
  if (values.length < 2) return null;
  const mn = Math.min(...values), mx = Math.max(...values);
  const d = values.map((v, i) => `${i ? "L" : "M"}${((i / (values.length - 1)) * (width - 4) + 2).toFixed(1)},${(height - 3 - ((v - mn) / Math.max(1e-9, mx - mn)) * (height - 6)).toFixed(1)}`).join("");
  return <svg width={width} height={height} aria-hidden className="vz-spark"><path d={d} className="vz-line vz-s1" /></svg>;
}

