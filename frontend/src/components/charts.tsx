import { Table2, BarChart3 } from "lucide-react";
import { type ReactNode, useMemo, useState } from "react";
import { onActivate } from "../lib/a11y";
import { fmtHour } from "../lib/format";
import { fmt, useT } from "../lib/i18n";
import type { Dashboard } from "../lib/types";

/**
 * Alterna entre el gráfico y una tabla con los mismos datos. La tabla es la alternativa
 * accesible para lectores de pantalla, navegación por teclado y personas que no distinguen colores.
 */
export function ChartOrTable({ columns, rows, caption, children }: {
  columns: string[];
  rows: (string | number)[][];
  caption: string;
  children: ReactNode;
}) {
  const t = useT();
  const [table, setTable] = useState(false);
  return (
    <div>
      <div className="mb-1 flex justify-end">
        <button className="btn-ghost px-2 py-1 text-xs" onClick={() => setTable(!table)} aria-pressed={table}>
          {table ? <BarChart3 size={13} aria-hidden="true" /> : <Table2 size={13} aria-hidden="true" />}
          {table ? t.viewChart : t.viewTable}
        </button>
      </div>
      {table ? (
        <div tabIndex={0} role="region" aria-label={caption} className="max-h-80 overflow-auto rounded-lg border border-slate-200 dark:border-slate-800">
          <table className="w-full border-collapse">
            <caption className="sr-only">{caption}</caption>
            <thead>
              <tr>
                {columns.map((c) => (
                  <th key={c} scope="col" className="th cursor-default">
                    {c}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {rows.map((r, i) => (
                <tr key={i}>
                  {r.map((v, j) => (
                    <td key={j} className="td tabular-nums">
                      {v}
                    </td>
                  ))}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : (
        children
      )}
    </div>
  );
}

/** Mapa de calor día × hora: secuencial de un solo tono (claro → oscuro), con marca de evidencia. */
export function Heatmap({ data, theme, onCell }: {
  data: Dashboard["heatmap"];
  theme: "light" | "dark";
  onCell: (weekday: number, hour: number) => void;
}) {
  const t = useT();
  const [hover, setHover] = useState<Dashboard["heatmap"][number] | null>(null);
  const max = Math.max(1, ...data.map((d) => d.events));
  const days = Array.from(new Set(data.map((d) => d.weekday)));
  const cw = 26;
  const ch = 22;
  const left = 36;
  const top = 18;
  // rampa secuencial azul: del color de superficie al azul profundo
  const ramp = (v: number) => {
    if (v === 0) return theme === "dark" ? "#1e293b" : "#f1f5f9";
    const k = 0.15 + 0.85 * Math.sqrt(v / max);
    const light = [219, 234, 254];
    const dark = theme === "dark" ? [96, 165, 250] : [29, 78, 216];
    const c = light.map((l, i) => Math.round(l + (dark[i] - l) * k));
    return `rgb(${c.join(",")})`;
  };
  const describe = (c: Dashboard["heatmap"][number]) =>
    fmt(t.heatmapCell, { day: t.weekdays[c.weekday], h: c.hour, events: c.events, evidence: c.evidence });
  return (
    <div className="relative">
      <svg viewBox={`0 0 ${left + 24 * cw} ${top + 7 * ch + 4}`} className="w-full" role="group" aria-label={t.heatmapAria}>
        {Array.from({ length: 24 }, (_, h) => (
          <text key={h} x={left + h * cw + cw / 2} y={12} textAnchor="middle" className="fill-slate-500" fontSize={12} aria-hidden="true">
            {h % 3 === 0 ? `${h}h` : ""}
          </text>
        ))}
        {days.map((d, row) => (
          <text key={d} x={left - 6} y={top + row * ch + ch / 2 + 3} textAnchor="end" className="fill-slate-500 text-xs" aria-hidden="true">
            {t.weekdays[d]}
          </text>
        ))}
        {data.map((c) => (
          <g
            key={`${c.weekday}-${c.hour}`}
            role="button"
            tabIndex={c.events ? 0 : -1}
            aria-label={describe(c)}
            onMouseEnter={() => setHover(c)}
            onMouseLeave={() => setHover(null)}
            onFocus={() => setHover(c)}
            onBlur={() => setHover(null)}
            onClick={() => onCell(c.weekday, c.hour)}
            onKeyDown={onActivate(() => onCell(c.weekday, c.hour))}
            className="cursor-pointer outline-none [&:focus-visible>rect]:stroke-sky-500 [&:focus-visible>rect]:stroke-2"
          >
            <rect x={left + c.hour * cw + 1} y={top + c.weekday * ch + 1} width={cw - 2} height={ch - 2} rx={3} fill={ramp(c.events)} />
            {c.evidence > 0 && <circle cx={left + c.hour * cw + cw - 6} cy={top + c.weekday * ch + 6} r={3} fill="#dc2626" stroke={theme === "dark" ? "#0f172a" : "#fff"} strokeWidth={1.5} />}
          </g>
        ))}
      </svg>
      <div className="mt-1 flex flex-wrap items-center gap-3 text-xs text-slate-500">
        <span className="flex items-center gap-1">
          {t.less} <span className="inline-block h-2.5 w-16 rounded" style={{ background: `linear-gradient(90deg, ${ramp(1)}, ${ramp(max)})` }} /> {t.moreEvents}
        </span>
        <span className="flex items-center gap-1">
          <span className="inline-block h-2 w-2 rounded-full bg-red-600" /> {t.hasEvidence}
        </span>
      </div>
      {hover && (
        <div role="status" className="pointer-events-none absolute right-0 top-0 rounded-lg border border-slate-200 bg-white px-2 py-1 text-xs shadow dark:border-slate-700 dark:bg-slate-800">
          {describe(hover)}
        </div>
      )}
    </div>
  );
}

/** Grafo dirigido de movimiento lateral (layout circular determinístico). */
export function LateralGraph({ graph, theme, onEdge }: {
  graph: Dashboard["lateral"];
  theme: "light" | "dark";
  onEdge: (edge: Dashboard["lateral"]["edges"][number]) => void;
}) {
  const t = useT();
  const [hover, setHover] = useState<string | null>(null);
  const W = 640;
  const H = 360;
  const pos = useMemo(() => {
    const nodes = [...graph.nodes].sort((a, b) => b.out - a.out || a.id.localeCompare(b.id));
    const r = Math.min(W, H) / 2 - 50;
    return Object.fromEntries(
      nodes.map((n, i) => {
        const a = (2 * Math.PI * i) / Math.max(nodes.length, 1) - Math.PI / 2;
        return [n.id, { x: W / 2 + r * 1.45 * Math.cos(a), y: H / 2 + r * Math.sin(a) }];
      }),
    );
  }, [graph]);
  const ink = theme === "dark" ? "#e2e8f0" : "#0f172a";
  const muted = theme === "dark" ? "#64748b" : "#94a3b8";
  const accent = theme === "dark" ? "#f87171" : "#dc2626";
  return (
    <svg viewBox={`0 0 ${W} ${H}`} className="w-full" role="group" aria-label={t.lateralAria}>
      <defs>
        {["lat", "oth"].map((k) => (
          <marker key={k} id={`arrow-${k}`} viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">
            <path d="M0,0 L10,5 L0,10 z" fill={k === "lat" ? accent : muted} />
          </marker>
        ))}
      </defs>
      {graph.edges.map((e) => {
        const a = pos[e.source];
        const b = pos[e.target];
        if (!a || !b) return null;
        const dx = b.x - a.x;
        const dy = b.y - a.y;
        const len = Math.hypot(dx, dy) || 1;
        const ux = dx / len;
        const uy = dy / len;
        const x1 = a.x + ux * 20;
        const y1 = a.y + uy * 20;
        const x2 = b.x - ux * 22;
        const y2 = b.y - uy * 22;
        const mx = (x1 + x2) / 2 - uy * 18;
        const my = (y1 + y2) / 2 + ux * 18;
        const key = `${e.source}->${e.target}`;
        const active = hover === key;
        return (
          <g
            key={key}
            role="button"
            tabIndex={0}
            aria-label={fmt(t.edgeAria, { from: e.source, to: e.target, kinds: e.kinds.join(", "), n: e.count })}
            className="cursor-pointer outline-none"
            onClick={() => onEdge(e)}
            onKeyDown={onActivate(() => onEdge(e))}
            onMouseEnter={() => setHover(key)}
            onMouseLeave={() => setHover(null)}
            onFocus={() => setHover(key)}
            onBlur={() => setHover(null)}
          >
            <path d={`M${x1},${y1} Q${mx},${my} ${x2},${y2}`} fill="none" stroke="transparent" strokeWidth={14} />
            <path
              d={`M${x1},${y1} Q${mx},${my} ${x2},${y2}`}
              fill="none"
              stroke={e.lateral ? accent : muted}
              strokeWidth={active ? 3.5 : 2}
              strokeDasharray={e.lateral ? undefined : "5 4"}
              markerEnd={`url(#arrow-${e.lateral ? "lat" : "oth"})`}
            />
            <text x={mx} y={my} textAnchor="middle" className="text-xs" fill={ink} fontWeight={active ? 700 : 400}>
              {e.kinds.join(" / ")} ×{e.count}
            </text>
          </g>
        );
      })}
      {graph.nodes.map((n) => {
        const p = pos[n.id];
        return (
          <g key={n.id} aria-hidden="true">
            <circle cx={p.x} cy={p.y} r={16} fill={n.kind === "ip" ? (theme === "dark" ? "#334155" : "#e2e8f0") : theme === "dark" ? "#1e3a8a" : "#dbeafe"} stroke={ink} strokeWidth={1} />
            <text x={p.x} y={p.y + 30} textAnchor="middle" className="text-xs font-medium" fill={ink}>
              {n.id}
            </text>
          </g>
        );
      })}
    </svg>
  );
}

export const tickHour = (v: string) => fmtHour(v);
