import { ArrowDown, ArrowUp, ChevronLeft, ChevronRight, Search } from "lucide-react";
import { Fragment, useEffect, useMemo, useState } from "react";
import { api } from "../lib/api";
import { cls, fmtTs } from "../lib/format";
import { fmt, useT } from "../lib/i18n";
import { useStore } from "../lib/store";
import type { EventRow, EventsPage } from "../lib/types";
import { Chip, ErrorBox, Spinner } from "./ui";

type ColKey = "row_id" | "ts_iso" | "event_id" | "user" | "host" | "src_ip" | "logon_type" | "outcome" | "command_line" | "log_id" | "log_source";

const COLUMNS: { key: ColKey; mono?: boolean; width?: string }[] = [
  { key: "row_id", mono: true, width: "w-36" },
  { key: "ts_iso", mono: true, width: "w-40" },
  { key: "event_id" },
  { key: "user" },
  { key: "host" },
  { key: "src_ip", mono: true },
  { key: "logon_type" },
  { key: "outcome" },
  { key: "command_line", mono: true },
];

function detail(r: EventRow, groupPrefix: string): string {
  const main = (r.command_line as string) || (r.process as string) || (r.group as string ? `${groupPrefix} ${r.group}` : "") || (r.message as string) || "";
  const dest = r.destination as string | undefined;
  return dest && !main.includes(dest) ? `${main}${main ? "  →  " : "→ "}${dest}` : main;
}

// columnas opcionales que solo se muestran si el archivo las trae
const OPTIONAL: { key: ColKey; mono?: boolean; after: ColKey }[] = [
  { key: "log_id", mono: true, after: "row_id" },
  { key: "log_source", after: "ts_iso" },
];

export default function EventsTable({ params = {}, compact = false, showToolbar = true, label }: {
  params?: Record<string, unknown>;
  label?: string;
  compact?: boolean;
  showToolbar?: boolean;
}) {
  const t = useT();
  const sid = useStore((s) => s.upload?.session_id);
  const [page, setPage] = useState(1);
  const [size, setSize] = useState(compact ? 25 : 50);
  const [q, setQ] = useState("");
  const [query, setQuery] = useState("");
  const [sort, setSort] = useState("ts");
  const [order, setOrder] = useState<"asc" | "desc">("asc");
  const [onlyIssues, setOnlyIssues] = useState(false);
  const [data, setData] = useState<EventsPage | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [open, setOpen] = useState<string | null>(null);
  const paramsKey = JSON.stringify(params);

  useEffect(() => setPage(1), [paramsKey, query, onlyIssues, size]);
  useEffect(() => {
    const h = setTimeout(() => setQuery(q.trim()), 300);
    return () => clearTimeout(h);
  }, [q]);

  useEffect(() => {
    if (!sid) return;
    let alive = true;
    setLoading(true);
    api
      .events(sid, { ...params, page, size, q: query, sort, order, only_issues: onlyIssues || undefined })
      .then((d) => alive && (setData(d), setError(null)))
      .catch((e) => alive && setError(e.message))
      .finally(() => alive && setLoading(false));
    return () => {
      alive = false;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [sid, paramsKey, page, size, query, sort, order, onlyIssues]);

  const pages = useMemo(() => (data ? Math.max(1, Math.ceil(data.total / data.size)) : 1), [data]);
  const columns = useMemo(() => {
    const cols = [...COLUMNS];
    for (const o of OPTIONAL) {
      if (data?.rows.some((r) => r[o.key])) cols.splice(cols.findIndex((c) => c.key === o.after) + 1, 0, o);
    }
    return cols;
  }, [data]);

  const toggleSort = (key: string) => {
    if (key === "command_line") return;
    if (sort === key) setOrder(order === "asc" ? "desc" : "asc");
    else {
      setSort(key);
      setOrder("asc");
    }
  };

  return (
    <div className="space-y-2">
      {showToolbar && (
        <div className="flex flex-wrap items-center gap-2">
          <div className="relative min-w-[200px] flex-1">
            <Search size={14} className="pointer-events-none absolute left-2.5 top-2.5 text-slate-400" />
            <input className="input pl-8" placeholder={t.search} value={q} onChange={(e) => setQ(e.target.value)} aria-label={t.search} />
          </div>
          <label className="flex items-center gap-1.5 text-xs text-slate-600 dark:text-slate-300">
            <input type="checkbox" checked={onlyIssues} onChange={(e) => setOnlyIssues(e.target.checked)} />
            {t.onlyIssues}
          </label>
          {loading && <Spinner />}
        </div>
      )}
      <ErrorBox error={error} />
      <div
        tabIndex={0}
        role="region"
        aria-label={label ?? t.eventsTableAria}
        className={cls("overflow-auto rounded-lg border border-slate-200 focus-visible:outline-2 focus-visible:outline-sky-500 dark:border-slate-800", compact ? "max-h-[420px]" : "max-h-[600px]")}
      >
        <table className="w-full min-w-[900px] border-collapse">
          <thead>
            <tr>
              {columns.map((c) => (
                <th
                  key={c.key}
                  scope="col"
                  className={cls("th", c.width)}
                  aria-sort={sort === (c.key === "ts_iso" ? "ts" : c.key) ? (order === "asc" ? "ascending" : "descending") : undefined}
                >
                  {c.key === "command_line" ? (
                    t.evCols[c.key]
                  ) : (
                    <button className="inline-flex items-center gap-1 uppercase" onClick={() => toggleSort(c.key)} title={fmt(t.sortBy, { c: t.evCols[c.key] })}>
                      {t.evCols[c.key]}
                      {sort === (c.key === "ts_iso" ? "ts" : c.key) && (order === "asc" ? <ArrowUp size={12} aria-hidden="true" /> : <ArrowDown size={12} aria-hidden="true" />)}
                    </button>
                  )}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {data?.rows.map((r, i) => (
              <Fragment key={r.row_id}>
                <tr
                  className={cls(
                    "cursor-pointer hover:bg-sky-50 dark:hover:bg-slate-800/60",
                    r.issues.length > 0 && "bg-amber-50/70 dark:bg-amber-900/10",
                    (r.finding_ids?.length ?? 0) > 0 && "border-l-2 border-l-red-500",
                  )}
                  onClick={() => setOpen(open === r.row_id ? null : r.row_id)}
                >
                  <td className="td mono whitespace-nowrap">
                    {/* la fila se expande con el mouse o, desde el teclado, con este botón */}
                    <button
                      className="text-sky-700 underline-offset-2 hover:underline dark:text-sky-300"
                      aria-expanded={open === r.row_id}
                      aria-controls={`raw-${i}`}
                      aria-label={fmt(open === r.row_id ? t.rowHide : t.rowShow, { id: r.row_id })}
                      onClick={(e) => {
                        e.stopPropagation();
                        setOpen(open === r.row_id ? null : r.row_id);
                      }}
                    >
                      {r.row_id}
                    </button>
                  </td>
                  {columns.some((c) => c.key === "log_id") && <td className="td mono whitespace-nowrap">{(r.log_id as string) ?? "—"}</td>}
                  <td className="td mono whitespace-nowrap">{r.ts_iso ? fmtTs(r.ts_iso) : <Chip tone="red">{t.invalidDate}</Chip>}</td>
                  {columns.some((c) => c.key === "log_source") && <td className="td">{(r.log_source as string) ?? "—"}</td>}
                  <td className="td">{r.event_id ?? r.sem ?? "—"}</td>
                  <td className="td">{r.user ?? "—"}</td>
                  <td className="td">{r.host ?? "—"}</td>
                  <td className="td mono">{r.src_ip ?? "—"}</td>
                  <td className="td">{r.logon_type ?? ""}</td>
                  <td className="td">{r.outcome ?? ""}</td>
                  <td className="td mono max-w-[480px]">
                    <div className="line-clamp-2 break-all">{detail(r, t.groupPrefix)}</div>
                    <div className="mt-0.5 flex flex-wrap gap-1">
                      {r.finding_ids?.map((f) => (
                        <Chip key={f} tone="red">
                          {f}
                        </Chip>
                      ))}
                      {r.issues.map((i) => (
                        <Chip key={i} tone="amber">
                          {i}
                        </Chip>
                      ))}
                    </div>
                  </td>
                </tr>
                {open === r.row_id && (
                  <tr id={`raw-${i}`} className="bg-slate-50 dark:bg-slate-900/80">
                    <td colSpan={columns.length} className="td">
                      <div className="mb-1 text-xs font-semibold text-slate-500">{t.rawRow} · {r.row_id}</div>
                      <dl className="grid grid-cols-1 gap-x-6 gap-y-0.5 sm:grid-cols-2 lg:grid-cols-3">
                        {Object.entries(r.raw).map(([k, v]) => (
                          <div key={k} className="flex gap-2 overflow-hidden">
                            <dt className="shrink-0 text-xs text-slate-500">{k}:</dt>
                            <dd className="mono break-all">{v ?? "—"}</dd>
                          </div>
                        ))}
                      </dl>
                    </td>
                  </tr>
                )}
              </Fragment>
            ))}
            {data && data.rows.length === 0 && (
              <tr>
                <td colSpan={columns.length} className="td py-6 text-center text-slate-500">
                  {t.noRows}
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
      {data && (
        <div className="flex flex-wrap items-center justify-between gap-2 text-xs text-slate-600 dark:text-slate-400">
          <div>
            {data.total.toLocaleString()} {t.events} · {t.rowsPerPage}{" "}
            <select aria-label={t.rowsPerPage} className="rounded border border-slate-300 bg-transparent px-1 dark:border-slate-700" value={size} onChange={(e) => setSize(Number(e.target.value))}>
              {[25, 50, 100, 250].map((n) => (
                <option key={n} value={n}>
                  {n}
                </option>
              ))}
            </select>
          </div>
          <div className="flex items-center gap-1">
            <button className="btn-ghost px-2 py-1" disabled={page <= 1} onClick={() => setPage(page - 1)} aria-label="Anterior">
              <ChevronLeft size={14} />
            </button>
            {page} {t.of} {pages}
            <button className="btn-ghost px-2 py-1" disabled={page >= pages} onClick={() => setPage(page + 1)} aria-label="Siguiente">
              <ChevronRight size={14} />
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
