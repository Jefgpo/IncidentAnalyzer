import { ArrowRight, FilterX, LayoutDashboard } from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import { Area, AreaChart, Bar, BarChart, CartesianGrid, Cell, LabelList, Legend, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { ChartOrTable, Heatmap, LateralGraph, tickHour } from "../components/charts";
import EventsTable from "../components/EventsTable";
import { Card, Chip, Empty, ErrorBox, PageHeader, SeverityBadge, Spinner, Stat } from "../components/ui";
import { api } from "../lib/api";
import { SERIES, SEVERITY_COLOR, SEVERITY_EN, SEVERITY_ORDER, cls, fmtHour } from "../lib/format";
import { fmt, useT } from "../lib/i18n";
import { useStore } from "../lib/store";
import type { Dashboard, Severity } from "../lib/types";

function MultiSelect({ label, options, value, onChange }: { label: string; options: { value: string; label: string }[]; value: string[]; onChange: (v: string[]) => void }) {
  return (
    <div className="min-w-[150px]">
      <label className="label">{label}</label>
      <select
        className="input py-1.5"
        value={value[0] ?? ""}
        onChange={(e) => onChange(e.target.value ? [e.target.value] : [])}
        aria-label={label}
      >
        <option value="">—</option>
        {options.map((o) => (
          <option key={o.value} value={o.value}>
            {o.label}
          </option>
        ))}
      </select>
    </div>
  );
}

export default function DashboardPage() {
  const t = useT();
  const { upload, analysis, filters, setFilters, resetFilters, openDrawer, theme, lang, setStep } = useStore();
  const [data, setData] = useState<Dashboard | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [onlyEvidence, setOnlyEvidence] = useState(false);
  const params = useMemo(
    () => ({
      severity: filters.severity,
      category: filters.category,
      host: filters.host,
      user: filters.user,
      src_ip: filters.src_ip,
      date_from: filters.date_from,
      date_to: filters.date_to,
    }),
    [filters],
  );
  const key = JSON.stringify(params);

  useEffect(() => {
    if (!upload) return;
    let alive = true;
    setLoading(true);
    api
      .dashboard(upload.session_id, params)
      .then((d) => alive && (setData(d), setError(null)))
      .catch((e) => alive && setError(e.message))
      .finally(() => alive && setLoading(false));
    return () => {
      alive = false;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [upload, key, lang]);

  if (!data) return error ? <ErrorBox error={error} /> : <Spinner label={t.loadingDashboard} />;

  const series = SERIES[theme];
  const axis = theme === "dark" ? "#94a3b8" : "#64748b";
  const grid = theme === "dark" ? "#1e293b" : "#e2e8f0";
  const sevLabel = (s: Severity) => (lang === "en" ? SEVERITY_EN[s] : s);
  const active = [...filters.severity, ...filters.category, ...filters.host, ...filters.user, ...filters.src_ip, filters.date_from, filters.date_to].filter(Boolean);
  const cats = analysis?.categories ?? [];
  const k = data.kpis;
  const sevData = data.by_severity.map((d) => ({ ...d, label: sevLabel(d.severity) }));
  const catData = (data.by_category as unknown as Record<string, number | string>[]).map((c) => ({ ...c, name: lang === "en" ? c.label_en : c.label }));

  return (
    <div className="space-y-4">
      <PageHeader
        icon={<LayoutDashboard size={20} />}
        title="Dashboard"
        description={t.clickHint}
        actions={
          <>
            {loading && <Spinner />}
            <button className="btn-primary" onClick={() => setStep("report")}>
              {t.goReport} <ArrowRight size={15} aria-hidden="true" />
            </button>
          </>
        }
      />

      {/* filtros globales: afectan a todos los widgets */}
      <div className="card flex flex-wrap items-end gap-3 px-4 py-3">
        <MultiSelect label={t.severity} value={filters.severity} onChange={(v) => setFilters({ severity: v })} options={SEVERITY_ORDER.map((s) => ({ value: s, label: sevLabel(s) }))} />
        <MultiSelect label={t.category} value={filters.category} onChange={(v) => setFilters({ category: v })} options={cats.map((c) => ({ value: c.category, label: lang === "en" ? c.label_en : c.label }))} />
        <MultiSelect label={t.host} value={filters.host} onChange={(v) => setFilters({ host: v })} options={data.options.hosts.map((h) => ({ value: h, label: h }))} />
        <MultiSelect label={t.user} value={filters.user} onChange={(v) => setFilters({ user: v })} options={data.options.users.map((h) => ({ value: h, label: h }))} />
        <div>
          <label className="label" htmlFor="df">{t.from}</label>
          <input id="df" type="date" className="input py-1.5" value={filters.date_from} min={data.date_range.min?.slice(0, 10)} max={data.date_range.max?.slice(0, 10)} onChange={(e) => setFilters({ date_from: e.target.value })} />
        </div>
        <div>
          <label className="label" htmlFor="dt">{t.to}</label>
          <input id="dt" type="date" className="input py-1.5" value={filters.date_to} min={data.date_range.min?.slice(0, 10)} max={data.date_range.max?.slice(0, 10)} onChange={(e) => setFilters({ date_to: e.target.value })} />
        </div>
        {filters.src_ip.length > 0 && <Chip tone="sky">IP: {filters.src_ip.join(", ")}</Chip>}
        <button className="btn-ghost" onClick={resetFilters} disabled={!active.length}>
          <FilterX size={15} /> {t.clear}
        </button>
      </div>
      <ErrorBox error={error} />

      <div className="grid grid-cols-2 gap-3 md:grid-cols-3 xl:grid-cols-6">
        <Stat label={t.kpiEvents} value={k.total_events.toLocaleString()} hint={fmt(t.kpiEventsHint, { rows: k.total_rows.toLocaleString(), invalid: k.invalid_rows })} />
        <Stat label={t.kpiFindings} value={k.findings} hint={fmt(t.kpiFindingsHint, { core: k.findings_core, anomalies: k.anomalies })} />
        <Stat label={t.kpiIncidents} value={k.incidents} accent={k.incidents ? SEVERITY_COLOR["Crítico"] : undefined} />
        <Stat label={t.kpiHosts} value={k.affected_hosts.length} hint={k.affected_hosts.join(", ")} />
        <Stat label={t.kpiUsers} value={k.affected_users.length} hint={k.affected_users.join(", ")} />
        <Stat label={t.kpiIps} value={k.affected_ips.length} hint={k.affected_ips.join(", ")} />
      </div>

      {data.incidents.length > 0 && (
        <div className="flex flex-wrap gap-2">
          {data.incidents.map((i) => (
            <button key={i.id} className="card flex items-center gap-2 px-3 py-2 text-left text-sm hover:ring-2 hover:ring-sky-400" onClick={() => openDrawer(`${i.id} · ${i.title}`, { incident: i.id, size: 100 })}>
              <span className="mono font-bold">{i.id}</span>
              <SeverityBadge severity={i.severity} score={i.score} />
              <span className="max-w-[420px] truncate">{i.title}</span>
            </button>
          ))}
        </div>
      )}

      <div className="grid gap-4 lg:grid-cols-2">
        <Card title={t.bySeverity}>
          <ChartOrTable caption={t.bySeverity} columns={[t.severity, t.colCount]} rows={sevData.map((d) => [d.label, d.count])}>
          <ResponsiveContainer width="100%" height={230}>
            <BarChart accessibilityLayer data={sevData} margin={{ top: 18, right: 8, left: -18, bottom: 0 }} barCategoryGap="30%">
              <CartesianGrid vertical={false} stroke={grid} />
              <XAxis dataKey="label" tick={{ fill: axis, fontSize: 12 }} axisLine={false} tickLine={false} />
              <YAxis allowDecimals={false} tick={{ fill: axis, fontSize: 11 }} axisLine={false} tickLine={false} />
              <Tooltip cursor={{ fill: grid, opacity: 0.4 }} />
              <Bar dataKey="count" name={t.findingsSeries} radius={[4, 4, 0, 0]} className="cursor-pointer" onClick={(d) => setFilters({ severity: [(d as unknown as { severity: string }).severity] })}>
                {sevData.map((d) => (
                  <Cell key={d.severity} fill={SEVERITY_COLOR[d.severity]} />
                ))}
                <LabelList dataKey="count" position="top" fill={axis} fontSize={12} />
              </Bar>
            </BarChart>
          </ResponsiveContainer>
          </ChartOrTable>
        </Card>
        <Card title={t.byCategory} subtitle={t.stackedBySeverity}>
          <ChartOrTable
            caption={t.byCategory}
            columns={[t.category, ...SEVERITY_ORDER.map(sevLabel)]}
            rows={catData.map((c) => [String(c.name), ...SEVERITY_ORDER.map((s) => Number((c as Record<string, unknown>)[s] ?? 0))])}
          >
          <ResponsiveContainer width="100%" height={290}>
            <BarChart accessibilityLayer data={catData} layout="vertical" margin={{ top: 0, right: 16, left: 40, bottom: 0 }} barCategoryGap="25%">
              <CartesianGrid horizontal={false} stroke={grid} />
              <XAxis type="number" allowDecimals={false} tick={{ fill: axis, fontSize: 11 }} axisLine={false} tickLine={false} />
              <YAxis type="category" dataKey="name" width={150} tick={{ fill: axis, fontSize: 11 }} axisLine={false} tickLine={false} />
              <Tooltip cursor={{ fill: grid, opacity: 0.4 }} />
              <Legend wrapperStyle={{ fontSize: 11 }} />
              {SEVERITY_ORDER.map((s, i) => (
                <Bar
                  key={s}
                  dataKey={s}
                  name={sevLabel(s)}
                  stackId="sev"
                  fill={SEVERITY_COLOR[s]}
                  stroke={theme === "dark" ? "#0f172a" : "#ffffff"}
                  strokeWidth={1}
                  radius={i === SEVERITY_ORDER.length - 1 ? [0, 4, 4, 0] : 0}
                  className="cursor-pointer"
                  onClick={(d) => setFilters({ category: [(d as unknown as { category: string }).category] })}
                />
              ))}
            </BarChart>
          </ResponsiveContainer>
          </ChartOrTable>
        </Card>
      </div>

      <Card title={t.eventTimeline} subtitle={t.timelineHint}>
        <ChartOrTable
          caption={t.eventTimeline}
          columns={[t.colHour, t.colEvents, t.colEvidence]}
          rows={data.timeline.filter((x) => x.events).map((x) => [fmtHour(x.ts), x.events, x.evidence])}
        >
        <ResponsiveContainer width="100%" height={250}>
          <AreaChart
            accessibilityLayer
            data={data.timeline}
            margin={{ top: 8, right: 8, left: -18, bottom: 0 }}
            onClick={(e) => {
              const ts = (e as { activeLabel?: string } | null)?.activeLabel;
              if (!ts) return;
              const endIso = `${ts.slice(0, 14)}59:59${ts.slice(19)}`; // misma hora, mismo offset
              openDrawer(fmt(t.drawerHour, { h: fmtHour(ts) }), { ...params, date_from: ts, date_to: endIso, size: 100 });
            }}
          >
            <CartesianGrid vertical={false} stroke={grid} />
            <XAxis dataKey="ts" tickFormatter={tickHour} minTickGap={40} tick={{ fill: axis, fontSize: 11 }} axisLine={false} tickLine={false} />
            <YAxis allowDecimals={false} tick={{ fill: axis, fontSize: 11 }} axisLine={false} tickLine={false} />
            <Tooltip labelFormatter={(v) => fmtHour(String(v))} />
            <Legend wrapperStyle={{ fontSize: 11 }} />
            <Area type="monotone" dataKey="events" name={t.colEvents} stroke={series[0]} fill={series[0]} fillOpacity={0.15} strokeWidth={2} dot={false} activeDot={{ r: 4 }} />
            <Area type="monotone" dataKey="evidence" name={t.evidenceSeries} stroke={series[1]} fill={series[1]} fillOpacity={0.3} strokeWidth={2} dot={false} activeDot={{ r: 4 }} />
          </AreaChart>
        </ResponsiveContainer>
        </ChartOrTable>
        <div className="mt-1 flex flex-wrap gap-1">
          {data.timeline.filter((x) => x.spike).map((x) => (
            <Chip key={x.ts} tone="amber">{fmt(t.spike, { h: fmtHour(x.ts) })}</Chip>
          ))}
        </div>
      </Card>

      <div className="grid gap-4 lg:grid-cols-3">
        {(
          [
            [t.topIps, data.top_ips, "src_ip"],
            [t.topUsers, data.top_users, "user"],
            [t.topHosts, data.top_hosts, "host"],
          ] as const
        ).map(([title, rows, field]) => (
          <Card key={field} title={title}>
            {rows.length === 0 ? (
              <Empty>—</Empty>
            ) : (
              <ChartOrTable caption={title} columns={[t.colValue, t.colEvents, t.colEvidence]} rows={rows.map((r) => [r.value, r.events, r.evidence])}>
              <ResponsiveContainer width="100%" height={Math.max(160, rows.length * 26 + 40)}>
                <BarChart accessibilityLayer data={[...rows]} layout="vertical" margin={{ top: 0, right: 24, left: 10, bottom: 0 }} barGap={2}>
                  <XAxis type="number" hide />
                  <YAxis type="category" dataKey="value" width={110} tick={{ fill: axis, fontSize: 11 }} axisLine={false} tickLine={false} />
                  <Tooltip cursor={{ fill: grid, opacity: 0.4 }} />
                  <Legend wrapperStyle={{ fontSize: 11 }} />
                  <Bar dataKey="events" name={t.colEvents} fill={series[0]} radius={[0, 4, 4, 0]} className="cursor-pointer" onClick={(d) => setFilters({ [field]: [(d as unknown as { value: string }).value] })} />
                  <Bar dataKey="evidence" name={t.colEvidence} fill={series[1]} radius={[0, 4, 4, 0]} className="cursor-pointer" onClick={(d) => setFilters({ [field]: [(d as unknown as { value: string }).value] })} />
                </BarChart>
              </ResponsiveContainer>
              </ChartOrTable>
            )}
          </Card>
        ))}
      </div>

      <div className="grid gap-4 xl:grid-cols-2">
        <Card title={t.heatmap} subtitle={fmt(t.heatmapHint, { tz: analysis?.config.timezone ?? "" })}>
          <ChartOrTable
            caption={t.heatmap}
            columns={[t.colDay, t.colHour, t.colEvents, t.colEvidence]}
            rows={data.heatmap.filter((c) => c.events).map((c) => [t.weekdays[c.weekday], `${c.hour}:00`, c.events, c.evidence])}
          >
            <Heatmap data={data.heatmap} theme={theme} onCell={(weekday, hour) => openDrawer(fmt(t.drawerCell, { day: t.weekdays[weekday], h: hour }), { ...params, weekday, hour, size: 100 })} />
          </ChartOrTable>
        </Card>
        <Card title={t.lateralGraph} subtitle={t.lateralHint}>
          {data.lateral.edges.length ? (
            <ChartOrTable
              caption={t.lateralGraph}
              columns={[t.colOrigin, t.colTarget, t.colKinds, t.colCount, t.colLateral]}
              rows={data.lateral.edges.map((e) => [e.source, e.target, e.kinds.join(", "), e.count, e.lateral ? t.yes : t.no])}
            >
              <LateralGraph graph={data.lateral} theme={theme} onEdge={(e) => openDrawer(`${e.source} → ${e.target}`, { rows: e.rows.join(","), size: 100 })} />
            </ChartOrTable>
          ) : (
            <Empty>{t.noLateral}</Empty>
          )}
        </Card>
      </div>

      <Card
        title={t.eventsFiltered}
        actions={
          <label className="flex items-center gap-1.5 text-xs">
            <input type="checkbox" checked={onlyEvidence} onChange={(e) => setOnlyEvidence(e.target.checked)} /> {t.onlyEvidenceRows}
          </label>
        }
      >
        <div className={cls(loading && "opacity-60")}>
          <EventsTable compact params={{ ...params, only_evidence: onlyEvidence || undefined }} />
        </div>
      </Card>
    </div>
  );
}
