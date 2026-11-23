import { ArrowRight, BookOpen, Download, Fingerprint, ListChecks, Play, Radar, RefreshCw, Scale, ShieldCheck, Siren } from "lucide-react";
import { type ReactNode, useMemo, useState } from "react";
import FindingCard from "../components/FindingCard";
import IncidentCard from "../components/IncidentCard";
import IntelPanel from "../components/IntelPanel";
import { Card, Chip, Empty, ErrorBox, PageHeader, SeverityBadge, Spinner } from "../components/ui";
import { api, downloadBlob } from "../lib/api";
import { SEVERITY_COLOR, SEVERITY_ORDER, SEVERITY_TEXT, categoryColor, cls, defang, sevLabel } from "../lib/format";
import { fmt, useT } from "../lib/i18n";
import { useStore } from "../lib/store";

type Tab = "incidents" | "findings" | "rules" | "iocs" | "intel" | "method";

export default function AnalysisPage() {
  const t = useT();
  const { upload, analysis, setAnalysis, setStep, openDrawer, lang, theme, toast } = useStore();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [tab, setTab] = useState<Tab>("incidents");
  const [cat, setCat] = useState("");
  const [sev, setSev] = useState("");

  const run = async () => {
    if (!upload) return;
    setBusy(true);
    setError(null);
    try {
      const a = await api.analyze(upload.session_id);
      setAnalysis(a);
      setTab("incidents");
      toast(fmt(t.analysisDone, { i: a.incidents.length, f: a.findings.length }));
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  };

  const findings = useMemo(
    () => (analysis?.findings ?? []).filter((f) => (!cat || f.category === cat) && (!sev || f.severity === sev)),
    [analysis, cat, sev],
  );

  if (!analysis) {
    return (
      <div className="mx-auto max-w-3xl space-y-6 pt-4">
        <PageHeader
          icon={<ShieldCheck size={20} />}
          title={t.analyzeTitle}
          description={t.analyzeDesc}
        />
        <div className="card flex flex-col items-center gap-5 px-6 py-10 text-center">
          <div className="grid w-full max-w-2xl gap-3 text-left text-xs text-slate-600 sm:grid-cols-3 dark:text-slate-400">
            {t.analyzeCards.map(([t1, t2]) => (
              <div key={t1} className="rounded-lg bg-slate-50 p-3 dark:bg-slate-800/50">
                <div className="mb-1 font-semibold text-slate-800 dark:text-slate-200">{t1}</div>
                {t2}
              </div>
            ))}
          </div>
          <button className="btn-primary px-6 py-3 text-base" onClick={run} disabled={busy}>
            <Play size={18} /> {t.runAnalysis}
          </button>
          {busy && <Spinner label={t.analyzing} />}
          <ErrorBox error={error} />
        </div>
      </div>
    );
  }

  const sevCounts = SEVERITY_ORDER.map((s) => ({ s, n: analysis.findings.filter((f) => f.severity === s).length }));
  const worst = SEVERITY_ORDER.find((s) => analysis.incidents.some((i) => i.severity === s));
  const tabs: [Tab, string, ReactNode][] = [
    ["incidents", `${t.incidents} (${analysis.incidents.length})`, <Siren key="i" size={14} />],
    ["findings", `${t.findings} (${analysis.findings.length})`, <ListChecks key="f" size={14} />],
    ["rules", `${t.rules} (${analysis.rules.length})`, <BookOpen key="r" size={14} />],
    ["iocs", `${t.iocs} (${analysis.iocs.length})`, <Fingerprint key="o" size={14} />],
    ["intel", t.intelTab, <Radar key="t" size={14} />],
    ["method", t.methodology, <Scale key="m" size={14} />],
  ];
  const goFindings = (s: string, c = "") => {
    setSev(s);
    setCat(c);
    setTab("findings");
  };

  return (
    <div className="space-y-5">
      <PageHeader
        icon={<ShieldCheck size={20} />}
        title={t.resultTitle}
        description={fmt(t.resultDesc, { n: analysis.rules.length, s: analysis.elapsed_s, tz: analysis.config.timezone })}
        actions={
          <>
            <button className="btn-secondary" onClick={run} disabled={busy}>
              <RefreshCw size={15} className={cls(busy && "animate-spin")} /> {t.rerun}
            </button>
            <button className="btn-primary" onClick={() => setStep("dashboard")}>
              {t.goDashboard} <ArrowRight size={15} />
            </button>
          </>
        }
      />
      <ErrorBox error={error} />

      {/* veredicto: lo primero que el analista necesita saber */}
      <section className="card overflow-hidden border-l-4" style={{ borderLeftColor: worst ? SEVERITY_COLOR[worst] : "#059669" }} aria-label={t.verdictAria}>
        <div className="grid gap-5 p-5 lg:grid-cols-[1fr_auto]">
          <div className="min-w-0">
            <div className="flex flex-wrap items-center gap-2">
              <span className="text-3xl font-bold tabular-nums">{analysis.incidents.length}</span>
              <span className="text-lg font-semibold">{analysis.incidents.length === 1 ? t.incidentOne : t.incidentMany}</span>
              {worst && <SeverityBadge severity={worst} />}
              <Chip tone="sky">{t.inference}</Chip>
            </div>
            <p className="mt-2 text-sm text-slate-700 dark:text-slate-300">{analysis.conclusion.text}</p>
            <details className="mt-2">
              <summary className="cursor-pointer text-xs font-medium text-sky-700 dark:text-sky-300">
                {fmt(t.seeJustification, { n: analysis.conclusion.justification.length })}
              </summary>
              <ul className="mt-2 list-disc space-y-1 pl-5 text-sm text-slate-600 dark:text-slate-400">
                {analysis.conclusion.justification.map((j, i) => (
                  <li key={i}>{j}</li>
                ))}
              </ul>
            </details>
          </div>
          <div className="grid grid-cols-2 gap-2 sm:grid-cols-4 lg:grid-cols-2">
            {sevCounts.map(({ s, n }) => (
              <button
                key={s}
                onClick={() => goFindings(s)}
                className="rounded-lg border border-slate-200 px-3 py-2 text-left transition hover:border-slate-400 dark:border-slate-700"
                title={fmt(t.seeSeverityFindings, { s: sevLabel(s, lang) })}
              >
                <div className="text-xs font-medium uppercase tracking-wide text-slate-500">{sevLabel(s, lang)}</div>
                <div className={cls("text-xl font-semibold tabular-nums", SEVERITY_TEXT[s])}>
                  {n}
                </div>
              </button>
            ))}
          </div>
        </div>
        <div className="flex flex-wrap gap-2 border-t border-slate-100 px-5 py-3 dark:border-slate-800">
          {analysis.categories.map((c) => (
            <button
              key={c.category}
              onClick={() => goFindings("", c.category)}
              disabled={!c.findings}
              className="inline-flex items-center gap-1.5 rounded-md border border-slate-200 px-2 py-1 text-xs transition enabled:hover:border-slate-400 disabled:opacity-60 dark:border-slate-700"
              title={c.status === "no_evaluable" ? t.categoryNotEvaluable : fmt(t.rulesEvaluable, { a: c.rules_evaluable, b: c.rules_total })}
            >
              <span className="h-2 w-2 rounded-full" style={{ background: categoryColor(c.category, theme) }} />
              {lang === "en" ? c.label_en : c.label}: <b>{c.findings}</b>
              {c.status === "no_evaluable" && <span className="text-amber-700 dark:text-amber-400">{t.notEvaluableShort}</span>}
            </button>
          ))}
        </div>
      </section>

      <div role="tablist" aria-label={t.resultTitle} className="flex flex-wrap gap-1 border-b border-slate-200 dark:border-slate-800">
        {tabs.map(([k, label, icon]) => (
          <button
            key={k}
            role="tab"
            aria-selected={tab === k}
            onClick={() => setTab(k)}
            className={cls(
              "-mb-px inline-flex items-center gap-1.5 border-b-2 px-3 py-2 text-sm transition",
              tab === k ? "border-sky-600 font-semibold text-sky-700 dark:text-sky-300" : "border-transparent text-slate-500 hover:text-slate-800 dark:hover:text-slate-200",
            )}
          >
            {icon}
            {label}
          </button>
        ))}
      </div>

      {tab === "incidents" && (
        <div className="space-y-3">
          {analysis.incidents.length === 0 && <Empty>{t.noIncidents}</Empty>}
          {analysis.incidents.map((inc, i) => (
            <IncidentCard key={inc.id} inc={inc} findings={analysis.findings} defaultOpen={i === 0} />
          ))}
          {analysis.isolated.length > 0 && (
            <Card title={fmt(t.isolatedTitle, { n: analysis.isolated.length })} subtitle={t.isolatedHint}>
              <div className="space-y-2">
                {analysis.findings.filter((f) => analysis.isolated.includes(f.id)).map((f) => (
                  <FindingCard key={f.id} f={f} />
                ))}
              </div>
            </Card>
          )}
        </div>
      )}

      {tab === "findings" && (
        <div className="space-y-3">
          <div className="flex flex-wrap items-center gap-2">
            <span className="text-xs font-medium text-slate-500">{t.severity}:</span>
            {["", ...SEVERITY_ORDER].map((s) => (
              <button
                key={s || "all"}
                onClick={() => setSev(s)}
                aria-pressed={sev === s}
                className={cls(
                  "rounded-full border px-3 py-1 text-xs transition",
                  sev === s ? "border-sky-600 bg-sky-700 text-white" : "border-slate-300 hover:border-slate-500 dark:border-slate-700",
                )}
              >
                {s ? sevLabel(s as (typeof SEVERITY_ORDER)[number], lang) : t.all}
              </button>
            ))}
            <select className="input ml-2 w-auto py-1 text-xs" value={cat} onChange={(e) => setCat(e.target.value)} aria-label={t.category}>
              <option value="">
                {t.category}: {t.all}
              </option>
              {analysis.categories.map((c) => (
                <option key={c.category} value={c.category}>
                  {lang === "en" ? c.label_en : c.label}
                </option>
              ))}
            </select>
            <span className="ml-auto text-xs text-slate-500">{fmt(t.findingsCount, { n: findings.length })}</span>
          </div>
          {findings.length === 0 && <Empty>{t.noFindingsFilter}</Empty>}
          {findings.map((f) => (
            <FindingCard key={f.id} f={f} />
          ))}
        </div>
      )}

      {tab === "rules" && (
        <Card title={t.rules} subtitle={t.rulesHint}>
          <div tabIndex={0} role="region" aria-label={t.rulesTableAria} className="overflow-auto">
            <table className="w-full min-w-[860px] border-collapse">
              <thead>
                <tr>
                  {t.rulesCols.map((h) => (
                    <th key={h} className="th cursor-default">
                      {h}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {analysis.rules.map((r) => (
                  <tr key={r.id}>
                    <td className="td mono">{r.id}</td>
                    <td className="td">
                      <div className="font-medium">{lang === "en" ? r.name_en : r.name}</div>
                      <div className="text-xs text-slate-500">{lang === "en" ? r.description_en : r.description}</div>
                    </td>
                    <td className="td">
                      <div className="flex flex-wrap gap-1">
                        {r.mitre.length ? r.mitre.map((m) => <Chip key={m.id} tone="sky" title={m.name}>{m.id}</Chip>) : <Chip>{t.anomalyChip}</Chip>}
                      </div>
                    </td>
                    <td className="td">
                      <Chip tone={r.status === "con_hallazgos" ? "red" : r.status === "no_evaluable" ? "amber" : "emerald"}>{t.status[r.status]}</Chip>
                      {r.missing.length > 0 && <div className="mt-0.5 text-xs text-amber-700 dark:text-amber-400">{fmt(t.missingFields, { f: r.missing.join(", ") })}</div>}
                    </td>
                    <td className="td tabular-nums">{r.count}</td>
                    <td className="td mono text-xs text-slate-500">{r.requires.join(", ")}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Card>
      )}

      {tab === "iocs" && (
        <Card
          title={t.iocs}
          subtitle={t.iocsHint}
          actions={
            <button className="btn-secondary py-1.5 text-xs" onClick={async () => upload && downloadBlob(await api.iocsCsv(upload.session_id), "iocs.csv")}>
              <Download size={14} /> CSV
            </button>
          }
        >
          <div tabIndex={0} role="region" aria-label={t.iocsTableAria} className="overflow-auto">
            <table className="w-full min-w-[860px] border-collapse">
              <thead>
                <tr>
                  {t.iocCols.map((h) => (
                    <th key={h} className="th cursor-default">
                      {h}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {analysis.iocs.map((i) => (
                  <tr key={i.id}>
                    <td className="td mono">{i.id}</td>
                    <td className="td">
                      <Chip>{i.type}</Chip>
                    </td>
                    <td className="td mono max-w-[420px] break-all">{/^extern/.test(i.context) || i.type !== "ip" ? defang(i.value, i.type) : i.value}</td>
                    <td className="td text-xs">{i.context}</td>
                    <td className="td tabular-nums">{i.count}</td>
                    <td className="td mono text-xs">{i.finding_ids.join(", ")}</td>
                    <td className="td">
                      <button className="text-xs text-sky-700 underline dark:text-sky-300" onClick={() => openDrawer(`${i.id} · ${i.value}`, { rows: i.rows.join(","), size: 100 })}>
                        {fmt(t.viewN, { n: Math.min(i.rows.length, 200) })}
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Card>
      )}

      {tab === "intel" && <IntelPanel />}

      {tab === "method" && (
        <Card title={t.methodology} subtitle={analysis.methodology.formula}>
          <div className="grid gap-4 lg:grid-cols-2">
            <table className="w-full border-collapse text-sm">
              <thead>
                <tr>
                  {t.methodCols.map((h) => (
                    <th key={h} className="th cursor-default">
                      {h}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {analysis.methodology.factors.map((f) => (
                  <tr key={f.factor}>
                    <td className="td font-medium">{f.factor}</td>
                    <td className="td whitespace-nowrap">{f.points}</td>
                    <td className="td text-xs text-slate-500">{f.detail}</td>
                  </tr>
                ))}
              </tbody>
            </table>
            <div className="space-y-3">
              <div className="flex flex-wrap gap-2">
                {analysis.methodology.bands.map((b) => (
                  <span key={b.severity} className="flex items-center gap-2 text-sm">
                    <SeverityBadge severity={b.severity} /> {b.range}
                  </span>
                ))}
              </div>
              <div className="label">{t.baseScore}</div>
              <div className="flex flex-wrap gap-1">
                {Object.entries(analysis.methodology.base).map(([k, v]) => (
                  <Chip key={k}>
                    {k}: {v}
                  </Chip>
                ))}
              </div>
              <p className="text-xs text-slate-500">
                {fmt(t.methodConfig, {
                  tz: analysis.config.timezone,
                  s: analysis.config.business_hours.start,
                  e: analysis.config.business_hours.end,
                  c: analysis.config.allowed_countries.join(", "),
                })}
                {analysis.baseline_end
                  ? fmt(t.baselineUntil, { d: analysis.baseline_end.slice(0, 16).replace("T", " ") })
                  : fmt(t.noBaseline, { h: analysis.span_hours, min: analysis.config.min_baseline_hours })}
                {t.thresholdsEditable}
              </p>
            </div>
          </div>
        </Card>
      )}
    </div>
  );
}
