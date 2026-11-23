import { ChevronDown, ChevronRight, Table2 } from "lucide-react";
import { useState } from "react";
import { SEVERITY_COLOR, cls, fmtTs } from "../lib/format";
import { fmt, useT } from "../lib/i18n";
import { useStore } from "../lib/store";
import type { Finding, Incident } from "../lib/types";
import FindingCard, { ScoreFactors } from "./FindingCard";
import { Chip, SeverityBadge } from "./ui";

export default function IncidentCard({ inc, findings, defaultOpen = true }: { inc: Incident; findings: Finding[]; defaultOpen?: boolean }) {
  const t = useT();
  const lang = useStore((s) => s.lang);
  const openDrawer = useStore((s) => s.openDrawer);
  const [tab, setTab] = useState<"timeline" | "findings" | "links">("timeline");
  const [open, setOpen] = useState(defaultOpen);
  const byId = Object.fromEntries(findings.map((f) => [f.id, f]));
  return (
    <section className="card overflow-hidden border-l-4" style={{ borderLeftColor: SEVERITY_COLOR[inc.severity] }}>
      <header className={cls("px-4 py-3", open && "border-b border-slate-100 dark:border-slate-800")}>
        <button className="flex w-full items-start gap-3 text-left" onClick={() => setOpen(!open)} aria-expanded={open}>
          <ChevronDown size={18} className={cls("mt-1 shrink-0 text-slate-400 transition", !open && "-rotate-90")} />
          <div className="min-w-0 flex-1">
            <div className="flex flex-wrap items-center gap-2">
              <span className="mono text-sm font-bold">{inc.id}</span>
              <SeverityBadge severity={inc.severity} score={inc.score} />
              <span className="text-xs text-slate-500">
                {fmtTs(inc.start, false)} → {fmtTs(inc.end, false).slice(11)}
              </span>
              <span className="text-xs text-slate-500">
                {fmt(t.incidentMeta, { f: inc.finding_ids.length, p: inc.phases.length })}
              </span>
            </div>
            <h2 className="mt-1 text-base font-semibold">{inc.title}</h2>
            {!open && (
              <div className="mt-1 truncate text-xs text-slate-500">{inc.phases.map((p) => (lang === "en" ? p.label_en : p.label)).join(" → ")}</div>
            )}
          </div>
        </button>
        {open && (
        <>
        <div className="mt-2 flex items-center gap-2 pl-8">
          <Chip tone="sky">{t.inference}</Chip>
          <p className="text-sm text-slate-600 dark:text-slate-300">{inc.summary}</p>
        </div>
        <div className="mt-3 pl-8">
          <div className="label">{t.killChain}</div>
          <ol className="flex flex-wrap items-center gap-1">
            {inc.phases.map((p, i) => (
              <li key={p.tactic} className="flex items-center gap-1">
                <span className="rounded-md bg-slate-800 px-2 py-1 text-xs font-medium text-white dark:bg-slate-700" title={`${p.mitre_tactic} · ${p.finding_ids.join(", ")}`}>
                  {lang === "en" ? p.label_en : p.label} <span className="opacity-70">({fmtTs(p.first_seen, false).slice(0, 16)})</span>
                </span>
                {i < inc.phases.length - 1 && <ChevronRight size={13} className="text-slate-400" />}
              </li>
            ))}
          </ol>
        </div>
        </>
        )}
      </header>
      {open && (
      <>
      <div className="px-4 pt-3">
        <div className="flex flex-wrap items-center gap-1 border-b border-slate-100 dark:border-slate-800">
          {(["timeline", "findings", "links"] as const).map((k) => (
            <button
              key={k}
              onClick={() => setTab(k)}
              className={`-mb-px border-b-2 px-3 py-1.5 text-sm ${tab === k ? "border-sky-600 font-medium text-sky-700 dark:text-sky-300" : "border-transparent text-slate-500"}`}
            >
              {k === "timeline" ? `${t.timeline} (${inc.timeline.length})` : k === "findings" ? `${t.findings} (${inc.finding_ids.length})` : `${t.links} (${inc.links.length})`}
            </button>
          ))}
          <button className="btn-ghost ml-auto py-1 text-xs" onClick={() => openDrawer(`${inc.id} · ${inc.title}`, { incident: inc.id, size: 100 })}>
            <Table2 size={14} /> {t.viewEvidence}
          </button>
        </div>
      </div>
      <div className="p-4">
        {tab === "timeline" && (
          <div tabIndex={0} role="region" aria-label={t.incidentTimeline} className="max-h-[480px] overflow-auto">
          <ol className="relative space-y-0 border-l-2 border-slate-200 pl-4 dark:border-slate-700">
            {inc.timeline.map((e) => (
              <li key={e.row_id} className="relative pb-2">
                <span className="absolute -left-[22px] top-1.5 h-2.5 w-2.5 rounded-full bg-sky-700 ring-2 ring-white dark:ring-slate-900" />
                <div className="flex flex-wrap items-baseline gap-2 text-xs">
                  <span className="mono font-medium">{fmtTs(e.ts)}</span>
                  <button className="mono text-sky-700 underline-offset-2 hover:underline dark:text-sky-300" onClick={() => openDrawer(e.row_id, { rows: e.row_id })}>
                    {e.row_id}
                  </button>
                  {e.rule_ids.map((r) => (
                    <Chip key={r}>{r}</Chip>
                  ))}
                </div>
                <div className="mono break-all text-slate-600 dark:text-slate-300">{e.description}</div>
              </li>
            ))}
          </ol>
          </div>
        )}
        {tab === "findings" && (
          <div className="space-y-2">
            {inc.finding_ids.map((id) => byId[id] && <FindingCard key={id} f={byId[id]} />)}
            {inc.anomaly_ids.length > 0 && (
              <>
                <div className="label mt-3">{t.relatedAnomalies}</div>
                {inc.anomaly_ids.map((id) => byId[id] && <FindingCard key={id} f={byId[id]} />)}
              </>
            )}
            <div className="mt-3 max-w-md">
              <div className="label">{t.scoreFactors} ({inc.id})</div>
              <ScoreFactors factors={inc.score_factors} total={inc.score} />
            </div>
          </div>
        )}
        {tab === "links" && (
          <div tabIndex={0} role="region" aria-label={t.findingLinks} className="max-h-[420px] overflow-auto">
          <ul className="space-y-1 text-xs">
            {inc.links.map((l, i) => (
              <li key={i} className="rounded bg-slate-50 px-2 py-1 dark:bg-slate-800/60">
                <span className="mono font-medium">
                  {l.a} ↔ {l.b}
                </span>{" "}
                {fmt(t.linkShares, { x: l.shared.join(", ") })} <span className="mono">{[...l.rows_a, ...l.rows_b].slice(0, 4).join(", ")}</span>
              </li>
            ))}
          </ul>
          </div>
        )}
      </div>
      </>
      )}
    </section>
  );
}
