import { ChevronDown, ChevronRight, Table2 } from "lucide-react";
import { useState } from "react";
import { fmtTs } from "../lib/format";
import { fmt, useT } from "../lib/i18n";
import { useStore } from "../lib/store";
import type { Finding } from "../lib/types";
import { Chip, SeverityBadge } from "./ui";

export function ScoreFactors({ factors, total }: { factors: { factor: string; points: number }[]; total: number }) {
  const t = useT();
  return (
    <table className="w-full text-xs">
      <tbody>
        {factors.map((f, i) => (
          <tr key={i} className="border-b border-slate-100 dark:border-slate-800">
            <td className="py-1 pr-2">{f.factor}</td>
            <td className="py-1 text-right tabular-nums font-medium">{f.points >= 0 ? `+${f.points}` : f.points}</td>
          </tr>
        ))}
        <tr>
          <td className="py-1 pr-2 font-semibold">{t.totalCap}</td>
          <td className="py-1 text-right font-bold tabular-nums">{total}</td>
        </tr>
      </tbody>
    </table>
  );
}

export default function FindingCard({ f, defaultOpen = false }: { f: Finding; defaultOpen?: boolean }) {
  const t = useT();
  const [open, setOpen] = useState(defaultOpen);
  const openDrawer = useStore((s) => s.openDrawer);
  const entities = Object.entries(f.entities).flatMap(([k, vs]) => vs.map((v) => `${k}: ${v}`));
  return (
    <article className="rounded-lg border border-slate-200 dark:border-slate-800">
      <button className="flex w-full items-start gap-2 px-3 py-2.5 text-left" onClick={() => setOpen(!open)} aria-expanded={open}>
        {open ? <ChevronDown size={16} className="mt-0.5 shrink-0" /> : <ChevronRight size={16} className="mt-0.5 shrink-0" />}
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-2">
            <span className="mono text-xs text-slate-500">{f.id}</span>
            <SeverityBadge severity={f.severity} score={f.score} />
            <Chip tone="slate">{f.rule_id}</Chip>
            {f.mitre.map((m) => (
              <Chip key={m.id} tone="sky" title={m.name}>
                {m.id}
              </Chip>
            ))}
            {f.is_anomaly && <Chip tone="amber">{t.anomaly}</Chip>}
            {f.incident_id && <Chip tone="red">{f.incident_id}</Chip>}
            {f.auth_success === false && <Chip tone="slate">{t.attemptOnly}</Chip>}
            {f.auth_success === true && <Chip tone="red">{t.success}</Chip>}
          </div>
          <div className="mt-1 text-sm font-medium">{f.title}</div>
          <div className="text-xs text-slate-500">
            {fmtTs(f.start)} → {fmtTs(f.end)} · {fmt(t.findingMeta, { n: f.rows.length, c: (t.confidenceLevels as Record<string, string>)[f.confidence] ?? f.confidence })}
          </div>
        </div>
      </button>
      {open && (
        <div className="space-y-3 border-t border-slate-100 px-3 py-3 text-sm dark:border-slate-800">
          <div>
            <Chip tone="emerald">{t.observed}</Chip>
            <p className="mt-1">{f.summary}</p>
          </div>
          {f.details.length > 0 && (
            <div>
              <div className="label">{t.details}</div>
              <ul className="space-y-1">
                {f.details.map((d, i) => (
                  <li key={i} className="mono break-all rounded bg-slate-50 px-2 py-1 dark:bg-slate-800/60">
                    {d}
                  </li>
                ))}
              </ul>
            </div>
          )}
          <div className="grid gap-3 md:grid-cols-2">
            <div>
              <div className="label">{t.entities}</div>
              <div className="flex flex-wrap gap-1">
                {entities.map((e) => (
                  <Chip key={e}>{e}</Chip>
                ))}
                {Object.entries(f.related).map(([k, vs]) => (
                  <Chip key={k} tone="slate" title={vs.join(", ")}>
                    {k} ({t.relatedShort}): {vs.slice(0, 4).join(", ")}
                    {vs.length > 4 ? ` +${vs.length - 4}` : ""}
                  </Chip>
                ))}
              </div>
              {f.fp_notes.length > 0 && (
                <>
                  <div className="label mt-3">{t.fpNotes}</div>
                  <ul className="list-disc space-y-0.5 pl-4 text-xs text-slate-600 dark:text-slate-400">
                    {f.fp_notes.map((n, i) => (
                      <li key={i}>{n}</li>
                    ))}
                  </ul>
                </>
              )}
            </div>
            <div>
              <div className="label">{t.scoreFactors}</div>
              <ScoreFactors factors={f.score_factors} total={f.score} />
            </div>
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <button className="btn-secondary py-1.5 text-xs" onClick={() => openDrawer(`${f.id} · ${f.title}`, { finding: f.id, size: 100 })}>
              <Table2 size={14} /> {t.viewEvidence} ({f.rows.length})
            </button>
            <span className="mono truncate text-xs text-slate-500">
              {f.rows.slice(0, 12).join(", ")}
              {f.rows.length > 12 ? " …" : ""}
            </span>
          </div>
        </div>
      )}
    </article>
  );
}
