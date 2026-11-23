import { X } from "lucide-react";
import { useRef } from "react";
import { useFocusTrap } from "../lib/a11y";
import { useT } from "../lib/i18n";
import { useStore } from "../lib/store";
import EventsTable from "./EventsTable";

/** Panel lateral con los eventos crudos de un drill-down (click en gráfico, hallazgo, IoC…). */
export default function EventsDrawer() {
  const t = useT();
  const drawer = useStore((s) => s.drawer);
  const close = useStore((s) => s.closeDrawer);
  const ref = useRef<HTMLDivElement>(null);
  // foco atrapado mientras está abierto; Escape cierra y el foco vuelve a donde estaba
  useFocusTrap(ref, !!drawer, close, "[data-autofocus]");
  if (!drawer) return null;
  return (
    <div className="fixed inset-0 z-50 flex justify-end bg-slate-950/40 backdrop-blur-[1px]" onClick={close}>
      <div
        ref={ref}
        role="dialog"
        aria-modal="true"
        aria-labelledby="drawer-title"
        className="flex h-full w-full max-w-6xl flex-col bg-white shadow-2xl dark:bg-slate-900"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="flex items-center justify-between border-b border-slate-200 px-4 py-3 dark:border-slate-800">
          <h2 id="drawer-title" className="truncate text-sm font-semibold">
            {drawer.title}
          </h2>
          <button className="btn-ghost px-2 py-1" onClick={close} aria-label={t.close} data-autofocus>
            <X size={16} aria-hidden="true" />
          </button>
        </div>
        <div className="flex-1 overflow-auto p-4">
          <EventsTable params={drawer.params} label={drawer.title} />
        </div>
      </div>
    </div>
  );
}
