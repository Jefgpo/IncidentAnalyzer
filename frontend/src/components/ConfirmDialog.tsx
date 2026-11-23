import { AlertTriangle } from "lucide-react";
import { useRef } from "react";
import { useFocusTrap } from "../lib/a11y";
import { cls } from "../lib/format";
import { useT } from "../lib/i18n";
import { useStore } from "../lib/store";

/** Diálogo de confirmación accesible (reemplaza a window.confirm): foco atrapado, Escape cancela. */
export default function ConfirmDialog() {
  const t = useT();
  const dialog = useStore((s) => s.dialog);
  const closeDialog = useStore((s) => s.closeDialog);
  const ref = useRef<HTMLDivElement>(null);
  useFocusTrap(ref, !!dialog, () => closeDialog(false), "[data-autofocus]");
  if (!dialog) return null;
  const danger = dialog.tone === "danger";
  return (
    <div className="fixed inset-0 z-[70] flex items-center justify-center bg-slate-950/50 p-4" onMouseDown={() => closeDialog(false)}>
      <div
        ref={ref}
        role="alertdialog"
        aria-modal="true"
        aria-labelledby="confirm-title"
        aria-describedby="confirm-message"
        className="card w-full max-w-md p-5 shadow-2xl"
        onMouseDown={(e) => e.stopPropagation()}
      >
        <div className="flex gap-3">
          <div className={cls("h-fit rounded-full p-2", danger ? "bg-red-100 text-red-700 dark:bg-red-950 dark:text-red-300" : "bg-sky-100 text-sky-700 dark:bg-sky-950 dark:text-sky-300")}>
            <AlertTriangle size={18} aria-hidden="true" />
          </div>
          <div>
            <h2 id="confirm-title" className="text-base font-semibold">
              {dialog.title}
            </h2>
            <p id="confirm-message" className="mt-1 text-sm text-slate-600 dark:text-slate-300">
              {dialog.message}
            </p>
          </div>
        </div>
        <div className="mt-5 flex justify-end gap-2">
          {/* el foco inicial va a «Cancelar»: confirmar una acción destructiva siempre exige un paso deliberado */}
          <button className="btn-secondary" data-autofocus onClick={() => closeDialog(false)}>
            {t.cancel}
          </button>
          <button className={danger ? "btn-danger" : "btn-primary"} onClick={() => closeDialog(true)}>
            {dialog.confirmLabel}
          </button>
        </div>
      </div>
    </div>
  );
}
