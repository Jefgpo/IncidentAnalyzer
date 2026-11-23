import { type RefObject, useEffect } from "react";

const FOCUSABLE =
  'a[href], button:not([disabled]), input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])';

/**
 * Mantiene el foco del teclado dentro de un diálogo o panel modal mientras está abierto,
 * cierra con Escape y, al cerrarse, devuelve el foco al elemento que lo abrió.
 */
export function useFocusTrap(ref: RefObject<HTMLElement | null>, active: boolean, onEscape: () => void, initialSelector?: string) {
  useEffect(() => {
    if (!active || !ref.current) return;
    const root = ref.current;
    const previous = document.activeElement as HTMLElement | null;
    const first = (initialSelector && root.querySelector<HTMLElement>(initialSelector)) || root.querySelector<HTMLElement>(FOCUSABLE);
    (first ?? root).focus();

    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") {
        e.stopPropagation();
        onEscape();
        return;
      }
      if (e.key !== "Tab") return;
      const items = [...root.querySelectorAll<HTMLElement>(FOCUSABLE)].filter((el) => !el.closest("[hidden],[inert],[aria-hidden=\"true\"]"));
      if (!items.length) return;
      const firstEl = items[0];
      const lastEl = items[items.length - 1];
      if (e.shiftKey && document.activeElement === firstEl) {
        e.preventDefault();
        lastEl.focus();
      } else if (!e.shiftKey && document.activeElement === lastEl) {
        e.preventDefault();
        firstEl.focus();
      }
    };
    root.addEventListener("keydown", onKey);
    return () => {
      root.removeEventListener("keydown", onKey);
      previous?.focus?.();
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [active]);
}

/** Activa con Enter o Espacio, como un botón (para elementos SVG interactivos). */
export function onActivate(handler: () => void) {
  return (e: { key: string; preventDefault: () => void }) => {
    if (e.key === "Enter" || e.key === " ") {
      e.preventDefault();
      handler();
    }
  };
}
