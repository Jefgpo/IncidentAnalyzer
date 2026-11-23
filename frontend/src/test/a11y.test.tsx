import { act, fireEvent, render, screen } from "@testing-library/react";
import axe from "axe-core";
import { describe, expect, it, vi } from "vitest";
import { ChartOrTable, Heatmap, LateralGraph } from "../components/charts";
import ConfirmDialog from "../components/ConfirmDialog";
import { Callout, Card, ErrorBox, PageHeader, Stat } from "../components/ui";
import { confirmDialog, useStore } from "../lib/store";
import type { Dashboard } from "../lib/types";

/** Corre axe sobre el contenedor. color-contrast no se puede medir en jsdom (no hay layout ni CSS real). */
async function violations(container: Element) {
  const res = await axe.run(container, { rules: { "color-contrast": { enabled: false }, region: { enabled: false } } });
  return res.violations.map((v) => `${v.id}: ${v.nodes.map((n) => n.target.join(" ")).join(", ")}`);
}

const heatmap: Dashboard["heatmap"] = Array.from({ length: 7 * 24 }, (_, i) => ({
  weekday: Math.floor(i / 24),
  label: "",
  hour: i % 24,
  events: i === 26 ? 5 : 0,
  evidence: i === 26 ? 2 : 0,
}));

const lateral = {
  nodes: [
    { id: "WS-017", kind: "host", out: 1 },
    { id: "SRV-SQL01", kind: "host", out: 0 },
  ],
  edges: [{ source: "WS-017", target: "SRV-SQL01", kinds: ["RDP"], count: 2, lateral: true, rows: [3, 4] }],
} as unknown as Dashboard["lateral"];

describe("ConfirmDialog", () => {
  it("es un alertdialog sin violaciones, con foco inicial en Cancelar", async () => {
    const { container } = render(<ConfirmDialog />);
    let result: Promise<boolean> = Promise.resolve(false);
    act(() => {
      result = confirmDialog({ title: "Borrar datos", message: "No se puede deshacer.", confirmLabel: "Borrar", tone: "danger" });
    });
    const dlg = screen.getByRole("alertdialog", { name: "Borrar datos" });
    expect(dlg).toHaveAttribute("aria-describedby", "confirm-message");
    expect(document.activeElement).toBe(screen.getByRole("button", { name: "Cancelar" }));
    expect(await violations(container)).toEqual([]);
    fireEvent.click(screen.getByRole("button", { name: "Borrar" }));
    await expect(result).resolves.toBe(true);
    expect(screen.queryByRole("alertdialog")).toBeNull();
  });

  it("Escape cancela", async () => {
    render(<ConfirmDialog />);
    let result: Promise<boolean> = Promise.resolve(true);
    act(() => {
      result = confirmDialog({ title: "T", message: "M", confirmLabel: "OK" });
    });
    fireEvent.keyDown(screen.getByRole("alertdialog"), { key: "Escape" });
    await expect(result).resolves.toBe(false);
  });

  it("Tab queda atrapado dentro del diálogo", () => {
    render(<ConfirmDialog />);
    act(() => {
      void confirmDialog({ title: "T", message: "M", confirmLabel: "Aceptar" });
    });
    const ok = screen.getByRole("button", { name: "Aceptar" });
    ok.focus();
    fireEvent.keyDown(screen.getByRole("alertdialog"), { key: "Tab" });
    expect(document.activeElement).toBe(screen.getByRole("button", { name: "Cancelar" }));
  });
});

describe("Heatmap", () => {
  it("las celdas con eventos son botones con nombre y responden a Enter", async () => {
    const onCell = vi.fn();
    const { container } = render(<Heatmap data={heatmap} theme="light" onCell={onCell} />);
    const cell = screen.getByRole("button", { name: /Mar 2:00–2:59: 5 eventos, 2 en evidencia/ });
    expect(cell).toHaveAttribute("tabindex", "0");
    fireEvent.keyDown(cell, { key: "Enter" });
    expect(onCell).toHaveBeenCalledWith(1, 2);
    expect(await violations(container)).toEqual([]);
  });
});

describe("LateralGraph", () => {
  it("cada arista es un botón accesible por teclado", async () => {
    const onEdge = vi.fn();
    const { container } = render(<LateralGraph graph={lateral} theme="dark" onEdge={onEdge} />);
    const edge = screen.getByRole("button", { name: "WS-017 → SRV-SQL01: RDP, 2 conexiones" });
    fireEvent.keyDown(edge, { key: " " });
    expect(onEdge).toHaveBeenCalledOnce();
    expect(await violations(container)).toEqual([]);
  });
});

describe("ChartOrTable", () => {
  it("ofrece la tabla equivalente al gráfico", async () => {
    const { container } = render(
      <ChartOrTable caption="Hallazgos por criticidad" columns={["Criticidad", "Cantidad"]} rows={[["Alto", 3]]}>
        <div>gráfico</div>
      </ChartOrTable>,
    );
    const toggle = screen.getByRole("button", { name: /Ver como tabla/ });
    expect(toggle).toHaveAttribute("aria-pressed", "false");
    fireEvent.click(toggle);
    expect(screen.getByRole("table", { name: "Hallazgos por criticidad" })).toBeInTheDocument();
    expect(screen.getByRole("columnheader", { name: "Cantidad" })).toBeInTheDocument();
    expect(await violations(container)).toEqual([]);
  });

  it("se traduce al inglés", () => {
    useStore.setState({ lang: "en" });
    render(
      <ChartOrTable caption="c" columns={["a"]} rows={[]}>
        <div />
      </ChartOrTable>,
    );
    expect(screen.getByRole("button", { name: /View as table/ })).toBeInTheDocument();
  });
});

describe("componentes base", () => {
  it("Card, PageHeader, Stat, Callout y ErrorBox no tienen violaciones", async () => {
    const { container } = render(
      <main>
        <PageHeader title="Dashboard" description="desc" />
        <Card title="Título" subtitle="sub">
          <Stat label="Eventos" value={10} hint="hint" />
        </Card>
        <Callout tone="warning" title="Aviso">texto</Callout>
        <ErrorBox error="Falló algo" onClose={() => undefined} />
      </main>,
    );
    expect(await violations(container)).toEqual([]);
  });
});
