"""Gráficos del informe (matplotlib) a partir de los mismos agregados del dashboard."""
from __future__ import annotations

import io
import math

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
from matplotlib.patches import FancyArrowPatch  # noqa: E402

from app.lang import current, sev, tx  # noqa: E402

SEV_COLORS = {"Crítico": "#dc2626", "Alto": "#ea580c", "Medio": "#ca8a04", "Bajo": "#0284c7"}
SERIES = ["#2a78d6", "#eb6834"]
INK = "#0f172a"
MUTED = "#64748b"
GRID = "#e2e8f0"

plt.rcParams.update({
    "font.family": "DejaVu Sans", "font.size": 8, "axes.edgecolor": GRID, "axes.labelcolor": MUTED,
    "xtick.color": MUTED, "ytick.color": MUTED, "axes.spines.top": False, "axes.spines.right": False,
    "axes.titleweight": "bold", "axes.titlesize": 9, "axes.titlecolor": INK,
})


def _png(fig) -> io.BytesIO:
    buf = io.BytesIO()
    fig.savefig(buf, format="png", dpi=200, bbox_inches="tight", facecolor="white")
    plt.close(fig)
    buf.seek(0)
    return buf


def severity_chart(d: dict) -> io.BytesIO:
    data = d["by_severity"]
    fig, ax = plt.subplots(figsize=(6.2, 2.4))
    keys = [x["severity"] for x in data]
    labels = [sev(s) for s in keys]
    values = [x["count"] for x in data]
    bars = ax.bar(labels, values, color=[SEV_COLORS[s] for s in keys], width=0.55)
    for b, v in zip(bars, values):
        ax.text(b.get_x() + b.get_width() / 2, b.get_height() + 0.2, str(v), ha="center", va="bottom", color=INK)
    ax.set_ylabel(tx("Hallazgos", "Findings"))
    ax.yaxis.grid(True, color=GRID)
    ax.set_axisbelow(True)
    return _png(fig)


def category_chart(d: dict) -> io.BytesIO:
    cats = d["by_category"]
    fig, ax = plt.subplots(figsize=(6.2, 2.6))
    names = [(c.get("label_en") or c["label"]) if current() == "en" else c["label"] for c in cats][::-1]
    left = [0] * len(cats)
    for level, color in SEV_COLORS.items():
        vals = [c.get(level, 0) for c in cats][::-1]
        ax.barh(names, vals, left=left, color=color, label=sev(level), edgecolor="white", linewidth=1, height=0.6)
        left = [a + b for a, b in zip(left, vals)]
    for y, total in enumerate(left):
        ax.text(total + 0.15, y, str(total), va="center", color=INK)
    ax.xaxis.grid(True, color=GRID)
    ax.set_axisbelow(True)
    ax.legend(ncol=4, loc="lower center", bbox_to_anchor=(0.5, 1.0), frameon=False, fontsize=7)
    return _png(fig)


def timeline_chart(d: dict) -> io.BytesIO:
    tl = d["timeline"]
    fig, ax = plt.subplots(figsize=(6.8, 2.4))
    xs = list(range(len(tl)))
    ev = [x["events"] for x in tl]
    evd = [x["evidence"] for x in tl]
    ax.fill_between(xs, ev, color=SERIES[0], alpha=0.15)
    ax.plot(xs, ev, color=SERIES[0], linewidth=1.5, label=tx("Eventos", "Events"))
    ax.fill_between(xs, evd, color=SERIES[1], alpha=0.3)
    ax.plot(xs, evd, color=SERIES[1], linewidth=1.5, label=tx("En evidencia de hallazgos", "In finding evidence"))
    for i, x in enumerate(tl):
        if x["spike"]:
            ax.axvspan(i - 0.5, i + 0.5, color="#fde68a", alpha=0.6, linewidth=0)
    step = max(1, len(tl) // 6)
    ax.set_xticks(xs[::step])
    ax.set_xticklabels([f"{x['ts'][8:10]}/{x['ts'][5:7]} {x['ts'][11:13]}h" for x in tl[::step]], rotation=0)
    ax.yaxis.grid(True, color=GRID)
    ax.set_axisbelow(True)
    ax.legend(frameon=False, fontsize=7, loc="upper left")
    ax.set_ylabel(tx("Eventos / hora", "Events / hour"))
    return _png(fig)


def heatmap_chart(d: dict) -> io.BytesIO:
    cells = d["heatmap"]
    grid = [[0] * 24 for _ in range(7)]
    ev = [[0] * 24 for _ in range(7)]
    for c in cells:
        grid[c["weekday"]][c["hour"]] = c["events"]
        ev[c["weekday"]][c["hour"]] = c["evidence"]
    fig, ax = plt.subplots(figsize=(6.8, 2.3))
    im = ax.imshow([[math.sqrt(v) for v in row] for row in grid], cmap="Blues", aspect="auto")
    for y in range(7):
        for x in range(24):
            if ev[y][x]:
                ax.plot(x + 0.3, y - 0.3, "o", color="#dc2626", markersize=3)
    ax.set_yticks(range(7))
    ax.set_yticklabels(tx("Lun Mar Mié Jue Vie Sáb Dom", "Mon Tue Wed Thu Fri Sat Sun").split())
    ax.set_xticks(range(0, 24, 2))
    ax.set_xticklabels([f"{h}h" for h in range(0, 24, 2)])
    for s in ax.spines.values():
        s.set_visible(False)
    cb = fig.colorbar(im, ax=ax, fraction=0.025, pad=0.01)
    cb.set_label(tx("√ eventos", "√ events"), fontsize=7)
    cb.outline.set_visible(False)
    ax.set_title(tx("● rojo = celda con evidencia de hallazgos", "● red = cell with finding evidence"), loc="right", fontsize=7, color=MUTED, fontweight="normal")
    return _png(fig)


def lateral_chart(d: dict) -> io.BytesIO:
    g = d["lateral"]
    nodes = sorted(g["nodes"], key=lambda n: (-n["out"], n["id"]))
    n = max(len(nodes), 1)
    pos = {nd["id"]: (1.6 * math.cos(2 * math.pi * i / n - math.pi / 2), math.sin(2 * math.pi * i / n - math.pi / 2))
           for i, nd in enumerate(nodes)}
    fig, ax = plt.subplots(figsize=(6.4, 3.4))
    for e in g["edges"]:
        a, b = pos[e["source"]], pos[e["target"]]
        color = "#dc2626" if e["lateral"] else "#94a3b8"
        ax.add_patch(FancyArrowPatch(a, b, arrowstyle="-|>", mutation_scale=10, color=color, linewidth=1.4,
                                     connectionstyle="arc3,rad=0.15", shrinkA=14, shrinkB=14))
        mx, my = (a[0] + b[0]) / 2, (a[1] + b[1]) / 2
        ax.text(mx, my, f"{'/'.join(e['kinds'])} ×{e['count']}", fontsize=6, color=INK, ha="center",
                bbox={"boxstyle": "round,pad=0.15", "fc": "white", "ec": "none", "alpha": 0.8})
    for nd in nodes:
        x, y = pos[nd["id"]]
        ax.scatter([x], [y], s=380, color="#dbeafe" if nd["kind"] == "host" else "#e2e8f0", edgecolors=INK, zorder=3)
        ax.text(x, y - 0.2, nd["id"], ha="center", va="top", fontsize=7, color=INK, fontweight="bold")
    ax.set_xlim(-2.1, 2.1)
    ax.set_ylim(-1.35, 1.25)
    ax.axis("off")
    return _png(fig)


CHARTS = {"severity": severity_chart, "category": category_chart, "timeline": timeline_chart,
          "heatmap": heatmap_chart, "lateral": lateral_chart}
