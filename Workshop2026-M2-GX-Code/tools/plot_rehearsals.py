"""Graphiques des répétitions : latence perçue par le client légitime avant, pendant et après l'incident.

  python tools/plot_rehearsals.py            # lit tests/rehearsals/run-*/result.json

Écrit tests/rehearsals/latency-run-N.png (une répétition) et latency-all.png (toutes, en colonnes empilées).
Code couleur : vert = opération réussie et rapide ; orange = réussie mais > 500 ms ; rouge = échec (503, 504...).
Ronds = virement, carrés = devis.
"""
import json
import sys
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
GREEN, ORANGE, RED, GREY, BLUE = "#059669", "#d97706", "#dc2626", "#64748b", "#2563eb"


def color(status_ok: bool, ms: float) -> str:
    if not status_ok:
        return RED
    return ORANGE if ms > 500 else GREEN


def draw(ax, run: dict, title: str, ymax: float = 2600):
    inc, p = run["incident"], run["params"]
    ax.axhline(500, color=GREY, ls="--", lw=0.8)
    ax.text(run["samples"][-1]["t"], 500 + ymax * 0.02, "seuil « dégradé » 500 ms", ha="right", va="bottom", fontsize=7, color=GREY)
    t_det, t_ok = inc["detected_after_s"], inc["recovered_after_s"]
    if t_det is not None and t_ok is not None:
        ax.axvspan(0, t_ok, color=ORANGE, alpha=0.07, lw=0)
        ax.axvline(t_det, color=BLUE, lw=1.2)
        ax.text(t_det, ymax * 0.86, f" alerte + bannissement ({t_det:.0f} s)", color=BLUE, fontsize=7.5, va="top")
        ax.axvline(t_ok, color=GREEN, lw=1.2)
        ax.text(t_ok, ymax * 0.75, f" rétabli ({t_ok:.0f} s)", color=GREEN, fontsize=7.5, va="top")
    ax.axvline(p["duration_s"], color=GREY, lw=1.0, ls=":")
    ax.text(p["duration_s"], ymax * 0.97, "fin du script d'attaque ", color=GREY, fontsize=7.5, va="top", ha="right")
    ax.axvline(0, color="#0f172a", lw=1.2)
    ax.text(0, ymax * 0.97, " début de l'attaque", color="#0f172a", fontsize=7.5, va="top")
    ts = [s["t"] for s in run["samples"]]
    ax.plot(ts, [s["virement_ms"] for s in run["samples"]], color="#cbd5e1", lw=0.8, zorder=1)
    for s in run["samples"]:
        ax.scatter(s["t"], min(s["virement_ms"], ymax), s=14, marker="o", zorder=3, color=color(s["virement"] == 201, s["virement_ms"]))
        ax.scatter(s["t"], min(s["devis_ms"], ymax), s=11, marker="s", zorder=2, alpha=0.75, color=color(s["devis"] == 200, s["devis_ms"]))
    from matplotlib.lines import Line2D
    ax.legend(handles=[
        Line2D([], [], marker="o", ls="", color=GREEN, label="réussi, rapide"),
        Line2D([], [], marker="o", ls="", color=ORANGE, label="réussi, > 500 ms"),
        Line2D([], [], marker="o", ls="", color=RED, label="échec (503...)"),
        Line2D([], [], marker="o", ls="", color=GREY, label="virement"),
        Line2D([], [], marker="s", ls="", color=GREY, label="devis")],
        loc="upper right", bbox_to_anchor=(1.0, 0.80), fontsize=6.5, ncol=1, frameon=False)
    ax.set_ylim(-60, ymax)
    ax.set_xlim(-2, ts[-1] + 2)
    ax.set_title(f"{title} : attaque à {p['rps']} req/s, la reprise a lieu alors que l'attaque continue jusqu'à {p['duration_s']} s",
                 fontsize=8.5, loc="left")
    ax.set_ylabel("latence perçue (ms)", fontsize=8)
    ax.tick_params(labelsize=7.5)
    for side in ("top", "right"):
        ax.spines[side].set_visible(False)


def main():
    out = ROOT / "tests" / "rehearsals"
    runs = {}
    for f in sorted(out.glob("run-*/result.json")):
        runs[int(f.parent.name.split("-")[1])] = json.loads(f.read_text(encoding="utf-8"))
    if not runs:
        sys.exit("aucune répétition trouvée dans tests/rehearsals/")
    for n, run in runs.items():
        fig, ax = plt.subplots(figsize=(7.2, 3.1), dpi=200)
        draw(ax, run, f"Répétition {n}")
        ax.set_xlabel("secondes depuis le début de l'attaque", fontsize=8)
        fig.tight_layout()
        fig.savefig(out / f"latency-run-{n}.png")
        plt.close(fig)
    fig, axes = plt.subplots(len(runs), 1, figsize=(7.2, 2.0 * len(runs)), dpi=200, sharex=True)
    for ax, (n, run) in zip(axes if len(runs) > 1 else [axes], runs.items()):
        draw(ax, run, f"Répétition {n}")
    (axes[-1] if len(runs) > 1 else axes).set_xlabel("secondes depuis le début de l'attaque", fontsize=8)
    fig.tight_layout()
    fig.savefig(out / "latency-all.png")
    print("écrit :", ", ".join(sorted(p.name for p in out.glob("latency-*.png"))))


if __name__ == "__main__":
    main()
