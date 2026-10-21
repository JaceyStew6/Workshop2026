"""Figures du dossier pour la consigne additionnelle 1 : chaîne biométrique et séquence du voyant mesurée.

  python tools/plot_biometrics.py            écrit dossier/figures/biometrie-chaine.png et biometrie-voyant.png

La séquence du voyant est celle relevée par tests/e2e/face_flow.py (le script joue le rôle de l'ESP8266 : même
interrogation, même protocole) ; les valeurs sont recopiées de la sortie de ce test.
"""
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch

OUT = Path(__file__).resolve().parent.parent / "dossier" / "figures"

# (t en s, motif) : changements de motif observés par l'ESP simulé pendant le test de bout en bout
SEQ = [(1.9, "off"), (2.9, "red_solid"), (32.6, "off"), (33.7, "green_blink"), (35.8, "red_blink"), (46.3, "off"),
       (47.4, "green_blink"), (47.4, "green_solid"), (77.7, "off"), (78.8, "red_solid"), (108.6, "off"),
       (109.7, "red_solid"), (139.4, "off")]
COL = {"off": "#d5d9e0", "green_blink": "#7bd88f", "green_solid": "#22a05a", "red_blink": "#f2a0a0", "red_solid": "#d93636"}
LAB = {"off": "éteint", "green_blink": "vert clignotant", "green_solid": "vert fixe", "red_blink": "rouge clignotant", "red_solid": "rouge fixe"}
STEPS = [(2.9, 32.6, "4. visage inconnu :\nrouge fixe 30 s"),
         (33.7, 46.3, "5. bon visage, mauvais mot\nde passe : vert clignotant puis\nrouge clignotant 10 s"),
         (47.4, 77.7, "6. succès :\nvert fixe 30 s"),
         (78.8, 139.4, "7. deux échecs de visage : rouge fixe 30 s chacun,\npuis blocage 5 min (voyant éteint)")]


def box(ax, x, y, w, h, text, fc, bold=False):
    ax.add_patch(FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0.02,rounding_size=0.08", fc=fc, ec="#3b4252", lw=1.4))
    ax.text(x + w / 2, y + h / 2, text, ha="center", va="center", fontsize=10.5, fontweight="bold" if bold else "normal")


def chain():
    fig, ax = plt.subplots(figsize=(12, 5.2))
    ax.set_xlim(0, 12)
    ax.set_ylim(0, 5.2)
    ax.axis("off")
    box(ax, 0.1, 2.2, 1.8, 0.9, "Navigateur\n(back-office)", "#e0f2fe")
    box(ax, 2.5, 2.2, 1.3, 0.9, "WAF\n:80", "#dbeafe", True)
    box(ax, 4.4, 2.2, 2.0, 0.9, "face-gate\n(décision, voyant)", "#fde7f3", True)
    box(ax, 7.4, 3.8, 2.4, 0.9, "Agent hôte (PC Hôte)\n127.0.0.1:8095", "#fef3c7")
    box(ax, 10.2, 3.8, 1.7, 0.9, "Caméra USB\nYuNet + SFace", "#fff7ed")
    box(ax, 7.4, 0.9, 2.4, 0.9, "auth-service\nticket + mot de passe", "#e2e8f0")
    box(ax, 10.2, 0.9, 1.7, 0.9, "PostgreSQL\nempreintes chiffrées", "#e2e8f0")
    box(ax, 4.4, 0.3, 2.0, 0.8, "ESP8266 + LED\nbicolore (WiFi)", "#dcfce7")
    arrows = [((1.9, 2.65), (2.5, 2.65)), ((3.8, 2.65), (4.4, 2.65)), ((6.4, 3.0), (7.4, 4.1)), ((9.8, 4.25), (10.2, 4.25)),
              ((6.4, 2.4), (7.4, 1.5)), ((9.8, 1.35), (10.2, 1.35)), ((5.4, 2.2), (5.4, 1.1))]
    for a_, b_ in arrows:
        ax.annotate("", xy=b_, xytext=a_, arrowprops=dict(arrowstyle="->", color="#475569", lw=1.6))
    ax.annotate("", xy=(3.15, 2.2), xytext=(4.4, 0.7), arrowprops=dict(arrowstyle="->", color="#16a34a", lw=1.4, ls="--"))
    ax.text(2.0, 0.95, "ESP : GET /gate/device/led\n1 fois par seconde, jeton", fontsize=8.5, color="#166534", ha="center")
    ax.text(6.2, 4.15, "caméra ON/OFF,\nempreintes", fontsize=8.5, color="#475569", ha="center")
    ax.text(6.2, 1.2, "mot de passe\n+ ticket facial", fontsize=8.5, color="#475569", ha="center")
    ax.text(0.1, 0.0, "Le navigateur ne voit jamais le ticket facial : face-gate le joint lui-même au mot de passe. "
                      "Aucune image ne quitte l'agent : seuls des vecteurs de 128 nombres sont transmis.", fontsize=8.8, color="#334155")
    fig.savefig(OUT / "biometrie-chaine.png", dpi=170, bbox_inches="tight")


def timeline():
    fig, ax = plt.subplots(figsize=(12, 3.4))
    for (t0, p), (t1, _) in zip(SEQ, SEQ[1:]):
        ax.barh(0, t1 - t0, left=t0, height=0.6, color=COL[p], edgecolor="white", lw=0.5)
    for a_, b_, label in STEPS:
        ax.text((a_ + b_) / 2 + (4 if a_ == 33.7 else 0), 0.45, label, ha="center", va="bottom", fontsize=8)
    ax.set_yticks([])
    ax.set_xlabel("temps (s) depuis le début du test de bout en bout")
    ax.set_xlim(0, 142)
    ax.set_ylim(-0.5, 1.9)
    handles = [plt.Rectangle((0, 0), 1, 1, color=COL[k]) for k in COL]
    ax.legend(handles, [LAB[k] for k in COL], ncol=5, loc="lower center", bbox_to_anchor=(0.5, -0.62), fontsize=8.5, frameon=False)
    for s in ("top", "right", "left"):
        ax.spines[s].set_visible(False)
    fig.savefig(OUT / "biometrie-voyant.png", dpi=170, bbox_inches="tight")


if __name__ == "__main__":
    chain()
    timeline()
    print("écrit :", OUT / "biometrie-chaine.png", OUT / "biometrie-voyant.png")
