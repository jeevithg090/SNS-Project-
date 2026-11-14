"""Matplotlib/seaborn figures summarising a simulation run."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import pandas as pd
import seaborn as sns

PALETTE = {
    "allow": "#2e8b57",
    "deny": "#cf3f3f",
    "background": "#f6f8fa",
    "grid": "#d8dee4",
    "accent": "#1f4e79",
}


def _prepare_figure() -> None:
    sns.set_theme(style="whitegrid")
    plt.rcParams["figure.facecolor"] = PALETTE["background"]
    plt.rcParams["axes.facecolor"] = PALETTE["background"]


def _fig_timeline(df: pd.DataFrame, out_dir: Path) -> Path:
    window_size_ms = 120
    timeline = (
        df.assign(window_ms=(df["time_ms"] // window_size_ms) * window_size_ms)
        .groupby(["window_ms", "decision"], as_index=False)
        .size()
        .pivot(index="window_ms", columns="decision", values="size")
        .fillna(0)
        .sort_index()
    )

    timeline["time_s"] = timeline.index / 1000.0
    allow = timeline.get("allow", pd.Series(index=timeline.index, data=0))
    deny = timeline.get("deny", pd.Series(index=timeline.index, data=0))

    fig, ax = plt.subplots(figsize=(12, 4.8))
    ax.plot(timeline["time_s"], allow, color=PALETTE["allow"], linewidth=2.2, label="Allowed")
    ax.plot(timeline["time_s"], deny, color=PALETTE["deny"], linewidth=2.2, label="Blocked")
    ax.fill_between(timeline["time_s"], allow, color=PALETTE["allow"], alpha=0.14)
    ax.fill_between(timeline["time_s"], deny, color=PALETTE["deny"], alpha=0.14)
    ax.set_title("Fig 1. Decision Timeline (Allowed vs Blocked)", fontweight="bold")
    ax.set_xlabel("Simulation Time (seconds)")
    ax.set_ylabel(f"Packets per {window_size_ms} ms")
    ax.grid(color=PALETTE["grid"], linestyle="--", linewidth=0.7)
    ax.legend(loc="upper right")

    path = out_dir / "fig1_decision_timeline.png"
    fig.tight_layout()
    fig.savefig(path, dpi=160)
    plt.close(fig)
    return path


def _fig_circuit_table(df: pd.DataFrame, out_dir: Path) -> Path:
    circuit_series = df.sort_values("time_ms")[["time_ms", "active_circuits"]].copy()
    circuit_series["time_s"] = circuit_series["time_ms"] / 1000.0
    circuit_series["smoothed"] = circuit_series["active_circuits"].rolling(window=12, min_periods=1).mean()

    fig, ax = plt.subplots(figsize=(12, 4.8))
    ax.plot(
        circuit_series["time_s"],
        circuit_series["active_circuits"],
        color=PALETTE["accent"],
        linewidth=1.5,
        alpha=0.55,
        label="Instant active circuits",
    )
    ax.plot(
        circuit_series["time_s"],
        circuit_series["smoothed"],
        color="#ff8c00",
        linewidth=2.2,
        label="Smoothed active circuits",
    )
    ax.set_title("Fig 2. Circuit Table Utilization Over Time", fontweight="bold")
    ax.set_xlabel("Simulation Time (seconds)")
    ax.set_ylabel("Active Circuits")
    ax.grid(color=PALETTE["grid"], linestyle="--", linewidth=0.7)
    ax.legend(loc="upper right")

    path = out_dir / "fig2_circuit_utilization.png"
    fig.tight_layout()
    fig.savefig(path, dpi=160)
    plt.close(fig)
    return path


def _fig_rule_hits(summary: dict[str, Any], out_dir: Path) -> Path:
    rule_hits = pd.Series(summary["rule_hits"], dtype="int64").sort_values(ascending=False)
    labels = [f"Rule {idx}" if str(idx).isdigit() else idx for idx in rule_hits.index]

    fig, ax = plt.subplots(figsize=(12, 5.2))
    bars = ax.bar(labels, rule_hits.values, color="#4169e1", alpha=0.85)
    for bar in bars:
        height = bar.get_height()
        ax.text(bar.get_x() + bar.get_width() / 2, height + 0.7, str(int(height)), ha="center", va="bottom", fontsize=8)

    ax.set_title("Fig 3. Rule Trigger Distribution", fontweight="bold")
    ax.set_xlabel("Rule Identifier")
    ax.set_ylabel("Packet Count")
    ax.tick_params(axis="x", labelrotation=32)
    ax.grid(axis="y", color=PALETTE["grid"], linestyle="--", linewidth=0.7)

    path = out_dir / "fig3_rule_hit_distribution.png"
    fig.tight_layout()
    fig.savefig(path, dpi=160)
    plt.close(fig)
    return path


def _fig_decision_matrix(df: pd.DataFrame, out_dir: Path) -> Path:
    tp = int(((df["label"] == "malicious") & (df["decision"] == "deny")).sum())
    fn = int(((df["label"] == "malicious") & (df["decision"] == "allow")).sum())
    fp = int(((df["label"] == "benign") & (df["decision"] == "deny")).sum())
    tn = int(((df["label"] == "benign") & (df["decision"] == "allow")).sum())

    matrix = pd.DataFrame(
        [[tp, fn], [fp, tn]],
        index=["Malicious", "Benign"],
        columns=["Blocked", "Allowed"],
    )

    fig, ax = plt.subplots(figsize=(8.2, 5.2))
    sns.heatmap(matrix, annot=True, fmt="d", cmap="YlOrRd", cbar=True, linewidths=0.8, linecolor="white", ax=ax)
    ax.set_title("Fig 4. Decision Matrix", fontweight="bold")
    ax.set_xlabel("Firewall Decision")
    ax.set_ylabel("Traffic Ground Truth")

    path = out_dir / "fig4_decision_matrix.png"
    fig.tight_layout()
    fig.savefig(path, dpi=160)
    plt.close(fig)
    return path


def _fig_scenario_breakdown(df: pd.DataFrame, out_dir: Path) -> Path:
    scenario_counts = (
        df.groupby(["scenario", "decision"], as_index=False)
        .size()
        .pivot(index="scenario", columns="decision", values="size")
        .fillna(0)
    )
    scenario_counts["total"] = scenario_counts.sum(axis=1)
    scenario_counts = scenario_counts.sort_values("total", ascending=False).head(10)

    allow = scenario_counts.get("allow", pd.Series(index=scenario_counts.index, data=0))
    deny = scenario_counts.get("deny", pd.Series(index=scenario_counts.index, data=0))

    fig, ax = plt.subplots(figsize=(12, 5.4))
    ax.bar(scenario_counts.index, allow, color=PALETTE["allow"], label="Allowed")
    ax.bar(scenario_counts.index, deny, bottom=allow, color=PALETTE["deny"], label="Blocked")

    ax.set_title("Fig 5. Top Scenarios by Decision Outcome", fontweight="bold")
    ax.set_xlabel("Scenario")
    ax.set_ylabel("Packet Count")
    ax.tick_params(axis="x", labelrotation=28)
    ax.grid(axis="y", color=PALETTE["grid"], linestyle="--", linewidth=0.7)
    ax.legend(loc="upper right")

    path = out_dir / "fig5_scenario_breakdown.png"
    fig.tight_layout()
    fig.savefig(path, dpi=160)
    plt.close(fig)
    return path


def generate_figures(df: pd.DataFrame, summary: dict[str, Any], out_dir: Path) -> list[Path]:
    """Render all five figures into ``out_dir`` and return their paths in order."""
    _prepare_figure()
    out_dir.mkdir(parents=True, exist_ok=True)

    figures = [
        _fig_timeline(df, out_dir),
        _fig_circuit_table(df, out_dir),
        _fig_rule_hits(summary, out_dir),
        _fig_decision_matrix(df, out_dir),
        _fig_scenario_breakdown(df, out_dir),
    ]

    return figures
