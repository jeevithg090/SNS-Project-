from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path

import pandas as pd

from circuit_firewall import CircuitFirewall, build_default_rules
from traffic_simulator import generate_traffic
from visualize import generate_figures


ROOT_DIR = Path(__file__).resolve().parents[1]
RESULTS_DIR = ROOT_DIR / "analysis" / "results"
FIGURES_DIR = ROOT_DIR / "analysis" / "figures"

PACKET_LOG_FILE = RESULTS_DIR / "circuit_packet_log.csv"
SUMMARY_FILE = RESULTS_DIR / "simulation_summary.json"
SCENARIO_FILE = RESULTS_DIR / "scenario_breakdown.csv"
EXECUTIVE_FILE = RESULTS_DIR / "executive_summary.md"


def _percent(part: int, whole: int) -> float:
    return round((part / whole) * 100.0, 2) if whole else 0.0


def _build_summary(df: pd.DataFrame, firewall: CircuitFirewall, seed: int) -> dict:
    total = len(df)
    allowed = int((df["decision"] == "allow").sum())
    blocked = int((df["decision"] == "deny").sum())

    malicious_df = df[df["label"] == "malicious"]
    benign_df = df[df["label"] == "benign"]

    true_positives = int((malicious_df["decision"] == "deny").sum())
    false_negatives = int((malicious_df["decision"] == "allow").sum())
    false_positives = int((benign_df["decision"] == "deny").sum())
    true_negatives = int((benign_df["decision"] == "allow").sum())

    p95_processing = float(df["processing_ms"].quantile(0.95)) if total else 0.0

    return {
        "run_timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "seed": seed,
        "total_packets": total,
        "allowed_packets": allowed,
        "blocked_packets": blocked,
        "allow_rate_percent": _percent(allowed, total),
        "block_rate_percent": _percent(blocked, total),
        "benign_packets": int(len(benign_df)),
        "malicious_packets": int(len(malicious_df)),
        "detection_rate_percent": _percent(true_positives, len(malicious_df)),
        "false_negative_rate_percent": _percent(false_negatives, len(malicious_df)),
        "false_positive_rate_percent": _percent(false_positives, len(benign_df)),
        "accuracy_percent": _percent(true_positives + true_negatives, total),
        "confusion_matrix": {
            "tp_malicious_blocked": true_positives,
            "fn_malicious_allowed": false_negatives,
            "fp_benign_blocked": false_positives,
            "tn_benign_allowed": true_negatives,
        },
        "avg_processing_ms": round(float(df["processing_ms"].mean()), 5) if total else 0.0,
        "p95_processing_ms": round(p95_processing, 5),
        "peak_active_circuits": int(df["active_circuits"].max()) if total else 0,
        "avg_active_circuits": round(float(df["active_circuits"].mean()), 2) if total else 0.0,
        "expired_circuit_entries": firewall.expired_circuit_count,
        "rule_hits": dict(firewall.rule_hits),
    }


def _write_executive_summary(summary: dict, figure_paths: list[str]) -> None:
    bullets = [
        f"- Total packets simulated: **{summary['total_packets']}**",
        f"- Allowed packets: **{summary['allowed_packets']}**",
        f"- Blocked packets: **{summary['blocked_packets']}**",
        f"- Detection rate (malicious blocked): **{summary['detection_rate_percent']}%**",
        f"- False positive rate (benign blocked): **{summary['false_positive_rate_percent']}%**",
        f"- Accuracy: **{summary['accuracy_percent']}%**",
        f"- Peak active circuits: **{summary['peak_active_circuits']}**",
        f"- p95 per-packet processing time: **{summary['p95_processing_ms']} ms**",
    ]

    lines = [
        "# Circuit Filtering Firewall - Simulation Executive Summary",
        "",
        "## Outcome",
        "This run demonstrates a circuit filtering firewall that uses stateful session tracking (no payload inspection) to permit valid return traffic and block unsolicited or policy-violating flows.",
        "",
        "## Key Metrics",
        *bullets,
        "",
        "## Generated Figures",
    ]
    lines.extend([f"- `{Path(path).name}`" for path in figure_paths])

    EXECUTIVE_FILE.write_text("\n".join(lines), encoding="utf-8")


def run(seed: int = 2026) -> dict:
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    FIGURES_DIR.mkdir(parents=True, exist_ok=True)

    firewall = CircuitFirewall(internal_cidr="10.0.0.0/24", rules=build_default_rules(), circuit_timeout_ms=3200)
    traffic = generate_traffic(seed=seed)

    rows = [firewall.process_packet(packet) for packet in traffic]
    df = pd.DataFrame(rows)

    df.to_csv(PACKET_LOG_FILE, index=False)
    scenario_df = (
        df.groupby(["scenario", "label", "decision"], as_index=False)
        .size()
        .rename(columns={"size": "packet_count"})
        .sort_values(["scenario", "label", "decision"])
    )
    scenario_df.to_csv(SCENARIO_FILE, index=False)

    summary = _build_summary(df, firewall, seed)
    figure_paths = generate_figures(df, summary, FIGURES_DIR)
    summary["figure_files"] = figure_paths

    with SUMMARY_FILE.open("w", encoding="utf-8") as file_obj:
        json.dump(summary, file_obj, indent=2)

    _write_executive_summary(summary, figure_paths)

    return summary


def main() -> None:
    parser = argparse.ArgumentParser(description="Run circuit filtering firewall simulation")
    parser.add_argument("--seed", type=int, default=2026, help="Random seed for deterministic traffic generation")
    args = parser.parse_args()

    summary = run(seed=args.seed)

    print("\n=== CIRCUIT FILTERING FIREWALL SIMULATION ===")
    print(f"Packet log: {PACKET_LOG_FILE}")
    print(f"Summary JSON: {SUMMARY_FILE}")
    print(f"Scenario CSV: {SCENARIO_FILE}")
    print(f"Figures directory: {FIGURES_DIR}")
    print(f"Detection rate: {summary['detection_rate_percent']}%")
    print(f"False positive rate: {summary['false_positive_rate_percent']}%")
    print(f"Accuracy: {summary['accuracy_percent']}%")


if __name__ == "__main__":
    main()
