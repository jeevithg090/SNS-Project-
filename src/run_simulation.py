"""Command-line entry point: generate traffic, run the firewall and write reports."""

from __future__ import annotations

import argparse
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pandas as pd

from circuit_firewall import CircuitFirewall, build_default_rules
from traffic_simulator import generate_traffic
from visualize import generate_figures

ROOT_DIR = Path(__file__).resolve().parents[1]
DEFAULT_OUTPUT_DIR = ROOT_DIR / "analysis"
DEFAULT_SEED = 2026
INTERNAL_CIDR = "10.0.0.0/24"
CIRCUIT_TIMEOUT_MS = 3200


@dataclass(frozen=True)
class OutputPaths:
    """Locations of every artifact produced by a simulation run."""

    root: Path

    @property
    def results_dir(self) -> Path:
        return self.root / "results"

    @property
    def figures_dir(self) -> Path:
        return self.root / "figures"

    @property
    def packet_log(self) -> Path:
        return self.results_dir / "circuit_packet_log.csv"

    @property
    def summary(self) -> Path:
        return self.results_dir / "simulation_summary.json"

    @property
    def scenarios(self) -> Path:
        return self.results_dir / "scenario_breakdown.csv"

    @property
    def executive_summary(self) -> Path:
        return self.results_dir / "executive_summary.md"


def _percent(part: int, whole: int) -> float:
    return round((part / whole) * 100.0, 2) if whole else 0.0


def build_summary(df: pd.DataFrame, firewall: CircuitFirewall, seed: int) -> dict[str, Any]:
    """Compute detection metrics and run statistics from the decision log."""
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
        "benign_packets": len(benign_df),
        "malicious_packets": len(malicious_df),
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


def _write_executive_summary(summary: dict[str, Any], figure_names: list[str], path: Path) -> None:
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
        (
            "This run demonstrates a circuit filtering firewall that uses stateful session tracking "
            "(no payload inspection) to permit valid return traffic and block unsolicited or "
            "policy-violating flows."
        ),
        "",
        "## Key Metrics",
        *bullets,
        "",
        "## Generated Figures",
    ]
    lines.extend([f"- `{name}`" for name in figure_names])

    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def simulate(seed: int = DEFAULT_SEED) -> tuple[pd.DataFrame, CircuitFirewall]:
    """Run the firewall over generated traffic and return the decision log."""
    firewall = CircuitFirewall(
        internal_cidr=INTERNAL_CIDR,
        rules=build_default_rules(),
        circuit_timeout_ms=CIRCUIT_TIMEOUT_MS,
    )
    rows = [firewall.process_packet(packet) for packet in generate_traffic(seed=seed)]
    return pd.DataFrame(rows), firewall


def run(seed: int = DEFAULT_SEED, output_dir: Path = DEFAULT_OUTPUT_DIR) -> dict[str, Any]:
    """Run the full pipeline and write logs, summaries and figures to ``output_dir``."""
    paths = OutputPaths(Path(output_dir))
    paths.results_dir.mkdir(parents=True, exist_ok=True)
    paths.figures_dir.mkdir(parents=True, exist_ok=True)

    df, firewall = simulate(seed)

    df.to_csv(paths.packet_log, index=False)
    scenario_df = (
        df.groupby(["scenario", "label", "decision"], as_index=False)
        .size()
        .rename(columns={"size": "packet_count"})
        .sort_values(["scenario", "label", "decision"])
    )
    scenario_df.to_csv(paths.scenarios, index=False)

    summary = build_summary(df, firewall, seed)
    figure_paths = generate_figures(df, summary, paths.figures_dir)
    # Store paths relative to the output root so results are portable between machines.
    summary["figure_files"] = [path.relative_to(paths.root).as_posix() for path in figure_paths]

    with paths.summary.open("w", encoding="utf-8") as file_obj:
        json.dump(summary, file_obj, indent=2)
        file_obj.write("\n")

    _write_executive_summary(summary, [path.name for path in figure_paths], paths.executive_summary)

    return summary


CLI_EPILOG = """\
examples:
  python src/run_simulation.py                     reference run (seed 2026) into analysis/
  python src/run_simulation.py --seed 42           another reproducible traffic mix
  python src/run_simulation.py --output-dir out/   keep analysis/ untouched

outputs (under the output directory):
  results/circuit_packet_log.csv   one row per packet with decision, rule and circuit state
  results/scenario_breakdown.csv   packet counts per scenario, label and decision
  results/simulation_summary.json  metrics, confusion matrix and rule hits
  results/executive_summary.md     short Markdown report
  figures/fig1..fig5_*.png         report figures
"""


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="run_simulation.py",
        description=(
            "Replay seeded benign and attack traffic through a stateful circuit filtering firewall, "
            "then write a decision log, metrics and report figures."
        ),
        epilog=CLI_EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=DEFAULT_SEED,
        help=f"random seed for deterministic traffic generation (default: {DEFAULT_SEED})",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=DEFAULT_OUTPUT_DIR,
        metavar="DIR",
        help="directory that receives results/ and figures/ (default: analysis/)",
    )
    return parser


def main(argv: list[str] | None = None) -> None:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.output_dir.exists() and not args.output_dir.is_dir():
        parser.error(f"--output-dir {args.output_dir} exists and is not a directory")

    print(f"Running circuit filtering simulation (seed {args.seed})...", flush=True)
    try:
        summary = run(seed=args.seed, output_dir=args.output_dir)
    except PermissionError as exc:
        parser.exit(1, f"error: cannot write to {exc.filename or args.output_dir}: permission denied\n")
    paths = OutputPaths(args.output_dir)

    print("\n=== CIRCUIT FILTERING FIREWALL SIMULATION ===")
    print(
        f"Packets: {summary['total_packets']} "
        f"({summary['benign_packets']} benign, {summary['malicious_packets']} malicious)"
    )
    print(f"Allowed / blocked: {summary['allowed_packets']} / {summary['blocked_packets']}")
    print(f"Detection rate: {summary['detection_rate_percent']}%")
    print(f"False positive rate: {summary['false_positive_rate_percent']}%")
    print(f"Accuracy: {summary['accuracy_percent']}%")
    print(f"Peak active circuits: {summary['peak_active_circuits']}")
    print("\nOutputs:")
    print(f"  Packet log:    {paths.packet_log}")
    print(f"  Summary JSON:  {paths.summary}")
    print(f"  Scenario CSV:  {paths.scenarios}")
    print(f"  Report:        {paths.executive_summary}")
    print(f"  Figures:       {paths.figures_dir} ({len(summary['figure_files'])} PNG files)")


if __name__ == "__main__":
    main()
