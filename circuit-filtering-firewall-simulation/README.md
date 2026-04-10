# Circuit Filtering Firewall Simulation

This module is a standalone, presentation-ready simulation of a **circuit filtering firewall**.
It is designed to complement your existing proxy firewall project by showing how security decisions are made at the **session/connection level (Layer 3/4 metadata)** without payload inspection.

## What This Demonstrates

- Stateful circuit tracking (session table) for TCP and UDP.
- Rule-based filtering for inbound and outbound traffic.
- Default-deny behavior for unmatched traffic.
- Attack simulation with realistic scenarios:
  - Inbound port scan
  - Risky outbound egress attempts (Telnet/SMB/RDP ports)
  - Probes from a blocked subnet
  - Unknown outbound C2 channel attempts
  - Lateral movement attempts
- Automatic reporting with figures and structured output files.

## Quick Start

From the repository root:

```bash
python3 circuit-filtering-firewall-simulation/src/run_simulation.py --seed 2026
```

## Generated Output

After one run, outputs are written to:

- `circuit-filtering-firewall-simulation/analysis/results/circuit_packet_log.csv`
- `circuit-filtering-firewall-simulation/analysis/results/simulation_summary.json`
- `circuit-filtering-firewall-simulation/analysis/results/scenario_breakdown.csv`
- `circuit-filtering-firewall-simulation/analysis/results/executive_summary.md`
- `circuit-filtering-firewall-simulation/analysis/figures/fig1_decision_timeline.png`
- `circuit-filtering-firewall-simulation/analysis/figures/fig2_circuit_utilization.png`
- `circuit-filtering-firewall-simulation/analysis/figures/fig3_rule_hit_distribution.png`
- `circuit-filtering-firewall-simulation/analysis/figures/fig4_decision_matrix.png`
- `circuit-filtering-firewall-simulation/analysis/figures/fig5_scenario_breakdown.png`

## Current Verified Run (Seed: 2026)

- Total packets: **402**
- Benign packets: **264**
- Malicious packets: **138**
- Allowed: **264**
- Blocked: **138**
- Detection rate: **100.0%**
- False positive rate: **0.0%**
- Accuracy: **100.0%**
- Peak active circuits: **24**

## Folder Structure

```text
circuit-filtering-firewall-simulation/
  README.md
  src/
    circuit_firewall.py
    traffic_simulator.py
    visualize.py
    run_simulation.py
  docs/
    implementation_guide.md
  analysis/
    figures/
    results/
```

## Documentation

- Implementation details: `circuit-filtering-firewall-simulation/docs/implementation_guide.md`

## Presentation Tip

Use the five generated figures in order (`fig1` to `fig5`).
This gives a clean story arc: traffic arrives -> circuits are managed -> rules fire -> decisions are validated -> scenarios are explained.
