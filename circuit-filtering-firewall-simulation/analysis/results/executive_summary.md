# Circuit Filtering Firewall - Simulation Executive Summary

## Outcome
This run demonstrates a circuit filtering firewall that uses stateful session tracking (no payload inspection) to permit valid return traffic and block unsolicited or policy-violating flows.

## Key Metrics
- Total packets simulated: **402**
- Allowed packets: **264**
- Blocked packets: **138**
- Detection rate (malicious blocked): **100.0%**
- False positive rate (benign blocked): **0.0%**
- Accuracy: **100.0%**
- Peak active circuits: **24**
- p95 per-packet processing time: **0.01917 ms**

## Generated Figures
- `fig1_decision_timeline.png`
- `fig2_circuit_utilization.png`
- `fig3_rule_hit_distribution.png`
- `fig4_decision_matrix.png`
- `fig5_scenario_breakdown.png`