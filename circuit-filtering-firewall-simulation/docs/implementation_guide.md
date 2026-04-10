# Implementation Guide: Circuit Filtering Firewall

## 1. Objective

This implementation simulates a **circuit filtering firewall** that:

- Evaluates packet metadata (IP, port, protocol, flags).
- Maintains a circuit table for active sessions.
- Allows valid return traffic only when an outbound circuit exists.
- Applies explicit allow/deny rules before falling back to implicit default deny.

No payload inspection is performed.
That is intentional, because circuit filtering focuses on session behavior, not content.

## 2. Core Components

### `src/circuit_firewall.py`

- `Packet`: event model for one packet in the simulation.
- `Rule`: ordered filtering rule with CIDR/port/protocol matching.
- `CircuitEntry`: state-table row for an active session.
- `CircuitFirewall`: processing engine with:
  - Direction classification (`outbound`, `inbound`, `lateral`)
  - Rule matching (first-match wins)
  - Circuit table lookup and state transitions
  - Decision logging (`allow` / `deny` + reason)

### `src/traffic_simulator.py`

Generates deterministic traffic (using a seed):

- Benign web sessions (ports 80/443)
- Benign partner API sessions (port 8443)
- Benign DNS request/response sessions (UDP 53)
- Malicious inbound scanning
- Malicious risky egress attempts
- Malicious probes from blocked subnet
- Malicious outbound unknown C2 attempts
- Malicious lateral movement attempts

### `src/visualize.py`

Builds publication-ready plots from simulation logs:

1. Decision timeline
2. Circuit table utilization
3. Rule-hit distribution
4. Decision matrix
5. Scenario outcome breakdown

### `src/run_simulation.py`

Orchestrates the full pipeline:

1. Build firewall + rules
2. Generate traffic
3. Process each packet
4. Save logs and summary
5. Render charts
6. Write executive summary markdown

## 3. Rule Set Used

| Rule ID | Action | Direction | Match | Purpose |
|---|---|---|---|---|
| 201 | deny | inbound | `203.0.113.0/24 -> 10.0.0.0/24` | Block known hostile subnet |
| 202 | deny | outbound | TCP destination port in `23, 445, 3389` | Block risky egress services |
| 101 | allow | outbound | TCP destination port in `80, 443` | Allow web traffic |
| 102 | allow | outbound | `10.0.0.0/24 -> 198.51.100.0/24:8443` | Allow partner API access |
| 103 | allow | outbound | UDP destination port in `53, 123` | Allow DNS/NTP |
| (implicit) | deny | any | no rule match | Default deny |

Rule order is important: **first match wins**.

## 4. Circuit State Behavior

For TCP sessions, the simplified state progression is:

- New outbound `SYN` accepted by rule -> `SYN_SENT`
- Inbound `SYN-ACK` that maps to existing circuit -> `SYN_RECEIVED`
- Outbound `ACK` -> `ESTABLISHED`
- `FIN` -> `CLOSING`
- Final `ACK` or `RST` -> entry removed

For UDP sessions:

- Outbound request creates an `ESTABLISHED` pseudo-circuit.
- Inbound response is allowed only if reverse flow matches the table entry.

## 5. Decision Algorithm (Simplified)

```text
for each packet:
  expire old circuit entries
  classify direction

  if packet maps to existing circuit:
      allow (stateful return)
      update circuit state
  else:
      apply ordered rules
      if allow and outbound:
          create circuit entry
      elif allow and inbound:
          deny (new inbound circuit not allowed)
      elif no match:
          deny (implicit default deny)

  write packet decision log
```

## 6. Verified Result Snapshot (Seed 2026)

- Total packets: 402
- Benign: 264
- Malicious: 138
- Detection rate: 100.0%
- False positive rate: 0.0%
- Accuracy: 100.0%
- Peak active circuits: 24

These values are in:
`analysis/results/simulation_summary.json`

## 7. How To Reproduce

From repo root:

```bash
python3 circuit-filtering-firewall-simulation/src/run_simulation.py --seed 2026
```

To produce a different deterministic run:

```bash
python3 circuit-filtering-firewall-simulation/src/run_simulation.py --seed 42
```

## 8. How To Extend

- Add CIDR-based geofencing rules in `build_default_rules()`.
- Add circuit timeout stress tests by reducing `circuit_timeout_ms`.
- Add NAT simulation fields (translated IP/port) in `Packet` and `CircuitEntry`.
- Add live packet replay by replacing synthetic generator with PCAP-driven metadata.
