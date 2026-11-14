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
  - Direction classification (`outbound`, `inbound`, `lateral` for internal↔internal, `transit` for external↔external)
  - Rule matching (first-match wins)
  - Circuit table lookup and state transitions
  - Decision logging (`allow` / `deny` + reason), with monotonically increasing circuit IDs (`C-0001`, `C-0002`, ...)
- `Rule` validates its action, direction, protocol and ports when it is created and raises `ValueError` on bad input.

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

  if direction is lateral or transit:
      deny (PERIMETER_ONLY: traffic is not crossing the perimeter)
  elif packet maps to existing circuit:
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

From the repository root, after `pip install -r requirements.txt`:

```bash
python src/run_simulation.py --seed 2026
```

To produce a different deterministic run, or to write somewhere other than `analysis/`:

```bash
python src/run_simulation.py --seed 42 --output-dir /tmp/run-42
```

`simulation_summary.json` stores figure paths relative to the output directory, so result sets can be moved
between machines.

## 8. How To Extend

- Add CIDR-based geofencing rules in `build_default_rules()`.
- Add circuit timeout stress tests by reducing `CIRCUIT_TIMEOUT_MS` in `src/run_simulation.py`.
- Add NAT simulation fields (translated IP/port) in `Packet` and `CircuitEntry`.
- Add live packet replay by replacing synthetic generator with PCAP-driven metadata.

## 9. Companion: DoS Rate-Limiting Simulator

`web/index.html` is a separate, browser-based demo of a different defence: per-source-IP SYN rate limiting.
The engine (`web/rate-limiter.js`) works like this:

- Each IP gets a fixed window (`windowMs`, 1 s by default) in which it may send `rateLimit` packets.
- Every packet over the limit inside a window counts as a violation and is blocked.
- An IP that reaches `banThreshold` violations is banned permanently, until the user clicks reset.

The page is split into `index.html` (markup and meta tags), `styles.css` (design tokens for spacing, type
and per-theme colours, plus components) and `app.js` (traffic generation, controls and rendering). `app.js`
batches packets and renders them a few times per second, so the page stays responsive at the highest
attack intensity (about 2,000 packets per second).

Unit tests are in `tests/web/rate-limiter.test.js`. Run them with `node --test tests/web/*.test.js`.
