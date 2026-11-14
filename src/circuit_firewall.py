"""Circuit-level (session) filtering firewall engine.

Decisions are made from Layer 3/4 metadata only (addresses, ports, protocol and
TCP flags). A circuit table tracks sessions initiated from the internal network
so that their return traffic can be admitted while unsolicited inbound sessions
are rejected.
"""

from __future__ import annotations

import ipaddress
import itertools
import time
from collections import Counter
from dataclasses import dataclass, field
from typing import Literal, TypedDict

Action = Literal["allow", "deny"]
Direction = Literal["inbound", "outbound", "lateral", "transit"]
FlowKey = tuple[str, int, str, int, str]

VALID_ACTIONS = frozenset({"allow", "deny"})
VALID_RULE_DIRECTIONS = frozenset({"inbound", "outbound", "any"})
VALID_PROTOCOLS = frozenset({"tcp", "udp", "any"})


@dataclass
class Packet:
    """A single packet's L3/L4 metadata plus ground-truth labels for evaluation."""

    event_id: int
    time_ms: int
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    flags: str
    label: str
    scenario: str


@dataclass
class Rule:
    """An ordered filtering rule. ``"any"`` acts as a wildcard for CIDRs and protocol."""

    rule_id: int
    action: str
    direction: str
    src_cidr: str
    dst_cidr: str
    protocol: str
    dst_ports: list[int] = field(default_factory=list)
    description: str = ""

    def __post_init__(self) -> None:
        self.action = self.action.lower()
        self.direction = self.direction.lower()
        self.protocol = self.protocol.lower()
        if self.action not in VALID_ACTIONS:
            raise ValueError(f"Rule {self.rule_id}: invalid action {self.action!r}")
        if self.direction not in VALID_RULE_DIRECTIONS:
            raise ValueError(f"Rule {self.rule_id}: invalid direction {self.direction!r}")
        if self.protocol not in VALID_PROTOCOLS:
            raise ValueError(f"Rule {self.rule_id}: invalid protocol {self.protocol!r}")
        for port in self.dst_ports:
            if not 0 <= port <= 65535:
                raise ValueError(f"Rule {self.rule_id}: port {port} out of range")
        self._src_net = None if self.src_cidr == "any" else ipaddress.ip_network(self.src_cidr)
        self._dst_net = None if self.dst_cidr == "any" else ipaddress.ip_network(self.dst_cidr)

    def matches(self, packet: Packet, packet_direction: str) -> bool:
        if self.direction != "any" and self.direction != packet_direction:
            return False

        if self.protocol != "any" and self.protocol != packet.protocol.lower():
            return False

        src_ip = ipaddress.ip_address(packet.src_ip)
        dst_ip = ipaddress.ip_address(packet.dst_ip)

        if self._src_net and src_ip not in self._src_net:
            return False

        if self._dst_net and dst_ip not in self._dst_net:
            return False

        return not self.dst_ports or packet.dst_port in self.dst_ports


class Decision(TypedDict):
    """One row of the firewall decision log."""

    event_id: int
    time_ms: int
    label: str
    scenario: str
    direction: Direction
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    flags: str
    decision: Action
    rule_id: str
    reason: str
    circuit_id: str
    circuit_state: str
    active_circuits: int
    processing_ms: float


@dataclass
class CircuitEntry:
    """A row of the circuit (session state) table."""

    circuit_id: str
    key: FlowKey
    state: str
    opened_at_ms: int
    last_seen_ms: int
    packets_forwarded: int = 0


class CircuitFirewall:
    """Circuit-level firewall.

    It filters using L3/L4 metadata only and uses a state table to allow return traffic
    only for sessions initiated from the internal network. Rules are evaluated in
    order (first match wins) and unmatched traffic is denied.
    """

    def __init__(
        self,
        internal_cidr: str,
        rules: list[Rule],
        circuit_timeout_ms: int = 4000,
    ) -> None:
        self.internal_net = ipaddress.ip_network(internal_cidr)
        self.rules = rules
        if circuit_timeout_ms <= 0:
            raise ValueError("circuit_timeout_ms must be positive")
        self.circuit_timeout_ms = circuit_timeout_ms
        self.circuit_table: dict[FlowKey, CircuitEntry] = {}
        self.rule_hits: Counter[str] = Counter()
        self.expired_circuit_count = 0
        # Monotonic ID source: IDs stay unique even after circuits close or expire.
        self._circuit_ids = itertools.count(1)

    def _is_internal(self, ip: str) -> bool:
        return ipaddress.ip_address(ip) in self.internal_net

    def _direction(self, packet: Packet) -> Direction:
        src_internal = self._is_internal(packet.src_ip)
        dst_internal = self._is_internal(packet.dst_ip)

        if src_internal and not dst_internal:
            return "outbound"
        if not src_internal and dst_internal:
            return "inbound"
        if src_internal and dst_internal:
            return "lateral"
        return "transit"

    def _flow_key(self, packet: Packet) -> FlowKey:
        return (
            packet.src_ip,
            packet.src_port,
            packet.dst_ip,
            packet.dst_port,
            packet.protocol.lower(),
        )

    def _reverse_flow_key(self, packet: Packet) -> FlowKey:
        return (
            packet.dst_ip,
            packet.dst_port,
            packet.src_ip,
            packet.src_port,
            packet.protocol.lower(),
        )

    def _expire_circuits(self, now_ms: int) -> None:
        stale_keys = [
            key for key, entry in self.circuit_table.items() if now_ms - entry.last_seen_ms > self.circuit_timeout_ms
        ]
        for key in stale_keys:
            self.circuit_table.pop(key, None)
        self.expired_circuit_count += len(stale_keys)

    @staticmethod
    def _flags(flags: str) -> set[str]:
        normalized = flags.replace("/", "-").replace(",", "-")
        return {item.strip().upper() for item in normalized.split("-") if item.strip()}

    def _first_matching_rule(self, packet: Packet, direction: str) -> Rule | None:
        for rule in self.rules:
            if rule.matches(packet, direction):
                return rule
        return None

    def _open_circuit(self, packet: Packet, now_ms: int) -> CircuitEntry:
        key = self._flow_key(packet)
        flags = self._flags(packet.flags)

        state = "ESTABLISHED"
        if packet.protocol.lower() == "tcp" and "SYN" in flags and "ACK" not in flags:
            state = "SYN_SENT"

        entry = CircuitEntry(
            circuit_id=f"C-{next(self._circuit_ids):04d}",
            key=key,
            state=state,
            opened_at_ms=now_ms,
            last_seen_ms=now_ms,
            packets_forwarded=1,
        )
        self.circuit_table[key] = entry
        return entry

    def _touch_circuit(self, entry: CircuitEntry, packet: Packet, direction: Direction) -> None:
        flags = self._flags(packet.flags)
        entry.last_seen_ms = packet.time_ms
        entry.packets_forwarded += 1

        if packet.protocol.lower() == "udp":
            entry.state = "ESTABLISHED"
            return

        if "RST" in flags:
            entry.state = "RESET"
            self.circuit_table.pop(entry.key, None)
            return

        if "FIN" in flags:
            entry.state = "CLOSING"
            return

        if direction == "inbound" and "SYN" in flags and "ACK" in flags and entry.state == "SYN_SENT":
            entry.state = "SYN_RECEIVED"
            return

        if direction == "outbound" and "ACK" in flags and entry.state in {"SYN_SENT", "SYN_RECEIVED"}:
            entry.state = "ESTABLISHED"
            return

        if direction == "inbound" and "ACK" in flags and entry.state == "CLOSING":
            entry.state = "CLOSED"
            self.circuit_table.pop(entry.key, None)

    def process_packet(self, packet: Packet) -> Decision:
        """Evaluate one packet, update circuit state and return the logged decision."""
        started = time.perf_counter()
        self._expire_circuits(packet.time_ms)

        direction = self._direction(packet)
        rule_id: str = "DEFAULT_DENY"
        reason = "Implicit deny"
        decision: Action = "deny"
        circuit_id = ""
        circuit_state = "NONE"

        existing: CircuitEntry | None = None
        if direction == "outbound":
            existing = self.circuit_table.get(self._flow_key(packet))
        elif direction == "inbound":
            existing = self.circuit_table.get(self._reverse_flow_key(packet))

        if direction in ("lateral", "transit"):
            rule_id = "PERIMETER_ONLY"
            reason = "Traffic is not crossing the perimeter"
        elif existing:
            decision = "allow"
            rule_id = "STATEFUL_RETURN"
            reason = "Matched existing circuit table entry"
            self._touch_circuit(existing, packet, direction)
            circuit_id = existing.circuit_id
            circuit_state = existing.state
        else:
            matched_rule = self._first_matching_rule(packet, direction)
            if matched_rule:
                rule_id = str(matched_rule.rule_id)
                reason = matched_rule.description
                decision = "allow" if matched_rule.action == "allow" else "deny"

            if decision == "allow" and direction == "outbound":
                created = self._open_circuit(packet, packet.time_ms)
                circuit_id = created.circuit_id
                circuit_state = created.state
            elif decision == "allow" and direction == "inbound":
                # Circuit filtering blocks externally initiated sessions by design.
                decision: Action = "deny"
                rule_id = "INBOUND_NEW_CIRCUIT"
                reason = "Inbound sessions must map to an existing outbound circuit"

        self.rule_hits[rule_id] += 1

        processing_ms = (time.perf_counter() - started) * 1000.0
        return {
            "event_id": packet.event_id,
            "time_ms": packet.time_ms,
            "label": packet.label,
            "scenario": packet.scenario,
            "direction": direction,
            "src_ip": packet.src_ip,
            "dst_ip": packet.dst_ip,
            "src_port": packet.src_port,
            "dst_port": packet.dst_port,
            "protocol": packet.protocol.lower(),
            "flags": packet.flags,
            "decision": decision,
            "rule_id": rule_id,
            "reason": reason,
            "circuit_id": circuit_id,
            "circuit_state": circuit_state,
            "active_circuits": len(self.circuit_table),
            "processing_ms": round(processing_ms, 5),
        }


def build_default_rules() -> list[Rule]:
    """Ordered rules. First match wins."""
    return [
        Rule(
            rule_id=201,
            action="deny",
            direction="inbound",
            src_cidr="203.0.113.0/24",
            dst_cidr="10.0.0.0/24",
            protocol="any",
            description="Block known hostile source subnet",
        ),
        Rule(
            rule_id=202,
            action="deny",
            direction="outbound",
            src_cidr="10.0.0.0/24",
            dst_cidr="any",
            protocol="tcp",
            dst_ports=[23, 445, 3389],
            description="Block risky egress service ports",
        ),
        Rule(
            rule_id=101,
            action="allow",
            direction="outbound",
            src_cidr="10.0.0.0/24",
            dst_cidr="any",
            protocol="tcp",
            dst_ports=[80, 443],
            description="Allow outbound web sessions",
        ),
        Rule(
            rule_id=102,
            action="allow",
            direction="outbound",
            src_cidr="10.0.0.0/24",
            dst_cidr="198.51.100.0/24",
            protocol="tcp",
            dst_ports=[8443],
            description="Allow partner API sessions",
        ),
        Rule(
            rule_id=103,
            action="allow",
            direction="outbound",
            src_cidr="10.0.0.0/24",
            dst_cidr="any",
            protocol="udp",
            dst_ports=[53, 123],
            description="Allow outbound DNS and NTP",
        ),
    ]
