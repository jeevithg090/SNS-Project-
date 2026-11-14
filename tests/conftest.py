from __future__ import annotations

import pytest

from circuit_firewall import CircuitFirewall, Packet, build_default_rules

INTERNAL = "10.0.0.11"
EXTERNAL_WEB = "198.51.100.20"


def make_packet(
    src_ip: str,
    dst_ip: str,
    src_port: int,
    dst_port: int,
    protocol: str = "tcp",
    flags: str = "SYN",
    time_ms: int = 0,
    label: str = "benign",
    scenario: str = "test",
    event_id: int = 1,
) -> Packet:
    return Packet(
        event_id=event_id,
        time_ms=time_ms,
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=src_port,
        dst_port=dst_port,
        protocol=protocol,
        flags=flags,
        label=label,
        scenario=scenario,
    )


@pytest.fixture
def firewall() -> CircuitFirewall:
    return CircuitFirewall(internal_cidr="10.0.0.0/24", rules=build_default_rules(), circuit_timeout_ms=1000)
