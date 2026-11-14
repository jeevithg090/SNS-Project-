"""Deterministic synthetic traffic: benign sessions plus labelled attack scenarios."""

from __future__ import annotations

from random import Random

from circuit_firewall import Packet


def _add_packet(
    events: list[Packet],
    time_ms: int,
    src_ip: str,
    dst_ip: str,
    src_port: int,
    dst_port: int,
    protocol: str,
    flags: str,
    label: str,
    scenario: str,
) -> None:
    events.append(
        Packet(
            event_id=0,
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
    )


def _add_tcp_session(
    events: list[Packet],
    rng: Random,
    start_ms: int,
    client_ip: str,
    server_ip: str,
    server_port: int,
    label: str,
    scenario: str,
    payload_bursts: int = 2,
) -> int:
    client_port = rng.randint(20000, 59000)
    current = start_ms

    _add_packet(events, current, client_ip, server_ip, client_port, server_port, "tcp", "SYN", label, scenario)
    _add_packet(events, current + 18, server_ip, client_ip, server_port, client_port, "tcp", "SYN-ACK", label, scenario)
    _add_packet(events, current + 32, client_ip, server_ip, client_port, server_port, "tcp", "ACK", label, scenario)

    burst_time = current + 70
    for _ in range(payload_bursts):
        _add_packet(
            events, burst_time, client_ip, server_ip, client_port, server_port, "tcp", "PSH-ACK", label, scenario
        )
        _add_packet(
            events, burst_time + 20, server_ip, client_ip, server_port, client_port, "tcp", "PSH-ACK", label, scenario
        )
        burst_time += rng.randint(55, 85)

    _add_packet(
        events, burst_time + 8, client_ip, server_ip, client_port, server_port, "tcp", "FIN-ACK", label, scenario
    )
    _add_packet(events, burst_time + 24, server_ip, client_ip, server_port, client_port, "tcp", "ACK", label, scenario)

    return burst_time + 35


def _add_udp_exchange(
    events: list[Packet],
    rng: Random,
    start_ms: int,
    client_ip: str,
    server_ip: str,
    dst_port: int,
    label: str,
    scenario: str,
) -> int:
    client_port = rng.randint(20000, 59000)

    _add_packet(events, start_ms, client_ip, server_ip, client_port, dst_port, "udp", "QUERY", label, scenario)
    _add_packet(
        events,
        start_ms + rng.randint(8, 20),
        server_ip,
        client_ip,
        dst_port,
        client_port,
        "udp",
        "RESPONSE",
        label,
        scenario,
    )
    return start_ms + rng.randint(35, 60)


def generate_traffic(seed: int = 2026) -> list[Packet]:
    rng = Random(seed)
    events: list[Packet] = []

    internal_hosts = ["10.0.0.11", "10.0.0.12", "10.0.0.13", "10.0.0.21"]
    web_servers = ["198.51.100.20", "198.51.100.30", "192.0.2.44"]
    dns_servers = ["8.8.8.8", "1.1.1.1"]

    t = 0

    # Benign: regular web browsing sessions.
    for _ in range(16):
        t += rng.randint(55, 105)
        t = _add_tcp_session(
            events,
            rng,
            t,
            client_ip=rng.choice(internal_hosts),
            server_ip=rng.choice(web_servers),
            server_port=rng.choice([80, 443]),
            label="benign",
            scenario="web_browsing",
            payload_bursts=rng.randint(2, 3),
        )

    # Benign: partner API traffic (rule 102).
    for _ in range(6):
        t += rng.randint(45, 95)
        t = _add_tcp_session(
            events,
            rng,
            t,
            client_ip=rng.choice(internal_hosts),
            server_ip="198.51.100.44",
            server_port=8443,
            label="benign",
            scenario="partner_api",
            payload_bursts=2,
        )

    # Benign: DNS queries over UDP (rule 103 + stateful return).
    for _ in range(24):
        t += rng.randint(20, 55)
        t = _add_udp_exchange(
            events,
            rng,
            t,
            client_ip=rng.choice(internal_hosts),
            server_ip=rng.choice(dns_servers),
            dst_port=53,
            label="benign",
            scenario="dns_resolution",
        )

    # Malicious: inbound port scan (unsolicited inbound SYN packets).
    scan_targets = [22, 80, 443, 445, 3389]
    scan_sources = [f"45.88.10.{x}" for x in range(10, 24)]
    attack_time = 340
    for src in scan_sources:
        for target_port in scan_targets:
            attack_time += rng.randint(4, 9)
            _add_packet(
                events,
                attack_time,
                src,
                rng.choice(internal_hosts),
                rng.randint(32000, 65000),
                target_port,
                "tcp",
                "SYN",
                "malicious",
                "inbound_port_scan",
            )

    # Malicious: infected host attempting telnet/RDP/SMB egress.
    attack_time = 650
    risky_ports = [23, 445, 3389]
    for _ in range(24):
        attack_time += rng.randint(12, 24)
        _add_packet(
            events,
            attack_time,
            rng.choice(internal_hosts),
            f"203.0.114.{rng.randint(10, 50)}",
            rng.randint(23000, 54000),
            rng.choice(risky_ports),
            "tcp",
            "SYN",
            "malicious",
            "risky_egress_attempt",
        )

    # Malicious: inbound traffic from explicitly blocked subnet (rule 201).
    attack_time = 1020
    for _ in range(18):
        attack_time += rng.randint(9, 18)
        _add_packet(
            events,
            attack_time,
            f"203.0.113.{rng.randint(1, 200)}",
            rng.choice(internal_hosts),
            rng.randint(30000, 63000),
            rng.choice([80, 443, 22]),
            "tcp",
            "SYN",
            "malicious",
            "blocked_subnet_probe",
        )

    # Malicious: outbound C2 over unsupported port, blocked by implicit deny.
    attack_time = 1300
    for _ in range(14):
        attack_time += rng.randint(15, 26)
        _add_packet(
            events,
            attack_time,
            rng.choice(internal_hosts),
            f"198.18.0.{rng.randint(1, 100)}",
            rng.randint(20000, 60000),
            6667,
            "tcp",
            "SYN",
            "malicious",
            "unknown_c2_channel",
        )

    # Malicious: lateral movement attempts (out of perimeter scope -> deny).
    attack_time = 1700
    for _ in range(12):
        attack_time += rng.randint(14, 25)
        source = rng.choice(internal_hosts)
        target = rng.choice([ip for ip in internal_hosts if ip != source])
        _add_packet(
            events,
            attack_time,
            source,
            target,
            rng.randint(30000, 65000),
            rng.choice([135, 139, 445]),
            "tcp",
            "SYN",
            "malicious",
            "lateral_movement",
        )

    events.sort(key=lambda item: (item.time_ms, item.scenario, item.src_ip, item.dst_ip, item.dst_port))
    for idx, packet in enumerate(events, start=1):
        packet.event_id = idx

    return events
