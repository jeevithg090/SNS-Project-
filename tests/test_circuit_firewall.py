from __future__ import annotations

import pytest

from circuit_firewall import CircuitFirewall, Rule
from conftest import EXTERNAL_WEB, INTERNAL, make_packet


def tcp_handshake(fw: CircuitFirewall, start_ms: int = 0, client_port: int = 40000, server_port: int = 443):
    """Run SYN / SYN-ACK / ACK and return the three decisions."""
    return [
        fw.process_packet(make_packet(INTERNAL, EXTERNAL_WEB, client_port, server_port, flags="SYN", time_ms=start_ms)),
        fw.process_packet(
            make_packet(EXTERNAL_WEB, INTERNAL, server_port, client_port, flags="SYN-ACK", time_ms=start_ms + 10)
        ),
        fw.process_packet(
            make_packet(INTERNAL, EXTERNAL_WEB, client_port, server_port, flags="ACK", time_ms=start_ms + 20)
        ),
    ]


class TestRule:
    def test_matches_on_direction_protocol_cidr_and_port(self):
        rule = Rule(1, "allow", "outbound", "10.0.0.0/24", "any", "tcp", [443])
        assert rule.matches(make_packet(INTERNAL, EXTERNAL_WEB, 40000, 443), "outbound")
        assert not rule.matches(make_packet(INTERNAL, EXTERNAL_WEB, 40000, 80), "outbound")
        assert not rule.matches(make_packet(INTERNAL, EXTERNAL_WEB, 40000, 443, protocol="udp"), "outbound")
        assert not rule.matches(make_packet(INTERNAL, EXTERNAL_WEB, 40000, 443), "inbound")
        assert not rule.matches(make_packet("10.0.1.5", EXTERNAL_WEB, 40000, 443), "outbound")

    def test_empty_port_list_matches_any_port(self):
        rule = Rule(1, "deny", "any", "any", "any", "any")
        assert rule.matches(make_packet(INTERNAL, EXTERNAL_WEB, 1, 65535, protocol="udp"), "outbound")

    def test_values_are_case_insensitive(self):
        rule = Rule(1, "ALLOW", "Outbound", "any", "any", "TCP", [80])
        assert rule.action == "allow"
        assert rule.matches(make_packet(INTERNAL, EXTERNAL_WEB, 40000, 80, protocol="TCP"), "outbound")

    @pytest.mark.parametrize(
        "kwargs",
        [
            {"action": "reject"},
            {"direction": "sideways"},
            {"protocol": "icmp"},
            {"dst_ports": [70000]},
            {"src_cidr": "not-a-cidr"},
        ],
    )
    def test_invalid_rules_are_rejected(self, kwargs):
        base = {
            "rule_id": 9,
            "action": "allow",
            "direction": "outbound",
            "src_cidr": "any",
            "dst_cidr": "any",
            "protocol": "tcp",
        }
        with pytest.raises(ValueError):
            Rule(**{**base, **kwargs})


class TestCircuitFirewall:
    def test_rejects_non_positive_timeout(self):
        with pytest.raises(ValueError):
            CircuitFirewall("10.0.0.0/24", [], circuit_timeout_ms=0)

    def test_outbound_web_session_opens_circuit_and_allows_return_traffic(self, firewall):
        syn, syn_ack, ack = tcp_handshake(firewall)

        assert syn["decision"] == "allow"
        assert syn["rule_id"] == "101"
        assert syn["circuit_state"] == "SYN_SENT"
        assert syn_ack["decision"] == "allow"
        assert syn_ack["rule_id"] == "STATEFUL_RETURN"
        assert syn_ack["circuit_state"] == "SYN_RECEIVED"
        assert ack["circuit_state"] == "ESTABLISHED"
        assert syn["circuit_id"] == syn_ack["circuit_id"] == ack["circuit_id"]
        assert ack["active_circuits"] == 1

    def test_fin_then_ack_closes_circuit(self, firewall):
        tcp_handshake(firewall)
        fin = firewall.process_packet(make_packet(INTERNAL, EXTERNAL_WEB, 40000, 443, flags="FIN-ACK", time_ms=30))
        last = firewall.process_packet(make_packet(EXTERNAL_WEB, INTERNAL, 443, 40000, flags="ACK", time_ms=40))

        assert fin["circuit_state"] == "CLOSING"
        assert last["circuit_state"] == "CLOSED"
        assert last["active_circuits"] == 0
        # The circuit is gone, so a late packet from the server is no longer admitted.
        late = firewall.process_packet(make_packet(EXTERNAL_WEB, INTERNAL, 443, 40000, flags="PSH-ACK", time_ms=50))
        assert late["decision"] == "deny"

    def test_rst_tears_down_circuit(self, firewall):
        tcp_handshake(firewall)
        rst = firewall.process_packet(make_packet(EXTERNAL_WEB, INTERNAL, 443, 40000, flags="RST", time_ms=30))
        assert rst["decision"] == "allow"
        assert rst["circuit_state"] == "RESET"
        assert rst["active_circuits"] == 0

    def test_unsolicited_inbound_is_denied_by_default(self, firewall):
        result = firewall.process_packet(make_packet("45.88.10.10", INTERNAL, 51000, 22))
        assert result["decision"] == "deny"
        assert result["rule_id"] == "DEFAULT_DENY"
        assert result["direction"] == "inbound"

    def test_inbound_allow_rule_cannot_open_new_circuit(self):
        rules = [Rule(1, "allow", "inbound", "any", "10.0.0.0/24", "tcp", [22], "Allow SSH in")]
        fw = CircuitFirewall("10.0.0.0/24", rules)
        result = fw.process_packet(make_packet("45.88.10.10", INTERNAL, 51000, 22))
        assert result["decision"] == "deny"
        assert result["rule_id"] == "INBOUND_NEW_CIRCUIT"
        assert fw.circuit_table == {}

    def test_blocked_subnet_and_risky_egress_rules(self, firewall):
        hostile = firewall.process_packet(make_packet("203.0.113.9", INTERNAL, 51000, 443))
        telnet = firewall.process_packet(make_packet(INTERNAL, "192.0.2.10", 40000, 23))
        assert (hostile["decision"], hostile["rule_id"]) == ("deny", "201")
        assert (telnet["decision"], telnet["rule_id"]) == ("deny", "202")

    def test_partner_api_only_allowed_to_partner_subnet(self, firewall):
        partner = firewall.process_packet(make_packet(INTERNAL, "198.51.100.44", 40000, 8443))
        other = firewall.process_packet(make_packet(INTERNAL, "192.0.2.44", 40001, 8443))
        assert partner["rule_id"] == "102"
        assert partner["decision"] == "allow"
        assert other["decision"] == "deny"

    def test_udp_dns_exchange(self, firewall):
        query = firewall.process_packet(make_packet(INTERNAL, "8.8.8.8", 40000, 53, protocol="udp", flags="QUERY"))
        answer = firewall.process_packet(
            make_packet("8.8.8.8", INTERNAL, 53, 40000, protocol="udp", flags="RESPONSE", time_ms=5)
        )
        spoofed = firewall.process_packet(
            make_packet("1.1.1.1", INTERNAL, 53, 40000, protocol="udp", flags="RESPONSE", time_ms=6)
        )
        assert query["circuit_state"] == "ESTABLISHED"
        assert answer["rule_id"] == "STATEFUL_RETURN"
        assert spoofed["decision"] == "deny"

    def test_lateral_and_transit_traffic_is_out_of_scope(self, firewall):
        lateral = firewall.process_packet(make_packet(INTERNAL, "10.0.0.12", 40000, 445))
        transit = firewall.process_packet(make_packet("192.0.2.1", "192.0.2.2", 40000, 443))
        assert (lateral["direction"], lateral["decision"], lateral["rule_id"]) == ("lateral", "deny", "PERIMETER_ONLY")
        assert (transit["direction"], transit["decision"], transit["rule_id"]) == ("transit", "deny", "PERIMETER_ONLY")

    def test_idle_circuits_expire(self, firewall):
        tcp_handshake(firewall)
        late = firewall.process_packet(make_packet(EXTERNAL_WEB, INTERNAL, 443, 40000, flags="PSH-ACK", time_ms=5000))
        assert late["decision"] == "deny"
        assert firewall.expired_circuit_count == 1

    def test_circuit_ids_stay_unique_after_circuits_close(self, firewall):
        ids = []
        for i in range(3):
            syn, *_ = tcp_handshake(firewall, start_ms=i * 100, client_port=40000 + i)
            ids.append(syn["circuit_id"])
            firewall.process_packet(
                make_packet(EXTERNAL_WEB, INTERNAL, 443, 40000 + i, flags="RST", time_ms=i * 100 + 50)
            )
        assert ids == ["C-0001", "C-0002", "C-0003"]

    def test_rule_hits_are_counted(self, firewall):
        tcp_handshake(firewall)
        firewall.process_packet(make_packet("45.88.10.10", INTERNAL, 51000, 22, time_ms=30))
        assert firewall.rule_hits == {"101": 1, "STATEFUL_RETURN": 2, "DEFAULT_DENY": 1}
