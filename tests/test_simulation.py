from __future__ import annotations

import json
from itertools import pairwise

import pytest

from run_simulation import main, simulate
from traffic_simulator import generate_traffic


def test_traffic_is_deterministic_for_a_seed():
    first = generate_traffic(seed=7)
    second = generate_traffic(seed=7)
    assert first == second
    assert first != generate_traffic(seed=8)


def test_traffic_is_time_ordered_with_sequential_ids():
    events = generate_traffic(seed=2026)
    assert [p.event_id for p in events] == list(range(1, len(events) + 1))
    assert all(a.time_ms <= b.time_ms for a, b in pairwise(events))
    assert {p.label for p in events} == {"benign", "malicious"}


@pytest.mark.parametrize("seed", [1, 42, 2026])
def test_default_policy_blocks_all_attacks_and_no_benign_traffic(seed):
    df, _ = simulate(seed)
    assert (df.loc[df["label"] == "malicious", "decision"] == "deny").all()
    assert (df.loc[df["label"] == "benign", "decision"] == "allow").all()


def test_reference_run_matches_documented_numbers():
    df, firewall = simulate(2026)
    assert len(df) == 402
    assert (df["label"] == "malicious").sum() == 138
    assert df["active_circuits"].max() == 24
    assert firewall.rule_hits["STATEFUL_RETURN"] == 218


def test_cli_writes_all_artifacts(tmp_path, capsys):
    main(["--seed", "3", "--output-dir", str(tmp_path)])

    results = tmp_path / "results"
    for name in ["circuit_packet_log.csv", "scenario_breakdown.csv", "simulation_summary.json", "executive_summary.md"]:
        assert (results / name).is_file()

    summary = json.loads((results / "simulation_summary.json").read_text())
    assert summary["seed"] == 3
    assert summary["accuracy_percent"] == 100.0
    assert len(summary["figure_files"]) == 5
    for rel in summary["figure_files"]:
        assert not rel.startswith("/")
        assert (tmp_path / rel).stat().st_size > 0

    assert "Accuracy: 100.0%" in capsys.readouterr().out


def test_cli_rejects_output_dir_that_is_a_file(tmp_path, capsys):
    target = tmp_path / "not-a-dir"
    target.write_text("x")
    with pytest.raises(SystemExit) as excinfo:
        main(["--output-dir", str(target)])
    assert excinfo.value.code == 2
    assert "is not a directory" in capsys.readouterr().err


def test_cli_help_lists_examples(capsys):
    with pytest.raises(SystemExit) as excinfo:
        main(["--help"])
    assert excinfo.value.code == 0
    out = capsys.readouterr().out
    assert "examples:" in out
    assert "--output-dir DIR" in out
