from datetime import datetime, timedelta

import pytest

import filenet_cpe_log_analyzer as la


@pytest.mark.parametrize("expr, expected", [
    ("24h", timedelta(hours=24)),
    ("2d", timedelta(days=2)),
    ("3h30m", timedelta(hours=3, minutes=30)),
    ("1w2d", timedelta(weeks=1, days=2)),
    ("48h15m10s", timedelta(hours=48, minutes=15, seconds=10)),
    ("0h", timedelta(0)),
    ("now", timedelta(0)),
    (" 2D6H ", timedelta(days=2, hours=6)),
])
def test_parse_relative_delta(expr, expected):
    assert la.parse_relative_delta(expr) == expected


def test_parse_relative_delta_none():
    assert la.parse_relative_delta(None) is None


def test_parse_relative_delta_invalid():
    with pytest.raises(ValueError):
        la.parse_relative_delta("yesterday")


def test_compute_time_window_counts_back_from_now():
    now = datetime(2026, 3, 3, 12, 0, 0)
    since_dt, until_dt = la.compute_time_window("24h", "2h", now=now)
    assert since_dt == datetime(2026, 3, 2, 12, 0, 0)
    assert until_dt == datetime(2026, 3, 3, 10, 0, 0)


def test_compute_time_window_defaults():
    now = datetime(2026, 3, 3, 12, 0, 0)
    assert la.compute_time_window(None, "0h", now=now) == (None, now)


def test_compute_time_window_rejects_inverted_window():
    with pytest.raises(SystemExit):
        la.compute_time_window("1h", "2h", now=datetime(2026, 3, 3, 12, 0, 0))


def test_parse_logs_time_window(ccx26_dir):
    since_dt = datetime(2026, 3, 2, 9, 0, 0)
    until_dt = datetime(2026, 3, 2, 12, 0, 0)
    rows = la.parse_logs(ccx26_dir, "ce_system*.log", since_dt, until_dt)
    assert [r["timestamp"] for r in rows] == [
        "2026-03-02T09:15:00.300",
        "2026-03-02T10:20:30.500",
        "2026-03-02T11:00:00.600",
    ]


def test_parse_logs_time_window_drops_continuation_of_excluded_entries(ccx26_dir):
    # The ERROR at 09:15 with its stack trace is outside the window; its
    # continuation lines must not leak into the next selected entry.
    since_dt = datetime(2026, 3, 2, 10, 0, 0)
    until_dt = datetime(2026, 3, 2, 10, 30, 0)
    rows = la.parse_logs(ccx26_dir, "ce_system*.log", since_dt, until_dt)
    assert len(rows) == 1
    assert rows[0]["continuation"] == []
