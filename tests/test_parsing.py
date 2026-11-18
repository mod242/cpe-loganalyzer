import pytest

import filenet_cpe_log_analyzer as la


def test_log_line_regex_matches_ccx26_format():
    line = "2026-03-02T08:05:10.200 0000002B LDAP FNRCE0000W - WARN  LDAP search failed"
    m = la.LOG_LINE_RE.match(line)
    assert m
    assert m.group("ts") == "2026-03-02T08:05:10.200"
    assert m.group("thread") == "0000002B"
    assert m.group("sub") == "LDAP"
    assert m.group("category") == "FNRCE0000W"
    assert m.group("level") == "WARN"
    assert m.group("msg") == "LDAP search failed"


def test_log_line_regex_matches_error_without_padding():
    m = la.LOG_LINE_RE.match("2026-03-02T09:15:00.300 0000003C API  FNRCE0000E - ERROR Method failed")
    assert m and m.group("level") == "ERROR" and m.group("msg") == "Method failed"


@pytest.mark.parametrize("line", [
    "IBM Content Platform Engine Version: 26.0.1.0, Build: content-engine-26.0.1-0-0 on cpe-test-1",
    "        VirtualServer: cpe-test-1, ServerInstance: cpe-test-1",
    "All times are local; the time zone is Coordinated Universal Time(UTC +00:00)",
    "Date (UTC +00:00)       Thread   Sub  Category     Sev   Message",
])
def test_header_lines_are_recognized_and_not_entries(line):
    assert la.HEADER_LINE_RE.match(line)
    assert not la.LOG_LINE_RE.match(line)


def test_parse_logs_counts_and_levels(ccx26_dir):
    stats = la.new_parse_stats()
    rows = la.parse_logs(ccx26_dir, "ce_system*.log", None, None, stats=stats)

    assert stats == {
        "files": 2,
        "lines": 39,
        "entries": 15,
        "header": 12,
        "blank": 1,
        "continuation": 11,
        "unparsed": 0,
        "selected": 10,
    }
    assert len(rows) == 10
    assert {r["level"] for r in rows} == {"WARN", "ERROR"}
    assert {r["source_file"] for r in rows} == {"ce_system0.log", "ce_system1.log"}


def test_parse_logs_respects_pattern(ccx26_dir):
    rows = la.parse_logs(ccx26_dir, "pe_system*.log", None, None)
    assert len(rows) == 1
    assert rows[0]["source_file"] == "pe_system0.log"


def test_parse_logs_without_matching_files_exits(tmp_path):
    with pytest.raises(SystemExit):
        la.parse_logs(str(tmp_path), "ce_system*.log", None, None)


def test_parse_logs_handles_crlf_and_reports_unparsed(tmp_path):
    (tmp_path / "ce_system0.log").write_bytes(
        b"garbage before first entry\r\n"
        b"2026-03-02T08:00:00.000 0000001A ENG  FNRCE0000E - ERROR Broken thing\r\n"
        b"\tat com.example.Foo.bar(Foo.java:1)\r\n"
    )
    stats = la.new_parse_stats()
    rows = la.parse_logs(str(tmp_path), "ce_system*.log", None, None, stats=stats)
    assert stats["unparsed"] == 1
    assert rows[0]["message"] == "Broken thing"
    assert rows[0]["continuation"] == ["\tat com.example.Foo.bar(Foo.java:1)"]


def test_parse_logs_warns_on_unknown_format(tmp_path, capsys):
    (tmp_path / "ce_system0.log").write_text("[3/2/26 8:00:00:000 UTC] 0000001a E Some other format\n")
    stats = la.new_parse_stats()
    rows = la.parse_logs(str(tmp_path), "ce_system*.log", None, None, stats=stats)
    assert rows == []
    assert stats["unparsed"] == 1
    assert "no log entries recognized" in capsys.readouterr().out
