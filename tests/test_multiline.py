import filenet_cpe_log_analyzer as la


def _rows(ccx26_dir):
    return {r["timestamp"]: r for r in la.parse_logs(ccx26_dir, "ce_system*.log", None, None)}


def test_stack_trace_attached_to_previous_entry(ccx26_dir):
    row = _rows(ccx26_dir)["2026-03-02T09:15:00.300"]
    assert row["message"].startswith("Method: getObject failed")
    assert len(row["continuation"]) == 7
    assert row["continuation"][0].startswith("com.filenet.api.exception.EngineRuntimeException: FNRCE0051E")
    assert row["continuation"][2] == "\tat com.example.engine.retrieve.ObjectRetriever.<init>(ObjectRetriever.java:45)"


def test_continuation_of_info_entries_is_not_attached_elsewhere(ccx26_dir):
    rows = _rows(ccx26_dir)
    # Entries directly followed by another entry have no continuation.
    assert rows["2026-03-02T10:20:30.500"]["continuation"] == []
    assert rows["2026-03-02T11:00:00.600"]["continuation"] == []


def test_header_after_restart_ends_entry_and_blank_lines_are_skipped(ccx26_dir):
    rows = _rows(ccx26_dir)
    # The WARN before the repeated header must not swallow header lines.
    assert rows["2026-03-02T12:00:00.700"]["continuation"] == []
    # Entry with "Caused by" chain; the trailing blank line is not stored.
    assert rows["2026-03-02T13:30:00.800"]["continuation"] == [
        "java.lang.IllegalStateException: converter not available",
        "\tat com.example.cbr.Extractor.run(Extractor.java:10)",
        "Caused by: com.filenet.api.exception.EngineRuntimeException: FNRCE0001E: E_ACCESS_DENIED: "
        "The requester has insufficient access rights.",
        "\t... 12 more",
    ]


def test_continuation_is_capped(tmp_path):
    lines = ["2026-03-02T08:00:00.000 0000001A ENG  FNRCE0000E - ERROR Boom"]
    lines += [f"\tat com.example.Frame{i}.run(Frame.java:{i})" for i in range(50)]
    (tmp_path / "ce_system0.log").write_text("\n".join(lines) + "\n")
    stats = la.new_parse_stats()
    rows = la.parse_logs(str(tmp_path), "ce_system*.log", None, None, stats=stats, max_continuation=10)
    assert len(rows[0]["continuation"]) == 10
    assert stats["continuation"] == 50


def test_stack_excerpt(ccx26_dir):
    row = _rows(ccx26_dir)["2026-03-02T09:15:00.300"]
    excerpt = la.stack_excerpt(row, 3)
    assert len(excerpt) == 3
    assert excerpt[1] == "    at com.example.engine.retrieve.ObjectRetriever.fetch(ObjectRetriever.java:120)"
    assert la.stack_excerpt(row, 0) == []


def test_example_rows_contain_stack_excerpt(ccx26_dir):
    rows = la.parse_logs(ccx26_dir, "ce_system*.log", None, None)
    families = {}
    for r in rows:
        families.setdefault(la.normalize_message(r["message"], r["continuation"]), []).append(r)
    examples = la.build_example_rows(families, examples=3, stack_lines=2)
    ex = next(e for e in examples if e["timestamp"] == "2026-03-02T09:15:00.300")
    assert ex["family"] == "FNRCE0051E (E_OBJECT_NOT_FOUND)"
    assert len(ex["stacktrace"]) == 2
