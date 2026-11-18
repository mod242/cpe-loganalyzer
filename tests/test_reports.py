import csv
import json
import re

import pytest

import filenet_cpe_log_analyzer as la


@pytest.fixture
def run_cli(ccx26_dir, tmp_path):
    def _run(*extra):
        outdir = tmp_path / "out"
        la.main([ccx26_dir, "--pattern", "ce_system*.log", "--outdir", str(outdir), *extra])
        return outdir
    return _run


def _read_csv(path):
    with open(path, newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def test_csv_outputs(run_cli):
    outdir = run_cli()

    summary = _read_csv(outdir / "summary.csv")
    assert list(summary[0].keys()) == ["count", "family"]
    assert sum(int(r["count"]) for r in summary) == 10
    assert {"count": "2", "family": "FNRCE0051E (E_OBJECT_NOT_FOUND)"} in summary

    raw = _read_csv(outdir / "raw_errors.csv")
    # 1.0 columns unchanged and first; stacktrace appended
    assert list(raw[0].keys()) == ["timestamp", "level", "source_file", "message", "stacktrace"]
    assert len(raw) == 10
    getobj = next(r for r in raw if r["timestamp"] == "2026-03-02T09:15:00.300")
    assert getobj["stacktrace"].count("\n") == la.DEFAULT_STACK_LINES - 1
    assert "FNRCE0051E" in getobj["stacktrace"]

    examples = _read_csv(outdir / "examples.csv")
    assert list(examples[0].keys()) == ["family", "timestamp", "source_file", "message", "stacktrace"]
    assert any(e["family"] == "FNRCE0001E (E_ACCESS_DENIED)" and "Caused by" in e["stacktrace"] for e in examples)

    daily = _read_csv(outdir / "timeseries_overall_daily.csv")
    assert daily == [{"date": "2026-03-02", "count": "7"}, {"date": "2026-03-03", "count": "3"}]

    fam_hourly = _read_csv(outdir / "timeseries_family_hourly.csv")
    assert {"datetime_hour": "2026-03-03 07:00", "family": "FNRCE0051E (E_OBJECT_NOT_FOUND)", "count": "1"} in fam_hourly


def test_stack_lines_option(run_cli):
    outdir = run_cli("--stack-lines", "0")
    raw = _read_csv(outdir / "raw_errors.csv")
    assert all(r["stacktrace"] == "" for r in raw)


def test_markdown_output(run_cli):
    outdir = run_cli()
    md = (outdir / "summary_markdown.md").read_text(encoding="utf-8")
    assert md.startswith("# Error overview (consolidated)")
    assert "| 2 | FNRCE0051E (E_OBJECT_NOT_FOUND) |" in md
    # Stack excerpt rendered inside the table cell, HTML-escaped
    assert "<code>at com.example.engine.retrieve.ObjectRetriever.&lt;init&gt;(ObjectRetriever.java:45)</code>" in md
    # Pipes in messages do not break the table
    assert "Queue item \\| dispatch delayed" in md


def test_html_output(run_cli, tmp_path):
    html_path = tmp_path / "report.html"
    run_cli("--html-report", str(html_path), "--html-title", "Test <Report> & Co")
    content = html_path.read_text(encoding="utf-8")

    assert content.startswith("<!DOCTYPE html>")
    assert "<title>Test &lt;Report&gt; &amp; Co</title>" in content
    # Messages and stack traces are escaped
    assert "&lt;init&gt;" in content and "<init>" not in content
    assert "Queue item | dispatch delayed for &lt;sweep&gt; &amp; retry" in content
    assert '<pre class="stacktrace">' in content
    # Chart data is valid JSON
    m = re.search(r"labels: (\[.*?\]),\n", content)
    assert m
    labels = json.loads(m.group(1))
    assert "FNRCE0051E (E_OBJECT_NOT_FOUND)" in labels
    assert '"2026-03-02", "2026-03-03"' in content
    # Total entries card
    assert re.search(r"Total Entries</h3>\s*<div class=\"value\">10</div>", content)


def test_pdf_output(run_cli, tmp_path):
    pdf_path = tmp_path / "report.pdf"
    outdir = run_cli("--pdf-report", str(pdf_path), "--pdf-landscape")
    assert pdf_path.read_bytes().startswith(b"%PDF")
    assert (outdir / "_charts" / "chart_top_families.png").exists()


def test_version_flag(capsys):
    with pytest.raises(SystemExit) as exc:
        la.main(["--version"])
    assert exc.value.code == 0
    assert la.__version__ in capsys.readouterr().out
