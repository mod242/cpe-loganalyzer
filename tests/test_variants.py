"""Variant counting, sample values and first/last seen per family (1.2.0)."""
import csv

import pytest

import filenet_cpe_log_analyzer as la

TRANSLATIONS = ("Missing locale-specific translations for key '{STR}' for the following locales: kk. "
                "Using '{STR}' locale instead.")


@pytest.fixture
def summary(ccx26_variants_dir):
    rows = la.parse_logs(ccx26_variants_dir, "ce_system*.log", None, None)
    families, kinds = {}, {}
    for r in rows:
        fam, kind = la.classify_message(r["message"], r["continuation"])
        families.setdefault(fam, []).append(r)
        kinds.setdefault(fam, kind)
    return {s["family"]: s for s in la.summarize_families(families, kinds)}


def test_family_count(summary):
    # 23 WARN/ERROR entries -> 12 families (each line would be its own family without masking)
    assert sum(s["count"] for s in summary.values()) == 23
    assert len(summary) == 12


def test_variants_and_samples(summary):
    s = summary[TRANSLATIONS]
    assert s["count"] == 5
    assert s["variants"] == 4                     # PROP_TestAlpha_DESC occurs twice
    # only the varying key is shown, not the constant 'en-us'; first three distinct keys in time order
    assert s["sample_values"] == ["PROP_TestAlpha_DESC", "PROP_TestBeta_NAME", "CLASS_TestGamma_DESC"]
    assert s["first_seen"] == "2026-03-04T06:00:01.100"
    assert s["last_seen"] == "2026-03-04T06:00:01.500"
    assert s["level"] == "WARN" and s["levels"] == {"WARN": 5}
    assert s["kind"] == la.KIND_MASKED


def test_several_varying_positions_are_joined(summary):
    s = summary["Connection to {HOST} ({IP}) timed out after {DUR}"]
    assert s["variants"] == 2
    assert s["sample_values"] == ["ldap01.example.com / 192.0.2.10:636 / 3000 ms",
                                  "ldap02.example.com / 192.0.2.11:636 / 5000 ms"]


def test_identical_messages_have_one_variant_and_no_samples(summary):
    s = summary["buildNewObjectStoreCache: cache reloaded in transaction. Not updating global"]
    assert (s["count"], s["variants"], s["sample_values"]) == (3, 1, [])
    assert (s["first_seen"], s["last_seen"]) == ("2026-03-04T06:02:00.100", "2026-03-04T06:02:00.300")


def test_mixed_levels(summary):
    s = summary['Sweep job "{STR}" ran for {DUR}']
    assert s["level"] == "ERROR"
    assert s["levels"] == {"ERROR": 1, "WARN": 1}
    assert s["sample_values"] == ["Retention Sweep / 12 seconds", "Disposal Sweep / 95 seconds"]


def test_distinct_errors_stay_separate(summary):
    assert "LDAP search operation failed: [LDAP: error code 12 - critical extension is not recognized]" in summary
    assert "LDAP search operation failed: [LDAP: error code 32 - No Such Object]" in summary
    assert sum(1 for f in summary if "AcceptSecurityContext" in f) == 2      # data 52e / data 775
    assert sum(1 for f in summary if f.startswith("SQL error ORA-")) == 2   # ORA-00001 / ORA-01017


def test_variant_samples_limit_and_truncation():
    msgs = [f"Key '{'K' * 100}{i}' missing" for i in range(5)]
    samples = la.variant_samples(msgs)
    assert len(samples) == la.MAX_SAMPLE_VALUES
    assert all(len(s) == la.MAX_SAMPLE_VALUE_LEN and "…" in s for s in samples)
    # values that differ only at the end stay distinguishable
    assert [s[-1] for s in samples] == ["0", "1", "2"]


def test_variant_samples_for_rule_family_with_different_templates():
    # A rule family can contain different message texts; samples come from each text's varying parts.
    msgs = ["Key 'a' missing", "Key 'b' missing", "Other text without values"]
    assert la.variant_samples(msgs) == ["a", "b"]


def test_report_outputs_contain_variant_columns(ccx26_variants_dir, tmp_path):
    outdir = tmp_path / "out"
    html_path = tmp_path / "report.html"
    pdf_path = tmp_path / "report.pdf"
    la.main([ccx26_variants_dir, "--pattern", "ce_system*.log", "--outdir", str(outdir),
             "--html-report", str(html_path), "--pdf-report", str(pdf_path)])

    with open(outdir / "summary.csv", newline="", encoding="utf-8") as f:
        rows = {r["family"]: r for r in csv.DictReader(f)}
    row = rows[TRANSLATIONS]
    assert row["count"] == "5" and row["variants"] == "4"
    assert row["sample_values"] == "PROP_TestAlpha_DESC ; PROP_TestBeta_NAME ; CLASS_TestGamma_DESC"
    assert row["first_seen"] == "2026-03-04T06:00:01.100"
    assert row["last_seen"] == "2026-03-04T06:00:01.500"

    md = (outdir / "summary_markdown.md").read_text(encoding="utf-8")
    assert "| Count | Error family | Variants | Sample values | First seen | Last seen |" in md
    assert (f"| 5 | {TRANSLATIONS} | 4 | `PROP_TestAlpha_DESC`, `PROP_TestBeta_NAME`, "
            "`CLASS_TestGamma_DESC` | 2026-03-04T06:00:01.100 | 2026-03-04T06:00:01.500 |") in md

    content = html_path.read_text(encoding="utf-8")
    assert "<th>Variants</th>" in content and "<th>Last seen</th>" in content
    assert "<code>PROP_TestBeta_NAME</code>" in content
    assert '<td class="seen">2026-03-04T06:00:01.500</td>' in content
    assert 'colspan="7"' in content

    assert pdf_path.read_bytes().startswith(b"%PDF")
