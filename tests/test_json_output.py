"""Machine-readable summary via --json (1.2.0)."""
import json
import os

import filenet_cpe_log_analyzer as la


def run(logdir, tmp_path, *extra):
    json_path = tmp_path / "sub" / "summary.json"
    la.main([logdir, "--pattern", "ce_system*.log", "--outdir", str(tmp_path / "out"),
             "--json", str(json_path), *extra])
    return json.loads(json_path.read_text(encoding="utf-8"))


def test_json_structure(ccx26_variants_dir, tmp_path):
    data = run(ccx26_variants_dir, tmp_path)

    assert data["schema_version"] == 1
    assert data["tool"] == "cpe-loganalyzer"
    assert data["version"] == la.__version__
    assert data["pattern"] == "ce_system*.log"
    assert data["rules_file"] is None
    assert data["time_window"]["since"] is None and data["time_window"]["until"]
    assert data["parse_stats"]["selected"] == 23

    assert data["totals"] == {
        "entries": 23,
        "families": 12,
        "levels": {"ERROR": 5, "WARN": 18},
        "first_seen": "2026-03-04T06:00:01.100",
        "last_seen": "2026-03-04T06:08:01.000",
    }

    fams = data["families"]
    assert len(fams) == 12
    # sorted by count, descending
    assert [f["count"] for f in fams] == sorted((f["count"] for f in fams), reverse=True)
    assert set(fams[0]) == {"family", "count", "level", "levels", "first_seen", "last_seen",
                            "variants", "sample_values", "kind"}
    top = fams[0]
    assert top["family"].startswith("Missing locale-specific translations for key '{STR}'")
    assert top["count"] == 5 and top["variants"] == 4
    assert top["level"] == "WARN" and top["levels"] == {"WARN": 5}
    assert top["sample_values"] == ["PROP_TestAlpha_DESC", "PROP_TestBeta_NAME", "CLASS_TestGamma_DESC"]
    assert top["first_seen"] == "2026-03-04T06:00:01.100"
    assert top["last_seen"] == "2026-03-04T06:00:01.500"
    assert top["kind"] == "masked-message"

    sweep = next(f for f in fams if f["family"].startswith("Sweep job"))
    assert sweep["level"] == "ERROR" and sweep["levels"] == {"ERROR": 1, "WARN": 1}


def test_json_with_rules_and_codes(ccx26_dir, examples_dir, tmp_path):
    rules = os.path.join(examples_dir, "rules.json")
    data = run(ccx26_dir, tmp_path, "--rules", rules)
    assert data["rules_file"] == rules
    kinds = {f["family"]: f["kind"] for f in data["families"]}
    assert kinds["LDAP error code 32"] == "custom-rule"
    assert kinds["FNRCE0051E (E_OBJECT_NOT_FOUND)"] == "fnrce-code"
    assert kinds["WSIAuthenticatorImpl login exception (authentication failures)"] == "builtin-rule"
    assert kinds["Database connection lost, code {NUM}"] == "masked-message"


def test_json_empty_window(ccx26_dir, tmp_path):
    # The synthetic logs are from March 2026: nothing in the last hour
    data = run(ccx26_dir, tmp_path, "--since", "1h")
    assert data["totals"]["entries"] == 0
    assert data["totals"]["first_seen"] is None
    assert data["families"] == []
    assert data["time_window"]["since"] is not None
