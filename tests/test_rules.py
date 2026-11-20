"""Custom family rules via --rules (JSON and YAML) (1.2.0)."""
import builtins
import csv
import json
import os

import pytest

import filenet_cpe_log_analyzer as la


def write_json(path, data):
    path.write_text(json.dumps(data), encoding="utf-8")
    return str(path)


def test_json_rules_loaded(tmp_path):
    p = write_json(tmp_path / "r.json", {"rules": [
        {"pattern": "cache reloaded", "family": "Cache reload"},
        {"pattern": r"LDAP: error code (\d+)", "family": r"LDAP error code \1", "ignore_case": True},
    ]})
    rules = la.load_rules(p)
    assert [r.family for r in rules] == ["Cache reload", r"LDAP error code \1"]
    assert la.normalize_message("buildNewObjectStoreCache: cache reloaded in transaction", rules=rules) == \
        "Cache reload"
    assert la.normalize_message("[ldap: ERROR CODE 32 - No Such Object]", rules=rules) == "LDAP error code 32"


def test_plain_list_accepted(tmp_path):
    p = write_json(tmp_path / "r.json", [{"pattern": "x", "family": "X"}])
    assert len(la.load_rules(p)) == 1


def test_named_group_reference(tmp_path):
    p = write_json(tmp_path / "r.json", [{"pattern": r"queue (?P<q>\w+) full", "family": r"Queue \g<q> full"}])
    assert la.normalize_message("Dispatcher queue CBR full", rules=la.load_rules(p)) == "Queue CBR full"


def test_rules_take_precedence_over_builtin_rules_and_codes(tmp_path):
    p = write_json(tmp_path / "r.json", [
        {"pattern": "WSIAuthenticatorImpl", "family": "Login failures"},
        {"pattern": "FNRCE0051E", "family": "Not found"},
    ])
    rules = la.load_rules(p)
    assert la.classify_message("[WSIAuthenticatorImpl] login exception", rules=rules) == \
        ("Login failures", la.KIND_CUSTOM)
    assert la.normalize_message("FNRCE0051E: E_OBJECT_NOT_FOUND", rules=rules) == "Not found"


def test_first_matching_rule_wins(tmp_path):
    p = write_json(tmp_path / "r.json", [
        {"pattern": "error code 49", "family": "first"},
        {"pattern": "error code", "family": "second"},
    ])
    assert la.normalize_message("LDAP: error code 49", rules=la.load_rules(p)) == "first"


def test_rules_only_match_the_first_line(tmp_path):
    p = write_json(tmp_path / "r.json", [{"pattern": "E_ACCESS_DENIED", "family": "Denied"}])
    fam = la.normalize_message("Text extraction failed", ["FNRCE0001E: E_ACCESS_DENIED"], rules=la.load_rules(p))
    assert fam == "FNRCE0001E (E_ACCESS_DENIED)"


def test_non_matching_rules_fall_through(tmp_path):
    p = write_json(tmp_path / "r.json", [{"pattern": "nothing matches this", "family": "X"}])
    assert la.normalize_message("Queue has 7 items", rules=la.load_rules(p)) == "Queue has {NUM} items"


@pytest.mark.parametrize("data, error", [
    ({"rules": [{"family": "X"}]}, "'pattern'"),
    ({"rules": [{"pattern": "x"}]}, "'family'"),
    ({"rules": [{"pattern": "(", "family": "X"}]}, "invalid regular expression"),
    ({"rules": [{"pattern": "x", "family": r"\1"}]}, "references group 1"),
    ({"rules": [{"pattern": "(?P<a>x)", "family": r"\g<b>"}]}, "unknown group 'b'"),
    ({"rules": [{"pattern": "x", "family": "X", "level": "WARN"}]}, "unknown key(s): level"),
    ({"rules": ["x"]}, "expected an object"),
    ({"other": []}, "expected a list of rules"),
])
def test_invalid_rules_are_reported(tmp_path, data, error):
    p = write_json(tmp_path / "r.json", data)
    with pytest.raises(SystemExit) as exc:
        la.load_rules(p)
    assert error in str(exc.value)
    assert "rule 1" in str(exc.value) or "expected a list" in str(exc.value)


def test_invalid_json_and_missing_file(tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text("{not json", encoding="utf-8")
    with pytest.raises(SystemExit, match="Invalid JSON"):
        la.load_rules(str(bad))
    with pytest.raises(SystemExit, match="Cannot read"):
        la.load_rules(str(tmp_path / "missing.json"))


def test_yaml_rules_loaded(tmp_path):
    pytest.importorskip("yaml")
    p = tmp_path / "r.yaml"
    p.write_text("rules:\n"
                 "  - pattern: 'LDAP: error code (\\d+)'\n"
                 "    family: 'LDAP error code \\1'\n", encoding="utf-8")
    rules = la.load_rules(str(p))
    assert la.normalize_message("[LDAP: error code 12 - critical extension]", rules=rules) == "LDAP error code 12"


def test_yaml_without_pyyaml(tmp_path, monkeypatch):
    p = tmp_path / "r.yml"
    p.write_text("rules: []\n", encoding="utf-8")
    real_import = builtins.__import__

    def fake_import(name, *args, **kwargs):
        if name == "yaml":
            raise ImportError("No module named 'yaml'")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import)
    with pytest.raises(SystemExit, match="PyYAML is not installed"):
        la.load_rules(str(p))
    # JSON still works without PyYAML
    assert la.load_rules(write_json(tmp_path / "r.json", [])) == []


def test_example_rule_files_are_equivalent(examples_dir):
    pytest.importorskip("yaml")
    from_json = la.load_rules(os.path.join(examples_dir, "rules.json"))
    from_yaml = la.load_rules(os.path.join(examples_dir, "rules.yaml"))
    assert [(r.pattern, r.family) for r in from_json] == [(r.pattern, r.family) for r in from_yaml]


@pytest.mark.parametrize("msg, family", [
    ("buildNewObjectStoreCache: cache reloaded in transaction. Not updating global",
     "ObjectStoreCache reloaded in transaction (MCHE)"),
    ("LDAP search operation failed: [LDAP: error code 12 - critical extension is not recognized]",
     "LDAP error code 12"),
    ("LDAP bind failed: [LDAP: error code 49 - 80090308: LdapErr: DSID-0C09042A, comment: "
     "AcceptSecurityContext error, data 775, v4563]",
     "LDAP error code 49 (AD bind failed, data 775)"),
])
def test_example_rules(examples_dir, msg, family):
    rules = la.load_rules(os.path.join(examples_dir, "rules.json"))
    assert la.normalize_message(msg, rules=rules) == family


@pytest.mark.parametrize("ext", ["json", "yaml"])
def test_cli_rules_option(ccx26_variants_dir, examples_dir, tmp_path, ext):
    if ext == "yaml":
        pytest.importorskip("yaml")
    outdir = tmp_path / "out"
    la.main([ccx26_variants_dir, "--pattern", "ce_system*.log", "--outdir", str(outdir),
             "--rules", os.path.join(examples_dir, f"rules.{ext}")])
    with open(outdir / "summary.csv", newline="", encoding="utf-8") as f:
        counts = {r["family"]: int(r["count"]) for r in csv.DictReader(f)}
    assert counts["ObjectStoreCache reloaded in transaction (MCHE)"] == 3
    assert counts["LDAP error code 12"] == 2
    assert counts["LDAP error code 32"] == 1
    assert counts["LDAP error code 49 (AD bind failed, data 52e)"] == 1
    assert counts["LDAP error code 49 (AD bind failed, data 775)"] == 1
    assert not any(f.startswith("LDAP search operation failed") for f in counts)
