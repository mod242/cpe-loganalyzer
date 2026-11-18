from collections import Counter

import pytest

import filenet_cpe_log_analyzer as la


@pytest.mark.parametrize("msg, family", [
    ("[WSIAuthenticatorImpl] login exception: Unable to authenticate user testuser",
     "WSIAuthenticatorImpl login exception (authentication failures)"),
    ("MethodName: checkNameCollision, something",
     "checkNameCollision / FNRCE0043E (E_NOT_UNIQUE) – Name already exists"),
    ("MethodName: getContent, content element missing",
     "getContent failures (content retrieval)"),
    ("Something went wrong: E_UNEXPECTED_EXCEPTION",
     "FNRCE0066E (E_UNEXPECTED_EXCEPTION) – unexpected error"),
    ("TTLStreamReaper could not be scheduled",
     "TTLStreamReaper scheduling issue"),
])
def test_fixed_rules_unchanged(msg, family):
    assert la.normalize_message(msg) == family


def test_fixed_rules_match_fnrce_codes_in_original_text():
    # In 1.0 the {ID} masking replaced the code before the rule was checked.
    assert la.normalize_message("Insert failed with FNRCE0043E") == \
        "checkNameCollision / FNRCE0043E (E_NOT_UNIQUE) – Name already exists"
    assert la.normalize_message("Call failed with FNRCE0066E") == \
        "FNRCE0066E (E_UNEXPECTED_EXCEPTION) – unexpected error"


def test_fixed_rules_take_precedence_over_codes():
    msg = "[WSIAuthenticatorImpl] login exception FNRCE0001E: E_ACCESS_DENIED"
    assert la.normalize_message(msg) == "WSIAuthenticatorImpl login exception (authentication failures)"


def test_fixed_rules_ignore_continuation_lines():
    family = la.normalize_message("Request failed", ["\tat com.example.WSIAuthenticatorImpl.login(X.java:1)"])
    assert family == "Request failed"


@pytest.mark.parametrize("msg, family", [
    ("FNRCE0051E: E_OBJECT_NOT_FOUND: Requested item not found. Object identity: {X}",
     "FNRCE0051E (E_OBJECT_NOT_FOUND)"),
    ("Failure FNRCE0001E - E_ACCESS_DENIED for user testuser", "FNRCE0001E (E_ACCESS_DENIED)"),
    ("Sweep job reported FNRCE0222W for object store OS1", "FNRCE0222W"),
])
def test_fnrce_code_in_message(msg, family):
    assert la.normalize_message(msg) == family


def test_fnrce_code_in_stack_trace():
    cont = [
        "java.lang.IllegalStateException: converter not available",
        "Caused by: com.filenet.api.exception.EngineRuntimeException: FNRCE0001E: E_ACCESS_DENIED: denied",
    ]
    assert la.normalize_message("Text extraction failed for document", cont) == "FNRCE0001E (E_ACCESS_DENIED)"


def test_message_code_wins_over_stack_code():
    assert la.normalize_message("FNRCE0222W in sweep", ["FNRCE0051E: E_OBJECT_NOT_FOUND"]) == "FNRCE0222W"


@pytest.mark.parametrize("msg", [
    "Generic FNRCE0000E failure",   # generic category code is not a family
    "Info code FNRCE0051I",          # only E and W codes
    "XFNRCE0051E glued to a word",   # word boundary
])
def test_non_matching_codes_fall_back(msg):
    assert not la.normalize_message(msg).startswith("FNRCE")


def test_fallback_masks_ids_and_numbers():
    assert la.normalize_message("Database connection lost, code 1234567") == "Database connection lost, code {NUM}"
    assert la.normalize_message("Object {11111111-2222-3333-4444-555555555555} locked") == "Object {{GUID}} locked"


def test_fallback_truncates_long_messages():
    fam = la.normalize_message("x " * 200)
    assert len(fam) == 141 and fam.endswith("…")


def test_families_for_synthetic_logs(ccx26_dir):
    rows = la.parse_logs(ccx26_dir, "ce_system*.log", None, None)
    families = Counter(la.normalize_message(r["message"], r["continuation"]) for r in rows)
    assert families == {
        "FNRCE0051E (E_OBJECT_NOT_FOUND)": 2,
        "LDAP search operation failed: [LDAP: error code 32 - No Such Object]": 2,
        "WSIAuthenticatorImpl login exception (authentication failures)": 1,
        "checkNameCollision / FNRCE0043E (E_NOT_UNIQUE) – Name already exists": 1,
        "Queue item | dispatch delayed for <sweep> & retry": 1,
        "FNRCE0001E (E_ACCESS_DENIED)": 1,
        "FNRCE0222W": 1,
        "Database connection lost, code {NUM}": 1,
    }
