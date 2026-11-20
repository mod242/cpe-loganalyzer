"""Masking of variable message parts in the fallback family (1.2.0)."""
import pytest

import filenet_cpe_log_analyzer as la


def mask(msg):
    return la.mask_message(msg)[0]


def values(msg):
    return la.mask_message(msg)[1]


@pytest.mark.parametrize("msg, template", [
    # quoted values (single and double quotes)
    ("Missing translation for key 'PROP_TestAlpha_DESC'. Using 'en-us' locale instead.",
     "Missing translation for key '{STR}'. Using '{STR}' locale instead."),
    ('Sweep job "Retention Sweep" started', 'Sweep job "{STR}" started'),
    ("Value '' is empty", "Value '{STR}' is empty"),
    # numbers of any length, decimals
    ("Queue has 7 items", "Queue has {NUM} items"),
    ("Queue has 1234567 items", "Queue has {NUM} items"),
    ("Ratio 0.75 reached", "Ratio {NUM} reached"),
    ("attempts: 2.", "attempts: {NUM}."),
    # hex values
    ("Lock held by thread 0x7f3a2b10", "Lock held by thread {HEX}"),
    ("Thread 0000004A blocked", "Thread {HEX} blocked"),
    ("Object com.example.Foo@1a2b3c4d leaked", "Object com.example.Foo@{HEX} leaked"),
    ("Session 7ab1213e53cf4260a247c75f16c2569d expired", "Session {HEX} expired"),
    # IP addresses
    ("Connect from 192.0.2.10 refused", "Connect from {IP} refused"),
    ("Connect to 192.0.2.10:636 refused", "Connect to {IP} refused"),
    ("Connect to 2001:db8:0:0:0:0:2:1 refused", "Connect to {IP} refused"),
    ("Connect to fe80::1ff:fe23:4567:890a refused", "Connect to {IP} refused"),
    ("Listening on ::1", "Listening on {IP}"),
    # host names
    ("Connection to ldap01.example.com timed out", "Connection to {HOST} timed out"),
    ("Final LDAP URL chosen for host [ldap-test] is: ldap://ldap-test:389",
     "Final LDAP URL chosen for host [{HOST}] is: ldap://{HOST}:{NUM}"),
    ("Using hostname=cpe-test-1 for registration", "Using hostname={HOST} for registration"),
    # file paths
    ("Content file /data/os1/content/FN1/doc.dat is not readable", "Content file {PATH} is not readable"),
    (r"Cannot read C:\temp\filenet\doc.dat", "Cannot read {PATH}"),
    (r"Share \\fileserver\content\os1 offline", "Share {PATH} offline"),
    # durations
    ("Request took 123 ms", "Request took {DUR}"),
    ("Request took 123ms", "Request took {DUR}"),
    ("Sweep ran for 2.5 seconds", "Sweep ran for {DUR}"),
    ("Retry in 5s.", "Retry in {DUR}."),
    ("Idle for 3 minutes", "Idle for {DUR}"),
    # dates and times
    ("Scheduled at 2026-03-04T06:00:00.000", "Scheduled at {TIME}"),
    ("Scheduled at 14:20:04.123", "Scheduled at {TIME}"),
    # whitespace is collapsed
    ("Two  spaces\tand tab", "Two spaces and tab"),
])
def test_masking(msg, template):
    assert mask(msg) == template


@pytest.mark.parametrize("msg", [
    # LDAP / SQL / HTTP result codes distinguish errors and stay visible
    "LDAP search operation failed: [LDAP: error code 12 - critical extension is not recognized]",
    "DB2 SQL Error: SQLCODE=-911, SQLSTATE=40001",
    "Request failed with HTTP status 503",
    "Call returned rc=8",
    # vendor error and message IDs
    "SQL error ORA-00001: unique constraint violated",
    "CWWKS1100A: Authentication did not succeed",
    "FNRCE0000E generic category code",
    "SQL0911N The current transaction has been rolled back",
    # upper-case words without digits (states, enum values)
    "Object store state changed to SUSPENDED",
    "Status RUNNING -> STOPPING",
    # apostrophes are not quotes
    "Can't open the server's cache",
    # Java packages are not host names, inner class numbers are not numbers
    "Error in com.filenet.engine.content.Foo",
    "at org.example.local.Worker$2.run",
    # slashes in words are not paths
    "invalid username/password and/or token",
    # numbers glued to words
    "Starting thread [PEPrimary1] for IF001",
])
def test_not_masked(msg):
    assert mask(msg) == " ".join(msg.split())
    assert values(msg) == ()


def test_values_in_order_of_appearance():
    msg = "Connection to ldap01.example.com (192.0.2.10:636) timed out after 3000 ms for user 'tester'"
    assert mask(msg) == "Connection to {HOST} ({IP}) timed out after {DUR} for user '{STR}'"
    assert values(msg) == ("ldap01.example.com", "192.0.2.10:636", "3000 ms", "tester")


def test_quoted_value_wins_over_inner_patterns():
    # GUID, path and number inside quotes are part of the quoted value
    msg = "Folder '/Root/{11111111-2222-3333-4444-555555555555}/2026' locked"
    assert mask(msg) == "Folder '{STR}' locked"
    assert values(msg) == ("/Root/{11111111-2222-3333-4444-555555555555}/2026",)


@pytest.mark.parametrize("msg, template", [
    ("IBM Content Platform Engine Version: 26.0.1.0", "IBM Content Platform Engine Version: {NUM}"),
    ("server info: IBM WebSphere Liberty/26.0.0.10", "server info: IBM WebSphere Liberty/{NUM}"),
    ("Starting PCH Listener, 5.0.0.11-156 built", "Starting PCH Listener, {NUM}-{NUM} built"),
    ("Invalid address 300.1.2.3", "Invalid address {NUM}"),
])
def test_dotted_versions_are_not_ip_addresses(msg, template):
    assert mask(msg) == template


def test_long_code_numbers_are_masked():
    # Only short numbers after a code keyword are kept (as in 1.0, 6+ digits are masked)
    assert mask("Database connection lost, code 1234567") == "Database connection lost, code {NUM}"
    assert mask("Database connection lost, code 17") == "Database connection lost, code 17"


@pytest.mark.parametrize("a, b", [
    # different LDAP result codes
    ("LDAP search operation failed: [LDAP: error code 12 - critical extension is not recognized]",
     "LDAP search operation failed: [LDAP: error code 32 - No Such Object]"),
    # Active Directory sub codes (invalid credentials vs. account locked)
    ("[LDAP: error code 49 - 80090308: LdapErr: DSID-0C09042A, comment: AcceptSecurityContext error, data 52e, v4563]",
     "[LDAP: error code 49 - 80090308: LdapErr: DSID-0C09042A, comment: AcceptSecurityContext error, data 775, v4563]"),
    # different Oracle errors
    ("SQL error ORA-00001: unique constraint violated", "SQL error ORA-01017: unique constraint violated"),
    # different states
    ("Object store state changed to SUSPENDED", "Object store state changed to DEGRADED"),
    # different HTTP status
    ("Request failed with HTTP status 503", "Request failed with HTTP status 404"),
])
def test_distinct_meanings_stay_separate(a, b):
    assert la.normalize_message(a) != la.normalize_message(b)


def test_variants_of_one_message_merge():
    keys = ["PROP_TestAlpha_DESC", "PROP_TestBeta_NAME", "CLASS_TestGamma_DESC"]
    fams = {la.normalize_message(f"Missing locale-specific translations for key '{k}' for the "
                                 f"following locales: kk.  Using 'en-us' locale instead.") for k in keys}
    assert fams == {"Missing locale-specific translations for key '{STR}' for the following locales: kk. "
                    "Using '{STR}' locale instead."}


def test_fixed_rules_and_codes_unaffected_by_masking():
    assert la.normalize_message("[WSIAuthenticatorImpl] login exception: Unable to authenticate user 'tester'") == \
        "WSIAuthenticatorImpl login exception (authentication failures)"
    assert la.normalize_message("FNRCE0051E: E_OBJECT_NOT_FOUND: Object '{X}' not found") == \
        "FNRCE0051E (E_OBJECT_NOT_FOUND)"


@pytest.mark.parametrize("msg, kind", [
    ("TTLStreamReaper could not be scheduled", la.KIND_BUILTIN),
    ("FNRCE0051E: E_OBJECT_NOT_FOUND", la.KIND_FNRCE),
    ("Queue has 7 items", la.KIND_MASKED),
])
def test_classify_kind(msg, kind):
    assert la.classify_message(msg)[1] == kind
