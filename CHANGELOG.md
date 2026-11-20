# Changelog

All notable changes to this project are documented in this file.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and the project uses [Semantic Versioning](https://semver.org/).

## [1.2.0] – unreleased

### Added
- **Variants per family**: Markdown, HTML, PDF and `summary.csv` show the number
  of distinct message texts (`variants`), up to three sample values of the
  masked positions that differ between the messages (`sample_values`, e.g. the
  concrete translation keys; constant values are left out) and `first_seen` /
  `last_seen`. `summary.csv` has these as new last columns
  (`count,family,variants,sample_values,first_seen,last_seen`; sample values
  separated by ` ; `).
- **Custom rules**: `--rules FILE` loads a list of `{pattern, family}` rules
  (regular expression on the first line of an entry → family name, optional
  `ignore_case` and `comment`). They are checked before the built-in rules;
  the first match wins. The family name may reference groups (`\1`,
  `\g<name>`). JSON works without extra packages; `.yaml`/`.yml` needs PyYAML
  (new optional extra `cpe-loganalyzer[yaml]`). Invalid files stop the run with
  a message naming the rule. Example files: `examples/rules.yaml`,
  `examples/rules.json` (ObjectStoreCache warning, LDAP `error code nn`,
  Active Directory bind failures by `data` sub code).
- **JSON summary**: `--json FILE` writes a machine-readable summary
  (`schema_version` 1): time window, parse statistics, totals, and per family
  count, highest level and count per level, first/last seen, variants, sample
  values and how the family was assigned (`custom-rule`, `builtin-rule`,
  `fnrce-code`, `masked-message`).
- Console line `[Families] N families for M entries (…)` on every run.

### Changed
- **More generic masking in the fallback family** (entries without a rule or
  FNRCE code). Masked now: values in single or double quotes (`{STR}`),
  numbers of any length (`{NUM}`, before: 6+ digits), hex values (`{HEX}`),
  IPv4/IPv6 addresses (`{IP}`), host names (`{HOST}`), Unix/Windows/UNC paths
  (`{PATH}`), durations such as `123 ms` (`{DUR}`) and dates/times (`{TIME}`).
  In a fresh Content Cortex 26 sandbox this reduces 68 entries from 56 to 4
  families (the 53 `Missing locale-specific translations for key '…'`
  warnings become one family).
  Deliberately not masked, because they distinguish different problems:
  result codes up to 5 digits after `error code`, `code`, `error`, `rc`,
  `status`, `HTTP`, `SQLCODE`, `SQLSTATE`, `errno` and the Active Directory sub
  code after `AcceptSecurityContext error, data`; message IDs (`CWWKS1100A`,
  `SQL0911N`) and hyphenated vendor codes (`ORA-00001`); upper-case words
  without digits (`SUSPENDED`); dotted versions are `{NUM}`, not `{IP}`.
  **Family names of the fallback path therefore differ from 1.1.0.**
- `{ID}` now requires letters and digits (8+ characters). Before, any
  upper-case word of 8+ letters (e.g. a state such as `STOPPING`) and any
  8+ digit number was masked as `{ID}`; numbers are now `{NUM}`.
- Markdown summary table: pipes in family names are escaped (before, a `|` in a
  fallback family broke the table row).
- `normalize_message()` accepts optional custom rules; the new
  `classify_message()` also returns how the family was assigned.

## [1.1.0] – 2026-11-18

### Added
- Support for **IBM Content Cortex 26**: verified against `ce_system*.log` of a
  Content Cortex 26.0.1 (IF001) CPE container. The CPE file header (also when it
  reappears after a server restart) is recognized explicitly.
- Parse statistics printed on every run (`[Parse] files=… entries=… header=…
  continuation=… unparsed=…`) and a warning for files in which no log entry was
  recognized.
- **Multi-line entries**: continuation lines (stack traces, `Caused by:` chains)
  are attached to the preceding entry (at most 200 lines per entry are kept).
  Markdown, PDF and HTML examples show the first lines of the stack trace.
- New option `--stack-lines N` (default 5, `0` disables the stack excerpt).
- New last column `stacktrace` in `raw_errors.csv` and `examples.csv`
  (first `--stack-lines` lines, newline-separated).
- **Automatic FNRCE families**: specific FileNet codes `FNRCEnnnnE`/`FNRCEnnnnW`
  in the message (or, if none, in the stack trace) form their own family, named
  after the code and – if present – the symbolic name, e.g.
  `FNRCE0051E (E_OBJECT_NOT_FOUND)`. The fixed rules still take precedence; the
  generic category code `FNRCE0000x` is ignored.
- **Docker source**: `--docker-container NAME` copies only matching files from a
  running local container before the analysis (`--docker-copy-mode tar` via
  `docker exec … tar`, or `cp` via `docker cp`). Defaults: remote path
  `/opt/ibm/wlp/usr/servers/defaultServer/FileNet`, pattern `ce_system*.log`;
  `--kube-remote-path`, `--kube-file-pattern` and `--kube-local-path` apply as
  overrides.
- Packaging: `pyproject.toml`, console command `cpe-loganalyzer`, `--version`.
- Test suite (pytest) with synthetic Content Cortex 26 logs and a GitHub
  Actions workflow running it on Python 3.11 and 3.14.

### Changed
- **Python 3.11 or newer is required** (3.10 reached end of life in October
  2026; current matplotlib requires 3.11).
- `requirements.txt` lists only the packages the code imports (`matplotlib`,
  `reportlab`), pinned to current versions; transitive dependencies are left to pip.
- HTML report loads a pinned Chart.js version (4.4.1) instead of "latest".
- `main()` accepts an optional argument list (`main(argv)`) for programmatic use.

### Fixed
- `--until` added the offset to the current time instead of subtracting it, so
  `--since 24h --until 2h` covered *now − 24h … now + 2h*. It now counts back
  from now as documented (*now − 24h … now − 2h*). The default `0h` is unchanged.
- The fixed rules for `FNRCE0043E` and `FNRCE0066E` never matched the code
  itself, because the ID masking replaced it first; they now check the original text.
- HTML report: log messages, family names and the title are HTML-escaped and
  chart labels are emitted as JSON. Before, tag-like text (e.g. `<sweep>`) was
  swallowed by the browser and a double quote in a family name broke the chart script.
- PDF report: log content is escaped. Before, ReportLab silently dropped
  tag-like text (e.g. `<init>` in stack traces) and aborted the report on text
  that looks like its own markup (e.g. an unclosed `<b>`).

### Removed
- README section "New Advanced Features", which described files
  (`advanced_filenet_cpe_log_analyzer.py`, `config.py`) that are not part of the repository.

## [1.0.0] – 2025-10 (untagged)

- Initial release: local and Kubernetes log collection, error families,
  time series, Markdown/CSV/PDF reports, HTML report.
