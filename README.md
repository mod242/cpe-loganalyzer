# FileNet CPE Log Analyzer

A **Kubernetes- and Docker-aware log analysis tool** for IBM FileNet Content Platform Engine (CPE) and **IBM Content Cortex 26**.

This utility helps you analyze CPE log files (`ce_system*.log`) — from **local directories**, directly from **OpenShift / Kubernetes** pods, or from a **local Docker container**.  
It automatically **collects**, **filters**, and **summarizes** log errors and warnings, then generates human-readable reports (Markdown, CSV, PDF with charts, and HTML).

It is designed for **containerized FileNet deployments** (e.g., Cloud Pak for Business Automation, IBM Content Cortex) and is especially useful for:
- Migration & health-check scenarios
- Offline analysis on developer notebooks
- Environments with autoscaling or ephemeral pods

---

## ✨ What's new in 1.2.0

- **Better grouping of similar messages** – the fallback family masks quoted values, numbers of any length, hex values, IP addresses, host names, file paths, durations and timestamps. Messages that differ only in such values become one family; in a fresh Content Cortex 26 sandbox the 53 warnings `Missing locale-specific translations for key '…'` are now 1 family instead of 53 (68 entries: 56 → 4 families). Values that tell different problems apart stay visible: LDAP/SQL/HTTP result codes (`error code 32`), vendor message IDs (`ORA-00001`, `CWWKS1100A`) and upper-case states (`SUSPENDED`).
- **Variants, sample values, first/last seen** per family in Markdown, HTML, PDF and `summary.csv` (new last columns `variants`, `sample_values`, `first_seen`, `last_seen`) – e.g. the concrete translation keys of the merged warning.
- **Custom rules without code changes** – `--rules rules.json|rules.yaml` maps regular expressions to family names; they are checked before the built-in rules. Example: [`examples/rules.yaml`](./examples/rules.yaml) / [`examples/rules.json`](./examples/rules.json).
- **JSON summary** – `--json summary.json` writes families with count, level, first/last seen, variants and sample values for monitoring or CI.

See [CHANGELOG.md](./CHANGELOG.md) for details.

## What's new in 1.1.0

- **IBM Content Cortex 26 support** – verified against `ce_system*.log` files of a Content Cortex 26.0.1 (IF001) CPE container. The log line format is unchanged; the CPE file header is now recognized explicitly, and every run prints parse statistics (entries, header, continuation and unparsed lines) so format changes become visible.
- **Multi-line entries** – stack traces and other continuation lines are attached to the preceding entry. The examples in Markdown, PDF and HTML show the first lines of the stack trace (`--stack-lines`, default 5); `raw_errors.csv` and `examples.csv` have a new last column `stacktrace`.
- **Automatic FNRCE families** – in addition to the fixed rules, specific FileNet error codes (`FNRCEnnnnE` / `FNRCEnnnnW`) in the message or in the stack trace become their own family, e.g. `FNRCE0051E (E_OBJECT_NOT_FOUND)`.
- **Docker as log source** – `--docker-container <name>` copies only the matching logs out of a running local container (e.g. the `cpe` container of a container-demo setup).
- **pip-installable** – `pyproject.toml` with the command `cpe-loganalyzer`; Python 3.11+.
- **Fixes** – `--until` now counts back from now (as documented); HTML and PDF reports escape log content; the fixed rules for `FNRCE0043E`/`FNRCE0066E` match the codes again.

---

## 📦 Installation

### 1. Python & the analyzer
Python **3.11 or newer** is required.

Install as a command-line tool with pip (provides the `cpe-loganalyzer` command):

```bash
git clone https://github.com/mod242/cpe-loganalyzer.git
cd cpe-loganalyzer
pip install .
cpe-loganalyzer --version
```

or directly from GitHub:

```bash
pip install git+https://github.com/mod242/cpe-loganalyzer.git
```

YAML rule files (`--rules rules.yaml`) need PyYAML, which is optional:

```bash
pip install ".[yaml]"
```

Running the script without installing it still works:

```bash
pip install -r requirements.txt
python filenet_cpe_log_analyzer.py --help
```

`cpe-loganalyzer <args>` and `python filenet_cpe_log_analyzer.py <args>` are equivalent; the examples below use the script form.

### 2. Optional: Kubernetes CLI

If you want to collect logs directly from a running CPE pod, install and configure `kubectl`:

```bash
# Verify your cluster connection
kubectl get pods -n filenet
```

### 3. Optional: Docker CLI

To collect logs from a local container (`--docker-container`), the `docker` command must be available and the container must be running. The container needs `sh`, `find` and `tar` (the IBM CPE images include them).

---

## 🚀 Quick Start

### Clone and run
```bash
git clone https://github.com/mod242/cpe-loganalyzer.git
cd cpe-loganalyzer
chmod +x filenet_cpe_log_analyzer.py
```

---

## 🧩 Local Analysis Example

Analyze existing local FileNet CPE logs (e.g. from `/opt/ibm/wlp/usr/servers/defaultServer/FileNet`):

```bash
python filenet_cpe_log_analyzer.py /home/user/logs \
  --pattern "ce_system*.log" \
  --since "24h" \
  --outdir ./results \
  --pdf-report ./results/filenet_cpe_report.pdf \
  --pdf-title "FileNet CPE Error Summary (Last 24h)" \
  --pdf-landscape
```

This will:
1. Scan logs recursively
2. Extract all WARN and ERROR entries from the last 24 hours
3. Consolidate frequent errors
4. Generate:
   - `summary_markdown.md`
   - CSV exports (summary, examples, timeseries)
   - `filenet_cpe_report.pdf` with charts and formatted tables

---

## ☸️ Kubernetes / OpenShift Integration

If your FileNet CPE runs on **Kubernetes/OpenShift**, the script can directly copy matching log files from a running pod.

### Example (robust TAR mode)

```bash
python filenet_cpe_log_analyzer.py /home/user/analyze \
  --kube-sync \
  --kube-single \
  --kube-flatten \
  --kube-namespace filenet \
  --kube-pod-prefix demo-cpe-deploy \
  --kube-container demo-cpe-deploy \
  --kube-remote-path /opt/ibm/wlp/usr/servers/defaultServer/FileNet \
  --kube-local-path /home/user/analyze \
  --kube-file-pattern "ce_system*.log" \
  --pattern "ce_system*.log" \
  --since "24h" \
  --outdir ./results \
  --pdf-report ./results/filenet_cpe_report.pdf \
  --html-report ./results/filenet_cpe_report.html \
  --pdf-title "FileNet CPE Kubernetes Logs – Last 24h" \
  --html-title "FileNet CPE Kubernetes Logs – Last 24h" \
  --pdf-landscape
```

### What happens:
1. Finds the running pod matching prefix `demo-cpe-deploy-*` in namespace `filenet`
2. Executes:
   ```bash
   find . -type f -name "ce_system*.log" -print0 | \
   tar --null -T - -czf - | tar -xzf - -C <localdir>
   ```
   (Only matching logs are streamed locally)
3. Analyzes the downloaded files
4. Produces Markdown, CSV, PDF, and HTML reports

---

## 🐳 Docker Integration (e.g. IBM Content Cortex 26 container-demo)

If CPE runs as a local Docker container — for example the `cpe` container of a container-demo / `cpit.sh` setup with IBM Content Cortex 26 — the script copies **only** the matching log files out of the container and analyzes them:

```bash
python filenet_cpe_log_analyzer.py ./cpe-logs \
  --docker-container cpe \
  --pattern "ce_system*.log" \
  --since "24h" \
  --outdir ./results \
  --pdf-report ./results/cpe_report.pdf \
  --html-report ./results/cpe_report.html \
  --pdf-title "Content Cortex 26 – CPE Logs (Last 24h)" \
  --html-title "Content Cortex 26 – CPE Logs (Last 24h)" \
  --pdf-landscape
```

### What happens:
1. Checks that container `cpe` is running (`docker inspect`)
2. Executes inside the container (default mode `--docker-copy-mode tar`):
   ```bash
   cd /opt/ibm/wlp/usr/servers/defaultServer/FileNet && \
   find . -type f -name "ce_system*.log" -print0 | tar --null -T - -czf -
   ```
   and extracts the stream locally into `./cpe-logs` (keeping the `<server-name>/ce_system0.log` sub folders; no local `tar` needed)
3. Analyzes the copied files and writes the reports

Defaults and overrides:

| Setting | Default | Override |
|---------|---------|----------|
| Path inside the container | `/opt/ibm/wlp/usr/servers/defaultServer/FileNet` | `--kube-remote-path` |
| Files to copy | `ce_system*.log` | `--kube-file-pattern` |
| Local target directory | `logdir` argument | `--kube-local-path` |
| Copy method | `tar` (docker exec + tar stream) | `--docker-copy-mode cp` (docker cp per file) |

> **Tip (container-demo):** the CPE `FileNet` directory is also mounted on the host (`~/cpit_data/cpe_data/FileNet`). Instead of copying from the container you can analyze it in place:
> `python filenet_cpe_log_analyzer.py ~/cpit_data/cpe_data/FileNet --pattern "ce_system*.log" --outdir ./results`

> **Time zone:** CPE writes timestamps in the container's time zone (UTC in the IBM images, see the log header). `--since`/`--until` are compared with the local time of the machine running the analyzer, so on a host in another time zone the window is shifted by the offset.

---

### Quick HTML Export Examples

```bash
# Generate HTML report for local logs
python filenet_cpe_log_analyzer.py /path/to/logs \
  --html-report ./error_analysis.html

# HTML report with custom title and time window
python filenet_cpe_log_analyzer.py /path/to/logs \
  --since "7d" \
  --html-report ./weekly_report.html \
  --html-title "Weekly FileNet Error Analysis"

# Generate both PDF and HTML reports
python filenet_cpe_log_analyzer.py /path/to/logs \
  --pdf-report ./report.pdf \
  --html-report ./report.html \
  --outdir ./analysis_results
```

---

## 📊 Sample Output Formats

### PDF Report
The generated PDF includes:

- Title page with timestamp (and optional logo)
- **Top error families** (wrapped labels)
- **Error count per day/hour**
- **Consolidated error table** (with variants, sample values, first/last seen)
- **Example log messages per family** (with the first lines of the stack trace)

**Charts included:**
- Top error families (horizontal bar chart)
- Errors per day
- Errors per hour

### Interactive HTML Report
The HTML report provides a modern, interactive web-based view with:

- **📈 Interactive Charts**: Bar charts and line graphs using Chart.js
- **📊 Statistics Dashboard**: Key metrics displayed in attractive cards
- **🔍 Expandable Error Details**: Click "Show Examples" to view actual log entries including a stack trace excerpt
- **📱 Responsive Design**: Works on desktop, tablet, and mobile
- **🎨 Professional Styling**: Modern UI with gradients and shadows
- **⚡ Fast Loading**: Self-contained HTML with embedded CSS and JavaScript

### Example snippet:

| Count | Error Family |
|-------|---------------|
| 850 | WSIAuthenticatorImpl login exception (authentication failures) |
| 548 | checkNameCollision / FNRCE0043E (E_NOT_UNIQUE) – Name already exists |
| 10  | getContent failures (content retrieval) |

**HTML Features:**
- Interactive charts (hover for details)
- Click to expand/collapse example log entries
- Statistics cards showing totals and trends
- Professional color scheme and typography

---

## ⚙️ Command Reference

### Core options

| Option | Description |
|--------|--------------|
| `--pattern` | File glob pattern (default: `*.log`) |
| `--since` | Relative start (e.g., `24h`, `2d6h`) |
| `--until` | Relative end, counted back from now (default: `0h` = now; `2h` = two hours ago) |
| `--outdir` | Directory for reports and CSVs |
| `--examples` | Example rows per family (default: 3) |
| `--stack-lines` | Stack trace lines shown per example and in the CSV `stacktrace` column (default: 5, `0` = none) |
| `--version` | Print the version and exit |

### Error families

Each WARN/ERROR entry is assigned to a family in this order:

1. Custom rules from `--rules` (first matching rule wins), see below.
2. Fixed rules on the first line of the entry (e.g. `WSIAuthenticatorImpl login exception`, `checkNameCollision / FNRCE0043E`, `getContent failures`).
3. The first specific FileNet code `FNRCEnnnnE`/`FNRCEnnnnW` in the message, otherwise in the stack trace. The family is named after the code, plus the symbolic name if it follows the code: `FNRCE0051E (E_OBJECT_NOT_FOUND)`. The generic category code `FNRCE0000x` of the log column is ignored.
4. Otherwise the first line of the message with variable parts replaced by placeholders (cut to 140 characters):

| Placeholder | Replaces | Example |
|-------------|----------|---------|
| `'{STR}'`, `"{STR}"` | values in single or double quotes (apostrophes as in `can't` are not quotes) | `key 'PROP_X_DESC'` → `key '{STR}'` |
| `{GUID}` | GUIDs | `{F79D75DA-…}` → `{{GUID}}` |
| `{HOST}` | host names in URLs, after `host [`/`host=`/`hostname:`, and fully qualified names with a common TLD (Java package names are left alone) | `ldap://ldap01:389` → `ldap://{HOST}:{NUM}` |
| `{IP}` | IPv4 (with optional port) and IPv6 addresses | `192.0.2.10:636` → `{IP}` |
| `{PATH}` | Unix, Windows and UNC paths | `/opt/ibm/…/ce_system0.log` → `{PATH}` |
| `{TIME}` | dates and times | `2026-03-04T06:00:00` → `{TIME}` |
| `{DUR}` | durations | `123 ms`, `2.5 seconds`, `5s` → `{DUR}` |
| `{HEX}` | `0x…`, hash codes after `@`, hex strings of 8+ characters with letters and digits | `0x7f3a2b10` → `{HEX}` |
| `{ID}` | upper-case tokens of 8+ characters with letters and digits | `DT502929` → `{ID}` |
| `{NUM}` | other numbers of any length, including dotted versions | `154352`, `26.0.1.0` → `{NUM}` |

Not masked, because they distinguish messages that mean different things:

- result codes with up to 5 digits after `error code`, `code`, `error`, `rc`, `status`, `HTTP`, `SQLCODE`, `SQLSTATE`, `errno` and the Active Directory sub code after `AcceptSecurityContext error, data` (`LDAP: error code 12` and `LDAP: error code 32` stay two families),
- message IDs such as `FNRCE0000E`, `CWWKS1100A`, `SQL0911N` and codes with a letter prefix and hyphen such as `ORA-00001`,
- upper-case words without digits (`SUSPENDED`, `STOPPING`), numbers glued to words (`PEPrimary1`, `IF001`) and inner class numbers (`Worker$2`).

Per family the reports show the number of **variants** (distinct message texts), up to three **sample values** of the masked positions that differ between the messages (constant values are left out; several positions are joined with ` / `), and the timestamps **first seen** / **last seen**.

> Family names of the fallback path changed in 1.2.0 (more placeholders). Compare per-family time series across versions with that in mind.

### Grouping and JSON options

| Option | Description |
|--------|--------------|
| `--rules FILE` | Custom family rules (JSON; YAML with PyYAML installed), checked before the built-in rules |
| `--json FILE` | Write a machine-readable JSON summary |

#### Custom rules (`--rules`)

A rules file is a list of regular expressions (Python syntax, searched in the first line of an entry) with the family name to use. Rules are checked top to bottom; the first match wins. The family name can reference groups of the pattern with `\1` or `\g<name>`. Optional keys: `ignore_case` (default `false`) and `comment`.

```yaml
# examples/rules.yaml
rules:
  - pattern: 'buildNewObjectStoreCache: cache reloaded in transaction'
    family: 'ObjectStoreCache reloaded in transaction (MCHE)'
  - pattern: 'LDAP: error code 49 .*AcceptSecurityContext error, data (\w+)'
    family: 'LDAP error code 49 (AD bind failed, data \1)'
  - pattern: 'LDAP: error code (\d+)'
    family: 'LDAP error code \1'
```

The same as JSON (no extra package needed; note the doubled backslashes):

```json
{
  "rules": [
    {"pattern": "buildNewObjectStoreCache: cache reloaded in transaction",
     "family": "ObjectStoreCache reloaded in transaction (MCHE)"},
    {"pattern": "LDAP: error code (\\d+)", "family": "LDAP error code \\1"}
  ]
}
```

```bash
python filenet_cpe_log_analyzer.py ./cpe-logs --pattern "ce_system*.log" \
  --rules examples/rules.json --outdir ./results
```

An invalid file (JSON/YAML syntax, regular expression, unknown key, reference to a missing group) stops the run with a message naming the rule. `.yaml`/`.yml` files without PyYAML installed stop with a hint to install it or to use JSON.

#### JSON summary (`--json`)

```bash
python filenet_cpe_log_analyzer.py ./cpe-logs --pattern "ce_system*.log" --since 24h \
  --outdir ./results --json ./results/summary.json
```

Output for the Content Cortex 26 sandbox from above (all available data, no `--since`; only the first family shown):

```json
{
  "schema_version": 1,
  "tool": "cpe-loganalyzer",
  "version": "1.2.0",
  "generated_at": "2026-11-20T17:33:05",
  "time_window": {"since": null, "until": "2026-11-20T17:33:04"},
  "pattern": "ce_system*.log",
  "rules_file": null,
  "parse_stats": {"files": 1, "lines": 137, "entries": 133, "header": 4, "blank": 0,
                  "continuation": 0, "unparsed": 0, "selected": 68},
  "totals": {"entries": 68, "families": 4, "levels": {"WARN": 68},
             "first_seen": "2026-11-18T14:16:36.199", "last_seen": "2026-11-18T14:20:04.301"},
  "families": [
    {
      "family": "Missing locale-specific translations for key '{STR}' for the following locales: kk. Using '{STR}' locale instead.",
      "count": 53,
      "level": "WARN",
      "levels": {"WARN": 53},
      "first_seen": "2026-11-18T14:16:36.199",
      "last_seen": "2026-11-18T14:16:36.320",
      "variants": 53,
      "sample_values": ["PROP_GroupSearchFilter_DESC", "PROP_TSMMinimumRetention_DESC", "PROP_RetrievalNameExtension_DESC"],
      "kind": "masked-message"
    }
  ]
}
```

`families` is sorted by count (descending). `level` is the highest level in the family (`ERROR` before `WARN`), `levels` the count per level. `kind` tells how the family was assigned: `custom-rule`, `builtin-rule`, `fnrce-code` or `masked-message`. Timestamps are in the log's time zone. Example for CI: fail if any ERROR family exists:

```bash
jq -e '[.families[] | select(.level == "ERROR")] | length == 0' ./results/summary.json
```

### PDF options

| Option | Description |
|--------|--------------|
| `--pdf-report` | Output path for PDF file |
| `--pdf-title` | Custom report title |
| `--pdf-logo` | Optional logo image for title page |
| `--pdf-landscape` | Generate PDF in landscape orientation (recommended) |

### HTML options

| Option | Description |
|--------|--------------|
| `--html-report` | Output path for HTML file (e.g., `./report.html`) |
| `--html-title` | Custom report title for HTML output |

### Kubernetes options

| Option | Description |
|--------|--------------|
| `--kube-sync` | Copy logs from Kubernetes before analysis |
| `--kube-namespace` | Namespace (e.g. `filenet`) |
| `--kube-pod-prefix` | Pod name prefix |
| `--kube-container` | Container name |
| `--kube-remote-path` | Path inside container |
| `--kube-local-path` | Local destination directory |
| `--kube-file-pattern` | Remote file pattern (e.g. `ce_system*.log`) |
| `--kube-single` | Use only one pod (shared log volume) |
| `--kube-flatten` | Do not create per-pod subfolders |
| `--kube-copy-mode` | One of: `tar` (default, robust), `snapshot`, `cp` |

### Docker options

| Option | Description |
|--------|--------------|
| `--docker-container` | Copy logs from this running local container before analysis (cannot be combined with `--kube-sync`) |
| `--docker-copy-mode` | `tar` (default, docker exec + tar stream) or `cp` (docker cp per file) |

`--kube-remote-path`, `--kube-file-pattern` and `--kube-local-path` also apply to `--docker-container` (see defaults above).

---

## 🧾 Output Overview

| File | Description |
|------|--------------|
| `summary_markdown.md` | Markdown summary report |
| `summary.csv` | Error families: `count`, `family`, `variants`, `sample_values` (separated by ` ; `), `first_seen`, `last_seen` |
| `examples.csv` | Example log entries per family (last column `stacktrace`) |
| `raw_errors.csv` | All WARN/ERROR entries (last column `stacktrace`) |
| `timeseries_overall_daily.csv` | Error count per day |
| `timeseries_overall_hourly.csv` | Error count per hour |
| `timeseries_family_daily.csv` | Error count per day per family |
| `timeseries_family_hourly.csv` | Error count per hour per family |
| `filenet_cpe_report.pdf` | Visual PDF report with charts |
| `report.html` | Interactive HTML report with embedded charts |
| `summary.json` | (`--json`) Machine-readable summary for monitoring/CI |

---

## 🧪 Tested Environments

- IBM FileNet CPE 5.5.8 / 5.7 (Liberty)
- IBM Content Cortex 26.0.1 (IF001) CPE container (Docker)
- IBM Cloud Pak for Business Automation 24.0.x
- OpenShift 4.x / Kubernetes 1.27+
- Ubuntu 22.04, macOS 13+, Windows 11
- Python 3.11 – 3.14 (CI runs the test suite on 3.11 and 3.14)

### Running the tests

```bash
pip install ".[test]"
pytest
```

The tests use small synthetic logs in `tests/data/` (Content Cortex 26 line format, no real host names, users or IDs). The `test` extra includes PyYAML for the YAML rule tests; without it they are skipped.

---

## 🔧 Example: Full Workflow (Kubernetes + PDF)

```bash
# Step 1: Sync CPE logs from the running pod
python filenet_cpe_log_analyzer.py /tmp/analyze \
  --kube-sync \
  --kube-single \
  --kube-flatten \
  --kube-namespace filenet \
  --kube-pod-prefix demo-cpe-deploy \
  --kube-container demo-cpe-deploy \
  --kube-remote-path /opt/ibm/wlp/usr/servers/defaultServer/FileNet \
  --kube-local-path /tmp/analyze \
  --kube-file-pattern "ce_system*.log" \
  --pattern "ce_system*.log" \
  --since "24h" \
  --outdir ./results \
  --pdf-report ./results/cpe_analysis.pdf \
  --pdf-title "FileNet CPE Log Analysis – Last 24 Hours" \
  --pdf-landscape

# Step 2: View the report
xdg-open ./results/cpe_analysis.pdf
```

---

## 📘 Example: Markdown & CSV Results

### `summary_markdown.md`

Output for a fresh IBM Content Cortex 26 sandbox (68 WARN entries, shortened):

```markdown
# Error overview (consolidated)

| Count | Error family | Variants | Sample values | First seen | Last seen |
|-------|---------------|----------|---------------|------------|-----------|
| 53 | Missing locale-specific translations for key '{STR}' for the following locales: kk. Using '{STR}' locale instead. | 53 | `PROP_GroupSearchFilter_DESC`, `PROP_TSMMinimumRetention_DESC`, `PROP_RetrievalNameExtension_DESC` | 2026-11-18T14:16:36.199 | 2026-11-18T14:16:36.320 |
| 9 | buildNewObjectStoreCache: cache reloaded in transaction. Not updating global | 1 |  | 2026-11-18T14:19:59.560 | 2026-11-18T14:20:02.980 |
| 5 | LDAP search operation failed: [LDAP: error code 12 - critical extension is not recognized] | 1 |  | 2026-11-18T14:20:04.102 | 2026-11-18T14:20:04.301 |
| 1 | Initializing default security on P8 domain '{STR}'. Only limited operations will be permitted. | 1 |  | 2026-11-18T14:17:55.838 | 2026-11-18T14:17:55.838 |

---

## Example entries per error family

### Missing locale-specific translations for key '{STR}' for the following locales: kk. Using '{STR}' locale instead.

| Timestamp | Logfile | Example message |
|-----------|---------|------------------|
| 2026-11-18T14:16:36.199 | ce_system0.log | Missing locale-specific translations for key 'PROP_GroupSearchFilter_DESC' for the following locales: kk.  Using 'en-us' locale instead. |
```

---

## 📄 License

Licensed under the **Apache License 2.0**.  
See [LICENSE](./LICENSE) for full terms.


## 💬 Motivation

In large-scale, distributed FileNet environments, logs are often scattered across multiple pods and rotated frequently.  
While cloud-native observability (e.g., Loki, OpenShift logging) handles streaming well, sometimes you just need an **offline, reproducible snapshot** — this script provides exactly that.

It’s ideal for:
- Migration and performance testing
- Offline troubleshooting (without cluster access)
- Quickly summarizing the most common error families

Inspired by real-world FileNet CPE scaling and migration projects.
