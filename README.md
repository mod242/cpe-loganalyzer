# FileNet CPE Log Analyzer

A **Kubernetes-aware log analysis tool** for IBM FileNet Content Platform Engine (CPE).

This utility helps you analyze CPE log files — either from **local directories** or directly from **OpenShift / Kubernetes** pods.  
It automatically **collects**, **filters**, and **summarizes** log errors and warnings, then generates human-readable reports (Markdown, CSV, or PDF with charts).

It is designed for **containerized FileNet deployments** (e.g., Cloud Pak for Business Automation) and is especially useful for:
- Migration & health-check scenarios
- Offline analysis on developer notebooks
- Environments with autoscaling or ephemeral pods

---

## 📦 Pre-Installation

### 1. Python & dependencies
Install Python (3.8+) and the required libraries:

```bash
pip install -r requirements.txt
```

### 2. Optional: Kubernetes CLI

If you want to collect logs directly from a running CPE pod, install and configure `kubectl`:

```bash
# Verify your cluster connection
kubectl get pods -n filenet
```

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
- **Consolidated error table**
- **Example log messages per family**

**Charts included:**
- Top error families (horizontal bar chart)
- Errors per day
- Errors per hour

### **NEW:** Interactive HTML Report
The HTML report provides a modern, interactive web-based view with:

- **📈 Interactive Charts**: Bar charts and line graphs using Chart.js
- **📊 Statistics Dashboard**: Key metrics displayed in attractive cards
- **🔍 Expandable Error Details**: Click "Show Examples" to view actual log entries
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
| `--until` | Relative end (default: `0h` = now) |
| `--outdir` | Directory for reports and CSVs |
| `--examples` | Example rows per family (default: 3) |

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

---

## 🧾 Output Overview

| File | Description |
|------|--------------|
| `summary_markdown.md` | Markdown summary report |
| `summary.csv` | Summary of error families and counts |
| `examples.csv` | Example log entries per family |
| `raw_errors.csv` | All WARN/ERROR lines |
| `timeseries_overall_daily.csv` | Error count per day |
| `timeseries_overall_hourly.csv` | Error count per hour |
| `timeseries_family_daily.csv` | Error count per day per family |
| `timeseries_family_hourly.csv` | Error count per hour per family |
| `filenet_cpe_report.pdf` | Visual PDF report with charts |
| `report.html` | **NEW:** Interactive HTML report with embedded charts |

---

## 🧪 Tested Environments

- IBM FileNet CPE 5.5.8 / 5.7 (Liberty)
- IBM Cloud Pak for Business Automation 24.0.x
- OpenShift 4.x / Kubernetes 1.27+
- Ubuntu 22.04, macOS 13+, Windows 11 (Python 3.10+)

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
```markdown
# Error overview (consolidated)

| Count | Error family |
|-------|---------------|
| 850 | WSIAuthenticatorImpl login exception (authentication failures) |
| 548 | checkNameCollision / FNRCE0043E (E_NOT_UNIQUE) – Name already exists |
| 10  | getContent failures (content retrieval) |

---

## Example entries per error family

### WSIAuthenticatorImpl login exception (authentication failures)
| Timestamp | Logfile | Example message |
|------------|----------|----------------|
| 2025-10-14T04:50:18.885 | ce_system0-cpe08.log | [WSIAuthenticatorImpl] login exception: Unable ... |
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

---

## 🚀 New Advanced Features

The project now includes several enhanced versions with advanced capabilities:

### Advanced FileNet CPE Log Analyzer (`advanced_filenet_cpe_log_analyzer.py`)

**New Features:**
- **Configuration Management**: JSON-based configuration files with environment variable support
- **Performance Monitoring**: Real-time memory usage and processing speed tracking
- **Enhanced Error Handling**: Automatic encoding detection and graceful error recovery
- **HTML Reports**: Rich HTML reports with interactive visualizations
- **Plugin Architecture**: Extensible design for custom normalizers and processors
- **Advanced Filtering**: More sophisticated filtering and search capabilities

**Configuration System (`config.py`):**
- Centralized configuration management with validation
- Environment variable support for CI/CD pipelines
- Sample configuration generation and validation utilities
- Support for custom analysis parameters and output formats

### Usage Examples

**Create and use configuration file:**
```bash
# Create a sample configuration file
python config.py --create-sample ./my_config.json

# Use custom configuration
python advanced_filenet_cpe_log_analyzer.py /path/to/logs --config ./my_config.json

# Validate configuration
python config.py --validate ./my_config.json
```

**Environment variables:**
```bash
export LOGANALYZER_FILE_PATTERN="*.log"
export LOGANALYZER_OUTPUT_FORMAT="html"
export LOGANALYZER_MAX_EXAMPLES="5"
python advanced_filenet_cpe_log_analyzer.py /path/to/logs
```

**Performance monitoring:**
```bash
python advanced_filenet_cpe_log_analyzer.py /path/to/logs --monitor-performance --verbose
```

### Configuration Options

The new configuration system supports:

```json
{
  "file_pattern": "*.log",
  "max_file_size_mb": 1000,
  "encoding": "utf-8",
  "max_examples": 3,
  "severity_levels": ["ERROR", "WARN", "WARNING", "FATAL", "SEVERE"],
  "normalize_messages": true,
  "max_pattern_length": 200,
  "progress_interval": 1000,
  "batch_size": 10000,
  "enable_parallel_processing": false,
  "output_format": "both",
  "chart_dpi": 300,
  "chart_width": 14,
  "chart_height": 8,
  "default_time_window": "24h",
  "timezone": "UTC"
}
```

### New Output Formats

- **HTML Reports**: Interactive HTML reports with embedded charts and filtering
- **Enhanced JSON**: Structured JSON with performance metrics and metadata
- **Excel Support**: Export to Excel format (when pandas is available)
- **Performance Logs**: Detailed performance and memory usage tracking

---

