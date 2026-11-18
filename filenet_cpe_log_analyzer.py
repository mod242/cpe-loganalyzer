#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
FileNet CPE Log Analyzer
(Recursive search, time series, relative time filters, optional Kubernetes sync, PDF reporting with charts)

Features:
- Optional: copy ONLY files matching a pattern from Kubernetes
  (kubectl exec + 'find . -print0 | tar --null -T - -czf -' → stream → local 'tar -xzf -').
- Optional: copy ONLY files matching a pattern from a local Docker container
  (docker exec + tar stream, or docker cp per file).
- Recursive local scan of log directories by glob pattern.
- Parse FileNet CPE / IBM Content Cortex (Liberty) log lines:
  "YYYY-MM-DDTHH:MM:SS.mmm <thread> <sub> <category> - LEVEL message".
  Continuation lines (stack traces etc.) are attached to the preceding entry.
- Relative time filters: --since/--until (e.g., "24h", "2d6h", "1w2d", "3h30m", "0h"/"now").
- Consolidated error families (fixed rules + automatic FNRCE error codes)
  + examples + time series (daily/hourly, overall & per family).
- PDF report with charts (top error families, daily and hourly time series).
- Landscape PDF layout via --pdf-landscape; dynamic table widths; wrapped labels; aspect-ratio image embedding.

Outputs:
  summary_markdown.md
  summary.csv
  examples.csv
  raw_errors.csv
  timeseries_overall_daily.csv
  timeseries_overall_hourly.csv
  timeseries_family_daily.csv
  timeseries_family_hourly.csv
  (optional) PDF report
  (optional) HTML report
"""

import argparse
import csv
import glob
import html
import json
import os
import re
import shlex
import subprocess
import tarfile
import tempfile
import textwrap
from collections import defaultdict, Counter
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional

# Matplotlib for charts (headless)
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.ticker import MaxNLocator
from matplotlib.dates import DateFormatter

# ---------- Log parsing ----------

# Entry line of ce_system*.log (FileNet CPE 5.5.x/5.7 and IBM Content Cortex 26):
#   2026-01-15T10:00:00.123 0000004A ENG  FNRCE0000W - WARN  Some message
#   <timestamp>             <thread> <sub> <category> - <severity> <message>
# The category column is usually the generic FNRCE0000<sev>; specific error
# codes appear in the message text or in the following stack trace.
LOG_LINE_RE = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3})\s+(?P<thread>\S+)\s+(?P<sub>\S+)\s+(?P<category>\S+)"
    r"\s+-\s+(?P<level>\w+)\s+(?P<msg>.*)$"
)

# File header written by the CPE at the top of each ce_system*.log (and again
# after a server restart when the file is appended to), e.g.:
#   IBM Content Platform Engine Version: 26.0.1.0, Build: ...
#           VirtualServer: <name>, ServerInstance: <name>
#   All times are local; the time zone is Coordinated Universal Time(UTC +00:00)
#   Date (UTC +00:00)       Thread   Sub  Category     Sev   Message
HEADER_LINE_RE = re.compile(
    r"^(?:IBM .*Version:|\s*VirtualServer:|All times are |Date \()"
)

# Maximum number of continuation lines (stack trace etc.) kept per entry.
MAX_CONTINUATION_LINES = 200

# Default number of continuation lines shown in examples/reports.
DEFAULT_STACK_LINES = 5

# Specific FileNet error/warning codes. FNRCE0000x is the generic category
# code of nearly every line and therefore not used as a family.
FNRCE_CODE_RE = re.compile(r"\b(FNRCE(?!0000)\d{4}[EW])\b")
FNRCE_CODE_WITH_NAME_RE = re.compile(r"\b(FNRCE(?!0000)\d{4}[EW])\b\s*[:\-]?\s*(E_[A-Z0-9_]+)")


def find_fnrce_code(texts) -> Optional[str]:
    """
    Return the first specific FNRCE code found in the given texts, formatted as
    "FNRCE0051E (E_OBJECT_NOT_FOUND)" when the symbolic name follows the code,
    otherwise just "FNRCE0051E". Returns None if no code is found.
    """
    for text in texts:
        if not text:
            continue
        m = FNRCE_CODE_RE.search(text)
        if not m:
            continue
        code = m.group(1)
        named = FNRCE_CODE_WITH_NAME_RE.search(text, m.start())
        if named and named.start() == m.start():
            return f"{code} ({named.group(2)})"
        return code
    return None


def normalize_message(msg: str, continuation: Optional[List[str]] = None) -> str:
    """
    Heuristics to consolidate similar messages into 'families'.

    Order:
      1. Fixed rules on the first line of the entry (unchanged from 1.0).
      2. Specific FNRCE error code (FNRCEnnnnE/W) in the message, then in the
         continuation lines (stack trace) -> family named after the code.
      3. Fallback: the normalized message text (IDs/GUIDs/numbers masked).
    """
    m = msg
    m = re.sub(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b", "{GUID}", m)
    m = re.sub(r"\b[A-Z0-9]{8,}\b", "{ID}", m)
    m = re.sub(r"\b\d{6,}\b", "{NUM}", m)
    m = re.sub(r"\s+", " ", m).strip()

    def has(needle: str) -> bool:
        # Check the normalized text (as in 1.0) and the original text, because
        # the {ID} masking above also replaces FNRCE codes such as FNRCE0043E.
        return needle in m or needle in msg

    if has("[WSIAuthenticatorImpl] login exception") or has("WSIAuthenticatorImpl"):
        return "WSIAuthenticatorImpl login exception (authentication failures)"
    if has("MethodName: checkNameCollision") or has("E_NOT_UNIQUE") or has("FNRCE0043E"):
        return "checkNameCollision / FNRCE0043E (E_NOT_UNIQUE) – Name already exists"
    if has("MethodName: getContent"):
        return "getContent failures (content retrieval)"
    if has("FNRCE0066E") or has("E_UNEXPECTED_EXCEPTION"):
        return "FNRCE0066E (E_UNEXPECTED_EXCEPTION) – unexpected error"
    if has("TTLStreamReaper"):
        return "TTLStreamReaper scheduling issue"

    code_family = find_fnrce_code([msg]) or find_fnrce_code(continuation or [])
    if code_family:
        return code_family

    return (m[:140] + "…") if len(m) > 140 else m


def parse_relative_delta(expr: Optional[str]):
    """
    Supports: "24h", "2d", "3h30m", "90m", "1w", "1w2d", "48h15m10s", "0h", "now"
    Units: w (weeks), d (days), h (hours), m (minutes), s (seconds)
    """
    if expr is None:
        return None
    expr = expr.strip().lower()
    if expr in ("now", "0", "0h", "0m", "0s"):
        return timedelta(0)

    patt = re.compile(r"(\d+)\s*([wdhms])")
    total = timedelta(0)
    found = False
    for m in patt.finditer(expr):
        found = True
        val = int(m.group(1))
        unit = m.group(2)
        if unit == "w":
            total += timedelta(weeks=val)
        elif unit == "d":
            total += timedelta(days=val)
        elif unit == "h":
            total += timedelta(hours=val)
        elif unit == "m":
            total += timedelta(minutes=val)
        elif unit == "s":
            total += timedelta(seconds=val)
    if not found:
        raise ValueError(f"Invalid relative time expression: {expr!r}")
    return total


def new_parse_stats() -> Dict[str, int]:
    return {
        "files": 0,          # files read
        "lines": 0,          # physical lines read
        "entries": 0,        # lines matching LOG_LINE_RE (any severity)
        "header": 0,         # CPE file header lines
        "blank": 0,          # empty lines
        "continuation": 0,   # lines attached to the preceding entry
        "unparsed": 0,       # lines that are neither of the above (before the first entry)
        "selected": 0,       # WARN/ERROR entries inside the time window
    }


def parse_logs(logdir: str, pattern: str, since_dt, until_dt,
               stats: Optional[Dict[str, int]] = None,
               max_continuation: int = MAX_CONTINUATION_LINES):
    """
    Recursively read all files, filter WARN/ERROR, and apply time window.

    Lines that do not start a new entry (stack traces, wrapped messages) are
    attached to the preceding entry as "continuation" (list of lines, at most
    max_continuation are kept). Pass a dict from new_parse_stats() as `stats`
    to get line counters.
    """
    files = sorted(glob.glob(os.path.join(logdir, "**", pattern), recursive=True))
    files = [fp for fp in files if os.path.isfile(fp)]
    if not files:
        raise SystemExit(f"No log files in {logdir!r} for pattern {pattern!r} (recursive).")

    if stats is None:
        stats = new_parse_stats()

    rows = []
    for fp in files:
        in_entry = False   # a log entry has been seen and may receive continuation lines
        current = None     # the selected row receiving continuation lines (None if not selected)
        file_entries = 0
        file_lines = 0
        try:
            with open(fp, "r", encoding="utf-8", errors="ignore") as f:
                stats["files"] += 1
                for raw in f:
                    line = raw.rstrip("\r\n")
                    file_lines += 1
                    stats["lines"] += 1

                    m = LOG_LINE_RE.match(line)
                    if m:
                        stats["entries"] += 1
                        file_entries += 1
                        in_entry = True
                        current = None
                        ts_str = m.group("ts")
                        level = m.group("level").upper()
                        msg = m.group("msg")
                        if level not in ("ERROR", "WARN"):
                            continue
                        try:
                            ts = datetime.strptime(ts_str, "%Y-%m-%dT%H:%M:%S.%f")
                        except Exception:
                            continue
                        if since_dt and ts < since_dt:
                            continue
                        if until_dt and ts > until_dt:
                            continue
                        current = {
                            "timestamp": ts_str,
                            "level": level,
                            "message": msg.strip(),
                            "source_file": os.path.basename(fp),
                            "continuation": [],
                        }
                        rows.append(current)
                        stats["selected"] += 1
                        continue

                    if HEADER_LINE_RE.match(line):
                        stats["header"] += 1
                        in_entry = False
                        current = None
                        continue
                    if not line.strip():
                        stats["blank"] += 1
                        continue
                    if in_entry:
                        stats["continuation"] += 1
                        if current is not None and len(current["continuation"]) < max_continuation:
                            current["continuation"].append(line.rstrip())
                    else:
                        stats["unparsed"] += 1
        except FileNotFoundError:
            # file rotated/removed while reading
            continue
        if file_lines and not file_entries:
            print(f"[Parse] WARNING: no log entries recognized in {fp} "
                  f"({file_lines} lines) – unexpected line format?")
    return rows


def format_parse_stats(stats: Dict[str, int]) -> str:
    return ("[Parse] files={files} lines={lines} entries={entries} header={header} "
            "continuation={continuation} blank={blank} unparsed={unparsed} "
            "selected(WARN/ERROR in window)={selected}").format(**stats)


def stack_excerpt(row: Dict[str, Any], max_lines: int) -> List[str]:
    """First max_lines continuation lines of a row (tabs expanded)."""
    if max_lines <= 0:
        return []
    return [ln.expandtabs(4) for ln in (row.get("continuation") or [])[:max_lines]]


def write_csv(path, rows, fieldnames):
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        for r in rows:
            w.writerow({k: r.get(k, "") for k in fieldnames})


# ---------- Kubernetes utilities ----------

def _run(cmd: List[str], check=True, capture=True):
    return subprocess.run(cmd, check=check, capture_output=capture, text=True)


def sh_quote(s: str) -> str:
    return "'" + s.replace("'", "'\"'\"'") + "'"


def list_running_pods(namespace: str, pod_prefix: str) -> List[str]:
    res = _run(["kubectl", "get", "pods", "-n", namespace, "-o", "json"])
    data = json.loads(res.stdout)
    pods = []
    for item in data.get("items", []):
        name = item.get("metadata", {}).get("name", "")
        phase = item.get("status", {}).get("phase", "")
        if name.startswith(pod_prefix) and phase == "Running":
            pods.append(name)
    return pods


def remote_find_files(namespace: str, pod: str, container: str, remote_path: str, pattern: str) -> List[str]:
    """
    Recursively list matching files (relative to remote_path) using find -print0 (robust).
    """
    cmd = [
        "kubectl", "exec", "-n", namespace, "-c", container, pod, "--",
        "sh", "-lc", f'cd {sh_quote(remote_path)} && find . -type f -name {sh_quote(pattern)} -print0'
    ]
    res = _run(cmd)
    out = res.stdout
    parts = out.split("\x00")
    files = []
    for p in parts:
        p = p.strip()
        if not p:
            continue
        if p.startswith("./"):
            p = p[2:]
        files.append(p)
    return files


# ---- Copy mode: cp (per file; less robust) ----

def kube_cp_file(namespace: str, pod: str, container: str, remote_full_path: str, local_full_path: str):
    os.makedirs(os.path.dirname(local_full_path) or ".", exist_ok=True)
    cmd = [
        "kubectl", "cp", "-n", namespace, "--container", container,
        f"{pod}:{remote_full_path}", local_full_path
    ]
    return _run(cmd)


# ---- Copy mode: snapshot (create stable copies in pod, then copy once) ----

def kube_snapshot_then_copy(namespace: str, pod: str, container: str,
                            remote_path: str, rel_files: List[str],
                            local_base: str):
    snap_dir = f"/tmp/filenet-log-snap-{int(datetime.now().timestamp())}"
    # 1) create snapshot structure and copy bytes into new files (cat -> new file)
    make_and_copy_cmds = []
    for rel in rel_files:
        subdir = os.path.dirname(rel) or "."
        make_and_copy_cmds.append(f'mkdir -p {sh_quote(snap_dir)}/{sh_quote(subdir)}')
    for rel in rel_files:
        src = remote_path.rstrip("/") + "/" + rel
        dst = snap_dir.rstrip("/") + "/" + rel
        make_and_copy_cmds.append(f'cat {sh_quote(src)} > {sh_quote(dst)}')
    _run(["kubectl", "exec", "-n", namespace, "-c", container, pod, "--", "sh", "-lc", " && ".join(make_and_copy_cmds)])

    # 2) kubectl cp snapshot dir once
    os.makedirs(local_base, exist_ok=True)
    _run(["kubectl", "cp", "-n", namespace, "--container", container, f"{pod}:{snap_dir}", local_base])

    # 3) cleanup
    _run(["kubectl", "exec", "-n", namespace, "-c", container, pod, "--", "sh", "-lc", f"rm -rf {sh_quote(snap_dir)}"])

    # 4) move files from local snapshot root one level up
    snap_local_root = os.path.join(local_base, os.path.basename(snap_dir))
    if os.path.isdir(snap_local_root):
        for root, _, files in os.walk(snap_local_root):
            for fn in files:
                rel_path = os.path.relpath(os.path.join(root, fn), snap_local_root)
                target_path = os.path.join(local_base, rel_path)
                os.makedirs(os.path.dirname(target_path), exist_ok=True)
                os.replace(os.path.join(root, fn), target_path)
        # clean residual dirs
        for r, dirs, files in os.walk(snap_local_root, topdown=False):
            for name in files:
                try:
                    os.remove(os.path.join(r, name))
                except Exception:
                    pass
            for name in dirs:
                try:
                    os.rmdir(os.path.join(r, name))
                except Exception:
                    pass
        try:
            os.rmdir(snap_local_root)
        except Exception:
            pass


# ---- Copy mode: tar (robust; mirrors working pipeline) ----

def kube_tar_stream(namespace: str, pod: str, container: str,
                    remote_path: str, file_pattern: str,
                    local_base: str):
    """
    Build gzipped tar in the pod from matching files and extract locally:
      cd <remote_path> &&
      find . -type f -name "<pattern>" -print0 |
      tar --null -T - -czf -
      | tar -xzf - -C <local_base>
    """
    os.makedirs(local_base, exist_ok=True)

    remote_cmd = (
        f'cd {sh_quote(remote_path)} && '
        f'find . -type f -name {sh_quote(file_pattern)} -print0 | '
        f'tar --null -T - -czf -'
    )

    full_cmd = (
        f'kubectl exec -n {shlex.quote(namespace)} '
        f'-c {shlex.quote(container)} {shlex.quote(pod)} -- '
        f'sh -lc {sh_quote(remote_cmd)} '
        f'| tar -xzf - -C {sh_quote(local_base)}'
    )

    # stream through a shell pipe; do not capture output
    subprocess.run(full_cmd, shell=True, check=True)


def kube_sync_pattern_only(namespace: str,
                           pod_prefix: str,
                           container: str,
                           remote_path: str,
                           local_base: str,
                           file_pattern: str,
                           copy_mode: str,
                           single: bool,
                           pod_name: str,
                           flatten: bool) -> str:
    pods = list_running_pods(namespace, pod_prefix)
    if not pods:
        raise SystemExit(f"No running pods found with prefix {pod_prefix!r} in namespace {namespace!r}.")
    if single:
        if pod_name:
            if pod_name not in pods:
                raise SystemExit(f"Pod {pod_name!r} is not running or does not match prefix {pod_prefix!r}.")
            pods = [pod_name]
        else:
            pods = [pods[0]]

    print("[Kube] Pods to use: %s" % ", ".join(pods))
    print("[Kube] Remote base dir: %s" % remote_path)
    print("[Kube] Pattern to copy (only matches): %s" % file_pattern)
    print("[Kube] Local base: %s%s" % (local_base, "" if flatten else "/<pod>/"))
    os.makedirs(local_base, exist_ok=True)

    for pod in pods:
        base = local_base if flatten else os.path.join(local_base, pod)
        os.makedirs(base, exist_ok=True)

        if copy_mode == "tar":
            kube_tar_stream(namespace, pod, container, remote_path, file_pattern, base)
        else:
            rel_files = remote_find_files(namespace, pod, container, remote_path, file_pattern)
            if not rel_files:
                print("[Kube] No matching files found in pod %s." % pod)
                if single:
                    break
                continue
            if copy_mode == "snapshot":
                kube_snapshot_then_copy(namespace, pod, container, remote_path, rel_files, base)
            elif copy_mode == "cp":
                for rel in rel_files:
                    remote_full = remote_path.rstrip("/") + "/" + rel
                    local_full = os.path.join(base, rel)
                    os.makedirs(os.path.dirname(local_full), exist_ok=True)
                    try:
                        kube_cp_file(namespace, pod, container, remote_full, local_full)
                    except subprocess.CalledProcessError as e:
                        print("[Kube] ERROR copying %s:%s -> %s\n%s\n%s" %
                              (pod, remote_full, local_full, e.stdout or "", e.stderr or ""))
            else:
                raise SystemExit(f"Unknown --kube-copy-mode: {copy_mode!r}")

        if single:
            break

    return local_base


# ---------- Docker utilities ----------

DEFAULT_REMOTE_LOG_PATH = "/opt/ibm/wlp/usr/servers/defaultServer/FileNet"
DEFAULT_REMOTE_FILE_PATTERN = "ce_system*.log"


def _remote_find_cmd(remote_path: str, file_pattern: str) -> str:
    return f"cd {sh_quote(remote_path)} && find . -type f -name {sh_quote(file_pattern)} -print0"


def docker_find_files(container: str, remote_path: str, file_pattern: str) -> List[str]:
    """List matching files (relative to remote_path) inside a running container."""
    # 'sh -c' (not -lc): login profiles could write to stdout and corrupt the output.
    res = _run(["docker", "exec", container, "sh", "-c", _remote_find_cmd(remote_path, file_pattern)])
    files = []
    for p in res.stdout.split("\x00"):
        p = p.strip()
        if not p:
            continue
        if p.startswith("./"):
            p = p[2:]
        files.append(p)
    return files


def _safe_member_path(dest: str, name: str) -> Optional[str]:
    """Return the extraction target for a tar member, or None if it would escape dest."""
    dest_abs = os.path.abspath(dest)
    if os.path.isabs(name):
        return None
    target = os.path.abspath(os.path.join(dest_abs, name))
    try:
        if os.path.commonpath([dest_abs, target]) != dest_abs or target == dest_abs:
            return None
    except ValueError:  # different drives on Windows
        return None
    return target


def extract_tar_stream(fileobj, dest: str) -> List[str]:
    """
    Extract regular files from a (gzipped) tar stream into dest.
    Only regular files are written; absolute paths and '..' are rejected.
    Returns the list of extracted relative paths.
    """
    os.makedirs(dest, exist_ok=True)
    extracted = []
    with tarfile.open(fileobj=fileobj, mode="r|*") as tf:
        for member in tf:
            if not member.isfile():
                continue
            target = _safe_member_path(dest, member.name)
            if target is None:
                print(f"[Docker] Skipping unsafe path in archive: {member.name!r}")
                continue
            src = tf.extractfile(member)
            if src is None:
                continue
            os.makedirs(os.path.dirname(target), exist_ok=True)
            with open(target, "wb") as out:
                while True:
                    chunk = src.read(1024 * 1024)
                    if not chunk:
                        break
                    out.write(chunk)
            extracted.append(os.path.relpath(target, os.path.abspath(dest)))
    return extracted


def docker_tar_stream(container: str, remote_path: str, file_pattern: str, local_base: str) -> List[str]:
    """
    Stream matching files out of the container as a gzipped tar and extract
    them locally (no local 'tar' binary needed):
      docker exec <container> sh -c 'cd <remote_path> && find . -type f -name <pattern> -print0 |
                                     tar --null -T - -czf -'
    """
    remote_cmd = _remote_find_cmd(remote_path, file_pattern) + " | tar --null -T - -czf -"
    cmd = ["docker", "exec", container, "sh", "-c", remote_cmd]
    with tempfile.TemporaryFile() as err:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=err)
        tar_error = None
        extracted: List[str] = []
        try:
            extracted = extract_tar_stream(proc.stdout, local_base)
        except tarfile.TarError as e:
            tar_error = e
        finally:
            if proc.stdout:
                proc.stdout.close()
        rc = proc.wait()
        err.seek(0)
        stderr_text = err.read().decode("utf-8", "replace").strip()
        if rc != 0:
            raise SystemExit(f"[Docker] 'docker exec' failed (exit {rc}): {stderr_text}")
        if tar_error is not None:
            raise SystemExit(f"[Docker] Could not read tar stream from container {container!r}: "
                             f"{tar_error} {stderr_text}".rstrip())
    return extracted


def docker_cp_files(container: str, remote_path: str, rel_files: List[str], local_base: str) -> List[str]:
    """Copy files one by one with 'docker cp'."""
    copied = []
    for rel in rel_files:
        target = _safe_member_path(local_base, rel)
        if target is None:
            print(f"[Docker] Skipping unsafe path: {rel!r}")
            continue
        os.makedirs(os.path.dirname(target), exist_ok=True)
        remote_full = remote_path.rstrip("/") + "/" + rel
        try:
            _run(["docker", "cp", f"{container}:{remote_full}", target])
            copied.append(rel)
        except subprocess.CalledProcessError as e:
            print("[Docker] ERROR copying %s:%s -> %s\n%s\n%s" %
                  (container, remote_full, target, e.stdout or "", e.stderr or ""))
    return copied


def docker_sync_pattern_only(container: str, remote_path: str, local_base: str,
                             file_pattern: str, copy_mode: str = "tar") -> str:
    """Copy ONLY files matching file_pattern from a local Docker container."""
    print("[Docker] Container: %s" % container)
    print("[Docker] Remote base dir: %s" % remote_path)
    print("[Docker] Pattern to copy (only matches): %s" % file_pattern)
    print("[Docker] Local base: %s" % local_base)
    os.makedirs(local_base, exist_ok=True)

    try:
        state = _run(["docker", "inspect", "-f", "{{.State.Running}}", container])
    except FileNotFoundError:
        raise SystemExit("[Docker] 'docker' command not found in PATH.")
    except subprocess.CalledProcessError as e:
        raise SystemExit(f"[Docker] Container {container!r} not found: {(e.stderr or '').strip()}")
    if state.stdout.strip() != "true":
        raise SystemExit(f"[Docker] Container {container!r} is not running.")

    if copy_mode == "tar":
        files = docker_tar_stream(container, remote_path, file_pattern, local_base)
    elif copy_mode == "cp":
        try:
            rel_files = docker_find_files(container, remote_path, file_pattern)
        except subprocess.CalledProcessError as e:
            raise SystemExit(f"[Docker] Listing files failed:\n{e.stderr or ''}")
        files = docker_cp_files(container, remote_path, rel_files, local_base)
    else:
        raise SystemExit(f"Unknown --docker-copy-mode: {copy_mode!r}")

    if files:
        print("[Docker] Copied %d file(s): %s" % (len(files), ", ".join(sorted(files))))
    else:
        print("[Docker] No matching files found in container %s." % container)
    return local_base


# ---------- PDF report (tables + charts) ----------

def _wrap_label(s: str, width: int = 40) -> str:
    return "\n".join(textwrap.wrap(s, width=width, break_long_words=False, break_on_hyphens=True)) or s

def save_top_families_chart(out_path: str, summary: List[Dict[str, Any]], top_n: int = 12):
    top = summary[:top_n]
    labels = [_wrap_label(s["family"], width=40) for s in top]
    counts = [s["count"] for s in top]
    plt.figure(figsize=(12, 6))  # wide & tall for readability
    y_pos = list(range(len(labels)))
    plt.barh(y_pos, counts)
    plt.yticks(y_pos, labels, fontsize=9)
    plt.gca().invert_yaxis()
    plt.xlabel("Count", fontsize=10)
    plt.title("Top error families", fontsize=12)
    plt.subplots_adjust(left=0.35, right=0.95, top=0.90, bottom=0.15)
    plt.tight_layout()
    plt.savefig(out_path, dpi=150, bbox_inches="tight")
    plt.close()

def save_timeseries_chart(out_path: str, series: Dict[str, int], title: str, xlabel: str):
    plt.figure(figsize=(12, 4))
    if not series:
        plt.title(title + " (no data)")
        plt.tight_layout()
        plt.savefig(out_path, dpi=150, bbox_inches="tight")
        plt.close()
        return

    # Keys are strings like "YYYY-MM-DD" or "YYYY-MM-DD HH:00"
    def _parse_key(k: str):
        for fmt in ("%Y-%m-%d %H:00", "%Y-%m-%d"):
            try:
                return datetime.strptime(k, fmt)
            except ValueError:
                pass
        return None

    parsed = [(_parse_key(k), v) for k, v in series.items()]
    parsed = [p for p in parsed if p[0] is not None]
    parsed.sort(key=lambda x: x[0])

    xs = [p[0] for p in parsed]
    ys = [p[1] for p in parsed]

    plt.plot(xs, ys, marker="o", linewidth=1.5, markersize=3)
    ax = plt.gca()
    ax.xaxis.set_major_locator(MaxNLocator(nbins=8, prune=None))
    if all(x.hour == 0 and x.minute == 0 for x in xs):
        ax.xaxis.set_major_formatter(DateFormatter("%Y-%m-%d"))
    else:
        ax.xaxis.set_major_formatter(DateFormatter("%Y-%m-%d %H:%M"))

    plt.xticks(rotation=30, ha="right", fontsize=8)
    plt.yticks(fontsize=9)
    plt.title(title, fontsize=12)
    plt.xlabel(xlabel, fontsize=10)
    plt.ylabel("Count", fontsize=10)
    plt.tight_layout()
    plt.savefig(out_path, dpi=150, bbox_inches="tight")
    plt.close()

# Aspect-ratio–preserving image embedding for PDF
from reportlab.lib.utils import ImageReader
def _image_with_aspect(path: str, target_width: float):
    """
    Return a ReportLab Image scaled to target_width while preserving aspect ratio.
    """
    from reportlab.platypus import Image as RLImage
    try:
        ir = ImageReader(path)
        iw, ih = ir.getSize()
        if iw and ih:
            aspect = ih / float(iw)
            return RLImage(path, width=target_width, height=target_width * aspect)
    except Exception:
        pass
    # Fallback: use a reasonable height
    return RLImage(path, width=target_width, height=max(1.0, target_width * 0.4))

def generate_pdf_report(
    output_pdf: str,
    project_title: str,
    logo_path: str,
    summary: List[Dict[str, Any]],
    example_rows: List[Dict[str, Any]],
    daily_counts: Dict[str, int],
    hourly_counts: Dict[str, int],
    outdir_for_images: str,
    landscape_mode: bool,
    stack_lines: int = DEFAULT_STACK_LINES,
):
    try:
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import A4, landscape as rl_landscape
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image, PageBreak
        from reportlab.lib.styles import getSampleStyleSheet
    except ImportError:
        raise SystemExit("ReportLab is required for PDF output. Install with: pip install reportlab")

    os.makedirs(os.path.dirname(output_pdf) or ".", exist_ok=True)
    os.makedirs(outdir_for_images, exist_ok=True)

    # Prepare charts
    top_png = os.path.join(outdir_for_images, "chart_top_families.png")
    daily_png = os.path.join(outdir_for_images, "chart_overall_daily.png")
    hourly_png = os.path.join(outdir_for_images, "chart_overall_hourly.png")
    save_top_families_chart(top_png, summary, top_n=min(12, len(summary) or 1))
    save_timeseries_chart(daily_png, daily_counts, "Overall errors per day", "Date")
    save_timeseries_chart(hourly_png, hourly_counts, "Overall errors per hour", "Hour")

    # Page layout
    page_size = rl_landscape(A4) if landscape_mode else A4
    doc = SimpleDocTemplate(output_pdf, pagesize=page_size, title="FileNet CPE Log Analyzer Report")
    styles = getSampleStyleSheet()
    elements = []

    # Available width for content
    page_w, page_h = doc.pagesize
    avail_w = page_w - doc.leftMargin - doc.rightMargin

    # Title page
    if logo_path and os.path.exists(logo_path):
        elements.append(Image(logo_path, width=200, height=60))
        elements.append(Spacer(1, 12))
    elements.append(Paragraph(project_title or "FileNet CPE Log Analyzer – Report", styles["Title"]))
    elements.append(Paragraph(datetime.now().strftime("%Y-%m-%d %H:%M:%S"), styles["Normal"]))
    elements.append(Spacer(1, 24))

    # Summary table with wrapped cells
    elements.append(Paragraph("Consolidated Error Families", styles["Heading2"]))
    from reportlab.platypus import Paragraph as RLParagraph
    body = styles["BodyText"]; body.fontSize = 9
    data = [["Count", "Error Family"]]
    for s in summary:
        fam_para = RLParagraph(html.escape(s["family"], quote=False), body)
        data.append([s["count"], fam_para])
    count_col = 80
    fam_col = max(200, avail_w - count_col)
    table = Table(data, colWidths=[count_col, fam_col])
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.gray),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("ALIGN", (0, 0), (-1, -1), "LEFT"),
        ("GRID", (0, 0), (-1, -1), 0.25, colors.black),
        ("BOTTOMPADDING", (0, 0), (-1, 0), 8),
    ]))
    elements.append(table)
    elements.append(Spacer(1, 18))

    # Charts (aspect-ratio preserved)
    elements.append(Paragraph("Charts", styles["Heading2"]))
    for img_path, caption in [
        (top_png, "Top error families"),
        (daily_png, "Errors per day"),
        (hourly_png, "Errors per hour"),
    ]:
        if os.path.exists(img_path):
            elements.append(Spacer(1, 6))
            elements.append(_image_with_aspect(img_path, target_width=avail_w))
            elements.append(Paragraph(caption, styles["Italic"]))
            elements.append(Spacer(1, 6))
    elements.append(PageBreak())

    # Examples
    elements.append(Paragraph("Example Entries", styles["Heading2"]))
    if not example_rows:
        elements.append(Paragraph("No examples available for the selected time window.", styles["Normal"]))
    else:
        fam_to_examples: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        for r in example_rows:
            fam_to_examples[r["family"]].append(r)
        for s in summary:
            fam = s["family"]
            examples = fam_to_examples.get(fam, [])[:2]
            if not examples:
                continue
            elements.append(Paragraph(html.escape(fam, quote=False), styles["Heading3"]))
            for ex in examples:
                msg = ex["message"]
                if len(msg) > 600:
                    msg = msg[:600] + "…"
                elements.append(Paragraph(f"<b>{html.escape(ex['timestamp'])}</b> — "
                                          f"{html.escape(msg, quote=False)}", styles["BodyText"]))
                stack = (ex.get("stacktrace") or [])[:max(0, stack_lines)]
                if stack:
                    # Long stack lines have few spaces to wrap at; cut them to keep the layout.
                    def _fmt(ln: str) -> str:
                        ln = ln if len(ln) <= 180 else ln[:180] + "…"
                        body_txt = ln.lstrip(" ")
                        indent = len(ln) - len(body_txt)
                        return "&nbsp;" * indent + html.escape(body_txt, quote=False)
                    stack_html = "<br/>".join(_fmt(ln) for ln in stack)
                    elements.append(Paragraph(f'<font face="Courier" size="7">{stack_html}</font>',
                                              styles["BodyText"]))
            elements.append(Spacer(1, 10))

    doc.build(elements)
    print(f"[PDF] Report generated: {output_pdf}")


# ---------- HTML report ----------

def generate_html_report(
    output_html: str,
    project_title: str,
    summary: List[Dict[str, Any]],
    example_rows: List[Dict[str, Any]],
    daily_counts: Dict[str, int],
    hourly_counts: Dict[str, int],
    total_entries: int,
    time_range: str,
    stack_lines: int = DEFAULT_STACK_LINES,
):
    """
    Generate an HTML report with embedded charts and interactive features.
    """
    os.makedirs(os.path.dirname(output_html) or ".", exist_ok=True)
    esc = html.escape

    def js(value) -> str:
        # JSON literal that is safe inside a <script> block.
        return json.dumps(value).replace("</", "<\\/")

    # Calculate statistics
    total_families = len(summary)
    top_error = summary[0] if summary else {"family": "None", "count": 0}

    # Group examples by family for easy lookup
    examples_by_family = defaultdict(list)
    for ex in example_rows:
        examples_by_family[ex["family"]].append(ex)

    # Prepare data for charts (JavaScript arrays)
    chart_labels = [s["family"][:50] + "..." if len(s["family"]) > 50 else s["family"] for s in summary[:10]]
    chart_counts = [s["count"] for s in summary[:10]]

    # Time series data
    daily_labels = sorted(daily_counts.keys())
    daily_values = [daily_counts[d] for d in daily_labels]

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{esc(project_title)}</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.1/dist/chart.umd.min.js"></script>
    <style>
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            margin: 0;
            padding: 20px;
            background-color: #f5f5f5;
            color: #333;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            padding: 30px;
            border-radius: 10px;
            box-shadow: 0 0 20px rgba(0,0,0,0.1);
        }}
        .header {{
            text-align: center;
            margin-bottom: 40px;
            padding-bottom: 20px;
            border-bottom: 2px solid #e0e0e0;
        }}
        .header h1 {{
            color: #2c3e50;
            margin: 0;
            font-size: 2.5em;
        }}
        .header .subtitle {{
            color: #7f8c8d;
            margin-top: 10px;
            font-size: 1.1em;
        }}
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 40px;
        }}
        .stat-card {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 20px;
            border-radius: 8px;
            text-align: center;
        }}
        .stat-card h3 {{
            margin: 0 0 10px 0;
            font-size: 1.2em;
            opacity: 0.9;
        }}
        .stat-card .value {{
            font-size: 2em;
            font-weight: bold;
            margin: 0;
        }}
        .chart-container {{
            margin: 40px 0;
            padding: 20px;
            background: #fafafa;
            border-radius: 8px;
            border: 1px solid #e0e0e0;
        }}
        .chart-title {{
            text-align: center;
            margin-bottom: 20px;
            font-size: 1.3em;
            color: #2c3e50;
        }}
        .chart-wrapper {{
            position: relative;
            height: 400px;
            margin-bottom: 20px;
        }}
        .families-table {{
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
            background: white;
            border-radius: 8px;
            overflow: hidden;
            box-shadow: 0 0 10px rgba(0,0,0,0.1);
        }}
        .families-table th {{
            background: #34495e;
            color: white;
            padding: 15px;
            text-align: left;
            font-weight: 600;
        }}
        .families-table td {{
            padding: 12px 15px;
            border-bottom: 1px solid #e0e0e0;
        }}
        .families-table tr:hover {{
            background-color: #f8f9fa;
        }}
        .error-family {{
            font-family: 'Courier New', monospace;
            background: #f8f9fa;
            padding: 4px 8px;
            border-radius: 4px;
            border-left: 4px solid #e74c3c;
        }}
        .count-badge {{
            background: #3498db;
            color: white;
            padding: 4px 12px;
            border-radius: 20px;
            font-weight: bold;
            font-size: 0.9em;
        }}
        .examples-section {{
            margin-top: 40px;
        }}
        .example-item {{
            background: #fff;
            border: 1px solid #e0e0e0;
            border-radius: 6px;
            margin: 15px 0;
            padding: 15px;
        }}
        .example-family {{
            font-weight: bold;
            color: #e74c3c;
            margin-bottom: 10px;
            font-size: 1.1em;
        }}
        .example-details {{
            font-family: 'Courier New', monospace;
            font-size: 0.9em;
            color: #555;
            background: #f8f9fa;
            padding: 10px;
            border-radius: 4px;
            border-left: 3px solid #3498db;
        }}
        .timestamp {{
            color: #2980b9;
            font-weight: bold;
        }}
        .footer {{
            text-align: center;
            margin-top: 50px;
            padding-top: 20px;
            border-top: 1px solid #e0e0e0;
            color: #7f8c8d;
        }}
        .toggle-btn {{
            background: #3498db;
            color: white;
            border: none;
            padding: 8px 16px;
            border-radius: 4px;
            cursor: pointer;
            margin: 5px;
            font-size: 0.9em;
        }}
        .toggle-btn:hover {{
            background: #2980b9;
        }}
        .hidden {{
            display: none;
        }}
        .stacktrace {{
            margin: 6px 0 0 0;
            padding: 6px 8px;
            background: #fff;
            border: 1px dashed #ccc;
            font-size: 0.85em;
            white-space: pre-wrap;
            word-break: break-all;
            color: #444;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>{esc(project_title)}</h1>
            <div class="subtitle">Generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</div>
            <div class="subtitle">Time Range: {esc(time_range)}</div>
        </div>

        <div class="stats-grid">
            <div class="stat-card">
                <h3>Total Entries</h3>
                <div class="value">{total_entries:,}</div>
            </div>
            <div class="stat-card">
                <h3>Error Families</h3>
                <div class="value">{total_families}</div>
            </div>
            <div class="stat-card">
                <h3>Top Error Count</h3>
                <div class="value">{top_error["count"]}</div>
            </div>
            <div class="stat-card">
                <h3>Analysis Period</h3>
                <div class="value">{len(daily_counts)} days</div>
            </div>
        </div>

        <div class="chart-container">
            <div class="chart-title">Top 10 Error Families</div>
            <div class="chart-wrapper">
                <canvas id="topErrorsChart"></canvas>
            </div>
        </div>

        <div class="chart-container">
            <div class="chart-title">Daily Error Trend</div>
            <div class="chart-wrapper">
                <canvas id="dailyTrendChart"></canvas>
            </div>
        </div>

        <h2>Error Families Summary</h2>
        <table class="families-table">
            <thead>
                <tr>
                    <th>Count</th>
                    <th>Error Family</th>
                    <th>Actions</th>
                </tr>
            </thead>
            <tbody>"""

    # Add family rows
    for i, family_data in enumerate(summary[:20]):  # Top 20 families
        family_examples = examples_by_family.get(family_data["family"], [])
        has_examples = len(family_examples) > 0
        
        html_content += f"""
                <tr>
                    <td><span class="count-badge">{family_data["count"]}</span></td>
                    <td><div class="error-family">{esc(family_data["family"])}</div></td>
                    <td>
                        {"<button class='toggle-btn' onclick='toggleExamples(" + str(i) + ")'>Show Examples</button>" if has_examples else "No examples"}
                    </td>
                </tr>"""
        
        if has_examples:
            html_content += f"""
                <tr id="examples-{i}" class="hidden">
                    <td colspan="3">
                        <div style="padding: 15px; background: #f8f9fa;">
                            <strong>Examples:</strong>"""
            
            for ex in family_examples[:3]:  # Show up to 3 examples
                stack = (ex.get("stacktrace") or [])[:max(0, stack_lines)]
                stack_html = (f'\n                                <pre class="stacktrace">{esc(chr(10).join(stack))}</pre>'
                              if stack else "")
                html_content += f"""
                            <div class="example-details" style="margin: 10px 0;">
                                <div><span class="timestamp">{esc(ex["timestamp"])}</span> | {esc(ex["source_file"])}</div>
                                <div style="margin-top: 5px;">{esc(ex["message"][:200])}{"..." if len(ex["message"]) > 200 else ""}</div>{stack_html}
                            </div>"""
            
            html_content += """
                        </div>
                    </td>
                </tr>"""

    html_content += f"""
            </tbody>
        </table>

        <div class="footer">
            <p>FileNet CPE Log Analyzer - HTML Report</p>
            <p>Processed {total_entries:,} log entries across {len(daily_counts)} days</p>
        </div>
    </div>

    <script>
        // Top Errors Chart
        const ctx1 = document.getElementById('topErrorsChart').getContext('2d');
        new Chart(ctx1, {{
            type: 'bar',
            data: {{
                labels: {js(chart_labels)},
                datasets: [{{
                    label: 'Error Count',
                    data: {js(chart_counts)},
                    backgroundColor: 'rgba(231, 76, 60, 0.7)',
                    borderColor: 'rgba(231, 76, 60, 1)',
                    borderWidth: 1
                }}]
            }},
            options: {{
                responsive: true,
                maintainAspectRatio: false,
                plugins: {{
                    legend: {{
                        display: false
                    }}
                }},
                scales: {{
                    y: {{
                        beginAtZero: true,
                        ticks: {{
                            precision: 0
                        }}
                    }},
                    x: {{
                        ticks: {{
                            maxRotation: 45,
                            minRotation: 45
                        }}
                    }}
                }}
            }}
        }});

        // Daily Trend Chart
        const ctx2 = document.getElementById('dailyTrendChart').getContext('2d');
        new Chart(ctx2, {{
            type: 'line',
            data: {{
                labels: {js(daily_labels)},
                datasets: [{{
                    label: 'Daily Errors',
                    data: {js(daily_values)},
                    borderColor: 'rgba(52, 152, 219, 1)',
                    backgroundColor: 'rgba(52, 152, 219, 0.1)',
                    tension: 0.4,
                    fill: true
                }}]
            }},
            options: {{
                responsive: true,
                maintainAspectRatio: false,
                plugins: {{
                    legend: {{
                        display: false
                    }}
                }},
                scales: {{
                    y: {{
                        beginAtZero: true,
                        ticks: {{
                            precision: 0
                        }}
                    }}
                }}
            }}
        }});

        // Toggle examples function
        function toggleExamples(index) {{
            const exampleRow = document.getElementById('examples-' + index);
            const button = event.target;
            
            if (exampleRow.classList.contains('hidden')) {{
                exampleRow.classList.remove('hidden');
                button.textContent = 'Hide Examples';
            }} else {{
                exampleRow.classList.add('hidden');
                button.textContent = 'Show Examples';
            }}
        }}
    </script>
</body>
</html>"""

    with open(output_html, 'w', encoding='utf-8') as f:
        f.write(html_content)
    
    print(f"[HTML] Report generated: {output_html}")


# ---------- Main ----------

def compute_time_window(since: Optional[str], until: Optional[str], now: Optional[datetime] = None):
    """
    Translate relative --since/--until expressions into absolute datetimes.
    Both are measured back from `now`: --since 24h --until 2h means
    [now - 24h, now - 2h]. Returns (since_dt or None, until_dt).
    """
    now = now or datetime.now()
    until_dt = now - (parse_relative_delta(until) or timedelta(0))
    since_dt = None
    since_delta = parse_relative_delta(since) if since else None
    if since_delta is not None:
        since_dt = now - since_delta
    if since_dt and since_dt > until_dt:
        raise SystemExit(f"Invalid time window: since ({since_dt}) > until ({until_dt})")
    return since_dt, until_dt


def build_example_rows(families: Dict[str, List[Dict[str, Any]]], examples: int,
                       stack_lines: int) -> List[Dict[str, Any]]:
    example_rows: List[Dict[str, Any]] = []
    for fam, items in families.items():
        for ex in sorted(items, key=lambda rr: rr["timestamp"])[: max(1, examples)]:
            example_rows.append({
                "family": fam,
                "timestamp": ex["timestamp"],
                "source_file": ex["source_file"],
                "message": ex["message"],
                "stacktrace": stack_excerpt(ex, stack_lines),
            })
    return example_rows


def raw_rows_for_csv(rows: List[Dict[str, Any]], stack_lines: int) -> List[Dict[str, Any]]:
    """Parsed rows with the first stack_lines continuation lines as one text column."""
    return [{**r, "stacktrace": "\n".join(stack_excerpt(r, stack_lines))} for r in rows]


def example_rows_for_csv(example_rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Example rows with the stack excerpt (list) joined into one text column."""
    return [{**r, "stacktrace": "\n".join(r.get("stacktrace") or [])} for r in example_rows]


def _md_cell(text: str) -> str:
    return text.replace("|", "\\|")


def main(argv: Optional[List[str]] = None):
    ap = argparse.ArgumentParser(description="FileNet CPE Log Analyzer (pattern-only K8s copy + PDF report)")
    ap.add_argument("logdir",
                    help="Local directory for analysis (recursively scanned). "
                         "With --kube-sync this is typically --kube-local-path. "
                         "With --docker-container the logs are copied into this directory "
                         "(or --kube-local-path, if given).")
    ap.add_argument("--pattern", default="*.log",
                    help='Local glob pattern (default: "*.log")')
    ap.add_argument("--examples", type=int, default=3,
                    help="Example rows per error family")
    ap.add_argument("--stack-lines", type=int, default=DEFAULT_STACK_LINES,
                    help="Number of stack trace / continuation lines shown per example "
                         f"(default: {DEFAULT_STACK_LINES}, 0 = none)")
    ap.add_argument("--outdir", default=".",
                    help="Output directory")
    ap.add_argument("--since", default=None,
                    help='Relative start, e.g. "24h", "2d", "3h30m"')
    ap.add_argument("--until", default="0h",
                    help='Relative end, measured back from now, e.g. "0h" (now), "2h" (two hours ago)')

    # Kubernetes options
    ap.add_argument("--kube-sync", action="store_true",
                    help="Before analysis, copy ONLY pattern-matching files from Kubernetes.")
    ap.add_argument("--kube-namespace", default=None)
    ap.add_argument("--kube-pod-prefix", default=None)
    ap.add_argument("--kube-container", default=None)
    ap.add_argument("--kube-remote-path", default=None)
    ap.add_argument("--kube-local-path", default=None)
    ap.add_argument("--kube-file-pattern", default=None)
    ap.add_argument("--kube-single", action="store_true",
                    help="Copy from ONE pod only (shared folder scenario).")
    ap.add_argument("--kube-pod-name", default=None,
                    help="Use a specific pod (overrides auto-pick).")
    ap.add_argument("--kube-flatten", action="store_true",
                    help="No per-pod subfolder in kube-local-path.")
    ap.add_argument("--kube-copy-mode", choices=["tar", "snapshot", "cp"], default="tar",
                    help="Copy mode: tar (default), snapshot, or cp")

    # Docker options
    ap.add_argument("--docker-container", default=None, metavar="NAME",
                    help="Before analysis, copy ONLY pattern-matching files from this running local "
                         "Docker container. Remote path: --kube-remote-path "
                         f"(default: {DEFAULT_REMOTE_LOG_PATH}); file pattern: --kube-file-pattern "
                         f'(default: "{DEFAULT_REMOTE_FILE_PATTERN}"); local target: --kube-local-path '
                         "(default: logdir).")
    ap.add_argument("--docker-copy-mode", choices=["tar", "cp"], default="tar",
                    help="Docker copy mode: tar (default, docker exec + tar stream) or cp (docker cp per file)")

    # PDF options
    ap.add_argument("--pdf-report", default=None,
                    help="Path to output PDF report (e.g., ./results/report.pdf)")
    ap.add_argument("--pdf-logo", default=None,
                    help="Optional logo image path to place on the PDF title page")
    ap.add_argument("--pdf-title", default="FileNet CPE Log Analyzer – Report",
                    help="Title shown on the PDF")
    ap.add_argument("--pdf-landscape", action="store_true",
                    help="Render PDF in landscape orientation (wider tables/charts).")

    # HTML options
    ap.add_argument("--html-report", default=None,
                    help="Path to output HTML report (e.g., ./results/report.html)")
    ap.add_argument("--html-title", default="FileNet CPE Log Analyzer – Report",
                    help="Title shown on the HTML report")

    args = ap.parse_args(argv)

    if args.kube_sync and args.docker_container:
        raise SystemExit("--kube-sync and --docker-container cannot be combined.")

    # Kubernetes sync
    if args.kube_sync:
        required = {
            "kube_namespace": args.kube_namespace,
            "kube_pod_prefix": args.kube_pod_prefix,
            "kube_container": args.kube_container,
            "kube_remote_path": args.kube_remote_path,
            "kube_local_path": args.kube_local_path,
            "kube_file_pattern": args.kube_file_pattern,
        }
        missing = [k for k, v in required.items() if not v]
        if missing:
            raise SystemExit("--kube-sync requires: %s" %
                             ", ".join("--" + k.replace("_", "-") for k in missing))

        print(f"[Kube] Copying files (mode: {args.kube_copy_mode}) …")
        base = kube_sync_pattern_only(
            namespace=args.kube_namespace,
            pod_prefix=args.kube_pod_prefix,
            container=args.kube_container,
            remote_path=args.kube_remote_path,
            local_base=args.kube_local_path,
            file_pattern=args.kube_file_pattern,
            copy_mode=args.kube_copy_mode,
            single=args.kube_single,
            pod_name=args.kube_pod_name,
            flatten=args.kube_flatten,
        )
        analysis_dir = base
    elif args.docker_container:
        local_base = args.kube_local_path or args.logdir
        print(f"[Docker] Copying files (mode: {args.docker_copy_mode}) …")
        analysis_dir = docker_sync_pattern_only(
            container=args.docker_container,
            remote_path=args.kube_remote_path or DEFAULT_REMOTE_LOG_PATH,
            local_base=local_base,
            file_pattern=args.kube_file_pattern or DEFAULT_REMOTE_FILE_PATTERN,
            copy_mode=args.docker_copy_mode,
        )
    else:
        analysis_dir = args.logdir

    os.makedirs(args.outdir, exist_ok=True)

    since_dt, until_dt = compute_time_window(args.since, args.until)

    # Analysis
    stats = new_parse_stats()
    rows = parse_logs(analysis_dir, args.pattern, since_dt, until_dt, stats=stats)
    print(format_parse_stats(stats))
    raw_csv = os.path.join(args.outdir, "raw_errors.csv")
    write_csv(raw_csv, raw_rows_for_csv(rows, args.stack_lines),
              ["timestamp", "level", "source_file", "message", "stacktrace"])

    families: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for r in rows:
        families[normalize_message(r["message"], r.get("continuation"))].append(r)

    summary = [{"family": fam, "count": len(items)} for fam, items in families.items()]
    summary.sort(key=lambda x: x["count"], reverse=True)
    write_csv(os.path.join(args.outdir, "summary.csv"), summary, ["count", "family"])

    example_rows = build_example_rows(families, args.examples, args.stack_lines)
    write_csv(os.path.join(args.outdir, "examples.csv"),
              example_rows_for_csv(example_rows),
              ["family", "timestamp", "source_file", "message", "stacktrace"])

    # Time series
    def parse_ts(ts_str: str):
        return datetime.strptime(ts_str, "%Y-%m-%dT%H:%M:%S.%f")

    daily: Counter = Counter()
    hourly: Counter = Counter()
    fam_daily: Dict[str, Counter] = defaultdict(Counter)
    fam_hourly: Dict[str, Counter] = defaultdict(Counter)

    for fam, items in families.items():
        for r in items:
            try:
                dt = parse_ts(r["timestamp"])
            except Exception:
                continue
            d = dt.strftime("%Y-%m-%d")
            h = dt.strftime("%Y-%m-%d %H:00")
            daily[d] += 1
            hourly[h] += 1
            fam_daily[fam][d] += 1
            fam_hourly[fam][h] += 1

    def write_rows(path, header, rows_iter):
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        with open(path, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(header)
            for r in rows_iter:
                w.writerow(r)

    write_rows(os.path.join(args.outdir, "timeseries_overall_daily.csv"), ["date", "count"], sorted(daily.items()))
    write_rows(os.path.join(args.outdir, "timeseries_overall_hourly.csv"), ["datetime_hour", "count"], sorted(hourly.items()))
    write_rows(os.path.join(args.outdir, "timeseries_family_daily.csv"),
               ["date", "family", "count"],
               ((d, f, cnt) for f in [s["family"] for s in summary] for d, cnt in sorted(fam_daily[f].items())))
    write_rows(os.path.join(args.outdir, "timeseries_family_hourly.csv"),
               ["datetime_hour", "family", "count"],
               ((h, f, cnt) for f in [s["family"] for s in summary] for h, cnt in sorted(fam_hourly[f].items())))

    # Markdown
    md_path = os.path.join(args.outdir, "summary_markdown.md")
    with open(md_path, "w", encoding="utf-8") as md:
        md.write("# Error overview (consolidated)\n\n")
        md.write("| Count | Error family |\n|-------|---------------|\n")
        for row in summary:
            md.write(f"| {row['count']} | {row['family']} |\n")
        md.write("\n---\n\n## Time series (files)\n\n")
        md.write("- `timeseries_overall_daily.csv`\n- `timeseries_overall_hourly.csv`\n")
        md.write("- `timeseries_family_daily.csv`\n- `timeseries_family_hourly.csv`\n\n")
        md.write("## Example entries per error family\n\n")
        examples_by_fam: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        for r in example_rows:
            examples_by_fam[r["family"]].append(r)
        for s in summary:
            fam = s["family"]
            md.write(f"### {fam}\n\n")
            md.write("| Timestamp | Logfile | Example message |\n|-----------|---------|------------------|\n")
            for ex in examples_by_fam.get(fam, [])[: max(1, args.examples)]:
                safe = _md_cell(ex['message'])
                stack = ex.get("stacktrace") or []
                if stack:
                    # Table cells cannot contain newlines: render the stack excerpt with <br>.
                    safe += "<br>" + "<br>".join(
                        "<code>" + _md_cell(html.escape(ln.strip(), quote=False)) + "</code>" for ln in stack
                    )
                md.write(f"| {ex['timestamp']} | {ex['source_file']} | {safe} |\n")
            md.write("\n")

    print("Analysis complete.")
    print(f"- Markdown:   {md_path}")

    # PDF (optional)
    if args.pdf_report:
        charts_dir = os.path.join(args.outdir, "_charts")
        generate_pdf_report(
            output_pdf=args.pdf_report,
            project_title=args.pdf_title,
            logo_path=args.pdf_logo,
            summary=summary,
            example_rows=example_rows,
            daily_counts=dict(daily),
            hourly_counts=dict(hourly),
            outdir_for_images=charts_dir,
            landscape_mode=args.pdf_landscape,
            stack_lines=args.stack_lines,
        )

    # HTML (optional)
    if args.html_report:
        # Create time range string for display
        time_range = "All available data"
        if since_dt or until_dt:
            start_str = since_dt.strftime("%Y-%m-%d %H:%M") if since_dt else "Beginning"
            end_str = until_dt.strftime("%Y-%m-%d %H:%M") if until_dt else "Now"
            time_range = f"{start_str} to {end_str}"
        
        generate_html_report(
            output_html=args.html_report,
            project_title=args.html_title,
            summary=summary,
            example_rows=example_rows,
            daily_counts=dict(daily),
            hourly_counts=dict(hourly),
            total_entries=len(rows),
            time_range=time_range,
            stack_lines=args.stack_lines,
        )

if __name__ == "__main__":
    main()
