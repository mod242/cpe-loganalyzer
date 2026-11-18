"""
Docker source tests. A fake 'docker' script on PATH maps 'docker exec' to a
local shell and 'docker cp' to cp, so the tar/cp pipelines run end to end
without a Docker daemon. The real container is tested manually (see README).
"""
import io
import os
import shutil
import stat
import sys
import tarfile

import pytest

import filenet_cpe_log_analyzer as la

pytestmark = pytest.mark.skipif(sys.platform == "win32", reason="needs a POSIX shell, find and tar")

FAKE_DOCKER = """#!/bin/sh
# Minimal stand-in for the docker CLI used by the analyzer.
case "$1" in
  inspect)
    [ "$4" = "cpe" ] && echo true && exit 0
    [ "$4" = "stopped" ] && echo false && exit 0
    echo "error: no such object: $4" >&2; exit 1 ;;
  exec)
    shift 2          # drop 'exec <container>'
    exec "$@" ;;
  cp)
    exec cp "${2#*:}" "$3" ;;
esac
echo "unexpected docker call: $*" >&2
exit 2
"""


@pytest.fixture
def fake_docker(tmp_path, monkeypatch, ccx26_dir):
    if not (shutil.which("tar") and shutil.which("find")):
        pytest.skip("tar/find not available")
    bindir = tmp_path / "bin"
    bindir.mkdir()
    script = bindir / "docker"
    script.write_text(FAKE_DOCKER)
    script.chmod(script.stat().st_mode | stat.S_IEXEC)
    monkeypatch.setenv("PATH", f"{bindir}{os.pathsep}{os.environ['PATH']}")
    return ccx26_dir  # acts as the "remote" FileNet directory


def _files(base):
    return sorted(os.path.relpath(os.path.join(r, f), base) for r, _, fs in os.walk(base) for f in fs)


@pytest.mark.parametrize("mode", ["tar", "cp"])
def test_docker_sync_copies_only_matching_files(fake_docker, tmp_path, mode):
    local = tmp_path / "logs"
    la.docker_sync_pattern_only("cpe", fake_docker, str(local), "ce_system*.log", copy_mode=mode)
    assert _files(local) == [
        os.path.join("cpe-test-1", "ce_system0.log"),
        os.path.join("cpe-test-2", "ce_system1.log"),
    ]
    src = os.path.join(fake_docker, "cpe-test-1", "ce_system0.log")
    assert (local / "cpe-test-1" / "ce_system0.log").read_bytes() == open(src, "rb").read()


def test_cli_docker_container_end_to_end(fake_docker, tmp_path):
    local = tmp_path / "logs"
    outdir = tmp_path / "out"
    html_path = tmp_path / "report.html"
    la.main([str(local), "--docker-container", "cpe", "--kube-remote-path", fake_docker,
             "--pattern", "ce_system*.log", "--outdir", str(outdir), "--html-report", str(html_path)])
    assert (outdir / "summary.csv").exists()
    assert "FNRCE0051E (E_OBJECT_NOT_FOUND)" in html_path.read_text(encoding="utf-8")


def test_docker_missing_container(fake_docker, tmp_path):
    with pytest.raises(SystemExit, match="not found"):
        la.docker_sync_pattern_only("nope", fake_docker, str(tmp_path), "ce_system*.log")


def test_docker_stopped_container(fake_docker, tmp_path):
    with pytest.raises(SystemExit, match="not running"):
        la.docker_sync_pattern_only("stopped", fake_docker, str(tmp_path), "ce_system*.log")


def test_docker_bad_remote_path(fake_docker, tmp_path):
    with pytest.raises(SystemExit, match="docker exec' failed"):
        la.docker_sync_pattern_only("cpe", str(tmp_path / "missing"), str(tmp_path / "l"), "ce_system*.log")


def test_kube_and_docker_are_exclusive(tmp_path):
    with pytest.raises(SystemExit, match="cannot be combined"):
        la.main([str(tmp_path), "--kube-sync", "--docker-container", "cpe"])


def _tar_bytes(entries):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        for name, data in entries:
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
    buf.seek(0)
    return buf


def test_extract_tar_stream_rejects_unsafe_paths(tmp_path):
    dest = tmp_path / "dest"
    stream = _tar_bytes([
        ("./node/ce_system0.log", b"ok"),
        ("../escape.log", b"bad"),
        ("/abs/escape.log", b"bad"),
    ])
    extracted = la.extract_tar_stream(stream, str(dest))
    assert extracted == [os.path.join("node", "ce_system0.log")]
    assert (dest / "node" / "ce_system0.log").read_bytes() == b"ok"
    assert not (tmp_path / "escape.log").exists()
