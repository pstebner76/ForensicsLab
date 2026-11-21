"""The original ``python triage.py <file>`` behavior, byte for byte on stdout."""

import subprocess
import sys
from pathlib import Path

from tests.vectors import ABC, ABC_SHA256

ROOT = Path(__file__).resolve().parents[1]


def run_legacy(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(ROOT / "triage.py"), *args],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )


def test_usage_goes_to_stdout(tmp_path):
    result = run_legacy()
    assert result.returncode == 1
    assert result.stdout == "Usage: python triage.py <file>\n"
    assert result.stderr == ""


def test_missing_file_message(tmp_path):
    missing = tmp_path / "missing.bin"
    result = run_legacy(str(missing))
    assert result.returncode == 1
    assert result.stdout == f"No such file exists: {missing}\n"


def test_directory_message(tmp_path):
    result = run_legacy(str(tmp_path))
    assert result.returncode == 1
    assert result.stdout == f"Not a file: {tmp_path}\n"


def test_prints_only_the_sha256_of_abc(tmp_path):
    target = tmp_path / "abc.txt"
    target.write_bytes(ABC)
    result = run_legacy(str(target), "ignored-extra-argument")
    assert result.returncode == 0
    assert result.stdout == ABC_SHA256 + "\n"
    assert result.stderr == ""


def test_legacy_script_still_follows_a_symlink(tmp_path):
    # The new CLI refuses this case. The wrapper follows it because the
    # original open() did, and scripts may already depend on that.
    target = tmp_path / "abc.txt"
    target.write_bytes(ABC)
    link = tmp_path / "link.txt"
    link.symlink_to(target)
    result = run_legacy(str(link))
    assert result.returncode == 0
    assert result.stdout == ABC_SHA256 + "\n"
