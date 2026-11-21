"""CLI tests. Each subcommand is run through main(), which is what the console script calls."""

import csv
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from forensicslab import __version__
from forensicslab.cli import main
from forensicslab.entropy import ENTROPY_FIELDS
from forensicslab.hashing import HASH_FIELDS
from forensicslab.triage import TRIAGE_FIELDS

from tests.vectors import ABC, ABC_MD5, ABC_SHA1, ABC_SHA256

ROOT = Path(__file__).resolve().parents[1]


def test_tools_share_the_join_columns():
    for fields in (HASH_FIELDS, TRIAGE_FIELDS, ENTROPY_FIELDS):
        assert fields[:3] == ("FullPath", "FileName", "Size")


def test_help_lists_every_subcommand(capsys):
    with pytest.raises(SystemExit) as caught:
        main(["--help"])
    assert caught.value.code == 0
    output = capsys.readouterr().out
    assert "hash" in output
    assert "triage" in output
    assert "entropy" in output
    assert "--csv" in output


def test_version(capsys):
    with pytest.raises(SystemExit) as caught:
        main(["--version"])
    assert caught.value.code == 0
    assert __version__ in capsys.readouterr().out


def test_version_matches_pyproject():
    text = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    assert f'version = "{__version__}"' in text


def test_missing_command_is_exit_2():
    with pytest.raises(SystemExit) as caught:
        main([])
    assert caught.value.code == 2


def test_hash_without_a_path_is_exit_2(capsys):
    assert main(["hash"]) == 2
    assert "at least one -f" in capsys.readouterr().err


def test_hash_file_prints_known_digests(tmp_path, capsys):
    target = tmp_path / "abc.txt"
    target.write_bytes(ABC)
    assert main(["hash", "-f", str(target)]) == 0
    output = capsys.readouterr().out
    assert "MD5: " + ABC_MD5 in output
    assert "SHA1: " + ABC_SHA1 in output
    assert "SHA256: " + ABC_SHA256 in output
    assert f"Size: {len(ABC)}" in output


def test_hash_csv_and_json_share_column_order(tmp_path, capsys):
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    (evidence / "café.bin").write_bytes(ABC)
    nested = evidence / "sub"
    nested.mkdir()
    (nested / "second.txt").write_bytes(b"zz")
    output = tmp_path / "out"

    assert main(["hash", "-d", str(evidence), "--csv", str(output), "--json", str(output)]) == 0
    captured = capsys.readouterr()
    csv_path = output / "hash.csv"
    json_path = output / "hash.json"
    assert f"Wrote {csv_path.resolve()}" in captured.err
    assert f"Wrote {json_path.resolve()}" in captured.err

    raw = csv_path.read_bytes()
    assert raw.startswith(b"\xef\xbb\xbf")
    with csv_path.open(encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        assert reader.fieldnames == list(HASH_FIELDS)
        rows = list(reader)
    assert [row["FileName"] for row in rows] == ["café.bin", "second.txt"]
    assert rows[0]["MD5"] == ABC_MD5
    assert rows[0]["SHA1"] == ABC_SHA1
    assert rows[0]["SHA256"] == ABC_SHA256
    assert rows[0]["Size"] == "3"

    payload = json.loads(json_path.read_text(encoding="utf-8"))
    assert list(payload[0]) == list(HASH_FIELDS)
    assert payload[0]["FileName"] == "café.bin"
    assert payload[0]["Size"] == 3
    assert payload[0]["SHA256"] == ABC_SHA256
    assert json_path.read_text(encoding="utf-8").endswith("\n")


def test_no_recursive_and_empty_directory(tmp_path, capsys):
    evidence = tmp_path / "evidence"
    (evidence / "sub").mkdir(parents=True)
    (evidence / "top.txt").write_bytes(ABC)
    (evidence / "sub" / "nested.txt").write_bytes(b"nested")
    assert main(["hash", "-d", str(evidence), "--no-recursive"]) == 0
    output = capsys.readouterr().out
    assert "top.txt" in output
    assert "nested.txt" not in output

    empty = tmp_path / "empty"
    empty.mkdir()
    assert main(["triage", "-d", str(empty)]) == 0
    assert "No files found." in capsys.readouterr().out


def test_directory_symlink_is_not_followed_and_exit_stays_zero(tmp_path, capsys):
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    (evidence / "inside.txt").write_bytes(ABC)
    outside = tmp_path / "outside.txt"
    outside.write_bytes(b"xyz")
    (evidence / "link.txt").symlink_to(outside)
    assert main(["hash", "-d", str(evidence)]) == 0
    captured = capsys.readouterr()
    assert "FileName: inside.txt" in captured.out
    assert "FileName: link.txt" not in captured.out
    assert "FileName: outside.txt" not in captured.out
    assert "outside.txt" not in captured.out
    assert "Skipping symlink" in captured.err
    assert ABC_SHA256 in captured.out


def test_explicit_symlink_is_exit_2_and_is_not_hashed(tmp_path, capsys):
    target = tmp_path / "abc.txt"
    target.write_bytes(ABC)
    link = tmp_path / "link.txt"
    link.symlink_to(target)
    assert main(["hash", "-f", str(link)]) == 2
    captured = capsys.readouterr()
    assert "Refusing to follow symlink" in captured.err
    assert ABC_SHA256 not in captured.out


def test_csv_inside_evidence_is_exit_2_and_writes_nothing(tmp_path, capsys):
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    (evidence / "abc.txt").write_bytes(ABC)
    assert main(["hash", "-d", str(evidence), "--csv", str(evidence / "reports")]) == 2
    captured = capsys.readouterr()
    assert "Refusing to write output" in captured.err
    assert not (evidence / "reports").exists()
    assert ABC_SHA256 not in captured.out


def test_triage_and_entropy_subcommands(tmp_path, capsys):
    target = tmp_path / "abc.txt"
    target.write_bytes(ABC)
    output = tmp_path / "out"
    assert main(["triage", "-f", str(target), "--csv", str(output)]) == 0
    triage_out = capsys.readouterr().out
    assert "ModifiedTimeUtc:" in triage_out
    assert "MetadataChangeTimeUtc:" in triage_out
    assert "CreationTimeUtc:" in triage_out
    assert "SHA256:" not in triage_out
    with (output / "triage.csv").open(encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        assert reader.fieldnames == list(TRIAGE_FIELDS)
        row = next(reader)
    assert row["Size"] == "3"
    assert row["CreationTimeUtc"] == ""
    assert row["MetadataChangeTimeUtc"] != ""

    assert main(["entropy", "-f", str(target), "--json", str(output)]) == 0
    entropy_out = capsys.readouterr().out
    assert "Entropy: 1.584963" in entropy_out
    assert "Band: low" in entropy_out
    assert "SHA256:" not in entropy_out
    payload = json.loads((output / "entropy.json").read_text(encoding="utf-8"))
    assert list(payload[0]) == list(ENTROPY_FIELDS)
    assert payload[0]["Entropy"] == 1.584963
    assert payload[0]["Band"] == "low"


def test_report_symlink_does_not_truncate_its_target(tmp_path, capsys):
    evidence = tmp_path / "evidence.bin"
    evidence.write_bytes(b"do-not-touch")
    other = tmp_path / "other.txt"
    other.write_bytes(ABC)
    output = tmp_path / "out"
    output.mkdir()
    (output / "hash.csv").symlink_to(evidence)
    code = main(["hash", "-f", str(other), "--csv", str(output)])
    assert code == 2
    assert "Refusing to write through symlink" in capsys.readouterr().err
    assert evidence.read_bytes() == b"do-not-touch"
    assert not (output / "hash.csv").is_file() or (output / "hash.csv").is_symlink()


def test_report_name_that_is_the_evidence_file_is_refused(tmp_path, capsys):
    folder = tmp_path / "case"
    folder.mkdir()
    evidence = folder / "hash.csv"
    evidence.write_bytes(b"do-not-touch")
    code = main(["hash", "-f", str(evidence), "--csv", str(folder)])
    assert code == 2
    assert "Refusing to overwrite evidence file" in capsys.readouterr().err
    assert evidence.read_bytes() == b"do-not-touch"


def test_unsearchable_directory_is_exit_1(tmp_path, capsys):
    if not hasattr(os, "geteuid") or os.geteuid() == 0:
        pytest.skip("root ignores file mode bits")
    secret = tmp_path / "secret"
    secret.mkdir()
    hidden = secret / "hidden.txt"
    hidden.write_bytes(ABC)
    secret.chmod(0)
    try:
        code = main(["hash", "-f", str(hidden)])
    finally:
        secret.chmod(0o755)
    assert code == 1
    captured = capsys.readouterr()
    assert ABC_SHA256 not in captured.out
    assert captured.err.startswith("error:")


def test_non_utf8_filename_is_exported_as_utf8(tmp_path):
    name = os.fsdecode(b"bad\xff.bin")
    target = tmp_path / name
    try:
        target.write_bytes(ABC)
    except OSError:
        pytest.skip("filesystem rejected a non-UTF-8 name")
    output = tmp_path / "out"
    assert main(["hash", "-f", str(target), "--csv", str(output), "--json", str(output)]) == 0
    raw = (output / "hash.csv").read_bytes()
    raw.decode("utf-8")
    text = raw.decode("utf-8-sig")
    assert "bad" in text
    payload = json.loads((output / "hash.json").read_text(encoding="utf-8"))
    assert payload[0]["SHA256"] == ABC_SHA256


def test_unreadable_file_keeps_the_readable_sibling_and_exits_1(tmp_path, capsys):
    if not hasattr(os, "geteuid") or os.geteuid() == 0:
        pytest.skip("root ignores file mode bits")
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    openable = evidence / "open.txt"
    blocked = evidence / "blocked.txt"
    openable.write_bytes(ABC)
    blocked.write_bytes(b"secret")
    blocked.chmod(0)
    try:
        code = main(["hash", "-d", str(evidence)])
    finally:
        blocked.chmod(0o644)
    assert code == 1
    captured = capsys.readouterr()
    assert "FileName: open.txt" in captured.out
    assert ABC_SHA256 in captured.out
    assert "FileName: blocked.txt" not in captured.out
    assert "blocked.txt" in captured.err
    assert "Cannot read" in captured.err


def test_module_entrypoint_matches_hash_output(tmp_path):
    target = tmp_path / "abc.txt"
    target.write_bytes(ABC)
    env = os.environ.copy()
    env["PYTHONPATH"] = str(ROOT) + os.pathsep + env.get("PYTHONPATH", "")
    result = subprocess.run(
        [sys.executable, "-m", "forensicslab", "hash", "-f", str(target)],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0
    assert ABC_SHA256 in result.stdout
    assert ABC_MD5 in result.stdout
