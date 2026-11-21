"""Walking, symlink, and output-location rules."""

import os

import pytest

from forensicslab.evidence import (
    UsageError,
    prepare_output_directory,
    scan,
    validate_directory,
    validate_file,
)


def test_recursive_scan_sorts_and_skips_symlinks_and_fifos(tmp_path):
    evidence = tmp_path / "evidence"
    nested = evidence / "sub"
    nested.mkdir(parents=True)
    (evidence / "b.txt").write_bytes(b"b")
    (evidence / "A.txt").write_bytes(b"A")
    (nested / "c.txt").write_bytes(b"c")
    outside = tmp_path / "outside.txt"
    outside.write_bytes(b"outside")
    (evidence / "link.txt").symlink_to(outside)
    (evidence / "linkdir").symlink_to(nested, target_is_directory=True)
    os.mkfifo(evidence / "pipe")

    # A second hard link is a different name and must stay in the list.
    os.link(evidence / "b.txt", evidence / "b-hardlink.txt")

    result = scan([], [validate_directory(evidence)], recursive=True)
    names = [path.name for path in result.files]
    assert names == ["A.txt", "b-hardlink.txt", "b.txt", "c.txt"]
    assert all(path.is_absolute() for path in result.files)
    notes = "\n".join(result.notes)
    assert "link.txt" in notes
    assert "linkdir" in notes
    assert "pipe" in notes
    assert "Skipping symlink" in notes
    assert "Skipping non-regular file" in notes
    assert result.errors == ()


def test_case_only_differences_sort_by_the_raw_path(tmp_path):
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    (evidence / "b.txt").write_bytes(b"b")
    (evidence / "B.txt").write_bytes(b"B")
    result = scan([], [validate_directory(evidence)], recursive=True)
    assert [path.name for path in result.files] == ["B.txt", "b.txt"]


def test_no_recursive_still_notes_a_symlink_directory(tmp_path):
    evidence = tmp_path / "evidence"
    nested = evidence / "sub"
    nested.mkdir(parents=True)
    (evidence / "top.txt").write_bytes(b"top")
    (evidence / "linkdir").symlink_to(nested, target_is_directory=True)
    result = scan([], [validate_directory(evidence)], recursive=False)
    assert [path.name for path in result.files] == ["top.txt"]
    assert any("linkdir" in note for note in result.notes)


def test_no_recursive_stays_in_the_top_directory(tmp_path):
    evidence = tmp_path / "evidence"
    (evidence / "sub").mkdir(parents=True)
    (evidence / "top.txt").write_bytes(b"top")
    (evidence / "sub" / "nested.txt").write_bytes(b"nested")
    result = scan([], [validate_directory(evidence)], recursive=False)
    assert [path.name for path in result.files] == ["top.txt"]


def test_explicit_file_and_directory_listing_dedupe(tmp_path):
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    target = evidence / "a.txt"
    target.write_bytes(b"a")
    result = scan([validate_file(target)], [validate_directory(evidence)], recursive=True)
    assert [path.name for path in result.files] == ["a.txt"]


def test_explicit_symlink_is_rejected(tmp_path):
    target = tmp_path / "a.txt"
    target.write_bytes(b"a")
    link = tmp_path / "link.txt"
    link.symlink_to(target)
    with pytest.raises(UsageError, match="Refusing to follow symlink"):
        validate_file(link)


def test_directory_passed_as_file_is_rejected(tmp_path):
    with pytest.raises(UsageError, match="Not a regular file"):
        validate_file(tmp_path)


def test_file_passed_as_directory_is_rejected(tmp_path):
    target = tmp_path / "a.txt"
    target.write_bytes(b"a")
    with pytest.raises(UsageError, match="Not a directory"):
        validate_directory(target)


def test_missing_path_is_rejected(tmp_path):
    missing = tmp_path / "missing.bin"
    with pytest.raises(UsageError, match="No such file"):
        validate_file(missing)


def test_output_directory_inside_evidence_is_refused(tmp_path):
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    nested = evidence / "reports"
    tricky = evidence / ".." / evidence.name
    with pytest.raises(UsageError, match="Refusing to write output"):
        prepare_output_directory(nested, [evidence])
    with pytest.raises(UsageError, match="Refusing to write output"):
        prepare_output_directory(tricky, [evidence.resolve()])
    assert not nested.exists()


def test_output_symlink_into_evidence_is_refused(tmp_path):
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    decoy = tmp_path / "decoy"
    decoy.symlink_to(evidence, target_is_directory=True)
    with pytest.raises(UsageError, match="Refusing to write output"):
        prepare_output_directory(decoy, [evidence])
    assert not (evidence / "hash.csv").exists()


def test_output_directory_beside_evidence_is_created(tmp_path):
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    output = tmp_path / "out"
    created = prepare_output_directory(output, [evidence])
    assert created == output.resolve()
    assert created.is_dir()


def test_unreadable_directory_is_an_error_not_a_silent_skip(tmp_path):
    if not hasattr(os, "geteuid") or os.geteuid() == 0:
        pytest.skip("root ignores file mode bits")
    evidence = tmp_path / "evidence"
    secret = evidence / "secret"
    secret.mkdir(parents=True)
    (secret / "hidden.txt").write_bytes(b"hidden")
    (evidence / "visible.txt").write_bytes(b"visible")
    secret.chmod(0)
    try:
        result = scan([], [validate_directory(evidence)], recursive=True)
    finally:
        secret.chmod(0o755)
    assert [path.name for path in result.files] == ["visible.txt"]
    assert any("secret" in error and error.startswith("Cannot list") for error in result.errors)
