"""Timestamp tests. The platform split is checked without needing Windows or macOS."""

import os
from types import SimpleNamespace

from forensicslab.triage import (
    TRIAGE_FIELDS,
    format_timestamp_ns,
    split_ctime,
    timestamps_from_stat,
    triage_file,
    triage_paths,
)

NS = 1_000_000_000_123456789


def test_format_timestamp_ns_is_utc_with_nanoseconds():
    assert format_timestamp_ns(0) == "1970-01-01T00:00:00.000000000Z"
    assert format_timestamp_ns(NS) == "2001-09-09T01:46:40.123456789Z"


def test_windows_ctime_is_labeled_creation():
    metadata, creation = split_ctime(NS, None, "win32")
    assert metadata == ""
    assert creation == format_timestamp_ns(NS)


def test_unix_ctime_is_labeled_metadata_change():
    metadata, creation = split_ctime(NS, None, "linux")
    assert metadata == format_timestamp_ns(NS)
    assert creation == ""


def test_float_birth_time_still_fills_creation():
    # Older interpreters expose st_birthtime and not st_birthtime_ns.
    info = SimpleNamespace(
        st_mtime_ns=NS,
        st_atime_ns=NS,
        st_ctime_ns=NS,
        st_birthtime=1_000_000_000.0,
    )
    row = timestamps_from_stat(info, "darwin")
    assert row["MetadataChangeTimeUtc"] == format_timestamp_ns(NS)
    assert row["CreationTimeUtc"] != ""


def test_bad_timestamp_does_not_abort_the_rest_of_the_run(tmp_path, monkeypatch):
    target = tmp_path / "odd.txt"
    target.write_bytes(b"x")

    def explode(_nanoseconds: int) -> str:
        raise OverflowError("timestamp out of range")

    monkeypatch.setattr("forensicslab.triage.format_timestamp_ns", explode)
    rows, errors = triage_paths([target])
    assert rows == []
    assert "odd.txt" in errors[0]


def test_macos_birth_time_fills_creation_without_relabeling_ctime():
    birth = 900_000_000_000000000
    metadata, creation = split_ctime(NS, birth, "darwin")
    assert metadata == format_timestamp_ns(NS)
    assert creation == format_timestamp_ns(birth)
    assert metadata != creation


def test_triage_reports_size_and_the_clocks_stat_actually_has(tmp_path):
    target = tmp_path / "note.txt"
    target.write_bytes(b"hello")
    atime_ns = 1_100_000_000_000000000
    mtime_ns = 1_200_000_000_000000000
    os.utime(target, ns=(atime_ns, mtime_ns))
    before = target.stat()
    row = triage_file(target).as_row()
    after = target.stat()

    assert tuple(row) == TRIAGE_FIELDS
    assert row["FileName"] == "note.txt"
    assert row["Size"] == 5
    assert row["ModifiedTimeUtc"] == format_timestamp_ns(after.st_mtime_ns)
    assert row["AccessTimeUtc"] == format_timestamp_ns(after.st_atime_ns)
    assert row["ModifiedTimeUtc"] != row["AccessTimeUtc"]
    # This host's stat() has no birth time, so creation stays blank and
    # ctime is reported as a metadata change. utime itself updates ctime,
    # which is why the value is read back from stat rather than predicted.
    assert row["MetadataChangeTimeUtc"] == format_timestamp_ns(after.st_ctime_ns)
    assert row["CreationTimeUtc"] == ""
    assert after.st_mtime_ns == before.st_mtime_ns
    assert target.read_bytes() == b"hello"
