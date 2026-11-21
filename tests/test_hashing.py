"""Hash tests. Expected digests come from tests/vectors.py, not from the tool."""

import os
import sys

import pytest

from forensicslab.evidence import CHUNK_SIZE, EvidenceReader
from forensicslab.hashing import HASH_FIELDS, hash_file

from tests.vectors import (
    ABC,
    ABC_MD5,
    ABC_SHA1,
    ABC_SHA256,
    EMPTY_MD5,
    EMPTY_SHA1,
    EMPTY_SHA256,
    LONG_MD5,
    LONG_PAYLOAD,
    LONG_SHA1,
    LONG_SHA256,
)


def test_chunk_size_matches_the_original_script():
    assert CHUNK_SIZE == 8192
    assert len(LONG_PAYLOAD) > CHUNK_SIZE


def test_empty_file_matches_published_digests(tmp_path):
    target = tmp_path / "empty.bin"
    target.write_bytes(b"")
    result = hash_file(target)
    assert result.size == 0
    assert result.md5 == EMPTY_MD5
    assert result.sha1 == EMPTY_SHA1
    assert result.sha256 == EMPTY_SHA256


def test_abc_matches_published_digests_one_byte_at_a_time(tmp_path):
    # chunk_size=1 forces the update loop to run once per byte. A hasher
    # that only digested the first read would not match the published value.
    target = tmp_path / "abc.txt"
    target.write_bytes(ABC)
    result = hash_file(target, EvidenceReader(chunk_size=1))
    assert result.size == 3
    assert result.md5 == ABC_MD5
    assert result.sha1 == ABC_SHA1
    assert result.sha256 == ABC_SHA256
    assert result.md5 == result.md5.lower()
    assert len(result.md5) == 32
    assert len(result.sha1) == 40
    assert len(result.sha256) == 64


def test_long_file_matches_one_shot_digest_across_chunks(tmp_path):
    target = tmp_path / "long.bin"
    target.write_bytes(LONG_PAYLOAD)
    result = hash_file(target)
    assert result.size == len(LONG_PAYLOAD)
    assert result.md5 == LONG_MD5
    assert result.sha1 == LONG_SHA1
    assert result.sha256 == LONG_SHA256


def test_row_column_order_is_fixed(tmp_path):
    target = tmp_path / "abc.txt"
    target.write_bytes(ABC)
    row = hash_file(target).as_row()
    assert tuple(row) == HASH_FIELDS
    assert row["FileName"] == "abc.txt"
    assert row["Size"] == 3
    assert row["SHA256"] == ABC_SHA256


def test_hashing_does_not_change_bytes_mtime_or_ctime(tmp_path):
    target = tmp_path / "abc.txt"
    target.write_bytes(ABC)
    before = target.stat()
    hash_file(target)
    after = target.stat()
    assert target.read_bytes() == ABC
    assert after.st_size == before.st_size
    assert after.st_mtime_ns == before.st_mtime_ns
    assert after.st_ctime_ns == before.st_ctime_ns
    assert after.st_mode == before.st_mode


def test_fifo_open_fails_instead_of_blocking(tmp_path):
    fifo = tmp_path / "pipe"
    os.mkfifo(fifo)
    reader = EvidenceReader()
    with pytest.raises(OSError, match="Not a regular file"):
        list(reader.chunks(fifo))


def test_owned_linux_file_keeps_its_access_time(tmp_path):
    if not sys.platform.startswith("linux"):
        pytest.skip("O_NOATIME is a Linux flag")
    target = tmp_path / "abc.txt"
    target.write_bytes(ABC)
    # Old enough that a relatime mount would refresh atime on a normal read.
    old = 1_000_000_000_000_000_000
    os.utime(target, ns=(old, old))
    reader = EvidenceReader()
    assert b"".join(reader.chunks(target)) == ABC
    assert target.stat().st_atime_ns == old
    assert reader.atime_warning is None
