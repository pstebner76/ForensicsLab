"""Entropy tests. 0, 1, and 8 are exact; the text value is a frozen literal."""

import math
from collections import Counter

import pytest

from forensicslab.entropy import (
    ENTROPY_FIELDS,
    entropy_band,
    entropy_file,
    shannon_entropy,
)
from forensicslab.evidence import CHUNK_SIZE, EvidenceReader
from tests.vectors import ABC


def test_empty_and_constant_files_are_zero(tmp_path):
    assert shannon_entropy(Counter(), 0) == 0.0
    assert shannon_entropy(Counter(b"aaaa"), 4) == 0.0

    empty = tmp_path / "empty.bin"
    empty.write_bytes(b"")
    constant = tmp_path / "constant.bin"
    constant.write_bytes(b"\x41" * 50)

    empty_row = entropy_file(empty).as_row()
    constant_row = entropy_file(constant).as_row()
    assert empty_row["Size"] == 0
    assert empty_row["Entropy"] == 0.0
    assert empty_row["Band"] == "very-low"
    assert constant_row["Entropy"] == 0.0
    assert constant_row["Band"] == "very-low"
    assert tuple(empty_row) == ENTROPY_FIELDS


def test_counts_must_match_the_reported_size():
    with pytest.raises(ValueError):
        shannon_entropy(Counter(b"aa"), 1)


def test_two_equally_common_bytes_are_one_bit():
    counts = Counter(b"\x00\xff")
    assert shannon_entropy(counts, 2) == 1.0


def test_all_256_byte_values_once_is_eight_bits():
    payload = bytes(range(256))
    assert shannon_entropy(Counter(payload), len(payload)) == 8.0


def test_abc_entropy_is_log2_of_three_rounded_for_display(tmp_path):
    assert shannon_entropy(Counter(ABC), 3) == math.log2(3)
    target = tmp_path / "abc.txt"
    target.write_bytes(ABC)
    row = entropy_file(target).as_row()
    assert row["Size"] == 3
    assert row["Entropy"] == 1.584963
    assert row["Band"] == "low"


def test_hello_entropy_matches_the_hand_counted_distribution(tmp_path):
    # h:1 e:1 l:2 o:1 over 5 bytes.
    target = tmp_path / "hello.txt"
    target.write_bytes(b"hello")
    row = entropy_file(target).as_row()
    assert row["Entropy"] == 1.921928
    assert row["Band"] == "low"


def test_bytes_past_the_first_chunk_are_counted(tmp_path):
    # The first chunk is all 0x00. The second is all 0xFF. Entropy of the
    # whole file is 1. Entropy of the first chunk alone is 0.
    assert CHUNK_SIZE == 8192
    payload = b"\x00" * CHUNK_SIZE + b"\xff" * CHUNK_SIZE
    target = tmp_path / "halves.bin"
    target.write_bytes(payload)
    row = entropy_file(target, EvidenceReader()).as_row()
    assert row["Size"] == len(payload)
    assert row["Entropy"] == 1.0
    assert row["Band"] == "low"


@pytest.mark.parametrize(
    ("value", "band"),
    [
        (0.0, "very-low"),
        (0.999999, "very-low"),
        (1.0, "low"),
        (3.999999, "low"),
        (4.0, "moderate"),
        (6.499999, "moderate"),
        (6.5, "high"),
        (7.499999, "high"),
        (7.5, "very-high"),
        (8.0, "very-high"),
    ],
)
def test_entropy_bands(value, band):
    assert entropy_band(value) == band
