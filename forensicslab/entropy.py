"""Shannon entropy of each file, in bits per byte.

Entropy measures how even the byte values are. It does not identify
malware. A value near 0 means the file is repetitive (a run of one byte,
or an empty file). Plain text usually lands lower than compressed or
encrypted bytes. A value near 8 means every byte value shows up about
equally often, which is what packed, compressed, and encrypted files tend
to look like. An ordinary ZIP archive is also near 8. Read the band as a
hint to look closer, then check the file type before treating the number
as suspicion.

The math is::

    H = -sum(p * log2(p))

where ``p`` is the fraction of bytes that have a given value. The maximum
for a byte is 8, because there are 256 possible values and
``log2(256) == 8``.

Counts are kept in a :class:`collections.Counter`. A ``bytes`` object
iterates as integers in ``0..255``, so ``Counter.update(chunk)`` tallies
byte values and does not store the chunk. The counter never has more than
256 keys, however large the file is.
"""

from __future__ import annotations

import math
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

from forensicslab.evidence import EvidenceReader, read_error_message

ENTROPY_FIELDS = ("FullPath", "FileName", "Size", "Entropy", "Band")


def shannon_entropy(counts: Counter[int], total: int) -> float:
    """Entropy in bits per byte for a tally of byte values.

    ``total`` is the number of bytes read. It is passed in, rather than
    taken from ``counts.total()``, so the denominator is the same number
    the tool reports as ``Size``. An empty file has no distribution. The
    formula would divide by zero; this returns ``0.0`` so the column stays
    numeric, and the band is ``very-low``.
    """

    if total <= 0:
        return 0.0
    counted = sum(counts.values())
    if counted != total:
        raise ValueError(
            f"byte counts add up to {counted}, not the reported size {total}"
        )
    entropy = 0.0
    for count in counts.values():
        if count <= 0:
            continue
        probability = count / total
        entropy -= probability * math.log2(probability)
    return entropy


def entropy_band(value: float) -> str:
    """A coarse label for triage, computed from the rounded entropy.

    The cut points are a reading aid, not a detector:

    - below 1: very-low (empty, or almost a single repeated byte)
    - below 4: low (text and other structured data often land here)
    - below 6.5: moderate
    - below 7.5: high (many compressed and media files)
    - 7.5 and above: very-high (packed, encrypted, or heavily compressed)
    """

    if value < 1.0:
        return "very-low"
    if value < 4.0:
        return "low"
    if value < 6.5:
        return "moderate"
    if value < 7.5:
        return "high"
    return "very-high"


@dataclass(frozen=True)
class EntropyRecord:
    path: Path
    size: int
    entropy: float

    def as_row(self) -> dict[str, object]:
        # Round first, then pick the band, so the label matches the number
        # written to the CSV even when a raw value sits on a boundary.
        rounded = round(self.entropy, 6)
        return {
            "FullPath": str(self.path),
            "FileName": self.path.name,
            "Size": self.size,
            "Entropy": rounded,
            "Band": entropy_band(rounded),
        }


def entropy_file(path: Path, reader: EvidenceReader | None = None) -> EntropyRecord:
    """Measure one regular file. ``Size`` is the number of bytes counted."""

    if reader is None:
        reader = EvidenceReader()
    counts: Counter[int] = Counter()
    total = 0
    for chunk in reader.chunks(path):
        # bytes iterates as integers 0..255. update() adds those tallies.
        # Passing a dict would add keys instead of counting bytes, which
        # is a different operation with the same method name.
        counts.update(chunk)
        total += len(chunk)
    return EntropyRecord(path=path, size=total, entropy=shannon_entropy(counts, total))


def entropy_paths(
    paths: list[Path], reader: EvidenceReader
) -> tuple[list[dict[str, object]], list[str]]:
    """Measure each path. A path that cannot be read is an error, not a row."""

    rows: list[dict[str, object]] = []
    errors: list[str] = []
    for path in paths:
        try:
            rows.append(entropy_file(path, reader).as_row())
        except OSError as exc:
            errors.append(read_error_message(path, exc))
    return rows, errors
