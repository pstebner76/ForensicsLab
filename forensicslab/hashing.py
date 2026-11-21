"""MD5, SHA-1, and SHA-256 of a file, from a single read.

MD5 and SHA-1 are collision-broken. They are still the digests that show
up in malware databases, NSRL-style hash sets, and older case notes, so a
triage tool that omitted them would not line up with those lists. SHA-256
is the value to trust when you are checking integrity against a digest
that came from a source you trust.

A matching hash means the bytes match. It does not say who wrote the file,
whether it is malicious, or whether the copy you hashed is the original
evidence. Hash the forensic image first, then hash files from a copy or a
mounted image.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path

from forensicslab.evidence import EvidenceReader, read_error_message

# Fixed header order. Timeline Explorer layouts and a future hash-set
# matcher can depend on these names staying put.
HASH_FIELDS = ("FullPath", "FileName", "Size", "MD5", "SHA1", "SHA256")


@dataclass(frozen=True)
class HashResult:
    """Digests of the bytes that were actually read.

    ``size`` is that byte count, not a separate ``stat`` call. If the file
    changed during the read the size and the digests still describe the
    same stream. ``stat`` size lives on the triage tool, which never reads
    contents.
    """

    path: Path
    size: int
    md5: str
    sha1: str
    sha256: str

    def as_row(self) -> dict[str, object]:
        return {
            "FullPath": str(self.path),
            "FileName": self.path.name,
            "Size": self.size,
            "MD5": self.md5,
            "SHA1": self.sha1,
            "SHA256": self.sha256,
        }


def hash_file(path: Path, reader: EvidenceReader | None = None) -> HashResult:
    """Hash one regular file.

    Three hasher objects are updated from each chunk. ``hashlib.file_digest``
    only feeds one algorithm per read, which would walk a large image three
    times and, without ``O_NOATIME``, could touch the access time three times.

    Digests are lowercase hex. That is the form most hash sets compare.
    """

    if reader is None:
        reader = EvidenceReader()
    # usedforsecurity=False marks MD5 and SHA-1 as identifiers, which is all
    # they are here. On a FIPS-mode Python this is also what keeps the
    # constructor from rejecting them. SHA-256 stays on the default: it is
    # the digest we treat as an integrity check.
    md5 = hashlib.md5(usedforsecurity=False)
    sha1 = hashlib.sha1(usedforsecurity=False)
    sha256 = hashlib.sha256()
    size = 0
    for chunk in reader.chunks(path):
        md5.update(chunk)
        sha1.update(chunk)
        sha256.update(chunk)
        size += len(chunk)
    return HashResult(
        path=path,
        size=size,
        md5=md5.hexdigest(),
        sha1=sha1.hexdigest(),
        sha256=sha256.hexdigest(),
    )


def sha256_file(path: Path | str) -> str:
    """SHA-256 hex digest of one file, for the legacy ``triage.py`` script.

    Follows a symlink, because the original script used ``open()`` and
    ``open()`` follows links. The ``forensicslab`` command does not follow
    links; it refuses them before it calls :func:`hash_file`.
    """

    reader = EvidenceReader(follow_symlinks=True)
    return hash_file(Path(path), reader).sha256


def hash_paths(paths: list[Path], reader: EvidenceReader) -> tuple[list[dict[str, object]], list[str]]:
    """Hash each path. A path that cannot be read is an error, not a row.

    A partial digest is worse than a missing one: it looks like a real
    hash and can be matched against the wrong file. On ``OSError`` the
    hashers for that file are discarded.
    """

    rows: list[dict[str, object]] = []
    errors: list[str] = []
    for path in paths:
        try:
            rows.append(hash_file(path, reader).as_row())
        except OSError as exc:
            errors.append(read_error_message(path, exc))
    return rows, errors
