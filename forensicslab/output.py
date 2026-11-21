"""Console, CSV, and JSON writers shared by every subcommand.

Column order is part of the tool's contract. The same tuple drives the
console lines, the CSV header, and the JSON keys, so a row cannot silently
gain a different shape in one format. CSV is aimed at Timeline Explorer:
UTF-8 with a byte-order mark, and CRLF line endings (the csv module's
default). JSON is UTF-8 without a BOM, indented, with non-ASCII paths
left as themselves.
"""

import csv
import json
import os
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path


def ordered_rows(
    rows: Sequence[Mapping[str, object]], fields: Sequence[str]
) -> list[dict[str, object]]:
    """Copy rows so each dict's keys are exactly ``fields``, in that order.

    A missing key raises ``KeyError`` here, instead of becoming a blank
    cell that an examiner might trust.
    """

    return [{field: _portable_text(row[field]) for field in fields} for row in rows]


def _portable_text(value: object) -> object:
    """Make a path safe to encode as UTF-8.

    POSIX allows filenames that are not UTF-8. Python represents those
    bytes as lone surrogates (``surrogateescape``). A strict UTF-8 encode
    then raises ``UnicodeEncodeError`` and the export dies mid-file.
    Round-tripping through ``surrogateescape`` and ``backslashreplace``
    keeps the byte in the cell as ``\\xff`` and leaves real Unicode alone.
    """

    if not isinstance(value, str):
        return value
    return value.encode("utf-8", "surrogateescape").decode("utf-8", "backslashreplace")


def write_console(rows: Sequence[Mapping[str, object]], fields: Sequence[str]) -> None:
    """Print one block per file. Blocks are separated by a blank line."""

    ordered = ordered_rows(rows, fields)
    if not ordered:
        print("No files found.")
        return
    for index, row in enumerate(ordered):
        if index:
            print()
        for field in fields:
            print(f"{field}: {row[field]}")


def write_csv(
    directory: Path,
    stem: str,
    rows: Sequence[Mapping[str, object]],
    fields: Sequence[str],
) -> Path:
    """Write ``<stem>.csv`` into ``directory`` and return that path.

    ``newline=""`` is required by the ``csv`` module. It lets the writer
    emit ``\\r\\n`` itself. Opening the file in text mode without that
    argument would turn each row break into ``\\r\\r\\n`` on Windows.

    ``utf-8-sig`` writes a BOM so Excel and Timeline Explorer read the
    file as UTF-8 instead of guessing a legacy code page and splitting a
    non-ASCII path into the wrong columns.
    """

    destination = directory / f"{stem}.csv"
    ordered = ordered_rows(rows, fields)

    def write(handle) -> None:
        writer = csv.DictWriter(handle, fieldnames=list(fields), extrasaction="raise")
        writer.writeheader()
        writer.writerows(ordered)

    return _publish(directory, destination.name, "utf-8-sig", write)


def write_json(
    directory: Path,
    stem: str,
    rows: Sequence[Mapping[str, object]],
    fields: Sequence[str],
) -> Path:
    """Write ``<stem>.json`` as a list of objects and return that path."""

    destination = directory / f"{stem}.json"
    ordered = ordered_rows(rows, fields)
    text = json.dumps(ordered, indent=2, ensure_ascii=False) + "\n"

    def write(handle) -> None:
        handle.write(text)

    return _publish(directory, destination.name, "utf-8", write)


def _publish(directory: Path, name: str, encoding: str, write: Callable[[object], None]) -> Path:
    """Write ``name`` via a new temp file, then rename it into place.

    The temp file is created with ``O_EXCL`` and ``O_NOFOLLOW``, so a
    symlink parked under the temp name is not followed and not truncated.
    ``os.replace`` then swaps the directory entry. It does not open the
    old path, so a symlink at ``name`` is replaced rather than followed.

    Callers still refuse that symlink up front. Replacing it would drop
    the link the analyst created, which is a surprising side effect even
    though the target file would survive.
    """

    destination = directory / name
    temporary = directory / f".{name}.{os.getpid()}.tmp"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    if hasattr(os, "O_BINARY"):
        flags |= os.O_BINARY
    fd = os.open(temporary, flags, 0o644)
    try:
        handle = os.fdopen(fd, "w", encoding=encoding, newline="")
    except Exception:
        os.close(fd)
        temporary.unlink(missing_ok=True)
        raise
    try:
        with handle:
            write(handle)
        os.replace(temporary, destination)
    except Exception:
        temporary.unlink(missing_ok=True)
        raise
    return destination
