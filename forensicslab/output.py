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
from collections.abc import Mapping, Sequence
from pathlib import Path


def ordered_rows(
    rows: Sequence[Mapping[str, object]], fields: Sequence[str]
) -> list[dict[str, object]]:
    """Copy rows so each dict's keys are exactly ``fields``, in that order.

    A missing key raises ``KeyError`` here, instead of becoming a blank
    cell that an examiner might trust.
    """

    return [{field: row[field] for field in fields} for row in rows]


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
    with destination.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(fields), extrasaction="raise")
        writer.writeheader()
        writer.writerows(ordered)
    return destination


def write_json(
    directory: Path,
    stem: str,
    rows: Sequence[Mapping[str, object]],
    fields: Sequence[str],
) -> Path:
    """Write ``<stem>.json`` as a list of objects and return that path."""

    destination = directory / f"{stem}.json"
    ordered = ordered_rows(rows, fields)
    text = json.dumps(ordered, indent=2, ensure_ascii=False)
    destination.write_text(text + "\n", encoding="utf-8")
    return destination
