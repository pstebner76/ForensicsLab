"""List size and timestamps for regular files. Do not read their bytes.

This is the metadata companion to ``hash``. It uses ``lstat``, which does
not open the file and does not follow symlinks, so it does not change the
file's access time and it does not hash a link target by mistake.

What ``st_ctime`` means depends on the operating system. The C library
used one field name for two different clocks:

- On Windows, ``st_ctime`` is the creation time.
- On Linux and macOS, ``st_ctime`` is the metadata-change time: the last
  time the inode changed (permissions, owner, rename, link count), not
  the time the file was born.

Those are different facts, so they are different columns. The column that
does not apply on this platform is left blank. A blank is "stat() does not
provide this", not "the event never happened".

macOS can also expose a birth time as ``st_birthtime``. When that field
exists it fills ``CreationTimeUtc``, and ``st_ctime`` still fills
``MetadataChangeTimeUtc``. This Linux build of Python has no birth time,
so ``CreationTimeUtc`` is blank here. Copying a file onto another disk
replaces all of these clocks with new ones. Timestamps describe the copy
you are looking at.
"""

from __future__ import annotations

import errno
import os
import stat
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from forensicslab.evidence import read_error_message

TRIAGE_FIELDS = (
    "FullPath",
    "FileName",
    "Size",
    "ModifiedTimeUtc",
    "AccessTimeUtc",
    "MetadataChangeTimeUtc",
    "CreationTimeUtc",
)


def format_timestamp_ns(nanoseconds: int) -> str:
    """Format a ``stat`` nanosecond clock as UTC, with 9 fractional digits.

    File timestamps from ``os.stat`` are POSIX time, not local time. UTC
    keeps two examiners on two laptops from writing down different clocks
    for the same inode. The suffix ``Z`` is the UTC marker. Nine digits
    keep the full ``st_mtime_ns`` value; filesystems that only store
    microseconds simply have zeros in the last three places.
    """

    seconds, remainder = divmod(int(nanoseconds), 1_000_000_000)
    # fromtimestamp takes seconds. The remainder is concatenated, not added
    # as a float, so the nanoseconds are not rounded by binary floating point.
    moment = datetime.fromtimestamp(seconds, timezone.utc)
    return moment.strftime("%Y-%m-%dT%H:%M:%S.") + f"{remainder:09d}Z"


def split_ctime(ctime_ns: int, birth_ns: int | None, platform: str) -> tuple[str, str]:
    """Return ``(metadata_change, creation)`` for one ``st_ctime`` value.

    ``platform`` is passed in, rather than read only from ``sys.platform``,
    so the Windows and macOS rules can be tested on a Linux machine. The
    caller passes ``sys.platform`` for a real file.
    """

    if platform == "win32":
        # Windows st_ctime is creation. The stdlib stat result has no
        # separate metadata-change time, so that column stays blank.
        return "", format_timestamp_ns(ctime_ns)
    metadata = format_timestamp_ns(ctime_ns)
    creation = "" if birth_ns is None else format_timestamp_ns(birth_ns)
    return metadata, creation


def _birth_ns(info: os.stat_result) -> int | None:
    """Return a birth time in nanoseconds, if this stat result has one.

    The float fallback loses sub-nanosecond precision. It exists so a
    build that only has ``st_birthtime`` still fills ``CreationTimeUtc``
    instead of leaving a blank that looks like "no birth time".
    """

    birth_ns = getattr(info, "st_birthtime_ns", None)
    if birth_ns is not None:
        return int(birth_ns)
    birth = getattr(info, "st_birthtime", None)
    if birth is None:
        return None
    return int(birth * 1_000_000_000)


def timestamps_from_stat(info: os.stat_result, platform: str | None = None) -> dict[str, str]:
    """Map one ``stat`` result onto the four timestamp columns."""

    system = sys.platform if platform is None else platform
    # CPython on Windows documents st_ctime as creation time and does not
    # offer a separate birth field. Other platforms may expose st_birthtime_ns
    # or, on older builds, only the float st_birthtime.
    birth_ns = None if system == "win32" else _birth_ns(info)
    metadata, creation = split_ctime(info.st_ctime_ns, birth_ns, system)
    return {
        "ModifiedTimeUtc": format_timestamp_ns(info.st_mtime_ns),
        "AccessTimeUtc": format_timestamp_ns(info.st_atime_ns),
        "MetadataChangeTimeUtc": metadata,
        "CreationTimeUtc": creation,
    }


@dataclass(frozen=True)
class TriageRecord:
    path: Path
    size: int
    timestamps: dict[str, str]

    def as_row(self) -> dict[str, object]:
        row: dict[str, object] = {
            "FullPath": str(self.path),
            "FileName": self.path.name,
            "Size": self.size,
        }
        row.update(self.timestamps)
        return row


def triage_file(path: Path, platform: str | None = None) -> TriageRecord:
    """Record size and timestamps for one regular file.

    ``lstat`` does not follow symlinks and does not read bytes. ``Size``
    here is ``st_size``. The hash tool's ``Size`` is the number of bytes
    it read. They match for a regular file that is not changing.
    """

    info = path.lstat()
    if stat.S_ISLNK(info.st_mode):
        raise OSError(errno.ELOOP, "Refusing to follow symlink", str(path))
    if not stat.S_ISREG(info.st_mode):
        raise OSError(errno.EINVAL, "Not a regular file", str(path))
    return TriageRecord(
        path=path,
        size=info.st_size,
        timestamps=timestamps_from_stat(info, platform),
    )


def triage_paths(paths: list[Path]) -> tuple[list[dict[str, object]], list[str]]:
    """Triage each path. An unreadable stat result is an error, not a row."""

    rows: list[dict[str, object]] = []
    errors: list[str] = []
    for path in paths:
        try:
            rows.append(triage_file(path).as_row())
        except OSError as exc:
            errors.append(read_error_message(path, exc))
        except (OverflowError, ValueError) as exc:
            # datetime.fromtimestamp rejects timestamps far outside the
            # range it can represent. One odd file should not abort the rest.
            errors.append(f"Cannot format timestamps for {path}: {exc}")
    return rows, errors
