"""How every tool is allowed to touch a disk.

The rules live here so a new command cannot accidentally invent a looser
policy of its own:

- Open evidence with ``os.O_RDONLY`` only. No write flag is ever set.
- On Linux, also try ``O_NOATIME`` so reading contents does not refresh
  the file's access time. Fall back, and remember to warn, if the kernel
  refuses that flag.
- Do not follow symlinks. ``O_NOFOLLOW`` covers the gap between the
  ``lstat`` check and the ``open`` call.
- Walk directories with ``followlinks=False``, and prune symlink
  directories explicitly so the skip is visible.
- Refuse to create an output directory inside a directory the user
  passed with ``-d``. Results are not evidence and must not land in it.

Listing a directory can still update that directory's own access time.
There is no portable flag that prevents it. File contents are never
written.
"""

import errno
import os
import stat
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO

# 8192 is the buffer the original triage.py used. Any positive size hashes
# and counts the same bytes. The loop, not the size, is what has to be right.
# 8 KiB is small enough to reason about and large enough that we do not call
# read() once per byte.
CHUNK_SIZE = 8192

ATIME_WARNING = (
    "Opened at least one file without O_NOATIME, so that file's access time "
    "may have been updated by this read. On Linux this happens when the "
    "kernel rejects O_NOATIME (the process is not the file owner, or the "
    "filesystem does not allow the flag). Windows has no O_NOATIME flag in "
    "Python's os module."
)

# These errnos mean "O_NOATIME was the problem", not "the file cannot be
# read". EPERM is the usual Linux answer when the caller is not the owner.
# EINVAL / EOPNOTSUPP show up on filesystems that do not implement the flag.
_NOATIME_REFUSED = {errno.EPERM, errno.EINVAL}
if hasattr(errno, "EOPNOTSUPP"):
    _NOATIME_REFUSED.add(errno.EOPNOTSUPP)
if hasattr(errno, "ENOTSUP"):
    _NOATIME_REFUSED.add(errno.ENOTSUP)


class UsageError(Exception):
    """The user asked for something the tool will not do.

    Raised by validation, not by a failed read. ``cli.main`` turns it
    into exit code 2. Library code must not call ``sys.exit`` itself, or
    tests and future callers cannot recover.
    """


@dataclass(frozen=True)
class ScanResult:
    """Files a command should process, plus what the walk could not do.

    ``notes`` are decisions, such as skipping a symlink. They do not fail
    the run. ``errors`` are directories that could not be listed. Those do
    fail the run, even if some files were still hashed.
    """

    files: tuple[Path, ...]
    notes: tuple[str, ...]
    errors: tuple[str, ...]


def read_error_message(path: Path, exc: OSError) -> str:
    """Turn an ``OSError`` from a read into one line for stderr.

    ``O_NOFOLLOW`` fails with ``ELOOP`` when the path is a symlink. Say
    that in the same words as the up-front check, so both paths teach the
    same rule.
    """

    if exc.errno == errno.ELOOP:
        return f"Refusing to follow symlink: {path}"
    reason = exc.strerror or str(exc)
    return f"Cannot read {path}: {reason}"


def validate_file(raw: str | Path) -> Path:
    """Return the resolved path of one regular file the user named with ``-f``."""

    path = Path(raw).expanduser()
    info = _lstat_or_raise(path)
    if stat.S_ISLNK(info.st_mode):
        raise UsageError(
            f"Refusing to follow symlink: {path}. "
            "Pass the real file path if that is the file you want to read."
        )
    if not stat.S_ISREG(info.st_mode):
        raise UsageError(f"Not a regular file: {path}")
    return path.resolve()


def validate_directory(raw: str | Path) -> Path:
    """Return the resolved path of one directory the user named with ``-d``."""

    path = Path(raw).expanduser()
    info = _lstat_or_raise(path)
    if stat.S_ISLNK(info.st_mode):
        raise UsageError(
            f"Refusing to follow symlink: {path}. "
            "Pass the real directory path if that is the tree you want to scan."
        )
    if not stat.S_ISDIR(info.st_mode):
        raise UsageError(f"Not a directory: {path}")
    return path.resolve()


def prepare_output_directory(raw: str | Path, evidence_directories: Sequence[Path]) -> Path:
    """Create an output directory that is not inside any ``-d`` tree.

    A single file passed with ``-f`` does not reserve its parent folder.
    Writing ``hash.csv`` beside one file is allowed. Writing it inside a
    directory you asked to scan is not: the CSV would become part of the
    evidence the next time that directory was listed.
    """

    destination = Path(raw).expanduser().resolve()
    for evidence in evidence_directories:
        root = evidence.resolve()
        if _is_inside(destination, root):
            raise UsageError(
                f"Refusing to write output to {destination} because it is inside "
                f"the evidence directory {root}. Pick a directory outside the evidence."
            )
    if destination.exists() and not destination.is_dir():
        raise UsageError(f"Output path is not a directory: {destination}")
    try:
        destination.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise UsageError(
            f"Cannot create output directory {destination}: {exc.strerror or exc}"
        ) from exc
    return destination


def scan(files: Sequence[Path], directories: Sequence[Path], *, recursive: bool) -> ScanResult:
    """Collect regular files, skipping symlinks and non-regular files.

    ``files`` and ``directories`` must already be validated. The same
    resolved path is returned once, even if ``-f`` and ``-d`` both reach
    it. Hard links stay separate: two names can both matter in a listing,
    even when the bytes are the same inode.

    Results are sorted so the same tree always produces the same CSV.
    Filesystem order is not acquisition order, and it is not stable.
    """

    notes: list[str] = []
    errors: list[str] = []
    chosen: dict[str, Path] = {}

    def add(path: Path) -> None:
        try:
            resolved = path.resolve()
        except OSError as exc:
            errors.append(f"Cannot stat {path}: {exc.strerror or exc}")
            return
        # normcase is a no-op on Linux and folds case on Windows, so the
        # same file is not listed twice when the only difference is case.
        key = os.path.normcase(str(resolved))
        chosen.setdefault(key, resolved)

    for file in files:
        add(file)

    for directory in directories:
        _scan_directory(directory, recursive=recursive, add=add, notes=notes, errors=errors)

    ordered = sorted(chosen.values(), key=lambda path: os.path.normcase(str(path)).casefold())
    return ScanResult(tuple(ordered), tuple(notes), tuple(errors))


class EvidenceReader:
    """Read file contents under the rules in the module docstring.

    One reader is created per command. It remembers whether any open had
    to skip ``O_NOATIME``, so the CLI can print a single warning instead
    of one warning per file.

    ``follow_symlinks`` defaults to false. The legacy ``triage.py`` script
    sets it true because the original ``open()`` followed links. New code
    should leave the default alone.
    """

    def __init__(self, chunk_size: int = CHUNK_SIZE, *, follow_symlinks: bool = False) -> None:
        if chunk_size <= 0:
            raise ValueError("chunk_size must be positive")
        self.chunk_size = chunk_size
        self.follow_symlinks = follow_symlinks
        self.atime_warning: str | None = None

    def chunks(self, path: Path):
        """Yield the file in pieces until ``read`` returns ``b""``.

        ``b""`` means end of file. A short read in the middle is just a
        short chunk and must be hashed or counted like any other.
        """

        _require_regular_file(path, follow_symlinks=self.follow_symlinks)
        handle, preserved = _open_read_only(path, follow_symlinks=self.follow_symlinks)
        if not preserved and self.atime_warning is None:
            self.atime_warning = ATIME_WARNING
        try:
            while True:
                block = handle.read(self.chunk_size)
                if not block:
                    break
                yield block
        finally:
            handle.close()


def _lstat_or_raise(path: Path) -> os.stat_result:
    """``lstat`` the path, or raise ``UsageError`` with the path the user typed.

    ``lstat`` does not follow a symlink, so a link can be reported as a
    link instead of as "no such file" or as whatever it points at.
    """

    try:
        return path.lstat()
    except FileNotFoundError:
        raise UsageError(f"No such file: {path}") from None
    except OSError as exc:
        raise UsageError(f"Cannot stat {path}: {exc.strerror or exc}") from None


def _is_inside(path: Path, parent: Path) -> bool:
    """True when ``path`` is ``parent`` or a directory inside it."""

    try:
        path.relative_to(parent)
    except ValueError:
        return False
    return True


def _scan_directory(directory: Path, *, recursive: bool, add, notes: list[str], errors: list[str]) -> None:
    def onerror(exc: OSError) -> None:
        location = getattr(exc, "filename", None) or directory
        errors.append(f"Cannot list {location}: {exc.strerror or exc}")

    # followlinks=False: os.walk will not enter a symlink directory. The
    # prune below is still required. It is the supported way to stop a
    # descent, and it is where the skip is recorded for the analyst.
    for dirpath, dirnames, filenames in os.walk(directory, followlinks=False, onerror=onerror):
        if not recursive:
            # Slice assignment, not ``dirnames = []``. os.walk keeps the
            # same list object and looks at it after this loop body. A
            # plain assignment would only rebind the local name, and the
            # walk would still descend.
            dirnames[:] = []
        else:
            kept: list[str] = []
            for name in dirnames:
                candidate = Path(dirpath) / name
                try:
                    is_link = candidate.is_symlink()
                except OSError as exc:
                    errors.append(f"Cannot stat {candidate}: {exc.strerror or exc}")
                    continue
                if is_link:
                    notes.append(f"Skipping symlink: {candidate}")
                    continue
                kept.append(name)
            dirnames[:] = kept

        for name in filenames:
            _consider_file(Path(dirpath) / name, add=add, notes=notes, errors=errors)


def _consider_file(path: Path, *, add, notes: list[str], errors: list[str]) -> None:
    try:
        info = path.lstat()
    except OSError as exc:
        errors.append(f"Cannot stat {path}: {exc.strerror or exc}")
        return
    if stat.S_ISLNK(info.st_mode):
        notes.append(f"Skipping symlink: {path}")
        return
    if stat.S_ISREG(info.st_mode):
        add(path)
        return
    if stat.S_ISDIR(info.st_mode):
        return
    # A fifo or device node is not evidence we can hash safely. Opening a
    # named pipe would block the tool forever, waiting for a writer.
    notes.append(f"Skipping non-regular file: {path}")


def _require_regular_file(path: Path, *, follow_symlinks: bool) -> None:
    info = path.lstat()
    if stat.S_ISLNK(info.st_mode) and not follow_symlinks:
        raise OSError(errno.ELOOP, "Refusing to follow symlink", str(path))
    described = path.stat() if follow_symlinks and stat.S_ISLNK(info.st_mode) else info
    if not stat.S_ISREG(described.st_mode):
        raise OSError(errno.EINVAL, "Not a regular file", str(path))


def _open_read_only(path: Path, *, follow_symlinks: bool) -> tuple[BinaryIO, bool]:
    """Open ``path`` for reading. Return ``(handle, atime_preserved)``.

    The second value is true only when the kernel accepted ``O_NOATIME``.
    A false value means the handle is still read-only, but the access time
    may move. Callers warn once for that case.
    """

    flags = os.O_RDONLY
    if hasattr(os, "O_BINARY"):
        # Windows text mode would translate bytes. Evidence hashes must see
        # the bytes on disk. POSIX Python ignores this flag; it is absent there.
        flags |= os.O_BINARY
    if not follow_symlinks and hasattr(os, "O_NOFOLLOW"):
        # Closes the race where the path becomes a symlink after lstat and
        # before open. The kernel then fails the open with ELOOP instead of
        # handing us the target's bytes.
        flags |= os.O_NOFOLLOW

    noatime = getattr(os, "O_NOATIME", 0)
    if noatime:
        try:
            return _fdopen(os.open(path, flags | noatime)), True
        except OSError as exc:
            if exc.errno not in _NOATIME_REFUSED:
                raise
    return _fdopen(os.open(path, flags)), False


def _fdopen(fd: int) -> BinaryIO:
    try:
        return os.fdopen(fd, "rb")
    except Exception:
        os.close(fd)
        raise
