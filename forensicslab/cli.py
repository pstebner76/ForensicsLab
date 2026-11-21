"""One command, three subcommands, one set of flags.

``forensicslab hash``, ``forensicslab triage``, and ``forensicslab entropy``
take the same ``-f``, ``-d``, ``--csv``, and ``--json`` arguments. The
tools return rows and error strings. They do not print, and they do not
pick an exit code. That split is what makes them easy to test, and it is
what a later hash-set matcher can call without dragging the CLI along.

Exit codes:

- 0: the run finished. Skipped symlinks and an empty directory are still 0.
- 1: at least one file or directory could not be read. Rows for the files
  that could be read are still written.
- 2: the arguments are wrong, a symlink was passed in explicitly, or an
  output directory would have been created inside a ``-d`` tree.

``argparse`` uses exit code 2 on its own for unknown flags and a missing
subcommand. That happens inside ``parse_args``, before this function
returns.
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from forensicslab import __version__
from forensicslab.entropy import ENTROPY_FIELDS, entropy_paths
from forensicslab.evidence import (
    EvidenceReader,
    UsageError,
    prepare_output_directory,
    refuse_output_alias,
    scan,
    validate_directory,
    validate_file,
)
from forensicslab.hashing import HASH_FIELDS, hash_paths
from forensicslab.output import write_console, write_csv, write_json
from forensicslab.triage import TRIAGE_FIELDS, triage_paths

EXAMPLES = """
examples:
  forensicslab hash -f suspicious.bin
  forensicslab hash -d evidence/ --csv out/ --json out/
  forensicslab triage -d evidence/ --csv out/
  forensicslab entropy -f suspicious.bin --csv out/
  python triage.py suspicious.bin
""".strip()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="forensicslab",
        description=(
            "Read-only file utilities for DFIR practice. Evidence is opened "
            "for reading and is not modified. --csv and --json write outside "
            "any directory you passed with -d."
        ),
        epilog=EXAMPLES,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"forensicslab {__version__}",
    )
    subcommands = parser.add_subparsers(dest="command", required=True, metavar="command")

    hash_parser = subcommands.add_parser(
        "hash",
        help="MD5, SHA-1, and SHA-256 of each file, from one read.",
        description=(
            "Hash file contents. MD5 and SHA-1 are included because existing "
            "hash sets still use them. SHA-256 is the integrity value to "
            "compare when you have a trusted digest. Each file is read once."
        ),
    )
    triage_parser = subcommands.add_parser(
        "triage",
        help="List size and timestamps without reading file contents.",
        description=(
            "List size, modification time, and access time. The ctime field "
            "is split into MetadataChangeTimeUtc and CreationTimeUtc so the "
            "column name matches what this operating system actually stores. "
            "The column that stat() cannot provide is left blank."
        ),
    )
    entropy_parser = subcommands.add_parser(
        "entropy",
        help="Shannon entropy of each file, in bits per byte.",
        description=(
            "Measure how even each file's byte values are. The band is a "
            "triage hint. Packed, encrypted, and compressed files can all "
            "score as very-high."
        ),
    )
    for subparser in (hash_parser, triage_parser, entropy_parser):
        _add_common_arguments(subparser)
    return parser


def _add_common_arguments(parser: argparse.ArgumentParser) -> None:
    """Attach the flags every subcommand accepts.

    A function, not a parent parser, keeps the defaults from being shared
    mutable lists. ``action="append"`` stores ``None`` when the flag is
    omitted; ``main`` turns that into a new list per run.
    """

    parser.add_argument(
        "-f",
        "--file",
        dest="files",
        action="append",
        metavar="PATH",
        help="Regular file to include. Repeat the flag for another file.",
    )
    parser.add_argument(
        "-d",
        "--directory",
        dest="directories",
        action="append",
        metavar="PATH",
        help="Directory of regular files to include. Repeat the flag to add another directory.",
    )
    parser.add_argument(
        "-r",
        "--recursive",
        action=argparse.BooleanOptionalAction,
        default=True,
        help=(
            "Enter subdirectories when scanning a directory. This is the "
            "default. Pass --no-recursive to stay in the top directory."
        ),
    )
    parser.add_argument(
        "--csv",
        metavar="DIR",
        help="Directory to write a UTF-8 CSV file into. Timeline Explorer can open it.",
    )
    parser.add_argument(
        "--json",
        metavar="DIR",
        help="Directory to write a JSON file into.",
    )


def main(argv: list[str] | None = None) -> int:
    """Run one subcommand. Return a process exit code. Do not call ``sys.exit``."""

    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        files = [validate_file(value) for value in (args.files or [])]
        directories = [validate_directory(value) for value in (args.directories or [])]
        if not files and not directories:
            raise UsageError("Provide at least one -f file or -d directory.")
        csv_dir = (
            prepare_output_directory(args.csv, directories) if args.csv else None
        )
        json_dir = (
            prepare_output_directory(args.json, directories) if args.json else None
        )
        found = scan(files, directories, recursive=args.recursive)
    except UsageError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except OSError as exc:
        # stat or mkdir failed. The path may be valid and still unreadable.
        print(f"error: {exc.strerror or exc}", file=sys.stderr)
        return 1

    reader = EvidenceReader()
    if args.command == "hash":
        rows, read_errors = hash_paths(list(found.files), reader)
        fields = HASH_FIELDS
        stem = "hash"
    elif args.command == "triage":
        rows, read_errors = triage_paths(list(found.files))
        fields = TRIAGE_FIELDS
        stem = "triage"
    elif args.command == "entropy":
        rows, read_errors = entropy_paths(list(found.files), reader)
        fields = ENTROPY_FIELDS
        stem = "entropy"
    else:
        print(f"error: Unknown command {args.command}", file=sys.stderr)
        return 2

    # Diagnostics go to stderr so a person can redirect stdout and still
    # have only the records in the redirect.
    if reader.atime_warning:
        print(reader.atime_warning, file=sys.stderr)
    for note in found.notes:
        print(note, file=sys.stderr)

    try:
        write_console(rows, fields)
        # stdout is block-buffered when it is not a terminal. Flush before the
        # stderr "Wrote" lines so the records stay above those lines in a log.
        sys.stdout.flush()
    except BrokenPipeError:
        # ``forensicslab hash -f a | head`` closes the pipe early. Without
        # this handler Python prints a traceback during shutdown. Point
        # stdout at devnull so that final flush has somewhere to go.
        # The exit code is unchanged: a closed pipe is not a failed read.
        _silence_stdout()

    write_failed = False
    policy_refusal = False
    try:
        if csv_dir is not None:
            refuse_output_alias(csv_dir / f"{stem}.csv", found.files)
        if json_dir is not None:
            refuse_output_alias(json_dir / f"{stem}.json", found.files)
        if csv_dir is not None:
            written = write_csv(csv_dir, stem, rows, fields)
            print(f"Wrote {written}", file=sys.stderr)
        if json_dir is not None:
            written = write_json(json_dir, stem, rows, fields)
            print(f"Wrote {written}", file=sys.stderr)
    except UsageError as exc:
        print(f"error: {exc}", file=sys.stderr)
        policy_refusal = True
    except OSError as exc:
        print(f"error: Cannot write output: {exc.strerror or exc}", file=sys.stderr)
        write_failed = True
    else:
        policy_refusal = False

    errors = list(found.errors) + list(read_errors)
    for error in errors:
        print(f"error: {error}", file=sys.stderr)
    if policy_refusal:
        return 2
    if write_failed or errors:
        return 1
    return 0


def _silence_stdout() -> None:
    """Replace stdout so a closed pipe does not raise again at shutdown."""

    try:
        sys.stdout.close()
    except OSError:
        pass
    try:
        fd = os.open(os.devnull, os.O_WRONLY)
    except OSError:
        return
    try:
        os.dup2(fd, 1)
    finally:
        os.close(fd)


def console_main() -> None:
    """Entry point for the ``forensicslab`` console script."""

    sys.exit(main())
