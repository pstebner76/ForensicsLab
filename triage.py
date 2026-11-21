"""SHA-256 a single file.

Historical entry point. ``python triage.py <file>`` still prints one
SHA-256 digest and nothing else, which is what the original script did.
The hashing itself lives in :mod:`forensicslab.hashing`.

Prefer ``forensicslab hash``. It also computes MD5 and SHA-1, accepts a
directory, and can write CSV or JSON.

Usage text is printed to stdout, and a symlink to a file is followed.
Both match the original script. The ``forensicslab`` command refuses
symlinks and writes its errors to stderr. Those differences are deliberate.
"""

import sys
from pathlib import Path

from forensicslab.hashing import sha256_file


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if len(args) < 1:
        print("Usage: python triage.py <file>")
        return 1
    # Extra arguments are ignored, as they were in the original script.
    target = Path(args[0])
    if not target.exists():
        print(f"No such file exists: {target}")
        return 1
    if not target.is_file():
        print(f"Not a file: {target}")
        return 1
    print(sha256_file(target))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
