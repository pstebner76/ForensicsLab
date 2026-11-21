# ForensicsLab

Small read-only command-line tools for DFIR practice, in the spirit of
Eric Zimmerman's single-purpose utilities. Each subcommand does one job,
the flags are the same on every subcommand, and CSV output keeps a fixed
column order so Timeline Explorer can open it.

The tools compute hashes, list file metadata, and measure Shannon entropy.
They are also meant to be read. The interesting forensic decisions are
called out in the module docstrings rather than hidden in helper code.

## Install

Python 3.10 or newer. The tools use only the standard library. pytest is
installed only if you want to run the tests.

```bash
python -m venv .venv
```

Windows:

```bat
.venv\Scripts\activate
python -m pip install -e ".[dev]"
```

Linux and macOS:

```bash
source .venv/bin/activate
python -m pip install -e ".[dev]"
```

That puts a `forensicslab` command on your PATH. `python -m forensicslab`
runs the same entry point without activating the environment, as long as
the package is installed or the repository root is on `PYTHONPATH`.

Check the install:

```bash
forensicslab --version
forensicslab --help
```

## Commands

Every subcommand accepts the same path and output flags.

| Flag | Meaning |
| --- | --- |
| `-f PATH` | Regular file. Repeat the flag to add another file. |
| `-d PATH` | Directory of regular files. Repeat the flag to add another directory. |
| `--recursive` / `--no-recursive` | Directories are walked recursively unless you pass `--no-recursive`. |
| `--csv DIR` | Write `<command>.csv` into this directory. |
| `--json DIR` | Write `<command>.json` into this directory. |

Records go to stdout. Skipped symlinks, read errors, and the `Wrote ...`
lines go to stderr, so you can redirect the records without losing the
diagnostics.

`FullPath`, `FileName`, and `Size` are the first three columns of every
tool. That is the join key if you load two CSVs into Timeline Explorer.

A trailing newline changes a hash. The samples below were made with
`printf '%s' abc`, which writes the three bytes `abc` and no newline.
`echo abc` writes a fourth byte and produces different digests.

### hash

MD5, SHA-1, and SHA-256, updated from one read of the file. MD5 and SHA-1
are there so the output lines up with hash sets and older case notes.
SHA-256 is the digest to trust for an integrity check.

```bash
forensicslab hash -f evidence/abc.txt
forensicslab hash -d evidence/ --csv out/ --json out/
```

```text
FullPath: /case/evidence/abc.txt
FileName: abc.txt
Size: 3
MD5: 900150983cd24fb0d6963f7d28e17f72
SHA1: a9993e364706816aba3e25717850c26c9cd0d89d
SHA256: ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
```

`out/hash.csv` (UTF-8 with a byte-order mark, so the header is the first
row you see in Excel or Timeline Explorer):

```text
FullPath,FileName,Size,MD5,SHA1,SHA256
/case/evidence/abc.txt,abc.txt,3,900150983cd24fb0d6963f7d28e17f72,a9993e364706816aba3e25717850c26c9cd0d89d,ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
```

`Size` on this tool is the number of bytes that were hashed.

### triage

Size and timestamps, from `lstat`. This command does not read file bytes.

```bash
forensicslab triage -d evidence/ --csv out/
```

```text
FullPath: /case/evidence/abc.txt
FileName: abc.txt
Size: 3
ModifiedTimeUtc: 2026-11-21T13:29:58.412772285Z
AccessTimeUtc: 2026-11-21T13:29:58.412772285Z
MetadataChangeTimeUtc: 2026-11-21T13:29:58.412772285Z
CreationTimeUtc:
```

The clocks are UTC, with 9 fractional digits (`st_mtime_ns` and the same
for the other fields). Your timestamps will differ; the column names will
not.

`st_ctime` is not one fact wearing two names:

- On Linux and macOS it is the metadata-change time (permissions, owner,
  rename), so it fills `MetadataChangeTimeUtc`.
- On Windows it is the creation time, so it fills `CreationTimeUtc`.
- A birth time (`st_birthtime` on macOS) fills `CreationTimeUtc` without
  changing the meaning of ctime.

The column this platform cannot fill is left blank. Blank means "`stat`
does not provide this", not "the file was never created". On Linux,
`CreationTimeUtc` is blank unless the interpreter exposes a birth time.

`Size` here is `st_size`. For a regular file that is not changing, it
matches the hash tool's byte count.

### entropy

Shannon entropy in bits per byte, using `collections.Counter`. The value
runs from 0 (empty, or one repeated byte) to 8 (every byte value equally
common). The band is a hint for where to look, not a detector. Compressed,
packed, and encrypted files can all land in `very-high`.

```bash
forensicslab entropy -f evidence/abc.txt
forensicslab entropy -d evidence/ --csv out/
```

```text
FullPath: /case/evidence/abc.txt
FileName: abc.txt
Size: 3
Entropy: 1.584963
Band: low
```

`abc` is three different bytes, so the entropy is `log2(3)` rounded to 6
places. Bands: below 1 very-low, below 4 low, below 6.5 moderate, below
7.5 high, otherwise very-high.

### The original script

`python triage.py <file>` still prints only a SHA-256 digest. That was the
whole program before this package. It follows symlinks, because the
original `open()` did. The `forensicslab` command refuses symlinks.

```bash
python triage.py evidence/abc.txt
```

```text
ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
```

## Forensic soundness

These tools are for learning and for triage of a copy. They are not a
write blocker, and they are not a substitute for hashing a forensic image
before you look inside it.

- Evidence files are opened with `os.O_RDONLY` only. No write flag is set.
  Hashes and entropy are computed from that read. Triage does not open the
  file at all; it uses `lstat`.
- On Linux the open also tries `O_NOATIME`, so reading bytes does not
  refresh the file's access time. The kernel allows that flag for the file
  owner (or a process with `CAP_FOWNER`). If it is refused, the tool still
  reads the file and prints one warning on stderr: the access time may
  have moved. Windows does not expose `O_NOATIME` to Python.
- Symlinks are not followed. `O_NOFOLLOW`, where the OS has it, covers the
  gap between the `lstat` check and the `open`, so a path that is swapped
  for a symlink in that gap is not hashed. Directory walks do not enter
  symlink directories. Named pipes are skipped rather than opened, because
  opening one would wait forever for a writer.
- `--csv` and `--json` refuse to create their output directory inside any
  directory you passed with `-d`, including through a path that contains
  `..` or a symlink that resolves inside that tree. A CSV written into the
  evidence tree would show up the next time you listed it. Writing next to
  a single `-f` file is allowed; prefer a separate `out/` directory anyway.
  The report file itself is also refused when it is a symlink or the same
  inode as a file being read, so `hash.csv` cannot be a link onto evidence
  and cannot be the evidence file. The bytes are written to a new temp
  file in the output directory and renamed into place.
- A symlink in the last component of `-f` or `-d` is refused. A symlink in
  an ancestor, such as macOS `/tmp`, is followed. That is ordinary path
  lookup, and refusing it would reject normal paths.
- The file list is kept in memory so the CSV can be sorted. That is the
  right shape for a case folder, not for tens of millions of paths.
- A filename that is not valid UTF-8 is written with backslash escapes
  such as `\xff`, so the CSV stays valid UTF-8. A filename that starts
  with `=` can be a formula if Excel opens the CSV. The tools do not
  rewrite evidence names. Timeline Explorer does not evaluate formulas.
- Listing a directory can still update that directory's own access time.
  There is no portable flag that prevents it.
- MD5 and SHA-1 are identifiers for existing hash sets. They are not
  integrity checks. Use SHA-256 for that. A matching hash means the bytes
  match. It does not say who wrote the file or whether the copy is the
  original evidence.
- Timestamps describe the file you stat. Copying, extracting, or
  downloading a file replaces them. Access time is often disabled
  (`noatime`, `relatime`) or updated by ordinary reads, so a quiet atime
  does not mean the file was never opened. ctime on Linux and macOS is not
  a birth time.

## Layout

```text
forensicslab/
  cli.py        subcommands, shared flags, exit codes
  evidence.py   read-only opens, directory walks, output-path rule
  hashing.py    MD5, SHA-1, and SHA-256 in one pass
  triage.py     size and timestamps, with ctime labeled per platform
  entropy.py    Shannon entropy via collections.Counter
  output.py     console text, CSV, and JSON in one column order
triage.py       legacy SHA-256 wrapper
tests/          one module per tool, plus walk and CLI tests
```

Exit codes: `0` finished (an empty directory and a skipped symlink are
still success), `1` at least one file or directory could not be read
(rows for the rest are still written), `2` the arguments are wrong.
Library functions return data or raise. They do not call `sys.exit`.

## Tests

```bash
pytest
```

GitHub Actions runs the same suite on push and pull request, on Python
3.12 and 3.13, then runs all three subcommands plus `triage.py`. The known
digests live in `tests/vectors.py`. Those constants are published test
vectors (and one frozen long-buffer digest). If a hash test fails, fix the
hasher. Do not paste the program's new output over the vector.

## License

MIT. See [LICENSE](LICENSE).
