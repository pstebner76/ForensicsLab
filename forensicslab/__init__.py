"""Small read-only DFIR tools, written to be read as well as run.

Start at ``cli.py`` for the commands and ``evidence.py`` for the rules
about touching disk. ``hashing.py``, ``triage.py``, and ``entropy.py``
are the tools. ``output.py`` turns their rows into console text, CSV,
and JSON.

The ``triage.py`` script at the repository root is the original
single-file hasher. It still prints one SHA-256 digest, and it now
calls :func:`forensicslab.hashing.sha256_file` to do it.

Keep ``__version__`` in step with ``pyproject.toml``.
"""

__version__ = "0.1.0"
