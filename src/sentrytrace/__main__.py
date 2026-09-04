"""Entry point for ``python -m sentrytrace``.

Keeping this file to a single delegation means the CLI can be imported and
tested as a plain function (``sentrytrace.cli.main``) without spawning a
subprocess.
"""

from sentrytrace.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
