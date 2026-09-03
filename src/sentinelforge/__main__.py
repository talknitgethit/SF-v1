"""Entry point for ``python -m sentinelforge``.

Keeping this file to a single delegation means the CLI can be imported and
tested as a plain function (``sentinelforge.cli.main``) without spawning a
subprocess.
"""

from sentinelforge.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
