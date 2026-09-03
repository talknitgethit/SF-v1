# SentinelForge

A security investigation and digital forensics platform written in Python.

SentinelForge takes untrusted evidence, analyses it without ever running it, and
produces a structured investigation result: identifying hashes, filesystem
metadata, and rule-based findings with an explained severity.

> **Status: pre-v0.1 — project foundation.**
> The packaging, CLI skeleton, logging, and test harness are in place. The
> analysis engine is being built feature by feature; `analyze` is registered but
> not yet implemented. The roadmap below states plainly what exists and what
> does not.

---

## Why this project exists

Most "malware scanner" side projects do one of two things: they wrap someone
else's API and call it detection, or they hard-code a list of bad hashes and
call it intelligence. Neither teaches you much, and neither survives a question
from an experienced reviewer.

SentinelForge is an attempt at the opposite. It is built around ideas that
actually matter in digital forensics and incident response:

- **Evidence is hostile.** It gets read as bytes and nothing else. No execution,
  no import, no shell, no "just open it and see".
- **A tool should not guess.** Findings are produced by named rules that state
  why they triggered. The output is a severity band and an explanation, not a
  malware verdict.
- **Results must be reproducible.** The engine is deterministic, and the JSON
  report is complete enough for another program, or another analyst, to check
  the work.

It is also a deliberate exercise in software engineering: typed, tested,
documented, and built in small reviewable increments rather than generated in
one shot.

## What it is not

Being precise about this is part of the point:

- It is **not** an antivirus product and does not detect malware.
- It **cannot** tell you a file is safe. Heuristics raise questions; they do not
  answer them.
- It performs **no** dynamic analysis, sandboxing, or emulation.
- It sends nothing to any third party. Evidence stays on your machine.

## Architecture

```
src/sentinelforge/
├── cli.py               argument parsing and dispatch only
├── exceptions.py        errors SentinelForge raises on purpose
├── core/                what an investigation is
│   ├── evidence.py      validated, untrusted-input intake        (planned)
│   ├── models.py        Finding, Severity, InvestigationResult    (planned)
│   └── investigator.py  orchestration                             (planned)
├── analyzers/           components that examine evidence
│   ├── hashing.py       chunked MD5 / SHA-1 / SHA-256             (planned)
│   ├── metadata.py      size, extension, timestamps               (planned)
│   └── heuristics.py    rule-based suspicion analysis             (planned)
├── reporting/           rendering results
│   ├── console.py       human-readable output                     (planned)
│   └── json_report.py   machine-readable output                   (planned)
└── utils/
    └── logging_config.py
```

Three boundaries hold the design together:

**Validation happens once, at the edge.** A user-supplied path is resolved and
checked in `core/evidence.py` and nowhere else. Analysers receive an `Evidence`
object that is already known-good, so no analyser ever has to re-derive whether
its input is trustworthy.

**Analysis never renders, rendering never analyses.** The investigation result
is a plain structured Python object. Reporters read it. That means adding an
output format cannot change a finding, and the engine can be driven from a
future web dashboard without dragging terminal formatting along with it.

**stdout is for results, stderr is for logs.** So `--json` output stays
pipeable no matter what verbosity is set.

## Requirements

- Python 3.11 or newer
- No runtime third-party dependencies

That second line is intentional. A forensics tool that handles hostile input
should have a supply chain you can audit in one glance, so the engine is built
on the standard library. `pytest` and `ruff` are development-only.

## Installation

```bash
git clone https://github.com/<your-username>/sentinelforge.git
cd sentinelforge

python -m venv .venv
source .venv/bin/activate      # Windows: .\.venv\Scripts\Activate.ps1

pip install -e ".[dev]"
```

## Usage

```bash
sentinelforge --help
sentinelforge --version

# equivalent, and works without the console script on PATH:
python -m sentinelforge --help
```

Once the engine lands:

```bash
sentinelforge analyze suspicious_file.exe
sentinelforge -v analyze suspicious_file.exe
```

Global options:

| Option | Effect |
| --- | --- |
| `-v`, `--verbose` | `-v` for investigation progress, `-vv` for debug detail |
| `-q`, `--quiet` | errors only |
| `--version` | print the version and exit |

Exit codes: `0` success, `1` an expected failure such as unreadable evidence,
`2` a usage error.

## Development

```bash
pytest                 # run the test suite
ruff check .           # lint, including flake8-bandit security rules
ruff format .          # format
```

The lint configuration enables ruff's `S` (bandit) ruleset, which flags
`shell=True`, `eval`, and weak hash usage. When MD5 and SHA-1 land they will
carry a narrow, commented suppression rather than a project-wide exemption:
they are computed because threat intelligence sources still index by them, not
because they are cryptographically sound, and that reasoning belongs next to
the code.

CI runs the test suite on Linux, Windows, and macOS. That is not box-ticking —
file creation timestamps genuinely differ between them, and this project reads
filesystem timestamps.

## Security considerations

Design constraints, not aspirations:

- Analysed files are never executed, imported, or evaluated as code.
- No file is ever opened with the operating system's default handler.
- No subprocess is spawned with `shell=True`.
- Paths are resolved and validated before use.
- Evidence is never uploaded anywhere.
- No administrator or root privileges are required.
- Log output records facts *about* evidence (paths, sizes, digests) and never
  its contents, which may hold credentials, personal data, or terminal escape
  sequences.
- Generated reports and evidence samples are git-ignored. Reports embed
  absolute paths and case data; sample files should never be distributed in a
  repository.

Later versions will parse file contents. Parsing is still reading: content will
be treated as untrusted data throughout.

## Roadmap

| Version | Scope | Status |
| --- | --- | --- |
| Foundation | Packaging, CLI skeleton, logging, tests, CI | Done |
| v0.1 | File validation, hashing, metadata, heuristics, JSON report | In progress |
| v0.2 | Magic bytes, MIME, entropy, strings, PE parsing, YARA | Planned |
| v0.3 | Threat intelligence enrichment (VirusTotal, MalwareBazaar) | Planned |
| v0.4 | Log investigation (auth logs, SSH, Windows events, web logs) | Planned |
| v0.5 | Network forensics from PCAP | Planned |
| v0.6 | Filesystem forensics and disk image artefacts | Planned |
| v0.7 | Web dashboard over the same engine | Planned |
| v0.8 | Local LLM assistant that explains findings, never produces them | Planned |

The v0.8 boundary is deliberate. The language model will receive structured
findings and help explain, summarise, and suggest next steps. It will not decide
whether anything is malicious. The deterministic engine stays the source of
evidence.

## License

MIT. See [LICENSE](LICENSE).
