# Sample evidence

A scratch directory for files you analyse while developing. **Everything in here
except this README is git-ignored, on purpose.**

## Why nothing is committed

Shipping suspicious-looking files in a repository is a bad habit even when the
files are harmless:

- GitHub scans pushed content and can flag or block the repository.
- Local antivirus quarantines the file mid-clone, which looks like a broken
  checkout to anyone trying your project.
- A cloned repository should never hand the cloner something they then have to
  be careful with.

**Do not commit the EICAR test string here.** It is designed to trip antivirus
engines, and it will — on your machine and on everyone else's.

## Generating safe fixtures

Anything you need for manual testing can be created in a couple of lines. These
files are inert: the extensions are what make them interesting to SentryTrace,
and nothing here is ever executed.

```bash
# an ordinary text file
echo "hello" > sample_evidence/notes.txt

# an empty file: an edge case for hashing and for size heuristics
: > sample_evidence/empty.bin

# a misleading double extension, the classic phishing-attachment pattern
echo "not really a pdf" > sample_evidence/invoice.pdf.exe

# random bytes, useful later for entropy analysis
head -c 4096 /dev/urandom > sample_evidence/random.bin
```

PowerShell equivalents:

```powershell
"hello" | Set-Content sample_evidence\notes.txt
New-Item sample_evidence\empty.bin -ItemType File -Force
"not really a pdf" | Set-Content sample_evidence\invoice.pdf.exe
[byte[]]::new(4096) | ForEach-Object { Get-Random -Max 256 } |
    Set-Content sample_evidence\random.bin -AsByteStream
```

## A note on automated tests

The test suite does not read from this directory. Tests build their own fixtures
in pytest's `tmp_path`, so they stay hermetic, run in any checkout, and cannot
be broken by whatever you happen to have left lying around here.

Use this directory for exploring by hand. Use `tmp_path` for anything that has
to pass in CI.
