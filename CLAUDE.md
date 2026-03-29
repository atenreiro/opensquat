# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

openSquat Core is an OSINT cybersecurity tool that detects domain squatting threats (phishing, typosquatting, IDN homograph attacks, doppelganger domains) by scanning newly registered domain (NRD) feeds against user-provided keywords using Levenshtein distance similarity.

## Commands

```bash
# Install dependencies
pip install -r requirements.txt          # runtime only
pip install -r requirements-dev.txt      # runtime + dev/test tools

# Run the tool
python opensquat.py -k keywords.txt                    # basic scan
python opensquat.py -k keywords.txt -o results.json -t json  # JSON output

# Run tests
pytest tests/ -v

# Run a single test
pytest tests/test_validations.py -v
pytest tests/test_ct.py::TestCRTSH::test_network_error_returns_true -v

# Lint
flake8 opensquat/ --max-line-length=127 --max-complexity=25

# Build PyPI package
python -m build
```

## Architecture

### Entry Points
- `opensquat.py` — Thin wrapper for repo users (`python opensquat.py`), imports `opensquat.cli:main`
- `opensquat/cli.py` — Actual CLI logic and `main()` function. Also the pip entry point (`opensquat` command)
- Post-processing filters (VT, subdomains, portcheck) run sequentially in cli.py after the main scan

### Core Detection Pipeline
```
cli.py → app.Domain.main() → FeedManager.ensure_feeds() → read_files() → worker()
                                                                              ↓
                                                              ProcessPoolExecutor
                                                                              ↓
                                                         verify_keyword_task (static method)
                                                                              ↓
                                                         SquattingDetector.check(keyword, domains_list)
                                                                              ↓
                                                         _process_levenshtein() → validations.levenshtein()
```

### Key Modules
- **`app.py`** — Orchestrator. Wires FeedManager, SquattingDetector, DNSValidator. Runs keywords in parallel via `ProcessPoolExecutor`. Returns both a flat domain list (`list_domains`) and a keyword-grouped dict (`keyword_domains`).
- **`squatting_detector.py`** — Core detection logic. Must be pickle-friendly (used in child processes). Uses `@staticmethod verify_keyword_task` in app.py to avoid pickling `self`.
- **`validations.py`** — Native Levenshtein implementation with early-exit optimization (no external dependencies). The `threshold` parameter skips computation when length difference exceeds it (~5.6x faster).
- **`feed_manager.py`** — Downloads NRD feeds, MD5 checksum validation, path traversal protection via `_safe_filename()`.
- **`dns_validator.py`** — Quad9 DNS reputation checks.
- **`homograph.py`** — IDN homograph detection using `confusable_homoglyphs` and `homoglyphs` libraries. These must NOT be replaced with native code (requires curated Unicode databases).

### Output Handling
- **TXT/CSV**: Flat list of flagged domains
- **JSON**: Grouped by keyword `[{"keyword": "google", "domains": ["gogle.com"]}]`. The grouping is built in `app.py worker()` and filtered against post-processing results in `cli.py`.

## Important Conventions

- **Version** is maintained in THREE places — keep them in sync: `opensquat/__init__.py`, `pyproject.toml`, and `CHANGELOG`
- **All `open()` calls** for text files must include `encoding='utf-8'` (Windows compatibility, issue #104)
- **Git config** for this repo uses `user.name "atenreiro"` and `user.email "andre@opensquat.com"`
- **Branches**: `master` is production, `dev` is development. Merge dev → master with `--no-ff`
- **PyPI publishing**: Automated via `.github/workflows/publish.yml` on push to master. Also available manually via `pyproject-build && twine upload dist/*`

## Known Issues

- `test_ct.py::test_certificates_not_found` fails in sandboxed/offline environments (network-dependent, pre-existing)
- `vt.py` has known bugs: `--subdomains` passes wrong parameter (#111), `domain_report()` can return None (#112)
- `.gitignore` blocks `*.txt` and `test*.py` at root — exceptions exist for `requirements*.txt` and `tests/test*.py`
