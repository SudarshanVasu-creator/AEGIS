# AEGIS — Application Security & Inspection System

A privacy-first, local source-code security scanner.
AEGIS examines a user-selected project directory, identifies common security issues,
redacts sensitive evidence, and produces a structured JSON report with remediation guidance.

**All scanning runs locally. No source code, secrets, or reports are sent anywhere.**

---

## Features (MVP)

- Python AST-based security analysis via [Bandit](https://bandit.readthedocs.io/)
- Regex-based secret detection (AWS keys, GitHub tokens, API keys, hardcoded passwords)
- Automatic redaction of detected secret values before report output
- Structured JSON report with severity, file, line number, and remediation guidance
- Safe path handling — never modifies scanned files

---

## Requirements

- Python 3.13 or later
- Git (for version control)

---

## Setup

```bash
# 1. Clone the repository
git clone https://github.com/your-org/aegis.git
cd aegis

# 2. Create and activate a dedicated virtual environment
python -m venv .venv
# Windows
.venv\Scripts\activate
# macOS / Linux
source .venv/bin/activate

# 3. Install the package in editable mode (includes runtime dependencies)
pip install -e .

# 4. Install development/test dependencies
pip install -r requirements-dev.txt
```

---

## Usage

```bash
aegis scan --project /path/to/your/project --output report.json
```

Or via the module entry point:

```bash
python -m aegis scan --project /path/to/your/project --output report.json
```

---

## Running Tests

```bash
pytest tests/
```

With coverage:

```bash
pytest --cov=aegis --cov-report=term-missing tests/
```

---

## Privacy

- Runs entirely offline. No external API calls are made.
- Detected secret values are redacted before appearing in any output.
- Scanned project files are never modified.
- Reports are written only to the path you specify.

See [docs/architecture.md](docs/architecture.md) for a full description of the design.

---

## License

License not yet selected. See project discussions.

---

## Status

Early development — MVP in progress.
