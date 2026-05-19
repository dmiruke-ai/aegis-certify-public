> **PATENT PENDING** — Technology and methodology patent pending. All rights reserved.

# CLI Architecture Guide — Where Does the CLI Go?

**Version:** 1.0
**Date:** 2026-04-21
**Question:** Where does the CLI go for AEGIS Certify and the Experimental Platform?

---

## Quick Answer

### **Two Separate CLIs:**

1. **AEGIS Certify CLI** (Existing)
   - Location: `src/aegis_certify/cli/`
   - Purpose: Core AEGIS operations (certify, evaluate, gates, registry)
   - Command: `aegis`
   - Status: ~60% complete

2. **Experimental Platform CLI** (New)
   - Location: `aegis-experimental-platform/backend/app/cli/`
   - Purpose: Run experiments, manage datasets, view results
   - Command: `aegis-exp` or `aexp`
   - Status: Not built yet (Sprint 1)

---

## 1. AEGIS Certify CLI (Existing)

### **Location:**
```
inferloop-aegis-certify/
└── src/
    └── aegis_certify/
        └── cli/                    ← CLI lives here
            ├── __init__.py
            ├── main.py             ← Main Typer app
            └── commands/           ← Command modules
                └── __init__.py
```

### **Current Structure:**
```python
src/aegis_certify/cli/
├── __init__.py                     # Empty (module marker)
├── main.py                         # Main CLI app (250 lines)
└── commands/                       # Command modules (mostly empty)
    ├── __init__.py
    ├── certify.py                  # TODO: Move certify command here
    ├── evaluate.py                 # TODO: Missing
    ├── gates.py                    # TODO: Move gates commands here
    ├── registry.py                 # TODO: Move registry commands here
    ├── evidence.py                 # TODO: Missing
    ├── report.py                   # TODO: Missing
    └── opa.py                      # TODO: Move OPA commands here
```

### **Recommended Structure (Clean Separation):**
```python
src/aegis_certify/cli/
├── __init__.py                     # Exports main app
├── main.py                         # Main Typer app (minimal, routes to commands)
├── commands/                       # All commands live here
│   ├── __init__.py                 # Exports all command apps
│   ├── certify.py                  # aegis certify
│   ├── evaluate.py                 # aegis evaluate <predicate>
│   ├── gates.py                    # aegis gates list|status
│   ├── registry.py                 # aegis registry list|validate
│   ├── evidence.py                 # aegis evidence submit|query
│   ├── report.py                   # aegis report generate
│   └── opa.py                      # aegis opa export|bundle|sync
└── utils/                          # Shared CLI utilities
    ├── __init__.py
    ├── formatters.py               # Output formatting (table, json, yaml)
    ├── validators.py               # Input validation
    └── progress.py                 # Progress bars, spinners
```

---

### **Installation:**
```bash
# AEGIS CLI is installed via pyproject.toml entry point

[project.scripts]
aegis = "aegis_certify.cli.main:app"

# After installation:
pip install -e .

# Now available globally:
aegis --help
aegis certify --artifact my-agent
aegis gates list
```

---

### **Current Commands (in main.py):**
```bash
# Implemented (✅)
aegis certify                       # Line 54-124
aegis gates list                    # Line 135-151
aegis registry validate             # Line 162-179
aegis registry list                 # Line 181-196
aegis opa export                    # Line 206-219
aegis opa bundle                    # Line 222-242

# Missing (❌)
aegis evaluate <predicate>          # Not implemented
aegis gates status                  # Not implemented
aegis evidence submit               # Not implemented
aegis evidence query                # Not implemented
aegis report generate               # Not implemented
```

---

## 2. Experimental Platform CLI (New)

### **Location:**
```
aegis-experimental-platform/        ← New project root
└── backend/
    └── app/
        └── cli/                    ← Experimental CLI lives here
            ├── __init__.py
            ├── main.py             ← Main Click/Typer app
            └── commands/           ← Command modules
                ├── __init__.py
                ├── experiments.py  # Experiment management
                ├── datasets.py     # Dataset operations
                ├── results.py      # View results
                ├── metrics.py      # Metrics & analysis
                └── export.py       # Export outputs
```

### **Recommended Structure:**
```python
aegis-experimental-platform/backend/app/cli/
├── __init__.py                     # Exports main app
├── main.py                         # Main CLI app
├── commands/
│   ├── __init__.py
│   ├── experiments.py              # aexp run, list, status, delete
│   ├── datasets.py                 # aexp dataset create, list, validate
│   ├── results.py                  # aexp results show, filter, export
│   ├── metrics.py                  # aexp metrics compute, compare
│   └── export.py                   # aexp export latex|json|pdf
└── utils/
    ├── __init__.py
    ├── formatters.py               # Rich tables, JSON output
    └── config.py                   # Config file management
```

---

### **Installation:**
```bash
# Experimental platform CLI via setup.py or pyproject.toml

# In aegis-experimental-platform/backend/pyproject.toml:
[project.scripts]
aegis-exp = "app.cli.main:app"
# Or shorter alias:
aexp = "app.cli.main:app"

# After installation:
cd aegis-experimental-platform/backend
pip install -e .

# Now available:
aegis-exp --help
aexp run --dataset prompt_injection --systems claude,gpt4
```

---

### **Planned Commands:**
```bash
# Experiments
aexp run <experiment_id>            # Run experiment
aexp list                           # List all experiments
aexp status <experiment_id>         # Show experiment status
aexp delete <experiment_id>         # Delete experiment

# Datasets
aexp dataset create <file>          # Create dataset from JSON
aexp dataset list                   # List datasets
aexp dataset validate <dataset_id>  # Validate dataset

# Results
aexp results show <experiment_id>   # Show results
aexp results filter --category=prompt_injection
aexp results export <experiment_id> --format=json

# Metrics
aexp metrics compute <experiment_id>    # Compute metrics
aexp metrics compare <exp1> <exp2>      # Compare experiments

# Export
aexp export latex <experiment_id>   # Export LaTeX tables
aexp export json <experiment_id>    # Export JSON
aexp export pdf <experiment_id>     # Generate PDF report
```

---

## 3. Complete Project Structure

### **Visual Layout:**

```
/home/damir/PROJECTS/agent-dev-products/
│
├── inferloop-aegis-certify/                    ← AEGIS Certify (existing)
│   └── src/
│       └── aegis_certify/
│           ├── cli/                            ← AEGIS CLI
│           │   ├── main.py                     ← Command: `aegis`
│           │   └── commands/
│           │       ├── certify.py
│           │       ├── gates.py
│           │       ├── registry.py
│           │       └── opa.py
│           ├── core/                           ← Core AEGIS logic
│           ├── pcus/                           ← PCU implementations
│           ├── sdk/                            ← Python SDK
│           └── api/                            ← REST API
│
└── aegis-experimental-platform/                ← Experimental Platform (new)
    └── backend/
        └── app/
            ├── cli/                            ← Experimental CLI
            │   ├── main.py                     ← Command: `aegis-exp`
            │   └── commands/
            │       ├── experiments.py
            │       ├── datasets.py
            │       ├── results.py
            │       └── export.py
            ├── core/                           ← Experiment runner
            ├── api/                            ← Experiment API
            └── models/                         ← Data models
```

---

## 4. CLI Separation Rationale

### **Why Two Separate CLIs?**

| CLI | Purpose | User | Use Case |
|-----|---------|------|----------|
| **`aegis`** | AEGIS operations | DevOps, Developers | Certify agents, check gates, export policies |
| **`aegis-exp`** | Experimentation | Researchers, Scientists | Run experiments, analyze results, generate papers |

### **Separation Benefits:**
1. ✅ **Clear scope:** AEGIS core vs research platform
2. ✅ **Independent versioning:** Can update experimental CLI without touching AEGIS
3. ✅ **Different users:** Production users vs researchers
4. ✅ **No confusion:** `aegis certify` vs `aexp run` are distinct

### **Potential Future: Unified CLI**
```bash
# Option: Combine under single CLI with subcommands
aegis core certify                  # Core AEGIS
aegis core gates list

aegis exp run                       # Experimental
aegis exp results show
```

**Decision:** Start with separate CLIs, unify later if needed.

---

## 5. Implementation Guide

### **Task 1: Complete AEGIS CLI (P1)**

#### **Step 1: Reorganize main.py**
**Current:** Everything in `main.py` (250 lines)
**Target:** Move commands to `commands/` modules

```bash
# Move commands from main.py to separate files
cd src/aegis_certify/cli/commands/

# Create command files
touch certify.py gates.py registry.py opa.py evidence.py evaluate.py report.py
```

#### **Step 2: Implement Missing Commands**
```python
# src/aegis_certify/cli/commands/evaluate.py

import typer
from rich.console import Console

app = typer.Typer()
console = Console()

@app.command()
def evaluate(
    predicate: str = typer.Argument(..., help="Predicate ID to evaluate"),
    artifact: str = typer.Option(..., "--artifact", "-a"),
    context: str = typer.Option("", "--context", "-c"),
    output: str = typer.Option("table", "--output", "-o"),
) -> None:
    """Evaluate a single predicate against an artifact."""
    from aegis_certify.sdk.client import AegisClient

    client = AegisClient()
    # Implementation...
    console.print(f"Evaluating predicate: {predicate}")
```

#### **Step 3: Update main.py to Import Commands**
```python
# src/aegis_certify/cli/main.py

from aegis_certify.cli.commands import (
    certify,
    evaluate,
    gates,
    registry,
    evidence,
    report,
    opa,
)

app = typer.Typer(name="aegis")

# Add command apps
app.add_typer(certify.app, name="certify")
app.add_typer(evaluate.app, name="evaluate")
app.add_typer(gates.app, name="gates")
app.add_typer(registry.app, name="registry")
app.add_typer(evidence.app, name="evidence")
app.add_typer(report.app, name="report")
app.add_typer(opa.app, name="opa")
```

---

### **Task 2: Build Experimental Platform CLI (Sprint 1)**

#### **Step 1: Create CLI Directory**
```bash
cd aegis-experimental-platform/backend
mkdir -p app/cli/commands app/cli/utils
touch app/cli/__init__.py
touch app/cli/main.py
touch app/cli/commands/__init__.py
```

#### **Step 2: Create Main App**
```python
# backend/app/cli/main.py

import typer
from rich.console import Console

from app.cli.commands import experiments, datasets, results, metrics, export_cmd

app = typer.Typer(
    name="aegis-exp",
    help="AEGIS Experimental Platform CLI"
)
console = Console()

# Add command groups
app.add_typer(experiments.app, name="run")       # aexp run
app.add_typer(datasets.app, name="dataset")      # aexp dataset
app.add_typer(results.app, name="results")       # aexp results
app.add_typer(metrics.app, name="metrics")       # aexp metrics
app.add_typer(export_cmd.app, name="export")     # aexp export

@app.command()
def version():
    """Show version."""
    console.print("AEGIS Experimental Platform v1.0.0")

if __name__ == "__main__":
    app()
```

#### **Step 3: Implement Experiment Commands**
```python
# backend/app/cli/commands/experiments.py

import typer
from rich.console import Console
from rich.table import Table

app = typer.Typer()
console = Console()

@app.command()
def run(
    experiment_id: str = typer.Argument(..., help="Experiment ID or template"),
    dry_run: bool = typer.Option(False, "--dry-run"),
) -> None:
    """Run an experiment."""
    from app.core.experiment_runner import ExperimentRunner

    console.print(f"[bold]Running experiment: {experiment_id}[/bold]")

    if dry_run:
        console.print("[yellow]Dry run mode - no actual execution[/yellow]")
        return

    runner = ExperimentRunner()
    # Implementation...

@app.command("list")
def list_experiments():
    """List all experiments."""
    from app.models.experiment import Experiment

    table = Table(title="Experiments")
    table.add_column("ID", style="cyan")
    table.add_column("Name")
    table.add_column("Status")
    table.add_column("Created")

    # Query experiments from DB
    # for exp in experiments:
    #     table.add_row(...)

    console.print(table)

@app.command()
def status(experiment_id: str):
    """Show experiment status."""
    console.print(f"Status of experiment: {experiment_id}")
    # Implementation...
```

---

## 6. Entry Points Configuration

### **AEGIS Certify (`pyproject.toml`):**
```toml
[project.scripts]
aegis = "aegis_certify.cli.main:app"
```

### **Experimental Platform (`pyproject.toml`):**
```toml
[project.scripts]
aegis-exp = "app.cli.main:app"
aexp = "app.cli.main:app"  # Short alias
```

### **Installation & Usage:**
```bash
# Install AEGIS CLI
cd inferloop-aegis-certify
pip install -e .
aegis --help

# Install Experimental CLI
cd aegis-experimental-platform/backend
pip install -e .
aegis-exp --help
aexp --help  # Same as above
```

---

## 7. CLI Design Principles (Both CLIs)

### **Unix Philosophy:**
1. ✅ Do one thing well
2. ✅ Composable (pipe-friendly)
3. ✅ Machine-readable output (`--output json`)
4. ✅ Exit codes (0=success, 1=fail, 2=warn)

### **User Experience:**
1. ✅ Progressive disclosure (simple by default, `--verbose` for detail)
2. ✅ Rich output (tables, colors, progress bars)
3. ✅ Helpful error messages
4. ✅ Auto-complete support

### **Output Formats:**
```bash
# Table (default, human-readable)
aegis certify --artifact my-agent

# JSON (machine-readable)
aegis certify --artifact my-agent --output json

# YAML
aegis certify --artifact my-agent --output yaml

# Quiet (only errors)
aegis certify --artifact my-agent --quiet
```

---

## 8. Quick Reference Commands

### **AEGIS CLI (Core Operations):**
```bash
# Certification
aegis certify --artifact my-agent --frameworks gdpr,eu_ai_act

# Gates
aegis gates list
aegis gates status

# Registry
aegis registry validate
aegis registry list --framework gdpr

# OPA Export
aegis opa export --output ./policies/
aegis opa bundle --output bundle.tar.gz

# Evidence
aegis evidence submit --file evidence.json
aegis evidence query --artifact my-agent

# Reports
aegis report generate --artifact my-agent --format pdf
```

---

### **Experimental Platform CLI:**
```bash
# Experiments
aexp run safety_vs_utility
aexp list
aexp status exp_001

# Datasets
aexp dataset create prompt_injection.json
aexp dataset list
aexp dataset validate dataset_001

# Results
aexp results show exp_001
aexp results filter --category=prompt_injection --system=agent_aegis

# Metrics
aexp metrics compute exp_001
aexp metrics compare exp_001 exp_002

# Export
aexp export latex exp_001
aexp export json exp_001 --output results.json
aexp export pdf exp_001 --output report.pdf
```

---

## 9. Summary

### **Two CLIs, Two Purposes:**

| CLI | Command | Location | Purpose | Status |
|-----|---------|----------|---------|--------|
| **AEGIS Certify** | `aegis` | `src/aegis_certify/cli/` | Core AEGIS operations | 60% complete |
| **Experimental** | `aegis-exp` / `aexp` | `backend/app/cli/` | Run experiments, research | Not built (Sprint 1) |

### **Next Steps:**

#### **Option 1: Complete AEGIS CLI First**
1. Reorganize `main.py` into `commands/` modules
2. Implement 5 missing commands (evaluate, gates status, evidence, report)
3. Estimated time: 2-3 hours

#### **Option 2: Build Experimental CLI (Sprint 1)**
1. Create CLI directory structure
2. Implement experiment commands
3. Add to Sprint 1 tasks

#### **Option 3: Do Both in Parallel**
1. Complete AEGIS CLI reorganization
2. Build experimental CLI basics
3. Test both independently

**Recommendation:** Complete AEGIS CLI first (it's 60% done), then build experimental CLI in Sprint 1.

---

**What would you like to do?**
1. Complete the AEGIS CLI now?
2. Start building the experimental CLI?
3. Review the current CLI implementation?

---

**END OF DOCUMENT**
