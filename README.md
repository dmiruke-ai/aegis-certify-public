# AEGIS Certify

**Deterministic AI Compliance Assurance Library**

AEGIS Certify is a mathematically-grounded AI governance system that evaluates AI artifacts against regulatory predicates using executable Primary Compute Units (PCUs), enforced through a FAIL-dominant lattice gate architecture.

---

## Live API

No installation required. The API is live and ready to use:

| Interface | URL |
|-----------|-----|
| Interactive API (Swagger UI) | http://37.27.97.75:18000/docs#/ |
| OpenAPI Specification | http://37.27.97.75:18000/openapi.json |
| Dashboard | http://37.27.97.75:3001/dashboard |
| Health Check | http://37.27.97.75:18000/health |

### Quick API Usage

```bash
# Health check
curl http://37.27.97.75:18000/health

# Create an experiment
curl -X POST http://37.27.97.75:18000/api/v1/experiments \
  -H "Content-Type: application/json" \
  -d '{"name": "jailbreak-eval", "description": "Jailbreak detection test"}'

# Run AEGIS certification
curl -X POST http://37.27.97.75:18000/api/v1/certify \
  -H "Content-Type: application/json" \
  -d '{"artifact_id": "test-agent-001", "context": {"domain": "general"}}'
```

Full interactive examples available at the Swagger UI above.

---

## Key Features

- **17-Gate Control Plane (G1-G17)**: Ordered, non-bypassable decision points
- **FAIL-Dominant Lattice**: If any PCU fails, the gate fails. No compensation, no averaging.
- **115+ Primary Compute Units (PCUs)**: Covering GDPR, EU AI Act, NIST AI RMF, SOC2, HIPAA, PCI DSS, and more
- **Unit Action Interception**: Runtime enforcement at the action level
- **Context Graph Support**: Constraint enforcement with context drift detection
- **Deterministic Evaluation**: Same inputs always produce the same outputs

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│               External Integrations                      │
│       (OPA, Kubernetes, CI/CD, Policy Engines)           │
└────────────────────────┬────────────────────────────────┘
                         │
┌────────────────────────▼────────────────────────────────┐
│              AEGIS Public Interfaces                     │
│       REST API │ gRPC │ Python SDK │ CLI                 │
└────────────────────────┬────────────────────────────────┘
                         │
┌────────────────────────▼────────────────────────────────┐
│               AEGIS Control Plane                        │
│            Gates G1–G17 (authoritative)                  │
└────────────────────────┬────────────────────────────────┘
                         │
┌────────────────────────▼────────────────────────────────┐
│             AEGIS Assurance Kernel                       │
│     Predicates │ PCUs │ Lattice │ Matroid Logic          │
└────────────────────────┬────────────────────────────────┘
                         │
┌────────────────────────▼────────────────────────────────┐
│            Evidence & Registry Layer                     │
│    PCU Registry │ Evidence Store │ Trace Log             │
└─────────────────────────────────────────────────────────┘
```

## Quick Start

### Installation

```bash
# Clone the repository
git clone https://github.com/aegis-certify/aegis.git
cd aegis

# Create virtual environment
python -m venv .venv
source .venv/bin/activate

# Install in development mode
pip install -e ".[dev]"
```

### Basic Usage

```python
from aegis_certify import AegisClient

# Initialize client
client = AegisClient()

# Certify an AI artifact
result = client.certify(
    artifact_id="my-agent-001",
    artifact_type="agent",
    evidence={
        "gdpr_consent_collected": True,
        "data_retention_days": 30,
        "human_oversight_enabled": True
    }
)

print(f"CAI Score: {result.cai_score}")
print(f"Decision: {result.decision}")  # PERMIT, THROTTLE, or HALT
print(f"Gates Passed: {result.gates_passed}")
```

### CLI Usage

```bash
# Certify an artifact
aegis certify agent-001 --type agent --evidence evidence.json

# List all gates
aegis gates list

# Check gate status
aegis gates status G14

# Validate PCU registry completeness
aegis registry validate
```

### Docker Deployment

```bash
cd infra/docker

# Start all services
docker-compose -f docker-compose.dev.yml up -d

# Access:
# - UI Dashboard: http://localhost:10300
# - API: http://localhost:10800
# - API Docs: http://localhost:10800/docs
```

## Gate Architecture

| Gate | Domain | Enforcement |
|------|--------|-------------|
| G1 | Legal Admissibility | HALT |
| G2 | Safety | HALT / THROTTLE |
| G3 | Data Governance | HALT |
| G4 | Risk Management | THROTTLE |
| G5 | Fairness | HALT |
| G6 | Audit Evidence | HALT |
| G7 | Human Oversight | HITL |
| G8 | Continuous Monitoring | THROTTLE |
| G9 | Capability Boundary | HALT |
| G10 | Objective Integrity | HALT |
| G11 | Assurance Integrity | FAIL |
| G12 | Composition Safety | HALT |
| G13 | Autonomy Escalation | DOWNGRADE |
| G14 | Tool Boundary | VETO |
| G15 | Reversibility | BLOCK |
| G16 | Context Shift | ADVISORY |
| G17 | Termination | INADMISSIBLE |

## Core Invariants

1. **FAIL-dominant lattice**: `if any PCU == FAIL → Gate = FAIL`
2. **No LLM authority**: LLMs assist semantic analysis ONLY
3. **No aggregation**: Compliance is binary per-predicate, not scored
4. **Determinism**: Same (artifact, context, evidence) → same result
5. **Soundness**: PCU FAIL ⇒ predicate false. No false PASS allowed.

## Regulatory Frameworks Supported

- **GDPR** - EU Data Protection
- **EU AI Act** - EU AI Regulation
- **NIST AI RMF** - Risk Management Framework
- **SOC 2** - Trust Service Criteria
- **HIPAA** - Healthcare Privacy
- **PCI DSS** - Payment Card Industry
- **ISO 42001** - AI Management System
- **FDA AI/ML** - Medical Device AI
- **Agentic AI Risks (R1-R7)** - Agent-specific safety

## Project Structure

```
aegis/
├── src/aegis_certify/       # Core library
│   ├── core/                # Predicates, PCUs, Gates, Lattice, Matroid
│   ├── pcus/                # PCU implementations by framework
│   ├── api/                 # FastAPI REST endpoints
│   ├── grpc/                # gRPC service
│   ├── cli/                 # Typer CLI
│   └── sdk/                 # Python SDK clients
├── tests/                   # Unit, integration, e2e tests
├── proto/                   # gRPC protobuf definitions
├── infra/                   # Docker, Kubernetes configs
├── ui/                      # React dashboard
├── docs/                    # Documentation
└── aegis-experimental-platform/  # Evaluation scaffold
```

## Development

```bash
# Run tests
make test

# Run linting
make lint

# Format code
make format

# Generate gRPC stubs
make proto

# Validate PCU registry
make validate-registry
```

## Documentation

- [Standalone Deployment Guide](docs/STANDALONE_SANDBOX_DEPLOYMENT.md)
- [Architecture Overview](docs/STANDALONE_BLOCK_ARCHITECTURE.md)
- [Experimental Platform Plan](docs/AEGIS_EXPERIMENTAL_PLATFORM_PLAN.md)
- [CLI Architecture](docs/CLI_ARCHITECTURE_GUIDE.md)
- [Context Graph Integration](docs/CONTEXT_GRAPH_INTEGRATION_PLAN.md)

## License

Business Source License 1.1

## Version

1.0.0 (Standalone Distribution)
