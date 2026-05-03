# AEGIS Certify

## Deterministic AI Compliance Assurance Infrastructure

**The difference between observing compliance and enforcing it.**

---

## Executive Summary

AEGIS Certify is a mathematically-grounded AI governance infrastructure that transforms compliance from advisory dashboards into executable enforcement. Unlike evaluation frameworks that produce scores for human review, AEGIS operates in the execution path of AI systems with hard veto power—blocking non-compliant operations before they can cause harm.

**Key differentiator:** When a compliance check fails in AEGIS, the AI system stops. No averaging. No compensation. No override.

---

## The Problem: Evaluation Without Enforcement

Today's AI compliance landscape is dominated by **evaluation frameworks** that produce:
- Scores (0.73, 4.2/5, 87%)
- Dashboards
- Reports for human review
- Alerts that may or may not be acted upon

This creates a fundamental gap: **observation is not governance**.

When your toxicity evaluator returns 0.12, what happens? A human looks at a dashboard. Maybe they take action. Maybe they don't. The AI system continues operating regardless.

When your groundedness score drops to 0.65, what enforcement occurs? None. The score is logged. The system runs. The risk accumulates.

**Regulators don't ask "What's your average compliance score?" They ask "Are you compliant?" The answer is binary.**

---

## The AEGIS Solution: Executable Governance

AEGIS Certify fundamentally redefines AI compliance from measurement to enforcement.

### From Scores to Enforcement Actions

| Traditional Evaluators | AEGIS Certify |
|----------------------|---------------|
| Score: 0.73 | Gate G2: **HALT** |
| Dashboard alert | Gate G7: **HITL** (Human-in-the-Loop) |
| Risk probability: 12% | Gate G13: **DOWNGRADE** autonomy |
| Report for review | Gate G17: **INADMISSIBLE** |

When AEGIS returns HALT, execution stops. When it returns DOWNGRADE, the AI system's capabilities are automatically reduced. When it returns INADMISSIBLE, the system cannot operate.

**This is the difference between a smoke detector (alert) and a sprinkler system (enforcement).**

---

## Mathematical Foundation

AEGIS Certify isn't built on heuristics—it's built on formal mathematical structures that guarantee correctness.

### 1. FAIL-Dominant Lattice Semantics

```
if any PCU == FAIL → Gate = FAIL
```

No averaging. No compensation. No weighted scores. If one compliance check fails, the entire gate fails. This reflects the reality of regulatory compliance: you can't offset a GDPR violation with good performance elsewhere.

**Theorem (FAIL-Dominance):** For any set of PCU results R, if ∃r ∈ R where r.decision = FAIL, then lattice_meet(R) = FAIL, regardless of all other results.

### 2. Matroid Theory for Autonomy Control

AEGIS uses matroid structures to compute **AssuranceRank**—the mathematical basis for determining what autonomy level an AI system may operate at.

```
AssuranceRank = cardinality of maximal independent set in assurance matroid
```

This ensures autonomy levels are computed from first principles, not arbitrary thresholds.

### 3. Context Graph Theory (12th AEGIS Formalism)

The newest addition to AEGIS: formal graph-theoretic reasoning about domain admissibility.

```
CG = (V, E, λ)
where:
  V = context nodes (domain, task, role, trust tier)
  E = directed edges (transitions, dependencies, capabilities)
  λ: V → {CERTIFIED, PROVISIONAL, FORBIDDEN}
```

**Why this matters:** An AI agent can satisfy every local compliance check at every moment and still drift—through individually acceptable transitions—into a context that was never certified. Context Graph Theory detects this drift.

---

## The 17-Gate Control Plane

AEGIS enforces compliance through an ordered sequence of 17 gates, each governing a specific domain of AI risk.

| Gate | Domain | On FAIL |
|------|--------|---------|
| **G1** | Legal Admissibility | HALT |
| **G2** | Safety | HALT |
| **G3** | Data Governance | HALT |
| **G4** | Risk Management | THROTTLE |
| **G5** | Fairness | HALT |
| **G6** | Audit Evidence | HALT |
| **G7** | Human Oversight | HITL |
| **G8** | Continuous Monitoring | THROTTLE |
| **G9** | Capability Boundary | HALT |
| **G10** | Objective Integrity | HALT |
| **G11** | Assurance Integrity | FAIL |
| **G12** | Composition Safety | HALT |
| **G13** | Autonomy Escalation | DOWNGRADE |
| **G14** | Tool Boundary | VETO |
| **G15** | Reversibility | BLOCK |
| **G16** | Context Shift | ADVISORY → HALT |
| **G17** | Termination | INADMISSIBLE |

### Gate Evaluation Rule

```python
for gate in GATES_ORDERED:
    result = gate.evaluate(assurance_state, context)
    if result == FAIL:
        return HALT_EXECUTION
    if result == WARN:
        autonomy = downgrade(autonomy)
return autonomy
```

**Nothing bypasses the Control Plane.** Not UI overrides. Not admin flags. Not ML outputs. The gates are authoritative.

---

## Regulatory Framework Coverage

AEGIS provides direct predicate mappings to regulatory requirements—not generic metrics, but specific compliance statements.

### Supported Frameworks

| Framework | Coverage | PCU Count |
|-----------|----------|-----------|
| **EU AI Act** | High-Risk AI Systems (Art. 6-51) | 45+ |
| **GDPR** | Data Processing & Rights | 30+ |
| **NIST AI RMF** | MAP, MEASURE, MANAGE, GOVERN | 40+ |
| **SOC 2** | Trust Service Criteria | 25+ |
| **HIPAA** | PHI Handling & Security | 20+ |
| **PCI DSS** | Payment Data Security | 15+ |
| **ISO 42001** | AI Management Systems | 35+ |
| **FDA AI/ML** | SaMD Guidance | 20+ |
| **OMB M-24-35** | Federal AI Governance | 15+ |

### Predicate-to-Regulation Traceability

```
EU AI Act Art. 9(2)(a) → PRED-EUAI-RISK-MGMT-001
                              │
                              ▼
                        PCU-EUAI-RISK-001
                              │
                              ▼
                           Gate G4
                              │
                              ▼
                       PASS / WARN / FAIL
```

When an auditor asks "Are you compliant with EU AI Act Article 9(2)(a)?", AEGIS provides **cryptographic evidence** of the evaluation, not a score interpretation.

---

## Agentic AI Governance

AEGIS includes specialized PCUs for the unique risks of agentic AI systems:

### Agentic Risk PCUs (R1-R7)

| Risk | PCU Coverage | Gate |
|------|-------------|------|
| **R1** | Uncontrolled Autonomy Escalation | G13 |
| **R2** | Tool Boundary Violations | G14 |
| **R3** | Objective Drift | G10 |
| **R4** | Composition Hazards | G12 |
| **R5** | Irreversible Actions | G15 |
| **R6** | Context Domain Shift | G16 |
| **R7** | Termination Failure | G17 |

### Monotone Autonomy Invariant

```
A(t+1) ≤ A(t) unless explicitly re-certified
```

AI systems cannot grant themselves more autonomy. Period. If G13 detects an autonomy escalation attempt, the system is automatically downgraded.

### Composition Safety (G12)

When multiple AI agents or tools are composed:

```
Agent A (Level 3) ──┬──► Combined System
                    │
Agent B (Level 4) ──┼──► Autonomy = MIN(3, 4, 2) = 2
                    │
Tool C (Level 2) ───┘
```

The weakest component determines system-wide autonomy. AEGIS enforces this automatically.

### Termination Guarantee (G17)

Every AI system certified by AEGIS must prove it can be stopped:

- Kill switch exists
- Kill switch has been tested
- Kill switch latency < 1000ms

If termination cannot be guaranteed, the system is **INADMISSIBLE**.

---

## Architecture

```
┌─────────────────────────────────────────────────┐
│            External Integrations                 │
│   (OPA, Kubernetes, CI/CD, Policy Engines)       │
└──────────────────────┬──────────────────────────┘
                       │
┌──────────────────────▼──────────────────────────┐
│            AEGIS Public Interfaces               │
│    REST API │ gRPC │ Python SDK │ CLI            │
└──────────────────────┬──────────────────────────┘
                       │
┌──────────────────────▼──────────────────────────┐
│            AEGIS Control Plane                   │
│         Gates G1–G17 (authoritative)             │
└──────────────────────┬──────────────────────────┘
                       │
┌──────────────────────▼──────────────────────────┐
│          AEGIS Assurance Kernel                  │
│   Predicates │ PCUs │ Lattice │ Matroid │ CG     │
└──────────────────────┬──────────────────────────┘
                       │
┌──────────────────────▼──────────────────────────┐
│           Evidence & Registry Layer              │
│   PCU Registry │ Evidence Store │ Trace Log      │
└─────────────────────────────────────────────────┘
```

### Key Components

| Component | Purpose |
|-----------|---------|
| **Assurance Kernel** | Deterministic computation core |
| **Control Plane** | Ordered gate enforcement |
| **PCU Registry** | Compliance evaluators with full traceability |
| **Evidence Store** | Cryptographic audit trail |
| **Context Graph** | Runtime domain boundary enforcement |

---

## Integration Patterns

### Python SDK

```python
from aegis_certify import AegisClient

client = AegisClient()

result = client.certify(
    artifact_id="agent-001",
    artifact_type="conversational_agent",
    jurisdiction="EU",
    frameworks=["GDPR", "EU_AI_ACT"],
)

if result.decision == "CERTIFIED":
    print(f"Certified at autonomy level {result.autonomy_level}")
else:
    print(f"Blocked by gates: {result.blocking_gates}")
```

### REST API

```bash
POST /v1/artifacts/{id}/certify
GET  /v1/certifications/{id}
POST /v1/evidence
GET  /v1/gates/status
```

### gRPC (High-Performance)

```protobuf
service CertifyService {
  rpc Certify(CertifyRequest) returns (CertificationResult);
  rpc StreamGates(StreamGatesRequest) returns (stream GateResult);
}
```

Real-time gate streaming for runtime enforcement during agent execution.

### CLI

```bash
# Certify an artifact
aegis certify agent-001 --type agent --jurisdiction EU

# Check gate status
aegis gates status

# Export OPA policies
aegis opa export --output ./policies
```

### OPA Integration

AEGIS exports compliance predicates as Rego policies for Kubernetes admission control, API gateways, and policy engines.

```rego
package aegis.gates.g3.gdpr_erasure

default decision := "FAIL"

decision := "PASS" if {
    input.evidence.deletion_verified == true
    input.evidence.deletion_latency_days <= data.aegis.thresholds.gdpr_erasure_max_days
}
```

---

## LLM Evaluators: Evidence, Not Authority

AEGIS can consume outputs from LLM evaluation frameworks (TruLens, RAGAS, DeepEval) as **evidence**—but LLMs never make compliance decisions.

```
┌─────────────────────────────────────────────────┐
│  LLM Evaluators (TruLens, RAGAS)                │
│       │                                          │
│       ▼ Score: 0.73                              │
│  ┌─────────────────────┐                         │
│  │   Evidence Store    │                         │
│  └─────────┬───────────┘                         │
│            │                                     │
│            ▼                                     │
│  ┌─────────────────────┐                         │
│  │   AEGIS PCU         │                         │
│  │   if score < 0.8:   │                         │
│  │     return FAIL     │ ◄── Deterministic       │
│  └─────────────────────┘                         │
└─────────────────────────────────────────────────┘
```

**LLMs observe. PCUs decide. Gates enforce.**

---

## Audit & Traceability

Every AEGIS decision includes a complete evidence chain:

```python
class PCUResult(BaseModel):
    decision: Literal["PASS", "WARN", "FAIL"]
    pcu_id: str
    predicate_ids: list[str]
    measurements: dict[str, Any]
    evidence_refs: list[str]       # Cryptographic hashes
    threshold_used: dict[str, Any] # Exact parameters
    timestamp: datetime
    trace_id: str                  # Full proof chain
```

This enables:
- **Regulatory audits**: Prove compliance at any point in time
- **Legal defense**: Exact parameters used for every decision
- **Reproducibility**: Same inputs always produce same outputs

---

## Why AEGIS vs. Alternatives

| Dimension | LLM Evaluators | AEGIS Certify |
|-----------|----------------|---------------|
| **Output** | Scores | Enforcement Actions |
| **Authority** | Advisory | Authoritative |
| **Timing** | Post-hoc | Runtime |
| **Composition** | Single model | Multi-agent systems |
| **Compliance** | Generic metrics | Regulatory predicates |
| **Aggregation** | Averaging allowed | FAIL-dominant |
| **Autonomy** | Not tracked | Monotone controlled |
| **Termination** | Not checked | Guaranteed |
| **Audit** | Logs | Cryptographic evidence |
| **Action** | Human decides | System enforces |

---

## Deployment Options

### Library (pip install)

```bash
pip install aegis-certify
```

Embed AEGIS directly in your application with zero external dependencies.

### Service (Docker/Kubernetes)

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: aegis-certify
spec:
  replicas: 3
  template:
    spec:
      containers:
      - name: aegis-certify
        image: inferloop/aegis-certify:latest
        ports:
        - containerPort: 8000  # REST
        - containerPort: 50051 # gRPC
```

### Cloud (InferLoop Platform)

```python
client = AegisClient(
    api_key="ak_xxx",
    backend="https://api.inferloop.ai/aegis/v1"
)
```

Managed AEGIS with InferLoop platform integration.

---

## Summary

**AEGIS Certify** is not another evaluation framework. It is **governance infrastructure** for AI systems operating in regulated environments.

- **Mathematical foundation**: FAIL-dominant lattice, matroid theory, context graphs
- **17-gate Control Plane**: Ordered, non-bypassable enforcement
- **350+ PCUs**: Covering GDPR, EU AI Act, NIST, SOC 2, HIPAA, and more
- **Agentic AI ready**: Autonomy control, composition safety, termination guarantee
- **Full traceability**: Cryptographic evidence for every decision
- **Multiple interfaces**: SDK, REST, gRPC, CLI, OPA export

**Because evaluation without enforcement is just observation.**

---

## Get Started

```python
from aegis_certify import AegisClient

client = AegisClient()
result = client.certify(
    artifact_id="my-agent",
    artifact_type="agent",
    frameworks=["EU_AI_ACT", "GDPR"]
)

# Your AI system is now governed.
```

---

*AEGIS Certify — Executable Governance for AI Systems*

**InferLoop Platform** | [inferloop.ai](https://inferloop.ai)
