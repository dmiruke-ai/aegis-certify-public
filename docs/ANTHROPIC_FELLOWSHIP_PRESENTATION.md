> **PATENT PENDING** — Technology and methodology patent pending. All rights reserved.

# AEGIS Certify — Anthropic Fellowship Presentation

**Project:** AEGIS Certify — Deterministic AI Compliance Assurance Library
**Presenter:** InferLoop Team
**Date:** April 2026
**Version:** 1.0

---

## Executive Summary

**AEGIS Certify** is a mathematically-grounded, deterministic AI compliance assurance library that provides executable governance with hard veto power. It evaluates AI systems against regulatory predicates using Primary Compute Units (PCUs), enforced through a FAIL-dominant lattice gate architecture.

### Key Innovation: Multi-LLM Control Plane Integration

AEGIS acts as an **inline safety interceptor** in multi-LLM control planes, providing real-time action-level enforcement across Claude, GPT, Gemini, and open-source models.

---

## Problem Statement

### The Challenge

Current AI compliance approaches suffer from:

1. **Post-hoc auditing** — violations discovered after deployment
2. **Soft guardrails** — recommendations without enforcement
3. **Score-based systems** — averaging masks critical failures
4. **Single-model focus** — doesn't handle multi-LLM orchestration
5. **Action blindness** — can't intercept dangerous operations in real-time

### The Stakes

- **Legal liability:** GDPR fines up to €20M or 4% global revenue
- **Safety incidents:** Autonomous agents with unbounded tool access
- **Regulatory pressure:** EU AI Act, OMB M-24-35, state-level mandates
- **Deployment blocks:** Enterprises can't certify agents for production

---

## AEGIS Solution Architecture

### Core Principles

1. **Determinism:** Same input → same result. Always.
2. **FAIL-dominant:** Any critical failure halts execution. No averaging.
3. **Mathematical rigor:** Lattice theory, matroid structures, Hodge decomposition
4. **No LLM authority:** LLMs assist; PCUs decide
5. **Runtime enforcement:** Not just certification—active interception

### Three-Layer Architecture

```
┌────────────────────────────────────────────────────────────┐
│  Layer 1: ARTIFACT CERTIFICATION (Pre-deployment)          │
│  - Full system evaluation against 12 frameworks            │
│  - 115+ PCUs across GDPR, EU AI Act, NIST, FedRAMP, etc.  │
│  - Composite Assurance Index (CAI) computation             │
│  - Gate-by-gate PASS/WARN/FAIL decisions                  │
└────────────────────────────────────────────────────────────┘
                         │
                         ▼
┌────────────────────────────────────────────────────────────┐
│  Layer 2: UNIT ACTION INTERCEPTION (Runtime)               │
│  ◄────── FELLOWSHIP FOCUS: Multi-LLM Control Plane         │
│  - Real-time action evaluation before execution            │
│  - Gate subset: G9, G10, G12, G14, G15, G17               │
│  - ALLOW / DENY / MODIFY decisions with reason codes      │
│  - Model-agnostic: Claude, GPT, Gemini, open models       │
└────────────────────────────────────────────────────────────┘
                         │
                         ▼
┌────────────────────────────────────────────────────────────┐
│  Layer 3: OBSERVABILITY & RESEARCH (Continuous)            │
│  - Tamper-evident audit logs with trace IDs                │
│  - Escape rate, false block metrics                        │
│  - Research telemetry for safety evaluation                │
│  - Certificate generation and badge rendering              │
└────────────────────────────────────────────────────────────┘
```

---

## Layer 2: Unit Action Interception (Fellowship Focus)

### Architecture: Multi-LLM Control Plane

```
┌─────────────────────────────────────────────────────────────┐
│                   MULTI-LLM CONTROL PLANE                    │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  User Request                                                │
│       │                                                      │
│       ▼                                                      │
│  ┌─────────────────┐       ┌──────────────┐                 │
│  │ Policy Router   │──────▶│Model Selector│                 │
│  │ (tenant/risk)   │       │Claude|GPT|...│                 │
│  └─────────────────┘       └──────┬───────┘                 │
│                                   │                         │
│                                   ▼                         │
│                           ┌────────────────┐                │
│                           │  LLM Engine    │                │
│                           │  (proposes     │                │
│                           │   tool calls)  │                │
│                           └────────┬───────┘                │
│                                   │                         │
│                        proposed action                      │
│                                   │                         │
│                                   ▼                         │
│  ┌────────────────────────────────────────────────────────┐ │
│  │      UA NORMALIZER (Canonical UnitAction Schema)       │ │
│  │  { actor, tool, params, capability, reversibility }    │ │
│  └────────────────────────┬───────────────────────────────┘ │
│                           │                                 │
│                           ▼                                 │
│  ┌────────────────────────────────────────────────────────┐ │
│  │         AEGIS INLINE INTERCEPTOR  C(UA)                │ │
│  │  Gates: G9, G10, G12, G14, G15, G17                    │ │
│  │  Output: ALLOW | DENY | MODIFY + reason_codes          │ │
│  └──────┬─────────────────────┬──────────────────┬────────┘ │
│         │                     │                  │          │
│     ALLOW                  MODIFY              DENY         │
│         │                     │                  │          │
│         ▼                     ▼                  ▼          │
│  ┌────────────┐       ┌────────────┐    ┌────────────┐     │
│  │ Tool Exec  │       │Safe Rewrite│    │Block+Alert │     │
│  │(sandboxed) │       │   / HITL   │    │+Fallback   │     │
│  └────────────┘       └────────────┘    └────────────┘     │
│                                                              │
│  All decisions logged to tamper-evident audit trail         │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

### UnitAction Schema

```python
class UnitAction(BaseModel):
    """Canonical action representation across all LLM providers"""
    action_id: str                    # Unique action identifier
    actor: str                        # Agent/component proposing action
    model_id: Optional[str]           # e.g., "claude-sonnet-4.5", "gpt-4"
    tool: str                         # Tool name (file_write, http_request, etc.)
    params: dict[str, Any]            # Tool parameters
    capability: str                   # Capability domain (filesystem, network, etc.)
    reversibility_score: float        # 0.0 (irreversible) to 1.0 (fully reversible)
    trace_id: Optional[str]           # Distributed trace ID
    chain_id: Optional[str]           # Multi-step chain identifier
```

### Gate Evaluation Logic

```python
# Agency & System Gates (Action-Scoped)
INTERCEPTION_GATES = {
    "G9": "Capability Boundary",      # Within declared capabilities?
    "G10": "Objective Integrity",     # Aligned with stated goals?
    "G12": "Composition Safety",      # Multi-agent coordination safe?
    "G14": "Tool Boundary",           # API/tool access authorized?
    "G15": "Reversibility",           # Can action be rolled back?
    "G17": "Termination",             # Kill switch operational?
}

def intercept_action(ua: UnitAction) -> ActionDecision:
    for gate_id in ["G9", "G10", "G12", "G14", "G15", "G17"]:
        result = evaluate_gate(gate_id, ua, evidence)
        if result == FAIL:
            return ActionDecision(
                decision="DENY",
                failed_gates=[gate_id],
                reason_codes=extract_reason_codes(result)
            )
        if result == WARN:
            # Accumulate warnings; may trigger MODIFY
            warnings.append(gate_id)

    if warnings:
        return ActionDecision(decision="MODIFY", warned_gates=warnings)

    return ActionDecision(decision="ALLOW")
```

### Example: Shell Command Interception

**Proposed Action (from LLM):**
```json
{
  "action_id": "act-004",
  "actor": "agent",
  "model_id": "claude-sonnet-4.5",
  "tool": "shell_exec",
  "params": {"command": "rm -rf /tmp/cache/*"},
  "capability": "system",
  "reversibility_score": 0.1
}
```

**AEGIS Evaluation:**

| Gate | Status | Reason |
|------|--------|--------|
| **G9** (Capability Boundary) | PASS | System capability declared |
| **G14** (Tool Boundary) | PASS | Shell execution authorized for this agent |
| **G15** (Reversibility) | **FAIL** | `rm -rf` irreversible; reversibility_score=0.1 < threshold |

**Decision:** `DENY` with reason code `G15_REVERSIBILITY_THRESHOLD_VIOLATION`

**Fallback:** Agent notified; may propose safer alternative or request HITL approval

---

## Demo: Live Action Interception

### UI Dashboard

The AEGIS UI (`/ui`) provides a **real-time action interception demo**:

1. **Sample Actions:** Pre-configured examples (file write, API call, database query, shell command)
2. **Custom JSON:** Paste arbitrary `UnitAction` payloads
3. **Intercept:** POST to `/v1/intercept-action` endpoint
4. **Results:** Visual display of ALLOW/DENY/MODIFY with:
   - Decision badge (color-coded)
   - Reason codes
   - Failed/warned gates
   - Full trace ID for audit

**Screenshot Placeholder:**

```
┌────────────────────────────────────────────────┐
│  Action Interception Demo                      │
├────────────────────────────────────────────────┤
│  [File Write] [API Call] [DB Query] [Shell Cmd]│
│                                                │
│  Action: shell_exec                            │
│  Command: rm -rf /tmp/cache/*                  │
│                                                │
│  [Intercept Action]                            │
│                                                │
│  ┌──────────────────────────────────────────┐  │
│  │ ❌ DENY                                  │  │
│  │ Reason: G15_REVERSIBILITY_VIOLATION      │  │
│  │ Failed Gates: G15                        │  │
│  │ Trace ID: trace-abc123                   │  │
│  └──────────────────────────────────────────┘  │
└────────────────────────────────────────────────┘
```

### API Endpoints

```bash
# Intercept single action
POST /v1/intercept-action
{
  "artifact": { "id": "agent-001", "type": "agentic_system" },
  "action": { ... },
  "frameworks": ["agentic"],
  "gate_filter": ["G9", "G10", "G14", "G15"]
}

# Response
{
  "decision": "DENY",
  "failed_gates": ["G15"],
  "reason_codes": ["G15_REVERSIBILITY_THRESHOLD_VIOLATION"],
  "trace_id": "trace-abc123",
  "latency_ms": 23
}
```

### MCP Integration

```typescript
// Claude Desktop / MCP Client
const result = await mcpClient.callTool("aegis.intercept_action", {
  artifact: { id: "agent-001", type: "agentic_system" },
  action: {
    tool: "shell_exec",
    params: { command: "rm -rf /tmp/cache/*" },
    capability: "system",
    reversibility_score: 0.1
  },
  frameworks: ["agentic"]
});

if (result.decision === "DENY") {
  console.error("Action blocked:", result.reason_codes);
}
```

---

## Implementation Status

### ✅ Completed

| Component | Status | Tests |
|-----------|--------|-------|
| **Core Models** | Complete | 100% |
| **Assurance Kernel** | Complete | 36 lattice tests |
| **115 PCUs** | Complete | Coverage across 12 frameworks |
| **Agentic PCUs (R1-R7)** | Complete | 7 risk categories |
| **REST API** | Complete | 33 tests (CAI), 61 tests (UA) |
| **Python SDK** | Complete | `client.intercept_action()` |
| **MCP Server** | Complete | `aegis.intercept_action` tool |
| **React UI** | Complete | Action Interception Demo |
| **Unit Action (UA) Interception** | Complete | Full impl + code review |

### 🔄 In Progress

- P1: SDK Plugin Entry Points (`AegisPlugin` class)
- P1: Registry Metadata Enrichment
- P1: Async SDK Client `intercept_action`

### 📋 Roadmap

- Streaming action evaluation (gRPC)
- Multi-action batch interception
- Anomaly detection for action sequences
- Integration with OpenAI function calling
- Anthropic tool use adapter

---

## Research & Telemetry

### Metrics Collected

```python
# Research metrics emitted for each interception
{
  "event_type": "action_intercepted",
  "artifact_id": "agent-001",
  "model_id": "claude-sonnet-4.5",
  "action_tool": "shell_exec",
  "capability": "system",
  "decision": "DENY",
  "failed_gates": ["G15"],
  "latency_ms": 23,
  "reversibility_score": 0.1,
  "trace_id": "trace-abc123",
  "timestamp": "2026-04-20T23:30:00Z"
}
```

### Research Questions

1. **Escape Rate:** What % of dangerous actions bypass gates?
2. **False Blocks:** How often are safe actions incorrectly blocked?
3. **Latency Impact:** Overhead on agent execution time?
4. **Coverage:** Which action types most frequently flagged?
5. **Model Differences:** Do Claude vs. GPT agents differ in violation patterns?

---

## Mathematical Foundation

### FAIL-Dominant Lattice

AEGIS uses a **bounded lattice** with FAIL as the absorbing element:

```
      ⊤ (top)
     / \
   PASS WARN
     \ /
     FAIL (absorbing)
      |
      ⊥ (bottom)
```

**Composition Rule:**
- `FAIL ∧ x = FAIL` for any `x`
- `WARN ∧ PASS = WARN`
- `PASS ∧ PASS = PASS`

**Consequence:** A single FAIL in any gate immediately propagates to the final decision. No averaging, no compensation.

### Matroid Assurance Rank

Assurance state forms a **matroid** with:
- **Ground set E:** All possible predicates
- **Basis B:** Maximally satisfied independent predicate sets
- **Rank function:** `r(S) = max{|I| : I ⊆ S, I ∈ I}`

**AssuranceRank** determines autonomy level:
- Rank ≥ 90%: High autonomy (L3)
- Rank 70-89%: Medium autonomy (L2)
- Rank < 70%: Low autonomy (L1)

**Monotonicity:** Rank can only decrease over time unless re-certified.

### Hodge Decomposition

Assurance state vector decomposed into:
```
state = core ⊕ residual ⊕ noise
```

- **Core:** Stable, provable compliance
- **Residual:** Temporal decay components
- **Noise:** Measurement uncertainty

Only **core** contributes to AssuranceRank.

---

## Deployment Architecture

### Standalone Library

AEGIS is deployable as:

1. **PyPI Package:** `pip install aegis-certify`
2. **Docker Compose:** Full stack (backend + UI + postgres)
3. **Kubernetes:** Helm chart with HPA, ingress, secrets
4. **Cloud-Agnostic:** AWS, GCP, Azure via Terraform modules

### Infrastructure Overview

```
aegis-certify/
├── ui/                    # React/TypeScript dashboard
├── infra/
│   ├── docker/           # docker-compose.yml, Dockerfiles
│   ├── kubernetes/       # K8s manifests (deployment, service, ingress)
│   ├── helm/             # Helm chart with values overlays
│   ├── terraform/        # IaC for AWS/GCP/Azure
│   └── scripts/          # deploy.sh, health-check.sh
└── src/aegis_certify/    # Python library source
```

### Quick Start

```bash
# Local development
cd infra/docker
docker-compose -f docker-compose.dev.yml up

# Access:
# - UI: http://localhost:3000
# - API: http://localhost:8000
# - MCP: http://localhost:8080

# Production K8s deployment
cd infra/scripts
./deploy.sh production
```

---

## Fellowship Contribution

### Why AEGIS for Anthropic Fellowship?

1. **Claude-Native:** Built for Anthropic's tool use and MCP paradigms
2. **Research Value:** Telemetry for safety research on agent actions
3. **Enterprise-Ready:** Deployable compliance infrastructure for production agents
4. **Multi-LLM:** Positions Claude as the safety-first model in orchestrated systems
5. **Open Foundation:** Mathematical rigor + open-source principles

### Anthropic Ecosystem Fit

```
┌─────────────────────────────────────────────────────┐
│            Anthropic Product Ecosystem               │
├─────────────────────────────────────────────────────┤
│                                                      │
│  Claude Desktop  ────►  MCP Server  ────►  AEGIS    │
│       │                    │                 │      │
│       │                    │                 │      │
│  Claude API  ─────────────►│                 │      │
│       │                    │                 │      │
│       └────────────────────┴─────────────────┘      │
│                            │                        │
│                            ▼                        │
│                  Enterprise Deployments             │
│            (Healthcare, Finance, Government)        │
│                                                      │
└─────────────────────────────────────────────────────┘
```

### Deliverables

1. **Production-Ready Library:** Fully tested, documented, deployable
2. **Reference Implementation:** Multi-LLM control plane with AEGIS
3. **Research Telemetry:** Metrics pipeline for safety evaluation
4. **Documentation:** API reference, deployment guides, cookbook
5. **Case Studies:** Real-world compliance use cases

---

## Competitive Landscape

| Solution | Approach | Enforcement | Multi-LLM | Determinism |
|----------|----------|-------------|-----------|-------------|
| **AEGIS** | Mathematical + PCUs | Hard veto | ✅ Yes | ✅ Yes |
| Guardrails AI | LLM validators | Soft | No | ❌ No |
| NeMo Guardrails | Rule-based | Soft | No | Partial |
| LangChain | Moderation chains | Soft | Yes | ❌ No |
| TrustLayer | Scoring | Advisory | No | ❌ No |

**AEGIS Differentiators:**
- **Only** solution with FAIL-dominant lattice (no compensation)
- **Only** solution with real-time action interception
- **Only** solution with formal mathematical foundation
- **Only** solution supporting 12+ regulatory frameworks

---

## Call to Action

### Next Steps

1. **Demo Request:** Live walkthrough of action interception
2. **Pilot Deployment:** Integrate AEGIS with Anthropic enterprise customer
3. **Research Collaboration:** Joint safety telemetry analysis
4. **Open Source:** Discuss licensing and community strategy

### Contact

- **GitHub:** [inferloop/aegis-certify](https://github.com/inferloop/aegis-certify)
- **Email:** contact@inferloop.com
- **Documentation:** [Full technical specs](docs/architecture/UNIFIED_ARCHITECTURE_DIAGRAM.md)
- **Live Demo:** [Request access](https://inferloop.com/aegis-demo)

---

## Appendix: Technical Deep Dives

### A. PCU Implementation Example

```python
# Example: G15 Reversibility PCU
class ReversibilityPCU(PCU):
    pcu_id = "PCU-AGENTIC-R7-001"
    evaluates = ["PRED-AGENTIC-R7"]  # Reversibility predicate
    version = "1.0.0"

    def evaluate(self, artifact, context, evidence) -> PCUResult:
        action = evidence.get("unit_action")

        # Check reversibility score
        if action.reversibility_score < self.threshold:
            return PCUResult(
                decision="FAIL",
                pcu_id=self.pcu_id,
                measurements={"reversibility_score": action.reversibility_score},
                reason_code="G15_REVERSIBILITY_THRESHOLD_VIOLATION"
            )

        # Check tool blacklist
        if action.tool in ["rm", "drop_table", "delete_bucket"]:
            return PCUResult(
                decision="FAIL",
                pcu_id=self.pcu_id,
                reason_code="G15_IRREVERSIBLE_TOOL"
            )

        return PCUResult(decision="PASS", pcu_id=self.pcu_id)
```

### B. Trace Object Structure

```python
class TraceObject(BaseModel):
    """6 canonical trace objects for explainability"""

    # 1. Normative Source
    predicate_id: str
    regulation_source: str  # "GDPR Art. 25", "EU AI Act Annex III"

    # 2. Predicate Derivation
    formal_statement: str  # P(A,C) → {true, false}
    preconditions: list[str]

    # 3. PCU Execution
    pcu_id: str
    execution_time_ms: float
    measurements: dict[str, Any]

    # 4. Gate Decision
    gate_id: str
    decision: Literal["PASS", "WARN", "FAIL"]
    aggregation_rule: str  # "FAIL-dominant lattice"

    # 5. Enforcement Action
    action_taken: Literal["HALT", "THROTTLE", "HITL", "PERMIT", "DENY", "MODIFY"]
    autonomy_impact: Optional[str]

    # 6. Evidence Chain
    evidence_refs: list[str]  # Hash IDs of evidence consumed
    evidence_independence: bool
```

### C. Performance Benchmarks

| Operation | Latency (p50) | Latency (p99) |
|-----------|---------------|---------------|
| Single PCU execution | 3ms | 12ms |
| Gate evaluation (6 PCUs avg) | 18ms | 45ms |
| Full certification (115 PCUs) | 450ms | 1.2s |
| Action interception (6 gates) | 23ms | 60ms |
| CAI computation | 520ms | 1.5s |

**Hardware:** 4-core CPU, 8GB RAM (no GPU required)

---

**End of Presentation**

*For questions or demo requests, contact: contact@inferloop.com*
