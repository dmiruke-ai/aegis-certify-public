# AEGIS Differentiators: Beyond Evaluation

**Why AEGIS is Governance Infrastructure, Not Another Evaluator**

---

## The Core Difference

```
┌─────────────────────────────────────────────────────────────────┐
│                    EVALUATORS (TruLens, RAGAS, etc.)            │
├─────────────────────────────────────────────────────────────────┤
│  Input → Score → Dashboard → Human Reviews → Maybe Action       │
│                                                                 │
│  "Your groundedness is 0.73"                                    │
│  "Toxicity probability: 12%"                                    │
│  "Relevance: 4.2/5"                                            │
│                                                                 │
│  Result: ADVISORY (human decides what to do)                    │
└─────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────┐
│                    AEGIS (Governance Infrastructure)            │
├─────────────────────────────────────────────────────────────────┤
│  Input → PCU → Gate → ENFORCEMENT ACTION                        │
│                                                                 │
│  G2 Safety: FAIL → HALT_EXECUTION (blocked)                     │
│  G5 Fairness: FAIL → HALT (cannot proceed)                      │
│  G13 Autonomy: WARN → DOWNGRADE (reduced capability)            │
│                                                                 │
│  Result: ENFORCEABLE (system acts automatically)                │
└─────────────────────────────────────────────────────────────────┘
```

---

## What Makes AEGIS More Than an Evaluator

### 1. ENFORCEMENT ACTIONS (Not Just Scores)

**Evaluators produce:**
- Scores (0.73, 4.2/5, 87%)
- Dashboards
- Reports
- Alerts

**AEGIS produces:**
| Action | Effect | Gate Example |
|--------|--------|--------------|
| `HALT` | Block execution entirely | G1, G2, G3, G5 |
| `THROTTLE` | Reduce capability/rate | G4, G8 |
| `HITL` | Require human approval | G7 |
| `DOWNGRADE` | Reduce autonomy level | G13 |
| `VETO` | Block specific action | G14 |
| `BLOCK` | Prevent operation | G15 |
| `INADMISSIBLE` | System cannot operate | G17 |

**This is the difference between a smoke detector (alert) and a sprinkler system (enforcement).**

---

### 2. FAIL-DOMINANT LATTICE (No Averaging)

**Evaluators:** "Average score is 82%, you're mostly compliant"

**AEGIS:** "One PCU failed. System is INADMISSIBLE. No averaging. No compensation."

```python
# AEGIS Lattice Meet Operation
def lattice_meet(results: list[PCUResult]) -> Decision:
    if any(r.decision == FAIL for r in results):
        return FAIL  # One failure = total failure
    if any(r.decision == WARN for r in results):
        return WARN
    return PASS

# There is NO weighted average, no "overall score"
# FAIL is FAIL. Period.
```

**Why this matters:**
- Regulatory compliance is binary (you're compliant or you're not)
- Safety is binary (it's safe or it's not)
- Averaging allows gaming the system

---

### 3. RUNTIME GATE ENFORCEMENT (Not Post-Hoc Analysis)

**Evaluators:** Run after the fact, produce reports

**AEGIS:** Runs IN THE EXECUTION PATH, blocks before harm

```
┌─────────────────────────────────────────────────────────────┐
│                   Agent Execution Flow                       │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│   User Request                                              │
│        │                                                    │
│        ▼                                                    │
│   ┌─────────┐                                               │
│   │  G1-G6  │ ◄── Pre-execution gates                       │
│   │ (Legal, │     HALT if failed                            │
│   │ Safety, │                                               │
│   │ Data)   │                                               │
│   └────┬────┘                                               │
│        │ PASS                                               │
│        ▼                                                    │
│   ┌─────────┐                                               │
│   │  Agent  │                                               │
│   │ Action  │                                               │
│   └────┬────┘                                               │
│        │                                                    │
│        ▼                                                    │
│   ┌─────────┐                                               │
│   │ G14-G15 │ ◄── Action gates                              │
│   │ (Tool,  │     VETO/BLOCK if violated                    │
│   │ Revers) │                                               │
│   └────┬────┘                                               │
│        │ PASS                                               │
│        ▼                                                    │
│   Response                                                  │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

---

### 4. MONOTONE AUTONOMY (Can Only Decrease)

**Evaluators:** No concept of autonomy levels

**AEGIS:** Autonomy is a controlled resource that can only decrease (unless re-certified)

```python
# AEGIS Autonomy Invariant
# A(t+1) ≤ A(t) unless explicitly re-certified

class AutonomyLevel(Enum):
    LEVEL_5 = "full_autonomy"      # No human oversight
    LEVEL_4 = "supervised"         # Human monitors
    LEVEL_3 = "human_on_loop"      # Human can intervene
    LEVEL_2 = "human_in_loop"      # Human approves each action
    LEVEL_1 = "human_only"         # AI assists, human acts
    LEVEL_0 = "disabled"           # AI cannot act

# If G13 detects autonomy escalation attempt: DOWNGRADE
# System CANNOT grant itself more autonomy
```

**Why this matters:**
- Prevents AI systems from expanding their own authority
- Regulatory requirement (EU AI Act, OMB M-24-35)
- Safety critical in agentic systems

---

### 5. COMPOSITION SAFETY (Multi-Agent Governance)

**Evaluators:** Evaluate single models/responses

**AEGIS:** Evaluates agent compositions, tool chains, multi-agent systems

```
┌─────────────────────────────────────────────────────────────┐
│                    G12: Composition Safety                   │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│   Agent A (Level 3) ──┬──► Combined System                  │
│                       │                                     │
│   Agent B (Level 4) ──┼──► Autonomy = MIN(3, 4, 2) = 2      │
│                       │    (Graph Meet Operation)           │
│   Tool C (Level 2) ───┘                                     │
│                                                             │
│   If ANY component FAILS → Entire composition HALTS         │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

**Why this matters:**
- Agentic systems compose multiple AI components
- Weakest link determines overall safety
- Evaluators can't reason about system composition

---

### 6. TERMINATION GUARANTEE (Kill Switch)

**Evaluators:** No concept of termination

**AEGIS G17:** Guarantees system can be terminated

```python
# G17: Termination Gate
class TerminationGuarantee:
    """
    Verifies the AI system can be stopped at any time.
    If termination cannot be guaranteed: INADMISSIBLE
    """

    def evaluate(self, artifact, context, evidence) -> PCUResult:
        # Check: Can we stop this system?
        if not evidence.has_kill_switch:
            return FAIL  # Cannot operate without kill switch

        if not evidence.kill_switch_tested:
            return WARN  # Kill switch not verified

        if evidence.kill_switch_latency_ms > 1000:
            return FAIL  # Too slow to stop

        return PASS
```

**Why this matters:**
- Regulatory requirement for high-risk AI
- Safety-critical systems must be stoppable
- No evaluator checks this

---

### 7. EVIDENCE-FIRST ARCHITECTURE (Audit Trail)

**Evaluators:** Produce scores, maybe logs

**AEGIS:** Every decision has a cryptographic evidence chain

```python
class PCUResult(BaseModel):
    decision: Literal["PASS", "WARN", "FAIL"]
    pcu_id: str
    predicate_ids: list[str]
    measurements: dict[str, Any]
    evidence_refs: list[str]       # Hashes of evidence consumed
    threshold_used: dict[str, Any] # Exact thresholds applied
    timestamp: datetime
    trace_id: str                  # Links to full proof chain
```

**Why this matters:**
- Regulatory audits require proof
- Legal liability requires evidence
- Reproducibility requires exact parameters

---

### 8. REGULATORY PREDICATE MAPPING (Compliance Built-In)

**Evaluators:** Generic metrics (toxicity, relevance, etc.)

**AEGIS:** Direct mapping to regulatory requirements

```
┌─────────────────────────────────────────────────────────────┐
│                  Regulatory Predicate Mapping                │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  EU AI Act Art. 9(2)(a) ──► PRED-EUAI-RISK-MGMT-001        │
│                                    │                        │
│                                    ▼                        │
│                            PCU-EUAI-RISK-001               │
│                                    │                        │
│                                    ▼                        │
│                               Gate G4                       │
│                                    │                        │
│                                    ▼                        │
│                           PASS/WARN/FAIL                    │
│                                                             │
│  "We comply with EU AI Act Art. 9(2)(a)" is now PROVABLE   │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

**Why this matters:**
- Regulators ask "Are you compliant with X?"
- AEGIS can answer with evidence
- Evaluators produce scores, not compliance statements

---

## Summary: Evaluator vs AEGIS

| Dimension | Evaluators | AEGIS |
|-----------|------------|-------|
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

## The Capabilities That Make AEGIS More Than Evaluators

### Must-Have (Differentiators)

1. **Gate Enforcement Engine** - HALT/THROTTLE/VETO runtime actions
2. **FAIL-Dominant Lattice** - No compensation, binary compliance
3. **Autonomy Control** - Monotone autonomy with DOWNGRADE enforcement
4. **Composition Safety (G12)** - Multi-agent governance
5. **Termination Guarantee (G17)** - Kill switch verification
6. **Regulatory Predicate Mapping** - Direct compliance proof
7. **Evidence Chain** - Cryptographic audit trail

### Nice-to-Have (Can Use External Evaluators)

1. TruLens metrics → Evidence input
2. RAGAS scores → Evidence input
3. DeepEval analysis → Evidence input
4. Relevance scoring → Evidence input

### The Formula

```
AEGIS = Evaluator Evidence + Deterministic PCUs + FAIL-Lattice + Gate Enforcement + Audit Trail
        \_________________/   \______________________________________________/
              INPUT                        GOVERNANCE INFRASTRUCTURE
```

**Evaluators produce data. AEGIS produces ENFORCEABLE GOVERNANCE.**

---

## Visual: Where AEGIS Sits

```
┌─────────────────────────────────────────────────────────────────┐
│                      AI System Stack                             │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │                    Application Layer                     │   │
│  │              (Agents, Chatbots, Workflows)               │   │
│  └─────────────────────────────────────────────────────────┘   │
│                              │                                  │
│                              ▼                                  │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │              AEGIS CONTROL PLANE (G1-G17)               │◄──┼── THIS IS WHERE
│  │         ┌────────────────────────────────┐              │   │   AEGIS OPERATES
│  │         │  HALT │ THROTTLE │ VETO │ HITL │              │   │
│  │         └────────────────────────────────┘              │   │
│  │                                                         │   │
│  │    ┌─────────────────────────────────────────────┐     │   │
│  │    │            AEGIS Assurance Kernel            │     │   │
│  │    │  ┌───────┐  ┌───────┐  ┌───────┐  ┌──────┐ │     │   │
│  │    │  │ PCUs  │  │Lattice│  │Matroid│  │Audit │ │     │   │
│  │    │  └───────┘  └───────┘  └───────┘  └──────┘ │     │   │
│  │    └─────────────────────────────────────────────┘     │   │
│  └─────────────────────────────────────────────────────────┘   │
│                              ▲                                  │
│                              │ Evidence                         │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │                   Evaluation Layer                       │   │
│  │    TruLens │ RAGAS │ DeepEval │ Fairlearn │ Evidently   │   │
│  │                    (Produce Metrics)                     │   │
│  └─────────────────────────────────────────────────────────┘   │
│                              │                                  │
│                              ▼                                  │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │                    Model Layer                           │   │
│  │           (LLMs, Embeddings, Classifiers)                │   │
│  └─────────────────────────────────────────────────────────┘   │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

---

*AEGIS: Because evaluation without enforcement is just observation.*
