> **PATENT PENDING** — Technology and methodology patent pending. All rights reserved.

# AEGIS Context Graph Integration Plan

**Version:** 1.0
**Date:** 2026-03-28
**Status:** PLANNING
**Authors:** AEGIS Development Team

---

## Executive Summary

This document outlines the integration of **Context Graphs** as the 12th formalism in the AEGIS Assurance Framework. Context graphs formalize domain admissibility as a graph-structural runtime predicate, enabling detection of **gradual domain drift** — a critical gap in point-in-time compliance checks.

### Key Insight

An agent may satisfy all local predicates at every time step and still traverse — through individually acceptable transitions — into a context that was never certified for deployment. Context Graph Theory provides the graph-structural reasoning layer to detect this.

---

## 1. Formal Definition

### 1.1 Context Graph Structure

```
CG = (V, E, λ)
```

| Component | Definition |
|-----------|------------|
| **V** | Set of context nodes (domain, task type, agent role, data scope, trust tier, time window) |
| **E ⊆ V × V × K** | Directed edges; K = {TRANSITION, DEPENDENCY, CAPABILITY, TRUST} |
| **λ: V → {CERTIFIED, PROVISIONAL, FORBIDDEN}** | Certification label function |

The **certified subgraph** `G* = (V, E*, λ)` where `E*` contains only certified edges defines the admissible execution domain.

### 1.2 AEGIS Algebra Extension

Extend from 8-tuple to 9-tuple:

```
𝔸 = ⟨A, ⊑, ⊥, C, Assure, f, d, π⟩  →  𝔸 = ⟨A, ⊑, ⊥, C, Assure, f, d, π, G⟩
```

**`G`** (the certified Context Graph) acts on the **shape of the admissible region** `C ⊂ X` at runtime.

---

## 2. Source Code Integration

### 2.1 New Module: `src/aegis_certify/core/context_graph/`

```
src/aegis_certify/core/context_graph/
├── __init__.py           # Public API exports
├── graph.py              # ContextGraph, ContextNode, ContextEdge, Builder
├── predicates.py         # P_CG_* normative and derived predicates
├── pcu.py                # PCU_CG_* executable compute units
├── serialization.py      # JSON/protobuf serialization
└── composition.py        # Category-theoretic graph composition
```

### 2.2 Files to Create (from ARXIV-3)

| Source File | Target Location |
|-------------|-----------------|
| `aegis_context_graph_core.py` | `src/aegis_certify/core/context_graph/graph.py` |
| `aegis_context_graph_predicates.py` | `src/aegis_certify/core/context_graph/predicates.py` |
| `aegis_context_graph_pcu.py` | `src/aegis_certify/core/context_graph/pcu.py` |
| `aegis_gate_g16_context_validity.py` | `src/aegis_certify/core/gates/g16_context_validity.py` |
| `aegis_gates_g8_g12_g14_cg.py` | `src/aegis_certify/core/gates/g8_g12_g14_cg.py` |

### 2.3 Import Path Corrections

The ARXIV-3 files use relative imports that need adjustment:

```python
# ARXIV-3 (standalone)
from .graph import ContextGraph

# Production (within aegis_certify package)
from aegis_certify.core.context_graph.graph import ContextGraph
```

---

## 3. Gate Integration

### 3.1 Gate-to-CG Predicate Mapping

| Gate | CG Predicate | PCU | On FAIL |
|------|-------------|-----|---------|
| **G8** — Objective Integrity | `P_CG_OBJECTIVE_ALIGNED` | `PCU_CG_OBJECTIVE_ALIGNED` | HITL |
| **G12** — Scope Containment | `P_CG_SCOPE_CONTAINED` | `PCU_CG_SCOPE_CONTAINED` | HALT |
| **G14** — Multi-Agent Trust | `P_CG_AGENT_TRUST_VALID` | `PCU_CG_AGENT_TRUST_VALID` | HALT |
| **G16** — Context/Domain Shift | `P_CG_PATH_VALID` | `PCU_CG_PATH_VALID` | HITL (soft) / HALT (hard) |

### 3.2 G16 Enhancement (Primary Integration Point)

**Legacy G16:**
```python
context_within_certified_domain(context) → {PASS, WARN}
```

**CG-Enhanced G16:**
```python
context_graph_traversal_valid(CG, path, t) → {PASS, WARN, FAIL}
```

| Property | Legacy G16 | CG-Enhanced G16 |
|----------|-----------|-----------------|
| Detection scope | Point-in-time | Full traversal path |
| Gradual drift detection | No | Yes |
| Multi-agent composition | No | Yes (TRUST edges) |
| Tool call scope | No | Yes (CAPABILITY edges) |
| Temporal expiry per node | No | Yes (time windows) |
| Audit granularity | Binary | Per-node, per-edge, epoch-bound |
| Outcomes | PASS, WARN | PASS, WARN, FAIL |

### 3.3 Gate Evaluation Rule (Updated)

```python
def evaluate_gates_with_cg(cg: ContextGraph, assurance_state, context, path):
    """Gate evaluation with CG integration."""

    for gate in GATES_ORDERED:
        # CG-enhanced gates use context graph
        if gate.id in ["G8", "G12", "G14", "G16"]:
            result = gate.evaluate_with_cg(cg, assurance_state, context, path)
        else:
            result = gate.evaluate(assurance_state, context)

        if result == FAIL:
            return HALT_EXECUTION
        if result == WARN:
            autonomy = downgrade(autonomy)

    return autonomy
```

---

## 4. API Endpoints

### 4.1 New REST Endpoints

```
POST   /v1/context-graphs                    # Create new context graph
GET    /v1/context-graphs/{id}               # Retrieve context graph
GET    /v1/context-graphs/{id}/fingerprint   # Get CG epoch fingerprint
POST   /v1/context-graphs/{id}/validate-path # Validate traversal path
POST   /v1/context-graphs/{id}/compose       # Compose with another CG
DELETE /v1/context-graphs/{id}               # Revoke/archive CG
```

### 4.2 New API Route File

Create `src/aegis_certify/api/routes/context_graph.py`:

```python
from fastapi import APIRouter, HTTPException
from aegis_certify.core.context_graph import (
    ContextGraph, ContextGraphBuilder,
    PCU_CG_PATH_VALID, G16_context_validity
)

router = APIRouter(prefix="/v1/context-graphs", tags=["context-graph"])

@router.post("/")
async def create_context_graph(request: ContextGraphCreateRequest):
    """Create a new certified context graph."""
    ...

@router.post("/{cg_id}/validate-path")
async def validate_path(cg_id: str, request: PathValidationRequest):
    """Validate an agent traversal path against the certified CG."""
    ...
```

### 4.3 gRPC Service Extension

Add to `proto/aegis/v1/context_graph.proto`:

```protobuf
service ContextGraphService {
  rpc CreateContextGraph(CreateContextGraphRequest) returns (ContextGraphResponse);
  rpc ValidatePath(PathValidationRequest) returns (PathValidationResponse);
  rpc ComposeGraphs(ComposeGraphsRequest) returns (ContextGraphResponse);
  rpc StreamPathValidation(stream PathValidationRequest) returns (stream PathValidationResponse);
}
```

---

## 5. PCU Registry Updates

### 5.1 New PCU Registrations

Add to `src/aegis_certify/pcus/context_graph/__init__.py`:

| PCU ID | Evaluates | Gate | Authority |
|--------|-----------|------|-----------|
| `PCU_CG_PATH_VALID` | P_CG_PATH_VALID | G16 | Soft / Hard |
| `PCU_CG_SCOPE_CONTAINED` | P_CG_SCOPE_CONTAINED | G12 | Hard |
| `PCU_CG_OBJECTIVE_ALIGNED` | P_CG_OBJECTIVE_ALIGNED | G8 | Soft |
| `PCU_CG_AGENT_TRUST_VALID` | P_CG_AGENT_TRUST_VALID | G14 | Hard |
| `PCU_CG_TOOL_EDGE_CERTIFIED` | P_CG_TOOL_EDGE_CERTIFIED | G12 (derived) | Hard |
| `PCU_CG_TEMPORAL_WINDOW` | P_CG_TEMPORAL_WINDOW | G16 (derived) | Soft |

### 5.2 Registry Completeness Validation

Update registry validation to ensure:
- Every CG predicate has at least one PCU
- CG PCUs are bound to correct gates
- CG fingerprint is emitted in all PCU results

---

## 6. Matroid Theory Integration

### 6.1 Parametric Matroid Extension

The certified context graph `G*` extends the static matroid ground set:

- `E_matroid = {p₁, …, pₙ}` — static assurance parameters (defined at certification)
- `V(G*)` — valid operational contexts at time `t` (dynamic domain boundary)

### 6.2 Update to `src/aegis_certify/core/matroid.py`

```python
class ParametricMatroid:
    """Matroid with context-graph-bounded ground set."""

    def __init__(self, static_ground_set: Set[str], context_graph: ContextGraph):
        self.E_static = static_ground_set
        self.cg = context_graph

    def ground_set_at(self, t: datetime) -> Set[str]:
        """Return active ground set elements bounded by CG at time t."""
        active_contexts = {
            node.node_id for node in self.cg.nodes()
            if node.is_temporally_valid(t) and not node.is_forbidden()
        }
        return self.E_static & active_contexts
```

---

## 7. Category-Theoretic Composition

### 7.1 Graph Composition Rule

When composing two agent systems with context graphs `G₁` and `G₂`:

```
G₁ ∘ G₂ = (V₁ ∪ V₂,  E₁ ∪ E₂ ∪ E_trust,  λ*)
```

Where:
- `E_trust` introduces TRUST edges between shared nodes
- `λ*` applies **weakest-link** label: `λ*(v) = max_priority(λ₁(v), λ₂(v))`
  - Priority: FORBIDDEN > PROVISIONAL > CERTIFIED

### 7.2 Theorem 3 Extension

**Weakest-Link Compositional Safety** extends to the context graph layer: a FORBIDDEN label in either component graph is preserved in the composed graph.

---

## 8. Audit & Traceability

### 8.1 CG Fingerprint Binding

Every PCU result emits a `cg_fingerprint` (SHA-256 of the graph epoch):

```python
@dataclass
class PCUResult:
    pcu_id: str
    decision: str  # PASS | WARN | FAIL
    cg_fingerprint: str  # SHA-256 of CG epoch
    ...
```

### 8.2 Audit Trace Chain

```
NSR (Regulatory Requirement)
  → PDR (Predicate Definition)
    → Gate (G8/G12/G14/G16)
      → PCU (PCU_CG_*)
        → Action (PASS/WARN/FAIL → NONE/HITL/HALT)
          → CG Fingerprint (Epoch Binding)
```

---

## 9. Implementation Phases

### Phase 1: Core Module (Week 1-2)

- [ ] Create `src/aegis_certify/core/context_graph/` directory structure
- [ ] Port and adapt `graph.py` from ARXIV-3
- [ ] Port and adapt `predicates.py` from ARXIV-3
- [ ] Port and adapt `pcu.py` from ARXIV-3
- [ ] Add serialization support (JSON, protobuf)
- [ ] Unit tests for all core classes

### Phase 2: Gate Integration (Week 3)

- [ ] Create `src/aegis_certify/core/gates/` directory
- [ ] Port G16 gate implementation
- [ ] Port G8, G12, G14 gate extensions
- [ ] Update gate registry
- [ ] Integration tests for gate evaluation

### Phase 3: API & gRPC (Week 4)

- [ ] Create REST endpoints in `api/routes/context_graph.py`
- [ ] Add protobuf definitions
- [ ] Implement gRPC servicer
- [ ] API documentation (OpenAPI)

### Phase 4: PCU Registry & Matroid (Week 5)

- [ ] Register CG PCUs in PCU registry
- [ ] Update matroid.py for parametric extension
- [ ] Registry completeness validation
- [ ] Update kernel.py for CG-aware evaluation

### Phase 5: Testing & Documentation (Week 6)

- [ ] End-to-end tests
- [ ] Performance benchmarks
- [ ] Documentation (SDK guide, API reference)
- [ ] Example notebooks

---

## 10. Test Requirements

### 10.1 Unit Tests (Per Module)

| Module | Required Tests |
|--------|----------------|
| `graph.py` | Node creation, edge creation, path validation, BFS, fingerprint, composition |
| `predicates.py` | P_CG_PATH_VALID, P_CG_SCOPE_CONTAINED, P_CG_OBJECTIVE_ALIGNED, P_CG_AGENT_TRUST_VALID |
| `pcu.py` | All 6 PCUs with PASS/WARN/FAIL paths, evidence binding |
| Gates | FAIL-dominance, hard/soft mode, audit trace generation |

### 10.2 Integration Tests

- Full predicate → PCU → gate → enforcement chain
- Multi-agent composition with TRUST edges
- Temporal window expiry handling
- CG fingerprint consistency across evaluations

### 10.3 Coverage Target

- **Core module:** 100% line coverage
- **PCUs:** 100% branch coverage
- **Gates:** 100% decision coverage

---

## 11. Compatibility & Migration

### 11.1 Backward Compatibility

- Existing gates (G1-G7, G9-G11, G13, G15, G17) remain unchanged
- CG-enhanced gates (G8, G12, G14, G16) are **additive** — they extend, not replace
- Legacy `context_within_certified_domain()` continues to work but emits deprecation warning

### 11.2 Migration Path

1. **Phase A:** Deploy CG module alongside existing gates (shadow mode)
2. **Phase B:** Enable CG predicates in evaluation (audit mode)
3. **Phase C:** Activate CG enforcement (full mode)

---

## 12. Risk Assessment

| Risk | Mitigation |
|------|------------|
| Performance overhead from graph traversal | BFS is O(V+E); cache reachability results per epoch |
| Graph version drift between services | CG fingerprint binding ensures consistency |
| Complex multi-agent composition | Category-theoretic rules are deterministic; extensive test coverage |
| Temporal window clock skew | Use NTP-synced UTC; tolerance window configurable |

---

## 13. Success Criteria

1. **All 43 tests from ARXIV-3 pass** in production codebase
2. **FAIL-dominance preserved** in all CG gate evaluations
3. **CG fingerprint** appears in every PCU result and audit trace
4. **G16 enhancement** detects gradual domain drift (test scenario)
5. **Multi-agent composition** correctly propagates FORBIDDEN labels
6. **REST/gRPC APIs** operational with < 50ms latency for path validation

---

## 14. References

- `AEGIS_Context_Graph_Integration_Summary.md` — Formal specification
- `ARXIV-3/` — Reference implementation
- CLAUDE.md — Project directives and invariants
- EU AI Act Articles 9, 14 — Normative regulatory sources
- NIST AI RMF GOVERN 1.1, 6.2, MAP 2.3 — Framework references
- ISO 42001 §8.4, §8.5 — Standard references

---

## Appendix A: Canonical Statement

> In AEGIS, the Context Graph `G = (V, E, λ)` defines the certified operational domain of an AI artifact as a labeled directed graph. The path validity predicate `P_CG` governs domain admissibility at runtime: any traversal of a FORBIDDEN node or uncertified edge collapses gate evaluation to `⊥` under FAIL-dominant lattice semantics. This predicate is non-compensatory, audit-traceable, and integrates directly into gates G8, G12, G14, and G16 of the AEGIS control plane.

---

## Appendix B: File Checklist

```
[ ] src/aegis_certify/core/context_graph/__init__.py
[ ] src/aegis_certify/core/context_graph/graph.py
[ ] src/aegis_certify/core/context_graph/predicates.py
[ ] src/aegis_certify/core/context_graph/pcu.py
[ ] src/aegis_certify/core/context_graph/serialization.py
[ ] src/aegis_certify/core/context_graph/composition.py
[ ] src/aegis_certify/core/gates/__init__.py
[ ] src/aegis_certify/core/gates/g16_context_validity.py
[ ] src/aegis_certify/core/gates/g8_g12_g14_cg.py
[ ] src/aegis_certify/api/routes/context_graph.py
[ ] proto/aegis/v1/context_graph.proto
[ ] tests/unit/test_context_graph.py
[ ] tests/unit/test_cg_predicates.py
[ ] tests/unit/test_cg_pcus.py
[ ] tests/unit/test_cg_gates.py
[ ] tests/integration/test_cg_evaluation_chain.py
[ ] docs/context-graph-guide.md
```

---

*Document generated: 2026-03-28*
*Next review: Upon completion of Phase 1*
