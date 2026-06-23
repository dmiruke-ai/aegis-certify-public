# AEGIS Algebra

**A unified mathematical framework for executable, non-compensatory assurance of agentic AI systems.**

AEGIS Algebra treats AI assurance as a machine-executable, multi-dimensional *state* — not a subjective trust score and not a post-hoc audit. It integrates five load-bearing formalisms into a single assurance space, each governing a distinct modality of AI behavior that the others cannot express:

| Formalism | Governs |
|---|---|
| **Matroid theory** | Structural feasibility — which configurations can exist at all |
| **Lattice & order theory** | Dominance and the absorbing nature of failure |
| **Constraint satisfaction** | Admissibility — whether a configuration satisfies its hard constraints |
| **Three-valued evaluation logic** | Soundness under partial evidence (PASS / WARN / FAIL) |
| **Temporal logic** | Validity over time — when assurance expires |

The framework is **non-compensatory by construction**: strong performance on one dimension cannot offset failure on another, and structurally infeasible configurations simply do not exist in the assurance space. No amount of evidence, confidence, or override can repair a circuit violation.

---

## The pipeline

Regulatory text is translated through a strict, layered pipeline in which **no layer substitutes for another**:

```
Regulatory clause  →  Predicate  →  Predicate Compute Unit (PCU)  →  Gate
  (legal meaning)    (binary truth)   (deterministic verdict)      (enforcement)
```

- **Predicates** carry legal meaning but encode no implementation.
- **PCUs** are deterministic, side-effect-free evaluators that compute `{PASS, WARN, FAIL}`. They never interpret legal meaning, learn, or aggregate.
- **Gates** compose verdicts under **FAIL-dominant lattice meet**: a single `FAIL` anywhere collapses the system-level decision.

A core soundness guarantee (Theorem 5): `FAIL ⇒ the predicate is false`, and a false `PASS` is impossible — partial telemetry yields `WARN`, never a silent `PASS`.

---

## Reference implementation

The framework is realized in a working **control plane** with a **demonstration system**. The current predicate basis comprises **126 Predicate Compute Units**:

- **96 standard-mapped PCUs** across six GRC standards — GDPR, EU AI Act, HIPAA, NIST AI RMF, PCI DSS, and SOC 2.
- **30 behavioral PCUs** spanning agentic, safety, fairness, RAG, data-exfiltration, monitoring, and related concerns.

These are composed across gates **G1–G17**. The canonical AEGIS matroid over this configuration has a **25-element ground set with 124 circuits** — against a subset space of 2²⁵ ≈ 3.4 × 10⁷, which is never enumerated. Independence, rank, closure, and matroid intersection are exposed as polynomial-time oracle queries. The architecture is designed to scale to broader regulatory coverage as the corpus grows.

---

## Worked examples

The paper derives executable components end-to-end from real regulatory text:

- **HIPAA §164.312(a)(2)(iv)** — encryption of ePHI (an addressable specification treated as a hard predicate once a deploying entity determines, per §164.306(d)(3), that encryption is reasonable and appropriate).
- **GDPR Article 17** — right to erasure, with the Article 12(3) one-month deadline (extendable by two further months for complex requests).
- **SOC 2 CC6.1** — logical access controls over protected information assets.

---

## Documentation

- **Paper:** *AEGIS Algebra: A Unified Mathematical Framework for Executable Assurance of Agentic AI Artifacts* (Preprint v2.2, June 2026).
- **Formal theorems:** five theorems covering soundness of admissibility, monotonicity under evidence refinement, weakest-link compositional safety, temporal invalidity of static assurance, and PCU soundness under partial evidence.

> **How to cite:** Miruke, D. *AEGIS Algebra: A Unified Mathematical Framework for Executable Assurance of Agentic AI Artifacts.* Inferloop Technologies Inc. Preprint v2.2, June 2026.

---

## What AEGIS is *not*

AEGIS is not a scoring framework, an LLM-based safety classifier, an OPA-style policy engine, or a static audit. It is a mathematically grounded control system for autonomy. It does not replace runtime-governance systems (GaaS, MI9, AAGATE, and others) — it provides the algebraic foundation against which they can be evaluated and composed. The matroid layer is also distinct from IAM (RBAC/ABAC/OPA/Cedar): IAM governs per-request *access decisions*, while the AEGIS matroid governs *configuration feasibility*.

---

## License

This repository uses a **dual-license** arrangement — please read carefully:

- **Paper / framework text, theorems, figures, and worked examples:** licensed under [Creative Commons Attribution 4.0 International (CC BY 4.0)](https://creativecommons.org/licenses/by/4.0/). You may share and adapt for any purpose, including commercially, with appropriate attribution.
- **Source code in this repository:** licensed under the **Business Source License 1.1 (BSL 1.1)**. See [`LICENSE`](./LICENSE) for the full terms, including the change date and any additional-use grant.

The production deployment corpus — the full predicate basis, PCU registry, cross-framework collapse mappings, and integration architecture — is proprietary, is **not** disclosed in this repository, and is **not** covered by the CC BY 4.0 license.

---

## Maintainer

Dattaram Miruke — Inferloop Technologies Inc. · [inferloop.ai](https://inferloop.ai) · dmiruke@inferloop.ai

---

<sub>Suggested repo topics: `ai-governance` · `ai-safety` · `agentic-ai` · `matroid-theory` · `formal-methods` · `compliance` · `temporal-logic` · `constraint-satisfaction`</sub>
