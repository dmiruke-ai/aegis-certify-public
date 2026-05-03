# OpenAI Fellowship Application - AEGIS Certify

**Applicant:** Dattaram Miruke
**Application Date:** May 3, 2026
**Project:** AEGIS Algebra - Mathematical Framework for Executable Assurance of Agentic AI

## Submission Structure

```
Fellowship/
├── README.md                          # This file
├── proposal/
│   ├── RESEARCH_PROPOSAL.md          # Main research proposal (2-3 pages)
│   └── EXECUTIVE_SUMMARY.md          # One-page executive summary
├── artifacts/
│   ├── SPRINT_2_RESULTS.md           # Experimental validation results
│   └── DEMO_METRICS.md               # Key metrics and visualizations
└── appendix/
    ├── TECHNICAL_DETAILS.md          # Deep technical implementation details
    └── FUTURE_WORK.md                # Sprint 3-7 roadmap
```

## Quick Links

- **Main Codebase:** `../aegis-experimental-platform/`
- **Sprint Reports:** `../aegis-experimental-platform/docs/`
- **Theoretical Foundation:** `../ARXIV-PAPERS/AEGIS Algebra_ A Unified Mathematical Framework.pdf`
- **GitHub Repository:** https://github.com/dmiruke-ai/aegis-certify-public
- **Live API:** http://37.27.97.75:18000/docs#/

## Key Results Summary

**Hypothesis Validation (Sprint 2):**
- ✅ **H1 (FPR):** 0.00% - Perfect performance on benign prompts
- ✅ **H2 (Jailbreak Detection):** 5.95% ASR - 93% improvement over heuristic baseline
- ✅ **H3 (Latency):** ~43ms average - Well within 100ms target
- ✅ **H4 (Evidence Quality):** High-quality evidence extraction verified

**Test Coverage:**
- 866 test cases from OpenAI fellowship dataset
- 7 attack categories evaluated
- Evidence-based PCU architecture validated

## Alignment with OpenAI Preparedness Framework

AEGIS directly operationalizes the OpenAI Prep Framework through:
- **Gate G16 (Context Shift):** ODD Enforcement for domain drift detection
- **100ms Activation:** Emergency stop mechanisms for AI-driven actions
- **Cryptographic Decision Provenance:** SHA-256 fingerprints for audit trails
- **Deterministic Governance:** Separation of Reasoning and Governance planes

## Contact

**Dattaram Miruke**
dattamiruke@gmail.com
