# AI Governance Frameworks

## Overview

This document provides an overview of major AI governance frameworks and how AEGIS aligns with each.

---

## EU AI Act

### Summary
The European Union's AI Act is the world's first comprehensive AI regulation. It establishes a risk-based approach to AI governance with specific requirements based on risk classification.

### Risk Categories

| Category | Description | Requirements |
|----------|-------------|--------------|
| **Unacceptable** | AI systems that pose unacceptable risks | Prohibited |
| **High-Risk** | AI in critical areas (Annex III) | Conformity assessment, monitoring, documentation |
| **Limited Risk** | AI with transparency obligations | User disclosure, logging |
| **Minimal Risk** | Most other AI systems | Voluntary codes of conduct |

### Key Requirements for High-Risk AI

1. **Risk Management System** (Article 9)
2. **Data Governance** (Article 10)
3. **Technical Documentation** (Article 11)
4. **Record-Keeping** (Article 12)
5. **Transparency** (Article 13)
6. **Human Oversight** (Article 14)
7. **Accuracy, Robustness, Cybersecurity** (Article 15)

### AEGIS Mapping

| EU AI Act Requirement | AEGIS Component |
|----------------------|-----------------|
| Risk Management | G4 (Risk Management), PCU framework |
| Data Governance | G3 (Data Governance) |
| Technical Documentation | G6 (Audit Evidence), Evidence Layer |
| Record-Keeping | Trace System |
| Transparency | XAI PCUs, Explanation generation |
| Human Oversight | G7 (Human Oversight) |
| Accuracy/Robustness | G2 (Safety), Safety PCUs |

---

## NIST AI Risk Management Framework

### Summary
The NIST AI RMF provides voluntary guidance for managing AI risks. It is organized around four core functions: GOVERN, MAP, MEASURE, and MANAGE.

### Core Functions

#### GOVERN
Establish governance structures and processes:
- Policies and procedures
- Roles and responsibilities
- Accountability mechanisms
- Risk tolerance definitions

#### MAP
Understand the AI system context:
- System purpose and intended use
- Stakeholder identification
- Risk framing
- Contextual analysis

#### MEASURE
Assess AI system characteristics:
- Quantitative and qualitative analysis
- Bias and fairness testing
- Safety and security evaluation
- Performance measurement

#### MANAGE
Respond to identified risks:
- Risk prioritization
- Mitigation strategies
- Monitoring and response
- Documentation and communication

### NIST Trustworthy AI Characteristics

| Characteristic | Description |
|----------------|-------------|
| Valid & Reliable | Accurate performance under expected conditions |
| Safe | No harm to people, property, or environment |
| Secure & Resilient | Resistant to attacks, able to recover |
| Accountable & Transparent | Decisions explainable, responsibility clear |
| Explainable & Interpretable | Understandable by stakeholders |
| Privacy-Enhanced | Protects individual privacy |
| Fair with Harmful Bias Managed | No discrimination, bias monitored |

### AEGIS Mapping

| NIST Function | AEGIS Component |
|---------------|-----------------|
| GOVERN | AEGIS Control Plane, Gate definitions |
| MAP | Risk classification, Context analysis |
| MEASURE | PCU evaluations, Evidence collection |
| MANAGE | Enforcement actions, Monitoring |

| NIST Characteristic | AEGIS Gate/PCU |
|--------------------|----------------|
| Valid & Reliable | Performance PCUs |
| Safe | G2 (Safety) |
| Secure & Resilient | G2, G9, Security PCUs |
| Accountable & Transparent | G6, Trace System |
| Explainable & Interpretable | XAI PCUs |
| Privacy-Enhanced | G3 (Data Governance) |
| Fair | G5 (Fairness) |

---

## ISO/IEC 42001

### Summary
ISO/IEC 42001 specifies requirements for an AI Management System (AIMS). It follows the ISO management system structure and can be certified.

### Key Elements

1. **Context of the Organization**
   - Understanding organizational context
   - Needs of interested parties
   - Scope of AIMS

2. **Leadership**
   - Management commitment
   - AI policy
   - Roles and responsibilities

3. **Planning**
   - Risk assessment
   - AI objectives
   - Planning for changes

4. **Support**
   - Resources
   - Competence
   - Awareness and communication
   - Documentation

5. **Operation**
   - Operational planning and control
   - AI system lifecycle
   - Third-party considerations

6. **Performance Evaluation**
   - Monitoring and measurement
   - Internal audit
   - Management review

7. **Improvement**
   - Nonconformity and corrective action
   - Continual improvement

### AEGIS as AIMS Implementation

AEGIS can serve as the technical foundation for ISO 42001 compliance:

| ISO 42001 Element | AEGIS Implementation |
|-------------------|---------------------|
| Risk assessment | AEGIS risk classification, Gate evaluation |
| Operational control | PCU enforcement, Control Plane |
| Monitoring | Continuous monitoring (G8), Metrics |
| Documentation | Evidence Layer, Trace System |
| Audit | Gate audit trail, Certification records |

---

## Industry-Specific Frameworks

### Financial Services

#### SR 11-7 (Fed Reserve Model Risk Management)
- Model validation requirements
- Ongoing monitoring
- Documentation standards

**AEGIS Alignment**: PCU validation, G4 (Risk Management), Evidence Layer

#### EU DORA (Digital Operational Resilience Act)
- ICT risk management
- Incident reporting
- Third-party risk

**AEGIS Alignment**: G2 (Safety), G4 (Risk Management), Trace System

### Healthcare

#### FDA AI/ML Software Guidance
- Software as Medical Device (SaMD)
- Predetermined change control plan
- Real-world performance monitoring

**AEGIS Alignment**: G2 (Safety), G8 (Continuous Monitoring), PCU versioning

#### HIPAA
- Protected health information (PHI)
- Security requirements
- Audit controls

**AEGIS Alignment**: G3 (Data Governance), G6 (Audit Evidence), Trace System

### Automotive

#### ISO 21448 (SOTIF)
- Safety of the Intended Functionality
- Hazard analysis
- Validation strategies

**AEGIS Alignment**: G2 (Safety), Safety PCUs, G9 (Capability Boundary)

#### UN R157 (Automated Lane Keeping)
- Operational Design Domain
- Transition demands
- Data storage

**AEGIS Alignment**: G9 (Capability Boundary), G16 (Context Shift), Evidence Layer

---

## Cross-Framework Mapping

### Compliance Matrix

| Requirement Area | EU AI Act | NIST AI RMF | ISO 42001 | AEGIS Gate |
|-----------------|-----------|-------------|-----------|------------|
| Risk Management | Art. 9 | GOVERN | 6.1 | G4 |
| Data Quality | Art. 10 | MAP | 7.2 | G3 |
| Documentation | Art. 11 | GOVERN | 7.5 | G6 |
| Logging | Art. 12 | MANAGE | 8.1 | Trace |
| Transparency | Art. 13 | MEASURE | 7.3 | XAI |
| Human Oversight | Art. 14 | GOVERN | 8.2 | G7 |
| Accuracy | Art. 15 | MEASURE | 9.1 | G2 |
| Robustness | Art. 15 | MEASURE | 8.1 | G2 |
| Bias/Fairness | Art. 10 | MEASURE | 6.1 | G5 |
| Privacy | GDPR ref | MEASURE | 7.2 | G3 |
| Security | Art. 15 | MANAGE | 8.1 | G2 |

### Unified Compliance Approach

AEGIS enables a unified approach to multi-framework compliance:

```
┌─────────────────────────────────────────────────────────────────┐
│                    Regulatory Requirements                       │
│  ┌─────────┐  ┌─────────┐  ┌─────────┐  ┌─────────┐            │
│  │ EU AI   │  │  NIST   │  │  ISO    │  │Industry │            │
│  │  Act    │  │ AI RMF  │  │ 42001   │  │Specific │            │
│  └────┬────┘  └────┬────┘  └────┬────┘  └────┬────┘            │
└───────┼────────────┼────────────┼────────────┼──────────────────┘
        │            │            │            │
        └────────────┴────────────┴────────────┘
                            │
                    ┌───────▼───────┐
                    │    AEGIS      │
                    │  Predicates   │
                    └───────┬───────┘
                            │
                    ┌───────▼───────┐
                    │    PCUs       │
                    └───────┬───────┘
                            │
                    ┌───────▼───────┐
                    │    Gates      │
                    └───────┬───────┘
                            │
                    ┌───────▼───────┐
                    │ Enforcement   │
                    └───────────────┘
```

---

## Emerging Frameworks

### Agentic AI Governance

As AI systems become more autonomous (agentic), new governance considerations emerge:

| Concern | Traditional AI | Agentic AI | AEGIS Gate |
|---------|---------------|------------|------------|
| Action scope | Fixed outputs | Dynamic actions | G9, G14 |
| Human oversight | Output review | Runtime monitoring | G7, G13 |
| Multi-agent | N/A | Coordination risk | G12 |
| Termination | Model shutdown | Active kill switch | G17 |

### International Harmonization

Efforts to harmonize AI governance frameworks:

- **OECD AI Principles**: Foundation for many national approaches
- **G7 Hiroshima Process**: Code of conduct for AI developers
- **ISO/IEC JTC 1/SC 42**: AI standardization work
- **IEEE**: Ethically aligned design standards

AEGIS is designed to adapt to evolving frameworks through:
- Extensible predicate definitions
- Pluggable PCU implementations
- Configurable gate mappings
- Evidence-based compliance demonstration
