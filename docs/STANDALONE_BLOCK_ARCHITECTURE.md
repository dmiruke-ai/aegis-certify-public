> **PATENT PENDING** — Technology and methodology patent pending. All rights reserved.

# AEGIS Certify - Standalone Block Architecture

## System Overview

```
┌────────────────────────────────────────────────────────────────────┐
│                  AEGIS CERTIFY STANDALONE SYSTEM                   │
│              Zero Dependencies on other AI Infrastructure         │
└────────────────────────────────────────────────────────────────────┘
```

---

## High-Level Block Diagram

```
┌──────────────────────────────────────────────────────────────────┐
│                         EXTERNAL CLIENTS                          │
├──────────────────────────────────────────────────────────────────┤
│  Web Browsers  │  Claude Desktop  │  Python SDKs  │  REST Clients │
│  (Dashboard)   │     (MCP)        │  (Async/Sync) │   (API Docs)  │
└───────┬────────┴────────┬────────┴───────┬───────┴──────┬─────────┘
        │                 │                 │              │
        │ HTTP:10300      │ HTTP:10080      │              │ HTTP:10800
        │                 │                 │              │
┌───────▼─────────────────▼─────────────────▼──────────────▼─────────┐
│                    NETWORK LAYER (Docker Bridge)                   │
│                      aegis-dev (172.24.0.0/16)                     │
└───────┬─────────────────┬─────────────────┬──────────────┬─────────┘
        │                 │                 │              │
┌───────▼─────────┐ ┌────▼──────────┐ ┌───▼──────────┐  │
│   AEGIS UI      │ │  MCP SERVER   │ │ AEGIS BACKEND│  │
│  (React/Vite)   │ │  (Python)     │ │  (FastAPI)   │  │
│                 │ │               │ │              │  │
│ Port: 3000      │ │ Port: 8080    │ │ Port: 8000   │  │
│ Ext: 10300      │ │ Ext: 10080    │ │ Ext: 10800   │  │
│                 │ │               │ │              │  │
│ Components:     │ │ Features:     │ │ Features:    │  │
│ - Dashboard     │ │ - Claude      │ │ - /certify   │  │
│ - CAI Display   │ │   Desktop     │ │ - /intercept │  │
│ - Gate Grid     │ │   Integration │ │ - /compute   │  │
│ - Action Demo   │ │ - Tool        │ │ - /health    │  │
│                 │ │   Exposure    │ │              │  │
└────────┬────────┘ └───────┬───────┘ └──────┬───────┘  │
         │                  │                 │          │
         │ API Calls        │ API Calls       │          │
         └──────────────────┴─────────────────┘          │
                            │                            │
                            │ Kernel Operations          │
                            ▼                            │
┌──────────────────────────────────────────────────────┐ │
│           AEGIS ASSURANCE KERNEL (Core Engine)        │ │
├──────────────────────────────────────────────────────┤ │
│  ┌────────────┐  ┌──────────────┐  ┌──────────────┐ │ │
│  │ Predicates │  │  PCU Engine  │  │  Gate System │ │ │
│  │            │  │              │  │              │ │ │
│  │ Formal     │  │ 115+ PCUs    │  │ G1-G17       │ │ │
│  │ Logic      │  │ Evaluators   │  │ Ordered      │ │ │
│  │ Assertions │  │              │  │ Gates        │ │ │
│  └────────────┘  └──────────────┘  └──────────────┘ │ │
│                                                       │ │
│  ┌────────────┐  ┌──────────────┐  ┌──────────────┐ │ │
│  │  Lattice   │  │   Matroid    │  │    CAI       │ │ │
│  │  Logic     │  │   Basis      │  │  Computation │ │ │
│  │            │  │              │  │              │ │ │
│  │ FAIL-      │  │ Assurance    │  │ 0-100        │ │ │
│  │ dominant   │  │ Rank         │  │ Score        │ │ │
│  └────────────┘  └──────────────┘  └──────────────┘ │ │
└───────────────────────┬──────────────────────────────┘ │
                        │                                │
                        │ Data Operations                │
                        ▼                                │
┌──────────────────────────────────────────────────────┐ │
│              DATA & PERSISTENCE LAYER                 │ │
├──────────────────────────────────────────────────────┤ │
│  ┌─────────────────────┐    ┌────────────────────┐  │ │
│  │  PostgreSQL         │    │  Redis Cache       │  │ │
│  │                     │    │                    │  │ │
│  │ Port: 5432 (15432)  │    │ Port: 6379 (16379) │  │ │
│  │                     │    │                    │  │ │
│  │ Tables:             │    │ Namespaces:        │  │ │
│  │ - certifications    │    │ - aegis:cai:*      │  │ │
│  │ - pcu_results       │    │ - aegis:gate:*     │  │ │
│  │ - gate_evaluations  │    │ - aegis:session:*  │  │ │
│  │ - audit_logs        │    │ - aegis:ratelimit:*│  │ │
│  │ - evidence_store    │    │                    │  │ │
│  │ - action_intercept  │    │                    │  │ │
│  │                     │    │                    │  │ │
│  │ Volume:             │    │ Ephemeral          │  │ │
│  │ postgres_dev_data   │    │ (in-memory)        │  │ │
│  └─────────────────────┘    └────────────────────┘  │ │
└──────────────────────────────────────────────────────┘ │
                                                         │
┌──────────────────────────────────────────────────────┐ │
│            SUPPORTING INFRASTRUCTURE                  │ │
├──────────────────────────────────────────────────────┤ │
│  ┌──────────────────────────────────────────────┐   │ │
│  │  Docker Network: docker_aegis-dev (Bridge)   │   │ │
│  │  Subnet: 172.24.0.0/16                       │   │ │
│  │  Isolation: Complete (no external networks)  │   │ │
│  └──────────────────────────────────────────────┘   │ │
│                                                      │ │
│  ┌──────────────────────────────────────────────┐   │ │
│  │  Volumes                                     │   │ │
│  │  - postgres_dev_data (persistent)            │   │ │
│  │  - /app/node_modules (anonymous)             │   │ │
│  │  - /app/.venv (anonymous)                    │   │ │
│  └──────────────────────────────────────────────┘   │ │
└──────────────────────────────────────────────────────┘ │
                                                         │
┌──────────────────────────────────────────────────────┐ │
│               NFTABLES PORT FORWARDING                │ │
├──────────────────────────────────────────────────────┤ │
│  37.27.97.75:10300  →  172.24.0.5:3000   (UI)       │ │
│  37.27.97.75:10800  →  172.24.0.4:8000   (Backend)  │ │
│  37.27.97.75:10080  →  172.24.0.6:8080   (MCP)      │ │
│  37.27.97.75:15432  →  172.24.0.2:5432   (Postgres) │ │
│  37.27.97.75:16379  →  172.24.0.3:6379   (Redis)    │ │
└──────────────────────────────────────────────────────┘ │
                                                         │
         Exposed to External Network: 37.27.97.75 ◄──────┘
```

---

## Component Details

### 1. User Interface Layer

#### AEGIS UI Dashboard (Container: `aegis-ui-dev`)
```
Technology Stack:
├── React 18 (Frontend Framework)
├── TypeScript (Type Safety)
├── Vite 5.4 (Build Tool & Dev Server)
├── Tailwind CSS (Styling - Dark Theme)
└── Axios (HTTP Client)

Features:
├── Certification Tab
│   ├── Artifact Input Form
│   ├── CAI Score Display (0-100)
│   └── 17-Gate Status Grid
│
└── Action Interception Tab
    ├── Sample Action Triggers
    ├── Real-time Interception Demo
    └── Gate Subset Visualization (G9, G10, G12, G14, G15, G17)

Container Details:
├── Base Image: node:18-alpine
├── Working Dir: /app
├── Command: npm install && npm run dev --host 0.0.0.0
├── Internal Port: 3000
├── External Port: 10300
└── Volume Mount: ../../ui:/app (live reload)
```

#### MCP Server (Container: `aegis-mcp-dev`)
```
Purpose: Claude Desktop Integration via Model Context Protocol

Features:
├── Tool Exposure to Claude Desktop
├── Certification Context Passing
├── Action Interception Hooks
└── Evidence Submission

Container Details:
├── Base Image: python:3.11-slim
├── Working Dir: /app
├── Command: python -m mcp_server.server
├── Internal Port: 8080
├── External Port: 10080
└── Environment: AEGIS_API_URL=http://backend:8000
```

---

### 2. Application Layer

#### AEGIS Backend API (Container: `aegis-backend-dev`)
```
Technology Stack:
├── FastAPI 0.136 (REST Framework)
├── Uvicorn (ASGI Server)
├── Pydantic v2 (Data Validation)
├── SQLAlchemy (ORM)
├── asyncpg (Async PostgreSQL Driver)
└── aioredis (Async Redis Client)

API Endpoints:
├── POST /v1/certify
│   └── Full artifact certification (calls all 17 gates)
│
├── POST /v1/intercept
│   └── Real-time action interception (subset of 6 gates)
│
├── POST /v1/cai/compute
│   └── Compute CAI score without full certification
│
├── GET /v1/gates
│   └── List all gates and their status
│
├── GET /v1/predicates
│   └── List all predicates and their PCUs
│
└── GET /health
    └── System health check

Container Details:
├── Base Image: python:3.11-slim
├── Working Dir: /app
├── Command: uvicorn aegis_certify.api.app:app --reload
├── Internal Port: 8000
├── External Port: 10800
├── Environment:
│   ├── DATABASE_URL: postgresql://aegis:***@postgres:5432/aegis_certify_dev
│   ├── REDIS_URL: redis://redis:6379/0
│   ├── CORS_ORIGINS: http://localhost:10300,http://localhost:10173
│   ├── SECRET_KEY: dev-secret-key
│   └── PYTHONPATH: /app/src
└── Volume Mount: ../../:/app (live reload)
```

---

### 3. Core Engine Layer

#### AEGIS Assurance Kernel
```
Core Modules (src/aegis_certify/core/):

┌─────────────────────────────────────────────────────┐
│  predicates.py                                      │
│  - Formal predicate definitions                    │
│  - Predicate algebra (AND, OR, NOT)                │
│  - Mapping to regulatory requirements              │
└─────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────┐
│  pcu.py                                             │
│  - PCU (Primary Compute Unit) base class           │
│  - PCU registry and completeness validation        │
│  - Evidence requirements specification             │
│  - Result: {PASS, WARN, FAIL}                      │
└─────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────┐
│  gates.py                                           │
│  - G1-G17 gate implementations                     │
│  - Ordered gate evaluation (non-bypassable)        │
│  - Decision: {HALT, THROTTLE, PERMIT, DOWNGRADE}   │
│  - Gate composition and dependency resolution      │
└─────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────┐
│  lattice.py                                         │
│  - FAIL-dominant lattice semantics                 │
│  - Meet/join operations                            │
│  - No compensation, no averaging                   │
│  - Monotonicity enforcement                        │
└─────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────┐
│  matroid.py                                         │
│  - Matroid basis computation                       │
│  - AssuranceRank calculation                       │
│  - Independence oracle                             │
│  - Autonomy level mapping                          │
└─────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────┐
│  kernel.py                                          │
│  - Main orchestrator                               │
│  - Certification workflow coordination             │
│  - CAI computation pipeline                        │
│  - Audit trail generation                          │
└─────────────────────────────────────────────────────┘
```

#### PCU Library (src/aegis_certify/pcus/)
```
115+ PCUs across 12 regulatory frameworks:

├── agentic/ (R1-R7 Agentic AI Risks)
│   ├── R1: Inadequate Monitoring
│   ├── R2: Unsafe Tool Use
│   ├── R3: Deceptive Behavior
│   ├── R4: Self-Exfiltration
│   ├── R5: Self-Proliferation
│   ├── R6: Resource Acquisition
│   └── R7: Power-Seeking
│
├── gdpr/ (EU Data Protection)
│   ├── Lawful Basis
│   ├── Consent Management
│   ├── Right to Erasure
│   ├── Data Minimization
│   └── Breach Notification
│
├── eu_ai_act/ (EU AI Regulation)
│   ├── High-Risk Classification
│   ├── Transparency Requirements
│   ├── Human Oversight
│   └── Technical Documentation
│
├── nist_ai_rmf/ (NIST AI Risk Management)
│   ├── Governance
│   ├── Mapping
│   ├── Measurement
│   └── Management
│
├── soc2/ (Trust Service Criteria)
│   ├── Security
│   ├── Availability
│   ├── Confidentiality
│   └── Privacy
│
├── hipaa/ (Healthcare Privacy)
├── pci_dss/ (Payment Card Industry)
├── iso42001/ (AI Management System)
└── fda_aiml/ (Medical Device AI/ML)
```

---

### 4. Data & Persistence Layer

#### PostgreSQL Database (Container: `aegis-postgres-dev`)
```
Database Schema:

certifications
├── id (UUID, PRIMARY KEY)
├── artifact_id (VARCHAR)
├── artifact_type (VARCHAR)
├── version (VARCHAR)
├── cai_score (FLOAT)
├── decision (ENUM: HALT, THROTTLE, PERMIT)
├── gate_results (JSONB)
├── pcu_results (JSONB)
├── trace_id (UUID)
├── certified_at (TIMESTAMP)
└── expires_at (TIMESTAMP)

pcu_results
├── id (UUID, PRIMARY KEY)
├── certification_id (UUID, FOREIGN KEY)
├── pcu_id (VARCHAR)
├── predicate_ids (ARRAY)
├── decision (ENUM: PASS, WARN, FAIL)
├── measurements (JSONB)
├── evidence_refs (JSONB)
├── threshold_used (JSONB)
└── evaluated_at (TIMESTAMP)

gate_evaluations
├── id (UUID, PRIMARY KEY)
├── certification_id (UUID, FOREIGN KEY)
├── gate_id (VARCHAR: G1-G17)
├── result (ENUM: PASS, FAIL)
├── predicates_evaluated (JSONB)
├── enforcement_action (ENUM: HALT, THROTTLE, PERMIT, DOWNGRADE)
└── evaluated_at (TIMESTAMP)

audit_logs (Tamper-Evident)
├── id (UUID, PRIMARY KEY)
├── event_type (VARCHAR)
├── certification_id (UUID)
├── actor (VARCHAR)
├── payload (JSONB)
├── previous_hash (VARCHAR)
├── current_hash (VARCHAR)
└── logged_at (TIMESTAMP)

evidence_store
├── id (UUID, PRIMARY KEY)
├── evidence_type (VARCHAR)
├── artifact_id (VARCHAR)
├── content (JSONB)
├── hash (VARCHAR)
└── submitted_at (TIMESTAMP)

action_intercept_log
├── id (UUID, PRIMARY KEY)
├── action_id (VARCHAR)
├── actor (VARCHAR)
├── tool (VARCHAR)
├── params (JSONB)
├── decision (ENUM: ALLOW, DENY, MODIFY)
├── gates_evaluated (JSONB)
├── reversibility_score (FLOAT)
└── intercepted_at (TIMESTAMP)

Container Details:
├── Base Image: postgres:15-alpine
├── Database: aegis_certify_dev
├── User: aegis
├── Internal Port: 5432
├── External Port: 15432
├── Volume: postgres_dev_data (persistent)
└── Health Check: pg_isready -U aegis
```

#### Redis Cache (Container: `aegis-redis-dev`)
```
Key Namespaces:

aegis:cai:*
├── aegis:cai:{artifact_id} → CAI Score (0-100)
├── TTL: 3600 seconds (1 hour)
└── Purpose: Fast CAI retrieval without recomputation

aegis:gate:*
├── aegis:gate:{artifact_id}:{gate_id} → Gate Result
├── TTL: 1800 seconds (30 minutes)
└── Purpose: Cache gate evaluations

aegis:session:*
├── aegis:session:{session_id} → User Session
├── TTL: 86400 seconds (24 hours)
└── Purpose: Session management

aegis:ratelimit:*
├── aegis:ratelimit:{client_ip}:{endpoint} → Request Count
├── TTL: 60 seconds (1 minute)
└── Purpose: API rate limiting

Container Details:
├── Base Image: redis:7-alpine
├── Internal Port: 6379
├── External Port: 16379
├── Persistence: None (ephemeral)
└── Health Check: redis-cli ping
```

---

### 5. Network & Isolation

#### Docker Network
```
Network: docker_aegis-dev
├── Driver: bridge
├── Subnet: 172.24.0.0/16
├── Gateway: 172.24.0.1
└── Isolation: Complete (no external network connectivity)

Container IP Assignments:
├── aegis-postgres-dev:  172.24.0.2
├── aegis-redis-dev:     172.24.0.3
├── aegis-backend-dev:   172.24.0.4
├── aegis-ui-dev:        172.24.0.5
└── aegis-mcp-dev:       172.24.0.6
```

#### Port Forwarding (nftables)
```
External Access via Server IP: 37.27.97.75

Rule Chain:
├── 37.27.97.75:10300 → 172.24.0.5:3000   (UI Dashboard)
├── 37.27.97.75:10800 → 172.24.0.4:8000   (Backend API)
├── 37.27.97.75:10080 → 172.24.0.6:8080   (MCP Server)
├── 37.27.97.75:15432 → 172.24.0.2:5432   (PostgreSQL)
└── 37.27.97.75:16379 → 172.24.0.3:6379   (Redis)

Firewall Status:
├── Managed by: nftables (NOT ufw)
├── Ingress: Allowed on all AEGIS ports
└── Egress: Unrestricted
```

---

## Data Flow Diagrams

### Certification Flow
```
┌──────────────────────────────────────────────────────────────────┐
│ 1. User Submits Artifact for Certification                       │
└──────────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌──────────────────────────────────────────────────────────────────┐
│ 2. UI → POST /v1/certify                                          │
│    {                                                              │
│      "artifact_id": "agent-001",                                  │
│      "artifact_type": "agent",                                    │
│      "frameworks": ["langgraph"],                                 │
│      "version": "1.0.0"                                           │
│    }                                                              │
└──────────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌──────────────────────────────────────────────────────────────────┐
│ 3. Backend Validates Request                                      │
│    - Check artifact_id format                                     │
│    - Validate version string                                      │
│    - Verify frameworks are supported                              │
└──────────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌──────────────────────────────────────────────────────────────────┐
│ 4. Check Redis Cache                                              │
│    GET aegis:cai:agent-001                                        │
│    - If HIT: Return cached result                                 │
│    - If MISS: Continue to evaluation                              │
└──────────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌──────────────────────────────────────────────────────────────────┐
│ 5. Kernel: Evaluate All 17 Gates in Order (G1 → G17)             │
│                                                                    │
│    For each Gate:                                                 │
│    ├── Load predicates for gate                                   │
│    ├── Load PCUs for each predicate                               │
│    ├── Execute PCUs with evidence                                 │
│    ├── Apply lattice logic (FAIL-dominant)                        │
│    └── Record result: {PASS, FAIL}                                │
│                                                                    │
│    If any Gate returns FAIL:                                      │
│    └── Return decision: HALT (stop evaluation)                    │
└──────────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌──────────────────────────────────────────────────────────────────┐
│ 6. Compute CAI Score (if all gates pass)                          │
│    - Matroid basis computation                                    │
│    - AssuranceRank calculation                                    │
│    - Normalize to 0-100 scale                                     │
│    - Map to autonomy level (L0/L1/L2/L3)                          │
└──────────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌──────────────────────────────────────────────────────────────────┐
│ 7. Persist Results                                                │
│    - INSERT INTO certifications (...)                             │
│    - INSERT INTO pcu_results (bulk insert)                        │
│    - INSERT INTO gate_evaluations (bulk insert)                   │
│    - INSERT INTO audit_logs (tamper-evident chain)                │
└──────────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌──────────────────────────────────────────────────────────────────┐
│ 8. Cache Result                                                   │
│    - SET aegis:cai:agent-001 → 78.5 EX 3600                       │
│    - SET aegis:gate:agent-001:G1 → PASS EX 1800                   │
│    - (Cache all gate results for fast re-checks)                  │
└──────────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌──────────────────────────────────────────────────────────────────┐
│ 9. Return Response to UI                                          │
│    {                                                              │
│      "certification_id": "uuid-...",                              │
│      "artifact_id": "agent-001",                                  │
│      "cai_score": 78.5,                                           │
│      "decision": "PERMIT",                                        │
│      "autonomy_level": "L2",                                      │
│      "gate_results": [                                            │
│        {"gate": "G1", "result": "PASS"},                          │
│        ...                                                        │
│      ],                                                           │
│      "trace_id": "uuid-..."                                       │
│    }                                                              │
└──────────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌──────────────────────────────────────────────────────────────────┐
│ 10. UI Displays Results                                           │
│     - CAI Score: Large number (78.5)                              │
│     - Gate Grid: 17 boxes (all green with checkmarks)             │
│     - Decision Badge: "PERMIT" (green)                            │
│     - Autonomy Level: "L2 - Supervised Automation"                │
└──────────────────────────────────────────────────────────────────┘
```

### Action Interception Flow
```
┌──────────────────────────────────────────────────────────────────┐
│ 1. Agent Attempts Action (e.g., File Write)                       │
└──────────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌──────────────────────────────────────────────────────────────────┐
│ 2. SDK/MCP → POST /v1/intercept                                   │
│    {                                                              │
│      "action_id": "act-123",                                      │
│      "actor": "agent-001",                                        │
│      "tool": "file_write",                                        │
│      "params": {                                                  │
│        "path": "/tmp/data.json",                                  │
│        "content": "{...}"                                         │
│      },                                                           │
│      "capability": "filesystem",                                  │
│      "reversibility_score": 0.8                                   │
│    }                                                              │
└──────────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌──────────────────────────────────────────────────────────────────┐
│ 3. Kernel: Evaluate Subset of 6 Gates (Fast Path)                │
│    - G9: Capability Boundary Check                                │
│    - G10: Objective Integrity Check                               │
│    - G12: Composition Safety                                      │
│    - G14: Tool Boundary Check                                     │
│    - G15: Reversibility Check                                     │
│    - G17: Termination Guarantee                                   │
│                                                                    │
│    Latency Target: <50ms                                          │
└──────────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌──────────────────────────────────────────────────────────────────┐
│ 4. Decision                                                       │
│    - If any gate FAIL → DENY                                      │
│    - If all gates PASS → ALLOW                                    │
│    - If WARN + unsafe → MODIFY (add safeguards)                   │
└──────────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌──────────────────────────────────────────────────────────────────┐
│ 5. Log Action                                                     │
│    INSERT INTO action_intercept_log (...)                         │
│    - Tamper-evident audit trail                                   │
│    - Telemetry for safety research                                │
└──────────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌──────────────────────────────────────────────────────────────────┐
│ 6. Return Decision                                                │
│    {                                                              │
│      "action_id": "act-123",                                      │
│      "decision": "ALLOW",                                         │
│      "gates_evaluated": ["G9", "G10", "G12", "G14", "G15", "G17"],│
│      "latency_ms": 23.4,                                          │
│      "trace_id": "uuid-..."                                       │
│    }                                                              │
└──────────────────────────────────────────────────────────────────┘
```

---

## Deployment Topology

### Development Environment (Current)
```
Server: 37.27.97.75
OS: Linux (Ubuntu/Debian)
Kernel: 6.8.0-100-generic
Docker: 24.x
Docker Compose: v2

├── All services in single docker-compose.dev.yml
├── Hot reload enabled (volume mounts)
├── Debug logging (LOG_LEVEL=DEBUG)
├── Development secrets (hardcoded)
└── No TLS (HTTP only)
```

### Production Deployment (K3s - Optional)
```
Cluster: K3s on server2
Namespace: aegis-sandbox

├── StatefulSet: PostgreSQL (1 replica, PVC)
├── Deployment: Redis (1 replica)
├── Deployment: Backend (2-10 replicas, HPA)
├── Deployment: UI (2 replicas)
├── Deployment: MCP (1 replica)
├── Ingress: TLS + rate limiting
├── Secrets: Vault integration
└── Monitoring: Prometheus + Grafana
```

---

## Resource Requirements

### Current Deployment (Docker Compose)
```
Container Resource Usage:
├── aegis-backend-dev:   CPU: 0.5 core   │ RAM: 512MB
├── aegis-ui-dev:        CPU: 0.2 core   │ RAM: 256MB
├── aegis-postgres-dev:  CPU: 0.5 core   │ RAM: 512MB
├── aegis-redis-dev:     CPU: 0.1 core   │ RAM: 256MB
├── aegis-mcp-dev:       CPU: 0.2 core   │ RAM: 256MB
└──────────────────────────────────────────────────────
    TOTAL:               CPU: 1.5 cores  │ RAM: 1.8GB

Disk Usage:
├── PostgreSQL Data: ~5GB
├── Container Images: ~1GB
└── TOTAL: ~6GB
```

---

## Access Summary

### Web URLs (External)
```
┌──────────────────────────────────────────────────────┐
│  http://37.27.97.75:10300                            │
│  AEGIS UI Dashboard                                  │
└──────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────┐
│  http://37.27.97.75:10800                            │
│  AEGIS Backend API                                   │
└──────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────┐
│  http://37.27.97.75:10800/docs                       │
│  Interactive API Documentation (Swagger UI)          │
└──────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────┐
│  http://37.27.97.75:10080                            │
│  MCP Server (Claude Desktop Integration)             │
└──────────────────────────────────────────────────────┘
```

### Database Access
```
psql -h 37.27.97.75 -p 15432 -U aegis -d aegis_certify_dev
```

### Redis Access
```
redis-cli -h 37.27.97.75 -p 16379
```

---

## Security Boundaries

```
┌──────────────────────────────────────────────────────┐
│  ISOLATION BOUNDARIES                                │
├──────────────────────────────────────────────────────┤
│  1. Network Isolation                                │
│     - Dedicated Docker bridge network                │
│     - No connections to InferLoop networks           │
│     - Internal DNS resolution only                   │
│                                                      │
│  2. Database Isolation                               │
│     - Separate PostgreSQL instance                   │
│     - Unique database: aegis_certify_dev             │
│     - No shared tables with other products           │
│                                                      │
│  3. Cache Isolation                                  │
│     - Separate Redis instance                        │
│     - Namespaced keys (aegis:*)                      │
│     - No key collisions                              │
│                                                      │
│  4. Process Isolation                                │
│     - Each service in separate container             │
│     - Resource limits (CPU, memory)                  │
│     - Non-root users where possible                  │
│                                                      │
│  5. Data Isolation                                   │
│     - Dedicated volumes                              │
│     - No volume sharing with other products          │
│     - Encrypted at rest (optional, production)       │
└──────────────────────────────────────────────────────┘
```

---

**Created:** 2026-04-21
**Server:** 37.27.97.75
**Status:** ✅ Running and Accessible
