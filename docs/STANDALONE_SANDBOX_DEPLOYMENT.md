# AEGIS Certify - Standalone Sandbox Deployment Guide

## Overview

This guide shows how to deploy AEGIS Certify in a completely isolated sandbox environment with zero dependencies on InferLoop infrastructure.

---

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│  AEGIS Standalone Sandbox                                │
│  Isolated Docker Network + K3s Namespace (Optional)      │
└─────────────────────────────────────────────────────────┘

Components:
- AEGIS Backend API (FastAPI)      → http://sandbox.aegis:10800
- AEGIS UI Dashboard (React)       → http://sandbox.aegis:10300
- PostgreSQL (dedicated)           → Internal: 5432, External: 15432
- Redis (dedicated)                → Internal: 6379, External: 16379
- MCP Server (optional)            → http://sandbox.aegis:10080
- Nginx Reverse Proxy (optional)   → https://aegis-sandbox.inferloop.com
```

---

## Prerequisites

### Option 1: Docker Compose (Simplest)
- Docker Engine 24+
- Docker Compose v2
- 4GB RAM, 10GB disk

### Option 2: K3s on inferloop2 (Production-like)
- K3s cluster access
- kubectl configured
- 8GB RAM, 20GB disk

---

## Deployment Steps

### Step 1: Copy AEGIS Repository

```bash
# On target sandbox server (e.g., inferloop2)
cd /opt/sandboxes  # or ~/sandboxes

# Clone AEGIS repo
git clone https://github.com/inferloop/inferloop-aegis-certify.git aegis-sandbox
cd aegis-sandbox

# Checkout stable branch
git checkout main  # or specific tag
```

**What's Included:**
- ✅ All source code (`src/aegis_certify/`)
- ✅ UI code (`ui/`)
- ✅ Docker configs (`infra/docker/`)
- ✅ K8s manifests (`infra/kubernetes/`)
- ✅ Documentation (`docs/`)

**What's NOT Needed:**
- ❌ No InferLoop dependencies
- ❌ No shared databases
- ❌ No registry synchronization

---

### Step 2: Deploy with Docker Compose (Recommended for Sandbox)

#### 2a. Create Environment File

```bash
cd infra/docker

# Create .env file
cat > .env.sandbox <<EOF
# Database
POSTGRES_PASSWORD=aegis_sandbox_secure_$(openssl rand -hex 16)
DATABASE_URL=postgresql://aegis:REPLACE_PASSWORD@postgres:5432/aegis_certify_sandbox

# Redis
REDIS_URL=redis://redis:6379/0

# API Configuration
API_HOST=0.0.0.0
API_PORT=8000
SECRET_KEY=$(openssl rand -hex 32)

# CORS (adjust for your sandbox domain)
CORS_ORIGINS=http://localhost:10300,http://sandbox.aegis.inferloop.com

# Logging
LOG_LEVEL=INFO

# Features
ENABLE_TRACING=true
ENABLE_METRICS=true
EOF

# Replace REPLACE_PASSWORD in .env.sandbox
sed -i "s/REPLACE_PASSWORD/$(grep POSTGRES_PASSWORD .env.sandbox | cut -d= -f2)/" .env.sandbox
```

#### 2b. Launch Sandbox Stack

```bash
# Start all services (detached)
docker compose -f docker-compose.dev.yml --env-file .env.sandbox up -d

# Check status
docker compose -f docker-compose.dev.yml ps

# View logs
docker compose -f docker-compose.dev.yml logs -f
```

#### 2c. Verify Services

```bash
# Backend health
curl http://localhost:10800/health
# Expected: {"status":"ok","service":"aegis-certify","version":"0.1.0"}

# UI
curl -I http://localhost:10300
# Expected: HTTP/1.1 200 OK

# PostgreSQL
psql -h localhost -p 15432 -U aegis -d aegis_certify_sandbox
# Password from .env.sandbox

# Redis
redis-cli -h localhost -p 16379 ping
# Expected: PONG
```

---

### Step 3: Deploy with K3s (Production Sandbox)

#### 3a. Create Namespace

```bash
kubectl create namespace aegis-sandbox

# Label for easy identification
kubectl label namespace aegis-sandbox env=sandbox product=aegis
```

#### 3b. Create Secrets

```bash
cd infra/kubernetes

# Copy template
cp secrets.yaml.template secrets-sandbox.yaml

# Generate secrets
cat > secrets-sandbox.yaml <<EOF
apiVersion: v1
kind: Secret
metadata:
  name: aegis-secrets
  namespace: aegis-sandbox
type: Opaque
stringData:
  POSTGRES_PASSWORD: "$(openssl rand -hex 16)"
  SECRET_KEY: "$(openssl rand -hex 32)"
  DATABASE_URL: "postgresql://aegis:REPLACE_PW@aegis-postgres:5432/aegis_certify_sandbox"
EOF

# Replace REPLACE_PW
PW=$(grep POSTGRES_PASSWORD secrets-sandbox.yaml | awk '{print $2}' | tr -d '"')
sed -i "s/REPLACE_PW/$PW/" secrets-sandbox.yaml

# Apply
kubectl apply -f secrets-sandbox.yaml
```

#### 3c. Deploy Components

```bash
# Apply namespace
kubectl apply -f namespace.yaml

# ConfigMap (edit CORS_ORIGINS first)
kubectl apply -f configmap.yaml -n aegis-sandbox

# Secrets (already applied)

# PostgreSQL
kubectl apply -f postgres-statefulset.yaml -n aegis-sandbox

# Redis
kubectl apply -f redis-deployment.yaml -n aegis-sandbox

# Wait for DB to be ready
kubectl wait --for=condition=ready pod -l app=aegis-postgres -n aegis-sandbox --timeout=120s

# Backend
kubectl apply -f backend-deployment.yaml -n aegis-sandbox

# UI
kubectl apply -f ui-deployment.yaml -n aegis-sandbox

# Ingress (optional, for external access)
kubectl apply -f ingress.yaml -n aegis-sandbox
```

#### 3d. Verify K3s Deployment

```bash
# Check all pods
kubectl get pods -n aegis-sandbox

# Check services
kubectl get svc -n aegis-sandbox

# Check ingress
kubectl get ingress -n aegis-sandbox

# Port forward for testing
kubectl port-forward -n aegis-sandbox svc/aegis-backend 10800:8000 &
kubectl port-forward -n aegis-sandbox svc/aegis-ui 10300:3000 &

# Test
curl http://localhost:10800/health
```

---

## Resource Requirements

### Docker Compose Deployment

| Service | CPU | Memory | Disk |
|---------|-----|--------|------|
| Backend | 0.5 core | 512MB | - |
| UI | 0.2 core | 256MB | - |
| PostgreSQL | 0.5 core | 512MB | 5GB |
| Redis | 0.1 core | 256MB | 1GB |
| **Total** | **1.3 cores** | **1.5GB** | **6GB** |

### K3s Deployment (with HPA)

| Service | Min Replicas | Max Replicas | CPU/Pod | Memory/Pod |
|---------|--------------|--------------|---------|------------|
| Backend | 2 | 10 | 500m | 512Mi |
| UI | 2 | 5 | 200m | 256Mi |
| PostgreSQL | 1 | 1 | 1000m | 1Gi |
| Redis | 1 | 1 | 200m | 256Mi |

---

## Access URLs

### Local Development (Docker Compose)

- **Backend API:** http://localhost:10800
- **API Docs:** http://localhost:10800/docs
- **UI Dashboard:** http://localhost:10300
- **PostgreSQL:** localhost:15432
- **Redis:** localhost:16379

### Network Access (Docker Compose)

```bash
# Get server IP
SERVER_IP=$(hostname -I | awk '{print $1}')
echo "Access UI at: http://$SERVER_IP:10300"
echo "Access API at: http://$SERVER_IP:10800"
```

### K3s with Ingress

```bash
# Get ingress IP
kubectl get ingress -n aegis-sandbox

# Add to /etc/hosts or DNS:
# 37.27.97.75  aegis-sandbox.inferloop.com
# 37.27.97.75  api.aegis-sandbox.inferloop.com
```

- **UI:** https://aegis-sandbox.inferloop.com
- **API:** https://api.aegis-sandbox.inferloop.com
- **Docs:** https://api.aegis-sandbox.inferloop.com/docs

---

## Data Independence

### Database Schema (Auto-created)

AEGIS creates its own tables:
- `certifications` - Certification records
- `pcu_results` - PCU evaluation results
- `gate_evaluations` - Gate decisions
- `audit_logs` - Tamper-evident audit trail
- `evidence_store` - Evidence submissions
- `action_intercept_log` - Action interception history

**No shared tables with InferLoop products.**

### Redis Key Namespaces

All keys prefixed with `aegis:`
- `aegis:cai:*` - CAI score cache
- `aegis:gate:*` - Gate evaluation cache
- `aegis:ratelimit:*` - Rate limiting
- `aegis:session:*` - Session data

**No key collisions with InferLoop.**

---

## Isolation Verification

### Network Isolation (Docker)

```bash
# Check network
docker network inspect docker_aegis-dev

# Verify no connections to InferLoop networks
docker network ls | grep aegis
# Should only show: docker_aegis-dev
```

### Process Isolation (K3s)

```bash
# Check namespace isolation
kubectl get all -n aegis-sandbox

# Verify no dependencies on other namespaces
kubectl get networkpolicies -n aegis-sandbox
```

---

## Testing Sandbox

### 1. Backend API Test

```bash
# Certify a sample artifact
curl -X POST http://localhost:10800/v1/certify \
  -H "Content-Type: application/json" \
  -d '{
    "artifact_id": "sandbox-test-agent-001",
    "artifact_type": "agent",
    "version": "1.0.0",
    "frameworks": ["langgraph"],
    "metadata": {
      "name": "Test Agent",
      "description": "Sandbox test"
    }
  }'
```

### 2. UI Test

Open browser:
```
http://localhost:10300
```

**Expected:**
- Dark theme dashboard
- Two tabs: "Certification" | "Action Interception"
- CAI score display (large number 0-100)
- 17-gate status grid
- Action interception demo

### 3. Database Test

```bash
psql -h localhost -p 15432 -U aegis -d aegis_certify_sandbox

# List tables
\dt

# Check certifications
SELECT artifact_id, cai_score, decision FROM certifications LIMIT 5;
```

### 4. Integration Test

```bash
# Run full test suite
cd /opt/sandboxes/aegis-sandbox
PYTHONPATH=src pytest tests/integration/ -v
```

---

## Maintenance

### Backup Database

```bash
# Docker Compose
docker exec aegis-postgres-dev pg_dump -U aegis aegis_certify_sandbox > backup-$(date +%Y%m%d).sql

# K3s
kubectl exec -n aegis-sandbox aegis-postgres-0 -- \
  pg_dump -U aegis aegis_certify_sandbox > backup-$(date +%Y%m%d).sql
```

### Update AEGIS

```bash
cd /opt/sandboxes/aegis-sandbox

# Pull latest code
git pull origin main

# Restart (Docker Compose)
docker compose -f infra/docker/docker-compose.dev.yml restart

# Or (K3s)
kubectl rollout restart deployment -n aegis-sandbox
```

### View Logs

```bash
# Docker Compose
docker compose -f docker-compose.dev.yml logs -f backend
docker compose -f docker-compose.dev.yml logs -f ui

# K3s
kubectl logs -f -n aegis-sandbox -l app=aegis-backend
kubectl logs -f -n aegis-sandbox -l app=aegis-ui
```

---

## Cleanup

### Docker Compose

```bash
cd infra/docker

# Stop services
docker compose -f docker-compose.dev.yml down

# Remove volumes (deletes data!)
docker compose -f docker-compose.dev.yml down -v

# Remove images
docker compose -f docker-compose.dev.yml down --rmi all
```

### K3s

```bash
# Delete namespace (deletes everything!)
kubectl delete namespace aegis-sandbox

# Verify cleanup
kubectl get all -n aegis-sandbox
# Expected: No resources found
```

---

## Troubleshooting

### Backend Won't Start

```bash
# Check logs
docker logs aegis-backend-dev --tail 50

# Common issues:
# 1. DB not ready → Wait for postgres health check
# 2. Import error → Check PYTHONPATH in docker-compose
# 3. Port conflict → Change external port mapping
```

### UI Shows Blank Page

```bash
# Check logs
docker logs aegis-ui-dev --tail 50

# Common issues:
# 1. npm install failed → Check node_modules volume
# 2. API URL wrong → Check VITE_API_BASE_URL
# 3. CORS error → Check CORS_ORIGINS in backend
```

### Database Connection Error

```bash
# Test connection
docker exec aegis-backend-dev psql $DATABASE_URL -c "SELECT 1"

# Common issues:
# 1. Wrong password → Check .env.sandbox
# 2. DB not ready → Wait for health check
# 3. Network issue → Check docker network
```

---

## Summary

### What We Copied from InferLoop
- ✅ AEGIS code repository (one-time clone)
- ✅ Nothing else!

### What We Replicated (New Instances)
- ✅ PostgreSQL database (dedicated)
- ✅ Redis cache (dedicated)
- ✅ Nginx (optional reverse proxy)
- ✅ Monitoring (optional Prometheus/Grafana)

### What We DON'T Need
- ❌ InferLoop Registry
- ❌ NATS/Agentic Mesh
- ❌ Shared Keycloak
- ❌ Other product databases
- ❌ Cortex context management

### Result
A completely isolated, self-contained AEGIS Certify sandbox with:
- Zero dependencies on InferLoop infrastructure
- Independent database and cache
- Standalone API and UI
- Full certification and action interception capabilities
- 1.5GB RAM, 6GB disk footprint

---

**Created:** 2026-04-21
**For:** AEGIS Certify Standalone Sandbox Deployment
