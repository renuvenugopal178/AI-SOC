# AI-SOC

AI-SOC is a portfolio-grade Intelligent Security Operations Platform designed to demonstrate modern full-stack engineering, cybersecurity fundamentals, and AI-assisted monitoring workflows.

## Architecture

- React + TypeScript frontend
- Node.js + Express + TypeScript backend
- MongoDB for operational data
- Python + FastAPI ML service

## Technology stack

### Frontend
- React
- TypeScript
- Vite
- Tailwind CSS
- Recharts

### Backend
- Node.js
- Express
- TypeScript
- MongoDB
- Mongoose
- JWT
- bcrypt
- Zod
- Helmet
- CORS
- express-rate-limit

### ML Service
- Python
- FastAPI
- Uvicorn
- scikit-learn
- pandas
- NumPy

### Infrastructure
- Docker
- Docker Compose

## Current status

The platform includes authenticated telemetry ingestion, rule-based detection, alerts, correlation, incident management, and an optional FastAPI Isolation Forest anomaly-assistance service. MongoDB runs in Docker. The ML service is an explainable local prototype and does not block the existing backend pipeline when unavailable.

## Real-time SOC updates

The backend publishes small Server-Sent Events (SSE) notifications after the existing MongoDB-backed telemetry, detection, and incident workflows complete. The frontend keeps its normal API loading and refresh behavior, and refetches the affected views when a notification arrives instead of reloading the page.

### SSE endpoint

```http
GET /api/realtime/events
Authorization: Bearer <JWT>
Accept: text/event-stream
```

The endpoint requires an active authenticated `ADMIN`, `SOC_ANALYST`, or `VIEWER` account. Each connected analyst receives only event identifiers and summary fields needed to refresh the SOC views; passwords, tokens, authorization headers, raw telemetry metadata, and MongoDB details are not broadcast.

### Event types

- `SECURITY_EVENT_CREATED`: a security event was stored.
- `ALERT_CREATED`: a new deduplicated rule or ML alert was stored.
- `INCIDENT_CREATED`: alert correlation created an incident.
- `INCIDENT_UPDATED`: incident risk, severity, related evidence, or analyst status changed.

Connections receive periodic SSE heartbeats, are removed when the client disconnects, and reconnect automatically after a connection loss. The frontend shows `LIVE` or `RECONNECTING`; API polling/manual refresh remains the fallback if the stream is unavailable.

## Local simulator workflow

Development mode enables a loopback-only simulator token endpoint. The simulator creates an ignored local secret file on first use, requests a normal short-lived JWT for the first active `ADMIN` or `SOC_ANALYST` account, and then sends telemetry through the same authenticated `/api/events/ingest` route used by real clients.

With MongoDB, the backend, the ML service, and the frontend running, keep the dashboard open and run:

```bash
cd backend
npm run seed-rules   # one-time setup for alert-producing scenarios
npm run simulate -- --scenario=BRUTE_FORCE
```

No browser token or admin password is required. The endpoint is available only when `NODE_ENV=development` and `LOCAL_SIMULATOR_AUTH=true`, accepts loopback requests only, and is disabled in production. The simulator does not insert alerts or incidents directly. `seed-rules` is idempotent and only creates missing development rules.

Jest forcibly uses the separate `ai-soc-test` database. Development data remains in `ai-soc`; test cleanup operations cannot target it through the test configuration.

## Project structure

- backend/
- frontend/
- ml-service/
- docs/
- tests/

## Setup

### Root environment

Copy the example environment file and adjust values if needed:

```bash
copy .env.example .env
```

### Backend

```bash
cd backend
npm install
npm run dev
```

### Frontend

```bash
cd frontend
npm install
npm run dev -- --host 0.0.0.0
```

### ML service

```bash
cd ml-service
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
uvicorn src.main:app --host 0.0.0.0 --port 8001 --reload
```

### MongoDB

```bash
docker compose up -d
```

## Planned features

- Event and alert ingestion
- Threat detection workflows
- Incident lifecycle management
- Risk scoring and triage
- AI-assisted investigation models
- Extended SOC dashboard

## Notes

This repository is intentionally focused on getting the initial working platform running and verified before building advanced security features.
