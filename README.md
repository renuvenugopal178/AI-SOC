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

The initial scaffold is in place and the base health endpoints for the backend and ML service are implemented. The frontend displays a professional system status page. MongoDB runs in Docker. This project is intentionally limited to a working baseline and does not yet include event ingestion, anomaly detection, RBAC, or advanced SOC workflows.

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
