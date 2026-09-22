# AI-SOC Backend

The backend provides the API layer for the AI-SOC platform.

## Scripts

```bash
npm install
npm run dev
npm run build
npm start
```

## Environment

Copy `.env.example` to `.env` and update the values for your environment.
`ML_SERVICE_URL` defaults to `http://localhost:8001`, and `ML_ANOMALY_THRESHOLD` defaults to `0.65`. ML scoring is advisory: service failures do not block event ingestion or rule-based detection. Qualifying anomaly alerts use the existing alert and incident workflows and are deduplicated per event.

## Real-time updates

Authenticated SOC clients can subscribe to `GET /api/realtime/events` with a Bearer JWT. `ADMIN`, `SOC_ANALYST`, and `VIEWER` roles are allowed. The SSE stream emits `SECURITY_EVENT_CREATED`, `ALERT_CREATED`, `INCIDENT_CREATED`, and `INCIDENT_UPDATED` notifications containing only identifiers and safe summary fields. Heartbeats keep idle connections open, and disconnected clients are cleaned up. The frontend reconnects automatically and continues to support normal API refreshes when realtime delivery is unavailable.

## Local simulator authentication

Set `NODE_ENV=development` and `LOCAL_SIMULATOR_AUTH=true` in the backend environment. When `AUTH_TOKEN` and credential variables are absent, `npm run simulate` creates or reuses the ignored `backend/.local-simulator-secret`, calls `POST /api/auth/local-simulator-token` over loopback, and receives a normal 8-hour JWT for an existing active `ADMIN` or `SOC_ANALYST` account. Telemetry is still submitted to the authenticated ingestion endpoint and follows rule detection, ML scoring, alerting, incident correlation, and SSE publication normally.

For alert-producing local scenarios, run `npm run seed-rules` once. The command is idempotent and does not clear existing data.

The local token endpoint returns `404` unless development mode and the explicit feature flag are enabled, requires the generated secret, accepts loopback connections only, and never works as a production authentication mechanism. It does not expose passwords, JWTs in logs, or sensitive user data.

## Database environments

- Development: `ai-soc`, configured by `backend/.env`.
- Tests: `ai-soc-test`, forcibly configured by `src/tests/setup.ts` and checked by `databaseIsolation.test.ts`.
- Production: configure a separate production URI and set `NODE_ENV=production`; the local simulator endpoint is disabled.

## Health check

```http
GET /api/health
```

Returns:

```json
{
  "status": "ok",
  "service": "AI-SOC Backend"
}
```
