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
