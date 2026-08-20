# API Documentation

## Backend

### Health endpoint

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

## ML Service

### Health endpoint

```http
GET /health
```

Returns:

```json
{
  "status": "ok",
  "service": "AI-SOC ML Service"
}
```

## Current status

Only the base health APIs are active.
