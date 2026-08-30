import { z } from 'zod';

export const sanitizeMetadata = (metadata: Record<string, unknown> = {}): Record<string, unknown> => {
  const SENSITIVE_KEYS = new Set([
    'password',
    'passwordhash',
    'password_hash',
    'token',
    'jwt',
    'secret',
    'authorization',
    'auth_token',
    'accesstoken',
    'access_token',
    'refreshtoken',
    'refresh_token',
    'apikey',
    'api_key',
    'privatekey',
    'private_key',
  ]);

  if (!metadata || typeof metadata !== 'object' || Array.isArray(metadata)) {
    return {};
  }

  const clean: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(metadata)) {
    if (SENSITIVE_KEYS.has(key.toLowerCase())) {
      clean[key] = '[REDACTED]';
    } else if (typeof value === 'object' && value !== null && !Array.isArray(value)) {
      clean[key] = sanitizeMetadata(value as Record<string, unknown>);
    } else {
      clean[key] = value;
    }
  }
  return clean;
};

export const securityEventSchema = z.object({
  timestamp: z.coerce.date({
    invalid_type_error: 'timestamp must be a valid ISO date string.',
  }).optional().default(() => new Date()),
  source: z.string({ required_error: 'source is required.' }).trim().min(1, 'source cannot be empty.').max(128),
  eventType: z.string({ required_error: 'eventType is required.' }).trim().min(1, 'eventType cannot be empty.').max(128).transform((value) => value.toUpperCase()),
  severity: z.enum(['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'], {
    errorMap: () => ({ message: 'severity must be one of: LOW, MEDIUM, HIGH, CRITICAL.' }),
  }),
  sourceIp: z.string().trim().ip().optional().nullable().or(z.literal('')).transform((value) => (!value ? undefined : value)),
  destinationIp: z.string().trim().ip().optional().nullable().or(z.literal('')).transform((value) => (!value ? undefined : value)),
  sourcePort: z.number().int().min(1).max(65535).optional().nullable().transform((value) => (value === null ? undefined : value)),
  destinationPort: z.number().int().min(1).max(65535).optional().nullable().transform((value) => (value === null ? undefined : value)),
  protocol: z.string().trim().min(1).max(16).optional().nullable().transform((value) => (!value ? undefined : value.toUpperCase())),
  username: z.string().trim().min(1).max(64).optional().nullable().transform((value) => (!value ? undefined : value)),
  action: z.string().trim().min(1).max(128).optional().nullable().transform((value) => (!value ? undefined : value)),
  message: z.string().trim().min(1).max(4000).optional().nullable().transform((value) => (!value ? undefined : value)),
  metadata: z.record(z.any()).optional().nullable().transform((value) => sanitizeMetadata(value ?? {})),
});

export const sanitizeSecurityEvent = (event: Record<string, any>) => ({
  id: event._id?.toString?.() ?? event.id,
  timestamp: event.timestamp,
  source: event.source,
  eventType: event.eventType,
  severity: event.severity,
  sourceIp: event.sourceIp ?? undefined,
  destinationIp: event.destinationIp ?? undefined,
  sourcePort: event.sourcePort ?? undefined,
  destinationPort: event.destinationPort ?? undefined,
  protocol: event.protocol ?? undefined,
  username: event.username ?? undefined,
  action: event.action ?? undefined,
  message: event.message ?? undefined,
  metadata: sanitizeMetadata(event.metadata ?? {}),
  createdAt: event.createdAt,
  updatedAt: event.updatedAt,
});

export const sanitizeViewerSecurityEvent = (event: Record<string, any>) => ({
  id: event._id?.toString?.() ?? event.id,
  timestamp: event.timestamp,
  source: event.source,
  eventType: event.eventType,
  severity: event.severity,
  protocol: event.protocol ?? undefined,
  username: event.username ?? undefined,
  action: event.action ?? undefined,
  message: event.message ?? undefined,
  metadata: sanitizeMetadata(event.metadata ?? {}),
  createdAt: event.createdAt,
  updatedAt: event.updatedAt,
});
