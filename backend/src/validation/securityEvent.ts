import { z } from 'zod';

export const securityEventSchema = z.object({
  timestamp: z.coerce.date({
    invalid_type_error: 'timestamp must be a valid ISO date string.',
    required_error: 'timestamp is required.',
  }),
  source: z.string().trim().min(1).max(128),
  eventType: z.string().trim().min(1).max(128).transform((value) => value.toUpperCase()),
  severity: z.enum(['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']),
  sourceIp: z.string().trim().ip().optional().or(z.literal('')).transform((value) => value === '' ? undefined : value),
  destinationIp: z.string().trim().ip().optional().or(z.literal('')).transform((value) => value === '' ? undefined : value),
  sourcePort: z.number().int().min(1).max(65535).optional(),
  destinationPort: z.number().int().min(1).max(65535).optional(),
  protocol: z.string().trim().min(1).max(16).transform((value) => value.toUpperCase()).optional(),
  username: z.string().trim().min(1).max(64).optional(),
  action: z.string().trim().min(1).max(128).optional(),
  message: z.string().trim().min(1).max(4000).optional(),
  metadata: z.record(z.any()).default({}).optional(),
});

export const sanitizeSecurityEvent = (event: Record<string, any>) => ({
  id: event._id?.toString?.() ?? event.id,
  timestamp: event.timestamp,
  source: event.source,
  eventType: event.eventType,
  severity: event.severity,
  sourceIp: event.sourceIp,
  destinationIp: event.destinationIp,
  sourcePort: event.sourcePort,
  destinationPort: event.destinationPort,
  protocol: event.protocol,
  username: event.username,
  action: event.action,
  message: event.message,
  metadata: event.metadata ?? {},
  createdAt: event.createdAt,
  updatedAt: event.updatedAt,
});

export const sanitizeViewerSecurityEvent = (event: Record<string, any>) => ({
  id: event._id?.toString?.() ?? event.id,
  timestamp: event.timestamp,
  source: event.source,
  eventType: event.eventType,
  severity: event.severity,
  protocol: event.protocol,
  username: event.username,
  action: event.action,
  message: event.message,
  metadata: event.metadata ?? {},
  createdAt: event.createdAt,
  updatedAt: event.updatedAt,
});
