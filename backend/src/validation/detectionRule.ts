import { z } from 'zod';

export const detectionRuleConditionSchema = z.object({
  field: z.string().trim().min(1).max(128),
  operator: z.enum(['EQUALS', 'NOT_EQUALS', 'CONTAINS', 'STARTS_WITH', 'GREATER_THAN', 'LESS_THAN']),
  value: z.union([z.string(), z.number(), z.boolean(), z.null()]).optional(),
  threshold: z.number().int().min(1).optional(),
  windowMinutes: z.number().int().min(1).optional(),
}).passthrough();

export const detectionRuleSchema = z.object({
  name: z.string().trim().min(1).max(128),
  description: z.string().trim().min(1).max(2000).optional().or(z.literal('')).transform((value) => value === '' ? undefined : value),
  ruleType: z.enum(['EVENT_MATCH', 'THRESHOLD']),
  severity: z.enum(['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']),
  enabled: z.boolean().default(true),
  riskScore: z.number().min(0).max(100),
  conditions: detectionRuleConditionSchema,
  createdBy: z.string().trim().min(1).max(128).optional(),
}).passthrough();

export const sanitizeDetectionRule = (rule: Record<string, any>) => ({
  id: rule._id?.toString?.() ?? rule.id,
  name: rule.name,
  description: rule.description,
  ruleType: rule.ruleType,
  enabled: rule.enabled,
  severity: rule.severity,
  riskScore: rule.riskScore,
  conditions: rule.conditions ?? {},
  createdBy: rule.createdBy,
  createdAt: rule.createdAt,
  updatedAt: rule.updatedAt,
});

export const sanitizeAlert = (alert: Record<string, any>) => ({
  id: alert._id?.toString?.() ?? alert.id,
  ruleId: alert.ruleId?.toString?.() ?? alert.ruleId,
  eventId: alert.eventId?.toString?.() ?? alert.eventId,
  title: alert.title,
  description: alert.description,
  severity: alert.severity,
  riskScore: alert.riskScore,
  status: alert.status,
  source: alert.source,
  eventType: alert.eventType,
  sourceIp: alert.sourceIp,
  username: alert.username,
  triggeredAt: alert.triggeredAt,
  metadata: alert.metadata ?? {},
  createdAt: alert.createdAt,
  updatedAt: alert.updatedAt,
});
