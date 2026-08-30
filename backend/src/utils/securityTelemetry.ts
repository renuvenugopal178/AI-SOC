import { Request } from 'express';
import SecurityEvent, { SecurityEventSeverity } from '../models/SecurityEvent';

interface SecurityTelemetryInput {
  eventType: string;
  severity: SecurityEventSeverity;
  action: string;
  message: string;
  username?: string;
  metadata?: Record<string, unknown>;
}

export const recordSecurityEvent = async (req: Request, input: SecurityTelemetryInput): Promise<void> => {
  try {
    await SecurityEvent.create({
      timestamp: new Date(),
      source: 'auth-service',
      eventType: input.eventType,
      severity: input.severity,
      sourceIp: req.ip,
      username: input.username,
      action: input.action,
      message: input.message,
      metadata: {
        method: req.method,
        path: req.path,
        userAgent: req.get('user-agent'),
        ...input.metadata,
      },
    });
  } catch (error) {
    console.error('Unable to record security event:', error);
  }
};