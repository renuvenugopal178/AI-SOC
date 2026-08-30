import { Request } from 'express';
import SecurityEvent, { SecurityEventSeverity } from '../models/SecurityEvent';
import { evaluateSecurityEvent } from '../services/detectionEngine';

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
    const event = await SecurityEvent.create({
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

    await evaluateSecurityEvent(event.toObject());
  } catch (error) {
    console.error('Unable to record security event:', error);
  }
};