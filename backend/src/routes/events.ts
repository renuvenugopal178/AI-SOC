import { Router, Response } from 'express';
import SecurityEvent from '../models/SecurityEvent';
import AuditLog from '../models/AuditLog';
import { authenticate, AuthenticatedRequest, requireRole } from '../middleware/auth';
import { sanitizeSecurityEvent, sanitizeViewerSecurityEvent, securityEventSchema } from '../validation/securityEvent';
import { evaluateSecurityEvent } from '../services/detectionEngine';

const router = Router();

const normalizeEventInput = (input: Record<string, any>) => {
  const normalized = { ...input };

  if (typeof normalized.source === 'string') {
    normalized.source = normalized.source.trim();
  }

  if (typeof normalized.eventType === 'string') {
    normalized.eventType = normalized.eventType.trim().toUpperCase();
  }

  if (typeof normalized.severity === 'string') {
    normalized.severity = normalized.severity.toUpperCase();
  }

  if (typeof normalized.protocol === 'string') {
    normalized.protocol = normalized.protocol.trim().toUpperCase();
  }

  if (typeof normalized.username === 'string') {
    normalized.username = normalized.username.trim();
  }

  if (typeof normalized.action === 'string') {
    normalized.action = normalized.action.trim();
  }

  if (typeof normalized.message === 'string') {
    normalized.message = normalized.message.trim();
  }

  if (normalized.metadata === undefined || normalized.metadata === null) {
    normalized.metadata = {};
  }

  return normalized;
};

const createAuditFailure = async (req: AuthenticatedRequest, metadata: Record<string, unknown>) => {
  await AuditLog.create({
    userId: req.user?.userId ? req.user.userId : undefined,
    action: 'EVENT_INGESTION_FAILURE',
    success: false,
    ipAddress: req.ip,
    metadata,
  });
};

router.post('/', authenticate, requireRole('ADMIN', 'SOC_ANALYST'), async (req: AuthenticatedRequest, res: Response) => {
  try {
    const parsed = securityEventSchema.safeParse(req.body);

    if (!parsed.success) {
      await createAuditFailure(req, {
        reason: 'invalid_event_payload',
        details: parsed.error.flatten(),
      });

      res.status(400).json({
        error: 'Invalid security event data.',
        details: parsed.error.flatten(),
      });
      return;
    }

    const normalized = normalizeEventInput(parsed.data);
    const event = await SecurityEvent.create(normalized);

    let generatedAlerts: any[] = [];

    try {
      generatedAlerts = await evaluateSecurityEvent(event.toObject());
    } catch (evaluationError) {
      await AuditLog.create({
        userId: req.user?.userId,
        action: 'DETECTION_EVALUATION_FAILURE',
        success: false,
        ipAddress: req.ip,
        metadata: {
          eventId: event._id.toString(),
          reason: 'detection_engine_failed',
          error: evaluationError instanceof Error ? evaluationError.message : 'Unknown error',
        },
      });
    }

    await AuditLog.create({
      userId: req.user?.userId,
      action: 'EVENT_INGESTION_SUCCESS',
      success: true,
      ipAddress: req.ip,
      metadata: {
        eventId: event._id.toString(),
        eventType: event.eventType,
        source: event.source,
        severity: event.severity,
        authenticatedUserId: req.user?.userId,
        alertsGenerated: generatedAlerts.length,
      },
    });

    res.status(201).json({
      message: 'Security event ingested successfully.',
      event: sanitizeSecurityEvent(event.toObject()),
      alerts: generatedAlerts,
    });
  } catch (error) {
    await createAuditFailure(req, {
      reason: 'event_ingestion_exception',
      error: error instanceof Error ? error.message : 'Unknown error',
    });

    res.status(500).json({ error: 'Unable to ingest security event.' });
  }
});

router.get('/', authenticate, requireRole('ADMIN', 'SOC_ANALYST', 'VIEWER'), async (req: AuthenticatedRequest, res: Response) => {
  try {
    const page = Math.max(1, Number(req.query.page) || 1);
    const limit = Math.min(100, Math.max(1, Number(req.query.limit) || 20));
    const skip = (page - 1) * limit;

    const [events, total] = await Promise.all([
      SecurityEvent.find({})
        .sort({ timestamp: -1, createdAt: -1 })
        .skip(skip)
        .limit(limit)
        .lean(),
      SecurityEvent.countDocuments(),
    ]);

    const totalPages = total === 0 ? 0 : Math.ceil(total / limit);
    const sanitizedEvents = (req.user?.role === 'VIEWER'
      ? events.map((event) => sanitizeViewerSecurityEvent(event))
      : events.map((event) => sanitizeSecurityEvent(event))
    );

    res.status(200).json({
      events: sanitizedEvents,
      page,
      limit,
      total,
      totalPages,
    });
  } catch (error) {
    res.status(500).json({ error: 'Unable to retrieve security events.' });
  }
});

export default router;
