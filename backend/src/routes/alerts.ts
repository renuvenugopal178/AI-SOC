import { Router, Response } from 'express';
import Alert from '../models/Alert';
import { authenticate, AuthenticatedRequest, requireRole } from '../middleware/auth';
import { sanitizeAlert } from '../validation/detectionRule';

const router = Router();

router.get('/', authenticate, requireRole('ADMIN', 'SOC_ANALYST', 'VIEWER'), async (req: AuthenticatedRequest, res: Response) => {
  try {
    const page = Math.max(1, Number(req.query.page) || 1);
    const limit = Math.min(100, Math.max(1, Number(req.query.limit) || 20));
    const skip = (page - 1) * limit;

    const status = typeof req.query.status === 'string' ? req.query.status : undefined;
    const severity = typeof req.query.severity === 'string' ? req.query.severity : undefined;
    const source = typeof req.query.source === 'string' ? req.query.source : undefined;
    const eventType = typeof req.query.eventType === 'string' ? req.query.eventType : undefined;

    const filter: Record<string, unknown> = {};
    if (status) filter.status = status;
    if (severity) filter.severity = severity;
    if (source) filter.source = source;
    if (eventType) filter.eventType = eventType;

    const [alerts, total] = await Promise.all([
      Alert.find(filter)
        .sort({ triggeredAt: -1, createdAt: -1 })
        .skip(skip)
        .limit(limit)
        .lean(),
      Alert.countDocuments(filter),
    ]);

    const sanitizedAlerts = alerts.map((alert) => sanitizeAlert(alert));

    res.status(200).json({
      alerts: sanitizedAlerts,
      page,
      limit,
      total,
      totalPages: total === 0 ? 0 : Math.ceil(total / limit),
    });
  } catch (error) {
    res.status(500).json({ error: 'Unable to retrieve alerts.' });
  }
});

router.get('/:id', authenticate, requireRole('ADMIN', 'SOC_ANALYST', 'VIEWER'), async (req: AuthenticatedRequest, res: Response) => {
  try {
    const alert = await Alert.findById(req.params.id).lean();

    if (!alert) {
      res.status(404).json({ error: 'Alert not found.' });
      return;
    }

    res.status(200).json({ alert: sanitizeAlert(alert) });
  } catch (error) {
    res.status(500).json({ error: 'Unable to retrieve alert.' });
  }
});

export default router;
