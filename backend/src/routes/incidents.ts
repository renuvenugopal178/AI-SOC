import { Router, Response } from 'express';
import Incident, { IncidentStatus } from '../models/Incident';
import { authenticate, AuthenticatedRequest, requireRole } from '../middleware/auth';
import { publishRealtimeEvent } from '../services/realtimeService';

const router = Router();
const incidentStatuses: IncidentStatus[] = ['NEW', 'INVESTIGATING', 'RESOLVED', 'FALSE_POSITIVE'];

router.get('/', authenticate, requireRole('ADMIN', 'SOC_ANALYST', 'VIEWER'), async (req: AuthenticatedRequest, res: Response) => {
  try {
    const page = Math.max(1, Number(req.query.page) || 1);
    const limit = Math.min(100, Math.max(1, Number(req.query.limit) || 20));
    const filter: Record<string, unknown> = {};

    if (typeof req.query.status === 'string' && incidentStatuses.includes(req.query.status as IncidentStatus)) {
      filter.status = req.query.status;
    }

    const [incidents, total] = await Promise.all([
      Incident.find(filter).sort({ lastSeen: -1, createdAt: -1 }).skip((page - 1) * limit).limit(limit).lean(),
      Incident.countDocuments(filter),
    ]);

    res.status(200).json({
      incidents,
      page,
      limit,
      total,
      totalPages: total === 0 ? 0 : Math.ceil(total / limit),
    });
  } catch (error) {
    res.status(500).json({ error: 'Unable to retrieve incidents.' });
  }
});

router.get('/:id', authenticate, requireRole('ADMIN', 'SOC_ANALYST', 'VIEWER'), async (req: AuthenticatedRequest, res: Response) => {
  try {
    const incident = await Incident.findById(req.params.id).lean();

    if (!incident) {
      res.status(404).json({ error: 'Incident not found.' });
      return;
    }

    res.status(200).json({ incident });
  } catch (error) {
    res.status(500).json({ error: 'Unable to retrieve incident.' });
  }
});

router.patch('/:id/status', authenticate, requireRole('ADMIN', 'SOC_ANALYST'), async (req: AuthenticatedRequest, res: Response) => {
  const status = req.body?.status;

  if (!incidentStatuses.includes(status)) {
    res.status(400).json({ error: 'Invalid incident status.' });
    return;
  }

  try {
    const currentIncident = await Incident.findById(req.params.id).lean();
    if (!currentIncident) {
      res.status(404).json({ error: 'Incident not found.' });
      return;
    }

    if (currentIncident.status === status) {
      res.status(200).json({ incident: currentIncident });
      return;
    }

    const incident = await Incident.findByIdAndUpdate(
      req.params.id,
      { status },
      { new: true, runValidators: true }
    ).lean();

    if (!incident) {
      res.status(404).json({ error: 'Incident not found.' });
      return;
    }

    publishRealtimeEvent('INCIDENT_UPDATED', {
      incidentId: incident._id.toString(),
      severity: incident.severity,
      riskScore: incident.riskScore,
      status: incident.status,
    });
    res.status(200).json({ incident });
  } catch (error) {
    res.status(500).json({ error: 'Unable to update incident status.' });
  }
});

export default router;
