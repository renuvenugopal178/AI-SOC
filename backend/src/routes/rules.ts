import { Router, Response } from 'express';
import { Types } from 'mongoose';
import DetectionRule from '../models/DetectionRule';
import AuditLog from '../models/AuditLog';
import { authenticate, AuthenticatedRequest, requireRole } from '../middleware/auth';
import { detectionRuleSchema, sanitizeDetectionRule } from '../validation/detectionRule';

const router = Router();

router.post('/', authenticate, requireRole('ADMIN'), async (req: AuthenticatedRequest, res: Response) => {
  try {
    const parsed = detectionRuleSchema.safeParse(req.body);

    if (!parsed.success) {
      await AuditLog.create({
        userId: req.user?.userId ? new Types.ObjectId(req.user.userId) : undefined,
        action: 'RULE_CREATION_FAILURE',
        success: false,
        ipAddress: req.ip,
        metadata: {
          reason: 'invalid_rule_payload',
          details: parsed.error.flatten(),
        },
      });

      res.status(400).json({
        error: 'Invalid detection rule data.',
        details: parsed.error.flatten(),
      });
      return;
    }

    const payload = {
      ...parsed.data,
      createdBy: req.user?.username || req.user?.email || 'system',
    };

    const rule = await DetectionRule.create(payload);

    await AuditLog.create({
      userId: req.user?.userId ? new Types.ObjectId(req.user.userId) : undefined,
      action: 'RULE_CREATION_SUCCESS',
      success: true,
      ipAddress: req.ip,
      metadata: {
        ruleId: rule._id.toString(),
        ruleName: rule.name,
        severity: rule.severity,
      },
    });

    res.status(201).json({
      message: 'Detection rule created successfully.',
      rule: sanitizeDetectionRule(rule.toObject()),
    });
  } catch (error) {
    await AuditLog.create({
      userId: req.user?.userId ? new Types.ObjectId(req.user.userId) : undefined,
      action: 'RULE_CREATION_FAILURE',
      success: false,
      ipAddress: req.ip,
      metadata: {
        reason: 'rule_creation_exception',
        error: error instanceof Error ? error.message : 'Unknown error',
      },
    });

    res.status(500).json({ error: 'Unable to create detection rule.' });
  }
});

router.get('/', authenticate, requireRole('ADMIN', 'SOC_ANALYST', 'VIEWER'), async (req: AuthenticatedRequest, res: Response) => {
  try {
    const page = Math.max(1, Number(req.query.page) || 1);
    const limit = Math.min(100, Math.max(1, Number(req.query.limit) || 20));
    const skip = (page - 1) * limit;

    const [rules, total] = await Promise.all([
      DetectionRule.find({})
        .sort({ createdAt: -1 })
        .skip(skip)
        .limit(limit)
        .lean(),
      DetectionRule.countDocuments(),
    ]);

    res.status(200).json({
      rules: rules.map((rule) => sanitizeDetectionRule(rule)),
      page,
      limit,
      total,
      totalPages: total === 0 ? 0 : Math.ceil(total / limit),
    });
  } catch (error) {
    res.status(500).json({ error: 'Unable to retrieve detection rules.' });
  }
});

router.get('/:id', authenticate, requireRole('ADMIN', 'SOC_ANALYST', 'VIEWER'), async (req: AuthenticatedRequest, res: Response) => {
  try {
    const rule = await DetectionRule.findById(req.params.id).lean();

    if (!rule) {
      res.status(404).json({ error: 'Detection rule not found.' });
      return;
    }

    res.status(200).json({ rule: sanitizeDetectionRule(rule) });
  } catch (error) {
    res.status(500).json({ error: 'Unable to retrieve detection rule.' });
  }
});

router.patch('/:id', authenticate, requireRole('ADMIN'), async (req: AuthenticatedRequest, res: Response) => {
  try {
    const parsed = detectionRuleSchema.partial().safeParse(req.body);

    if (!parsed.success) {
      res.status(400).json({
        error: 'Invalid detection rule update payload.',
        details: parsed.error.flatten(),
      });
      return;
    }

    const rule = await DetectionRule.findByIdAndUpdate(
      req.params.id,
      {
        ...parsed.data,
        updatedAt: new Date(),
      },
      { new: true }
    );

    if (!rule) {
      res.status(404).json({ error: 'Detection rule not found.' });
      return;
    }

    await AuditLog.create({
      userId: req.user?.userId ? new Types.ObjectId(req.user.userId) : undefined,
      action: 'RULE_UPDATE_SUCCESS',
      success: true,
      ipAddress: req.ip,
      metadata: {
        ruleId: rule._id.toString(),
        ruleName: rule.name,
      },
    });

    res.status(200).json({
      message: 'Detection rule updated successfully.',
      rule: sanitizeDetectionRule(rule.toObject()),
    });
  } catch (error) {
    res.status(500).json({ error: 'Unable to update detection rule.' });
  }
});

router.delete('/:id', authenticate, requireRole('ADMIN'), async (req: AuthenticatedRequest, res: Response) => {
  try {
    const rule = await DetectionRule.findByIdAndDelete(req.params.id);

    if (!rule) {
      res.status(404).json({ error: 'Detection rule not found.' });
      return;
    }

    await AuditLog.create({
      userId: req.user?.userId ? new Types.ObjectId(req.user.userId) : undefined,
      action: 'RULE_DELETION_SUCCESS',
      success: true,
      ipAddress: req.ip,
      metadata: {
        ruleId: rule._id.toString(),
        ruleName: rule.name,
      },
    });

    res.status(200).json({
      message: 'Detection rule deleted successfully.',
      ruleId: rule._id.toString(),
    });
  } catch (error) {
    res.status(500).json({ error: 'Unable to delete detection rule.' });
  }
});

export default router;
