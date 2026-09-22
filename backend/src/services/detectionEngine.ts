import mongoose, { Types } from 'mongoose';
import DetectionRule, { DetectionRuleType } from '../models/DetectionRule';
import Alert from '../models/Alert';
import SecurityEvent, { ISecurityEvent } from '../models/SecurityEvent';
import { correlateAlert } from './correlationService';
import { scoreEventForAnomaly } from './mlClient';
import { publishRealtimeEvent } from './realtimeService';

const safeStringValue = (value: unknown): string | undefined => {
  if (typeof value === 'string') return value;
  if (typeof value === 'number' || typeof value === 'boolean') return String(value);
  return undefined;
};

const safeNumberValue = (value: unknown): number | undefined => {
  if (typeof value === 'number' && Number.isFinite(value)) return value;
  return undefined;
};

const compareValues = (left: unknown, operator: string, right: unknown): boolean => {
  const leftString = safeStringValue(left);
  const rightString = safeStringValue(right);
  const leftNumber = safeNumberValue(left);
  const rightNumber = safeNumberValue(right);

  switch (operator) {
    case 'EQUALS':
      return left === right;
    case 'NOT_EQUALS':
      return left !== right;
    case 'CONTAINS':
      return Boolean(leftString && rightString && leftString.includes(rightString));
    case 'STARTS_WITH':
      return Boolean(leftString && rightString && leftString.startsWith(rightString));
    case 'GREATER_THAN':
      if (leftNumber !== undefined && rightNumber !== undefined) return leftNumber > rightNumber;
      if (leftString && rightString) return leftString.localeCompare(rightString) > 0;
      return false;
    case 'LESS_THAN':
      if (leftNumber !== undefined && rightNumber !== undefined) return leftNumber < rightNumber;
      if (leftString && rightString) return leftString.localeCompare(rightString) < 0;
      return false;
    default:
      return false;
  }
};

const evaluatesEventMatchRule = (event: Record<string, any>, rule: Record<string, any>): boolean => {
  const conditions = rule.conditions ?? {};
  const field = conditions.field;
  const operator = conditions.operator;
  const value = conditions.value;

  if (!field || !operator) {
    return false;
  }

  const eventValue = event[field];
  return compareValues(eventValue, operator, value);
};

const evaluatesThresholdRule = async (event: Record<string, any>, rule: Record<string, any>): Promise<boolean> => {
  const conditions = rule.conditions ?? {};
  const field = conditions.field;
  const operator = conditions.operator;
  const value = conditions.value;
  const threshold = Number(conditions.threshold ?? 0);
  const windowMinutes = Number(conditions.windowMinutes ?? 0);

  if (!field || !operator || !threshold || !windowMinutes) {
    return false;
  }

  const eventValue = event[field];
  if (!compareValues(eventValue, operator, value)) {
    return false;
  }

  const cutoff = new Date(event.timestamp ?? Date.now());
  cutoff.setMinutes(cutoff.getMinutes() - windowMinutes);

  const query: Record<string, any> = {
    timestamp: { $gte: cutoff },
    [field]: value,
  };

  // count only matching events within the time window, using MongoDB query instead of in-memory iteration
  const count = await SecurityEvent.countDocuments(query);
  return count >= threshold;
};

const dedupeAlertKey = (ruleId: string, eventId: string): string => `${ruleId}:${eventId}`;

const createAnomalyAlert = async (event: Record<string, any>, anomalyScore: number, modelVersion: string): Promise<any> => {
  const eventId = String(event._id ?? event.id);
  const eventData = await SecurityEvent.findById(eventId).lean();
  const rule = await DetectionRule.findOneAndUpdate(
    { name: 'ML Anomaly Detection' },
    {
      name: 'ML Anomaly Detection',
      description: 'Isolation Forest anomaly-assistance signal.',
      ruleType: 'EVENT_MATCH',
      enabled: true,
      severity: 'HIGH',
      riskScore: Math.round(anomalyScore * 100),
      conditions: { source: 'ml-service', modelVersion },
      createdBy: 'system',
    },
    { upsert: true, new: true, setDefaultsOnInsert: true }
  );

  const alertFilter = { ruleId: rule._id, eventId: new Types.ObjectId(eventId) };
  const existingAlert = await Alert.exists(alertFilter);
  const alert = await Alert.findOneAndUpdate(
    alertFilter,
    {
      ruleId: rule._id,
      eventId: new Types.ObjectId(eventId),
      title: 'ML anomaly detected',
      description: `Isolation Forest identified unusual event behavior (score ${anomalyScore.toFixed(3)}).`,
      severity: 'HIGH',
      riskScore: Math.round(anomalyScore * 100),
      status: 'NEW',
      source: eventData?.source || event.source,
      eventType: eventData?.eventType || event.eventType,
      sourceIp: eventData?.sourceIp || event.sourceIp,
      username: eventData?.username || event.username,
      triggeredAt: eventData?.timestamp || event.timestamp || new Date(),
      metadata: { detectionType: 'ML_ANOMALY', modelVersion, anomalyScore },
    },
    { upsert: true, new: true, setDefaultsOnInsert: true }
  );

  if (!existingAlert) {
    publishRealtimeEvent('ALERT_CREATED', {
      alertId: alert._id.toString(),
      eventId,
      eventType: alert.eventType,
      severity: alert.severity,
      riskScore: alert.riskScore,
    });
  }
  await correlateAlert(alert);
  return alert;
};

export const evaluateSecurityEvent = async (event: Record<string, any>): Promise<any[]> => {
  try {
    const rules = await DetectionRule.find({ enabled: true }).lean();
    const generatedAlerts: any[] = [];
    const seenAlertKeys = new Set<string>();
    const anomalyResult = await scoreEventForAnomaly(event);
    const anomalyThreshold = Number(process.env.ML_ANOMALY_THRESHOLD ?? 0.65);

    if (anomalyResult?.is_anomaly && anomalyResult.anomaly_score >= anomalyThreshold) {
      generatedAlerts.push(await createAnomalyAlert(event, anomalyResult.anomaly_score, anomalyResult.model_version));
    }

    for (const rule of rules) {
      const ruleId = String(rule._id);
      const eventId = String(event._id ?? event.id ?? event._id);
      const alertKey = dedupeAlertKey(ruleId, eventId);

      if (seenAlertKeys.has(alertKey)) {
        continue;
      }

      let matched = false;

      if (rule.ruleType === 'EVENT_MATCH') {
        matched = evaluatesEventMatchRule(event, rule);
      } else if (rule.ruleType === 'THRESHOLD') {
        matched = await evaluatesThresholdRule(event, rule);
      }

      if (!matched) {
        continue;
      }

      const title = `${rule.name || 'Security detection'} Triggered`;
      const description = rule.description || `Detection rule ${rule.name} matched the event.`;
      const eventData = await SecurityEvent.findById(event._id ?? event.id).lean();

      const alertFilter = { ruleId: new Types.ObjectId(ruleId), eventId: new Types.ObjectId(eventId) };
      const existingAlert = await Alert.exists(alertFilter);
      const alert = await Alert.findOneAndUpdate(
        alertFilter,
        {
          ruleId: new Types.ObjectId(ruleId),
          eventId: new Types.ObjectId(eventId),
          title,
          description,
          severity: rule.severity,
          riskScore: rule.riskScore,
          status: 'NEW',
          source: eventData?.source || event.source,
          eventType: eventData?.eventType || event.eventType,
          sourceIp: eventData?.sourceIp || event.sourceIp,
          username: eventData?.username || event.username,
          triggeredAt: eventData?.timestamp || event.timestamp || new Date(),
          metadata: {
            ruleType: rule.ruleType,
            matchedField: rule.conditions?.field,
            eventSummary: eventData?.message || event.message,
          },
        },
        {
          upsert: true,
          new: true,
          setDefaultsOnInsert: true,
        }
      );

      if (!existingAlert) {
        publishRealtimeEvent('ALERT_CREATED', {
          alertId: alert._id.toString(),
          eventId,
          eventType: alert.eventType,
          severity: alert.severity,
          riskScore: alert.riskScore,
        });
      }
      generatedAlerts.push(alert);
      await correlateAlert(alert);
      seenAlertKeys.add(alertKey);
    }

    return generatedAlerts;
  } catch (error) {
    console.error('Detection engine evaluation failed:', error);
    return [];
  }
};

export default { evaluateSecurityEvent };
