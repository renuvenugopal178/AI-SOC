import mongoose, { Types } from 'mongoose';
import DetectionRule, { DetectionRuleType } from '../models/DetectionRule';
import Alert from '../models/Alert';
import SecurityEvent, { ISecurityEvent } from '../models/SecurityEvent';

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

export const evaluateSecurityEvent = async (event: Record<string, any>): Promise<any[]> => {
  try {
    const rules = await DetectionRule.find({ enabled: true }).lean();
    const generatedAlerts: any[] = [];
    const seenAlertKeys = new Set<string>();

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

      const alert = await Alert.findOneAndUpdate(
        { ruleId: new Types.ObjectId(ruleId), eventId: new Types.ObjectId(eventId) },
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

      generatedAlerts.push(alert);
      seenAlertKeys.add(alertKey);
    }

    return generatedAlerts;
  } catch (error) {
    console.error('Detection engine evaluation failed:', error);
    return [];
  }
};

export default { evaluateSecurityEvent };
