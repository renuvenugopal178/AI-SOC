import { ISecurityEvent } from '../models/SecurityEvent';

export interface AnomalyResult {
  is_anomaly: boolean;
  anomaly_score: number;
  model_version: string;
}

const getMlServiceUrl = (): string => process.env.ML_SERVICE_URL || 'http://localhost:8001';

export const scoreEventForAnomaly = async (event: Partial<ISecurityEvent>): Promise<AnomalyResult | null> => {
  try {
    const response = await fetch(`${getMlServiceUrl()}/predict`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        source_port: event.sourcePort,
        destination_port: event.destinationPort,
        severity: event.severity,
        event_type: event.eventType,
        protocol: event.protocol,
        action: event.action,
        message: event.message,
        event_frequency: 1,
      }),
      signal: AbortSignal.timeout(3000),
    });

    if (!response.ok) {
      return null;
    }

    const result = await response.json() as Partial<AnomalyResult>;
    if (typeof result.is_anomaly !== 'boolean' || typeof result.anomaly_score !== 'number' || typeof result.model_version !== 'string') {
      return null;
    }

    return result as AnomalyResult;
  } catch (error) {
    return null;
  }
};

export default { scoreEventForAnomaly };
