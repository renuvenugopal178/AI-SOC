import mongoose from 'mongoose';
import Alert from '../models/Alert';
import DetectionRule from '../models/DetectionRule';
import SecurityEvent from '../models/SecurityEvent';
import { evaluateSecurityEvent } from '../services/detectionEngine';

const anomalyResponse = {
  ok: true,
  json: async () => ({ is_anomaly: true, anomaly_score: 0.9, model_version: 'test-model' }),
} as Response;

describe('ML anomaly detection integration', () => {
  beforeAll(async () => {
    process.env.JWT_SECRET = 'test-secret-key';
    await mongoose.connect(process.env.MONGODB_URI || 'mongodb://admin:change_me_password@localhost:27017/ai-soc?authSource=admin');
  });

  beforeEach(async () => {
    await Alert.deleteMany({});
    await DetectionRule.deleteMany({});
    await SecurityEvent.deleteMany({});
  });

  afterEach(() => jest.restoreAllMocks());
  afterAll(async () => mongoose.disconnect());

  const createEvent = async () => SecurityEvent.create({
    timestamp: new Date(),
    source: 'auth-service',
    eventType: 'LOGIN_SUCCESS',
    severity: 'MEDIUM',
    sourceIp: '10.0.0.20',
    destinationPort: 443,
  });

  it('creates a valid anomaly alert and deduplicates repeated processing', async () => {
    jest.spyOn(global, 'fetch').mockResolvedValue(anomalyResponse);
    const event = await createEvent();

    await evaluateSecurityEvent(event.toObject());
    await evaluateSecurityEvent(event.toObject());

    expect(await Alert.countDocuments({ eventId: event._id })).toBe(1);
    expect((await Alert.findOne({ eventId: event._id }))?.metadata).toMatchObject({
      detectionType: 'ML_ANOMALY',
      modelVersion: 'test-model',
    });
  });

  it('continues rule detection when the ML service is unavailable', async () => {
    jest.spyOn(global, 'fetch').mockRejectedValue(new Error('connection refused'));
    await DetectionRule.create({
      name: 'Login success rule',
      description: 'test rule',
      ruleType: 'EVENT_MATCH',
      enabled: true,
      severity: 'LOW',
      riskScore: 10,
      conditions: { field: 'eventType', operator: 'EQUALS', value: 'LOGIN_SUCCESS' },
      createdBy: 'test',
    });
    const event = await createEvent();

    const alerts = await evaluateSecurityEvent(event.toObject());

    expect(alerts).toHaveLength(1);
    expect(alerts[0].metadata.detectionType).toBeUndefined();
  });
});
