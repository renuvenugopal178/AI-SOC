import request from 'supertest';
import mongoose from 'mongoose';
import bcrypt from 'bcrypt';
import app from '../app';
import User from '../models/User';
import Alert from '../models/Alert';
import Incident from '../models/Incident';
import SecurityEvent from '../models/SecurityEvent';
import DetectionRule from '../models/DetectionRule';
import { correlateAlert } from '../services/correlationService';

const createUser = async (role: 'ADMIN' | 'SOC_ANALYST' | 'VIEWER', suffix: string) => {
  const email = `${role.toLowerCase()}_${suffix}@example.com`;
  await User.create({
    username: `${role.toLowerCase()}_${suffix}`,
    email,
    passwordHash: await bcrypt.hash('Password123!', 10),
    role,
    isActive: true,
  });

  const response = await request(app).post('/api/auth/login').send({ email, password: 'Password123!' });
  return response.body.token;
};

const createAlert = async (sourceIp: string, eventType: string, riskScore: number, minutesAgo = 0) => {
  const event = await SecurityEvent.create({
    timestamp: new Date(Date.now() - minutesAgo * 60 * 1000),
    source: 'test-source',
    eventType,
    severity: riskScore >= 80 ? 'HIGH' : 'MEDIUM',
    sourceIp,
    username: 'target-user',
  });
  const rule = await DetectionRule.create({
    name: `${eventType} rule`,
    description: 'test rule',
    ruleType: eventType === 'LOGIN_FAILED' ? 'THRESHOLD' : 'EVENT_MATCH',
    enabled: true,
    severity: riskScore >= 80 ? 'HIGH' : 'MEDIUM',
    riskScore,
    conditions: { field: 'eventType', operator: 'EQUALS', value: eventType },
    createdBy: 'test',
  });
  return Alert.create({
    ruleId: rule._id,
    eventId: event._id,
    title: `${eventType} alert`,
    description: 'test alert',
    severity: riskScore >= 80 ? 'HIGH' : 'MEDIUM',
    riskScore,
    status: 'NEW',
    eventType,
    sourceIp,
    username: 'target-user',
    triggeredAt: event.timestamp,
    metadata: { ruleType: eventType === 'LOGIN_FAILED' ? 'THRESHOLD' : 'EVENT_MATCH' },
  });
};

describe('Incident correlation and management', () => {
  beforeAll(async () => {
    process.env.JWT_SECRET = 'test-secret-key';
    await mongoose.connect(process.env.MONGODB_URI || 'mongodb://admin:change_me_password@localhost:27017/ai-soc?authSource=admin');
  });

  beforeEach(async () => {
    await User.deleteMany({});
    await Alert.deleteMany({});
    await Incident.deleteMany({});
    await SecurityEvent.deleteMany({});
    await DetectionRule.deleteMany({});
  });

  afterAll(async () => {
    await mongoose.disconnect();
  });

  it('creates one incident for related alerts and updates it with additional alerts', async () => {
    const failed = await createAlert('10.0.0.5', 'LOGIN_FAILED', 60, 2);
    expect(await correlateAlert(failed)).toBeNull();

    const success = await createAlert('10.0.0.5', 'LOGIN_SUCCESS', 30);
    const incident = await correlateAlert(success);
    expect(incident).not.toBeNull();
    expect(incident?.relatedAlertIds).toHaveLength(2);

    const additional = await createAlert('10.0.0.5', 'UNAUTHORIZED_ACCESS', 40);
    await correlateAlert(additional);

    expect(await Incident.countDocuments()).toBe(1);
    const updated = await Incident.findOne();
    expect(updated?.relatedAlertIds).toHaveLength(3);
    expect(updated?.riskScore).toBe(100);
  });

  it('does not correlate unrelated source IPs or alerts outside the time window', async () => {
    const first = await createAlert('10.0.0.6', 'LOGIN_FAILED', 40, 45);
    const differentIp = await createAlert('10.0.0.7', 'LOGIN_SUCCESS', 40);
    const oldResult = await correlateAlert(first);
    expect(oldResult).toBeNull();
    expect(await correlateAlert(differentIp)).toBeNull();
    expect(await Incident.countDocuments()).toBe(0);
  });

  it('does not create duplicate incidents when the same alert is processed repeatedly', async () => {
    const first = await createAlert('10.0.0.8', 'LOGIN_FAILED', 60);
    const second = await createAlert('10.0.0.8', 'LOGIN_SUCCESS', 20);
    await correlateAlert(second);
    await correlateAlert(second);
    await correlateAlert(first);

    expect(await Incident.countDocuments()).toBe(1);
    expect((await Incident.findOne())?.relatedAlertIds).toHaveLength(2);
  });

  it('allows viewers to read incidents but only analysts and admins can update status', async () => {
    const first = await createAlert('10.0.0.9', 'LOGIN_FAILED', 50);
    const second = await createAlert('10.0.0.9', 'LOGIN_SUCCESS', 30);
    await correlateAlert(second);
    const incident = await Incident.findOne();
    const viewerToken = await createUser('VIEWER', 'incident_viewer');
    const analystToken = await createUser('SOC_ANALYST', 'incident_analyst');

    expect((await request(app).get('/api/incidents').set('Authorization', `Bearer ${viewerToken}`)).status).toBe(200);
    expect((await request(app).patch(`/api/incidents/${incident?._id}/status`).set('Authorization', `Bearer ${viewerToken}`).send({ status: 'INVESTIGATING' })).status).toBe(403);

    const update = await request(app)
      .patch(`/api/incidents/${incident?._id}/status`)
      .set('Authorization', `Bearer ${analystToken}`)
      .send({ status: 'INVESTIGATING' });
    expect(update.status).toBe(200);
    expect(update.body.incident.status).toBe('INVESTIGATING');
    expect(first._id).toBeDefined();
  });
});
