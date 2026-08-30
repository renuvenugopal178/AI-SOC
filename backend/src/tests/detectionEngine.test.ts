import request from 'supertest';
import mongoose from 'mongoose';
import bcrypt from 'bcrypt';
import app from '../app';
import User from '../models/User';
import AuditLog from '../models/AuditLog';
import SecurityEvent from '../models/SecurityEvent';
import DetectionRule from '../models/DetectionRule';
import Alert from '../models/Alert';

const createUser = async (role: 'ADMIN' | 'SOC_ANALYST' | 'VIEWER', uniqueSuffix: string) => {
  const email = `${role.toLowerCase()}_${uniqueSuffix}@example.com`;
  const username = `${role.toLowerCase()}_${uniqueSuffix}`;

  await User.create({
    username,
    email,
    passwordHash: await bcrypt.hash('Password123!', 10),
    role,
    isActive: true,
  });

  const loginRes = await request(app)
    .post('/api/auth/login')
    .send({ email, password: 'Password123!' });

  return loginRes.body.token;
};

describe('Detection engine and rule management', () => {
  beforeAll(async () => {
    process.env.JWT_SECRET = 'test-secret-key';
    const mongoUri = process.env.MONGODB_URI || 'mongodb://admin:change_me_password@localhost:27017/ai-soc?authSource=admin';
    await mongoose.connect(mongoUri);
    await User.deleteMany({});
    await AuditLog.deleteMany({});
    await SecurityEvent.deleteMany({});
    await DetectionRule.deleteMany({});
    await Alert.deleteMany({});
  });

  beforeEach(async () => {
    await User.deleteMany({});
    await AuditLog.deleteMany({});
    await SecurityEvent.deleteMany({});
    await DetectionRule.deleteMany({});
    await Alert.deleteMany({});
  });

  afterAll(async () => {
    await mongoose.disconnect();
  });

  it('1. Creates EVENT_MATCH rule', async () => {
    const token = await createUser('ADMIN', 'rule_create_1');

    const res = await request(app)
      .post('/api/rules')
      .set('Authorization', `Bearer ${token}`)
      .send({
        name: 'Suspicious Login',
        description: 'Detect suspicious login events',
        ruleType: 'EVENT_MATCH',
        severity: 'HIGH',
        enabled: true,
        riskScore: 70,
        conditions: {
          field: 'eventType',
          operator: 'EQUALS',
          value: 'LOGIN_FAILED',
        },
      });

    expect(res.status).toBe(201);
    expect(res.body.rule.name).toBe('Suspicious Login');
  });

  it('2. Rejects invalid rule', async () => {
    const token = await createUser('ADMIN', 'invalid_rule');

    const res = await request(app)
      .post('/api/rules')
      .set('Authorization', `Bearer ${token}`)
      .send({
        name: '',
        description: 'bad',
        ruleType: 'EVENT_MATCH',
        severity: 'INVALID',
        enabled: true,
        riskScore: 101,
        conditions: {},
      });

    expect(res.status).toBe(400);
  });

  it('3. Rejects invalid risk score', async () => {
    const token = await createUser('ADMIN', 'bad_risk');

    const res = await request(app)
      .post('/api/rules')
      .set('Authorization', `Bearer ${token}`)
      .send({
        name: 'Bad Risk Rule',
        description: 'Risk out of range',
        ruleType: 'THRESHOLD',
        severity: 'MEDIUM',
        enabled: true,
        riskScore: 200,
        conditions: {
          field: 'eventType',
          operator: 'EQUALS',
          value: 'LOGIN_FAILED',
          threshold: 3,
          windowMinutes: 5,
        },
      });

    expect(res.status).toBe(400);
  });

  it('4. ADMIN can create rule', async () => {
    const token = await createUser('ADMIN', 'admin_create_rule');

    const res = await request(app)
      .post('/api/rules')
      .set('Authorization', `Bearer ${token}`)
      .send({
        name: 'Admin Rule',
        description: 'Created by admin',
        ruleType: 'EVENT_MATCH',
        severity: 'LOW',
        enabled: true,
        riskScore: 25,
        conditions: {
          field: 'source',
          operator: 'EQUALS',
          value: 'firewall',
        },
      });

    expect(res.status).toBe(201);
  });

  it('5. SOC_ANALYST cannot create rule', async () => {
    const token = await createUser('SOC_ANALYST', 'soc_no_create');

    const res = await request(app)
      .post('/api/rules')
      .set('Authorization', `Bearer ${token}`)
      .send({
        name: 'Forbidden Rule',
        description: 'Should fail',
        ruleType: 'EVENT_MATCH',
        severity: 'MEDIUM',
        enabled: true,
        riskScore: 45,
        conditions: { field: 'source', operator: 'EQUALS', value: 'ids' },
      });

    expect(res.status).toBe(403);
  });

  it('6. VIEWER cannot create rule', async () => {
    const token = await createUser('VIEWER', 'viewer_no_create');

    const res = await request(app)
      .post('/api/rules')
      .set('Authorization', `Bearer ${token}`)
      .send({
        name: 'Viewer Rule',
        description: 'Should fail',
        ruleType: 'EVENT_MATCH',
        severity: 'MEDIUM',
        enabled: true,
        riskScore: 45,
        conditions: { field: 'source', operator: 'EQUALS', value: 'ids' },
      });

    expect(res.status).toBe(403);
  });

  it('7. ADMIN can update rule', async () => {
    const token = await createUser('ADMIN', 'admin_update_rule');

    const created = await DetectionRule.create({
      name: 'Old Rule',
      description: 'old desc',
      ruleType: 'EVENT_MATCH',
      enabled: true,
      severity: 'MEDIUM',
      riskScore: 40,
      conditions: { field: 'eventType', operator: 'EQUALS', value: 'PORT_SCAN' },
      createdBy: 'admin',
    });

    const res = await request(app)
      .patch(`/api/rules/${created._id}`)
      .set('Authorization', `Bearer ${token}`)
      .send({
        name: 'Updated Rule',
        enabled: false,
      });

    expect(res.status).toBe(200);
    expect(res.body.rule.name).toBe('Updated Rule');
  });

  it('8. ADMIN can delete rule', async () => {
    const token = await createUser('ADMIN', 'admin_delete_rule');

    const created = await DetectionRule.create({
      name: 'Delete Me',
      description: 'delete',
      ruleType: 'EVENT_MATCH',
      enabled: true,
      severity: 'HIGH',
      riskScore: 80,
      conditions: { field: 'source', operator: 'EQUALS', value: 'ids' },
      createdBy: 'admin',
    });

    const res = await request(app)
      .delete(`/api/rules/${created._id}`)
      .set('Authorization', `Bearer ${token}`);

    expect(res.status).toBe(200);
  });

  it('9. Enabled EVENT_MATCH rule triggers alert', async () => {
    const token = await createUser('ADMIN', 'event_match_trigger');

    const rule = await DetectionRule.create({
      name: 'Login Failure Match',
      description: 'trigger when login fails',
      ruleType: 'EVENT_MATCH',
      enabled: true,
      severity: 'HIGH',
      riskScore: 70,
      conditions: { field: 'eventType', operator: 'EQUALS', value: 'LOGIN_FAILED' },
      createdBy: 'admin',
    });

    const event = await SecurityEvent.create({
      timestamp: new Date(),
      source: 'auth-service',
      eventType: 'LOGIN_FAILED',
      severity: 'HIGH',
      sourceIp: '10.0.0.5',
      message: 'Failed login',
    });

    const alerts = await (await import('../services/detectionEngine')).evaluateSecurityEvent(event.toObject());
    expect(alerts.length).toBeGreaterThan(0);
    expect(alerts[0].ruleId.toString()).toBe(rule._id.toString());
  });

  it('10. Disabled rule does not trigger alert', async () => {
    await DetectionRule.create({
      name: 'Disabled Rule',
      description: 'disabled rule',
      ruleType: 'EVENT_MATCH',
      enabled: false,
      severity: 'MEDIUM',
      riskScore: 30,
      conditions: { field: 'eventType', operator: 'EQUALS', value: 'LOGIN_FAILED' },
      createdBy: 'admin',
    });

    const event = await SecurityEvent.create({
      timestamp: new Date(),
      source: 'auth-service',
      eventType: 'LOGIN_FAILED',
      severity: 'HIGH',
      sourceIp: '10.0.0.5',
      message: 'Failed login',
    });

    const alerts = await (await import('../services/detectionEngine')).evaluateSecurityEvent(event.toObject());
    expect(alerts.length).toBe(0);
  });

  it('11. Matching event creates alert', async () => {
    await DetectionRule.create({
      name: 'Port Scan Alert',
      description: 'port scan rule',
      ruleType: 'EVENT_MATCH',
      enabled: true,
      severity: 'HIGH',
      riskScore: 80,
      conditions: { field: 'eventType', operator: 'EQUALS', value: 'PORT_SCAN' },
      createdBy: 'admin',
    });

    const event = await SecurityEvent.create({
      timestamp: new Date(),
      source: 'firewall',
      eventType: 'PORT_SCAN',
      severity: 'HIGH',
      sourceIp: '10.0.0.8',
      destinationIp: '10.0.0.10',
      message: 'Scanner found',
    });

    const alerts = await (await import('../services/detectionEngine')).evaluateSecurityEvent(event.toObject());
    expect(alerts.length).toBe(1);
  });

  it('12. Non-matching event creates no alert', async () => {
    await DetectionRule.create({
      name: 'Only Failures Count',
      description: 'only for login failures',
      ruleType: 'EVENT_MATCH',
      enabled: true,
      severity: 'MEDIUM',
      riskScore: 40,
      conditions: { field: 'eventType', operator: 'EQUALS', value: 'LOGIN_FAILED' },
      createdBy: 'admin',
    });

    const event = await SecurityEvent.create({
      timestamp: new Date(),
      source: 'auth-service',
      eventType: 'LOGIN_SUCCESS',
      severity: 'LOW',
      sourceIp: '10.0.0.9',
      message: 'Successful login',
    });

    const alerts = await (await import('../services/detectionEngine')).evaluateSecurityEvent(event.toObject());
    expect(alerts.length).toBe(0);
  });

  it('13. Threshold rule triggers when threshold is exceeded', async () => {
    await DetectionRule.create({
      name: 'Multiple Failed Logins',
      description: 'More than 2 failures in 5 minutes',
      ruleType: 'THRESHOLD',
      enabled: true,
      severity: 'HIGH',
      riskScore: 70,
      conditions: {
        field: 'eventType',
        operator: 'EQUALS',
        value: 'LOGIN_FAILED',
        threshold: 2,
        windowMinutes: 5,
      },
      createdBy: 'admin',
    });

    await SecurityEvent.insertMany([
      { timestamp: new Date(), source: 'auth-service', eventType: 'LOGIN_FAILED', severity: 'MEDIUM', message: '1' },
      { timestamp: new Date(Date.now() - 1000), source: 'auth-service', eventType: 'LOGIN_FAILED', severity: 'MEDIUM', message: '2' },
      { timestamp: new Date(Date.now() - 2000), source: 'auth-service', eventType: 'LOGIN_FAILED', severity: 'MEDIUM', message: '3' },
    ]);

    const event = await SecurityEvent.create({
      timestamp: new Date(),
      source: 'auth-service',
      eventType: 'LOGIN_FAILED',
      severity: 'MEDIUM',
      message: '4',
    });

    const alerts = await (await import('../services/detectionEngine')).evaluateSecurityEvent(event.toObject());
    expect(alerts.length).toBeGreaterThan(0);
  });

  it('14. Threshold rule does not trigger below threshold', async () => {
    await DetectionRule.create({
      name: 'Low Threshold Rule',
      description: 'Requires 5',
      ruleType: 'THRESHOLD',
      enabled: true,
      severity: 'MEDIUM',
      riskScore: 50,
      conditions: {
        field: 'eventType',
        operator: 'EQUALS',
        value: 'LOGIN_FAILED',
        threshold: 5,
        windowMinutes: 5,
      },
      createdBy: 'admin',
    });

    await SecurityEvent.create({
      timestamp: new Date(),
      source: 'auth-service',
      eventType: 'LOGIN_FAILED',
      severity: 'MEDIUM',
      message: 'one',
    });

    const event = await SecurityEvent.create({
      timestamp: new Date(),
      source: 'auth-service',
      eventType: 'LOGIN_FAILED',
      severity: 'MEDIUM',
      message: 'two',
    });

    const alerts = await (await import('../services/detectionEngine')).evaluateSecurityEvent(event.toObject());
    expect(alerts.length).toBe(0);
  });

  it('15. Alert references the correct rule', async () => {
    const rule = await DetectionRule.create({
      name: 'Rule Link Check',
      description: 'link',
      ruleType: 'EVENT_MATCH',
      enabled: true,
      severity: 'HIGH',
      riskScore: 75,
      conditions: { field: 'eventType', operator: 'EQUALS', value: 'PORT_SCAN' },
      createdBy: 'admin',
    });

    const event = await SecurityEvent.create({
      timestamp: new Date(),
      source: 'firewall',
      eventType: 'PORT_SCAN',
      severity: 'HIGH',
      message: 'scan',
    });

    const alerts = await (await import('../services/detectionEngine')).evaluateSecurityEvent(event.toObject());
    expect(alerts[0].ruleId.toString()).toBe(rule._id.toString());
  });

  it('16. Alert references the triggering event', async () => {
    await DetectionRule.create({
      name: 'Triggered Event Check',
      description: 'event link',
      ruleType: 'EVENT_MATCH',
      enabled: true,
      severity: 'CRITICAL',
      riskScore: 90,
      conditions: { field: 'eventType', operator: 'EQUALS', value: 'MALWARE_DETECTION' },
      createdBy: 'admin',
    });

    const event = await SecurityEvent.create({
      timestamp: new Date(),
      source: 'endpoint',
      eventType: 'MALWARE_DETECTION',
      severity: 'CRITICAL',
      message: 'malware',
    });

    const alerts = await (await import('../services/detectionEngine')).evaluateSecurityEvent(event.toObject());
    expect(alerts[0].eventId.toString()).toBe(event._id.toString());
  });

  it('17. Risk score is copied correctly', async () => {
    await DetectionRule.create({
      name: 'Risk Copy Rule',
      description: 'copy risk',
      ruleType: 'EVENT_MATCH',
      enabled: true,
      severity: 'HIGH',
      riskScore: 88,
      conditions: { field: 'eventType', operator: 'EQUALS', value: 'LOGIN_FAILED' },
      createdBy: 'admin',
    });

    const event = await SecurityEvent.create({
      timestamp: new Date(),
      source: 'auth-service',
      eventType: 'LOGIN_FAILED',
      severity: 'HIGH',
      message: 'copy risk',
    });

    const alerts = await (await import('../services/detectionEngine')).evaluateSecurityEvent(event.toObject());
    expect(alerts[0].riskScore).toBe(88);
  });

  it('18. Alert status starts as NEW', async () => {
    await DetectionRule.create({
      name: 'New Alert Rule',
      description: 'status new',
      ruleType: 'EVENT_MATCH',
      enabled: true,
      severity: 'MEDIUM',
      riskScore: 50,
      conditions: { field: 'eventType', operator: 'EQUALS', value: 'LOGIN_SUCCESS' },
      createdBy: 'admin',
    });

    const event = await SecurityEvent.create({
      timestamp: new Date(),
      source: 'auth-service',
      eventType: 'LOGIN_SUCCESS',
      severity: 'MEDIUM',
      message: 'logged in',
    });

    const alerts = await (await import('../services/detectionEngine')).evaluateSecurityEvent(event.toObject());
    expect(alerts[0].status).toBe('NEW');
  });

  it('19. Duplicate processing of the same event and rule does not create duplicate alerts', async () => {
    const rule = await DetectionRule.create({
      name: 'Deduplication Test Rule',
      description: 'rule for dedup check',
      ruleType: 'EVENT_MATCH',
      enabled: true,
      severity: 'HIGH',
      riskScore: 75,
      conditions: { field: 'eventType', operator: 'EQUALS', value: 'SQL_INJECTION' },
      createdBy: 'admin',
    });

    const event = await SecurityEvent.create({
      timestamp: new Date(),
      source: 'waf',
      eventType: 'SQL_INJECTION',
      severity: 'HIGH',
      message: 'SQL injection attack detected',
    });

    const { evaluateSecurityEvent } = await import('../services/detectionEngine');

    // First evaluation
    const firstRunAlerts = await evaluateSecurityEvent(event.toObject());
    expect(firstRunAlerts.length).toBe(1);

    const alertCountAfterFirst = await Alert.countDocuments({
      ruleId: rule._id,
      eventId: event._id,
    });
    expect(alertCountAfterFirst).toBe(1);

    // Second evaluation on the same event
    const secondRunAlerts = await evaluateSecurityEvent(event.toObject());
    expect(secondRunAlerts.length).toBe(1);

    // Total alerts in DB must still be 1 (no duplicates)
    const alertCountAfterSecond = await Alert.countDocuments({
      ruleId: rule._id,
      eventId: event._id,
    });
    expect(alertCountAfterSecond).toBe(1);
    expect(await Alert.countDocuments({})).toBe(1);
  });

  it('20. Ingestion endpoint automatically executes detection and creates an alert for matching event', async () => {
    const token = await createUser('ADMIN', 'auto_detect_ingest');

    await DetectionRule.create({
      name: 'Ingest Match Rule',
      description: 'rule matching ingested event',
      ruleType: 'EVENT_MATCH',
      enabled: true,
      severity: 'CRITICAL',
      riskScore: 90,
      conditions: { field: 'eventType', operator: 'EQUALS', value: 'BRUTE_FORCE' },
      createdBy: 'admin',
    });

    const res = await request(app)
      .post('/api/events/ingest')
      .set('Authorization', `Bearer ${token}`)
      .send({
        source: 'auth-service',
        eventType: 'BRUTE_FORCE',
        severity: 'CRITICAL',
        sourceIp: '192.168.1.100',
        message: 'Repeated authentication failures detected',
      });

    expect(res.status).toBe(201);
    expect(res.body.alerts).toBeDefined();
    expect(res.body.alerts.length).toBe(1);
    expect(res.body.alerts[0].severity).toBe('CRITICAL');

    const alertInDb = await Alert.findOne({ eventId: res.body.eventId });
    expect(alertInDb).not.toBeNull();
    expect(alertInDb?.title).toContain('Ingest Match Rule');
  });

  it('21. Ingestion endpoint does not create alert for disabled rule', async () => {
    const token = await createUser('ADMIN', 'auto_detect_disabled');

    await DetectionRule.create({
      name: 'Disabled Ingest Rule',
      description: 'disabled rule',
      ruleType: 'EVENT_MATCH',
      enabled: false,
      severity: 'HIGH',
      riskScore: 70,
      conditions: { field: 'eventType', operator: 'EQUALS', value: 'XSS_ATTACK' },
      createdBy: 'admin',
    });

    const res = await request(app)
      .post('/api/events/ingest')
      .set('Authorization', `Bearer ${token}`)
      .send({
        source: 'waf',
        eventType: 'XSS_ATTACK',
        severity: 'HIGH',
        message: 'XSS payload in query string',
      });

    expect(res.status).toBe(201);
    expect(res.body.alerts).toEqual([]);
    expect(await Alert.countDocuments({})).toBe(0);
  });

  it('22. Ingestion endpoint does not create alert for non-matching event', async () => {
    const token = await createUser('ADMIN', 'auto_detect_nomatch');

    await DetectionRule.create({
      name: 'Port Scan Rule',
      description: 'only port scans',
      ruleType: 'EVENT_MATCH',
      enabled: true,
      severity: 'HIGH',
      riskScore: 80,
      conditions: { field: 'eventType', operator: 'EQUALS', value: 'PORT_SCAN' },
      createdBy: 'admin',
    });

    const res = await request(app)
      .post('/api/events/ingest')
      .set('Authorization', `Bearer ${token}`)
      .send({
        source: 'sensor',
        eventType: 'SYSTEM_STARTUP',
        severity: 'LOW',
        message: 'Host rebooted normally',
      });

    expect(res.status).toBe(201);
    expect(res.body.alerts).toEqual([]);
    expect(await Alert.countDocuments({})).toBe(0);
  });
});

