import request from 'supertest';
import mongoose from 'mongoose';
import bcrypt from 'bcrypt';
import app from '../app';
import User from '../models/User';
import AuditLog from '../models/AuditLog';
import SecurityEvent from '../models/SecurityEvent';

const basePayload = {
  timestamp: '2026-08-20T12:00:00.000Z',
  source: 'firewall',
  eventType: 'PORT_SCAN',
  severity: 'HIGH',
  sourceIp: '192.168.1.50',
  destinationIp: '10.0.0.10',
  destinationPort: 22,
  protocol: 'TCP',
  message: 'Multiple connection attempts detected',
  metadata: {
    attempts: 25,
  },
};

const passwordHash = async () => bcrypt.hash('Password123!', 10);

describe('Security event ingestion and retrieval', () => {
  beforeAll(async () => {
    process.env.JWT_SECRET = 'test-secret-key';
    const mongoUri = process.env.MONGODB_URI || 'mongodb://admin:change_me_password@localhost:27017/ai-soc?authSource=admin';
    await mongoose.connect(mongoUri);
    await User.deleteMany({});
    await AuditLog.deleteMany({});
    await SecurityEvent.deleteMany({});
  });

  beforeEach(async () => {
    await User.deleteMany({});
    await AuditLog.deleteMany({});
    await SecurityEvent.deleteMany({});
  });

  afterAll(async () => {
    await mongoose.disconnect();
  });

  it('1. Authenticated ADMIN can ingest an event', async () => {
    await User.create({
      username: 'admin_ingest',
      email: 'admin_ingest@example.com',
      passwordHash: await passwordHash(),
      role: 'ADMIN',
      isActive: true,
    });

    const loginRes = await request(app)
      .post('/api/auth/login')
      .send({ email: 'admin_ingest@example.com', password: 'Password123!' });

    const res = await request(app)
      .post('/api/events')
      .set('Authorization', `Bearer ${loginRes.body.token}`)
      .send(basePayload);

    expect(res.status).toBe(201);
    expect(res.body.event).toMatchObject({
      source: 'firewall',
      eventType: 'PORT_SCAN',
      severity: 'HIGH',
      sourceIp: '192.168.1.50',
    });
    expect(res.body.event.password).toBeUndefined();
  });

  it('2. Authenticated SOC_ANALYST can ingest an event', async () => {
    await User.create({
      username: 'soc_ingest',
      email: 'soc_ingest@example.com',
      passwordHash: await passwordHash(),
      role: 'SOC_ANALYST',
      isActive: true,
    });

    const loginRes = await request(app)
      .post('/api/auth/login')
      .send({ email: 'soc_ingest@example.com', password: 'Password123!' });

    const res = await request(app)
      .post('/api/events')
      .set('Authorization', `Bearer ${loginRes.body.token}`)
      .send({
        ...basePayload,
        source: 'ids',
        eventType: 'MALWARE_DETECTION',
        severity: 'CRITICAL',
      });

    expect(res.status).toBe(201);
    expect(res.body.event.eventType).toBe('MALWARE_DETECTION');
  });

  it('3. VIEWER is denied from ingestion', async () => {
    await User.create({
      username: 'viewer_ingest',
      email: 'viewer_ingest@example.com',
      passwordHash: await passwordHash(),
      role: 'VIEWER',
      isActive: true,
    });

    const loginRes = await request(app)
      .post('/api/auth/login')
      .send({ email: 'viewer_ingest@example.com', password: 'Password123!' });

    const res = await request(app)
      .post('/api/events')
      .set('Authorization', `Bearer ${loginRes.body.token}`)
      .send(basePayload);

    expect(res.status).toBe(403);
  });

  it('4. Missing JWT is rejected', async () => {
    const res = await request(app)
      .post('/api/events')
      .send(basePayload);

    expect(res.status).toBe(401);
  });

  it('5. Invalid event data is rejected', async () => {
    await User.create({
      username: 'admin_invalid',
      email: 'admin_invalid@example.com',
      passwordHash: await passwordHash(),
      role: 'ADMIN',
      isActive: true,
    });

    const loginRes = await request(app)
      .post('/api/auth/login')
      .send({ email: 'admin_invalid@example.com', password: 'Password123!' });

    const res = await request(app)
      .post('/api/events')
      .set('Authorization', `Bearer ${loginRes.body.token}`)
      .send({
        timestamp: 'not-a-date',
        source: '',
        eventType: 'PORT_SCAN',
        severity: 'INVALID',
      });

    expect(res.status).toBe(400);
  });

  it('6. Valid event is stored in MongoDB', async () => {
    await User.create({
      username: 'admin_store',
      email: 'admin_store@example.com',
      passwordHash: await passwordHash(),
      role: 'ADMIN',
      isActive: true,
    });

    const loginRes = await request(app)
      .post('/api/auth/login')
      .send({ email: 'admin_store@example.com', password: 'Password123!' });

    const res = await request(app)
      .post('/api/events')
      .set('Authorization', `Bearer ${loginRes.body.token}`)
      .send(basePayload);

    expect(res.status).toBe(201);

    const stored = await SecurityEvent.findOne({ source: 'firewall', eventType: 'PORT_SCAN' });
    expect(stored).not.toBeNull();
    expect(stored?.message).toBe('Multiple connection attempts detected');
  });

  it('7. GET /api/events requires authentication', async () => {
    const res = await request(app).get('/api/events');
    expect(res.status).toBe(401);
  });

  it('8. ADMIN can retrieve events', async () => {
    await User.create({
      username: 'admin_get',
      email: 'admin_get@example.com',
      passwordHash: await passwordHash(),
      role: 'ADMIN',
      isActive: true,
    });

    await SecurityEvent.create({
      ...basePayload,
      source: 'admin-retrieve',
      eventType: 'AUTHENTICATION_FAILURE',
      severity: 'MEDIUM',
      username: 'admin-user',
      message: 'Auth failure',
    });

    const loginRes = await request(app)
      .post('/api/auth/login')
      .send({ email: 'admin_get@example.com', password: 'Password123!' });

    const res = await request(app)
      .get('/api/events')
      .set('Authorization', `Bearer ${loginRes.body.token}`)
      .query({ page: 1, limit: 10 });

    expect(res.status).toBe(200);
    expect(res.body.events.length).toBeGreaterThan(0);
    expect(res.body.page).toBe(1);
    expect(res.body.total).toBeGreaterThan(0);
  });

  it('9. SOC_ANALYST can retrieve events', async () => {
    await User.create({
      username: 'soc_get',
      email: 'soc_get@example.com',
      passwordHash: await passwordHash(),
      role: 'SOC_ANALYST',
      isActive: true,
    });

    await SecurityEvent.create({
      ...basePayload,
      source: 'soc-retrieve',
      eventType: 'AUTHENTICATION_SUCCESS',
      severity: 'LOW',
      username: 'soc-user',
      message: 'Log in succeeded',
    });

    const loginRes = await request(app)
      .post('/api/auth/login')
      .send({ email: 'soc_get@example.com', password: 'Password123!' });

    const res = await request(app)
      .get('/api/events')
      .set('Authorization', `Bearer ${loginRes.body.token}`)
      .query({ page: 1, limit: 10 });

    expect(res.status).toBe(200);
    expect(Array.isArray(res.body.events)).toBe(true);
  });

  it('10. VIEWER can retrieve events', async () => {
    await User.create({
      username: 'viewer_get',
      email: 'viewer_get@example.com',
      passwordHash: await passwordHash(),
      role: 'VIEWER',
      isActive: true,
    });

    await SecurityEvent.create({
      ...basePayload,
      source: 'viewer-retrieve',
      eventType: 'FILE_MODIFICATION',
      severity: 'HIGH',
      username: 'viewer-user',
      message: 'File modified',
    });

    const loginRes = await request(app)
      .post('/api/auth/login')
      .send({ email: 'viewer_get@example.com', password: 'Password123!' });

    const res = await request(app)
      .get('/api/events')
      .set('Authorization', `Bearer ${loginRes.body.token}`)
      .query({ page: 1, limit: 10 });

    expect(res.status).toBe(200);
    expect(res.body.events[0]).not.toHaveProperty('sourceIp');
    expect(res.body.events[0]).toHaveProperty('message');
  });

  it('11. Pagination works', async () => {
    await User.create({
      username: 'admin_pagination',
      email: 'admin_pagination@example.com',
      passwordHash: await passwordHash(),
      role: 'ADMIN',
      isActive: true,
    });

    for (let i = 0; i < 5; i++) {
      await SecurityEvent.create({
        ...basePayload,
        source: `pag-${i}`,
        eventType: i % 2 === 0 ? 'PORT_SCAN' : 'LOGIN_FAILURE',
        severity: i % 2 === 0 ? 'HIGH' : 'MEDIUM',
        message: `event ${i}`,
      });
    }

    const loginRes = await request(app)
      .post('/api/auth/login')
      .send({ email: 'admin_pagination@example.com', password: 'Password123!' });

    const res = await request(app)
      .get('/api/events')
      .set('Authorization', `Bearer ${loginRes.body.token}`)
      .query({ page: 2, limit: 2 });

    expect(res.status).toBe(200);
    expect(res.body.page).toBe(2);
    expect(res.body.limit).toBe(2);
    expect(res.body.events.length).toBeLessThanOrEqual(2);
    expect(res.body.totalPages).toBeGreaterThanOrEqual(1);
  });

  it('12. Audit log is created for successful ingestion', async () => {
    await User.create({
      username: 'admin_audit',
      email: 'admin_audit@example.com',
      passwordHash: await passwordHash(),
      role: 'ADMIN',
      isActive: true,
    });

    const loginRes = await request(app)
      .post('/api/auth/login')
      .send({ email: 'admin_audit@example.com', password: 'Password123!' });

    const res = await request(app)
      .post('/api/events')
      .set('Authorization', `Bearer ${loginRes.body.token}`)
      .send({
        ...basePayload,
        eventType: 'SQL_INJECTION',
        source: 'web-gateway',
        severity: 'CRITICAL',
      });

    expect(res.status).toBe(201);

    const auditLog = await AuditLog.findOne({
      action: 'EVENT_INGESTION_SUCCESS',
      'metadata.eventId': res.body.event.id,
    });

    expect(auditLog).not.toBeNull();
    expect(auditLog?.success).toBe(true);
  });
});
