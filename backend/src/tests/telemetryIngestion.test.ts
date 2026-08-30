import request from 'supertest';
import mongoose from 'mongoose';
import bcrypt from 'bcrypt';
import app from '../app';
import User from '../models/User';
import AuditLog from '../models/AuditLog';
import SecurityEvent from '../models/SecurityEvent';
import DetectionRule from '../models/DetectionRule';
import Alert from '../models/Alert';

const createTestUser = async (role: 'ADMIN' | 'SOC_ANALYST' | 'VIEWER', name: string) => {
  const email = `${name.toLowerCase()}@ai-soc.local`;
  const username = name.toLowerCase();

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

describe('Generic SOC Telemetry Ingestion Layer', () => {
  beforeAll(async () => {
    process.env.JWT_SECRET = 'test-secret-key';
    const mongoUri =
      process.env.MONGODB_URI ||
      'mongodb://admin:change_me_password@localhost:27017/ai-soc?authSource=admin';
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(mongoUri);
    }
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

  describe('Dedicated Ingestion Endpoint (/api/events/ingest)', () => {
    it('successfully ingests a fully populated telemetry event with all defined fields', async () => {
      const token = await createTestUser('SOC_ANALYST', 'analyst_ingest_1');

      const fullPayload = {
        timestamp: '2026-08-25T14:30:00.000Z',
        source: 'edr-agent-01',
        eventType: 'SUSPICIOUS_PROCESS_EXECUTION',
        severity: 'HIGH',
        sourceIp: '192.168.10.45',
        destinationIp: '10.0.5.20',
        sourcePort: 49152,
        destinationPort: 445,
        protocol: 'TCP',
        username: 'victim_user',
        action: 'PROCESS_SPAWN',
        message: 'cmd.exe spawned powershell.exe with encoded arguments',
        metadata: {
          parentProcess: 'cmd.exe',
          childProcess: 'powershell.exe',
          pid: 4092,
        },
      };

      const res = await request(app)
        .post('/api/events/ingest')
        .set('Authorization', `Bearer ${token}`)
        .send(fullPayload);

      expect(res.status).toBe(201);
      expect(res.body.message).toBe('Security event ingested successfully.');
      expect(res.body.eventId).toBeDefined();
      expect(typeof res.body.eventId).toBe('string');
      expect(res.body.event).toMatchObject({
        id: res.body.eventId,
        source: 'edr-agent-01',
        eventType: 'SUSPICIOUS_PROCESS_EXECUTION',
        severity: 'HIGH',
        sourceIp: '192.168.10.45',
        destinationIp: '10.0.5.20',
        sourcePort: 49152,
        destinationPort: 445,
        protocol: 'TCP',
        username: 'victim_user',
        action: 'PROCESS_SPAWN',
        message: 'cmd.exe spawned powershell.exe with encoded arguments',
      });
      expect(res.body.event.metadata).toEqual({
        parentProcess: 'cmd.exe',
        childProcess: 'powershell.exe',
        pid: 4092,
      });

      // Verify stored document in MongoDB
      const stored = await SecurityEvent.findById(res.body.eventId);
      expect(stored).not.toBeNull();
      expect(stored?.source).toBe('edr-agent-01');
      expect(stored?.eventType).toBe('SUSPICIOUS_PROCESS_EXECUTION');
    });

    it('defaults timestamp to current time if omitted from payload', async () => {
      const token = await createTestUser('ADMIN', 'admin_notime');
      const beforeTime = new Date(Date.now() - 1000);

      const res = await request(app)
        .post('/api/events/ingest')
        .set('Authorization', `Bearer ${token}`)
        .send({
          source: 'suricata-ids',
          eventType: 'DNS_EXFILTRATION',
          severity: 'CRITICAL',
          sourceIp: '172.16.0.88',
          destinationIp: '8.8.8.8',
          protocol: 'UDP',
          message: 'Abnormally high volume of TXT records queried',
        });

      expect(res.status).toBe(201);
      expect(res.body.eventId).toBeDefined();
      const eventTimestamp = new Date(res.body.event.timestamp);
      expect(eventTimestamp.getTime()).toBeGreaterThanOrEqual(beforeTime.getTime());
    });

    it('redacts sensitive keys (password, token, apiKey, secret) in metadata', async () => {
      const token = await createTestUser('ADMIN', 'admin_sensitive');

      const res = await request(app)
        .post('/api/events/ingest')
        .set('Authorization', `Bearer ${token}`)
        .send({
          source: 'auth-gateway',
          eventType: 'AUTH_ATTEMPT',
          severity: 'LOW',
          message: 'User authentication probe',
          metadata: {
            username: 'alice',
            password: 'SuperSecretPassword123!',
            token: 'jwt-bearer-token-string',
            apiKey: 'sk-live-1234567890',
            clientVersion: '1.2.0',
            nested: {
              passwordHash: '$2b$10$abcdef',
            },
          },
        });

      expect(res.status).toBe(201);
      expect(res.body.event.metadata.password).toBe('[REDACTED]');
      expect(res.body.event.metadata.token).toBe('[REDACTED]');
      expect(res.body.event.metadata.apiKey).toBe('[REDACTED]');
      expect(res.body.event.metadata.clientVersion).toBe('1.2.0');
      expect(res.body.event.metadata.nested.passwordHash).toBe('[REDACTED]');

      // Check stored DB document
      const stored = await SecurityEvent.findById(res.body.eventId);
      expect(stored?.metadata?.password).toBe('[REDACTED]');
      expect(stored?.metadata?.token).toBe('[REDACTED]');
    });
  });

  describe('Validation & Error Handling', () => {
    it('rejects payload with invalid severity enum', async () => {
      const token = await createTestUser('ADMIN', 'admin_val_sev');

      const res = await request(app)
        .post('/api/events/ingest')
        .set('Authorization', `Bearer ${token}`)
        .send({
          source: 'firewall',
          eventType: 'PORT_SCAN',
          severity: 'SUPER_CRITICAL',
        });

      expect(res.status).toBe(400);
      expect(res.body.error).toBe('Invalid security event data.');
    });

    it('rejects payload with invalid sourceIp format', async () => {
      const token = await createTestUser('ADMIN', 'admin_val_ip');

      const res = await request(app)
        .post('/api/events/ingest')
        .set('Authorization', `Bearer ${token}`)
        .send({
          source: 'firewall',
          eventType: 'PORT_SCAN',
          severity: 'HIGH',
          sourceIp: '999.999.999.999',
        });

      expect(res.status).toBe(400);
      expect(res.body.error).toBe('Invalid security event data.');
    });

    it('rejects payload with invalid port numbers', async () => {
      const token = await createTestUser('ADMIN', 'admin_val_port');

      const res = await request(app)
        .post('/api/events/ingest')
        .set('Authorization', `Bearer ${token}`)
        .send({
          source: 'firewall',
          eventType: 'PORT_SCAN',
          severity: 'HIGH',
          destinationPort: 70000,
        });

      expect(res.status).toBe(400);
    });

    it('rejects payload with missing or empty source', async () => {
      const token = await createTestUser('ADMIN', 'admin_val_src');

      const res = await request(app)
        .post('/api/events/ingest')
        .set('Authorization', `Bearer ${token}`)
        .send({
          source: '   ',
          eventType: 'PORT_SCAN',
          severity: 'HIGH',
        });

      expect(res.status).toBe(400);
    });

    it('rejects payload with missing or empty eventType', async () => {
      const token = await createTestUser('ADMIN', 'admin_val_evt');

      const res = await request(app)
        .post('/api/events/ingest')
        .set('Authorization', `Bearer ${token}`)
        .send({
          source: 'firewall',
          eventType: '',
          severity: 'HIGH',
        });

      expect(res.status).toBe(400);
    });

    it('rejects payload with unparseable timestamp', async () => {
      const token = await createTestUser('ADMIN', 'admin_val_time');

      const res = await request(app)
        .post('/api/events/ingest')
        .set('Authorization', `Bearer ${token}`)
        .send({
          timestamp: 'invalid-date-string',
          source: 'firewall',
          eventType: 'PORT_SCAN',
          severity: 'HIGH',
        });

      expect(res.status).toBe(400);
    });
  });

  describe('Authentication and RBAC Controls', () => {
    it('rejects unauthenticated requests with 401', async () => {
      const res = await request(app)
        .post('/api/events/ingest')
        .send({
          source: 'sensor',
          eventType: 'PING',
          severity: 'LOW',
        });

      expect(res.status).toBe(401);
    });

    it('rejects VIEWER role with 403 Forbidden', async () => {
      const token = await createTestUser('VIEWER', 'viewer_no_ingest');

      const res = await request(app)
        .post('/api/events/ingest')
        .set('Authorization', `Bearer ${token}`)
        .send({
          source: 'sensor',
          eventType: 'PING',
          severity: 'LOW',
        });

      expect(res.status).toBe(403);
    });

    it('allows SOC_ANALYST to ingest telemetry', async () => {
      const token = await createTestUser('SOC_ANALYST', 'analyst_allowed');

      const res = await request(app)
        .post('/api/events/ingest')
        .set('Authorization', `Bearer ${token}`)
        .send({
          source: 'waf',
          eventType: 'SQL_INJECTION',
          severity: 'HIGH',
          sourceIp: '203.0.113.195',
          message: 'UNION SELECT injection attempt',
        });

      expect(res.status).toBe(201);
      expect(res.body.eventId).toBeDefined();
    });

    it('allows ADMIN to ingest telemetry', async () => {
      const token = await createTestUser('ADMIN', 'admin_allowed');

      const res = await request(app)
        .post('/api/events/ingest')
        .set('Authorization', `Bearer ${token}`)
        .send({
          source: 'syslog',
          eventType: 'SERVICE_STOPPED',
          severity: 'MEDIUM',
          message: 'Defender service stopped unexpectedly',
        });

      expect(res.status).toBe(201);
      expect(res.body.eventId).toBeDefined();
    });
  });

  describe('Integration with Detection Engine and Event Retrieval', () => {
    it('evaluates detection rules and generates alerts on ingested telemetry', async () => {
      const token = await createTestUser('ADMIN', 'admin_rule_test');

      // Create detection rule
      await DetectionRule.create({
        name: 'Ransomware Extension Detected',
        description: 'Detect ransomware activity',
        ruleType: 'EVENT_MATCH',
        enabled: true,
        severity: 'CRITICAL',
        riskScore: 95,
        conditions: {
          field: 'eventType',
          operator: 'EQUALS',
          value: 'RANSOMWARE_BEHAVIOR',
        },
        createdBy: 'admin',
      });

      const res = await request(app)
        .post('/api/events/ingest')
        .set('Authorization', `Bearer ${token}`)
        .send({
          source: 'endpoint-sentinel',
          eventType: 'RANSOMWARE_BEHAVIOR',
          severity: 'CRITICAL',
          sourceIp: '10.10.10.50',
          username: 'ceo_workstation',
          message: 'Mass file extension alteration to .locked detected',
        });

      expect(res.status).toBe(201);
      expect(res.body.alerts).toBeDefined();
      expect(res.body.alerts.length).toBe(1);
      expect(res.body.alerts[0].title).toContain('Ransomware Extension Detected');
      expect(res.body.alerts[0].severity).toBe('CRITICAL');
      expect(res.body.alerts[0].riskScore).toBe(95);

      // Verify alert stored in DB
      const alertInDb = await Alert.findOne({ eventId: res.body.eventId });
      expect(alertInDb).not.toBeNull();
      expect(alertInDb?.status).toBe('NEW');
    });

    it('allows single event retrieval via GET /api/events/:id', async () => {
      const adminToken = await createTestUser('ADMIN', 'admin_fetch_one');
      const viewerToken = await createTestUser('VIEWER', 'viewer_fetch_one');

      const ingestRes = await request(app)
        .post('/api/events/ingest')
        .set('Authorization', `Bearer ${adminToken}`)
        .send({
          source: 'zeek-ids',
          eventType: 'SSH_BRUTE_FORCE',
          severity: 'HIGH',
          sourceIp: '198.51.100.23',
          destinationIp: '10.0.1.5',
          destinationPort: 22,
          protocol: 'TCP',
          username: 'root',
          message: 'Failed SSH attempts',
        });

      const eventId = ingestRes.body.eventId;

      // Admin retrieves full event
      const adminGetRes = await request(app)
        .get(`/api/events/${eventId}`)
        .set('Authorization', `Bearer ${adminToken}`);

      expect(adminGetRes.status).toBe(200);
      expect(adminGetRes.body.event.id).toBe(eventId);
      expect(adminGetRes.body.event.sourceIp).toBe('198.51.100.23');

      // Viewer retrieves sanitized event (no sourceIp for viewer)
      const viewerGetRes = await request(app)
        .get(`/api/events/${eventId}`)
        .set('Authorization', `Bearer ${viewerToken}`);

      expect(viewerGetRes.status).toBe(200);
      expect(viewerGetRes.body.event.id).toBe(eventId);
      expect(viewerGetRes.body.event.sourceIp).toBeUndefined();
      expect(viewerGetRes.body.event.message).toBe('Failed SSH attempts');
    });
  });
});

