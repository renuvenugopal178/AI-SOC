import request from 'supertest';
import mongoose from 'mongoose';
import bcrypt from 'bcrypt';
import http from 'http';
import app from '../app';
import User from '../models/User';
import AuditLog from '../models/AuditLog';
import SecurityEvent from '../models/SecurityEvent';
import DetectionRule from '../models/DetectionRule';
import Alert from '../models/Alert';
import {
  SCENARIO_DEFINITIONS,
  getScenarioEvents,
  normalizeApiUrl,
  loginAndGetToken,
  dispatchSimulationEvent,
  runSimulation,
  ScenarioType,
} from '../simulator/telemetrySimulator';
import { securityEventSchema } from '../validation/securityEvent';

const createAdminToken = async () => {
  const email = 'sim_admin@ai-soc.local';
  const username = 'sim_admin';

  await User.create({
    username,
    email,
    passwordHash: await bcrypt.hash('Password123!', 10),
    role: 'ADMIN',
    isActive: true,
  });

  const loginRes = await request(app)
    .post('/api/auth/login')
    .send({ email, password: 'Password123!' });

  return { token: loginRes.body.token as string, email, password: 'Password123!' };
};

describe('SOC Telemetry Simulator', () => {
  let server: http.Server;
  let serverUrl: string;

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

    // Start an in-process HTTP server on an ephemeral port for testing fetch-based simulator functions
    await new Promise<void>((resolve) => {
      server = app.listen(0, () => {
        const address = server.address();
        if (address && typeof address === 'object') {
          serverUrl = `http://127.0.0.1:${address.port}`;
        }
        resolve();
      });
    });
  });

  beforeEach(async () => {
    await User.deleteMany({});
    await AuditLog.deleteMany({});
    await SecurityEvent.deleteMany({});
    await DetectionRule.deleteMany({});
    await Alert.deleteMany({});
  });

  afterAll(async () => {
    await new Promise<void>((resolve) => {
      if (server) {
        server.close(() => resolve());
      } else {
        resolve();
      }
    });
    await mongoose.disconnect();
  });

  describe('1. Scenario Generator & Payload Validation', () => {
    const scenarioKeys: Array<Exclude<ScenarioType, 'ALL'>> = [
      'NORMAL_ACTIVITY',
      'BRUTE_FORCE',
      'PORT_SCAN',
      'CRITICAL_EVENT',
      'UNAUTHORIZED_ACCESS',
    ];

    it('contains all 5 required scenario definitions', () => {
      for (const key of scenarioKeys) {
        expect(SCENARIO_DEFINITIONS[key]).toBeDefined();
        expect(SCENARIO_DEFINITIONS[key].name).toBe(key);
        expect(typeof SCENARIO_DEFINITIONS[key].description).toBe('string');
      }
    });

    it('all generated scenario events adhere to securityEventSchema and include simulation metadata', () => {
      for (const key of scenarioKeys) {
        const events = SCENARIO_DEFINITIONS[key].generateEvents();
        expect(events.length).toBeGreaterThan(0);

        for (const evt of events) {
          const parsed = securityEventSchema.safeParse(evt);
          expect(parsed.success).toBe(true);

          expect(evt.metadata).toBeDefined();
          expect(evt.metadata?.simulated).toBe(true);
          expect(evt.metadata?.simulator).toBe('ai-soc-local');
          expect(evt.metadata?.scenario).toBe(key);

          // Ensure IP addresses are private or documentation ranges
          if (evt.sourceIp) {
            const isPrivateOrDoc =
              evt.sourceIp.startsWith('10.') ||
              evt.sourceIp.startsWith('172.16.') ||
              evt.sourceIp.startsWith('192.168.') ||
              evt.sourceIp.startsWith('192.0.2.') ||
              evt.sourceIp.startsWith('198.51.100.') ||
              evt.sourceIp.startsWith('203.0.113.');
            expect(isPrivateOrDoc).toBe(true);
          }
        }
      }
    });

    it('getScenarioEvents returns all events when ALL is requested', () => {
      const allEvents = getScenarioEvents('ALL');
      expect(allEvents.length).toBe(11); // 3 normal + 5 brute force + 1 port scan + 1 critical + 1 unauthorized
      const scenariosFound = new Set(allEvents.map((e) => e.scenario));
      expect(scenariosFound.size).toBe(5);
    });

    it('getScenarioEvents throws error for unknown scenario', () => {
      expect(() => getScenarioEvents('INVALID_SCENARIO' as any)).toThrow(
        'Unknown scenario "INVALID_SCENARIO"'
      );
    });

    it('normalizeApiUrl cleans trailing slashes and redundant /api path', () => {
      expect(normalizeApiUrl('http://localhost:4000/')).toBe('http://localhost:4000');
      expect(normalizeApiUrl('http://localhost:4000/api/')).toBe('http://localhost:4000');
      expect(normalizeApiUrl('http://localhost:4000/api')).toBe('http://localhost:4000');
      expect(normalizeApiUrl('http://localhost:4000')).toBe('http://localhost:4000');
    });
  });

  describe('2. End-to-End Scenario Ingestion & Detection Verification', () => {
    let token: string;

    beforeEach(async () => {
      const auth = await createAdminToken();
      token = auth.token;

      // Seed baseline detection rules
      await DetectionRule.create([
        {
          name: 'Multiple Failed Login Attempts',
          description: 'Detect repeated failed logins within a short time window.',
          ruleType: 'THRESHOLD',
          enabled: true,
          severity: 'HIGH',
          riskScore: 70,
          conditions: {
            field: 'eventType',
            operator: 'EQUALS',
            value: 'LOGIN_FAILED',
            threshold: 5,
            windowMinutes: 5,
          },
          createdBy: 'system',
        },
        {
          name: 'Critical Security Event',
          description: 'Trigger on critical severity security events.',
          ruleType: 'EVENT_MATCH',
          enabled: true,
          severity: 'CRITICAL',
          riskScore: 90,
          conditions: {
            field: 'severity',
            operator: 'EQUALS',
            value: 'CRITICAL',
          },
          createdBy: 'system',
        },
        {
          name: 'Suspicious Network Scan',
          description: 'Trigger on port scan activity from external sources.',
          ruleType: 'EVENT_MATCH',
          enabled: true,
          severity: 'HIGH',
          riskScore: 80,
          conditions: {
            field: 'eventType',
            operator: 'EQUALS',
            value: 'PORT_SCAN',
          },
          createdBy: 'system',
        },
      ]);
    });

    it('NORMAL_ACTIVITY generates 3 events and 0 alerts', async () => {
      const events = SCENARIO_DEFINITIONS.NORMAL_ACTIVITY.generateEvents();
      expect(events.length).toBe(3);

      for (const evt of events) {
        const res = await request(app)
          .post('/api/events/ingest')
          .set('Authorization', `Bearer ${token}`)
          .send(evt);

        expect(res.status).toBe(201);
        expect(res.body.alerts.length).toBe(0);
      }

      const totalAlerts = await Alert.countDocuments({});
      expect(totalAlerts).toBe(0);
    });

    it('BRUTE_FORCE generates 5 events and triggers the Multiple Failed Login Attempts rule on the 5th attempt', async () => {
      const events = SCENARIO_DEFINITIONS.BRUTE_FORCE.generateEvents();
      expect(events.length).toBe(5);

      let lastRes: any;
      for (let i = 0; i < events.length; i++) {
        const res = await request(app)
          .post('/api/events/ingest')
          .set('Authorization', `Bearer ${token}`)
          .send(events[i]);

        expect(res.status).toBe(201);
        lastRes = res;
      }

      expect(lastRes.body.alerts.length).toBe(1);
      expect(lastRes.body.alerts[0].title).toContain('Multiple Failed Login Attempts');
      expect(lastRes.body.alerts[0].severity).toBe('HIGH');
      expect(lastRes.body.alerts[0].riskScore).toBe(70);

      const alertInDb = await Alert.findOne({ eventId: lastRes.body.eventId });
      expect(alertInDb).not.toBeNull();
    });

    it('PORT_SCAN generates 1 event and triggers the Suspicious Network Scan rule', async () => {
      const events = SCENARIO_DEFINITIONS.PORT_SCAN.generateEvents();
      expect(events.length).toBe(1);

      const res = await request(app)
        .post('/api/events/ingest')
        .set('Authorization', `Bearer ${token}`)
        .send(events[0]);

      expect(res.status).toBe(201);
      expect(res.body.alerts.length).toBe(1);
      expect(res.body.alerts[0].title).toContain('Suspicious Network Scan');
      expect(res.body.alerts[0].severity).toBe('HIGH');
      expect(res.body.alerts[0].riskScore).toBe(80);
    });

    it('CRITICAL_EVENT generates 1 event and triggers the Critical Security Event rule', async () => {
      const events = SCENARIO_DEFINITIONS.CRITICAL_EVENT.generateEvents();
      expect(events.length).toBe(1);

      const res = await request(app)
        .post('/api/events/ingest')
        .set('Authorization', `Bearer ${token}`)
        .send(events[0]);

      expect(res.status).toBe(201);
      expect(res.body.alerts.length).toBe(1);
      expect(res.body.alerts[0].title).toContain('Critical Security Event');
      expect(res.body.alerts[0].severity).toBe('CRITICAL');
      expect(res.body.alerts[0].riskScore).toBe(90);
    });

    it('UNAUTHORIZED_ACCESS generates 1 event with proper access denied telemetry', async () => {
      const events = SCENARIO_DEFINITIONS.UNAUTHORIZED_ACCESS.generateEvents();
      expect(events.length).toBe(1);

      const res = await request(app)
        .post('/api/events/ingest')
        .set('Authorization', `Bearer ${token}`)
        .send(events[0]);

      expect(res.status).toBe(201);
      expect(res.body.event.eventType).toBe('UNAUTHORIZED_ACCESS');
      expect(res.body.event.action).toBe('ACCESS_DENIED');
    });
  });

  describe('3. Simulator Dispatcher & Client Functions', () => {
    it('loginAndGetToken authenticates valid credentials and returns JWT token', async () => {
      const auth = await createAdminToken();
      const fetchedToken = await loginAndGetToken(serverUrl, auth.email, auth.password);

      expect(fetchedToken).toBeDefined();
      expect(typeof fetchedToken).toBe('string');
      expect(fetchedToken.length).toBeGreaterThan(20);
    });

    it('loginAndGetToken throws clear error without exposing password on bad credentials', async () => {
      await createAdminToken();
      await expect(
        loginAndGetToken(serverUrl, 'sim_admin@ai-soc.local', 'WrongPassword123!')
      ).rejects.toThrow('Login failed for "sim_admin@ai-soc.local"');
    });

    it('dispatchSimulationEvent sends event to running server and captures alert metadata', async () => {
      const auth = await createAdminToken();
      await DetectionRule.create({
        name: 'Critical Security Event',
        description: 'Trigger on critical',
        ruleType: 'EVENT_MATCH',
        enabled: true,
        severity: 'CRITICAL',
        riskScore: 90,
        conditions: { field: 'severity', operator: 'EQUALS', value: 'CRITICAL' },
        createdBy: 'system',
      });

      const eventPayload = SCENARIO_DEFINITIONS.CRITICAL_EVENT.generateEvents()[0];
      const result = await dispatchSimulationEvent(
        serverUrl,
        auth.token,
        'CRITICAL_EVENT',
        eventPayload
      );

      expect(result.success).toBe(true);
      expect(result.statusCode).toBe(201);
      expect(result.eventId).toBeDefined();
      expect(result.alertsGenerated).toBe(1);
      expect(result.alertTitles[0]).toContain('Critical Security Event');
    });

    it('runSimulation executes all scenarios and returns complete simulation summary', async () => {
      const auth = await createAdminToken();
      // Seed rules
      await DetectionRule.create([
        {
          name: 'Multiple Failed Login Attempts',
          description: '5 failed logins',
          ruleType: 'THRESHOLD',
          enabled: true,
          severity: 'HIGH',
          riskScore: 70,
          conditions: {
            field: 'eventType',
            operator: 'EQUALS',
            value: 'LOGIN_FAILED',
            threshold: 5,
            windowMinutes: 5,
          },
          createdBy: 'system',
        },
        {
          name: 'Suspicious Network Scan',
          description: 'port scan',
          ruleType: 'EVENT_MATCH',
          enabled: true,
          severity: 'HIGH',
          riskScore: 80,
          conditions: { field: 'eventType', operator: 'EQUALS', value: 'PORT_SCAN' },
          createdBy: 'system',
        },
        {
          name: 'Critical Security Event',
          description: 'critical severity',
          ruleType: 'EVENT_MATCH',
          enabled: true,
          severity: 'CRITICAL',
          riskScore: 90,
          conditions: { field: 'severity', operator: 'EQUALS', value: 'CRITICAL' },
          createdBy: 'system',
        },
      ]);

      const dispatchedItems: string[] = [];
      const summary = await runSimulation({
        apiUrl: serverUrl,
        token: auth.token,
        scenario: 'ALL',
        delayMs: 10,
        onEventDispatched: (res) => {
          dispatchedItems.push(res.eventType);
        },
      });

      expect(summary.totalEvents).toBe(11);
      expect(summary.successfulEvents).toBe(11);
      expect(summary.failedEvents).toBe(0);
      expect(summary.totalAlerts).toBe(3); // 1 from BRUTE_FORCE (5th attempt), 1 from PORT_SCAN, 1 from CRITICAL_EVENT
      expect(dispatchedItems.length).toBe(11);
    });
  });
});

