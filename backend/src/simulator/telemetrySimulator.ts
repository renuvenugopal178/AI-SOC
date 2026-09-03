import { securityEventSchema } from '../validation/securityEvent';

export type ScenarioType =
  | 'NORMAL_ACTIVITY'
  | 'BRUTE_FORCE'
  | 'PORT_SCAN'
  | 'CRITICAL_EVENT'
  | 'UNAUTHORIZED_ACCESS'
  | 'ALL';

export interface SimulatedEventPayload {
  timestamp?: string;
  source: string;
  eventType: string;
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  sourceIp?: string;
  destinationIp?: string;
  sourcePort?: number;
  destinationPort?: number;
  protocol?: string;
  username?: string;
  action?: string;
  message?: string;
  metadata?: Record<string, unknown>;
}

export interface ScenarioDefinition {
  name: Exclude<ScenarioType, 'ALL'>;
  description: string;
  generateEvents: () => SimulatedEventPayload[];
}

export const SCENARIO_DEFINITIONS: Record<Exclude<ScenarioType, 'ALL'>, ScenarioDefinition> = {
  NORMAL_ACTIVITY: {
    name: 'NORMAL_ACTIVITY',
    description: 'Routine benign user authentication and internal network queries.',
    generateEvents: () => [
      {
        timestamp: new Date().toISOString(),
        source: 'auth-service',
        eventType: 'LOGIN_SUCCESS',
        severity: 'LOW',
        sourceIp: '192.168.1.105',
        destinationIp: '10.0.0.10',
        destinationPort: 443,
        protocol: 'TCP',
        username: 'analyst_alice',
        action: 'USER_LOGIN',
        message: 'User analyst_alice authenticated successfully via web console.',
        metadata: {
          simulated: true,
          simulator: 'ai-soc-local',
          scenario: 'NORMAL_ACTIVITY',
          authMethod: 'password_and_totp',
        },
      },
      {
        timestamp: new Date(Date.now() + 100).toISOString(),
        source: 'perimeter-firewall',
        eventType: 'NETWORK_CONNECTION',
        severity: 'LOW',
        sourceIp: '192.168.1.105',
        destinationIp: '10.0.0.15',
        destinationPort: 8080,
        protocol: 'TCP',
        action: 'ALLOW',
        message: 'Authorized HTTP query dispatched to internal reporting service.',
        metadata: {
          simulated: true,
          simulator: 'ai-soc-local',
          scenario: 'NORMAL_ACTIVITY',
          direction: 'outbound',
        },
      },
      {
        timestamp: new Date(Date.now() + 200).toISOString(),
        source: 'auth-service',
        eventType: 'USER_LOGOUT',
        severity: 'LOW',
        sourceIp: '192.168.1.105',
        username: 'analyst_alice',
        action: 'USER_LOGOUT',
        message: 'User analyst_alice logged out gracefully.',
        metadata: {
          simulated: true,
          simulator: 'ai-soc-local',
          scenario: 'NORMAL_ACTIVITY',
          sessionDurationSeconds: 1200,
        },
      },
    ],
  },

  BRUTE_FORCE: {
    name: 'BRUTE_FORCE',
    description: 'Multiple failed login attempts from a single source IP to trigger the Multiple Failed Login Attempts rule.',
    generateEvents: () => {
      const events: SimulatedEventPayload[] = [];
      const sourceIp = '198.51.100.77'; // RFC 5737 TEST-NET-2 documentation IP
      const now = Date.now();
      for (let i = 0; i < 5; i++) {
        events.push({
          timestamp: new Date(now - (4 - i) * 1000).toISOString(),
          source: 'auth-service',
          eventType: 'LOGIN_FAILED',
          severity: 'MEDIUM',
          sourceIp,
          destinationIp: '10.0.0.10',
          destinationPort: 443,
          protocol: 'TCP',
          username: 'admin',
          action: 'AUTH_FAILED',
          message: `Failed login attempt ${i + 1} of 5 for user admin: invalid password provided.`,
          metadata: {
            simulated: true,
            simulator: 'ai-soc-local',
            scenario: 'BRUTE_FORCE',
            attemptNumber: i + 1,
            failureReason: 'invalid_password',
          },
        });
      }
      return events;
    },
  },

  PORT_SCAN: {
    name: 'PORT_SCAN',
    description: 'Reconnaissance scan across common ports to trigger the Suspicious Network Scan rule.',
    generateEvents: () => [
      {
        timestamp: new Date().toISOString(),
        source: 'network-ids',
        eventType: 'PORT_SCAN',
        severity: 'HIGH',
        sourceIp: '203.0.113.89', // RFC 5737 TEST-NET-3 documentation IP
        destinationIp: '10.0.0.50',
        destinationPort: 22,
        protocol: 'TCP',
        action: 'DETECT_SCAN',
        message: 'Sequential SYN connection attempts across 100 ports detected from external host.',
        metadata: {
          simulated: true,
          simulator: 'ai-soc-local',
          scenario: 'PORT_SCAN',
          scannedPortRange: '20-1024',
          scanType: 'SYN_STEALTH',
          probedPortsCount: 250,
        },
      },
    ],
  },

  CRITICAL_EVENT: {
    name: 'CRITICAL_EVENT',
    description: 'High-severity security event to trigger the Critical Security Event rule.',
    generateEvents: () => [
      {
        timestamp: new Date().toISOString(),
        source: 'endpoint-edr',
        eventType: 'RANSOMWARE_BEHAVIOR',
        severity: 'CRITICAL',
        sourceIp: '172.16.4.12',
        destinationIp: '10.0.0.2',
        destinationPort: 445,
        protocol: 'TCP',
        username: 'finance_station_03',
        action: 'PROCESS_BLOCKED',
        message: 'Critical: High-entropy mass file encryption and ransom note generation blocked.',
        metadata: {
          simulated: true,
          simulator: 'ai-soc-local',
          scenario: 'CRITICAL_EVENT',
          sha256: '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08',
          threatFamily: 'Ransomware.Lockbit.Variant',
          quarantined: true,
        },
      },
    ],
  },

  UNAUTHORIZED_ACCESS: {
    name: 'UNAUTHORIZED_ACCESS',
    description: 'Unauthorized access attempt against a restricted management endpoint.',
    generateEvents: () => [
      {
        timestamp: new Date().toISOString(),
        source: 'api-gateway',
        eventType: 'UNAUTHORIZED_ACCESS',
        severity: 'HIGH',
        sourceIp: '192.0.2.44', // RFC 5737 TEST-NET-1 documentation IP
        destinationIp: '10.0.0.10',
        destinationPort: 443,
        protocol: 'TCP',
        username: 'guest_user',
        action: 'ACCESS_DENIED',
        message: 'Access denied: unauthorized request made to /api/admin/system-settings by non-admin role.',
        metadata: {
          simulated: true,
          simulator: 'ai-soc-local',
          scenario: 'UNAUTHORIZED_ACCESS',
          attemptedEndpoint: '/api/admin/system-settings',
          requiredRole: 'ADMIN',
          callerRole: 'VIEWER',
        },
      },
    ],
  },
};

export const normalizeApiUrl = (apiUrl: string): string => {
  let normalized = apiUrl.trim();
  if (normalized.endsWith('/')) {
    normalized = normalized.slice(0, -1);
  }
  if (normalized.endsWith('/api')) {
    normalized = normalized.slice(0, -4);
  }
  return normalized;
};

export const getScenarioEvents = (scenario: ScenarioType): Array<{ scenario: Exclude<ScenarioType, 'ALL'>; event: SimulatedEventPayload }> => {
  if (scenario === 'ALL') {
    const allEvents: Array<{ scenario: Exclude<ScenarioType, 'ALL'>; event: SimulatedEventPayload }> = [];
    const orderedScenarios: Array<Exclude<ScenarioType, 'ALL'>> = [
      'NORMAL_ACTIVITY',
      'BRUTE_FORCE',
      'PORT_SCAN',
      'CRITICAL_EVENT',
      'UNAUTHORIZED_ACCESS',
    ];
    for (const key of orderedScenarios) {
      const scEvents = SCENARIO_DEFINITIONS[key].generateEvents();
      for (const evt of scEvents) {
        allEvents.push({ scenario: key, event: evt });
      }
    }
    return allEvents;
  }

  const def = SCENARIO_DEFINITIONS[scenario];
  if (!def) {
    throw new Error(`Unknown scenario "${scenario}". Valid scenarios are: NORMAL_ACTIVITY, BRUTE_FORCE, PORT_SCAN, CRITICAL_EVENT, UNAUTHORIZED_ACCESS, ALL.`);
  }

  return def.generateEvents().map((event) => ({ scenario, event }));
};

export interface EventDispatchResult {
  scenario: string;
  eventType: string;
  source: string;
  severity: string;
  success: boolean;
  statusCode: number;
  eventId?: string;
  alertsGenerated: number;
  alertTitles: string[];
  error?: string;
}

export interface SimulationOptions {
  apiUrl: string;
  token: string;
  scenario?: ScenarioType;
  delayMs?: number;
  onEventDispatched?: (result: EventDispatchResult, index: number, total: number) => void;
}

export interface SimulationSummary {
  scenario: ScenarioType;
  totalEvents: number;
  successfulEvents: number;
  failedEvents: number;
  totalAlerts: number;
  results: EventDispatchResult[];
}

export const dispatchSimulationEvent = async (
  apiUrl: string,
  token: string,
  scenario: string,
  eventPayload: SimulatedEventPayload
): Promise<EventDispatchResult> => {
  const base = normalizeApiUrl(apiUrl);
  const endpoint = `${base}/api/events/ingest`;

  try {
    const response = await fetch(endpoint, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${token}`,
      },
      body: JSON.stringify(eventPayload),
    });

    const statusCode = response.status;
    const data = (await response.json().catch(() => ({}))) as Record<string, any>;

    if (response.ok && statusCode === 201) {
      const alerts = Array.isArray(data.alerts) ? data.alerts : [];
      const alertTitles = alerts.map((a: any) => a.title || 'Security Alert');
      return {
        scenario,
        eventType: eventPayload.eventType,
        source: eventPayload.source,
        severity: eventPayload.severity,
        success: true,
        statusCode,
        eventId: data.eventId || data.event?.id,
        alertsGenerated: alerts.length,
        alertTitles,
      };
    }

    return {
      scenario,
      eventType: eventPayload.eventType,
      source: eventPayload.source,
      severity: eventPayload.severity,
      success: false,
      statusCode,
      alertsGenerated: 0,
      alertTitles: [],
      error: data.error || `HTTP ${statusCode} ${response.statusText}`,
    };
  } catch (err) {
    const message = err instanceof Error ? err.message : 'Network request failed';
    return {
      scenario,
      eventType: eventPayload.eventType,
      source: eventPayload.source,
      severity: eventPayload.severity,
      success: false,
      statusCode: 0,
      alertsGenerated: 0,
      alertTitles: [],
      error: message,
    };
  }
};

export const loginAndGetToken = async (
  apiUrl: string,
  email: string,
  password: string
): Promise<string> => {
  const base = normalizeApiUrl(apiUrl);
  const endpoint = `${base}/api/auth/login`;

  const response = await fetch(endpoint, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email: email.trim().toLowerCase(), password }),
  });

  const data = (await response.json().catch(() => ({}))) as Record<string, any>;

  if (!response.ok || !data.token) {
    const errorMsg = data.error || `Authentication failed with status ${response.status}`;
    throw new Error(`Login failed for "${email.trim().toLowerCase()}": ${errorMsg}`);
  }

  return data.token as string;
};

export const runSimulation = async (options: SimulationOptions): Promise<SimulationSummary> => {
  const scenario = options.scenario || 'ALL';
  const scenarioItems = getScenarioEvents(scenario);
  const results: EventDispatchResult[] = [];

  for (let i = 0; i < scenarioItems.length; i++) {
    const { scenario: itemScenario, event } = scenarioItems[i];
    const result = await dispatchSimulationEvent(
      options.apiUrl,
      options.token,
      itemScenario,
      event
    );
    results.push(result);

    if (options.onEventDispatched) {
      options.onEventDispatched(result, i + 1, scenarioItems.length);
    }

    if (options.delayMs && options.delayMs > 0 && i < scenarioItems.length - 1) {
      await new Promise((resolve) => setTimeout(resolve, options.delayMs));
    }
  }

  const successfulEvents = results.filter((r) => r.success).length;
  const failedEvents = results.filter((r) => !r.success).length;
  const totalAlerts = results.reduce((acc, r) => acc + r.alertsGenerated, 0);

  return {
    scenario,
    totalEvents: scenarioItems.length,
    successfulEvents,
    failedEvents,
    totalAlerts,
    results,
  };
};

