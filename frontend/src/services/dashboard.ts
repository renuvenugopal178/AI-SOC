import { API_BASE } from './auth';

export type SecuritySeverity = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
export type AlertStatus = 'NEW' | 'ACKNOWLEDGED' | 'RESOLVED';

export type SecurityEvent = {
  id: string;
  timestamp: string;
  source: string;
  eventType: string;
  severity: SecuritySeverity;
  sourceIp?: string | null;
  username?: string | null;
  action?: string | null;
  message?: string | null;
};

export type Alert = {
  id: string;
  title: string;
  description: string;
  severity: SecuritySeverity;
  riskScore: number;
  status: AlertStatus;
  source?: string | null;
  eventType?: string | null;
  triggeredAt: string;
};

type CollectionResponse<T> = {
  [key: string]: T[] | number;
  total: number;
};

export type DashboardData = {
  totalEvents: number;
  totalAlerts: number;
  criticalAlerts: number;
  highAlerts: number;
  newAlerts: number;
  recentEvents: SecurityEvent[];
  recentAlerts: Alert[];
};

const getCollection = async <T>(
  path: string,
  collectionKey: 'events' | 'alerts',
  token: string,
): Promise<{ items: T[]; total: number }> => {
  const response = await fetch(`${API_BASE}${path}`, {
    headers: { Authorization: `Bearer ${token}` },
  });
  const data = (await response.json()) as CollectionResponse<T> & { error?: string };

  if (!response.ok) {
    throw new Error(data.error || 'Unable to load dashboard data.');
  }

  return {
    items: Array.isArray(data[collectionKey]) ? data[collectionKey] as T[] : [],
    total: data.total,
  };
};

export const fetchDashboardData = async (token: string): Promise<DashboardData> => {
  const [events, alerts, criticalAlerts, highAlerts, newAlerts, recentEvents, recentAlerts] = await Promise.all([
    getCollection<SecurityEvent>('/events?limit=1', 'events', token),
    getCollection<Alert>('/alerts?limit=1', 'alerts', token),
    getCollection<Alert>('/alerts?severity=CRITICAL&limit=1', 'alerts', token),
    getCollection<Alert>('/alerts?severity=HIGH&limit=1', 'alerts', token),
    getCollection<Alert>('/alerts?status=NEW&limit=1', 'alerts', token),
    getCollection<SecurityEvent>('/events?limit=5', 'events', token),
    getCollection<Alert>('/alerts?limit=5', 'alerts', token),
  ]);

  return {
    totalEvents: events.total,
    totalAlerts: alerts.total,
    criticalAlerts: criticalAlerts.total,
    highAlerts: highAlerts.total,
    newAlerts: newAlerts.total,
    recentEvents: recentEvents.items,
    recentAlerts: recentAlerts.items,
  };
};