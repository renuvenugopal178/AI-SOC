import { API_BASE } from './auth';
import type { Alert, SecuritySeverity } from './dashboard';
import type { SecurityEventRecord } from './events';

export type IncidentStatus = 'NEW' | 'INVESTIGATING' | 'RESOLVED' | 'FALSE_POSITIVE';

export type Incident = {
  id: string;
  incidentId: string;
  title: string;
  description: string;
  severity: SecuritySeverity;
  riskScore: number;
  status: IncidentStatus;
  sourceIps: string[];
  affectedUsers: string[];
  relatedEventIds: string[];
  relatedAlertIds: string[];
  firstSeen: string;
  lastSeen: string;
  createdAt: string;
  updatedAt: string;
};

export type DetectionRule = {
  id: string;
  name: string;
  description?: string;
  severity: SecuritySeverity;
  riskScore: number;
};

export type IncidentEvidence = {
  incident: Incident;
  alerts: Alert[];
  events: SecurityEventRecord[];
  rules: DetectionRule[];
};

type IncidentResponse = { incidents: Array<Record<string, unknown>>; total: number };

const normalizeIncident = (raw: Record<string, any>): Incident => ({
  id: String(raw._id ?? raw.id),
  incidentId: raw.incidentId,
  title: raw.title,
  description: raw.description,
  severity: raw.severity,
  riskScore: raw.riskScore,
  status: raw.status,
  sourceIps: raw.sourceIps ?? [],
  affectedUsers: raw.affectedUsers ?? [],
  relatedEventIds: (raw.relatedEventIds ?? []).map(String),
  relatedAlertIds: (raw.relatedAlertIds ?? []).map(String),
  firstSeen: raw.firstSeen,
  lastSeen: raw.lastSeen,
  createdAt: raw.createdAt,
  updatedAt: raw.updatedAt,
});

const requestJson = async <T>(path: string, token: string, options?: RequestInit): Promise<T> => {
  const response = await fetch(`${API_BASE}${path}`, {
    ...options,
    headers: { Authorization: `Bearer ${token}`, ...(options?.headers ?? {}) },
  });
  const data = (await response.json()) as T & { error?: string };
  if (!response.ok) throw new Error(data.error || 'Unable to load incident data.');
  return data;
};

export const fetchIncidents = async (token: string, filters: { status?: string; severity?: string; risk?: string; time?: string }): Promise<{ incidents: Incident[]; total: number }> => {
  const params = new URLSearchParams({ limit: '100' });
  if (filters.status && filters.status !== 'ALL') params.set('status', filters.status === 'OPEN' ? 'NEW' : filters.status);
  const response = await requestJson<IncidentResponse>(`/incidents?${params.toString()}`, token);
  const now = Date.now();
  const incidents = response.incidents.map(normalizeIncident).filter((incident) => {
    if (filters.severity && filters.severity !== 'ALL' && incident.severity !== filters.severity) return false;
    if (filters.risk === 'HIGH' && incident.riskScore < 70) return false;
    if (filters.risk === 'MEDIUM' && (incident.riskScore < 40 || incident.riskScore >= 70)) return false;
    if (filters.risk === 'LOW' && incident.riskScore >= 40) return false;
    if (filters.time === '24H' && now - new Date(incident.createdAt).getTime() > 24 * 60 * 60 * 1000) return false;
    if (filters.time === '7D' && now - new Date(incident.createdAt).getTime() > 7 * 24 * 60 * 60 * 1000) return false;
    return true;
  });
  return { incidents, total: incidents.length };
};

export const updateIncidentStatus = async (token: string, id: string, status: IncidentStatus): Promise<Incident> => {
  const response = await requestJson<{ incident: Record<string, unknown> }>(`/incidents/${id}/status`, token, {
    method: 'PATCH',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ status }),
  });
  return normalizeIncident(response.incident);
};

export const fetchIncidentEvidence = async (token: string, id: string): Promise<IncidentEvidence> => {
  const detail = await requestJson<{ incident: Record<string, unknown> }>(`/incidents/${id}`, token);
  const incident = normalizeIncident(detail.incident);
  const [alertsResponse, eventsResponse, rulesResponse] = await Promise.all([
    requestJson<{ alerts: Alert[] }>('/alerts?limit=100', token),
    requestJson<{ events: SecurityEventRecord[] }>('/events?limit=100', token),
    requestJson<{ rules: DetectionRule[] }>('/rules?limit=100', token),
  ]);
  const alertIds = new Set(incident.relatedAlertIds);
  const eventIds = new Set(incident.relatedEventIds);
  const ruleIds = new Set(alertsResponse.alerts.filter((alert) => alertIds.has(alert.id)).map((alert) => alert.ruleId));
  return {
    incident,
    alerts: alertsResponse.alerts.filter((alert) => alertIds.has(alert.id)),
    events: eventsResponse.events.filter((event) => eventIds.has(event.id)),
    rules: rulesResponse.rules.filter((rule) => ruleIds.has(rule.id)),
  };
};

export const formatIncidentStatus = (status: IncidentStatus) => status === 'NEW' ? 'OPEN' : status;
