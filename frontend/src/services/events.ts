import { API_BASE } from './auth';
import type { SecuritySeverity } from './dashboard';

export type SecurityEventRecord = {
  id: string;
  timestamp: string;
  source: string;
  eventType: string;
  severity: SecuritySeverity;
  sourceIp?: string | null;
  destinationIp?: string | null;
  protocol?: string | null;
  username?: string | null;
  action?: string | null;
  message?: string | null;
};

export type EventsResponse = {
  events: SecurityEventRecord[];
  page: number;
  limit: number;
  total: number;
  totalPages: number;
};

export const fetchEvents = async (token: string, page: number, limit = 20): Promise<EventsResponse> => {
  const response = await fetch(`${API_BASE}/events?page=${page}&limit=${limit}`, {
    headers: { Authorization: `Bearer ${token}` },
  });
  const data = (await response.json()) as EventsResponse & { error?: string };

  if (!response.ok) {
    throw new Error(data.error || 'Unable to load security events.');
  }

  return data;
};