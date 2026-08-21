import { API_BASE } from './auth';
import type { Alert, AlertStatus, SecuritySeverity } from './dashboard';

export type AlertFilters = {
  severity: SecuritySeverity | 'ALL';
  status: AlertStatus | 'ALL';
};

type AlertsResponse = {
  alerts: Alert[];
  total: number;
  totalPages: number;
};

export const fetchAlerts = async (token: string, filters: AlertFilters): Promise<AlertsResponse> => {
  const params = new URLSearchParams({ limit: '100' });
  if (filters.severity !== 'ALL') params.set('severity', filters.severity);
  if (filters.status !== 'ALL') params.set('status', filters.status);

  const response = await fetch(`${API_BASE}/alerts?${params.toString()}`, {
    headers: { Authorization: `Bearer ${token}` },
  });
  const data = (await response.json()) as AlertsResponse & { error?: string };

  if (!response.ok) {
    throw new Error(data.error || 'Unable to load alerts.');
  }

  return data;
};