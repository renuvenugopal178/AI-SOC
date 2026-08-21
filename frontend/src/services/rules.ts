import { API_BASE } from './auth';

export type RuleSeverity = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
export type RuleType = 'EVENT_MATCH' | 'THRESHOLD';
export type RuleOperator = 'EQUALS' | 'NOT_EQUALS' | 'CONTAINS' | 'STARTS_WITH' | 'GREATER_THAN' | 'LESS_THAN';

export type DetectionRule = {
  id: string;
  name: string;
  description?: string;
  ruleType: RuleType;
  severity: RuleSeverity;
  riskScore: number;
  enabled: boolean;
  conditions: {
    field: string;
    operator: RuleOperator;
    value?: string | number | boolean | null;
    threshold?: number;
    windowMinutes?: number;
  };
  createdBy?: string;
  createdAt?: string;
  updatedAt?: string;
};

export type RuleInput = {
  name: string;
  description?: string;
  ruleType: RuleType;
  severity: RuleSeverity;
  riskScore: number;
  enabled: boolean;
  conditions: DetectionRule['conditions'];
};

type RulesResponse = { rules: DetectionRule[]; total: number; totalPages: number };

const request = async <T>(token: string, path: string, options?: RequestInit): Promise<T> => {
  const response = await fetch(`${API_BASE}${path}`, {
    ...options,
    headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}`, ...options?.headers },
  });
  const data = (await response.json()) as T & { error?: string };
  if (!response.ok) throw new Error(data.error || 'Unable to complete rules request.');
  return data;
};

export const fetchRules = (token: string) => request<RulesResponse>(token, '/rules?limit=100');
export const createRule = (token: string, input: RuleInput) => request<{ rule: DetectionRule }>(token, '/rules', { method: 'POST', body: JSON.stringify(input) });
export const updateRule = (token: string, id: string, input: Partial<RuleInput>) => request<{ rule: DetectionRule }>(token, `/rules/${id}`, { method: 'PATCH', body: JSON.stringify(input) });
export const deleteRule = (token: string, id: string) => request<{ ruleId: string }>(token, `/rules/${id}`, { method: 'DELETE' });