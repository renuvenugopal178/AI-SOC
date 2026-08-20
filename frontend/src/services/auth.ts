export type AuthRole = 'ADMIN' | 'SOC_ANALYST' | 'VIEWER';

export type AuthUser = {
  id: string;
  username: string;
  email: string;
  role: AuthRole;
  isActive: boolean;
  createdAt?: string;
  updatedAt?: string;
  lastLoginAt?: string | null;
};

export type AuthResponse = {
  token: string;
  user: AuthUser;
};

const API_BASE = 'http://localhost:4000/api';

const getStoredToken = () => localStorage.getItem('ai-soc-token');

const storeSession = (token: string, user: AuthUser) => {
  localStorage.setItem('ai-soc-token', token);
  localStorage.setItem('ai-soc-user', JSON.stringify(user));
};

const logoutClient = () => {
  localStorage.removeItem('ai-soc-token');
  localStorage.removeItem('ai-soc-user');
};

const getStoredUser = (): AuthUser | null => {
  const raw = localStorage.getItem('ai-soc-user');
  if (!raw) return null;

  try {
    return JSON.parse(raw) as AuthUser;
  } catch {
    return null;
  }
};

const ensureJsonResult = async <T>(response: Response): Promise<{ ok: boolean; data?: T; error?: string }> => {
  try {
    const data = (await response.json()) as T & { error?: string; details?: unknown };

    if (!response.ok) {
      const errorMessage =
        typeof (data as { error?: string }).error === 'string'
          ? (data as { error?: string }).error
          : 'Request failed.';
      return { ok: false, error: errorMessage };
    }

    return { ok: true, data };
  } catch {
    return { ok: false, error: 'Request failed.' };
  }
};

const loginUser = async (input: { email: string; password: string }) => {
  const response = await fetch(`${API_BASE}/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(input),
  });

  const result = await ensureJsonResult<AuthResponse>(response);
  if (result.ok && result.data) {
    storeSession(result.data.token, result.data.user);
  }

  return result;
};

const registerUser = async (input: {
  username: string;
  email: string;
  password: string;
  role: AuthRole;
}) => {
  const response = await fetch(`${API_BASE}/auth/register`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(input),
  });

  return ensureJsonResult<{ user: AuthUser }>(response);
};

const fetchCurrentUser = async (token: string) => {
  const response = await fetch(`${API_BASE}/auth/me`, {
    method: 'GET',
    headers: { Authorization: `Bearer ${token}` },
  });

  return ensureJsonResult<{ user: AuthUser }>(response);
};

export { API_BASE, fetchCurrentUser, getStoredToken, getStoredUser, loginUser, logoutClient, registerUser, storeSession };
