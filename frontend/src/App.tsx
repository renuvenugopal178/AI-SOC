import { useEffect, useMemo, useState } from 'react';
import { AuthPage } from './pages/AuthPage';
import { DashboardPage } from './pages/DashboardPage';
import {
  fetchCurrentUser,
  getStoredUser,
  getStoredToken,
  loginUser,
  logoutClient,
  registerUser,
  type AuthUser,
} from './services/auth';

const roleNavMap: Record<AuthUser['role'], string[]> = {
  ADMIN: ['Dashboard', 'Users', 'Detection Rules', 'Incidents', 'Events'],
  SOC_ANALYST: ['Dashboard', 'Events', 'Alerts', 'Incidents'],
  VIEWER: ['Dashboard', 'Events'],
};

export default function App() {
  const [authMode, setAuthMode] = useState<'login' | 'register'>('login');
  const [user, setUser] = useState<AuthUser | null>(getStoredUser());
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const token = getStoredToken();

  useEffect(() => {
    const hydrateSession = async () => {
      if (!token) {
        setLoading(false);
        return;
      }

      try {
        const result = await fetchCurrentUser(token);

        if (result.ok && result.data?.user) {
          setUser(result.data.user);
          localStorage.setItem(
            'ai-soc-user',
            JSON.stringify(result.data.user),
          );
        } else {
          logoutClient();
          setUser(null);
        }
      } catch {
        logoutClient();
        setUser(null);
      } finally {
        setLoading(false);
      }
    };

    void hydrateSession();
  }, [token]);

  const navItems = useMemo(() => {
    if (!user) {
      return [];
    }

    return roleNavMap[user.role] ?? ['Dashboard'];
  }, [user]);

  const handleLogin = async (email: string, password: string) => {
    setError(null);

    const result = await loginUser({
      email,
      password,
    });

    if (!result.ok) {
      setError(result.error || 'Unable to sign in.');
      return false;
    }

    if (!result.data?.user) {
      setError('Login succeeded but user data was not returned.');
      return false;
    }

    setUser(result.data.user);
    return true;
  };

  const handleRegister = async (input: {
    username: string;
    email: string;
    password: string;
    role: AuthUser['role'];
  }) => {
    setError(null);

    const result = await registerUser(input);

    if (!result.ok) {
      setError(result.error || 'Registration failed.');
      return false;
    }

    const loginResult = await loginUser({
      email: input.email,
      password: input.password,
    });

    if (!loginResult.ok) {
      setError('Registration succeeded, but sign-in failed.');
      return false;
    }

    if (!loginResult.data?.user) {
      setError('Registration succeeded, but user data was not returned.');
      return false;
    }

    setUser(loginResult.data.user);
    return true;
  };

  const handleLogout = () => {
    logoutClient();
    setUser(null);
    setAuthMode('login');
  };

  if (loading) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-slate-950 text-slate-100">
        <div className="rounded-xl border border-slate-700 bg-slate-900 px-6 py-4 text-slate-200">
          Loading session...
        </div>
      </div>
    );
  }

  if (!user) {
    return (
      <AuthPage
        authMode={authMode}
        onModeChange={setAuthMode}
        onLogin={handleLogin}
        onRegister={handleRegister}
        error={error}
      />
    );
  }

  return (
    <DashboardPage
      user={user}
      navItems={navItems}
      onLogout={handleLogout}
      apiError={error}
    />
  );
}