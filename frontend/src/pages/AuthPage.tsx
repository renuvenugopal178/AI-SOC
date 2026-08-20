import { FormEvent, useState } from 'react';

type AuthMode = 'login' | 'register';

type AuthPageProps = {
  authMode: AuthMode;
  onModeChange: (mode: AuthMode) => void;
  onLogin: (email: string, password: string) => Promise<boolean>;
  onRegister: (input: {
    username: string;
    email: string;
    password: string;
    role: 'ADMIN' | 'SOC_ANALYST' | 'VIEWER';
  }) => Promise<boolean>;
  error: string | null;
};

export function AuthPage({ authMode, onModeChange, onLogin, onRegister, error }: AuthPageProps) {
  const [username, setUsername] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [role, setRole] = useState<'VIEWER' | 'SOC_ANALYST'>('VIEWER');
  const [submitting, setSubmitting] = useState(false);

  const submit = async (event: FormEvent) => {
    event.preventDefault();
    setSubmitting(true);

    if (authMode === 'login') {
      const success = await onLogin(email, password);
      if (!success) {
        setSubmitting(false);
        return;
      }
      return;
    }

    const success = await onRegister({ username, email, password, role });
    setSubmitting(false);
    if (!success) {
      return;
    }
  };

  return (
    <div className="flex min-h-screen items-center justify-center bg-slate-950 px-4 py-10 text-slate-100">
      <div className="w-full max-w-md rounded-2xl border border-slate-800 bg-slate-900/80 p-8 shadow-2xl shadow-slate-950/60">
        <div className="mb-6 flex items-center justify-between">
          <div>
            <p className="text-xs font-semibold uppercase tracking-[0.3em] text-sky-300">AI-SOC</p>
            <h1 className="mt-2 text-2xl font-bold text-white">Secure Access</h1>
          </div>
          <div className="rounded-full border border-sky-500/30 bg-sky-500/10 px-3 py-1 text-xs text-sky-300">
            RBAC Enabled
          </div>
        </div>

        <div className="mb-6 flex rounded-xl border border-slate-700 bg-slate-950/80 p-1">
          <button
            type="button"
            onClick={() => onModeChange('login')}
            className={`flex-1 rounded-lg px-3 py-2 text-sm font-medium transition ${
              authMode === 'login' ? 'bg-sky-500 text-white' : 'text-slate-300'
            }`}
          >
            Login
          </button>
          <button
            type="button"
            onClick={() => onModeChange('register')}
            className={`flex-1 rounded-lg px-3 py-2 text-sm font-medium transition ${
              authMode === 'register' ? 'bg-sky-500 text-white' : 'text-slate-300'
            }`}
          >
            Register
          </button>
        </div>

        <form onSubmit={submit} className="space-y-4">
          {authMode === 'register' && (
            <div>
              <label className="mb-1 block text-sm text-slate-300">Username</label>
              <input
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                className="w-full rounded-xl border border-slate-700 bg-slate-950 px-3 py-2 text-white outline-none ring-0 transition focus:border-sky-500"
                placeholder="soc_analyst"
                required
              />
            </div>
          )}

          <div>
            <label className="mb-1 block text-sm text-slate-300">Email</label>
            <input
              type="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              className="w-full rounded-xl border border-slate-700 bg-slate-950 px-3 py-2 text-white outline-none ring-0 transition focus:border-sky-500"
              placeholder="name@example.com"
              required
            />
          </div>

          <div>
            <label className="mb-1 block text-sm text-slate-300">Password</label>
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              className="w-full rounded-xl border border-slate-700 bg-slate-950 px-3 py-2 text-white outline-none ring-0 transition focus:border-sky-500"
              placeholder="Minimum 8 chars"
              required
            />
          </div>

          {authMode === 'register' && (
            <div>
              <label className="mb-1 block text-sm text-slate-300">Role</label>
              <select
                value={role}
                onChange={(e) => setRole(e.target.value as 'VIEWER' | 'SOC_ANALYST')}
                className="w-full rounded-xl border border-slate-700 bg-slate-950 px-3 py-2 text-white outline-none transition focus:border-sky-500"
              >
                <option value="VIEWER">VIEWER</option>
                <option value="SOC_ANALYST">SOC_ANALYST</option>
              </select>
            </div>
          )}

          {error && <div className="rounded-lg border border-rose-500/40 bg-rose-500/10 px-3 py-2 text-sm text-rose-200">{error}</div>}

          <button
            type="submit"
            disabled={submitting}
            className="w-full rounded-xl bg-sky-500 px-4 py-3 font-semibold text-white transition hover:bg-sky-400 disabled:cursor-not-allowed disabled:opacity-60"
          >
            {submitting ? 'Please wait...' : authMode === 'login' ? 'Sign In' : 'Create Account'}
          </button>
        </form>
      </div>
    </div>
  );
}
