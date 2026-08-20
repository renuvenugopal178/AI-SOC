import type { AuthUser } from '../services/auth';

type DashboardPageProps = {
  user: AuthUser;
  navItems: string[];
  onLogout: () => void;
  apiError?: string | null;
};

export function DashboardPage({ user, navItems, onLogout, apiError }: DashboardPageProps) {
  return (
    <div className="min-h-screen bg-slate-950 text-slate-100">
      <aside className="fixed left-0 top-0 h-full w-72 border-r border-slate-800 bg-slate-900/95 p-6">
        <div className="mb-8 inline-flex items-center rounded-full border border-sky-500/40 bg-sky-500/10 px-3 py-2 text-xs font-semibold uppercase tracking-[0.25em] text-sky-300">
          AI-SOC
        </div>

        <nav className="space-y-2">
          {navItems.map((item) => (
            <button
              key={item}
              type="button"
              className="flex w-full items-center justify-between rounded-xl border border-slate-800 bg-slate-950/70 px-3 py-2 text-left text-sm text-slate-200 transition hover:border-sky-500/40 hover:text-white"
            >
              {item}
              <span className="text-xs text-slate-400">→</span>
            </button>
          ))}
        </nav>

        <div className="mt-10 rounded-xl border border-slate-800 bg-slate-950/70 p-4">
          <div className="text-xs uppercase tracking-[0.25em] text-slate-400">Signed in</div>
          <div className="mt-3 text-lg font-semibold text-white">{user.username}</div>
          <div className="text-sm text-slate-300">{user.email}</div>
          <div className="mt-2 inline-flex rounded-full border border-emerald-500/30 bg-emerald-500/10 px-2 py-1 text-xs text-emerald-300">
            {user.role}
          </div>
        </div>
      </aside>

      <main className="ml-72 min-h-screen p-8">
        <div className="mb-8 flex items-center justify-between rounded-2xl border border-slate-800 bg-slate-900/80 p-5">
          <div>
            <p className="text-sm uppercase tracking-[0.3em] text-slate-400">Operations</p>
            <h1 className="mt-2 text-3xl font-bold text-white">Dashboard</h1>
          </div>

          <button
            type="button"
            onClick={onLogout}
            className="rounded-xl border border-slate-700 bg-slate-950 px-4 py-2 text-sm font-medium text-slate-100 hover:border-sky-500/40 hover:text-sky-200"
          >
            Logout
          </button>
        </div>

        {apiError && (
          <div className="mb-6 rounded-xl border border-rose-500/40 bg-rose-500/10 px-4 py-3 text-sm text-rose-200">
            {apiError}
          </div>
        )}

        <div className="grid gap-5 md:grid-cols-2 xl:grid-cols-3">
          <div className="rounded-2xl border border-slate-800 bg-slate-900/80 p-5">
            <div className="text-sm uppercase tracking-[0.25em] text-slate-400">User</div>
            <div className="mt-4 text-2xl font-semibold text-white">{user.username}</div>
            <div className="mt-2 text-slate-300">{user.role}</div>
          </div>
          <div className="rounded-2xl border border-slate-800 bg-slate-900/80 p-5">
            <div className="text-sm uppercase tracking-[0.25em] text-slate-400">Access</div>
            <div className="mt-4 text-2xl font-semibold text-white">Protected</div>
            <div className="mt-2 text-slate-300">API authorization active</div>
          </div>
          <div className="rounded-2xl border border-slate-800 bg-slate-900/80 p-5">
            <div className="text-sm uppercase tracking-[0.25em] text-slate-400">Status</div>
            <div className="mt-4 text-2xl font-semibold text-emerald-300">Online</div>
            <div className="mt-2 text-slate-300">Signed in securely</div>
          </div>
        </div>
      </main>
    </div>
  );
}
