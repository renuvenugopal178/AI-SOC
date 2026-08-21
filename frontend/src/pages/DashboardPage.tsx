import { Children, useEffect, useState, type ReactNode } from 'react';
import { getStoredToken, type AuthUser } from '../services/auth';
import { fetchDashboardData, type Alert, type DashboardData, type SecurityEvent } from '../services/dashboard';

type DashboardPageProps = {
  user: AuthUser;
  navItems: string[];
  onLogout: () => void;
  onNavigate: (page: string) => void;
  apiError?: string | null;
};

export function DashboardPage({ user, navItems, onLogout, onNavigate, apiError }: DashboardPageProps) {
  const [dashboard, setDashboard] = useState<DashboardData | null>(null);
  const [loading, setLoading] = useState(true);
  const [dashboardError, setDashboardError] = useState<string | null>(null);

  useEffect(() => {
    const token = getStoredToken();
    if (!token) {
      setDashboardError('Your session has expired. Please sign in again.');
      setLoading(false);
      return;
    }

    fetchDashboardData(token)
      .then(setDashboard)
      .catch((error: unknown) => {
        setDashboardError(error instanceof Error ? error.message : 'Unable to load dashboard data.');
      })
      .finally(() => setLoading(false));
  }, []);

  const errorMessage = apiError || dashboardError;

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
              onClick={() => onNavigate(item)}
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

        {errorMessage && (
          <div className="mb-6 rounded-xl border border-rose-500/40 bg-rose-500/10 px-4 py-3 text-sm text-rose-200">
            {errorMessage}
          </div>
        )}

        {loading ? <DashboardLoading /> : dashboard && <DashboardContent data={dashboard} />}
      </main>
    </div>
  );
}

const formatDate = (value: string) => new Intl.DateTimeFormat(undefined, {
  month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit',
}).format(new Date(value));

const severityClass: Record<SecurityEvent['severity'], string> = {
  LOW: 'text-slate-300',
  MEDIUM: 'text-sky-300',
  HIGH: 'text-amber-300',
  CRITICAL: 'text-rose-300',
};

function DashboardLoading() {
  return <div className="rounded-2xl border border-slate-800 bg-slate-900/80 p-8 text-slate-400">Loading live SOC metrics...</div>;
}

function DashboardContent({ data }: { data: DashboardData }) {
  const metrics = [
    ['Total events', data.totalEvents, 'border-sky-500/30'],
    ['Total alerts', data.totalAlerts, 'border-violet-500/30'],
    ['Critical alerts', data.criticalAlerts, 'border-rose-500/40'],
    ['High alerts', data.highAlerts, 'border-amber-500/40'],
    ['New alerts', data.newAlerts, 'border-emerald-500/40'],
  ] as const;

  return (
    <>
      <div className="mb-6 grid gap-4 sm:grid-cols-2 xl:grid-cols-5">
        {metrics.map(([label, value, border]) => (
          <div key={label} className={`rounded-2xl border ${border} bg-slate-900/80 p-5`}>
            <div className="text-xs font-semibold uppercase tracking-[0.2em] text-slate-400">{label}</div>
            <div className="mt-3 text-3xl font-bold text-white">{value.toLocaleString()}</div>
          </div>
        ))}
      </div>

      <div className="grid gap-6 xl:grid-cols-2">
        <ActivityPanel title="Recent events" empty="No security events recorded yet.">
          {data.recentEvents.map((event) => (
            <div key={event.id} className="flex items-start justify-between gap-4 border-b border-slate-800 py-4 last:border-0">
              <div className="min-w-0">
                <div className="truncate font-semibold text-white">{event.eventType}</div>
                <div className="mt-1 truncate text-sm text-slate-400">{event.source}{event.sourceIp ? ` · ${event.sourceIp}` : ''}</div>
              </div>
              <div className="shrink-0 text-right">
                <div className={`text-xs font-bold ${severityClass[event.severity]}`}>{event.severity}</div>
                <div className="mt-1 text-xs text-slate-500">{formatDate(event.timestamp)}</div>
              </div>
            </div>
          ))}
        </ActivityPanel>

        <ActivityPanel title="Recent alerts" empty="No alerts generated yet.">
          {data.recentAlerts.map((alert) => (
            <div key={alert.id} className="flex items-start justify-between gap-4 border-b border-slate-800 py-4 last:border-0">
              <div className="min-w-0">
                <div className="truncate font-semibold text-white">{alert.title}</div>
                <div className="mt-1 truncate text-sm text-slate-400">{alert.source || alert.eventType || 'Detection rule'}</div>
              </div>
              <div className="shrink-0 text-right">
                <div className={`text-xs font-bold ${severityClass[alert.severity]}`}>{alert.severity}</div>
                <div className="mt-1 text-xs text-slate-500">{formatDate(alert.triggeredAt)}</div>
                <div className="mt-1 text-xs text-slate-400">{alert.status}</div>
              </div>
            </div>
          ))}
        </ActivityPanel>
      </div>
    </>
  );
}

function ActivityPanel({ title, empty, children }: { title: string; empty: string; children: ReactNode }) {
  return (
    <section className="rounded-2xl border border-slate-800 bg-slate-900/80 px-5">
      <div className="border-b border-slate-800 py-4 text-sm font-semibold uppercase tracking-[0.2em] text-slate-300">{title}</div>
      {Children.count(children) > 0 ? children : <div className="py-8 text-sm text-slate-500">{empty}</div>}
    </section>
  );
}
