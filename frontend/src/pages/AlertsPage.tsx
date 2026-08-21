import { useEffect, useState } from 'react';
import { getStoredToken, type AuthUser } from '../services/auth';
import { fetchAlerts, type AlertFilters } from '../services/alerts';
import type { Alert, AlertStatus, SecuritySeverity } from '../services/dashboard';

type AlertsPageProps = {
  user: AuthUser;
  navItems: string[];
  onLogout: () => void;
  onNavigate: (page: string) => void;
  apiError?: string | null;
};

const severityOptions: Array<SecuritySeverity | 'ALL'> = ['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];
const statusOptions: Array<AlertStatus | 'ALL'> = ['ALL', 'NEW', 'ACKNOWLEDGED', 'RESOLVED'];

const formatDate = (value: string) => new Intl.DateTimeFormat(undefined, {
  year: 'numeric', month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit',
}).format(new Date(value));

const severityClass: Record<SecuritySeverity, string> = {
  LOW: 'border-slate-600 bg-slate-800 text-slate-300',
  MEDIUM: 'border-sky-500/40 bg-sky-500/10 text-sky-300',
  HIGH: 'border-amber-500/40 bg-amber-500/10 text-amber-300',
  CRITICAL: 'border-rose-500/40 bg-rose-500/10 text-rose-300',
};

const statusClass: Record<AlertStatus, string> = {
  NEW: 'text-emerald-300',
  ACKNOWLEDGED: 'text-amber-300',
  RESOLVED: 'text-slate-400',
};

export function AlertsPage({ user, navItems, onLogout, onNavigate, apiError }: AlertsPageProps) {
  const [filters, setFilters] = useState<AlertFilters>({ severity: 'ALL', status: 'ALL' });
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const token = getStoredToken();
    if (!token) {
      setError('Your session has expired. Please sign in again.');
      setLoading(false);
      return;
    }

    setLoading(true);
    setError(null);
    fetchAlerts(token, filters)
      .then((result) => {
        setAlerts(result.alerts);
        setTotal(result.total);
      })
      .catch((requestError: unknown) => {
        setError(requestError instanceof Error ? requestError.message : 'Unable to load alerts.');
      })
      .finally(() => setLoading(false));
  }, [filters]);

  const errorMessage = apiError || error;

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100">
      <aside className="fixed left-0 top-0 hidden h-full w-72 border-r border-slate-800 bg-slate-900/95 p-6 lg:block">
        <div className="mb-8 inline-flex items-center rounded-full border border-sky-500/40 bg-sky-500/10 px-3 py-2 text-xs font-semibold uppercase tracking-[0.25em] text-sky-300">AI-SOC</div>
        <nav className="space-y-2">
          {navItems.map((item) => (
            <button key={item} type="button" onClick={() => onNavigate(item)} className={`flex w-full items-center justify-between rounded-xl border px-3 py-2 text-left text-sm transition ${item === 'Alerts' ? 'border-sky-500/50 bg-sky-500/10 text-white' : 'border-slate-800 bg-slate-950/70 text-slate-200 hover:border-sky-500/40 hover:text-white'}`}>
              {item}<span className="text-xs text-slate-400">→</span>
            </button>
          ))}
        </nav>
        <div className="mt-10 rounded-xl border border-slate-800 bg-slate-950/70 p-4">
          <div className="text-xs uppercase tracking-[0.25em] text-slate-400">Signed in</div>
          <div className="mt-3 text-lg font-semibold text-white">{user.username}</div>
          <div className="text-sm text-slate-300">{user.email}</div>
          <div className="mt-2 inline-flex rounded-full border border-emerald-500/30 bg-emerald-500/10 px-2 py-1 text-xs text-emerald-300">{user.role}</div>
        </div>
      </aside>

      <main className="min-h-screen p-4 sm:p-8 lg:ml-72">
        <header className="mb-8 flex flex-col gap-4 rounded-2xl border border-slate-800 bg-slate-900/80 p-5 sm:flex-row sm:items-center sm:justify-between">
          <div><p className="text-sm uppercase tracking-[0.3em] text-slate-400">Operations</p><h1 className="mt-2 text-3xl font-bold text-white">Alerts</h1></div>
          <button type="button" onClick={onLogout} className="self-start rounded-xl border border-slate-700 bg-slate-950 px-4 py-2 text-sm font-medium text-slate-100 hover:border-sky-500/40 hover:text-sky-200 sm:self-auto">Logout</button>
        </header>

        {errorMessage && <div className="mb-6 rounded-xl border border-rose-500/40 bg-rose-500/10 px-4 py-3 text-sm text-rose-200">{errorMessage}</div>}

        <section className="mb-6 flex flex-col gap-4 rounded-2xl border border-slate-800 bg-slate-900/80 p-5 sm:flex-row sm:items-end sm:justify-between">
          <div><div className="text-xs font-semibold uppercase tracking-[0.2em] text-slate-400">Alert queue</div><div className="mt-2 text-2xl font-bold text-white">{total.toLocaleString()} alerts</div></div>
          <div className="grid gap-3 sm:grid-cols-2">
            <label className="text-xs font-semibold uppercase tracking-[0.15em] text-slate-400">Severity<select value={filters.severity} onChange={(event) => setFilters({ ...filters, severity: event.target.value as AlertFilters['severity'] })} className="mt-2 block w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm font-normal tracking-normal text-white outline-none focus:border-sky-500"><option value="ALL">All severities</option>{severityOptions.slice(1).map((option) => <option key={option} value={option}>{option}</option>)}</select></label>
            <label className="text-xs font-semibold uppercase tracking-[0.15em] text-slate-400">Status<select value={filters.status} onChange={(event) => setFilters({ ...filters, status: event.target.value as AlertFilters['status'] })} className="mt-2 block w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm font-normal tracking-normal text-white outline-none focus:border-sky-500"><option value="ALL">All statuses</option>{statusOptions.slice(1).map((option) => <option key={option} value={option}>{option}</option>)}</select></label>
          </div>
        </section>

        {loading ? <div className="rounded-2xl border border-slate-800 bg-slate-900/80 p-8 text-slate-400">Loading alerts...</div> : alerts.length === 0 ? <div className="rounded-2xl border border-slate-800 bg-slate-900/80 p-10 text-center text-slate-400">No alerts match the selected filters.</div> : <AlertTable alerts={alerts} />}
      </main>
    </div>
  );
}

function AlertTable({ alerts }: { alerts: Alert[] }) {
  return <div className="overflow-hidden rounded-2xl border border-slate-800 bg-slate-900/80"><div className="hidden grid-cols-7 gap-4 border-b border-slate-800 px-5 py-3 text-xs font-semibold uppercase tracking-[0.15em] text-slate-500 md:grid"><div className="col-span-2">Alert</div><div>Severity</div><div>Risk score</div><div>Status</div><div>Source</div><div>Timestamp</div></div>{alerts.map((alert) => <article key={alert.id} className="grid gap-3 border-b border-slate-800 px-5 py-4 last:border-0 md:grid-cols-7 md:items-center md:gap-4"><div className="min-w-0 md:col-span-2"><div className="truncate font-semibold text-white">{alert.title}</div><div className="mt-1 truncate text-sm text-slate-400">{alert.description}</div></div><div><span className={`inline-flex rounded-full border px-2 py-1 text-xs font-semibold ${severityClass[alert.severity]}`}>{alert.severity}</span></div><div className="text-sm text-slate-200"><span className="text-slate-500 md:hidden">Risk score: </span>{alert.riskScore}</div><div className={`text-sm font-semibold ${statusClass[alert.status]}`}>{alert.status}</div><div className="text-sm text-slate-300">{alert.source || '—'}<span className="block text-xs text-slate-500">{alert.eventType || 'Unknown event'}</span></div><time className="text-sm text-slate-400" dateTime={alert.triggeredAt}>{formatDate(alert.triggeredAt)}</time></article>)}</div>;
}