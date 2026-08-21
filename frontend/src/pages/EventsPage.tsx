import { useEffect, useState } from 'react';
import { getStoredToken, type AuthUser } from '../services/auth';
import { fetchEvents, type SecurityEventRecord } from '../services/events';
import type { SecuritySeverity } from '../services/dashboard';

type EventsPageProps = {
  user: AuthUser;
  navItems: string[];
  onLogout: () => void;
  onNavigate: (page: string) => void;
  apiError?: string | null;
};

const severityClass: Record<SecuritySeverity, string> = {
  LOW: 'border-slate-600 bg-slate-800 text-slate-300',
  MEDIUM: 'border-sky-500/40 bg-sky-500/10 text-sky-300',
  HIGH: 'border-amber-500/40 bg-amber-500/10 text-amber-300',
  CRITICAL: 'border-rose-500/40 bg-rose-500/10 text-rose-300',
};

const formatDate = (value: string) => new Intl.DateTimeFormat(undefined, {
  year: 'numeric', month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit',
}).format(new Date(value));

const displayValue = (value?: string | null) => value || '—';

export function EventsPage({ user, navItems, onLogout, onNavigate, apiError }: EventsPageProps) {
  const [events, setEvents] = useState<SecurityEventRecord[]>([]);
  const [page, setPage] = useState(1);
  const [total, setTotal] = useState(0);
  const [totalPages, setTotalPages] = useState(0);
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
    fetchEvents(token, page)
      .then((result) => {
        setEvents(result.events);
        setTotal(result.total);
        setTotalPages(result.totalPages);
      })
      .catch((requestError: unknown) => {
        setError(requestError instanceof Error ? requestError.message : 'Unable to load security events.');
      })
      .finally(() => setLoading(false));
  }, [page]);

  const errorMessage = apiError || error;

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100">
      <aside className="fixed left-0 top-0 hidden h-full w-72 border-r border-slate-800 bg-slate-900/95 p-6 lg:block">
        <div className="mb-8 inline-flex items-center rounded-full border border-sky-500/40 bg-sky-500/10 px-3 py-2 text-xs font-semibold uppercase tracking-[0.25em] text-sky-300">AI-SOC</div>
        <nav className="space-y-2">
          {navItems.map((item) => <button key={item} type="button" onClick={() => onNavigate(item)} className={`flex w-full items-center justify-between rounded-xl border px-3 py-2 text-left text-sm transition ${item === 'Events' ? 'border-sky-500/50 bg-sky-500/10 text-white' : 'border-slate-800 bg-slate-950/70 text-slate-200 hover:border-sky-500/40 hover:text-white'}`}>{item}<span className="text-xs text-slate-400">→</span></button>)}
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
          <div><p className="text-sm uppercase tracking-[0.3em] text-slate-400">Operations</p><h1 className="mt-2 text-3xl font-bold text-white">Security Events</h1></div>
          <button type="button" onClick={onLogout} className="self-start rounded-xl border border-slate-700 bg-slate-950 px-4 py-2 text-sm font-medium text-slate-100 hover:border-sky-500/40 hover:text-sky-200 sm:self-auto">Logout</button>
        </header>

        {errorMessage && <div className="mb-6 rounded-xl border border-rose-500/40 bg-rose-500/10 px-4 py-3 text-sm text-rose-200">{errorMessage}</div>}
        <section className="mb-6 rounded-2xl border border-slate-800 bg-slate-900/80 p-5"><div className="text-xs font-semibold uppercase tracking-[0.2em] text-slate-400">Event stream</div><div className="mt-2 text-2xl font-bold text-white">{total.toLocaleString()} events</div></section>

        {loading ? <div className="rounded-2xl border border-slate-800 bg-slate-900/80 p-8 text-slate-400">Loading security events...</div> : events.length === 0 ? <div className="rounded-2xl border border-slate-800 bg-slate-900/80 p-10 text-center text-slate-400">No security events have been recorded.</div> : <EventsTable events={events} />}

        {!loading && totalPages > 0 && <div className="mt-5 flex items-center justify-between rounded-xl border border-slate-800 bg-slate-900/80 px-4 py-3"><button type="button" disabled={page <= 1} onClick={() => setPage((currentPage) => currentPage - 1)} className="rounded-lg border border-slate-700 px-3 py-2 text-sm text-slate-200 hover:border-sky-500/40 disabled:cursor-not-allowed disabled:opacity-40">Previous</button><span className="text-sm text-slate-400">Page {page} of {totalPages}</span><button type="button" disabled={page >= totalPages} onClick={() => setPage((currentPage) => currentPage + 1)} className="rounded-lg border border-slate-700 px-3 py-2 text-sm text-slate-200 hover:border-sky-500/40 disabled:cursor-not-allowed disabled:opacity-40">Next</button></div>}
      </main>
    </div>
  );
}

function EventsTable({ events }: { events: SecurityEventRecord[] }) {
  return <div className="overflow-hidden rounded-2xl border border-slate-800 bg-slate-900/80"><div className="hidden grid-cols-10 gap-3 border-b border-slate-800 px-5 py-3 text-xs font-semibold uppercase tracking-[0.12em] text-slate-500 xl:grid"><div>Timestamp</div><div>Source</div><div>Event type</div><div>Severity</div><div>Source IP</div><div>Destination IP</div><div>Protocol</div><div>Username</div><div>Action</div><div>Message</div></div>{events.map((event) => <article key={event.id} className="grid gap-3 border-b border-slate-800 px-5 py-4 last:border-0 xl:grid-cols-10 xl:items-start xl:gap-3"><time className="text-sm text-slate-400" dateTime={event.timestamp}>{formatDate(event.timestamp)}</time><div className="text-sm text-slate-200">{event.source}</div><div className="text-sm font-semibold text-white">{event.eventType}</div><div><span className={`inline-flex rounded-full border px-2 py-1 text-xs font-semibold ${severityClass[event.severity]}`}>{event.severity}</span></div><div className="text-sm text-slate-300">{displayValue(event.sourceIp)}</div><div className="text-sm text-slate-300">{displayValue(event.destinationIp)}</div><div className="text-sm text-slate-300">{displayValue(event.protocol)}</div><div className="text-sm text-slate-300">{displayValue(event.username)}</div><div className="text-sm text-slate-300">{displayValue(event.action)}</div><div className="break-words text-sm text-slate-400">{displayValue(event.message)}</div></article>)}</div>;
}