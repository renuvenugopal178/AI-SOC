import { useEffect, useState } from 'react';
import { API_BASE } from '../services/auth';

export type RealtimeStatus = 'LIVE' | 'RECONNECTING';
export type RealtimeMessage = {
  type: 'SECURITY_EVENT_CREATED' | 'ALERT_CREATED' | 'INCIDENT_CREATED' | 'INCIDENT_UPDATED';
  [key: string]: unknown;
};

export function useRealtimeEvents(token: string | null, enabled: boolean) {
  const [status, setStatus] = useState<RealtimeStatus>('RECONNECTING');
  const [eventVersion, setEventVersion] = useState(0);

  useEffect(() => {
    if (!enabled || !token) {
      setStatus('RECONNECTING');
      return undefined;
    }

    let stopped = false;
    let retryTimer: ReturnType<typeof setTimeout> | undefined;
    let controller: AbortController | undefined;

    const connect = async () => {
      controller = new AbortController();
      try {
        const response = await fetch(`${API_BASE}/realtime/events`, {
          headers: { Authorization: `Bearer ${token}`, Accept: 'text/event-stream' },
          signal: controller.signal,
        });
        if (!response.ok || !response.body) throw new Error('Realtime connection failed.');
        setStatus('LIVE');
        const reader = response.body.getReader();
        const decoder = new TextDecoder();
        let buffer = '';
        while (!stopped) {
          const chunk = await reader.read();
          if (chunk.done) break;
          buffer += decoder.decode(chunk.value, { stream: true });
          const messages = buffer.split(/\r?\n\r?\n/);
          buffer = messages.pop() || '';
          messages.forEach((message) => {
            const dataLines = message
              .split(/\r?\n/)
              .filter((line) => line.startsWith('data: '));
            if (dataLines.length === 0) return;
            try {
              const parsed = JSON.parse(dataLines.map((line) => line.substring(6)).join('\n')) as RealtimeMessage;
              if (['SECURITY_EVENT_CREATED', 'ALERT_CREATED', 'INCIDENT_CREATED', 'INCIDENT_UPDATED'].includes(parsed.type)) {
                setEventVersion((version) => version + 1);
              }
            } catch {
              // Ignore malformed server messages and keep the stream alive.
            }
          });
        }
      } catch {
        if (!stopped) setStatus('RECONNECTING');
      } finally {
        if (!stopped) {
          setStatus('RECONNECTING');
          retryTimer = setTimeout(() => { void connect(); }, 3000);
        }
      }
    };

    void connect();
    return () => {
      stopped = true;
      controller?.abort();
      if (retryTimer) clearTimeout(retryTimer);
    };
  }, [enabled, token]);

  return { status, eventVersion };
}
