import { Response } from 'express';

export type RealtimeEventType = 'SECURITY_EVENT_CREATED' | 'ALERT_CREATED' | 'INCIDENT_CREATED' | 'INCIDENT_UPDATED';

type RealtimeClient = {
  response: Response;
  heartbeat: NodeJS.Timeout;
  remove: () => void;
  removed: boolean;
};

const clients = new Set<RealtimeClient>();

export const publishRealtimeEvent = (type: RealtimeEventType, data: Record<string, unknown>): void => {
  const message = `event: ${type}\ndata: ${JSON.stringify({ type, ...data })}\n\n`;
  for (const client of [...clients]) {
    try {
      if (client.response.writableEnded || client.response.destroyed) {
        removeRealtimeClient(client);
        continue;
      }
      client.response.write(message);
    } catch {
      removeRealtimeClient(client);
    }
  }
};

export const addRealtimeClient = (response: Response): (() => void) => {
  let client: RealtimeClient;
  const remove = () => removeRealtimeClient(client);
  const heartbeat = setInterval(() => {
    try {
      if (response.writableEnded || response.destroyed) {
        remove();
        return;
      }
      response.write(': heartbeat\n\n');
    } catch {
      remove();
    }
  }, 25_000);
  heartbeat.unref();
  client = { response, heartbeat, remove, removed: false };
  clients.add(client);
  response.on('close', remove);
  response.on('error', remove);

  return remove;
};

const removeRealtimeClient = (client: RealtimeClient): void => {
  if (client.removed) return;
  client.removed = true;
  clients.delete(client);
  clearInterval(client.heartbeat);
  client.response.removeListener('close', client.remove);
  client.response.removeListener('error', client.remove);
};

export const getRealtimeClientCount = (): number => clients.size;

export const removeAllRealtimeClients = (): void => {
  for (const client of [...clients]) {
    removeRealtimeClient(client);
  }
};
