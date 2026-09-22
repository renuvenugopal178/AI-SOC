import { EventEmitter } from 'events';
import { addRealtimeClient, getRealtimeClientCount, publishRealtimeEvent } from '../services/realtimeService';

type TestResponse = EventEmitter & {
  writableEnded: boolean;
  destroyed: boolean;
  write: jest.Mock<boolean, [string]>;
};

const createResponse = (): TestResponse => {
  const response = new EventEmitter() as TestResponse;
  response.writableEnded = false;
  response.destroyed = false;
  response.write = jest.fn((_message: string) => true);
  return response;
};

describe('realtime service', () => {
  beforeEach(() => {
    jest.useFakeTimers();
  });

  afterEach(() => {
    jest.useRealTimers();
  });

  it('publishes safe event frames to all connected clients', () => {
    const first = createResponse();
    const second = createResponse();
    const removeFirst = addRealtimeClient(first as never);
    const removeSecond = addRealtimeClient(second as never);

    publishRealtimeEvent('ALERT_CREATED', {
      alertId: 'alert-1',
      severity: 'HIGH',
      riskScore: 80,
    });

    expect(first.write).toHaveBeenCalledWith(expect.stringContaining('event: ALERT_CREATED'));
    expect(first.write).toHaveBeenCalledWith(expect.stringContaining('"alertId":"alert-1"'));
    expect(second.write).toHaveBeenCalledTimes(1);
    expect(getRealtimeClientCount()).toBe(2);

    removeFirst();
    removeSecond();
    expect(getRealtimeClientCount()).toBe(0);
  });

  it('sends heartbeats and removes disconnected clients', () => {
    const response = createResponse();
    addRealtimeClient(response as never);

    jest.advanceTimersByTime(25_000);
    expect(response.write).toHaveBeenCalledWith(': heartbeat\n\n');

    response.emit('close');
    response.emit('close');
    expect(getRealtimeClientCount()).toBe(0);
  });

  it('removes clients when a write fails', () => {
    const response = createResponse();
    response.write.mockImplementationOnce(() => {
      throw new Error('disconnected');
    });
    addRealtimeClient(response as never);

    publishRealtimeEvent('SECURITY_EVENT_CREATED', { eventId: 'event-1' });

    expect(getRealtimeClientCount()).toBe(0);
  });
});
