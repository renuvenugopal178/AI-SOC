import http from 'http';
import jwt from 'jsonwebtoken';
import request from 'supertest';
import { jest } from '@jest/globals';
import app from '../app';
import User, { UserRole } from '../models/User';
import { getRealtimeClientCount, removeAllRealtimeClients } from '../services/realtimeService';

jest.mock('../utils/securityTelemetry', () => ({
  recordSecurityEvent: jest.fn().mockImplementation(async () => undefined),
}));

describe('Realtime SSE endpoint', () => {
  beforeEach(() => {
    process.env.JWT_SECRET = 'test-secret-key';
    removeAllRealtimeClients();
    expect(getRealtimeClientCount()).toBe(0);
  });

  it('rejects unauthenticated connections', async () => {
    const response = await request(app).get('/api/realtime/events');

    expect(response.status).toBe(401);
  });

  it.each<UserRole>(['ADMIN', 'SOC_ANALYST', 'VIEWER'])('allows %s to connect and cleans up disconnects', async (role) => {
    const userId = `507f1f77bcf86cd7994390${role === 'ADMIN' ? '01' : role === 'SOC_ANALYST' ? '02' : '03'}`;
    const user = {
      _id: userId,
      username: `${role.toLowerCase()}-user`,
      email: `${role.toLowerCase()}@ai-soc.local`,
      role,
      isActive: true,
    };
    const select = jest.fn().mockImplementation(async () => user);
    const findById = jest.spyOn(User, 'findById').mockReturnValue({ select } as never);
    const token = jwt.sign({ userId, role }, process.env.JWT_SECRET as string);
    const server = app.listen(0);

    try {
      await new Promise<void>((resolve, reject) => {
        server.once('listening', () => {
          const address = server.address();
          if (!address || typeof address === 'string') {
            reject(new Error('Test server did not expose a TCP address.'));
            return;
          }

          const client = http.get({
            port: address.port,
            path: '/api/realtime/events',
            headers: { Authorization: `Bearer ${token}` },
          }, (response) => {
            expect(response.statusCode).toBe(200);
            expect(response.headers['content-type']).toContain('text/event-stream');
            response.once('close', () => server.close(() => setImmediate(resolve)));
            response.destroy();
          });
          client.on('error', (error) => {
            if ((error as NodeJS.ErrnoException).code !== 'ECONNRESET') reject(error);
          });
        });
      });

      expect(select).toHaveBeenCalledWith('_id username email role isActive');
      removeAllRealtimeClients();
      expect(getRealtimeClientCount()).toBe(0);
    } finally {
      findById.mockRestore();
      if (server.listening) server.close();
    }
  });
});
