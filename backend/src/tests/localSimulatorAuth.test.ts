import jwt from 'jsonwebtoken';
import request from 'supertest';
import app from '../app';
import User from '../models/User';

describe('local simulator authentication', () => {
  const originalNodeEnv = process.env.NODE_ENV;
  const originalSimulatorAuth = process.env.LOCAL_SIMULATOR_AUTH;
  const originalSimulatorSecret = process.env.LOCAL_SIMULATOR_SECRET;

  beforeEach(() => {
    process.env.NODE_ENV = 'development';
    process.env.LOCAL_SIMULATOR_AUTH = 'true';
    process.env.LOCAL_SIMULATOR_SECRET = 'test-local-simulator-secret';
  });

  afterEach(() => {
    process.env.NODE_ENV = originalNodeEnv;
    process.env.LOCAL_SIMULATOR_AUTH = originalSimulatorAuth;
    process.env.LOCAL_SIMULATOR_SECRET = originalSimulatorSecret;
    jest.restoreAllMocks();
  });

  it('issues a normal JWT for an existing active admin without a password', async () => {
    const user = {
      _id: { toString: () => '507f1f77bcf86cd799439011' },
      username: 'local-admin',
      email: 'local-admin@example.com',
      role: 'ADMIN' as const,
      isActive: true,
      toObject: () => ({
        _id: '507f1f77bcf86cd799439011',
        username: 'local-admin',
        email: 'local-admin@example.com',
        role: 'ADMIN' as const,
        isActive: true,
      }),
    };
    const sort = jest.fn().mockResolvedValue(user);
    jest.spyOn(User, 'findOne').mockReturnValue({ sort } as never);

    const response = await request(app)
      .post('/api/auth/local-simulator-token')
      .set('X-Local-Simulator-Secret', 'test-local-simulator-secret');

    expect(response.status).toBe(200);
    expect(response.body.user.passwordHash).toBeUndefined();
    expect(jwt.verify(response.body.token, 'test-secret-key')).toMatchObject({
      userId: '507f1f77bcf86cd799439011',
      role: 'ADMIN',
    });
    expect(User.findOne).toHaveBeenCalledWith({
      role: { $in: ['ADMIN', 'SOC_ANALYST'] },
      isActive: true,
    });
  });

  it('is disabled outside explicit development mode', async () => {
    process.env.NODE_ENV = 'production';

    const response = await request(app)
      .post('/api/auth/local-simulator-token')
      .set('X-Local-Simulator-Secret', 'test-local-simulator-secret');

    expect(response.status).toBe(404);
  });

  it('rejects an incorrect local secret', async () => {
    const response = await request(app)
      .post('/api/auth/local-simulator-token')
      .set('X-Local-Simulator-Secret', 'wrong-secret');

    expect(response.status).toBe(401);
  });
});
