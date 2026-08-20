import request from 'supertest';
import mongoose from 'mongoose';
import bcrypt from 'bcrypt';
import app from '../app';
import User from '../models/User';
import AuditLog from '../models/AuditLog';

const baseUser = {
  username: 'analyst1',
  email: 'analyst1@example.com',
  password: 'Password123!',
  role: 'SOC_ANALYST',
};

describe('Authentication and RBAC API', () => {
  beforeAll(async () => {
    process.env.JWT_SECRET = 'test-secret-key';
    const mongoUri = process.env.MONGODB_URI || 'mongodb://admin:change_me_password@localhost:27017/ai-soc?authSource=admin';
    await mongoose.connect(mongoUri);
    await User.deleteMany({});
    await AuditLog.deleteMany({});
  });

  beforeEach(async () => {
    await User.deleteMany({});
    await AuditLog.deleteMany({});
  });

  afterAll(async () => {
    await mongoose.disconnect();
  });

  it('1. registers a valid user', async () => {
    const res = await request(app)
      .post('/api/auth/register')
      .send({
        username: 'alice',
        email: 'alice@example.com',
        password: 'Password123!',
        role: 'VIEWER',
      });

    expect(res.status).toBe(201);
    expect(res.body.user).toMatchObject({
      username: 'alice',
      email: 'alice@example.com',
      role: 'VIEWER',
    });
    expect(res.body.user.passwordHash).toBeUndefined();
  });

  it('2. rejects duplicate email', async () => {
    await User.create({
      username: 'dupuser',
      email: 'dup@example.com',
      passwordHash: await bcrypt.hash('Password123!', 10),
      role: 'VIEWER',
    });

    const res = await request(app)
      .post('/api/auth/register')
      .send({
        username: 'dupuser2',
        email: 'dup@example.com',
        password: 'Password123!',
        role: 'VIEWER',
      });

    expect(res.status).toBe(409);
  });

  it('3. rejects invalid email', async () => {
    const res = await request(app)
      .post('/api/auth/register')
      .send({
        username: 'bademail',
        email: 'not-an-email',
        password: 'Password123!',
        role: 'VIEWER',
      });

    expect(res.status).toBe(400);
  });

  it('4. rejects weak password', async () => {
    const res = await request(app)
      .post('/api/auth/register')
      .send({
        username: 'weakpw',
        email: 'weak@example.com',
        password: 'short',
        role: 'VIEWER',
      });

    expect(res.status).toBe(400);
  });

  it('5. logs in successfully', async () => {
    await User.create({
      username: 'loginuser',
      email: 'login@example.com',
      passwordHash: await bcrypt.hash('Password123!', 10),
      role: 'SOC_ANALYST',
      isActive: true,
    });

    const res = await request(app)
      .post('/api/auth/login')
      .send({
        email: 'login@example.com',
        password: 'Password123!',
      });

    expect(res.status).toBe(200);
    expect(res.body.token).toBeTruthy();
    expect(res.body.user.email).toBe('login@example.com');
  });

  it('6. rejects incorrect password', async () => {
    await User.create({
      username: 'wrongpw',
      email: 'wrongpw@example.com',
      passwordHash: await bcrypt.hash('Password123!', 10),
      role: 'VIEWER',
      isActive: true,
    });

    const res = await request(app)
      .post('/api/auth/login')
      .send({
        email: 'wrongpw@example.com',
        password: 'WrongPassword1!',
      });

    expect(res.status).toBe(401);
  });

  it('7. rejects non-existent user', async () => {
    const res = await request(app)
      .post('/api/auth/login')
      .send({
        email: 'missing@example.com',
        password: 'Password123!',
      });

    expect(res.status).toBe(401);
  });

  it('8. rejects missing JWT', async () => {
    const res = await request(app).get('/api/auth/me');
    expect(res.status).toBe(401);
  });

  it('9. rejects invalid JWT', async () => {
    const res = await request(app)
      .get('/api/auth/me')
      .set('Authorization', 'Bearer invalid.token.here');

    expect(res.status).toBe(401);
  });

  it('10. rejects expired JWT', async () => {
    const expiredToken = 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abc';
    const res = await request(app)
      .get('/api/auth/me')
      .set('Authorization', `Bearer ${expiredToken}`);

    expect(res.status).toBe(401);
  });

  it('11. denies VIEWER from admin endpoint', async () => {
    const user = await User.create({
      username: 'vieweruser',
      email: 'viewer@example.com',
      passwordHash: await bcrypt.hash('Password123!', 10),
      role: 'VIEWER',
      isActive: true,
    });

    const loginRes = await request(app)
      .post('/api/auth/login')
      .send({ email: 'viewer@example.com', password: 'Password123!' });

    const res = await request(app)
      .get('/api/admin/test')
      .set('Authorization', `Bearer ${loginRes.body.token}`);

    expect(res.status).toBe(403);
  });

  it('12. denies SOC_ANALYST from admin endpoint', async () => {
    const user = await User.create({
      username: 'socuser',
      email: 'soc@example.com',
      passwordHash: await bcrypt.hash('Password123!', 10),
      role: 'SOC_ANALYST',
      isActive: true,
    });

    const loginRes = await request(app)
      .post('/api/auth/login')
      .send({ email: 'soc@example.com', password: 'Password123!' });

    const res = await request(app)
      .get('/api/admin/test')
      .set('Authorization', `Bearer ${loginRes.body.token}`);

    expect(res.status).toBe(403);
  });

  it('13. allows ADMIN on admin endpoint', async () => {
    await User.create({
      username: 'adminuser',
      email: 'admin@example.com',
      passwordHash: await bcrypt.hash('Password123!', 10),
      role: 'ADMIN',
      isActive: true,
    });

    const loginRes = await request(app)
      .post('/api/auth/login')
      .send({ email: 'admin@example.com', password: 'Password123!' });

    const res = await request(app)
      .get('/api/admin/test')
      .set('Authorization', `Bearer ${loginRes.body.token}`);

    expect(res.status).toBe(200);
  });

  it('14. allows ADMIN on analyst endpoint', async () => {
    await User.create({
      username: 'adminanalyst',
      email: 'adminanalyst@example.com',
      passwordHash: await bcrypt.hash('Password123!', 10),
      role: 'ADMIN',
      isActive: true,
    });

    const loginRes = await request(app)
      .post('/api/auth/login')
      .send({ email: 'adminanalyst@example.com', password: 'Password123!' });

    const res = await request(app)
      .get('/api/analyst/test')
      .set('Authorization', `Bearer ${loginRes.body.token}`);

    expect(res.status).toBe(200);
  });

  it('15. allows SOC_ANALYST on analyst endpoint', async () => {
    await User.create({
      username: 'socanalyst',
      email: 'socanalyst@example.com',
      passwordHash: await bcrypt.hash('Password123!', 10),
      role: 'SOC_ANALYST',
      isActive: true,
    });

    const loginRes = await request(app)
      .post('/api/auth/login')
      .send({ email: 'socanalyst@example.com', password: 'Password123!' });

    const res = await request(app)
      .get('/api/analyst/test')
      .set('Authorization', `Bearer ${loginRes.body.token}`);

    expect(res.status).toBe(200);
  });
});
