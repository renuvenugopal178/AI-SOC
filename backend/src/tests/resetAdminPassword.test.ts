import mongoose from 'mongoose';
import bcrypt from 'bcrypt';
import request from 'supertest';
import app from '../app';
import User from '../models/User';
import { validateAdminPassword, resetAdminPassword } from '../utils/adminPasswordReset';

describe('Development ADMIN password reset capability', () => {
  beforeAll(async () => {
    process.env.JWT_SECRET = 'test-secret-key';
    const mongoUri =
      process.env.MONGODB_URI ||
      'mongodb://admin:change_me_password@localhost:27017/ai-soc?authSource=admin';
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(mongoUri);
    }
    await User.deleteMany({});
  });

  beforeEach(async () => {
    await User.deleteMany({});
  });

  afterAll(async () => {
    await mongoose.disconnect();
  });

  describe('Password validation requirements (same as seed-admin)', () => {
    it('rejects passwords shorter than 12 characters', () => {
      expect(() => validateAdminPassword('Short1!Aa')).toThrow(
        'ADMIN_PASSWORD must contain at least 12 characters.'
      );
    });

    it('rejects passwords without uppercase letter', () => {
      expect(() => validateAdminPassword('lowercase123!@#')).toThrow(
        'ADMIN_PASSWORD must contain an uppercase letter.'
      );
    });

    it('rejects passwords without lowercase letter', () => {
      expect(() => validateAdminPassword('UPPERCASE123!@#')).toThrow(
        'ADMIN_PASSWORD must contain a lowercase letter.'
      );
    });

    it('rejects passwords without a number', () => {
      expect(() => validateAdminPassword('NoNumberAtAll!@#')).toThrow(
        'ADMIN_PASSWORD must contain a number.'
      );
    });

    it('rejects passwords without a special character', () => {
      expect(() => validateAdminPassword('NoSpecialChar12345')).toThrow(
        'ADMIN_PASSWORD must contain a special character.'
      );
    });

    it('accepts valid strong password', () => {
      expect(() => validateAdminPassword('ValidAdminPassword123!')).not.toThrow();
    });
  });

  describe('Password reset execution', () => {
    it('throws when email or password is missing', async () => {
      await expect(
        resetAdminPassword({ email: '', newPassword: 'ValidAdminPassword123!' })
      ).rejects.toThrow('ADMIN_EMAIL and ADMIN_PASSWORD environment variables are required.');

      await expect(
        resetAdminPassword({ email: 'admin@example.com', newPassword: '' })
      ).rejects.toThrow('ADMIN_EMAIL and ADMIN_PASSWORD environment variables are required.');
    });

    it('throws when user does not exist and does not create any user', async () => {
      await expect(
        resetAdminPassword({
          email: 'nonexistent@example.com',
          newPassword: 'NewAdminPassword123!',
        })
      ).rejects.toThrow('ADMIN user with email "nonexistent@example.com" not found.');

      const count = await User.countDocuments({});
      expect(count).toBe(0);
    });

    it('throws when user is not an ADMIN and does not modify user or create duplicates', async () => {
      const initialHash = await bcrypt.hash('OldPassword123!', 10);
      await User.create({
        username: 'analyst_user',
        email: 'analyst@example.com',
        passwordHash: initialHash,
        role: 'SOC_ANALYST',
        isActive: true,
      });

      await expect(
        resetAdminPassword({
          email: 'analyst@example.com',
          newPassword: 'NewAdminPassword123!',
        })
      ).rejects.toThrow('User with email "analyst@example.com" is not an ADMIN. No changes were made.');

      const count = await User.countDocuments({});
      expect(count).toBe(1);

      const user = await User.findOne({ email: 'analyst@example.com' });
      expect(user?.passwordHash).toBe(initialHash);
      expect(user?.role).toBe('SOC_ANALYST');
    });

    it('successfully updates only passwordHash for existing ADMIN and allows login with new password', async () => {
      const oldPasswordHash = await bcrypt.hash('OldAdminPassword123!', 12);
      const adminUser = await User.create({
        username: 'admin_root',
        email: 'admin@ai-soc.local',
        passwordHash: oldPasswordHash,
        role: 'ADMIN',
        isActive: true,
      });

      const initialCount = await User.countDocuments({});
      expect(initialCount).toBe(1);

      const result = await resetAdminPassword({
        email: 'admin@ai-soc.local',
        newPassword: 'NewSecureAdminPassword456!',
      });

      expect(result.success).toBe(true);
      expect(result.username).toBe('admin_root');
      expect(result.email).toBe('admin@ai-soc.local');

      // Ensure no duplicate users were created
      const totalCount = await User.countDocuments({});
      expect(totalCount).toBe(1);

      // Verify updated user in database
      const updatedUser = await User.findById(adminUser._id);
      expect(updatedUser).toBeDefined();
      expect(updatedUser?.username).toBe('admin_root');
      expect(updatedUser?.email).toBe('admin@ai-soc.local');
      expect(updatedUser?.role).toBe('ADMIN');
      expect(updatedUser?.isActive).toBe(true);
      expect(updatedUser?.passwordHash).not.toBe(oldPasswordHash);

      // Verify old password fails compare
      const oldMatches = await bcrypt.compare('OldAdminPassword123!', updatedUser!.passwordHash);
      expect(oldMatches).toBe(false);

      // Verify new password matches
      const newMatches = await bcrypt.compare('NewSecureAdminPassword456!', updatedUser!.passwordHash);
      expect(newMatches).toBe(true);

      // Verify login via auth endpoint with new password
      const loginRes = await request(app)
        .post('/api/auth/login')
        .send({
          email: 'admin@ai-soc.local',
          password: 'NewSecureAdminPassword456!',
        });

      expect(loginRes.status).toBe(200);
      expect(loginRes.body.token).toBeDefined();
      expect(loginRes.body.user.role).toBe('ADMIN');

      // Verify login fails with old password
      const oldLoginRes = await request(app)
        .post('/api/auth/login')
        .send({
          email: 'admin@ai-soc.local',
          password: 'OldAdminPassword123!',
        });

      expect(oldLoginRes.status).toBe(401);
    });
  });
});

