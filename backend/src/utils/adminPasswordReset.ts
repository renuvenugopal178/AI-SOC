import bcrypt from 'bcrypt';
import User from '../models/User';

export const validateAdminPassword = (password: string): void => {
  if (password.length < 12) {
    throw new Error('ADMIN_PASSWORD must contain at least 12 characters.');
  }

  if (!/[A-Z]/.test(password)) {
    throw new Error('ADMIN_PASSWORD must contain an uppercase letter.');
  }

  if (!/[a-z]/.test(password)) {
    throw new Error('ADMIN_PASSWORD must contain a lowercase letter.');
  }

  if (!/[0-9]/.test(password)) {
    throw new Error('ADMIN_PASSWORD must contain a number.');
  }

  if (!/[^A-Za-z0-9]/.test(password)) {
    throw new Error('ADMIN_PASSWORD must contain a special character.');
  }
};

export interface ResetAdminPasswordOptions {
  email?: string;
  newPassword?: string;
}

export const resetAdminPassword = async (options?: ResetAdminPasswordOptions) => {
  const email = (options?.email !== undefined ? options.email : (process.env.ADMIN_EMAIL || '')).trim();
  const password = (options?.newPassword !== undefined ? options.newPassword : (process.env.ADMIN_PASSWORD || process.env.NEW_ADMIN_PASSWORD || '')).trim();

  if (!email || !password) {
    throw new Error(
      'ADMIN_EMAIL and ADMIN_PASSWORD environment variables are required.'
    );
  }

  validateAdminPassword(password);

  const existingUser = await User.findOne({
    email: email.toLowerCase(),
  });

  if (!existingUser) {
    throw new Error(`ADMIN user with email "${email.toLowerCase()}" not found.`);
  }

  if (existingUser.role !== 'ADMIN') {
    throw new Error(
      `User with email "${email.toLowerCase()}" is not an ADMIN. No changes were made.`
    );
  }

  const passwordHash = await bcrypt.hash(password, 12);

  await User.updateOne(
    { _id: existingUser._id },
    { $set: { passwordHash } }
  );

  console.log('ADMIN password reset successfully.');
  console.log(`Username: ${existingUser.username}`);
  console.log(`Email: ${existingUser.email}`);
  console.log('Password: [hidden]');

  return {
    success: true,
    username: existingUser.username,
    email: existingUser.email,
  };
};

