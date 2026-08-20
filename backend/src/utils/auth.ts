import jwt from 'jsonwebtoken';
import bcrypt from 'bcrypt';
import { UserRole } from '../models/User';

export const getJwtSecret = (): string => process.env.JWT_SECRET || 'development-secret-change-me';

export const hashPassword = async (password: string): Promise<string> => {
  const saltRounds = 10;
  return bcrypt.hash(password, saltRounds);
};

export const comparePassword = async (password: string, passwordHash: string): Promise<boolean> => {
  return bcrypt.compare(password, passwordHash);
};

export const generateToken = (userId: string, role: UserRole): string => {
  return jwt.sign({ userId, role }, getJwtSecret(), { expiresIn: '8h' });
};

export const sanitizeUser = (user: {
  _id?: unknown;
  username?: string;
  email?: string;
  role?: UserRole;
  isActive?: boolean;
  lastLoginAt?: Date | null;
  createdAt?: Date;
  updatedAt?: Date;
}) => ({
  id: user._id?.toString?.() ?? user._id,
  username: user.username,
  email: user.email,
  role: user.role,
  isActive: user.isActive,
  lastLoginAt: user.lastLoginAt,
  createdAt: user.createdAt,
  updatedAt: user.updatedAt,
});
