import { z } from 'zod';

export const registerSchema = z.object({
  username: z.string().trim().min(3).max(32),
  email: z.string().trim().email(),
  password: z.string().min(8).regex(/^(?=.*[A-Za-z])(?=.*\d)(?=.*[^A-Za-z0-9]).+$/),
  role: z.enum(['ADMIN', 'SOC_ANALYST', 'VIEWER']).optional().default('VIEWER'),
}).refine((data) => {
  if (data.role === 'ADMIN') return false;
  return true;
}, {
  message: 'Public registration cannot create an ADMIN account.',
  path: ['role'],
});

export const loginSchema = z.object({
  email: z.string().trim().email(),
  password: z.string().min(8),
});
