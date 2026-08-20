import { Router, Request, Response } from 'express';
import bcrypt from 'bcrypt';
import User from '../models/User';
import AuditLog from '../models/AuditLog';
import { registerSchema, loginSchema } from '../validation/auth';
import { generateToken, hashPassword, sanitizeUser } from '../utils/auth';
import { authenticate, AuthenticatedRequest } from '../middleware/auth';

const router = Router();

router.post('/register', async (req: Request, res: Response) => {
  try {
    const parsed = registerSchema.safeParse(req.body);

    if (!parsed.success) {
      res.status(400).json({ error: 'Invalid registration data.', details: parsed.error.flatten() });
      return;
    }

    const { username, email, password, role } = parsed.data;

    const existingUser = await User.findOne({ $or: [{ email }, { username }] });
    if (existingUser) {
      await AuditLog.create({
        action: 'registration',
        success: false,
        ipAddress: req.ip,
        metadata: { email, username, reason: 'duplicate_user' },
      });
      res.status(409).json({ error: 'Username or email already exists.' });
      return;
    }

    const passwordHash = await hashPassword(password);
    const user = await User.create({
      username,
      email,
      passwordHash,
      role,
      isActive: true,
    });

    await AuditLog.create({
      userId: user._id,
      action: 'registration',
      success: true,
      ipAddress: req.ip,
      metadata: { username, email, role },
    });

    res.status(201).json({
      message: 'User registered successfully.',
      user: sanitizeUser(user.toObject()),
    });
  } catch (error) {
    res.status(500).json({ error: 'Unable to register user.' });
  }
});

router.post('/login', async (req: Request, res: Response) => {
  try {
    const parsed = loginSchema.safeParse(req.body);

    if (!parsed.success) {
      res.status(400).json({ error: 'Invalid login data.', details: parsed.error.flatten() });
      return;
    }

    const { email, password } = parsed.data;
    const user = await User.findOne({ email: email.toLowerCase() });

    if (!user) {
      await AuditLog.create({
        action: 'login_failure',
        success: false,
        ipAddress: req.ip,
        metadata: { email, reason: 'user_not_found' },
      });
      res.status(401).json({ error: 'Invalid email or password.' });
      return;
    }

    const isPasswordValid = await bcrypt.compare(password, user.passwordHash);
    if (!isPasswordValid) {
      await AuditLog.create({
        userId: user._id,
        action: 'login_failure',
        success: false,
        ipAddress: req.ip,
        metadata: { email, reason: 'invalid_password' },
      });
      res.status(401).json({ error: 'Invalid email or password.' });
      return;
    }

    if (!user.isActive) {
      await AuditLog.create({
        userId: user._id,
        action: 'login_failure',
        success: false,
        ipAddress: req.ip,
        metadata: { email, reason: 'inactive_account' },
      });
      res.status(401).json({ error: 'Account is inactive.' });
      return;
    }

    user.lastLoginAt = new Date();
    await user.save();

    const token = generateToken(user._id.toString(), user.role);

    await AuditLog.create({
      userId: user._id,
      action: 'login_success',
      success: true,
      ipAddress: req.ip,
      metadata: { email, role: user.role },
    });

    res.status(200).json({
      token,
      user: sanitizeUser(user.toObject()),
    });
  } catch (error) {
    res.status(500).json({ error: 'Unable to process login request.' });
  }
});

router.get('/me', authenticate, async (req: AuthenticatedRequest, res: Response) => {
  const user = await User.findById(req.user?.userId).select('_id username email role isActive lastLoginAt createdAt updatedAt');

  if (!user) {
    res.status(404).json({ error: 'User not found.' });
    return;
  }

  res.status(200).json({ user: sanitizeUser(user.toObject()) });
});

export default router;
