import { Router, Request, Response } from 'express';
import bcrypt from 'bcrypt';
import User from '../models/User';
import AuditLog from '../models/AuditLog';
import { registerSchema, loginSchema } from '../validation/auth';
import { generateToken, hashPassword, sanitizeUser } from '../utils/auth';
import { authenticate, AuthenticatedRequest } from '../middleware/auth';
import { recordSecurityEvent } from '../utils/securityTelemetry';
import { getLocalSimulatorSecret, isLoopbackRequest } from '../utils/localSimulatorAuth';

const router = Router();

router.post('/local-simulator-token', async (req: Request, res: Response) => {
  if (process.env.NODE_ENV !== 'development' || process.env.LOCAL_SIMULATOR_AUTH !== 'true') {
    res.status(404).json({ error: 'Not found.' });
    return;
  }

  const requestAddress = req.socket.remoteAddress || req.ip;
  if (!isLoopbackRequest(requestAddress)) {
    res.status(404).json({ error: 'Not found.' });
    return;
  }

  const configuredSecret = getLocalSimulatorSecret();
  const providedSecret = req.get('X-Local-Simulator-Secret');
  if (!configuredSecret || !providedSecret || providedSecret !== configuredSecret) {
    res.status(401).json({ error: 'Local simulator authentication failed.' });
    return;
  }

  try {
    const user = await User.findOne({
      role: { $in: ['ADMIN', 'SOC_ANALYST'] },
      isActive: true,
    }).sort({ role: 1, createdAt: 1 });

    if (!user) {
      res.status(503).json({ error: 'Create an active ADMIN or SOC_ANALYST account before running the simulator.' });
      return;
    }

    res.status(200).json({
      token: generateToken(user._id.toString(), user.role),
      user: sanitizeUser(user.toObject()),
    });
  } catch {
    res.status(503).json({ error: 'Unable to create a local simulator token.' });
  }
});

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
      await recordSecurityEvent(req, {
        eventType: 'USER_REGISTRATION_FAILED',
        severity: 'LOW',
        action: 'registration',
        message: 'User registration failed because the username or email already exists.',
        username,
        metadata: { reason: 'duplicate_user' },
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
    await recordSecurityEvent(req, {
      eventType: 'USER_REGISTRATION',
      severity: 'LOW',
      action: 'registration',
      message: 'User registration succeeded.',
      username: user.username,
      metadata: { role: user.role },
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
      await recordSecurityEvent(req, {
        eventType: 'LOGIN_FAILED',
        severity: 'MEDIUM',
        action: 'login',
        message: 'Login failed because the user was not found.',
        metadata: { reason: 'user_not_found' },
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
      await recordSecurityEvent(req, {
        eventType: 'LOGIN_FAILED',
        severity: 'MEDIUM',
        action: 'login',
        message: 'Login failed because the password was invalid.',
        username: user.username,
        metadata: { reason: 'invalid_password' },
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
      await recordSecurityEvent(req, {
        eventType: 'LOGIN_FAILED',
        severity: 'MEDIUM',
        action: 'login',
        message: 'Login failed because the account is inactive.',
        username: user.username,
        metadata: { reason: 'inactive_account' },
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
    await recordSecurityEvent(req, {
      eventType: 'LOGIN_SUCCESS',
      severity: 'LOW',
      action: 'login',
      message: 'Login succeeded.',
      username: user.username,
      metadata: { role: user.role },
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
