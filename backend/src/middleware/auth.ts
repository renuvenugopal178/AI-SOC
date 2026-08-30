import { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';
import User, { UserRole } from '../models/User';
import { recordSecurityEvent } from '../utils/securityTelemetry';

export interface AuthenticatedRequest extends Request {
  user?: {
    userId: string;
    role: UserRole;
    username?: string;
    email?: string;
  };
}

export const authenticate = async (
  req: AuthenticatedRequest,
  res: Response,
  next: NextFunction
): Promise<void> => {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    await recordSecurityEvent(req, {
      eventType: 'UNAUTHORIZED_ACCESS',
      severity: 'MEDIUM',
      action: 'authentication',
      message: 'Authentication failed because credentials were not provided.',
      metadata: { reason: 'missing_credentials' },
    });
    res.status(401).json({ error: 'Authentication required.' });
    return;
  }

  const token = authHeader.substring(7);

  try {
    const secret = process.env.JWT_SECRET || 'development-secret-change-me';
    const decoded = jwt.verify(token, secret) as { userId: string; role: UserRole };

    const user = await User.findById(decoded.userId).select('_id username email role isActive');

    if (!user || !user.isActive) {
      await recordSecurityEvent(req, {
        eventType: 'UNAUTHORIZED_ACCESS',
        severity: 'MEDIUM',
        action: 'authentication',
        message: 'Authentication failed because the account was not found or is inactive.',
        metadata: { reason: !user ? 'user_not_found' : 'inactive_account' },
      });
      res.status(401).json({ error: 'Authentication required.' });
      return;
    }

    req.user = {
      userId: user._id.toString(),
      role: user.role,
      username: user.username,
      email: user.email,
    };
    next();
  } catch (error) {
    await recordSecurityEvent(req, {
      eventType: 'UNAUTHORIZED_ACCESS',
      severity: 'MEDIUM',
      action: 'authentication',
      message: 'Authentication failed because the token was invalid or expired.',
      metadata: { reason: 'invalid_or_expired_token' },
    });
    res.status(401).json({ error: 'Invalid or expired token.' });
  }
};

export const requireRole = (...allowedRoles: UserRole[]) => {
  return (req: AuthenticatedRequest, res: Response, next: NextFunction): void => {
    if (!req.user) {
      res.status(401).json({ error: 'Authentication required.' });
      return;
    }

    if (!allowedRoles.includes(req.user.role)) {
      void recordSecurityEvent(req, {
        eventType: 'FORBIDDEN_ACCESS',
        severity: 'MEDIUM',
        action: 'authorization',
        message: 'Authorization failed because the user role is not permitted.',
        username: req.user.username,
        metadata: { role: req.user.role },
      });
      res.status(403).json({ error: 'You do not have permission to access this resource.' });
      return;
    }

    next();
  };
};
