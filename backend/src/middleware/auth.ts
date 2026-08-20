import { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';
import User, { UserRole } from '../models/User';

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
    res.status(401).json({ error: 'Authentication required.' });
    return;
  }

  const token = authHeader.substring(7);

  try {
    const secret = process.env.JWT_SECRET || 'development-secret-change-me';
    const decoded = jwt.verify(token, secret) as { userId: string; role: UserRole };

    const user = await User.findById(decoded.userId).select('_id username email role isActive');

    if (!user || !user.isActive) {
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
      res.status(403).json({ error: 'You do not have permission to access this resource.' });
      return;
    }

    next();
  };
};
