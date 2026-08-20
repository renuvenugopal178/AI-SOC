import { Router, Response } from 'express';
import { authenticate, AuthenticatedRequest, requireRole } from '../middleware/auth';

const router = Router();

router.get('/test', authenticate, requireRole('ADMIN'), (req: AuthenticatedRequest, res: Response) => {
  res.status(200).json({
    message: 'Admin access granted.',
    user: {
      userId: req.user?.userId,
      role: req.user?.role,
      username: req.user?.username,
    },
  });
});

export default router;
