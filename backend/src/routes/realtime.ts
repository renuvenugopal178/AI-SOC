import { Router, Response } from 'express';
import { authenticate, AuthenticatedRequest, requireRole } from '../middleware/auth';
import { addRealtimeClient } from '../services/realtimeService';

const router = Router();

router.get('/events', authenticate, requireRole('ADMIN', 'SOC_ANALYST', 'VIEWER'), (req: AuthenticatedRequest, res: Response) => {
  res.status(200);
  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache, no-transform');
  res.setHeader('Connection', 'keep-alive');
  res.setHeader('X-Accel-Buffering', 'no');
  res.flushHeaders();
  res.write(': connected\n\n');

  const removeClient = addRealtimeClient(res);
  req.on('close', () => {
    removeClient();
  });
  res.on('close', removeClient);
  res.on('error', removeClient);
});

export default router;
