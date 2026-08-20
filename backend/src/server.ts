import app from './app';
import { connectDatabase } from './config/database';
import dotenv from 'dotenv';

dotenv.config();

const PORT = Number(process.env.PORT) || 4000;

const startServer = async (): Promise<void> => {
  const dbConnected = await connectDatabase();

  if (!dbConnected) {
    console.warn('MongoDB is unavailable. The backend will continue running without database connectivity for this baseline setup.');
  }

  app.listen(PORT, () => {
    console.log(`AI-SOC backend running on http://localhost:${PORT}`);
  });
};

startServer();
