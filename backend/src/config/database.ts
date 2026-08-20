import mongoose from 'mongoose';
import dotenv from 'dotenv';

dotenv.config();

const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://admin:change_me_password@localhost:27017/ai-soc?authSource=admin';

export const connectDatabase = async (retries = 5, delayMs = 2000): Promise<boolean> => {
  try {
    await mongoose.connect(MONGODB_URI);
    console.log('MongoDB connected successfully');
    return true;
  } catch (error) {
    if (retries > 0) {
      console.warn(`MongoDB connection failed. Retrying in ${delayMs / 1000}s...`);
      await new Promise((resolve) => setTimeout(resolve, delayMs));
      return connectDatabase(retries - 1, delayMs);
    }

    console.error('MongoDB connection failed after retries:', error);
    return false;
  }
};
