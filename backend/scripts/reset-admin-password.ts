import mongoose from 'mongoose';
import dotenv from 'dotenv';
import { resetAdminPassword } from '../src/utils/adminPasswordReset';

dotenv.config();

const MONGODB_URI =
  process.env.MONGODB_URI ||
  'mongodb://admin:change_me_password@localhost:27017/ai-soc?authSource=admin';

const main = async () => {
  await mongoose.connect(MONGODB_URI);
  await resetAdminPassword();
};

main()
  .catch((error) => {
    console.error(
      error instanceof Error ? error.message : 'Failed to reset ADMIN password.'
    );
    process.exitCode = 1;
  })
  .finally(async () => {
    await mongoose.disconnect();
  });

