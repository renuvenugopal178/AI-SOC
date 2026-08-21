import mongoose from 'mongoose';
import bcrypt from 'bcrypt';
import dotenv from 'dotenv';
import User from '../src/models/User';

dotenv.config();

const MONGODB_URI =
  process.env.MONGODB_URI ||
  'mongodb://admin:change_me_password@localhost:27017/ai-soc?authSource=admin';

const ADMIN_USERNAME = process.env.ADMIN_USERNAME;
const ADMIN_EMAIL = process.env.ADMIN_EMAIL;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;

const main = async () => {
  if (!ADMIN_USERNAME || !ADMIN_EMAIL || !ADMIN_PASSWORD) {
    throw new Error(
      'ADMIN_USERNAME, ADMIN_EMAIL and ADMIN_PASSWORD environment variables are required.'
    );
  }

  if (ADMIN_USERNAME.length < 3 || ADMIN_USERNAME.length > 32) {
    throw new Error('ADMIN_USERNAME must be between 3 and 32 characters.');
  }

  if (ADMIN_PASSWORD.length < 12) {
    throw new Error('ADMIN_PASSWORD must contain at least 12 characters.');
  }

  if (!/[A-Z]/.test(ADMIN_PASSWORD)) {
    throw new Error('ADMIN_PASSWORD must contain an uppercase letter.');
  }

  if (!/[a-z]/.test(ADMIN_PASSWORD)) {
    throw new Error('ADMIN_PASSWORD must contain a lowercase letter.');
  }

  if (!/[0-9]/.test(ADMIN_PASSWORD)) {
    throw new Error('ADMIN_PASSWORD must contain a number.');
  }

  if (!/[^A-Za-z0-9]/.test(ADMIN_PASSWORD)) {
    throw new Error('ADMIN_PASSWORD must contain a special character.');
  }

  await mongoose.connect(MONGODB_URI);

  const existingByUsername = await User.findOne({
    username: ADMIN_USERNAME,
  });

  const existingByEmail = await User.findOne({
    email: ADMIN_EMAIL.toLowerCase(),
  });

  if (existingByUsername || existingByEmail) {
    const existingUser = existingByUsername || existingByEmail;

    if (existingUser?.role === 'ADMIN') {
      console.log('An ADMIN account with these credentials already exists.');
      return;
    }

    throw new Error(
      'A user with this username or email already exists and is not an ADMIN. No changes were made.'
    );
  }

  const passwordHash = await bcrypt.hash(ADMIN_PASSWORD, 12);

  await User.create({
    username: ADMIN_USERNAME,
    email: ADMIN_EMAIL.toLowerCase(),
    passwordHash,
    role: 'ADMIN',
    isActive: true,
  });

  console.log('ADMIN account created successfully.');
  console.log(`Username: ${ADMIN_USERNAME}`);
  console.log(`Email: ${ADMIN_EMAIL.toLowerCase()}`);
  console.log('Password: [hidden]');
};

main()
  .catch((error) => {
    console.error(
      error instanceof Error ? error.message : 'Failed to create ADMIN account.'
    );
    process.exitCode = 1;
  })
  .finally(async () => {
    await mongoose.disconnect();
  });