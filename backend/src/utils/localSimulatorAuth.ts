import fs from 'fs';
import path from 'path';
import crypto from 'crypto';

const secretFile = path.resolve(__dirname, '../../.local-simulator-secret');

export const getLocalSimulatorSecret = (): string | null => {
  const configuredSecret = process.env.LOCAL_SIMULATOR_SECRET?.trim();
  if (configuredSecret) return configuredSecret;

  try {
    const fileSecret = fs.readFileSync(secretFile, 'utf8').trim();
    return fileSecret || null;
  } catch {
    return null;
  }
};

export const ensureLocalSimulatorSecret = (): string => {
  const existingSecret = getLocalSimulatorSecret();
  if (existingSecret) return existingSecret;

  const generatedSecret = crypto.randomBytes(32).toString('hex');
  fs.writeFileSync(secretFile, `${generatedSecret}\n`, { encoding: 'utf8', mode: 0o600 });
  return generatedSecret;
};

export const isLoopbackRequest = (address?: string): boolean => {
  if (!address) return false;
  const normalizedAddress = address.replace(/^::ffff:/, '');
  return normalizedAddress === '::1'
    || normalizedAddress === '127.0.0.1'
    || normalizedAddress.startsWith('127.');
};