import mongoose from 'mongoose';
import dotenv from 'dotenv';
import DetectionRule from '../src/models/DetectionRule';

dotenv.config();

const baseRules = [
  {
    name: 'Multiple Failed Login Attempts',
    description: 'Detect repeated failed logins within a short time window.',
    ruleType: 'THRESHOLD',
    enabled: true,
    severity: 'HIGH',
    riskScore: 70,
    conditions: {
      field: 'eventType',
      operator: 'EQUALS',
      value: 'LOGIN_FAILED',
      threshold: 5,
      windowMinutes: 5,
    },
    createdBy: 'system',
  },
  {
    name: 'Critical Security Event',
    description: 'Trigger on critical severity security events.',
    ruleType: 'EVENT_MATCH',
    enabled: true,
    severity: 'CRITICAL',
    riskScore: 90,
    conditions: {
      field: 'severity',
      operator: 'EQUALS',
      value: 'CRITICAL',
    },
    createdBy: 'system',
  },
  {
    name: 'Suspicious Network Scan',
    description: 'Trigger on port scan activity from external sources.',
    ruleType: 'EVENT_MATCH',
    enabled: true,
    severity: 'HIGH',
    riskScore: 80,
    conditions: {
      field: 'eventType',
      operator: 'EQUALS',
      value: 'PORT_SCAN',
    },
    createdBy: 'system',
  },
];

const seedRules = async () => {
  const mongoUri = process.env.MONGODB_URI || 'mongodb://admin:change_me_password@localhost:27017/ai-soc?authSource=admin';
  await mongoose.connect(mongoUri);

  for (const rule of baseRules) {
    const existing = await DetectionRule.findOne({ name: rule.name });
    if (!existing) {
      await DetectionRule.create(rule);
    }
  }

  console.log('Detection rules seed complete.');
  await mongoose.disconnect();
};

seedRules().catch((error) => {
  console.error('Seed failed:', error);
  process.exitCode = 1;
});
