process.env.NODE_ENV = 'test';
process.env.JWT_SECRET = 'test-secret-key';

const testMongoUri = process.env.TEST_MONGODB_URI || 'mongodb://admin:change_me_password@localhost:27017/ai-soc-test?authSource=admin';
if (!/[\/]ai-soc-test(?:\?|$)/.test(testMongoUri)) {
  throw new Error('TEST_MONGODB_URI must target the ai-soc-test database.');
}

process.env.MONGODB_URI = testMongoUri;