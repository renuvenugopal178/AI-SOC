describe('test database isolation', () => {
  it('always targets the dedicated ai-soc-test database', () => {
    expect(process.env.MONGODB_URI).toContain('/ai-soc-test?');
    expect(process.env.MONGODB_URI).not.toContain('/ai-soc?');
  });
});
