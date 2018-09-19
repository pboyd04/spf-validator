var spf = require('../index');

test('Version is string', () => {
  expect(typeof spf.version).toBe('string');
});
test('SPFValidator is function', () => {
  expect(typeof spf.SPFValidator).toBe('function');
});
