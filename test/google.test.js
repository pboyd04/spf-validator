var spf = require('../index');

test('google.com has 3 mechanisms (no expand)', () => {
  let validator = new spf.SPFValidator('google.com');
  let promise = validator.getRecords();
  return promise.then(records => {
    expect(records.mechanisms.length).toBe(3);
  });
});

test('google ip address SOFTFAIL (no expand)', () => {
  let validator = new spf.SPFValidator('google.com');
  let promise = validator.validateSender('172.217.9.142');
  return promise.then(result => {
    expect(result).toBe('SOFTFAIL');
  });
});

test('google.com has 3 mechanisms (expand)', () => {
  let validator = new spf.SPFValidator({'domain': 'google.com', 'expandIncludes': true});
  let promise = validator.getRecords();
  return promise.then(records => {
    expect(records.mechanisms.length).toBe(3);
  });
});

test('google.com address SOFTFAIL (no expand)', () => {
  let validator = new spf.SPFValidator('google.com');
  let promise = validator.validateSender('google.com');
  return promise.then(result => {
    expect(result).toBe('SOFTFAIL');
  });
});

test('google ip address PASS (expand)', () => {
  let validator = new spf.SPFValidator({'domain': 'google.com', 'expandIncludes': true});
  let promise = validator.validateSender('172.217.9.142');
  return promise.then(result => {
    expect(result).toBe('PASS');
  });
});

test('google.com address PASS (expand)', () => {
  let validator = new spf.SPFValidator({'domain': 'google.com', 'expandIncludes': true});
  let promise = validator.validateSender('google.com');
  return promise.then(result => {
    expect(result).toBe('PASS');
  });
});
