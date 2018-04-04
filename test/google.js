var spf = require('../index');

module.exports.google = function(assert) {
    let validator = new spf.SPFValidator('google.com');
    let promise = validator.getRecords();
    promise.then(function(records) {
      assert.equal(records.mechanisms.length, 3);
    }).catch(function(e) {
      assert.ifError(e);
    });
    let promise2 = validator.validateSender('172.217.9.142');
    promise2.then(function(result) {
      assert.equal(result, 'SOFTFAIL');
    }).catch(function(e) {
      assert.ifError(e);
    });
    let promise3 = validator.validateSender('google.com');
    promise3.then(function(result) {
      assert.equal(result, 'SOFTFAIL');
      assert.done();
    }).catch(function(e) {
      assert.ifError(e);
      assert.done();
    });
}

module.exports.googleExpand = function(assert) {
    let validator = new spf.SPFValidator({'domain': 'google.com', 'expandIncludes': true});
    let promise = validator.getRecords();
    promise.then(function(records) {
      assert.equal(records.mechanisms.length, 3);
    }).catch(function(e) {
      assert.ifError(e);
    });
    let promise2 = validator.validateSender('172.217.9.142');
    promise2.then(function(result) {
      assert.equal(result, 'PASS');
    }).catch(function(e) {
      assert.ifError(e);
    });
    let promise3 = validator.validateSender('google.com');
    promise3.then(function(result) {
      assert.equal(result, 'PASS');
      assert.done();
    }).catch(function(e) {
      assert.ifError(e);
      assert.done();
    });
}
