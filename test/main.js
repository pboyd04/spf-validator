var package = require('../package');
var spf = require('../index');

module.exports.constants = function(assert) {
    assert.ok(typeof spf.version == 'string');
    assert.ok(typeof spf.SPFValidator == 'function');
    assert.done();
}
