var packageFile = require('../package');
var spf = require('../index');
var assert = require('chai').assert;

describe('Constants', function(){
  describe('version', function(){
    it('Should be a string', function(){
      assert.equal(typeof spf.version, 'string');
    });
    it('Should be same as package', function(){
      assert.equal(spf.version, packageFile.version);
    });
  });
  describe('SPFValidator', function(){
    it('Should be a function', function(){
      assert.equal(typeof spf.SPFValidator, 'function');
    });
  });
});
/* vim: set tabstop=2 shiftwidth=2 expandtab: */
