var spf = require('../index');
var assert = require('chai').assert;

describe('Google', function(){
  describe('No Expand', function(){
    let validator = new spf.SPFValidator('google.com');
    it('Get Records', function(){
      this.timeout(5000);
      let promise = validator.getRecords();
      return promise.then((records) => {
        assert.equal(records.mechanisms.length, 3);
      });
    });
    it('Validate by IP', function() {
      this.timeout(5000);
      let promise = validator.validateSender('172.217.9.142');
      return promise.then((result) => {
        assert.equal(result, 'SOFTFAIL');
      });
    });
    it('Validate by Domain Name', function() {
      this.timeout(5000);
      let promise = validator.validateSender('google.com');
      return promise.then((result) => {
        assert.equal(result, 'SOFTFAIL');
      });
    });
  });
  describe('Expand', function(){
    let validator = new spf.SPFValidator({'domain': 'google.com', 'expandIncludes': true});
    it('Get Records', function(){
      this.timeout(5000);
      let promise = validator.getRecords();
      return promise.then((records) => {
        assert.equal(records.mechanisms.length, 3);
      });
    });
    it('Validate by IP', function() {
      this.timeout(5000);
      let promise = validator.validateSender('172.217.9.142');
      return promise.then((result) => {
        assert.equal(result, 'PASS');
      });
    });
    it('Validate by Domain Name', function() {
      this.timeout(5000);
      let promise = validator.validateSender('google.com');
      return promise.then((result) => {
        assert.equal(result, 'PASS');
      });
    });
  });
});
/* vim: set tabstop=2 shiftwidth=2 expandtab: */
