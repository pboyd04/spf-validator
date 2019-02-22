var spf = require('../index').SPFValidator;
var assert = require('chai').assert;

describe('OpenSPF', function(){
  describe('RFC4408', function(){
    describe('Initial processing', function(){
      it('DNS labels limited to 63 chars.', function(){
        let email = 'lyme.eater@A123456789012345678901234567890123456789012345678901234567890123.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"example.com":["TIMEOUT"],"example.net":[{"SPF":"v=spf1 -all exp=exp.example.net"}],"a.example.net":[{"SPF":"v=spf1 -all exp=exp.example.net"}],"exp.example.net":[{"TXT":"%{l}"}],"a12345678901234567890123456789012345678901234567890123456789012.example.com":[{"SPF":"v=spf1 -all"}],"hosed.example.com":[{"SPF":"v=spf1 a:ï»¿garbage.example.net -all"}],"hosed2.example.com":[{"SPF":"v=spf1 a:example.net -all"}],"hosed3.example.com":[{"SPF":"v=spf1 a:example.net all"}],"nothosed.example.com":[{"SPF":"v=spf1 a:example.net -all"},{"SPF":""}],"fine.example.com":[{"TXT":"v=spf1 a  -all"}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.5');
        return promise.then((result) => {
          assert.equal(result, 'NONE');
        });
      });
      it('DNS labels limited to 63 chars.', function(){
        let email = 'lyme.eater@A12345678901234567890123456789012345678901234567890123456789012.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"example.com":["TIMEOUT"],"example.net":[{"SPF":"v=spf1 -all exp=exp.example.net"}],"a.example.net":[{"SPF":"v=spf1 -all exp=exp.example.net"}],"exp.example.net":[{"TXT":"%{l}"}],"a12345678901234567890123456789012345678901234567890123456789012.example.com":[{"SPF":"v=spf1 -all"}],"hosed.example.com":[{"SPF":"v=spf1 a:ï»¿garbage.example.net -all"}],"hosed2.example.com":[{"SPF":"v=spf1 a:example.net -all"}],"hosed3.example.com":[{"SPF":"v=spf1 a:example.net all"}],"nothosed.example.com":[{"SPF":"v=spf1 a:example.net -all"},{"SPF":""}],"fine.example.com":[{"TXT":"v=spf1 a  -all"}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.5');
        return promise.then((result) => {
          assert.equal(result, 'FAIL');
        });
      });
      it('emptylabel', function(){
        let email = 'lyme.eater@A...example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"example.com":["TIMEOUT"],"example.net":[{"SPF":"v=spf1 -all exp=exp.example.net"}],"a.example.net":[{"SPF":"v=spf1 -all exp=exp.example.net"}],"exp.example.net":[{"TXT":"%{l}"}],"a12345678901234567890123456789012345678901234567890123456789012.example.com":[{"SPF":"v=spf1 -all"}],"hosed.example.com":[{"SPF":"v=spf1 a:ï»¿garbage.example.net -all"}],"hosed2.example.com":[{"SPF":"v=spf1 a:example.net -all"}],"hosed3.example.com":[{"SPF":"v=spf1 a:example.net all"}],"nothosed.example.com":[{"SPF":"v=spf1 a:example.net -all"},{"SPF":""}],"fine.example.com":[{"TXT":"v=spf1 a  -all"}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.5');
        return promise.then((result) => {
          assert.equal(result, 'NONE');
        });
      });
      it('helo-not-fqdn', function(){
        let email = '';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"example.com":["TIMEOUT"],"example.net":[{"SPF":"v=spf1 -all exp=exp.example.net"}],"a.example.net":[{"SPF":"v=spf1 -all exp=exp.example.net"}],"exp.example.net":[{"TXT":"%{l}"}],"a12345678901234567890123456789012345678901234567890123456789012.example.com":[{"SPF":"v=spf1 -all"}],"hosed.example.com":[{"SPF":"v=spf1 a:ï»¿garbage.example.net -all"}],"hosed2.example.com":[{"SPF":"v=spf1 a:example.net -all"}],"hosed3.example.com":[{"SPF":"v=spf1 a:example.net all"}],"nothosed.example.com":[{"SPF":"v=spf1 a:example.net -all"},{"SPF":""}],"fine.example.com":[{"TXT":"v=spf1 a  -all"}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.5');
        return promise.then((result) => {
          assert.equal(result, 'NONE');
        });
      });
      it('helo-domain-literal', function(){
        let email = '';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"example.com":["TIMEOUT"],"example.net":[{"SPF":"v=spf1 -all exp=exp.example.net"}],"a.example.net":[{"SPF":"v=spf1 -all exp=exp.example.net"}],"exp.example.net":[{"TXT":"%{l}"}],"a12345678901234567890123456789012345678901234567890123456789012.example.com":[{"SPF":"v=spf1 -all"}],"hosed.example.com":[{"SPF":"v=spf1 a:ï»¿garbage.example.net -all"}],"hosed2.example.com":[{"SPF":"v=spf1 a:example.net -all"}],"hosed3.example.com":[{"SPF":"v=spf1 a:example.net all"}],"nothosed.example.com":[{"SPF":"v=spf1 a:example.net -all"},{"SPF":""}],"fine.example.com":[{"TXT":"v=spf1 a  -all"}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.5');
        return promise.then((result) => {
          assert.equal(result, 'NONE');
        });
      });
      it('nolocalpart', function(){
        let email = '@example.net';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"example.com":["TIMEOUT"],"example.net":[{"SPF":"v=spf1 -all exp=exp.example.net"}],"a.example.net":[{"SPF":"v=spf1 -all exp=exp.example.net"}],"exp.example.net":[{"TXT":"%{l}"}],"a12345678901234567890123456789012345678901234567890123456789012.example.com":[{"SPF":"v=spf1 -all"}],"hosed.example.com":[{"SPF":"v=spf1 a:ï»¿garbage.example.net -all"}],"hosed2.example.com":[{"SPF":"v=spf1 a:example.net -all"}],"hosed3.example.com":[{"SPF":"v=spf1 a:example.net all"}],"nothosed.example.com":[{"SPF":"v=spf1 a:example.net -all"},{"SPF":""}],"fine.example.com":[{"TXT":"v=spf1 a  -all"}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.4');
        return promise.then((result) => {
          assert.equal(result, 'FAIL');
        });
      });
      it('domain-literal', function(){
        let email = 'foo@[1.2.3.5]';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"example.com":["TIMEOUT"],"example.net":[{"SPF":"v=spf1 -all exp=exp.example.net"}],"a.example.net":[{"SPF":"v=spf1 -all exp=exp.example.net"}],"exp.example.net":[{"TXT":"%{l}"}],"a12345678901234567890123456789012345678901234567890123456789012.example.com":[{"SPF":"v=spf1 -all"}],"hosed.example.com":[{"SPF":"v=spf1 a:ï»¿garbage.example.net -all"}],"hosed2.example.com":[{"SPF":"v=spf1 a:example.net -all"}],"hosed3.example.com":[{"SPF":"v=spf1 a:example.net all"}],"nothosed.example.com":[{"SPF":"v=spf1 a:example.net -all"},{"SPF":""}],"fine.example.com":[{"TXT":"v=spf1 a  -all"}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.5');
        return promise.then((result) => {
          assert.equal(result, 'NONE');
        });
      });
      it('SPF policies are restricted to 7-bit ascii.', function(){
        let email = 'foobar@hosed.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"example.com":["TIMEOUT"],"example.net":[{"SPF":"v=spf1 -all exp=exp.example.net"}],"a.example.net":[{"SPF":"v=spf1 -all exp=exp.example.net"}],"exp.example.net":[{"TXT":"%{l}"}],"a12345678901234567890123456789012345678901234567890123456789012.example.com":[{"SPF":"v=spf1 -all"}],"hosed.example.com":[{"SPF":"v=spf1 a:ï»¿garbage.example.net -all"}],"hosed2.example.com":[{"SPF":"v=spf1 a:example.net -all"}],"hosed3.example.com":[{"SPF":"v=spf1 a:example.net all"}],"nothosed.example.com":[{"SPF":"v=spf1 a:example.net -all"},{"SPF":""}],"fine.example.com":[{"TXT":"v=spf1 a  -all"}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.4');
        return promise.then((result) => {
          assert.equal(result, 'PERMERROR');
        });
      });
      it('SPF policies are restricted to 7-bit ascii.', function(){
        let email = 'foobar@hosed2.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"example.com":["TIMEOUT"],"example.net":[{"SPF":"v=spf1 -all exp=exp.example.net"}],"a.example.net":[{"SPF":"v=spf1 -all exp=exp.example.net"}],"exp.example.net":[{"TXT":"%{l}"}],"a12345678901234567890123456789012345678901234567890123456789012.example.com":[{"SPF":"v=spf1 -all"}],"hosed.example.com":[{"SPF":"v=spf1 a:ï»¿garbage.example.net -all"}],"hosed2.example.com":[{"SPF":"v=spf1 a:example.net -all"}],"hosed3.example.com":[{"SPF":"v=spf1 a:example.net all"}],"nothosed.example.com":[{"SPF":"v=spf1 a:example.net -all"},{"SPF":""}],"fine.example.com":[{"TXT":"v=spf1 a  -all"}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.4');
        return promise.then((result) => {
          assert.equal(result, 'PERMERROR');
        });
      });
      it('SPF policies are restricted to 7-bit ascii.', function(){
        let email = 'foobar@hosed3.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"example.com":["TIMEOUT"],"example.net":[{"SPF":"v=spf1 -all exp=exp.example.net"}],"a.example.net":[{"SPF":"v=spf1 -all exp=exp.example.net"}],"exp.example.net":[{"TXT":"%{l}"}],"a12345678901234567890123456789012345678901234567890123456789012.example.com":[{"SPF":"v=spf1 -all"}],"hosed.example.com":[{"SPF":"v=spf1 a:ï»¿garbage.example.net -all"}],"hosed2.example.com":[{"SPF":"v=spf1 a:example.net -all"}],"hosed3.example.com":[{"SPF":"v=spf1 a:example.net all"}],"nothosed.example.com":[{"SPF":"v=spf1 a:example.net -all"},{"SPF":""}],"fine.example.com":[{"TXT":"v=spf1 a  -all"}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.4');
        return promise.then((result) => {
          assert.equal(result, 'PERMERROR');
        });
      });
      it('Non-ascii content in non-SPF related records.', function(){
        let email = 'foobar@nothosed.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"example.com":["TIMEOUT"],"example.net":[{"SPF":"v=spf1 -all exp=exp.example.net"}],"a.example.net":[{"SPF":"v=spf1 -all exp=exp.example.net"}],"exp.example.net":[{"TXT":"%{l}"}],"a12345678901234567890123456789012345678901234567890123456789012.example.com":[{"SPF":"v=spf1 -all"}],"hosed.example.com":[{"SPF":"v=spf1 a:ï»¿garbage.example.net -all"}],"hosed2.example.com":[{"SPF":"v=spf1 a:example.net -all"}],"hosed3.example.com":[{"SPF":"v=spf1 a:example.net all"}],"nothosed.example.com":[{"SPF":"v=spf1 a:example.net -all"},{"SPF":""}],"fine.example.com":[{"TXT":"v=spf1 a  -all"}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.4');
        return promise.then((result) => {
          assert.equal(result, 'FAIL');
        });
      });
      it('ABNF for term separation is one or more spaces, not just one.', function(){
        let email = 'actually@fine.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"example.com":["TIMEOUT"],"example.net":[{"SPF":"v=spf1 -all exp=exp.example.net"}],"a.example.net":[{"SPF":"v=spf1 -all exp=exp.example.net"}],"exp.example.net":[{"TXT":"%{l}"}],"a12345678901234567890123456789012345678901234567890123456789012.example.com":[{"SPF":"v=spf1 -all"}],"hosed.example.com":[{"SPF":"v=spf1 a:ï»¿garbage.example.net -all"}],"hosed2.example.com":[{"SPF":"v=spf1 a:example.net -all"}],"hosed3.example.com":[{"SPF":"v=spf1 a:example.net all"}],"nothosed.example.com":[{"SPF":"v=spf1 a:example.net -all"},{"SPF":""}],"fine.example.com":[{"TXT":"v=spf1 a  -all"}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.4');
        return promise.then((result) => {
          assert.equal(result, 'FAIL');
        });
      });
    });
    describe('Record lookup', function(){
      it('both', function(){
        let email = 'foo@both.example.net';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"both.example.net":[{"TXT":"v=spf1 -all"},{"SPF":"v=spf1 -all"}],"txtonly.example.net":[{"TXT":"v=spf1 -all"}],"spfonly.example.net":[{"SPF":"v=spf1 -all"},{"TXT":"NONE"}],"spftimeout.example.net":[{"TXT":"v=spf1 -all"},"TIMEOUT"],"txttimeout.example.net":[{"SPF":"v=spf1 -all"},{"TXT":"NONE"},"TIMEOUT"],"nospftxttimeout.example.net":[{"SPF":"v=spf3 !a:yahoo.com -all"},{"TXT":"NONE"},"TIMEOUT"],"alltimeout.example.net":["TIMEOUT"]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.4');
        return promise.then((result) => {
          assert.equal(result, 'FAIL');
        });
      });
      it('Result is none if checking SPF records only.', function(){
        let email = 'foo@txtonly.example.net';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"both.example.net":[{"TXT":"v=spf1 -all"},{"SPF":"v=spf1 -all"}],"txtonly.example.net":[{"TXT":"v=spf1 -all"}],"spfonly.example.net":[{"SPF":"v=spf1 -all"},{"TXT":"NONE"}],"spftimeout.example.net":[{"TXT":"v=spf1 -all"},"TIMEOUT"],"txttimeout.example.net":[{"SPF":"v=spf1 -all"},{"TXT":"NONE"},"TIMEOUT"],"nospftxttimeout.example.net":[{"SPF":"v=spf3 !a:yahoo.com -all"},{"TXT":"NONE"},"TIMEOUT"],"alltimeout.example.net":["TIMEOUT"]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.4');
        return promise.then((result) => {
          assert.include(["fail","none"], result.toLowerCase());
        });
      });
      it('Result is none if checking TXT records only.', function(){
        let email = 'foo@spfonly.example.net';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"both.example.net":[{"TXT":"v=spf1 -all"},{"SPF":"v=spf1 -all"}],"txtonly.example.net":[{"TXT":"v=spf1 -all"}],"spfonly.example.net":[{"SPF":"v=spf1 -all"},{"TXT":"NONE"}],"spftimeout.example.net":[{"TXT":"v=spf1 -all"},"TIMEOUT"],"txttimeout.example.net":[{"SPF":"v=spf1 -all"},{"TXT":"NONE"},"TIMEOUT"],"nospftxttimeout.example.net":[{"SPF":"v=spf3 !a:yahoo.com -all"},{"TXT":"NONE"},"TIMEOUT"],"alltimeout.example.net":["TIMEOUT"]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.4');
        return promise.then((result) => {
          assert.include(["fail","none"], result.toLowerCase());
        });
      });
      it('TXT record present, but SPF lookup times out. Result is temperror if checking SPF records only.', function(){
        let email = 'foo@spftimeout.example.net';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"both.example.net":[{"TXT":"v=spf1 -all"},{"SPF":"v=spf1 -all"}],"txtonly.example.net":[{"TXT":"v=spf1 -all"}],"spfonly.example.net":[{"SPF":"v=spf1 -all"},{"TXT":"NONE"}],"spftimeout.example.net":[{"TXT":"v=spf1 -all"},"TIMEOUT"],"txttimeout.example.net":[{"SPF":"v=spf1 -all"},{"TXT":"NONE"},"TIMEOUT"],"nospftxttimeout.example.net":[{"SPF":"v=spf3 !a:yahoo.com -all"},{"TXT":"NONE"},"TIMEOUT"],"alltimeout.example.net":["TIMEOUT"]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.4');
        return promise.then((result) => {
          assert.include(["fail","temperror"], result.toLowerCase());
        });
      });
      it('SPF record present, but TXT lookup times out. If only TXT records are checked, result is temperror.', function(){
        let email = 'foo@txttimeout.example.net';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"both.example.net":[{"TXT":"v=spf1 -all"},{"SPF":"v=spf1 -all"}],"txtonly.example.net":[{"TXT":"v=spf1 -all"}],"spfonly.example.net":[{"SPF":"v=spf1 -all"},{"TXT":"NONE"}],"spftimeout.example.net":[{"TXT":"v=spf1 -all"},"TIMEOUT"],"txttimeout.example.net":[{"SPF":"v=spf1 -all"},{"TXT":"NONE"},"TIMEOUT"],"nospftxttimeout.example.net":[{"SPF":"v=spf3 !a:yahoo.com -all"},{"TXT":"NONE"},"TIMEOUT"],"alltimeout.example.net":["TIMEOUT"]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.4');
        return promise.then((result) => {
          assert.include(["fail","temperror"], result.toLowerCase());
        });
      });
      it('No SPF record present, and TXT lookup times out. If only TXT records are checked, result is temperror.', function(){
        let email = 'foo@nospftxttimeout.example.net';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"both.example.net":[{"TXT":"v=spf1 -all"},{"SPF":"v=spf1 -all"}],"txtonly.example.net":[{"TXT":"v=spf1 -all"}],"spfonly.example.net":[{"SPF":"v=spf1 -all"},{"TXT":"NONE"}],"spftimeout.example.net":[{"TXT":"v=spf1 -all"},"TIMEOUT"],"txttimeout.example.net":[{"SPF":"v=spf1 -all"},{"TXT":"NONE"},"TIMEOUT"],"nospftxttimeout.example.net":[{"SPF":"v=spf3 !a:yahoo.com -all"},{"TXT":"NONE"},"TIMEOUT"],"alltimeout.example.net":["TIMEOUT"]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.4');
        return promise.then((result) => {
          assert.include(["temperror","none"], result.toLowerCase());
        });
      });
      it('Both TXT and SPF queries time out', function(){
        let email = 'foo@alltimeout.example.net';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"both.example.net":[{"TXT":"v=spf1 -all"},{"SPF":"v=spf1 -all"}],"txtonly.example.net":[{"TXT":"v=spf1 -all"}],"spfonly.example.net":[{"SPF":"v=spf1 -all"},{"TXT":"NONE"}],"spftimeout.example.net":[{"TXT":"v=spf1 -all"},"TIMEOUT"],"txttimeout.example.net":[{"SPF":"v=spf1 -all"},{"TXT":"NONE"},"TIMEOUT"],"nospftxttimeout.example.net":[{"SPF":"v=spf3 !a:yahoo.com -all"},{"TXT":"NONE"},"TIMEOUT"],"alltimeout.example.net":["TIMEOUT"]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.4');
        return promise.then((result) => {
          assert.equal(result, 'TEMPERROR');
        });
      });
    });
    describe('Selecting records', function(){
      it('Version must be terminated by space or end of record.  TXT pieces are joined without intervening spaces.', function(){
        let email = 'foo@example2.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"example3.com":[{"SPF":"v=spf10"},{"SPF":"v=spf1 mx"},{"MX":[0,"mail.example1.com"]}],"example1.com":[{"SPF":"v=spf1"}],"example2.com":[{"SPF":["v=spf1","mx"]}],"mail.example1.com":[{"A":"1.2.3.4"}],"example4.com":[{"SPF":"v=spf1 +all"},{"TXT":"v=spf1 -all"}],"example5.com":[{"SPF":"v=spf1 +all"},{"TXT":"v=spf1 -all"},{"TXT":"v=spf1 +all"}],"example6.com":[{"SPF":"v=spf1 -all"},{"SPF":"V=sPf1 +all"}],"example7.com":[{"SPF":"v=spf1 -all"},{"SPF":"v=spf1 -all"}],"example8.com":[{"SPF":"V=spf1 -all"},{"SPF":"v=spf1 -all"},{"TXT":"v=spf1 +all"}],"example9.com":[{"SPF":"v=SpF1 ~all"}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.4');
        return promise.then((result) => {
          assert.equal(result, 'NONE');
        });
      });
      it('Empty SPF record.', function(){
        let email = 'foo@example1.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"example3.com":[{"SPF":"v=spf10"},{"SPF":"v=spf1 mx"},{"MX":[0,"mail.example1.com"]}],"example1.com":[{"SPF":"v=spf1"}],"example2.com":[{"SPF":["v=spf1","mx"]}],"mail.example1.com":[{"A":"1.2.3.4"}],"example4.com":[{"SPF":"v=spf1 +all"},{"TXT":"v=spf1 -all"}],"example5.com":[{"SPF":"v=spf1 +all"},{"TXT":"v=spf1 -all"},{"TXT":"v=spf1 +all"}],"example6.com":[{"SPF":"v=spf1 -all"},{"SPF":"V=sPf1 +all"}],"example7.com":[{"SPF":"v=spf1 -all"},{"SPF":"v=spf1 -all"}],"example8.com":[{"SPF":"V=spf1 -all"},{"SPF":"v=spf1 -all"},{"TXT":"v=spf1 +all"}],"example9.com":[{"SPF":"v=SpF1 ~all"}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.4');
        return promise.then((result) => {
          assert.equal(result, 'NEUTRAL');
        });
      });
      it('nospace2', function(){
        let email = 'foo@example3.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"example3.com":[{"SPF":"v=spf10"},{"SPF":"v=spf1 mx"},{"MX":[0,"mail.example1.com"]}],"example1.com":[{"SPF":"v=spf1"}],"example2.com":[{"SPF":["v=spf1","mx"]}],"mail.example1.com":[{"A":"1.2.3.4"}],"example4.com":[{"SPF":"v=spf1 +all"},{"TXT":"v=spf1 -all"}],"example5.com":[{"SPF":"v=spf1 +all"},{"TXT":"v=spf1 -all"},{"TXT":"v=spf1 +all"}],"example6.com":[{"SPF":"v=spf1 -all"},{"SPF":"V=sPf1 +all"}],"example7.com":[{"SPF":"v=spf1 -all"},{"SPF":"v=spf1 -all"}],"example8.com":[{"SPF":"V=spf1 -all"},{"SPF":"v=spf1 -all"},{"TXT":"v=spf1 +all"}],"example9.com":[{"SPF":"v=SpF1 ~all"}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.4');
        return promise.then((result) => {
          assert.equal(result, 'PASS');
        });
      });
      it('SPF records override TXT records.  Older implementation may check TXT records only.', function(){
        let email = 'foo@example4.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"example3.com":[{"SPF":"v=spf10"},{"SPF":"v=spf1 mx"},{"MX":[0,"mail.example1.com"]}],"example1.com":[{"SPF":"v=spf1"}],"example2.com":[{"SPF":["v=spf1","mx"]}],"mail.example1.com":[{"A":"1.2.3.4"}],"example4.com":[{"SPF":"v=spf1 +all"},{"TXT":"v=spf1 -all"}],"example5.com":[{"SPF":"v=spf1 +all"},{"TXT":"v=spf1 -all"},{"TXT":"v=spf1 +all"}],"example6.com":[{"SPF":"v=spf1 -all"},{"SPF":"V=sPf1 +all"}],"example7.com":[{"SPF":"v=spf1 -all"},{"SPF":"v=spf1 -all"}],"example8.com":[{"SPF":"V=spf1 -all"},{"SPF":"v=spf1 -all"},{"TXT":"v=spf1 +all"}],"example9.com":[{"SPF":"v=SpF1 ~all"}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.4');
        return promise.then((result) => {
          assert.include(["pass","fail"], result.toLowerCase());
        });
      });
      it('Older implementations will give permerror/unknown because of the conflicting TXT records.  However, RFC 4408 says the SPF records overrides them.', function(){
        let email = 'foo@example5.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"example3.com":[{"SPF":"v=spf10"},{"SPF":"v=spf1 mx"},{"MX":[0,"mail.example1.com"]}],"example1.com":[{"SPF":"v=spf1"}],"example2.com":[{"SPF":["v=spf1","mx"]}],"mail.example1.com":[{"A":"1.2.3.4"}],"example4.com":[{"SPF":"v=spf1 +all"},{"TXT":"v=spf1 -all"}],"example5.com":[{"SPF":"v=spf1 +all"},{"TXT":"v=spf1 -all"},{"TXT":"v=spf1 +all"}],"example6.com":[{"SPF":"v=spf1 -all"},{"SPF":"V=sPf1 +all"}],"example7.com":[{"SPF":"v=spf1 -all"},{"SPF":"v=spf1 -all"}],"example8.com":[{"SPF":"V=spf1 -all"},{"SPF":"v=spf1 -all"},{"TXT":"v=spf1 +all"}],"example9.com":[{"SPF":"v=SpF1 ~all"}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.4');
        return promise.then((result) => {
          assert.include(["pass","permerror"], result.toLowerCase());
        });
      });
      it('Multiple records is a permerror, v=spf1 is case insensitive', function(){
        let email = 'foo@example6.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"example3.com":[{"SPF":"v=spf10"},{"SPF":"v=spf1 mx"},{"MX":[0,"mail.example1.com"]}],"example1.com":[{"SPF":"v=spf1"}],"example2.com":[{"SPF":["v=spf1","mx"]}],"mail.example1.com":[{"A":"1.2.3.4"}],"example4.com":[{"SPF":"v=spf1 +all"},{"TXT":"v=spf1 -all"}],"example5.com":[{"SPF":"v=spf1 +all"},{"TXT":"v=spf1 -all"},{"TXT":"v=spf1 +all"}],"example6.com":[{"SPF":"v=spf1 -all"},{"SPF":"V=sPf1 +all"}],"example7.com":[{"SPF":"v=spf1 -all"},{"SPF":"v=spf1 -all"}],"example8.com":[{"SPF":"V=spf1 -all"},{"SPF":"v=spf1 -all"},{"TXT":"v=spf1 +all"}],"example9.com":[{"SPF":"v=SpF1 ~all"}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.4');
        return promise.then((result) => {
          assert.equal(result, 'PERMERROR');
        });
      });
      it('Multiple records is a permerror, even when they are identical. However, this situation cannot be reliably reproduced with live DNS since cache and resolvers are allowed to combine identical records.', function(){
        let email = 'foo@example7.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"example3.com":[{"SPF":"v=spf10"},{"SPF":"v=spf1 mx"},{"MX":[0,"mail.example1.com"]}],"example1.com":[{"SPF":"v=spf1"}],"example2.com":[{"SPF":["v=spf1","mx"]}],"mail.example1.com":[{"A":"1.2.3.4"}],"example4.com":[{"SPF":"v=spf1 +all"},{"TXT":"v=spf1 -all"}],"example5.com":[{"SPF":"v=spf1 +all"},{"TXT":"v=spf1 -all"},{"TXT":"v=spf1 +all"}],"example6.com":[{"SPF":"v=spf1 -all"},{"SPF":"V=sPf1 +all"}],"example7.com":[{"SPF":"v=spf1 -all"},{"SPF":"v=spf1 -all"}],"example8.com":[{"SPF":"V=spf1 -all"},{"SPF":"v=spf1 -all"},{"TXT":"v=spf1 +all"}],"example9.com":[{"SPF":"v=SpF1 ~all"}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.4');
        return promise.then((result) => {
          assert.include(["permerror","fail"], result.toLowerCase());
        });
      });
      it('Older implementations ignoring SPF-type records will give pass because there is a (single) TXT record.  But RFC 4408 requires permerror because the SPF records override and there are more than one.', function(){
        let email = 'foo@example8.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"example3.com":[{"SPF":"v=spf10"},{"SPF":"v=spf1 mx"},{"MX":[0,"mail.example1.com"]}],"example1.com":[{"SPF":"v=spf1"}],"example2.com":[{"SPF":["v=spf1","mx"]}],"mail.example1.com":[{"A":"1.2.3.4"}],"example4.com":[{"SPF":"v=spf1 +all"},{"TXT":"v=spf1 -all"}],"example5.com":[{"SPF":"v=spf1 +all"},{"TXT":"v=spf1 -all"},{"TXT":"v=spf1 +all"}],"example6.com":[{"SPF":"v=spf1 -all"},{"SPF":"V=sPf1 +all"}],"example7.com":[{"SPF":"v=spf1 -all"},{"SPF":"v=spf1 -all"}],"example8.com":[{"SPF":"V=spf1 -all"},{"SPF":"v=spf1 -all"},{"TXT":"v=spf1 +all"}],"example9.com":[{"SPF":"v=SpF1 ~all"}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.4');
        return promise.then((result) => {
          assert.include(["permerror","pass"], result.toLowerCase());
        });
      });
      it('nospf', function(){
        let email = 'foo@mail.example1.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"example3.com":[{"SPF":"v=spf10"},{"SPF":"v=spf1 mx"},{"MX":[0,"mail.example1.com"]}],"example1.com":[{"SPF":"v=spf1"}],"example2.com":[{"SPF":["v=spf1","mx"]}],"mail.example1.com":[{"A":"1.2.3.4"}],"example4.com":[{"SPF":"v=spf1 +all"},{"TXT":"v=spf1 -all"}],"example5.com":[{"SPF":"v=spf1 +all"},{"TXT":"v=spf1 -all"},{"TXT":"v=spf1 +all"}],"example6.com":[{"SPF":"v=spf1 -all"},{"SPF":"V=sPf1 +all"}],"example7.com":[{"SPF":"v=spf1 -all"},{"SPF":"v=spf1 -all"}],"example8.com":[{"SPF":"V=spf1 -all"},{"SPF":"v=spf1 -all"},{"TXT":"v=spf1 +all"}],"example9.com":[{"SPF":"v=SpF1 ~all"}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.4');
        return promise.then((result) => {
          assert.equal(result, 'NONE');
        });
      });
      it('v=spf1 is case insensitive', function(){
        let email = 'foo@example9.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"example3.com":[{"SPF":"v=spf10"},{"SPF":"v=spf1 mx"},{"MX":[0,"mail.example1.com"]}],"example1.com":[{"SPF":"v=spf1"}],"example2.com":[{"SPF":["v=spf1","mx"]}],"mail.example1.com":[{"A":"1.2.3.4"}],"example4.com":[{"SPF":"v=spf1 +all"},{"TXT":"v=spf1 -all"}],"example5.com":[{"SPF":"v=spf1 +all"},{"TXT":"v=spf1 -all"},{"TXT":"v=spf1 +all"}],"example6.com":[{"SPF":"v=spf1 -all"},{"SPF":"V=sPf1 +all"}],"example7.com":[{"SPF":"v=spf1 -all"},{"SPF":"v=spf1 -all"}],"example8.com":[{"SPF":"V=spf1 -all"},{"SPF":"v=spf1 -all"},{"TXT":"v=spf1 +all"}],"example9.com":[{"SPF":"v=SpF1 ~all"}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.4');
        return promise.then((result) => {
          assert.equal(result, 'SOFTFAIL');
        });
      });
    });
    describe('Record evaluation', function(){
      it('Any syntax errors anywhere in the record MUST be detected.', function(){
        let email = 'foo@t1.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"t1.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4 -all moo"}],"t2.example.com":[{"SPF":"v=spf1 moo.cow-far_out=man:dog/cat ip4:1.2.3.4 -all"}],"t3.example.com":[{"SPF":"v=spf1 moo.cow/far_out=man:dog/cat ip4:1.2.3.4 -all"}],"t4.example.com":[{"SPF":"v=spf1 moo.cow:far_out=man:dog/cat ip4:1.2.3.4 -all"}],"t5.example.com":[{"SPF":"v=spf1 redirect=t5.example.com ~all"}],"t6.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4 redirect=t2.example.com"}],"t7.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4"}],"t8.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4 redirect:t2.example.com"}],"t9.example.com":[{"SPF":"v=spf1 a:foo-bar -all"}],"t10.example.com":[{"SPF":"v=spf1 a:mail.example...com -all"}],"t11.example.com":[{"SPF":"v=spf1 a:a123456789012345678901234567890123456789012345678901234567890123.example.com -all"}],"t12.example.com":[{"SPF":"v=spf1 a:%{H}.bar -all"}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.4');
        return promise.then((result) => {
          assert.equal(result, 'PERMERROR');
        });
      });
      it('name = ALPHA *( ALPHA / DIGIT / "-" / "_" / "." )', function(){
        let email = 'foo@t2.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"t1.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4 -all moo"}],"t2.example.com":[{"SPF":"v=spf1 moo.cow-far_out=man:dog/cat ip4:1.2.3.4 -all"}],"t3.example.com":[{"SPF":"v=spf1 moo.cow/far_out=man:dog/cat ip4:1.2.3.4 -all"}],"t4.example.com":[{"SPF":"v=spf1 moo.cow:far_out=man:dog/cat ip4:1.2.3.4 -all"}],"t5.example.com":[{"SPF":"v=spf1 redirect=t5.example.com ~all"}],"t6.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4 redirect=t2.example.com"}],"t7.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4"}],"t8.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4 redirect:t2.example.com"}],"t9.example.com":[{"SPF":"v=spf1 a:foo-bar -all"}],"t10.example.com":[{"SPF":"v=spf1 a:mail.example...com -all"}],"t11.example.com":[{"SPF":"v=spf1 a:a123456789012345678901234567890123456789012345678901234567890123.example.com -all"}],"t12.example.com":[{"SPF":"v=spf1 a:%{H}.bar -all"}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.4');
        return promise.then((result) => {
          assert.equal(result, 'PASS');
        });
      });
      it('"=" character immediately after the name and before any ":" or "/"', function(){
        let email = 'foo@t3.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"t1.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4 -all moo"}],"t2.example.com":[{"SPF":"v=spf1 moo.cow-far_out=man:dog/cat ip4:1.2.3.4 -all"}],"t3.example.com":[{"SPF":"v=spf1 moo.cow/far_out=man:dog/cat ip4:1.2.3.4 -all"}],"t4.example.com":[{"SPF":"v=spf1 moo.cow:far_out=man:dog/cat ip4:1.2.3.4 -all"}],"t5.example.com":[{"SPF":"v=spf1 redirect=t5.example.com ~all"}],"t6.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4 redirect=t2.example.com"}],"t7.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4"}],"t8.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4 redirect:t2.example.com"}],"t9.example.com":[{"SPF":"v=spf1 a:foo-bar -all"}],"t10.example.com":[{"SPF":"v=spf1 a:mail.example...com -all"}],"t11.example.com":[{"SPF":"v=spf1 a:a123456789012345678901234567890123456789012345678901234567890123.example.com -all"}],"t12.example.com":[{"SPF":"v=spf1 a:%{H}.bar -all"}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.4');
        return promise.then((result) => {
          assert.equal(result, 'PERMERROR');
        });
      });
      it('"=" character immediately after the name and before any ":" or "/"', function(){
        let email = 'foo@t4.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"t1.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4 -all moo"}],"t2.example.com":[{"SPF":"v=spf1 moo.cow-far_out=man:dog/cat ip4:1.2.3.4 -all"}],"t3.example.com":[{"SPF":"v=spf1 moo.cow/far_out=man:dog/cat ip4:1.2.3.4 -all"}],"t4.example.com":[{"SPF":"v=spf1 moo.cow:far_out=man:dog/cat ip4:1.2.3.4 -all"}],"t5.example.com":[{"SPF":"v=spf1 redirect=t5.example.com ~all"}],"t6.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4 redirect=t2.example.com"}],"t7.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4"}],"t8.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4 redirect:t2.example.com"}],"t9.example.com":[{"SPF":"v=spf1 a:foo-bar -all"}],"t10.example.com":[{"SPF":"v=spf1 a:mail.example...com -all"}],"t11.example.com":[{"SPF":"v=spf1 a:a123456789012345678901234567890123456789012345678901234567890123.example.com -all"}],"t12.example.com":[{"SPF":"v=spf1 a:%{H}.bar -all"}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.4');
        return promise.then((result) => {
          assert.equal(result, 'PERMERROR');
        });
      });
      it('The "redirect" modifier has an effect after all the mechanisms.', function(){
        let email = 'foo@t5.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"t1.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4 -all moo"}],"t2.example.com":[{"SPF":"v=spf1 moo.cow-far_out=man:dog/cat ip4:1.2.3.4 -all"}],"t3.example.com":[{"SPF":"v=spf1 moo.cow/far_out=man:dog/cat ip4:1.2.3.4 -all"}],"t4.example.com":[{"SPF":"v=spf1 moo.cow:far_out=man:dog/cat ip4:1.2.3.4 -all"}],"t5.example.com":[{"SPF":"v=spf1 redirect=t5.example.com ~all"}],"t6.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4 redirect=t2.example.com"}],"t7.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4"}],"t8.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4 redirect:t2.example.com"}],"t9.example.com":[{"SPF":"v=spf1 a:foo-bar -all"}],"t10.example.com":[{"SPF":"v=spf1 a:mail.example...com -all"}],"t11.example.com":[{"SPF":"v=spf1 a:a123456789012345678901234567890123456789012345678901234567890123.example.com -all"}],"t12.example.com":[{"SPF":"v=spf1 a:%{H}.bar -all"}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.4');
        return promise.then((result) => {
          assert.equal(result, 'SOFTFAIL');
        });
      });
      it('The "redirect" modifier has an effect after all the mechanisms.', function(){
        let email = 'foo@t6.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"t1.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4 -all moo"}],"t2.example.com":[{"SPF":"v=spf1 moo.cow-far_out=man:dog/cat ip4:1.2.3.4 -all"}],"t3.example.com":[{"SPF":"v=spf1 moo.cow/far_out=man:dog/cat ip4:1.2.3.4 -all"}],"t4.example.com":[{"SPF":"v=spf1 moo.cow:far_out=man:dog/cat ip4:1.2.3.4 -all"}],"t5.example.com":[{"SPF":"v=spf1 redirect=t5.example.com ~all"}],"t6.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4 redirect=t2.example.com"}],"t7.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4"}],"t8.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4 redirect:t2.example.com"}],"t9.example.com":[{"SPF":"v=spf1 a:foo-bar -all"}],"t10.example.com":[{"SPF":"v=spf1 a:mail.example...com -all"}],"t11.example.com":[{"SPF":"v=spf1 a:a123456789012345678901234567890123456789012345678901234567890123.example.com -all"}],"t12.example.com":[{"SPF":"v=spf1 a:%{H}.bar -all"}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.5');
        return promise.then((result) => {
          assert.equal(result, 'FAIL');
        });
      });
      it('Default result is neutral.', function(){
        let email = 'foo@t7.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"t1.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4 -all moo"}],"t2.example.com":[{"SPF":"v=spf1 moo.cow-far_out=man:dog/cat ip4:1.2.3.4 -all"}],"t3.example.com":[{"SPF":"v=spf1 moo.cow/far_out=man:dog/cat ip4:1.2.3.4 -all"}],"t4.example.com":[{"SPF":"v=spf1 moo.cow:far_out=man:dog/cat ip4:1.2.3.4 -all"}],"t5.example.com":[{"SPF":"v=spf1 redirect=t5.example.com ~all"}],"t6.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4 redirect=t2.example.com"}],"t7.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4"}],"t8.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4 redirect:t2.example.com"}],"t9.example.com":[{"SPF":"v=spf1 a:foo-bar -all"}],"t10.example.com":[{"SPF":"v=spf1 a:mail.example...com -all"}],"t11.example.com":[{"SPF":"v=spf1 a:a123456789012345678901234567890123456789012345678901234567890123.example.com -all"}],"t12.example.com":[{"SPF":"v=spf1 a:%{H}.bar -all"}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.5');
        return promise.then((result) => {
          assert.equal(result, 'NEUTRAL');
        });
      });
      it('Invalid mechanism.  Redirect is a modifier.', function(){
        let email = 'foo@t8.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"t1.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4 -all moo"}],"t2.example.com":[{"SPF":"v=spf1 moo.cow-far_out=man:dog/cat ip4:1.2.3.4 -all"}],"t3.example.com":[{"SPF":"v=spf1 moo.cow/far_out=man:dog/cat ip4:1.2.3.4 -all"}],"t4.example.com":[{"SPF":"v=spf1 moo.cow:far_out=man:dog/cat ip4:1.2.3.4 -all"}],"t5.example.com":[{"SPF":"v=spf1 redirect=t5.example.com ~all"}],"t6.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4 redirect=t2.example.com"}],"t7.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4"}],"t8.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4 redirect:t2.example.com"}],"t9.example.com":[{"SPF":"v=spf1 a:foo-bar -all"}],"t10.example.com":[{"SPF":"v=spf1 a:mail.example...com -all"}],"t11.example.com":[{"SPF":"v=spf1 a:a123456789012345678901234567890123456789012345678901234567890123.example.com -all"}],"t12.example.com":[{"SPF":"v=spf1 a:%{H}.bar -all"}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.4');
        return promise.then((result) => {
          assert.equal(result, 'PERMERROR');
        });
      });
      it('Domain-spec must end in macro-expand or valid toplabel.', function(){
        let email = 'foo@t9.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"t1.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4 -all moo"}],"t2.example.com":[{"SPF":"v=spf1 moo.cow-far_out=man:dog/cat ip4:1.2.3.4 -all"}],"t3.example.com":[{"SPF":"v=spf1 moo.cow/far_out=man:dog/cat ip4:1.2.3.4 -all"}],"t4.example.com":[{"SPF":"v=spf1 moo.cow:far_out=man:dog/cat ip4:1.2.3.4 -all"}],"t5.example.com":[{"SPF":"v=spf1 redirect=t5.example.com ~all"}],"t6.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4 redirect=t2.example.com"}],"t7.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4"}],"t8.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4 redirect:t2.example.com"}],"t9.example.com":[{"SPF":"v=spf1 a:foo-bar -all"}],"t10.example.com":[{"SPF":"v=spf1 a:mail.example...com -all"}],"t11.example.com":[{"SPF":"v=spf1 a:a123456789012345678901234567890123456789012345678901234567890123.example.com -all"}],"t12.example.com":[{"SPF":"v=spf1 a:%{H}.bar -all"}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.4');
        return promise.then((result) => {
          assert.equal(result, 'PERMERROR');
        });
      });
      it('target-name that is a valid domain-spec per RFC 4408 but an invalid domain name per RFC 1035 (empty label) must be treated as non-existent.', function(){
        let email = 'foo@t10.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"t1.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4 -all moo"}],"t2.example.com":[{"SPF":"v=spf1 moo.cow-far_out=man:dog/cat ip4:1.2.3.4 -all"}],"t3.example.com":[{"SPF":"v=spf1 moo.cow/far_out=man:dog/cat ip4:1.2.3.4 -all"}],"t4.example.com":[{"SPF":"v=spf1 moo.cow:far_out=man:dog/cat ip4:1.2.3.4 -all"}],"t5.example.com":[{"SPF":"v=spf1 redirect=t5.example.com ~all"}],"t6.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4 redirect=t2.example.com"}],"t7.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4"}],"t8.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4 redirect:t2.example.com"}],"t9.example.com":[{"SPF":"v=spf1 a:foo-bar -all"}],"t10.example.com":[{"SPF":"v=spf1 a:mail.example...com -all"}],"t11.example.com":[{"SPF":"v=spf1 a:a123456789012345678901234567890123456789012345678901234567890123.example.com -all"}],"t12.example.com":[{"SPF":"v=spf1 a:%{H}.bar -all"}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.4');
        return promise.then((result) => {
          assert.include(["permerror","fail"], result.toLowerCase());
        });
      });
      it('target-name that is a valid domain-spec per RFC 4408 but an invalid domain name per RFC 1035 (long label) must be treated as non-existent.', function(){
        let email = 'foo@t11.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"t1.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4 -all moo"}],"t2.example.com":[{"SPF":"v=spf1 moo.cow-far_out=man:dog/cat ip4:1.2.3.4 -all"}],"t3.example.com":[{"SPF":"v=spf1 moo.cow/far_out=man:dog/cat ip4:1.2.3.4 -all"}],"t4.example.com":[{"SPF":"v=spf1 moo.cow:far_out=man:dog/cat ip4:1.2.3.4 -all"}],"t5.example.com":[{"SPF":"v=spf1 redirect=t5.example.com ~all"}],"t6.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4 redirect=t2.example.com"}],"t7.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4"}],"t8.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4 redirect:t2.example.com"}],"t9.example.com":[{"SPF":"v=spf1 a:foo-bar -all"}],"t10.example.com":[{"SPF":"v=spf1 a:mail.example...com -all"}],"t11.example.com":[{"SPF":"v=spf1 a:a123456789012345678901234567890123456789012345678901234567890123.example.com -all"}],"t12.example.com":[{"SPF":"v=spf1 a:%{H}.bar -all"}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.4');
        return promise.then((result) => {
          assert.include(["permerror","fail"], result.toLowerCase());
        });
      });
      it('target-name that is a valid domain-spec per RFC 4408 but an invalid domain name per RFC 1035 (long label) must be treated as non-existent.', function(){
        let email = 'foo@t12.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"t1.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4 -all moo"}],"t2.example.com":[{"SPF":"v=spf1 moo.cow-far_out=man:dog/cat ip4:1.2.3.4 -all"}],"t3.example.com":[{"SPF":"v=spf1 moo.cow/far_out=man:dog/cat ip4:1.2.3.4 -all"}],"t4.example.com":[{"SPF":"v=spf1 moo.cow:far_out=man:dog/cat ip4:1.2.3.4 -all"}],"t5.example.com":[{"SPF":"v=spf1 redirect=t5.example.com ~all"}],"t6.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4 redirect=t2.example.com"}],"t7.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4"}],"t8.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4 redirect:t2.example.com"}],"t9.example.com":[{"SPF":"v=spf1 a:foo-bar -all"}],"t10.example.com":[{"SPF":"v=spf1 a:mail.example...com -all"}],"t11.example.com":[{"SPF":"v=spf1 a:a123456789012345678901234567890123456789012345678901234567890123.example.com -all"}],"t12.example.com":[{"SPF":"v=spf1 a:%{H}.bar -all"}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.4');
        return promise.then((result) => {
          assert.include(["permerror","fail"], result.toLowerCase());
        });
      });
    });
    describe('ALL mechanism syntax', function(){
      it('all              = "all"', function(){
        let email = 'foo@e1.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 -all."}],"e2.example.com":[{"SPF":"v=spf1 -all:foobar"}],"e3.example.com":[{"SPF":"v=spf1 -all/8"}],"e4.example.com":[{"SPF":"v=spf1 ?all"}],"e5.example.com":[{"SPF":"v=spf1 all -all"}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.4');
        return promise.then((result) => {
          assert.equal(result, 'PERMERROR');
        });
      });
      it('all              = "all"', function(){
        let email = 'foo@e2.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 -all."}],"e2.example.com":[{"SPF":"v=spf1 -all:foobar"}],"e3.example.com":[{"SPF":"v=spf1 -all/8"}],"e4.example.com":[{"SPF":"v=spf1 ?all"}],"e5.example.com":[{"SPF":"v=spf1 all -all"}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.4');
        return promise.then((result) => {
          assert.equal(result, 'PERMERROR');
        });
      });
      it('all              = "all"', function(){
        let email = 'foo@e3.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 -all."}],"e2.example.com":[{"SPF":"v=spf1 -all:foobar"}],"e3.example.com":[{"SPF":"v=spf1 -all/8"}],"e4.example.com":[{"SPF":"v=spf1 ?all"}],"e5.example.com":[{"SPF":"v=spf1 all -all"}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.4');
        return promise.then((result) => {
          assert.equal(result, 'PERMERROR');
        });
      });
      it('all              = "all"', function(){
        let email = 'foo@e4.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 -all."}],"e2.example.com":[{"SPF":"v=spf1 -all:foobar"}],"e3.example.com":[{"SPF":"v=spf1 -all/8"}],"e4.example.com":[{"SPF":"v=spf1 ?all"}],"e5.example.com":[{"SPF":"v=spf1 all -all"}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.4');
        return promise.then((result) => {
          assert.equal(result, 'NEUTRAL');
        });
      });
      it('all              = "all"', function(){
        let email = 'foo@e5.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 -all."}],"e2.example.com":[{"SPF":"v=spf1 -all:foobar"}],"e3.example.com":[{"SPF":"v=spf1 -all/8"}],"e4.example.com":[{"SPF":"v=spf1 ?all"}],"e5.example.com":[{"SPF":"v=spf1 all -all"}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.4');
        return promise.then((result) => {
          assert.equal(result, 'PASS');
        });
      });
    });
    describe('PTR mechanism syntax', function(){
      it('PTR              = "ptr"    [ ":" domain-spec ]', function(){
        let email = 'foo@e1.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 ptr/0 -all"}],"e2.example.com":[{"SPF":"v=spf1 ptr:example.com -all"}],"4.3.2.1.in-addr.arpa":[{"PTR":"e3.example.com"},{"PTR":"e4.example.com"},{"PTR":"mail.example.com"}],"1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.E.B.A.B.E.F.A.C.ip6.arpa":[{"PTR":"e3.example.com"}],"e3.example.com":[{"SPF":"v=spf1 ptr -all"},{"A":"1.2.3.4"},{"AAAA":"CAFE:BABE::1"}],"e4.example.com":[{"SPF":"v=spf1 ptr -all"}],"e5.example.com":[{"SPF":"v=spf1 ptr:"}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.4');
        return promise.then((result) => {
          assert.equal(result, 'PERMERROR');
        });
      });
      it('Check all validated domain names to see if they end in the <target-name> domain.', function(){
        let email = 'foo@e2.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 ptr/0 -all"}],"e2.example.com":[{"SPF":"v=spf1 ptr:example.com -all"}],"4.3.2.1.in-addr.arpa":[{"PTR":"e3.example.com"},{"PTR":"e4.example.com"},{"PTR":"mail.example.com"}],"1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.E.B.A.B.E.F.A.C.ip6.arpa":[{"PTR":"e3.example.com"}],"e3.example.com":[{"SPF":"v=spf1 ptr -all"},{"A":"1.2.3.4"},{"AAAA":"CAFE:BABE::1"}],"e4.example.com":[{"SPF":"v=spf1 ptr -all"}],"e5.example.com":[{"SPF":"v=spf1 ptr:"}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.4');
        return promise.then((result) => {
          assert.equal(result, 'PASS');
        });
      });
      it('Check all validated domain names to see if they end in the <target-name> domain.', function(){
        let email = 'foo@e3.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 ptr/0 -all"}],"e2.example.com":[{"SPF":"v=spf1 ptr:example.com -all"}],"4.3.2.1.in-addr.arpa":[{"PTR":"e3.example.com"},{"PTR":"e4.example.com"},{"PTR":"mail.example.com"}],"1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.E.B.A.B.E.F.A.C.ip6.arpa":[{"PTR":"e3.example.com"}],"e3.example.com":[{"SPF":"v=spf1 ptr -all"},{"A":"1.2.3.4"},{"AAAA":"CAFE:BABE::1"}],"e4.example.com":[{"SPF":"v=spf1 ptr -all"}],"e5.example.com":[{"SPF":"v=spf1 ptr:"}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.4');
        return promise.then((result) => {
          assert.equal(result, 'PASS');
        });
      });
      it('Check all validated domain names to see if they end in the <target-name> domain.', function(){
        let email = 'foo@e4.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 ptr/0 -all"}],"e2.example.com":[{"SPF":"v=spf1 ptr:example.com -all"}],"4.3.2.1.in-addr.arpa":[{"PTR":"e3.example.com"},{"PTR":"e4.example.com"},{"PTR":"mail.example.com"}],"1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.E.B.A.B.E.F.A.C.ip6.arpa":[{"PTR":"e3.example.com"}],"e3.example.com":[{"SPF":"v=spf1 ptr -all"},{"A":"1.2.3.4"},{"AAAA":"CAFE:BABE::1"}],"e4.example.com":[{"SPF":"v=spf1 ptr -all"}],"e5.example.com":[{"SPF":"v=spf1 ptr:"}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.4');
        return promise.then((result) => {
          assert.equal(result, 'FAIL');
        });
      });
      it('Check all validated domain names to see if they end in the <target-name> domain.', function(){
        let email = 'foo@e3.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 ptr/0 -all"}],"e2.example.com":[{"SPF":"v=spf1 ptr:example.com -all"}],"4.3.2.1.in-addr.arpa":[{"PTR":"e3.example.com"},{"PTR":"e4.example.com"},{"PTR":"mail.example.com"}],"1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.E.B.A.B.E.F.A.C.ip6.arpa":[{"PTR":"e3.example.com"}],"e3.example.com":[{"SPF":"v=spf1 ptr -all"},{"A":"1.2.3.4"},{"AAAA":"CAFE:BABE::1"}],"e4.example.com":[{"SPF":"v=spf1 ptr -all"}],"e5.example.com":[{"SPF":"v=spf1 ptr:"}]}, failOnNoFake: true});
        let promise = validator.validateSender('CAFE:BABE::1');
        return promise.then((result) => {
          assert.equal(result, 'PASS');
        });
      });
      it('domain-spec cannot be empty.', function(){
        let email = 'foo@e5.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 ptr/0 -all"}],"e2.example.com":[{"SPF":"v=spf1 ptr:example.com -all"}],"4.3.2.1.in-addr.arpa":[{"PTR":"e3.example.com"},{"PTR":"e4.example.com"},{"PTR":"mail.example.com"}],"1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.E.B.A.B.E.F.A.C.ip6.arpa":[{"PTR":"e3.example.com"}],"e3.example.com":[{"SPF":"v=spf1 ptr -all"},{"A":"1.2.3.4"},{"AAAA":"CAFE:BABE::1"}],"e4.example.com":[{"SPF":"v=spf1 ptr -all"}],"e5.example.com":[{"SPF":"v=spf1 ptr:"}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.4');
        return promise.then((result) => {
          assert.equal(result, 'PERMERROR');
        });
      });
    });
    describe('A mechanism syntax', function(){
      it('A                = "a"      [ ":" domain-spec ] [ dual-cidr-length ] dual-cidr-length = [ ip4-cidr-length ] [ "/" ip6-cidr-length ]', function(){
        let email = 'foo@e6.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 a/0 -all"}],"e2.example.com":[{"A":"1.1.1.1"},{"AAAA":"1234::2"},{"SPF":"v=spf1 a/0 -all"}],"e2a.example.com":[{"AAAA":"1234::1"},{"SPF":"v=spf1 a//0 -all"}],"e2b.example.com":[{"A":"1.1.1.1"},{"SPF":"v=spf1 a//0 -all"}],"ipv6.example.com":[{"AAAA":"1234::1"},{"A":"1.1.1.1"},{"SPF":"v=spf1 a -all"}],"e3.example.com":[{"SPF":"v=spf1 a:foo.example.com\u0000"}],"e4.example.com":[{"SPF":"v=spf1 a:111.222.33.44"}],"e5.example.com":[{"SPF":"v=spf1 a:abc.123"}],"e5a.example.com":[{"SPF":"v=spf1 a:museum"}],"e5b.example.com":[{"SPF":"v=spf1 a:museum."}],"e6.example.com":[{"SPF":"v=spf1 a//33 -all"}],"e6a.example.com":[{"SPF":"v=spf1 a/33 -all"}],"e7.example.com":[{"SPF":"v=spf1 a//129 -all"}],"e8.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24//64 -all"}],"e8e.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24/64 -all"}],"e8a.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24 -all"}],"e8b.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a//64 -all"}],"e9.example.com":[{"SPF":"v=spf1 a:example.com:8080"}],"e10.example.com":[{"SPF":"v=spf1 a:foo.example.com/24"}],"foo.example.com":[{"A":"1.1.1.1"},{"A":"1.2.3.5"}],"e11.example.com":[{"SPF":"v=spf1 a:foo:bar/baz.example.com"}],"foo:bar/baz.example.com":[{"A":"1.2.3.4"}],"e12.example.com":[{"SPF":"v=spf1 a:example.-com"}],"e13.example.com":[{"SPF":"v=spf1 a:"}],"e14.example.com":[{"SPF":"v=spf1 a:foo.example.xn--zckzah -all"}],"foo.example.xn--zckzah":[{"A":"1.2.3.4"}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.4');
        return promise.then((result) => {
          assert.equal(result, 'FAIL');
        });
      });
      it('A                = "a"      [ ":" domain-spec ] [ dual-cidr-length ] dual-cidr-length = [ ip4-cidr-length ] [ "/" ip6-cidr-length ]', function(){
        let email = 'foo@e6a.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 a/0 -all"}],"e2.example.com":[{"A":"1.1.1.1"},{"AAAA":"1234::2"},{"SPF":"v=spf1 a/0 -all"}],"e2a.example.com":[{"AAAA":"1234::1"},{"SPF":"v=spf1 a//0 -all"}],"e2b.example.com":[{"A":"1.1.1.1"},{"SPF":"v=spf1 a//0 -all"}],"ipv6.example.com":[{"AAAA":"1234::1"},{"A":"1.1.1.1"},{"SPF":"v=spf1 a -all"}],"e3.example.com":[{"SPF":"v=spf1 a:foo.example.com\u0000"}],"e4.example.com":[{"SPF":"v=spf1 a:111.222.33.44"}],"e5.example.com":[{"SPF":"v=spf1 a:abc.123"}],"e5a.example.com":[{"SPF":"v=spf1 a:museum"}],"e5b.example.com":[{"SPF":"v=spf1 a:museum."}],"e6.example.com":[{"SPF":"v=spf1 a//33 -all"}],"e6a.example.com":[{"SPF":"v=spf1 a/33 -all"}],"e7.example.com":[{"SPF":"v=spf1 a//129 -all"}],"e8.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24//64 -all"}],"e8e.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24/64 -all"}],"e8a.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24 -all"}],"e8b.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a//64 -all"}],"e9.example.com":[{"SPF":"v=spf1 a:example.com:8080"}],"e10.example.com":[{"SPF":"v=spf1 a:foo.example.com/24"}],"foo.example.com":[{"A":"1.1.1.1"},{"A":"1.2.3.5"}],"e11.example.com":[{"SPF":"v=spf1 a:foo:bar/baz.example.com"}],"foo:bar/baz.example.com":[{"A":"1.2.3.4"}],"e12.example.com":[{"SPF":"v=spf1 a:example.-com"}],"e13.example.com":[{"SPF":"v=spf1 a:"}],"e14.example.com":[{"SPF":"v=spf1 a:foo.example.xn--zckzah -all"}],"foo.example.xn--zckzah":[{"A":"1.2.3.4"}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.4');
        return promise.then((result) => {
          assert.equal(result, 'PERMERROR');
        });
      });
      it('A                = "a"      [ ":" domain-spec ] [ dual-cidr-length ] dual-cidr-length = [ ip4-cidr-length ] [ "/" ip6-cidr-length ]', function(){
        let email = 'foo@e7.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 a/0 -all"}],"e2.example.com":[{"A":"1.1.1.1"},{"AAAA":"1234::2"},{"SPF":"v=spf1 a/0 -all"}],"e2a.example.com":[{"AAAA":"1234::1"},{"SPF":"v=spf1 a//0 -all"}],"e2b.example.com":[{"A":"1.1.1.1"},{"SPF":"v=spf1 a//0 -all"}],"ipv6.example.com":[{"AAAA":"1234::1"},{"A":"1.1.1.1"},{"SPF":"v=spf1 a -all"}],"e3.example.com":[{"SPF":"v=spf1 a:foo.example.com\u0000"}],"e4.example.com":[{"SPF":"v=spf1 a:111.222.33.44"}],"e5.example.com":[{"SPF":"v=spf1 a:abc.123"}],"e5a.example.com":[{"SPF":"v=spf1 a:museum"}],"e5b.example.com":[{"SPF":"v=spf1 a:museum."}],"e6.example.com":[{"SPF":"v=spf1 a//33 -all"}],"e6a.example.com":[{"SPF":"v=spf1 a/33 -all"}],"e7.example.com":[{"SPF":"v=spf1 a//129 -all"}],"e8.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24//64 -all"}],"e8e.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24/64 -all"}],"e8a.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24 -all"}],"e8b.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a//64 -all"}],"e9.example.com":[{"SPF":"v=spf1 a:example.com:8080"}],"e10.example.com":[{"SPF":"v=spf1 a:foo.example.com/24"}],"foo.example.com":[{"A":"1.1.1.1"},{"A":"1.2.3.5"}],"e11.example.com":[{"SPF":"v=spf1 a:foo:bar/baz.example.com"}],"foo:bar/baz.example.com":[{"A":"1.2.3.4"}],"e12.example.com":[{"SPF":"v=spf1 a:example.-com"}],"e13.example.com":[{"SPF":"v=spf1 a:"}],"e14.example.com":[{"SPF":"v=spf1 a:foo.example.xn--zckzah -all"}],"foo.example.xn--zckzah":[{"A":"1.2.3.4"}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.4');
        return promise.then((result) => {
          assert.equal(result, 'PERMERROR');
        });
      });
      it('A                = "a"      [ ":" domain-spec ] [ dual-cidr-length ] dual-cidr-length = [ ip4-cidr-length ] [ "/" ip6-cidr-length ]', function(){
        let email = 'foo@e8.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 a/0 -all"}],"e2.example.com":[{"A":"1.1.1.1"},{"AAAA":"1234::2"},{"SPF":"v=spf1 a/0 -all"}],"e2a.example.com":[{"AAAA":"1234::1"},{"SPF":"v=spf1 a//0 -all"}],"e2b.example.com":[{"A":"1.1.1.1"},{"SPF":"v=spf1 a//0 -all"}],"ipv6.example.com":[{"AAAA":"1234::1"},{"A":"1.1.1.1"},{"SPF":"v=spf1 a -all"}],"e3.example.com":[{"SPF":"v=spf1 a:foo.example.com\u0000"}],"e4.example.com":[{"SPF":"v=spf1 a:111.222.33.44"}],"e5.example.com":[{"SPF":"v=spf1 a:abc.123"}],"e5a.example.com":[{"SPF":"v=spf1 a:museum"}],"e5b.example.com":[{"SPF":"v=spf1 a:museum."}],"e6.example.com":[{"SPF":"v=spf1 a//33 -all"}],"e6a.example.com":[{"SPF":"v=spf1 a/33 -all"}],"e7.example.com":[{"SPF":"v=spf1 a//129 -all"}],"e8.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24//64 -all"}],"e8e.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24/64 -all"}],"e8a.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24 -all"}],"e8b.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a//64 -all"}],"e9.example.com":[{"SPF":"v=spf1 a:example.com:8080"}],"e10.example.com":[{"SPF":"v=spf1 a:foo.example.com/24"}],"foo.example.com":[{"A":"1.1.1.1"},{"A":"1.2.3.5"}],"e11.example.com":[{"SPF":"v=spf1 a:foo:bar/baz.example.com"}],"foo:bar/baz.example.com":[{"A":"1.2.3.4"}],"e12.example.com":[{"SPF":"v=spf1 a:example.-com"}],"e13.example.com":[{"SPF":"v=spf1 a:"}],"e14.example.com":[{"SPF":"v=spf1 a:foo.example.xn--zckzah -all"}],"foo.example.xn--zckzah":[{"A":"1.2.3.4"}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.4');
        return promise.then((result) => {
          assert.equal(result, 'PASS');
        });
      });
      it('A                = "a"      [ ":" domain-spec ] [ dual-cidr-length ] dual-cidr-length = [ ip4-cidr-length ] [ "/" ip6-cidr-length ]', function(){
        let email = 'foo@e8e.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 a/0 -all"}],"e2.example.com":[{"A":"1.1.1.1"},{"AAAA":"1234::2"},{"SPF":"v=spf1 a/0 -all"}],"e2a.example.com":[{"AAAA":"1234::1"},{"SPF":"v=spf1 a//0 -all"}],"e2b.example.com":[{"A":"1.1.1.1"},{"SPF":"v=spf1 a//0 -all"}],"ipv6.example.com":[{"AAAA":"1234::1"},{"A":"1.1.1.1"},{"SPF":"v=spf1 a -all"}],"e3.example.com":[{"SPF":"v=spf1 a:foo.example.com\u0000"}],"e4.example.com":[{"SPF":"v=spf1 a:111.222.33.44"}],"e5.example.com":[{"SPF":"v=spf1 a:abc.123"}],"e5a.example.com":[{"SPF":"v=spf1 a:museum"}],"e5b.example.com":[{"SPF":"v=spf1 a:museum."}],"e6.example.com":[{"SPF":"v=spf1 a//33 -all"}],"e6a.example.com":[{"SPF":"v=spf1 a/33 -all"}],"e7.example.com":[{"SPF":"v=spf1 a//129 -all"}],"e8.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24//64 -all"}],"e8e.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24/64 -all"}],"e8a.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24 -all"}],"e8b.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a//64 -all"}],"e9.example.com":[{"SPF":"v=spf1 a:example.com:8080"}],"e10.example.com":[{"SPF":"v=spf1 a:foo.example.com/24"}],"foo.example.com":[{"A":"1.1.1.1"},{"A":"1.2.3.5"}],"e11.example.com":[{"SPF":"v=spf1 a:foo:bar/baz.example.com"}],"foo:bar/baz.example.com":[{"A":"1.2.3.4"}],"e12.example.com":[{"SPF":"v=spf1 a:example.-com"}],"e13.example.com":[{"SPF":"v=spf1 a:"}],"e14.example.com":[{"SPF":"v=spf1 a:foo.example.xn--zckzah -all"}],"foo.example.xn--zckzah":[{"A":"1.2.3.4"}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.4');
        return promise.then((result) => {
          assert.equal(result, 'PERMERROR');
        });
      });
      it('A                = "a"      [ ":" domain-spec ] [ dual-cidr-length ] dual-cidr-length = [ ip4-cidr-length ] [ "/" ip6-cidr-length ]', function(){
        let email = 'foo@e8.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 a/0 -all"}],"e2.example.com":[{"A":"1.1.1.1"},{"AAAA":"1234::2"},{"SPF":"v=spf1 a/0 -all"}],"e2a.example.com":[{"AAAA":"1234::1"},{"SPF":"v=spf1 a//0 -all"}],"e2b.example.com":[{"A":"1.1.1.1"},{"SPF":"v=spf1 a//0 -all"}],"ipv6.example.com":[{"AAAA":"1234::1"},{"A":"1.1.1.1"},{"SPF":"v=spf1 a -all"}],"e3.example.com":[{"SPF":"v=spf1 a:foo.example.com\u0000"}],"e4.example.com":[{"SPF":"v=spf1 a:111.222.33.44"}],"e5.example.com":[{"SPF":"v=spf1 a:abc.123"}],"e5a.example.com":[{"SPF":"v=spf1 a:museum"}],"e5b.example.com":[{"SPF":"v=spf1 a:museum."}],"e6.example.com":[{"SPF":"v=spf1 a//33 -all"}],"e6a.example.com":[{"SPF":"v=spf1 a/33 -all"}],"e7.example.com":[{"SPF":"v=spf1 a//129 -all"}],"e8.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24//64 -all"}],"e8e.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24/64 -all"}],"e8a.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24 -all"}],"e8b.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a//64 -all"}],"e9.example.com":[{"SPF":"v=spf1 a:example.com:8080"}],"e10.example.com":[{"SPF":"v=spf1 a:foo.example.com/24"}],"foo.example.com":[{"A":"1.1.1.1"},{"A":"1.2.3.5"}],"e11.example.com":[{"SPF":"v=spf1 a:foo:bar/baz.example.com"}],"foo:bar/baz.example.com":[{"A":"1.2.3.4"}],"e12.example.com":[{"SPF":"v=spf1 a:example.-com"}],"e13.example.com":[{"SPF":"v=spf1 a:"}],"e14.example.com":[{"SPF":"v=spf1 a:foo.example.xn--zckzah -all"}],"foo.example.xn--zckzah":[{"A":"1.2.3.4"}]}, failOnNoFake: true});
        let promise = validator.validateSender('2001:db8:1234::cafe:babe');
        return promise.then((result) => {
          assert.equal(result, 'PASS');
        });
      });
      it('A                = "a"      [ ":" domain-spec ] [ dual-cidr-length ] dual-cidr-length = [ ip4-cidr-length ] [ "/" ip6-cidr-length ]', function(){
        let email = 'foo@e8b.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 a/0 -all"}],"e2.example.com":[{"A":"1.1.1.1"},{"AAAA":"1234::2"},{"SPF":"v=spf1 a/0 -all"}],"e2a.example.com":[{"AAAA":"1234::1"},{"SPF":"v=spf1 a//0 -all"}],"e2b.example.com":[{"A":"1.1.1.1"},{"SPF":"v=spf1 a//0 -all"}],"ipv6.example.com":[{"AAAA":"1234::1"},{"A":"1.1.1.1"},{"SPF":"v=spf1 a -all"}],"e3.example.com":[{"SPF":"v=spf1 a:foo.example.com\u0000"}],"e4.example.com":[{"SPF":"v=spf1 a:111.222.33.44"}],"e5.example.com":[{"SPF":"v=spf1 a:abc.123"}],"e5a.example.com":[{"SPF":"v=spf1 a:museum"}],"e5b.example.com":[{"SPF":"v=spf1 a:museum."}],"e6.example.com":[{"SPF":"v=spf1 a//33 -all"}],"e6a.example.com":[{"SPF":"v=spf1 a/33 -all"}],"e7.example.com":[{"SPF":"v=spf1 a//129 -all"}],"e8.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24//64 -all"}],"e8e.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24/64 -all"}],"e8a.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24 -all"}],"e8b.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a//64 -all"}],"e9.example.com":[{"SPF":"v=spf1 a:example.com:8080"}],"e10.example.com":[{"SPF":"v=spf1 a:foo.example.com/24"}],"foo.example.com":[{"A":"1.1.1.1"},{"A":"1.2.3.5"}],"e11.example.com":[{"SPF":"v=spf1 a:foo:bar/baz.example.com"}],"foo:bar/baz.example.com":[{"A":"1.2.3.4"}],"e12.example.com":[{"SPF":"v=spf1 a:example.-com"}],"e13.example.com":[{"SPF":"v=spf1 a:"}],"e14.example.com":[{"SPF":"v=spf1 a:foo.example.xn--zckzah -all"}],"foo.example.xn--zckzah":[{"A":"1.2.3.4"}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.4');
        return promise.then((result) => {
          assert.equal(result, 'FAIL');
        });
      });
      it('A                = "a"      [ ":" domain-spec ] [ dual-cidr-length ] dual-cidr-length = [ ip4-cidr-length ] [ "/" ip6-cidr-length ]', function(){
        let email = 'foo@e8a.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 a/0 -all"}],"e2.example.com":[{"A":"1.1.1.1"},{"AAAA":"1234::2"},{"SPF":"v=spf1 a/0 -all"}],"e2a.example.com":[{"AAAA":"1234::1"},{"SPF":"v=spf1 a//0 -all"}],"e2b.example.com":[{"A":"1.1.1.1"},{"SPF":"v=spf1 a//0 -all"}],"ipv6.example.com":[{"AAAA":"1234::1"},{"A":"1.1.1.1"},{"SPF":"v=spf1 a -all"}],"e3.example.com":[{"SPF":"v=spf1 a:foo.example.com\u0000"}],"e4.example.com":[{"SPF":"v=spf1 a:111.222.33.44"}],"e5.example.com":[{"SPF":"v=spf1 a:abc.123"}],"e5a.example.com":[{"SPF":"v=spf1 a:museum"}],"e5b.example.com":[{"SPF":"v=spf1 a:museum."}],"e6.example.com":[{"SPF":"v=spf1 a//33 -all"}],"e6a.example.com":[{"SPF":"v=spf1 a/33 -all"}],"e7.example.com":[{"SPF":"v=spf1 a//129 -all"}],"e8.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24//64 -all"}],"e8e.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24/64 -all"}],"e8a.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24 -all"}],"e8b.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a//64 -all"}],"e9.example.com":[{"SPF":"v=spf1 a:example.com:8080"}],"e10.example.com":[{"SPF":"v=spf1 a:foo.example.com/24"}],"foo.example.com":[{"A":"1.1.1.1"},{"A":"1.2.3.5"}],"e11.example.com":[{"SPF":"v=spf1 a:foo:bar/baz.example.com"}],"foo:bar/baz.example.com":[{"A":"1.2.3.4"}],"e12.example.com":[{"SPF":"v=spf1 a:example.-com"}],"e13.example.com":[{"SPF":"v=spf1 a:"}],"e14.example.com":[{"SPF":"v=spf1 a:foo.example.xn--zckzah -all"}],"foo.example.xn--zckzah":[{"A":"1.2.3.4"}]}, failOnNoFake: true});
        let promise = validator.validateSender('2001:db8:1234::cafe:babe');
        return promise.then((result) => {
          assert.equal(result, 'FAIL');
        });
      });
      it('A matches any returned IP.', function(){
        let email = 'foo@e10.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 a/0 -all"}],"e2.example.com":[{"A":"1.1.1.1"},{"AAAA":"1234::2"},{"SPF":"v=spf1 a/0 -all"}],"e2a.example.com":[{"AAAA":"1234::1"},{"SPF":"v=spf1 a//0 -all"}],"e2b.example.com":[{"A":"1.1.1.1"},{"SPF":"v=spf1 a//0 -all"}],"ipv6.example.com":[{"AAAA":"1234::1"},{"A":"1.1.1.1"},{"SPF":"v=spf1 a -all"}],"e3.example.com":[{"SPF":"v=spf1 a:foo.example.com\u0000"}],"e4.example.com":[{"SPF":"v=spf1 a:111.222.33.44"}],"e5.example.com":[{"SPF":"v=spf1 a:abc.123"}],"e5a.example.com":[{"SPF":"v=spf1 a:museum"}],"e5b.example.com":[{"SPF":"v=spf1 a:museum."}],"e6.example.com":[{"SPF":"v=spf1 a//33 -all"}],"e6a.example.com":[{"SPF":"v=spf1 a/33 -all"}],"e7.example.com":[{"SPF":"v=spf1 a//129 -all"}],"e8.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24//64 -all"}],"e8e.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24/64 -all"}],"e8a.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24 -all"}],"e8b.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a//64 -all"}],"e9.example.com":[{"SPF":"v=spf1 a:example.com:8080"}],"e10.example.com":[{"SPF":"v=spf1 a:foo.example.com/24"}],"foo.example.com":[{"A":"1.1.1.1"},{"A":"1.2.3.5"}],"e11.example.com":[{"SPF":"v=spf1 a:foo:bar/baz.example.com"}],"foo:bar/baz.example.com":[{"A":"1.2.3.4"}],"e12.example.com":[{"SPF":"v=spf1 a:example.-com"}],"e13.example.com":[{"SPF":"v=spf1 a:"}],"e14.example.com":[{"SPF":"v=spf1 a:foo.example.xn--zckzah -all"}],"foo.example.xn--zckzah":[{"A":"1.2.3.4"}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.4');
        return promise.then((result) => {
          assert.equal(result, 'PASS');
        });
      });
      it('A matches any returned IP.', function(){
        let email = 'foo@e10.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 a/0 -all"}],"e2.example.com":[{"A":"1.1.1.1"},{"AAAA":"1234::2"},{"SPF":"v=spf1 a/0 -all"}],"e2a.example.com":[{"AAAA":"1234::1"},{"SPF":"v=spf1 a//0 -all"}],"e2b.example.com":[{"A":"1.1.1.1"},{"SPF":"v=spf1 a//0 -all"}],"ipv6.example.com":[{"AAAA":"1234::1"},{"A":"1.1.1.1"},{"SPF":"v=spf1 a -all"}],"e3.example.com":[{"SPF":"v=spf1 a:foo.example.com\u0000"}],"e4.example.com":[{"SPF":"v=spf1 a:111.222.33.44"}],"e5.example.com":[{"SPF":"v=spf1 a:abc.123"}],"e5a.example.com":[{"SPF":"v=spf1 a:museum"}],"e5b.example.com":[{"SPF":"v=spf1 a:museum."}],"e6.example.com":[{"SPF":"v=spf1 a//33 -all"}],"e6a.example.com":[{"SPF":"v=spf1 a/33 -all"}],"e7.example.com":[{"SPF":"v=spf1 a//129 -all"}],"e8.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24//64 -all"}],"e8e.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24/64 -all"}],"e8a.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24 -all"}],"e8b.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a//64 -all"}],"e9.example.com":[{"SPF":"v=spf1 a:example.com:8080"}],"e10.example.com":[{"SPF":"v=spf1 a:foo.example.com/24"}],"foo.example.com":[{"A":"1.1.1.1"},{"A":"1.2.3.5"}],"e11.example.com":[{"SPF":"v=spf1 a:foo:bar/baz.example.com"}],"foo:bar/baz.example.com":[{"A":"1.2.3.4"}],"e12.example.com":[{"SPF":"v=spf1 a:example.-com"}],"e13.example.com":[{"SPF":"v=spf1 a:"}],"e14.example.com":[{"SPF":"v=spf1 a:foo.example.xn--zckzah -all"}],"foo.example.xn--zckzah":[{"A":"1.2.3.4"}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.4');
        return promise.then((result) => {
          assert.equal(result, 'PASS');
        });
      });
      it('domain-spec must pass basic syntax checks; a ":" may appear in domain-spec, but not in top-label', function(){
        let email = 'foo@e9.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 a/0 -all"}],"e2.example.com":[{"A":"1.1.1.1"},{"AAAA":"1234::2"},{"SPF":"v=spf1 a/0 -all"}],"e2a.example.com":[{"AAAA":"1234::1"},{"SPF":"v=spf1 a//0 -all"}],"e2b.example.com":[{"A":"1.1.1.1"},{"SPF":"v=spf1 a//0 -all"}],"ipv6.example.com":[{"AAAA":"1234::1"},{"A":"1.1.1.1"},{"SPF":"v=spf1 a -all"}],"e3.example.com":[{"SPF":"v=spf1 a:foo.example.com\u0000"}],"e4.example.com":[{"SPF":"v=spf1 a:111.222.33.44"}],"e5.example.com":[{"SPF":"v=spf1 a:abc.123"}],"e5a.example.com":[{"SPF":"v=spf1 a:museum"}],"e5b.example.com":[{"SPF":"v=spf1 a:museum."}],"e6.example.com":[{"SPF":"v=spf1 a//33 -all"}],"e6a.example.com":[{"SPF":"v=spf1 a/33 -all"}],"e7.example.com":[{"SPF":"v=spf1 a//129 -all"}],"e8.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24//64 -all"}],"e8e.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24/64 -all"}],"e8a.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24 -all"}],"e8b.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a//64 -all"}],"e9.example.com":[{"SPF":"v=spf1 a:example.com:8080"}],"e10.example.com":[{"SPF":"v=spf1 a:foo.example.com/24"}],"foo.example.com":[{"A":"1.1.1.1"},{"A":"1.2.3.5"}],"e11.example.com":[{"SPF":"v=spf1 a:foo:bar/baz.example.com"}],"foo:bar/baz.example.com":[{"A":"1.2.3.4"}],"e12.example.com":[{"SPF":"v=spf1 a:example.-com"}],"e13.example.com":[{"SPF":"v=spf1 a:"}],"e14.example.com":[{"SPF":"v=spf1 a:foo.example.xn--zckzah -all"}],"foo.example.xn--zckzah":[{"A":"1.2.3.4"}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.4');
        return promise.then((result) => {
          assert.equal(result, 'PERMERROR');
        });
      });
      it('If no ips are returned, A mechanism does not match, even with /0.', function(){
        let email = 'foo@e1.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 a/0 -all"}],"e2.example.com":[{"A":"1.1.1.1"},{"AAAA":"1234::2"},{"SPF":"v=spf1 a/0 -all"}],"e2a.example.com":[{"AAAA":"1234::1"},{"SPF":"v=spf1 a//0 -all"}],"e2b.example.com":[{"A":"1.1.1.1"},{"SPF":"v=spf1 a//0 -all"}],"ipv6.example.com":[{"AAAA":"1234::1"},{"A":"1.1.1.1"},{"SPF":"v=spf1 a -all"}],"e3.example.com":[{"SPF":"v=spf1 a:foo.example.com\u0000"}],"e4.example.com":[{"SPF":"v=spf1 a:111.222.33.44"}],"e5.example.com":[{"SPF":"v=spf1 a:abc.123"}],"e5a.example.com":[{"SPF":"v=spf1 a:museum"}],"e5b.example.com":[{"SPF":"v=spf1 a:museum."}],"e6.example.com":[{"SPF":"v=spf1 a//33 -all"}],"e6a.example.com":[{"SPF":"v=spf1 a/33 -all"}],"e7.example.com":[{"SPF":"v=spf1 a//129 -all"}],"e8.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24//64 -all"}],"e8e.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24/64 -all"}],"e8a.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24 -all"}],"e8b.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a//64 -all"}],"e9.example.com":[{"SPF":"v=spf1 a:example.com:8080"}],"e10.example.com":[{"SPF":"v=spf1 a:foo.example.com/24"}],"foo.example.com":[{"A":"1.1.1.1"},{"A":"1.2.3.5"}],"e11.example.com":[{"SPF":"v=spf1 a:foo:bar/baz.example.com"}],"foo:bar/baz.example.com":[{"A":"1.2.3.4"}],"e12.example.com":[{"SPF":"v=spf1 a:example.-com"}],"e13.example.com":[{"SPF":"v=spf1 a:"}],"e14.example.com":[{"SPF":"v=spf1 a:foo.example.xn--zckzah -all"}],"foo.example.xn--zckzah":[{"A":"1.2.3.4"}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.4');
        return promise.then((result) => {
          assert.equal(result, 'FAIL');
        });
      });
      it('Matches if any A records are present in DNS.', function(){
        let email = 'foo@e2.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 a/0 -all"}],"e2.example.com":[{"A":"1.1.1.1"},{"AAAA":"1234::2"},{"SPF":"v=spf1 a/0 -all"}],"e2a.example.com":[{"AAAA":"1234::1"},{"SPF":"v=spf1 a//0 -all"}],"e2b.example.com":[{"A":"1.1.1.1"},{"SPF":"v=spf1 a//0 -all"}],"ipv6.example.com":[{"AAAA":"1234::1"},{"A":"1.1.1.1"},{"SPF":"v=spf1 a -all"}],"e3.example.com":[{"SPF":"v=spf1 a:foo.example.com\u0000"}],"e4.example.com":[{"SPF":"v=spf1 a:111.222.33.44"}],"e5.example.com":[{"SPF":"v=spf1 a:abc.123"}],"e5a.example.com":[{"SPF":"v=spf1 a:museum"}],"e5b.example.com":[{"SPF":"v=spf1 a:museum."}],"e6.example.com":[{"SPF":"v=spf1 a//33 -all"}],"e6a.example.com":[{"SPF":"v=spf1 a/33 -all"}],"e7.example.com":[{"SPF":"v=spf1 a//129 -all"}],"e8.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24//64 -all"}],"e8e.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24/64 -all"}],"e8a.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24 -all"}],"e8b.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a//64 -all"}],"e9.example.com":[{"SPF":"v=spf1 a:example.com:8080"}],"e10.example.com":[{"SPF":"v=spf1 a:foo.example.com/24"}],"foo.example.com":[{"A":"1.1.1.1"},{"A":"1.2.3.5"}],"e11.example.com":[{"SPF":"v=spf1 a:foo:bar/baz.example.com"}],"foo:bar/baz.example.com":[{"A":"1.2.3.4"}],"e12.example.com":[{"SPF":"v=spf1 a:example.-com"}],"e13.example.com":[{"SPF":"v=spf1 a:"}],"e14.example.com":[{"SPF":"v=spf1 a:foo.example.xn--zckzah -all"}],"foo.example.xn--zckzah":[{"A":"1.2.3.4"}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.4');
        return promise.then((result) => {
          assert.equal(result, 'PASS');
        });
      });
      it('Matches if any A records are present in DNS.', function(){
        let email = 'foo@e2.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 a/0 -all"}],"e2.example.com":[{"A":"1.1.1.1"},{"AAAA":"1234::2"},{"SPF":"v=spf1 a/0 -all"}],"e2a.example.com":[{"AAAA":"1234::1"},{"SPF":"v=spf1 a//0 -all"}],"e2b.example.com":[{"A":"1.1.1.1"},{"SPF":"v=spf1 a//0 -all"}],"ipv6.example.com":[{"AAAA":"1234::1"},{"A":"1.1.1.1"},{"SPF":"v=spf1 a -all"}],"e3.example.com":[{"SPF":"v=spf1 a:foo.example.com\u0000"}],"e4.example.com":[{"SPF":"v=spf1 a:111.222.33.44"}],"e5.example.com":[{"SPF":"v=spf1 a:abc.123"}],"e5a.example.com":[{"SPF":"v=spf1 a:museum"}],"e5b.example.com":[{"SPF":"v=spf1 a:museum."}],"e6.example.com":[{"SPF":"v=spf1 a//33 -all"}],"e6a.example.com":[{"SPF":"v=spf1 a/33 -all"}],"e7.example.com":[{"SPF":"v=spf1 a//129 -all"}],"e8.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24//64 -all"}],"e8e.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24/64 -all"}],"e8a.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24 -all"}],"e8b.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a//64 -all"}],"e9.example.com":[{"SPF":"v=spf1 a:example.com:8080"}],"e10.example.com":[{"SPF":"v=spf1 a:foo.example.com/24"}],"foo.example.com":[{"A":"1.1.1.1"},{"A":"1.2.3.5"}],"e11.example.com":[{"SPF":"v=spf1 a:foo:bar/baz.example.com"}],"foo:bar/baz.example.com":[{"A":"1.2.3.4"}],"e12.example.com":[{"SPF":"v=spf1 a:example.-com"}],"e13.example.com":[{"SPF":"v=spf1 a:"}],"e14.example.com":[{"SPF":"v=spf1 a:foo.example.xn--zckzah -all"}],"foo.example.xn--zckzah":[{"A":"1.2.3.4"}]}, failOnNoFake: true});
        let promise = validator.validateSender('1234::1');
        return promise.then((result) => {
          assert.equal(result, 'FAIL');
        });
      });
      it('Would match if any AAAA records are present in DNS, but not for an IP4 connection.', function(){
        let email = 'foo@e2a.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 a/0 -all"}],"e2.example.com":[{"A":"1.1.1.1"},{"AAAA":"1234::2"},{"SPF":"v=spf1 a/0 -all"}],"e2a.example.com":[{"AAAA":"1234::1"},{"SPF":"v=spf1 a//0 -all"}],"e2b.example.com":[{"A":"1.1.1.1"},{"SPF":"v=spf1 a//0 -all"}],"ipv6.example.com":[{"AAAA":"1234::1"},{"A":"1.1.1.1"},{"SPF":"v=spf1 a -all"}],"e3.example.com":[{"SPF":"v=spf1 a:foo.example.com\u0000"}],"e4.example.com":[{"SPF":"v=spf1 a:111.222.33.44"}],"e5.example.com":[{"SPF":"v=spf1 a:abc.123"}],"e5a.example.com":[{"SPF":"v=spf1 a:museum"}],"e5b.example.com":[{"SPF":"v=spf1 a:museum."}],"e6.example.com":[{"SPF":"v=spf1 a//33 -all"}],"e6a.example.com":[{"SPF":"v=spf1 a/33 -all"}],"e7.example.com":[{"SPF":"v=spf1 a//129 -all"}],"e8.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24//64 -all"}],"e8e.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24/64 -all"}],"e8a.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24 -all"}],"e8b.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a//64 -all"}],"e9.example.com":[{"SPF":"v=spf1 a:example.com:8080"}],"e10.example.com":[{"SPF":"v=spf1 a:foo.example.com/24"}],"foo.example.com":[{"A":"1.1.1.1"},{"A":"1.2.3.5"}],"e11.example.com":[{"SPF":"v=spf1 a:foo:bar/baz.example.com"}],"foo:bar/baz.example.com":[{"A":"1.2.3.4"}],"e12.example.com":[{"SPF":"v=spf1 a:example.-com"}],"e13.example.com":[{"SPF":"v=spf1 a:"}],"e14.example.com":[{"SPF":"v=spf1 a:foo.example.xn--zckzah -all"}],"foo.example.xn--zckzah":[{"A":"1.2.3.4"}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.4');
        return promise.then((result) => {
          assert.equal(result, 'FAIL');
        });
      });
      it('Would match if any AAAA records are present in DNS, but not for an IP4 connection.', function(){
        let email = 'foo@e2a.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 a/0 -all"}],"e2.example.com":[{"A":"1.1.1.1"},{"AAAA":"1234::2"},{"SPF":"v=spf1 a/0 -all"}],"e2a.example.com":[{"AAAA":"1234::1"},{"SPF":"v=spf1 a//0 -all"}],"e2b.example.com":[{"A":"1.1.1.1"},{"SPF":"v=spf1 a//0 -all"}],"ipv6.example.com":[{"AAAA":"1234::1"},{"A":"1.1.1.1"},{"SPF":"v=spf1 a -all"}],"e3.example.com":[{"SPF":"v=spf1 a:foo.example.com\u0000"}],"e4.example.com":[{"SPF":"v=spf1 a:111.222.33.44"}],"e5.example.com":[{"SPF":"v=spf1 a:abc.123"}],"e5a.example.com":[{"SPF":"v=spf1 a:museum"}],"e5b.example.com":[{"SPF":"v=spf1 a:museum."}],"e6.example.com":[{"SPF":"v=spf1 a//33 -all"}],"e6a.example.com":[{"SPF":"v=spf1 a/33 -all"}],"e7.example.com":[{"SPF":"v=spf1 a//129 -all"}],"e8.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24//64 -all"}],"e8e.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24/64 -all"}],"e8a.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24 -all"}],"e8b.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a//64 -all"}],"e9.example.com":[{"SPF":"v=spf1 a:example.com:8080"}],"e10.example.com":[{"SPF":"v=spf1 a:foo.example.com/24"}],"foo.example.com":[{"A":"1.1.1.1"},{"A":"1.2.3.5"}],"e11.example.com":[{"SPF":"v=spf1 a:foo:bar/baz.example.com"}],"foo:bar/baz.example.com":[{"A":"1.2.3.4"}],"e12.example.com":[{"SPF":"v=spf1 a:example.-com"}],"e13.example.com":[{"SPF":"v=spf1 a:"}],"e14.example.com":[{"SPF":"v=spf1 a:foo.example.xn--zckzah -all"}],"foo.example.xn--zckzah":[{"A":"1.2.3.4"}]}, failOnNoFake: true});
        let promise = validator.validateSender('::FFFF:1.2.3.4');
        return promise.then((result) => {
          assert.equal(result, 'FAIL');
        });
      });
      it('Matches if any AAAA records are present in DNS.', function(){
        let email = 'foo@e2a.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 a/0 -all"}],"e2.example.com":[{"A":"1.1.1.1"},{"AAAA":"1234::2"},{"SPF":"v=spf1 a/0 -all"}],"e2a.example.com":[{"AAAA":"1234::1"},{"SPF":"v=spf1 a//0 -all"}],"e2b.example.com":[{"A":"1.1.1.1"},{"SPF":"v=spf1 a//0 -all"}],"ipv6.example.com":[{"AAAA":"1234::1"},{"A":"1.1.1.1"},{"SPF":"v=spf1 a -all"}],"e3.example.com":[{"SPF":"v=spf1 a:foo.example.com\u0000"}],"e4.example.com":[{"SPF":"v=spf1 a:111.222.33.44"}],"e5.example.com":[{"SPF":"v=spf1 a:abc.123"}],"e5a.example.com":[{"SPF":"v=spf1 a:museum"}],"e5b.example.com":[{"SPF":"v=spf1 a:museum."}],"e6.example.com":[{"SPF":"v=spf1 a//33 -all"}],"e6a.example.com":[{"SPF":"v=spf1 a/33 -all"}],"e7.example.com":[{"SPF":"v=spf1 a//129 -all"}],"e8.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24//64 -all"}],"e8e.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24/64 -all"}],"e8a.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24 -all"}],"e8b.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a//64 -all"}],"e9.example.com":[{"SPF":"v=spf1 a:example.com:8080"}],"e10.example.com":[{"SPF":"v=spf1 a:foo.example.com/24"}],"foo.example.com":[{"A":"1.1.1.1"},{"A":"1.2.3.5"}],"e11.example.com":[{"SPF":"v=spf1 a:foo:bar/baz.example.com"}],"foo:bar/baz.example.com":[{"A":"1.2.3.4"}],"e12.example.com":[{"SPF":"v=spf1 a:example.-com"}],"e13.example.com":[{"SPF":"v=spf1 a:"}],"e14.example.com":[{"SPF":"v=spf1 a:foo.example.xn--zckzah -all"}],"foo.example.xn--zckzah":[{"A":"1.2.3.4"}]}, failOnNoFake: true});
        let promise = validator.validateSender('1234::1');
        return promise.then((result) => {
          assert.equal(result, 'PASS');
        });
      });
      it('Simple IP6 Address match with dual stack.', function(){
        let email = 'foo@ipv6.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 a/0 -all"}],"e2.example.com":[{"A":"1.1.1.1"},{"AAAA":"1234::2"},{"SPF":"v=spf1 a/0 -all"}],"e2a.example.com":[{"AAAA":"1234::1"},{"SPF":"v=spf1 a//0 -all"}],"e2b.example.com":[{"A":"1.1.1.1"},{"SPF":"v=spf1 a//0 -all"}],"ipv6.example.com":[{"AAAA":"1234::1"},{"A":"1.1.1.1"},{"SPF":"v=spf1 a -all"}],"e3.example.com":[{"SPF":"v=spf1 a:foo.example.com\u0000"}],"e4.example.com":[{"SPF":"v=spf1 a:111.222.33.44"}],"e5.example.com":[{"SPF":"v=spf1 a:abc.123"}],"e5a.example.com":[{"SPF":"v=spf1 a:museum"}],"e5b.example.com":[{"SPF":"v=spf1 a:museum."}],"e6.example.com":[{"SPF":"v=spf1 a//33 -all"}],"e6a.example.com":[{"SPF":"v=spf1 a/33 -all"}],"e7.example.com":[{"SPF":"v=spf1 a//129 -all"}],"e8.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24//64 -all"}],"e8e.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24/64 -all"}],"e8a.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24 -all"}],"e8b.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a//64 -all"}],"e9.example.com":[{"SPF":"v=spf1 a:example.com:8080"}],"e10.example.com":[{"SPF":"v=spf1 a:foo.example.com/24"}],"foo.example.com":[{"A":"1.1.1.1"},{"A":"1.2.3.5"}],"e11.example.com":[{"SPF":"v=spf1 a:foo:bar/baz.example.com"}],"foo:bar/baz.example.com":[{"A":"1.2.3.4"}],"e12.example.com":[{"SPF":"v=spf1 a:example.-com"}],"e13.example.com":[{"SPF":"v=spf1 a:"}],"e14.example.com":[{"SPF":"v=spf1 a:foo.example.xn--zckzah -all"}],"foo.example.xn--zckzah":[{"A":"1.2.3.4"}]}, failOnNoFake: true});
        let promise = validator.validateSender('1234::1');
        return promise.then((result) => {
          assert.equal(result, 'PASS');
        });
      });
      it('No match if no AAAA records are present in DNS.', function(){
        let email = 'foo@e2b.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 a/0 -all"}],"e2.example.com":[{"A":"1.1.1.1"},{"AAAA":"1234::2"},{"SPF":"v=spf1 a/0 -all"}],"e2a.example.com":[{"AAAA":"1234::1"},{"SPF":"v=spf1 a//0 -all"}],"e2b.example.com":[{"A":"1.1.1.1"},{"SPF":"v=spf1 a//0 -all"}],"ipv6.example.com":[{"AAAA":"1234::1"},{"A":"1.1.1.1"},{"SPF":"v=spf1 a -all"}],"e3.example.com":[{"SPF":"v=spf1 a:foo.example.com\u0000"}],"e4.example.com":[{"SPF":"v=spf1 a:111.222.33.44"}],"e5.example.com":[{"SPF":"v=spf1 a:abc.123"}],"e5a.example.com":[{"SPF":"v=spf1 a:museum"}],"e5b.example.com":[{"SPF":"v=spf1 a:museum."}],"e6.example.com":[{"SPF":"v=spf1 a//33 -all"}],"e6a.example.com":[{"SPF":"v=spf1 a/33 -all"}],"e7.example.com":[{"SPF":"v=spf1 a//129 -all"}],"e8.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24//64 -all"}],"e8e.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24/64 -all"}],"e8a.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24 -all"}],"e8b.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a//64 -all"}],"e9.example.com":[{"SPF":"v=spf1 a:example.com:8080"}],"e10.example.com":[{"SPF":"v=spf1 a:foo.example.com/24"}],"foo.example.com":[{"A":"1.1.1.1"},{"A":"1.2.3.5"}],"e11.example.com":[{"SPF":"v=spf1 a:foo:bar/baz.example.com"}],"foo:bar/baz.example.com":[{"A":"1.2.3.4"}],"e12.example.com":[{"SPF":"v=spf1 a:example.-com"}],"e13.example.com":[{"SPF":"v=spf1 a:"}],"e14.example.com":[{"SPF":"v=spf1 a:foo.example.xn--zckzah -all"}],"foo.example.xn--zckzah":[{"A":"1.2.3.4"}]}, failOnNoFake: true});
        let promise = validator.validateSender('1234::1');
        return promise.then((result) => {
          assert.equal(result, 'FAIL');
        });
      });
      it('Null octets not allowed in toplabel', function(){
        let email = 'foo@e3.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 a/0 -all"}],"e2.example.com":[{"A":"1.1.1.1"},{"AAAA":"1234::2"},{"SPF":"v=spf1 a/0 -all"}],"e2a.example.com":[{"AAAA":"1234::1"},{"SPF":"v=spf1 a//0 -all"}],"e2b.example.com":[{"A":"1.1.1.1"},{"SPF":"v=spf1 a//0 -all"}],"ipv6.example.com":[{"AAAA":"1234::1"},{"A":"1.1.1.1"},{"SPF":"v=spf1 a -all"}],"e3.example.com":[{"SPF":"v=spf1 a:foo.example.com\u0000"}],"e4.example.com":[{"SPF":"v=spf1 a:111.222.33.44"}],"e5.example.com":[{"SPF":"v=spf1 a:abc.123"}],"e5a.example.com":[{"SPF":"v=spf1 a:museum"}],"e5b.example.com":[{"SPF":"v=spf1 a:museum."}],"e6.example.com":[{"SPF":"v=spf1 a//33 -all"}],"e6a.example.com":[{"SPF":"v=spf1 a/33 -all"}],"e7.example.com":[{"SPF":"v=spf1 a//129 -all"}],"e8.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24//64 -all"}],"e8e.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24/64 -all"}],"e8a.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24 -all"}],"e8b.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a//64 -all"}],"e9.example.com":[{"SPF":"v=spf1 a:example.com:8080"}],"e10.example.com":[{"SPF":"v=spf1 a:foo.example.com/24"}],"foo.example.com":[{"A":"1.1.1.1"},{"A":"1.2.3.5"}],"e11.example.com":[{"SPF":"v=spf1 a:foo:bar/baz.example.com"}],"foo:bar/baz.example.com":[{"A":"1.2.3.4"}],"e12.example.com":[{"SPF":"v=spf1 a:example.-com"}],"e13.example.com":[{"SPF":"v=spf1 a:"}],"e14.example.com":[{"SPF":"v=spf1 a:foo.example.xn--zckzah -all"}],"foo.example.xn--zckzah":[{"A":"1.2.3.4"}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.5');
        return promise.then((result) => {
          assert.equal(result, 'PERMERROR');
        });
      });
      it('toplabel may not be all numeric', function(){
        let email = 'foo@e4.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 a/0 -all"}],"e2.example.com":[{"A":"1.1.1.1"},{"AAAA":"1234::2"},{"SPF":"v=spf1 a/0 -all"}],"e2a.example.com":[{"AAAA":"1234::1"},{"SPF":"v=spf1 a//0 -all"}],"e2b.example.com":[{"A":"1.1.1.1"},{"SPF":"v=spf1 a//0 -all"}],"ipv6.example.com":[{"AAAA":"1234::1"},{"A":"1.1.1.1"},{"SPF":"v=spf1 a -all"}],"e3.example.com":[{"SPF":"v=spf1 a:foo.example.com\u0000"}],"e4.example.com":[{"SPF":"v=spf1 a:111.222.33.44"}],"e5.example.com":[{"SPF":"v=spf1 a:abc.123"}],"e5a.example.com":[{"SPF":"v=spf1 a:museum"}],"e5b.example.com":[{"SPF":"v=spf1 a:museum."}],"e6.example.com":[{"SPF":"v=spf1 a//33 -all"}],"e6a.example.com":[{"SPF":"v=spf1 a/33 -all"}],"e7.example.com":[{"SPF":"v=spf1 a//129 -all"}],"e8.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24//64 -all"}],"e8e.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24/64 -all"}],"e8a.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24 -all"}],"e8b.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a//64 -all"}],"e9.example.com":[{"SPF":"v=spf1 a:example.com:8080"}],"e10.example.com":[{"SPF":"v=spf1 a:foo.example.com/24"}],"foo.example.com":[{"A":"1.1.1.1"},{"A":"1.2.3.5"}],"e11.example.com":[{"SPF":"v=spf1 a:foo:bar/baz.example.com"}],"foo:bar/baz.example.com":[{"A":"1.2.3.4"}],"e12.example.com":[{"SPF":"v=spf1 a:example.-com"}],"e13.example.com":[{"SPF":"v=spf1 a:"}],"e14.example.com":[{"SPF":"v=spf1 a:foo.example.xn--zckzah -all"}],"foo.example.xn--zckzah":[{"A":"1.2.3.4"}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.4');
        return promise.then((result) => {
          assert.equal(result, 'PERMERROR');
        });
      });
      it('toplabel may not be all numeric', function(){
        let email = 'foo@e5.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 a/0 -all"}],"e2.example.com":[{"A":"1.1.1.1"},{"AAAA":"1234::2"},{"SPF":"v=spf1 a/0 -all"}],"e2a.example.com":[{"AAAA":"1234::1"},{"SPF":"v=spf1 a//0 -all"}],"e2b.example.com":[{"A":"1.1.1.1"},{"SPF":"v=spf1 a//0 -all"}],"ipv6.example.com":[{"AAAA":"1234::1"},{"A":"1.1.1.1"},{"SPF":"v=spf1 a -all"}],"e3.example.com":[{"SPF":"v=spf1 a:foo.example.com\u0000"}],"e4.example.com":[{"SPF":"v=spf1 a:111.222.33.44"}],"e5.example.com":[{"SPF":"v=spf1 a:abc.123"}],"e5a.example.com":[{"SPF":"v=spf1 a:museum"}],"e5b.example.com":[{"SPF":"v=spf1 a:museum."}],"e6.example.com":[{"SPF":"v=spf1 a//33 -all"}],"e6a.example.com":[{"SPF":"v=spf1 a/33 -all"}],"e7.example.com":[{"SPF":"v=spf1 a//129 -all"}],"e8.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24//64 -all"}],"e8e.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24/64 -all"}],"e8a.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24 -all"}],"e8b.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a//64 -all"}],"e9.example.com":[{"SPF":"v=spf1 a:example.com:8080"}],"e10.example.com":[{"SPF":"v=spf1 a:foo.example.com/24"}],"foo.example.com":[{"A":"1.1.1.1"},{"A":"1.2.3.5"}],"e11.example.com":[{"SPF":"v=spf1 a:foo:bar/baz.example.com"}],"foo:bar/baz.example.com":[{"A":"1.2.3.4"}],"e12.example.com":[{"SPF":"v=spf1 a:example.-com"}],"e13.example.com":[{"SPF":"v=spf1 a:"}],"e14.example.com":[{"SPF":"v=spf1 a:foo.example.xn--zckzah -all"}],"foo.example.xn--zckzah":[{"A":"1.2.3.4"}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.4');
        return promise.then((result) => {
          assert.equal(result, 'PERMERROR');
        });
      });
      it('toplabel may contain dashes', function(){
        let email = 'foo@e14.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 a/0 -all"}],"e2.example.com":[{"A":"1.1.1.1"},{"AAAA":"1234::2"},{"SPF":"v=spf1 a/0 -all"}],"e2a.example.com":[{"AAAA":"1234::1"},{"SPF":"v=spf1 a//0 -all"}],"e2b.example.com":[{"A":"1.1.1.1"},{"SPF":"v=spf1 a//0 -all"}],"ipv6.example.com":[{"AAAA":"1234::1"},{"A":"1.1.1.1"},{"SPF":"v=spf1 a -all"}],"e3.example.com":[{"SPF":"v=spf1 a:foo.example.com\u0000"}],"e4.example.com":[{"SPF":"v=spf1 a:111.222.33.44"}],"e5.example.com":[{"SPF":"v=spf1 a:abc.123"}],"e5a.example.com":[{"SPF":"v=spf1 a:museum"}],"e5b.example.com":[{"SPF":"v=spf1 a:museum."}],"e6.example.com":[{"SPF":"v=spf1 a//33 -all"}],"e6a.example.com":[{"SPF":"v=spf1 a/33 -all"}],"e7.example.com":[{"SPF":"v=spf1 a//129 -all"}],"e8.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24//64 -all"}],"e8e.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24/64 -all"}],"e8a.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24 -all"}],"e8b.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a//64 -all"}],"e9.example.com":[{"SPF":"v=spf1 a:example.com:8080"}],"e10.example.com":[{"SPF":"v=spf1 a:foo.example.com/24"}],"foo.example.com":[{"A":"1.1.1.1"},{"A":"1.2.3.5"}],"e11.example.com":[{"SPF":"v=spf1 a:foo:bar/baz.example.com"}],"foo:bar/baz.example.com":[{"A":"1.2.3.4"}],"e12.example.com":[{"SPF":"v=spf1 a:example.-com"}],"e13.example.com":[{"SPF":"v=spf1 a:"}],"e14.example.com":[{"SPF":"v=spf1 a:foo.example.xn--zckzah -all"}],"foo.example.xn--zckzah":[{"A":"1.2.3.4"}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.4');
        return promise.then((result) => {
          assert.equal(result, 'PASS');
        });
      });
      it('toplabel may not begin with a dash', function(){
        let email = 'foo@e12.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 a/0 -all"}],"e2.example.com":[{"A":"1.1.1.1"},{"AAAA":"1234::2"},{"SPF":"v=spf1 a/0 -all"}],"e2a.example.com":[{"AAAA":"1234::1"},{"SPF":"v=spf1 a//0 -all"}],"e2b.example.com":[{"A":"1.1.1.1"},{"SPF":"v=spf1 a//0 -all"}],"ipv6.example.com":[{"AAAA":"1234::1"},{"A":"1.1.1.1"},{"SPF":"v=spf1 a -all"}],"e3.example.com":[{"SPF":"v=spf1 a:foo.example.com\u0000"}],"e4.example.com":[{"SPF":"v=spf1 a:111.222.33.44"}],"e5.example.com":[{"SPF":"v=spf1 a:abc.123"}],"e5a.example.com":[{"SPF":"v=spf1 a:museum"}],"e5b.example.com":[{"SPF":"v=spf1 a:museum."}],"e6.example.com":[{"SPF":"v=spf1 a//33 -all"}],"e6a.example.com":[{"SPF":"v=spf1 a/33 -all"}],"e7.example.com":[{"SPF":"v=spf1 a//129 -all"}],"e8.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24//64 -all"}],"e8e.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24/64 -all"}],"e8a.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24 -all"}],"e8b.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a//64 -all"}],"e9.example.com":[{"SPF":"v=spf1 a:example.com:8080"}],"e10.example.com":[{"SPF":"v=spf1 a:foo.example.com/24"}],"foo.example.com":[{"A":"1.1.1.1"},{"A":"1.2.3.5"}],"e11.example.com":[{"SPF":"v=spf1 a:foo:bar/baz.example.com"}],"foo:bar/baz.example.com":[{"A":"1.2.3.4"}],"e12.example.com":[{"SPF":"v=spf1 a:example.-com"}],"e13.example.com":[{"SPF":"v=spf1 a:"}],"e14.example.com":[{"SPF":"v=spf1 a:foo.example.xn--zckzah -all"}],"foo.example.xn--zckzah":[{"A":"1.2.3.4"}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.4');
        return promise.then((result) => {
          assert.equal(result, 'PERMERROR');
        });
      });
      it('domain-spec may not consist of only a toplabel.', function(){
        let email = 'foo@e5a.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 a/0 -all"}],"e2.example.com":[{"A":"1.1.1.1"},{"AAAA":"1234::2"},{"SPF":"v=spf1 a/0 -all"}],"e2a.example.com":[{"AAAA":"1234::1"},{"SPF":"v=spf1 a//0 -all"}],"e2b.example.com":[{"A":"1.1.1.1"},{"SPF":"v=spf1 a//0 -all"}],"ipv6.example.com":[{"AAAA":"1234::1"},{"A":"1.1.1.1"},{"SPF":"v=spf1 a -all"}],"e3.example.com":[{"SPF":"v=spf1 a:foo.example.com\u0000"}],"e4.example.com":[{"SPF":"v=spf1 a:111.222.33.44"}],"e5.example.com":[{"SPF":"v=spf1 a:abc.123"}],"e5a.example.com":[{"SPF":"v=spf1 a:museum"}],"e5b.example.com":[{"SPF":"v=spf1 a:museum."}],"e6.example.com":[{"SPF":"v=spf1 a//33 -all"}],"e6a.example.com":[{"SPF":"v=spf1 a/33 -all"}],"e7.example.com":[{"SPF":"v=spf1 a//129 -all"}],"e8.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24//64 -all"}],"e8e.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24/64 -all"}],"e8a.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24 -all"}],"e8b.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a//64 -all"}],"e9.example.com":[{"SPF":"v=spf1 a:example.com:8080"}],"e10.example.com":[{"SPF":"v=spf1 a:foo.example.com/24"}],"foo.example.com":[{"A":"1.1.1.1"},{"A":"1.2.3.5"}],"e11.example.com":[{"SPF":"v=spf1 a:foo:bar/baz.example.com"}],"foo:bar/baz.example.com":[{"A":"1.2.3.4"}],"e12.example.com":[{"SPF":"v=spf1 a:example.-com"}],"e13.example.com":[{"SPF":"v=spf1 a:"}],"e14.example.com":[{"SPF":"v=spf1 a:foo.example.xn--zckzah -all"}],"foo.example.xn--zckzah":[{"A":"1.2.3.4"}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.4');
        return promise.then((result) => {
          assert.equal(result, 'PERMERROR');
        });
      });
      it('domain-spec may not consist of only a toplabel.', function(){
        let email = 'foo@e5b.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 a/0 -all"}],"e2.example.com":[{"A":"1.1.1.1"},{"AAAA":"1234::2"},{"SPF":"v=spf1 a/0 -all"}],"e2a.example.com":[{"AAAA":"1234::1"},{"SPF":"v=spf1 a//0 -all"}],"e2b.example.com":[{"A":"1.1.1.1"},{"SPF":"v=spf1 a//0 -all"}],"ipv6.example.com":[{"AAAA":"1234::1"},{"A":"1.1.1.1"},{"SPF":"v=spf1 a -all"}],"e3.example.com":[{"SPF":"v=spf1 a:foo.example.com\u0000"}],"e4.example.com":[{"SPF":"v=spf1 a:111.222.33.44"}],"e5.example.com":[{"SPF":"v=spf1 a:abc.123"}],"e5a.example.com":[{"SPF":"v=spf1 a:museum"}],"e5b.example.com":[{"SPF":"v=spf1 a:museum."}],"e6.example.com":[{"SPF":"v=spf1 a//33 -all"}],"e6a.example.com":[{"SPF":"v=spf1 a/33 -all"}],"e7.example.com":[{"SPF":"v=spf1 a//129 -all"}],"e8.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24//64 -all"}],"e8e.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24/64 -all"}],"e8a.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24 -all"}],"e8b.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a//64 -all"}],"e9.example.com":[{"SPF":"v=spf1 a:example.com:8080"}],"e10.example.com":[{"SPF":"v=spf1 a:foo.example.com/24"}],"foo.example.com":[{"A":"1.1.1.1"},{"A":"1.2.3.5"}],"e11.example.com":[{"SPF":"v=spf1 a:foo:bar/baz.example.com"}],"foo:bar/baz.example.com":[{"A":"1.2.3.4"}],"e12.example.com":[{"SPF":"v=spf1 a:example.-com"}],"e13.example.com":[{"SPF":"v=spf1 a:"}],"e14.example.com":[{"SPF":"v=spf1 a:foo.example.xn--zckzah -all"}],"foo.example.xn--zckzah":[{"A":"1.2.3.4"}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.4');
        return promise.then((result) => {
          assert.equal(result, 'PERMERROR');
        });
      });
      it('domain-spec may contain any visible char except %', function(){
        let email = 'foo@e11.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 a/0 -all"}],"e2.example.com":[{"A":"1.1.1.1"},{"AAAA":"1234::2"},{"SPF":"v=spf1 a/0 -all"}],"e2a.example.com":[{"AAAA":"1234::1"},{"SPF":"v=spf1 a//0 -all"}],"e2b.example.com":[{"A":"1.1.1.1"},{"SPF":"v=spf1 a//0 -all"}],"ipv6.example.com":[{"AAAA":"1234::1"},{"A":"1.1.1.1"},{"SPF":"v=spf1 a -all"}],"e3.example.com":[{"SPF":"v=spf1 a:foo.example.com\u0000"}],"e4.example.com":[{"SPF":"v=spf1 a:111.222.33.44"}],"e5.example.com":[{"SPF":"v=spf1 a:abc.123"}],"e5a.example.com":[{"SPF":"v=spf1 a:museum"}],"e5b.example.com":[{"SPF":"v=spf1 a:museum."}],"e6.example.com":[{"SPF":"v=spf1 a//33 -all"}],"e6a.example.com":[{"SPF":"v=spf1 a/33 -all"}],"e7.example.com":[{"SPF":"v=spf1 a//129 -all"}],"e8.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24//64 -all"}],"e8e.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24/64 -all"}],"e8a.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24 -all"}],"e8b.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a//64 -all"}],"e9.example.com":[{"SPF":"v=spf1 a:example.com:8080"}],"e10.example.com":[{"SPF":"v=spf1 a:foo.example.com/24"}],"foo.example.com":[{"A":"1.1.1.1"},{"A":"1.2.3.5"}],"e11.example.com":[{"SPF":"v=spf1 a:foo:bar/baz.example.com"}],"foo:bar/baz.example.com":[{"A":"1.2.3.4"}],"e12.example.com":[{"SPF":"v=spf1 a:example.-com"}],"e13.example.com":[{"SPF":"v=spf1 a:"}],"e14.example.com":[{"SPF":"v=spf1 a:foo.example.xn--zckzah -all"}],"foo.example.xn--zckzah":[{"A":"1.2.3.4"}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.4');
        return promise.then((result) => {
          assert.equal(result, 'PASS');
        });
      });
      it('domain-spec may contain any visible char except %', function(){
        let email = 'foo@e11.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 a/0 -all"}],"e2.example.com":[{"A":"1.1.1.1"},{"AAAA":"1234::2"},{"SPF":"v=spf1 a/0 -all"}],"e2a.example.com":[{"AAAA":"1234::1"},{"SPF":"v=spf1 a//0 -all"}],"e2b.example.com":[{"A":"1.1.1.1"},{"SPF":"v=spf1 a//0 -all"}],"ipv6.example.com":[{"AAAA":"1234::1"},{"A":"1.1.1.1"},{"SPF":"v=spf1 a -all"}],"e3.example.com":[{"SPF":"v=spf1 a:foo.example.com\u0000"}],"e4.example.com":[{"SPF":"v=spf1 a:111.222.33.44"}],"e5.example.com":[{"SPF":"v=spf1 a:abc.123"}],"e5a.example.com":[{"SPF":"v=spf1 a:museum"}],"e5b.example.com":[{"SPF":"v=spf1 a:museum."}],"e6.example.com":[{"SPF":"v=spf1 a//33 -all"}],"e6a.example.com":[{"SPF":"v=spf1 a/33 -all"}],"e7.example.com":[{"SPF":"v=spf1 a//129 -all"}],"e8.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24//64 -all"}],"e8e.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24/64 -all"}],"e8a.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24 -all"}],"e8b.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a//64 -all"}],"e9.example.com":[{"SPF":"v=spf1 a:example.com:8080"}],"e10.example.com":[{"SPF":"v=spf1 a:foo.example.com/24"}],"foo.example.com":[{"A":"1.1.1.1"},{"A":"1.2.3.5"}],"e11.example.com":[{"SPF":"v=spf1 a:foo:bar/baz.example.com"}],"foo:bar/baz.example.com":[{"A":"1.2.3.4"}],"e12.example.com":[{"SPF":"v=spf1 a:example.-com"}],"e13.example.com":[{"SPF":"v=spf1 a:"}],"e14.example.com":[{"SPF":"v=spf1 a:foo.example.xn--zckzah -all"}],"foo.example.xn--zckzah":[{"A":"1.2.3.4"}]}, failOnNoFake: true});
        let promise = validator.validateSender('::FFFF:1.2.3.4');
        return promise.then((result) => {
          assert.equal(result, 'PASS');
        });
      });
      it('domain-spec cannot be empty.', function(){
        let email = 'foo@e13.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 a/0 -all"}],"e2.example.com":[{"A":"1.1.1.1"},{"AAAA":"1234::2"},{"SPF":"v=spf1 a/0 -all"}],"e2a.example.com":[{"AAAA":"1234::1"},{"SPF":"v=spf1 a//0 -all"}],"e2b.example.com":[{"A":"1.1.1.1"},{"SPF":"v=spf1 a//0 -all"}],"ipv6.example.com":[{"AAAA":"1234::1"},{"A":"1.1.1.1"},{"SPF":"v=spf1 a -all"}],"e3.example.com":[{"SPF":"v=spf1 a:foo.example.com\u0000"}],"e4.example.com":[{"SPF":"v=spf1 a:111.222.33.44"}],"e5.example.com":[{"SPF":"v=spf1 a:abc.123"}],"e5a.example.com":[{"SPF":"v=spf1 a:museum"}],"e5b.example.com":[{"SPF":"v=spf1 a:museum."}],"e6.example.com":[{"SPF":"v=spf1 a//33 -all"}],"e6a.example.com":[{"SPF":"v=spf1 a/33 -all"}],"e7.example.com":[{"SPF":"v=spf1 a//129 -all"}],"e8.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24//64 -all"}],"e8e.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24/64 -all"}],"e8a.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24 -all"}],"e8b.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a//64 -all"}],"e9.example.com":[{"SPF":"v=spf1 a:example.com:8080"}],"e10.example.com":[{"SPF":"v=spf1 a:foo.example.com/24"}],"foo.example.com":[{"A":"1.1.1.1"},{"A":"1.2.3.5"}],"e11.example.com":[{"SPF":"v=spf1 a:foo:bar/baz.example.com"}],"foo:bar/baz.example.com":[{"A":"1.2.3.4"}],"e12.example.com":[{"SPF":"v=spf1 a:example.-com"}],"e13.example.com":[{"SPF":"v=spf1 a:"}],"e14.example.com":[{"SPF":"v=spf1 a:foo.example.xn--zckzah -all"}],"foo.example.xn--zckzah":[{"A":"1.2.3.4"}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.4');
        return promise.then((result) => {
          assert.equal(result, 'PERMERROR');
        });
      });
    });
    describe('Include mechanism semantics and syntax', function(){
      it('recursive check_host() result of fail causes include to not match.', function(){
        let email = 'foo@e1.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"ip5.example.com":[{"SPF":"v=spf1 ip4:1.2.3.5 -all"}],"ip6.example.com":[{"SPF":"v=spf1 ip4:1.2.3.6 ~all"}],"ip7.example.com":[{"SPF":"v=spf1 ip4:1.2.3.7 ?all"}],"ip8.example.com":["TIMEOUT"],"erehwon.example.com":[{"TXT":"v=spfl am not an SPF record"}],"e1.example.com":[{"SPF":"v=spf1 include:ip5.example.com ~all"}],"e2.example.com":[{"SPF":"v=spf1 include:ip6.example.com all"}],"e3.example.com":[{"SPF":"v=spf1 include:ip7.example.com -all"}],"e4.example.com":[{"SPF":"v=spf1 include:ip8.example.com -all"}],"e5.example.com":[{"SPF":"v=spf1 include:e6.example.com -all"}],"e6.example.com":[{"SPF":"v=spf1 include +all"}],"e7.example.com":[{"SPF":"v=spf1 include:erehwon.example.com -all"}],"e8.example.com":[{"SPF":"v=spf1 include: -all"}],"e9.example.com":[{"SPF":"v=spf1 include:ip5.example.com/24 -all"}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.4');
        return promise.then((result) => {
          assert.equal(result, 'SOFTFAIL');
        });
      });
      it('recursive check_host() result of softfail causes include to not match.', function(){
        let email = 'foo@e2.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"ip5.example.com":[{"SPF":"v=spf1 ip4:1.2.3.5 -all"}],"ip6.example.com":[{"SPF":"v=spf1 ip4:1.2.3.6 ~all"}],"ip7.example.com":[{"SPF":"v=spf1 ip4:1.2.3.7 ?all"}],"ip8.example.com":["TIMEOUT"],"erehwon.example.com":[{"TXT":"v=spfl am not an SPF record"}],"e1.example.com":[{"SPF":"v=spf1 include:ip5.example.com ~all"}],"e2.example.com":[{"SPF":"v=spf1 include:ip6.example.com all"}],"e3.example.com":[{"SPF":"v=spf1 include:ip7.example.com -all"}],"e4.example.com":[{"SPF":"v=spf1 include:ip8.example.com -all"}],"e5.example.com":[{"SPF":"v=spf1 include:e6.example.com -all"}],"e6.example.com":[{"SPF":"v=spf1 include +all"}],"e7.example.com":[{"SPF":"v=spf1 include:erehwon.example.com -all"}],"e8.example.com":[{"SPF":"v=spf1 include: -all"}],"e9.example.com":[{"SPF":"v=spf1 include:ip5.example.com/24 -all"}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.4');
        return promise.then((result) => {
          assert.equal(result, 'PASS');
        });
      });
      it('recursive check_host() result of neutral causes include to not match.', function(){
        let email = 'foo@e3.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"ip5.example.com":[{"SPF":"v=spf1 ip4:1.2.3.5 -all"}],"ip6.example.com":[{"SPF":"v=spf1 ip4:1.2.3.6 ~all"}],"ip7.example.com":[{"SPF":"v=spf1 ip4:1.2.3.7 ?all"}],"ip8.example.com":["TIMEOUT"],"erehwon.example.com":[{"TXT":"v=spfl am not an SPF record"}],"e1.example.com":[{"SPF":"v=spf1 include:ip5.example.com ~all"}],"e2.example.com":[{"SPF":"v=spf1 include:ip6.example.com all"}],"e3.example.com":[{"SPF":"v=spf1 include:ip7.example.com -all"}],"e4.example.com":[{"SPF":"v=spf1 include:ip8.example.com -all"}],"e5.example.com":[{"SPF":"v=spf1 include:e6.example.com -all"}],"e6.example.com":[{"SPF":"v=spf1 include +all"}],"e7.example.com":[{"SPF":"v=spf1 include:erehwon.example.com -all"}],"e8.example.com":[{"SPF":"v=spf1 include: -all"}],"e9.example.com":[{"SPF":"v=spf1 include:ip5.example.com/24 -all"}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.4');
        return promise.then((result) => {
          assert.equal(result, 'FAIL');
        });
      });
      it('recursive check_host() result of temperror causes include to temperror', function(){
        let email = 'foo@e4.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"ip5.example.com":[{"SPF":"v=spf1 ip4:1.2.3.5 -all"}],"ip6.example.com":[{"SPF":"v=spf1 ip4:1.2.3.6 ~all"}],"ip7.example.com":[{"SPF":"v=spf1 ip4:1.2.3.7 ?all"}],"ip8.example.com":["TIMEOUT"],"erehwon.example.com":[{"TXT":"v=spfl am not an SPF record"}],"e1.example.com":[{"SPF":"v=spf1 include:ip5.example.com ~all"}],"e2.example.com":[{"SPF":"v=spf1 include:ip6.example.com all"}],"e3.example.com":[{"SPF":"v=spf1 include:ip7.example.com -all"}],"e4.example.com":[{"SPF":"v=spf1 include:ip8.example.com -all"}],"e5.example.com":[{"SPF":"v=spf1 include:e6.example.com -all"}],"e6.example.com":[{"SPF":"v=spf1 include +all"}],"e7.example.com":[{"SPF":"v=spf1 include:erehwon.example.com -all"}],"e8.example.com":[{"SPF":"v=spf1 include: -all"}],"e9.example.com":[{"SPF":"v=spf1 include:ip5.example.com/24 -all"}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.4');
        return promise.then((result) => {
          assert.equal(result, 'TEMPERROR');
        });
      });
      it('recursive check_host() result of permerror causes include to permerror', function(){
        let email = 'foo@e5.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"ip5.example.com":[{"SPF":"v=spf1 ip4:1.2.3.5 -all"}],"ip6.example.com":[{"SPF":"v=spf1 ip4:1.2.3.6 ~all"}],"ip7.example.com":[{"SPF":"v=spf1 ip4:1.2.3.7 ?all"}],"ip8.example.com":["TIMEOUT"],"erehwon.example.com":[{"TXT":"v=spfl am not an SPF record"}],"e1.example.com":[{"SPF":"v=spf1 include:ip5.example.com ~all"}],"e2.example.com":[{"SPF":"v=spf1 include:ip6.example.com all"}],"e3.example.com":[{"SPF":"v=spf1 include:ip7.example.com -all"}],"e4.example.com":[{"SPF":"v=spf1 include:ip8.example.com -all"}],"e5.example.com":[{"SPF":"v=spf1 include:e6.example.com -all"}],"e6.example.com":[{"SPF":"v=spf1 include +all"}],"e7.example.com":[{"SPF":"v=spf1 include:erehwon.example.com -all"}],"e8.example.com":[{"SPF":"v=spf1 include: -all"}],"e9.example.com":[{"SPF":"v=spf1 include:ip5.example.com/24 -all"}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.4');
        return promise.then((result) => {
          assert.equal(result, 'PERMERROR');
        });
      });
      it('include          = "include"  ":" domain-spec', function(){
        let email = 'foo@e6.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"ip5.example.com":[{"SPF":"v=spf1 ip4:1.2.3.5 -all"}],"ip6.example.com":[{"SPF":"v=spf1 ip4:1.2.3.6 ~all"}],"ip7.example.com":[{"SPF":"v=spf1 ip4:1.2.3.7 ?all"}],"ip8.example.com":["TIMEOUT"],"erehwon.example.com":[{"TXT":"v=spfl am not an SPF record"}],"e1.example.com":[{"SPF":"v=spf1 include:ip5.example.com ~all"}],"e2.example.com":[{"SPF":"v=spf1 include:ip6.example.com all"}],"e3.example.com":[{"SPF":"v=spf1 include:ip7.example.com -all"}],"e4.example.com":[{"SPF":"v=spf1 include:ip8.example.com -all"}],"e5.example.com":[{"SPF":"v=spf1 include:e6.example.com -all"}],"e6.example.com":[{"SPF":"v=spf1 include +all"}],"e7.example.com":[{"SPF":"v=spf1 include:erehwon.example.com -all"}],"e8.example.com":[{"SPF":"v=spf1 include: -all"}],"e9.example.com":[{"SPF":"v=spf1 include:ip5.example.com/24 -all"}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.4');
        return promise.then((result) => {
          assert.equal(result, 'PERMERROR');
        });
      });
      it('include          = "include"  ":" domain-spec', function(){
        let email = 'foo@e9.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"ip5.example.com":[{"SPF":"v=spf1 ip4:1.2.3.5 -all"}],"ip6.example.com":[{"SPF":"v=spf1 ip4:1.2.3.6 ~all"}],"ip7.example.com":[{"SPF":"v=spf1 ip4:1.2.3.7 ?all"}],"ip8.example.com":["TIMEOUT"],"erehwon.example.com":[{"TXT":"v=spfl am not an SPF record"}],"e1.example.com":[{"SPF":"v=spf1 include:ip5.example.com ~all"}],"e2.example.com":[{"SPF":"v=spf1 include:ip6.example.com all"}],"e3.example.com":[{"SPF":"v=spf1 include:ip7.example.com -all"}],"e4.example.com":[{"SPF":"v=spf1 include:ip8.example.com -all"}],"e5.example.com":[{"SPF":"v=spf1 include:e6.example.com -all"}],"e6.example.com":[{"SPF":"v=spf1 include +all"}],"e7.example.com":[{"SPF":"v=spf1 include:erehwon.example.com -all"}],"e8.example.com":[{"SPF":"v=spf1 include: -all"}],"e9.example.com":[{"SPF":"v=spf1 include:ip5.example.com/24 -all"}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.4');
        return promise.then((result) => {
          assert.equal(result, 'PERMERROR');
        });
      });
      it('recursive check_host() result of none causes include to permerror', function(){
        let email = 'foo@e7.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"ip5.example.com":[{"SPF":"v=spf1 ip4:1.2.3.5 -all"}],"ip6.example.com":[{"SPF":"v=spf1 ip4:1.2.3.6 ~all"}],"ip7.example.com":[{"SPF":"v=spf1 ip4:1.2.3.7 ?all"}],"ip8.example.com":["TIMEOUT"],"erehwon.example.com":[{"TXT":"v=spfl am not an SPF record"}],"e1.example.com":[{"SPF":"v=spf1 include:ip5.example.com ~all"}],"e2.example.com":[{"SPF":"v=spf1 include:ip6.example.com all"}],"e3.example.com":[{"SPF":"v=spf1 include:ip7.example.com -all"}],"e4.example.com":[{"SPF":"v=spf1 include:ip8.example.com -all"}],"e5.example.com":[{"SPF":"v=spf1 include:e6.example.com -all"}],"e6.example.com":[{"SPF":"v=spf1 include +all"}],"e7.example.com":[{"SPF":"v=spf1 include:erehwon.example.com -all"}],"e8.example.com":[{"SPF":"v=spf1 include: -all"}],"e9.example.com":[{"SPF":"v=spf1 include:ip5.example.com/24 -all"}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.4');
        return promise.then((result) => {
          assert.equal(result, 'PERMERROR');
        });
      });
      it('domain-spec cannot be empty.', function(){
        let email = 'foo@e8.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"ip5.example.com":[{"SPF":"v=spf1 ip4:1.2.3.5 -all"}],"ip6.example.com":[{"SPF":"v=spf1 ip4:1.2.3.6 ~all"}],"ip7.example.com":[{"SPF":"v=spf1 ip4:1.2.3.7 ?all"}],"ip8.example.com":["TIMEOUT"],"erehwon.example.com":[{"TXT":"v=spfl am not an SPF record"}],"e1.example.com":[{"SPF":"v=spf1 include:ip5.example.com ~all"}],"e2.example.com":[{"SPF":"v=spf1 include:ip6.example.com all"}],"e3.example.com":[{"SPF":"v=spf1 include:ip7.example.com -all"}],"e4.example.com":[{"SPF":"v=spf1 include:ip8.example.com -all"}],"e5.example.com":[{"SPF":"v=spf1 include:e6.example.com -all"}],"e6.example.com":[{"SPF":"v=spf1 include +all"}],"e7.example.com":[{"SPF":"v=spf1 include:erehwon.example.com -all"}],"e8.example.com":[{"SPF":"v=spf1 include: -all"}],"e9.example.com":[{"SPF":"v=spf1 include:ip5.example.com/24 -all"}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.4');
        return promise.then((result) => {
          assert.equal(result, 'PERMERROR');
        });
      });
    });
    describe('MX mechanism syntax', function(){
      it('MX                = "mx"      [ ":" domain-spec ] [ dual-cidr-length ] dual-cidr-length = [ ip4-cidr-length ] [ "/" ip6-cidr-length ]', function(){
        let email = 'foo@e6.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"},{"MX":[0,""]},{"SPF":"v=spf1 mx"}],"e1.example.com":[{"SPF":"v=spf1 mx/0 -all"},{"MX":[0,"e1.example.com"]}],"e2.example.com":[{"A":"1.1.1.1"},{"AAAA":"1234::2"},{"MX":[0,"e2.example.com"]},{"SPF":"v=spf1 mx/0 -all"}],"e2a.example.com":[{"AAAA":"1234::1"},{"MX":[0,"e2a.example.com"]},{"SPF":"v=spf1 mx//0 -all"}],"e2b.example.com":[{"A":"1.1.1.1"},{"MX":[0,"e2b.example.com"]},{"SPF":"v=spf1 mx//0 -all"}],"e3.example.com":[{"SPF":"v=spf1 mx:foo.example.com\u0000"}],"e4.example.com":[{"SPF":"v=spf1 mx"},{"A":"1.2.3.4"}],"e5.example.com":[{"SPF":"v=spf1 mx:abc.123"}],"e6.example.com":[{"SPF":"v=spf1 mx//33 -all"}],"e6a.example.com":[{"SPF":"v=spf1 mx/33 -all"}],"e7.example.com":[{"SPF":"v=spf1 mx//129 -all"}],"e9.example.com":[{"SPF":"v=spf1 mx:example.com:8080"}],"e10.example.com":[{"SPF":"v=spf1 mx:foo.example.com/24"}],"foo.example.com":[{"MX":[0,"foo1.example.com"]}],"foo1.example.com":[{"A":"1.1.1.1"},{"A":"1.2.3.5"}],"e11.example.com":[{"SPF":"v=spf1 mx:foo:bar/baz.example.com"}],"foo:bar/baz.example.com":[{"MX":[0,"foo:bar/baz.example.com"]},{"A":"1.2.3.4"}],"e12.example.com":[{"SPF":"v=spf1 mx:example.-com"}],"e13.example.com":[{"SPF":"v=spf1 mx: -all"}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.4');
        return promise.then((result) => {
          assert.equal(result, 'FAIL');
        });
      });
      it('MX                = "mx"      [ ":" domain-spec ] [ dual-cidr-length ] dual-cidr-length = [ ip4-cidr-length ] [ "/" ip6-cidr-length ]', function(){
        let email = 'foo@e6a.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"},{"MX":[0,""]},{"SPF":"v=spf1 mx"}],"e1.example.com":[{"SPF":"v=spf1 mx/0 -all"},{"MX":[0,"e1.example.com"]}],"e2.example.com":[{"A":"1.1.1.1"},{"AAAA":"1234::2"},{"MX":[0,"e2.example.com"]},{"SPF":"v=spf1 mx/0 -all"}],"e2a.example.com":[{"AAAA":"1234::1"},{"MX":[0,"e2a.example.com"]},{"SPF":"v=spf1 mx//0 -all"}],"e2b.example.com":[{"A":"1.1.1.1"},{"MX":[0,"e2b.example.com"]},{"SPF":"v=spf1 mx//0 -all"}],"e3.example.com":[{"SPF":"v=spf1 mx:foo.example.com\u0000"}],"e4.example.com":[{"SPF":"v=spf1 mx"},{"A":"1.2.3.4"}],"e5.example.com":[{"SPF":"v=spf1 mx:abc.123"}],"e6.example.com":[{"SPF":"v=spf1 mx//33 -all"}],"e6a.example.com":[{"SPF":"v=spf1 mx/33 -all"}],"e7.example.com":[{"SPF":"v=spf1 mx//129 -all"}],"e9.example.com":[{"SPF":"v=spf1 mx:example.com:8080"}],"e10.example.com":[{"SPF":"v=spf1 mx:foo.example.com/24"}],"foo.example.com":[{"MX":[0,"foo1.example.com"]}],"foo1.example.com":[{"A":"1.1.1.1"},{"A":"1.2.3.5"}],"e11.example.com":[{"SPF":"v=spf1 mx:foo:bar/baz.example.com"}],"foo:bar/baz.example.com":[{"MX":[0,"foo:bar/baz.example.com"]},{"A":"1.2.3.4"}],"e12.example.com":[{"SPF":"v=spf1 mx:example.-com"}],"e13.example.com":[{"SPF":"v=spf1 mx: -all"}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.4');
        return promise.then((result) => {
          assert.equal(result, 'PERMERROR');
        });
      });
      it('MX                = "mx"      [ ":" domain-spec ] [ dual-cidr-length ] dual-cidr-length = [ ip4-cidr-length ] [ "/" ip6-cidr-length ]', function(){
        let email = 'foo@e7.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"},{"MX":[0,""]},{"SPF":"v=spf1 mx"}],"e1.example.com":[{"SPF":"v=spf1 mx/0 -all"},{"MX":[0,"e1.example.com"]}],"e2.example.com":[{"A":"1.1.1.1"},{"AAAA":"1234::2"},{"MX":[0,"e2.example.com"]},{"SPF":"v=spf1 mx/0 -all"}],"e2a.example.com":[{"AAAA":"1234::1"},{"MX":[0,"e2a.example.com"]},{"SPF":"v=spf1 mx//0 -all"}],"e2b.example.com":[{"A":"1.1.1.1"},{"MX":[0,"e2b.example.com"]},{"SPF":"v=spf1 mx//0 -all"}],"e3.example.com":[{"SPF":"v=spf1 mx:foo.example.com\u0000"}],"e4.example.com":[{"SPF":"v=spf1 mx"},{"A":"1.2.3.4"}],"e5.example.com":[{"SPF":"v=spf1 mx:abc.123"}],"e6.example.com":[{"SPF":"v=spf1 mx//33 -all"}],"e6a.example.com":[{"SPF":"v=spf1 mx/33 -all"}],"e7.example.com":[{"SPF":"v=spf1 mx//129 -all"}],"e9.example.com":[{"SPF":"v=spf1 mx:example.com:8080"}],"e10.example.com":[{"SPF":"v=spf1 mx:foo.example.com/24"}],"foo.example.com":[{"MX":[0,"foo1.example.com"]}],"foo1.example.com":[{"A":"1.1.1.1"},{"A":"1.2.3.5"}],"e11.example.com":[{"SPF":"v=spf1 mx:foo:bar/baz.example.com"}],"foo:bar/baz.example.com":[{"MX":[0,"foo:bar/baz.example.com"]},{"A":"1.2.3.4"}],"e12.example.com":[{"SPF":"v=spf1 mx:example.-com"}],"e13.example.com":[{"SPF":"v=spf1 mx: -all"}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.4');
        return promise.then((result) => {
          assert.equal(result, 'PERMERROR');
        });
      });
      it('MX matches any returned IP.', function(){
        let email = 'foo@e10.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"},{"MX":[0,""]},{"SPF":"v=spf1 mx"}],"e1.example.com":[{"SPF":"v=spf1 mx/0 -all"},{"MX":[0,"e1.example.com"]}],"e2.example.com":[{"A":"1.1.1.1"},{"AAAA":"1234::2"},{"MX":[0,"e2.example.com"]},{"SPF":"v=spf1 mx/0 -all"}],"e2a.example.com":[{"AAAA":"1234::1"},{"MX":[0,"e2a.example.com"]},{"SPF":"v=spf1 mx//0 -all"}],"e2b.example.com":[{"A":"1.1.1.1"},{"MX":[0,"e2b.example.com"]},{"SPF":"v=spf1 mx//0 -all"}],"e3.example.com":[{"SPF":"v=spf1 mx:foo.example.com\u0000"}],"e4.example.com":[{"SPF":"v=spf1 mx"},{"A":"1.2.3.4"}],"e5.example.com":[{"SPF":"v=spf1 mx:abc.123"}],"e6.example.com":[{"SPF":"v=spf1 mx//33 -all"}],"e6a.example.com":[{"SPF":"v=spf1 mx/33 -all"}],"e7.example.com":[{"SPF":"v=spf1 mx//129 -all"}],"e9.example.com":[{"SPF":"v=spf1 mx:example.com:8080"}],"e10.example.com":[{"SPF":"v=spf1 mx:foo.example.com/24"}],"foo.example.com":[{"MX":[0,"foo1.example.com"]}],"foo1.example.com":[{"A":"1.1.1.1"},{"A":"1.2.3.5"}],"e11.example.com":[{"SPF":"v=spf1 mx:foo:bar/baz.example.com"}],"foo:bar/baz.example.com":[{"MX":[0,"foo:bar/baz.example.com"]},{"A":"1.2.3.4"}],"e12.example.com":[{"SPF":"v=spf1 mx:example.-com"}],"e13.example.com":[{"SPF":"v=spf1 mx: -all"}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.4');
        return promise.then((result) => {
          assert.equal(result, 'PASS');
        });
      });
      it('MX matches any returned IP.', function(){
        let email = 'foo@e10.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"},{"MX":[0,""]},{"SPF":"v=spf1 mx"}],"e1.example.com":[{"SPF":"v=spf1 mx/0 -all"},{"MX":[0,"e1.example.com"]}],"e2.example.com":[{"A":"1.1.1.1"},{"AAAA":"1234::2"},{"MX":[0,"e2.example.com"]},{"SPF":"v=spf1 mx/0 -all"}],"e2a.example.com":[{"AAAA":"1234::1"},{"MX":[0,"e2a.example.com"]},{"SPF":"v=spf1 mx//0 -all"}],"e2b.example.com":[{"A":"1.1.1.1"},{"MX":[0,"e2b.example.com"]},{"SPF":"v=spf1 mx//0 -all"}],"e3.example.com":[{"SPF":"v=spf1 mx:foo.example.com\u0000"}],"e4.example.com":[{"SPF":"v=spf1 mx"},{"A":"1.2.3.4"}],"e5.example.com":[{"SPF":"v=spf1 mx:abc.123"}],"e6.example.com":[{"SPF":"v=spf1 mx//33 -all"}],"e6a.example.com":[{"SPF":"v=spf1 mx/33 -all"}],"e7.example.com":[{"SPF":"v=spf1 mx//129 -all"}],"e9.example.com":[{"SPF":"v=spf1 mx:example.com:8080"}],"e10.example.com":[{"SPF":"v=spf1 mx:foo.example.com/24"}],"foo.example.com":[{"MX":[0,"foo1.example.com"]}],"foo1.example.com":[{"A":"1.1.1.1"},{"A":"1.2.3.5"}],"e11.example.com":[{"SPF":"v=spf1 mx:foo:bar/baz.example.com"}],"foo:bar/baz.example.com":[{"MX":[0,"foo:bar/baz.example.com"]},{"A":"1.2.3.4"}],"e12.example.com":[{"SPF":"v=spf1 mx:example.-com"}],"e13.example.com":[{"SPF":"v=spf1 mx: -all"}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.4');
        return promise.then((result) => {
          assert.equal(result, 'PASS');
        });
      });
      it('domain-spec must pass basic syntax checks', function(){
        let email = 'foo@e9.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"},{"MX":[0,""]},{"SPF":"v=spf1 mx"}],"e1.example.com":[{"SPF":"v=spf1 mx/0 -all"},{"MX":[0,"e1.example.com"]}],"e2.example.com":[{"A":"1.1.1.1"},{"AAAA":"1234::2"},{"MX":[0,"e2.example.com"]},{"SPF":"v=spf1 mx/0 -all"}],"e2a.example.com":[{"AAAA":"1234::1"},{"MX":[0,"e2a.example.com"]},{"SPF":"v=spf1 mx//0 -all"}],"e2b.example.com":[{"A":"1.1.1.1"},{"MX":[0,"e2b.example.com"]},{"SPF":"v=spf1 mx//0 -all"}],"e3.example.com":[{"SPF":"v=spf1 mx:foo.example.com\u0000"}],"e4.example.com":[{"SPF":"v=spf1 mx"},{"A":"1.2.3.4"}],"e5.example.com":[{"SPF":"v=spf1 mx:abc.123"}],"e6.example.com":[{"SPF":"v=spf1 mx//33 -all"}],"e6a.example.com":[{"SPF":"v=spf1 mx/33 -all"}],"e7.example.com":[{"SPF":"v=spf1 mx//129 -all"}],"e9.example.com":[{"SPF":"v=spf1 mx:example.com:8080"}],"e10.example.com":[{"SPF":"v=spf1 mx:foo.example.com/24"}],"foo.example.com":[{"MX":[0,"foo1.example.com"]}],"foo1.example.com":[{"A":"1.1.1.1"},{"A":"1.2.3.5"}],"e11.example.com":[{"SPF":"v=spf1 mx:foo:bar/baz.example.com"}],"foo:bar/baz.example.com":[{"MX":[0,"foo:bar/baz.example.com"]},{"A":"1.2.3.4"}],"e12.example.com":[{"SPF":"v=spf1 mx:example.-com"}],"e13.example.com":[{"SPF":"v=spf1 mx: -all"}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.4');
        return promise.then((result) => {
          assert.equal(result, 'PERMERROR');
        });
      });
      it('If no ips are returned, MX mechanism does not match, even with /0.', function(){
        let email = 'foo@e1.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"},{"MX":[0,""]},{"SPF":"v=spf1 mx"}],"e1.example.com":[{"SPF":"v=spf1 mx/0 -all"},{"MX":[0,"e1.example.com"]}],"e2.example.com":[{"A":"1.1.1.1"},{"AAAA":"1234::2"},{"MX":[0,"e2.example.com"]},{"SPF":"v=spf1 mx/0 -all"}],"e2a.example.com":[{"AAAA":"1234::1"},{"MX":[0,"e2a.example.com"]},{"SPF":"v=spf1 mx//0 -all"}],"e2b.example.com":[{"A":"1.1.1.1"},{"MX":[0,"e2b.example.com"]},{"SPF":"v=spf1 mx//0 -all"}],"e3.example.com":[{"SPF":"v=spf1 mx:foo.example.com\u0000"}],"e4.example.com":[{"SPF":"v=spf1 mx"},{"A":"1.2.3.4"}],"e5.example.com":[{"SPF":"v=spf1 mx:abc.123"}],"e6.example.com":[{"SPF":"v=spf1 mx//33 -all"}],"e6a.example.com":[{"SPF":"v=spf1 mx/33 -all"}],"e7.example.com":[{"SPF":"v=spf1 mx//129 -all"}],"e9.example.com":[{"SPF":"v=spf1 mx:example.com:8080"}],"e10.example.com":[{"SPF":"v=spf1 mx:foo.example.com/24"}],"foo.example.com":[{"MX":[0,"foo1.example.com"]}],"foo1.example.com":[{"A":"1.1.1.1"},{"A":"1.2.3.5"}],"e11.example.com":[{"SPF":"v=spf1 mx:foo:bar/baz.example.com"}],"foo:bar/baz.example.com":[{"MX":[0,"foo:bar/baz.example.com"]},{"A":"1.2.3.4"}],"e12.example.com":[{"SPF":"v=spf1 mx:example.-com"}],"e13.example.com":[{"SPF":"v=spf1 mx: -all"}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.4');
        return promise.then((result) => {
          assert.equal(result, 'FAIL');
        });
      });
      it('Matches if any A records for any MX records are present in DNS.', function(){
        let email = 'foo@e2.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"},{"MX":[0,""]},{"SPF":"v=spf1 mx"}],"e1.example.com":[{"SPF":"v=spf1 mx/0 -all"},{"MX":[0,"e1.example.com"]}],"e2.example.com":[{"A":"1.1.1.1"},{"AAAA":"1234::2"},{"MX":[0,"e2.example.com"]},{"SPF":"v=spf1 mx/0 -all"}],"e2a.example.com":[{"AAAA":"1234::1"},{"MX":[0,"e2a.example.com"]},{"SPF":"v=spf1 mx//0 -all"}],"e2b.example.com":[{"A":"1.1.1.1"},{"MX":[0,"e2b.example.com"]},{"SPF":"v=spf1 mx//0 -all"}],"e3.example.com":[{"SPF":"v=spf1 mx:foo.example.com\u0000"}],"e4.example.com":[{"SPF":"v=spf1 mx"},{"A":"1.2.3.4"}],"e5.example.com":[{"SPF":"v=spf1 mx:abc.123"}],"e6.example.com":[{"SPF":"v=spf1 mx//33 -all"}],"e6a.example.com":[{"SPF":"v=spf1 mx/33 -all"}],"e7.example.com":[{"SPF":"v=spf1 mx//129 -all"}],"e9.example.com":[{"SPF":"v=spf1 mx:example.com:8080"}],"e10.example.com":[{"SPF":"v=spf1 mx:foo.example.com/24"}],"foo.example.com":[{"MX":[0,"foo1.example.com"]}],"foo1.example.com":[{"A":"1.1.1.1"},{"A":"1.2.3.5"}],"e11.example.com":[{"SPF":"v=spf1 mx:foo:bar/baz.example.com"}],"foo:bar/baz.example.com":[{"MX":[0,"foo:bar/baz.example.com"]},{"A":"1.2.3.4"}],"e12.example.com":[{"SPF":"v=spf1 mx:example.-com"}],"e13.example.com":[{"SPF":"v=spf1 mx: -all"}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.4');
        return promise.then((result) => {
          assert.equal(result, 'PASS');
        });
      });
      it('Matches if any A records for any MX records are present in DNS.', function(){
        let email = 'foo@e2.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"},{"MX":[0,""]},{"SPF":"v=spf1 mx"}],"e1.example.com":[{"SPF":"v=spf1 mx/0 -all"},{"MX":[0,"e1.example.com"]}],"e2.example.com":[{"A":"1.1.1.1"},{"AAAA":"1234::2"},{"MX":[0,"e2.example.com"]},{"SPF":"v=spf1 mx/0 -all"}],"e2a.example.com":[{"AAAA":"1234::1"},{"MX":[0,"e2a.example.com"]},{"SPF":"v=spf1 mx//0 -all"}],"e2b.example.com":[{"A":"1.1.1.1"},{"MX":[0,"e2b.example.com"]},{"SPF":"v=spf1 mx//0 -all"}],"e3.example.com":[{"SPF":"v=spf1 mx:foo.example.com\u0000"}],"e4.example.com":[{"SPF":"v=spf1 mx"},{"A":"1.2.3.4"}],"e5.example.com":[{"SPF":"v=spf1 mx:abc.123"}],"e6.example.com":[{"SPF":"v=spf1 mx//33 -all"}],"e6a.example.com":[{"SPF":"v=spf1 mx/33 -all"}],"e7.example.com":[{"SPF":"v=spf1 mx//129 -all"}],"e9.example.com":[{"SPF":"v=spf1 mx:example.com:8080"}],"e10.example.com":[{"SPF":"v=spf1 mx:foo.example.com/24"}],"foo.example.com":[{"MX":[0,"foo1.example.com"]}],"foo1.example.com":[{"A":"1.1.1.1"},{"A":"1.2.3.5"}],"e11.example.com":[{"SPF":"v=spf1 mx:foo:bar/baz.example.com"}],"foo:bar/baz.example.com":[{"MX":[0,"foo:bar/baz.example.com"]},{"A":"1.2.3.4"}],"e12.example.com":[{"SPF":"v=spf1 mx:example.-com"}],"e13.example.com":[{"SPF":"v=spf1 mx: -all"}]}, failOnNoFake: true});
        let promise = validator.validateSender('1234::1');
        return promise.then((result) => {
          assert.equal(result, 'FAIL');
        });
      });
      it('Would match if any AAAA records for MX records are present in DNS, but not for an IP4 connection.', function(){
        let email = 'foo@e2a.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"},{"MX":[0,""]},{"SPF":"v=spf1 mx"}],"e1.example.com":[{"SPF":"v=spf1 mx/0 -all"},{"MX":[0,"e1.example.com"]}],"e2.example.com":[{"A":"1.1.1.1"},{"AAAA":"1234::2"},{"MX":[0,"e2.example.com"]},{"SPF":"v=spf1 mx/0 -all"}],"e2a.example.com":[{"AAAA":"1234::1"},{"MX":[0,"e2a.example.com"]},{"SPF":"v=spf1 mx//0 -all"}],"e2b.example.com":[{"A":"1.1.1.1"},{"MX":[0,"e2b.example.com"]},{"SPF":"v=spf1 mx//0 -all"}],"e3.example.com":[{"SPF":"v=spf1 mx:foo.example.com\u0000"}],"e4.example.com":[{"SPF":"v=spf1 mx"},{"A":"1.2.3.4"}],"e5.example.com":[{"SPF":"v=spf1 mx:abc.123"}],"e6.example.com":[{"SPF":"v=spf1 mx//33 -all"}],"e6a.example.com":[{"SPF":"v=spf1 mx/33 -all"}],"e7.example.com":[{"SPF":"v=spf1 mx//129 -all"}],"e9.example.com":[{"SPF":"v=spf1 mx:example.com:8080"}],"e10.example.com":[{"SPF":"v=spf1 mx:foo.example.com/24"}],"foo.example.com":[{"MX":[0,"foo1.example.com"]}],"foo1.example.com":[{"A":"1.1.1.1"},{"A":"1.2.3.5"}],"e11.example.com":[{"SPF":"v=spf1 mx:foo:bar/baz.example.com"}],"foo:bar/baz.example.com":[{"MX":[0,"foo:bar/baz.example.com"]},{"A":"1.2.3.4"}],"e12.example.com":[{"SPF":"v=spf1 mx:example.-com"}],"e13.example.com":[{"SPF":"v=spf1 mx: -all"}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.4');
        return promise.then((result) => {
          assert.equal(result, 'FAIL');
        });
      });
      it('Would match if any AAAA records for MX records are present in DNS, but not for an IP4 connection.', function(){
        let email = 'foo@e2a.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"},{"MX":[0,""]},{"SPF":"v=spf1 mx"}],"e1.example.com":[{"SPF":"v=spf1 mx/0 -all"},{"MX":[0,"e1.example.com"]}],"e2.example.com":[{"A":"1.1.1.1"},{"AAAA":"1234::2"},{"MX":[0,"e2.example.com"]},{"SPF":"v=spf1 mx/0 -all"}],"e2a.example.com":[{"AAAA":"1234::1"},{"MX":[0,"e2a.example.com"]},{"SPF":"v=spf1 mx//0 -all"}],"e2b.example.com":[{"A":"1.1.1.1"},{"MX":[0,"e2b.example.com"]},{"SPF":"v=spf1 mx//0 -all"}],"e3.example.com":[{"SPF":"v=spf1 mx:foo.example.com\u0000"}],"e4.example.com":[{"SPF":"v=spf1 mx"},{"A":"1.2.3.4"}],"e5.example.com":[{"SPF":"v=spf1 mx:abc.123"}],"e6.example.com":[{"SPF":"v=spf1 mx//33 -all"}],"e6a.example.com":[{"SPF":"v=spf1 mx/33 -all"}],"e7.example.com":[{"SPF":"v=spf1 mx//129 -all"}],"e9.example.com":[{"SPF":"v=spf1 mx:example.com:8080"}],"e10.example.com":[{"SPF":"v=spf1 mx:foo.example.com/24"}],"foo.example.com":[{"MX":[0,"foo1.example.com"]}],"foo1.example.com":[{"A":"1.1.1.1"},{"A":"1.2.3.5"}],"e11.example.com":[{"SPF":"v=spf1 mx:foo:bar/baz.example.com"}],"foo:bar/baz.example.com":[{"MX":[0,"foo:bar/baz.example.com"]},{"A":"1.2.3.4"}],"e12.example.com":[{"SPF":"v=spf1 mx:example.-com"}],"e13.example.com":[{"SPF":"v=spf1 mx: -all"}]}, failOnNoFake: true});
        let promise = validator.validateSender('::FFFF:1.2.3.4');
        return promise.then((result) => {
          assert.equal(result, 'FAIL');
        });
      });
      it('Matches if any AAAA records for any MX records are present in DNS.', function(){
        let email = 'foo@e2a.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"},{"MX":[0,""]},{"SPF":"v=spf1 mx"}],"e1.example.com":[{"SPF":"v=spf1 mx/0 -all"},{"MX":[0,"e1.example.com"]}],"e2.example.com":[{"A":"1.1.1.1"},{"AAAA":"1234::2"},{"MX":[0,"e2.example.com"]},{"SPF":"v=spf1 mx/0 -all"}],"e2a.example.com":[{"AAAA":"1234::1"},{"MX":[0,"e2a.example.com"]},{"SPF":"v=spf1 mx//0 -all"}],"e2b.example.com":[{"A":"1.1.1.1"},{"MX":[0,"e2b.example.com"]},{"SPF":"v=spf1 mx//0 -all"}],"e3.example.com":[{"SPF":"v=spf1 mx:foo.example.com\u0000"}],"e4.example.com":[{"SPF":"v=spf1 mx"},{"A":"1.2.3.4"}],"e5.example.com":[{"SPF":"v=spf1 mx:abc.123"}],"e6.example.com":[{"SPF":"v=spf1 mx//33 -all"}],"e6a.example.com":[{"SPF":"v=spf1 mx/33 -all"}],"e7.example.com":[{"SPF":"v=spf1 mx//129 -all"}],"e9.example.com":[{"SPF":"v=spf1 mx:example.com:8080"}],"e10.example.com":[{"SPF":"v=spf1 mx:foo.example.com/24"}],"foo.example.com":[{"MX":[0,"foo1.example.com"]}],"foo1.example.com":[{"A":"1.1.1.1"},{"A":"1.2.3.5"}],"e11.example.com":[{"SPF":"v=spf1 mx:foo:bar/baz.example.com"}],"foo:bar/baz.example.com":[{"MX":[0,"foo:bar/baz.example.com"]},{"A":"1.2.3.4"}],"e12.example.com":[{"SPF":"v=spf1 mx:example.-com"}],"e13.example.com":[{"SPF":"v=spf1 mx: -all"}]}, failOnNoFake: true});
        let promise = validator.validateSender('1234::1');
        return promise.then((result) => {
          assert.equal(result, 'PASS');
        });
      });
      it('No match if no AAAA records for any MX records are present in DNS.', function(){
        let email = 'foo@e2b.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"},{"MX":[0,""]},{"SPF":"v=spf1 mx"}],"e1.example.com":[{"SPF":"v=spf1 mx/0 -all"},{"MX":[0,"e1.example.com"]}],"e2.example.com":[{"A":"1.1.1.1"},{"AAAA":"1234::2"},{"MX":[0,"e2.example.com"]},{"SPF":"v=spf1 mx/0 -all"}],"e2a.example.com":[{"AAAA":"1234::1"},{"MX":[0,"e2a.example.com"]},{"SPF":"v=spf1 mx//0 -all"}],"e2b.example.com":[{"A":"1.1.1.1"},{"MX":[0,"e2b.example.com"]},{"SPF":"v=spf1 mx//0 -all"}],"e3.example.com":[{"SPF":"v=spf1 mx:foo.example.com\u0000"}],"e4.example.com":[{"SPF":"v=spf1 mx"},{"A":"1.2.3.4"}],"e5.example.com":[{"SPF":"v=spf1 mx:abc.123"}],"e6.example.com":[{"SPF":"v=spf1 mx//33 -all"}],"e6a.example.com":[{"SPF":"v=spf1 mx/33 -all"}],"e7.example.com":[{"SPF":"v=spf1 mx//129 -all"}],"e9.example.com":[{"SPF":"v=spf1 mx:example.com:8080"}],"e10.example.com":[{"SPF":"v=spf1 mx:foo.example.com/24"}],"foo.example.com":[{"MX":[0,"foo1.example.com"]}],"foo1.example.com":[{"A":"1.1.1.1"},{"A":"1.2.3.5"}],"e11.example.com":[{"SPF":"v=spf1 mx:foo:bar/baz.example.com"}],"foo:bar/baz.example.com":[{"MX":[0,"foo:bar/baz.example.com"]},{"A":"1.2.3.4"}],"e12.example.com":[{"SPF":"v=spf1 mx:example.-com"}],"e13.example.com":[{"SPF":"v=spf1 mx: -all"}]}, failOnNoFake: true});
        let promise = validator.validateSender('1234::1');
        return promise.then((result) => {
          assert.equal(result, 'FAIL');
        });
      });
      it('Null not allowed in top-label.', function(){
        let email = 'foo@e3.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"},{"MX":[0,""]},{"SPF":"v=spf1 mx"}],"e1.example.com":[{"SPF":"v=spf1 mx/0 -all"},{"MX":[0,"e1.example.com"]}],"e2.example.com":[{"A":"1.1.1.1"},{"AAAA":"1234::2"},{"MX":[0,"e2.example.com"]},{"SPF":"v=spf1 mx/0 -all"}],"e2a.example.com":[{"AAAA":"1234::1"},{"MX":[0,"e2a.example.com"]},{"SPF":"v=spf1 mx//0 -all"}],"e2b.example.com":[{"A":"1.1.1.1"},{"MX":[0,"e2b.example.com"]},{"SPF":"v=spf1 mx//0 -all"}],"e3.example.com":[{"SPF":"v=spf1 mx:foo.example.com\u0000"}],"e4.example.com":[{"SPF":"v=spf1 mx"},{"A":"1.2.3.4"}],"e5.example.com":[{"SPF":"v=spf1 mx:abc.123"}],"e6.example.com":[{"SPF":"v=spf1 mx//33 -all"}],"e6a.example.com":[{"SPF":"v=spf1 mx/33 -all"}],"e7.example.com":[{"SPF":"v=spf1 mx//129 -all"}],"e9.example.com":[{"SPF":"v=spf1 mx:example.com:8080"}],"e10.example.com":[{"SPF":"v=spf1 mx:foo.example.com/24"}],"foo.example.com":[{"MX":[0,"foo1.example.com"]}],"foo1.example.com":[{"A":"1.1.1.1"},{"A":"1.2.3.5"}],"e11.example.com":[{"SPF":"v=spf1 mx:foo:bar/baz.example.com"}],"foo:bar/baz.example.com":[{"MX":[0,"foo:bar/baz.example.com"]},{"A":"1.2.3.4"}],"e12.example.com":[{"SPF":"v=spf1 mx:example.-com"}],"e13.example.com":[{"SPF":"v=spf1 mx: -all"}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.5');
        return promise.then((result) => {
          assert.equal(result, 'PERMERROR');
        });
      });
      it('Top-label may not be all numeric', function(){
        let email = 'foo@e5.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"},{"MX":[0,""]},{"SPF":"v=spf1 mx"}],"e1.example.com":[{"SPF":"v=spf1 mx/0 -all"},{"MX":[0,"e1.example.com"]}],"e2.example.com":[{"A":"1.1.1.1"},{"AAAA":"1234::2"},{"MX":[0,"e2.example.com"]},{"SPF":"v=spf1 mx/0 -all"}],"e2a.example.com":[{"AAAA":"1234::1"},{"MX":[0,"e2a.example.com"]},{"SPF":"v=spf1 mx//0 -all"}],"e2b.example.com":[{"A":"1.1.1.1"},{"MX":[0,"e2b.example.com"]},{"SPF":"v=spf1 mx//0 -all"}],"e3.example.com":[{"SPF":"v=spf1 mx:foo.example.com\u0000"}],"e4.example.com":[{"SPF":"v=spf1 mx"},{"A":"1.2.3.4"}],"e5.example.com":[{"SPF":"v=spf1 mx:abc.123"}],"e6.example.com":[{"SPF":"v=spf1 mx//33 -all"}],"e6a.example.com":[{"SPF":"v=spf1 mx/33 -all"}],"e7.example.com":[{"SPF":"v=spf1 mx//129 -all"}],"e9.example.com":[{"SPF":"v=spf1 mx:example.com:8080"}],"e10.example.com":[{"SPF":"v=spf1 mx:foo.example.com/24"}],"foo.example.com":[{"MX":[0,"foo1.example.com"]}],"foo1.example.com":[{"A":"1.1.1.1"},{"A":"1.2.3.5"}],"e11.example.com":[{"SPF":"v=spf1 mx:foo:bar/baz.example.com"}],"foo:bar/baz.example.com":[{"MX":[0,"foo:bar/baz.example.com"]},{"A":"1.2.3.4"}],"e12.example.com":[{"SPF":"v=spf1 mx:example.-com"}],"e13.example.com":[{"SPF":"v=spf1 mx: -all"}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.4');
        return promise.then((result) => {
          assert.equal(result, 'PERMERROR');
        });
      });
      it('Domain-spec may contain any visible char except %', function(){
        let email = 'foo@e11.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"},{"MX":[0,""]},{"SPF":"v=spf1 mx"}],"e1.example.com":[{"SPF":"v=spf1 mx/0 -all"},{"MX":[0,"e1.example.com"]}],"e2.example.com":[{"A":"1.1.1.1"},{"AAAA":"1234::2"},{"MX":[0,"e2.example.com"]},{"SPF":"v=spf1 mx/0 -all"}],"e2a.example.com":[{"AAAA":"1234::1"},{"MX":[0,"e2a.example.com"]},{"SPF":"v=spf1 mx//0 -all"}],"e2b.example.com":[{"A":"1.1.1.1"},{"MX":[0,"e2b.example.com"]},{"SPF":"v=spf1 mx//0 -all"}],"e3.example.com":[{"SPF":"v=spf1 mx:foo.example.com\u0000"}],"e4.example.com":[{"SPF":"v=spf1 mx"},{"A":"1.2.3.4"}],"e5.example.com":[{"SPF":"v=spf1 mx:abc.123"}],"e6.example.com":[{"SPF":"v=spf1 mx//33 -all"}],"e6a.example.com":[{"SPF":"v=spf1 mx/33 -all"}],"e7.example.com":[{"SPF":"v=spf1 mx//129 -all"}],"e9.example.com":[{"SPF":"v=spf1 mx:example.com:8080"}],"e10.example.com":[{"SPF":"v=spf1 mx:foo.example.com/24"}],"foo.example.com":[{"MX":[0,"foo1.example.com"]}],"foo1.example.com":[{"A":"1.1.1.1"},{"A":"1.2.3.5"}],"e11.example.com":[{"SPF":"v=spf1 mx:foo:bar/baz.example.com"}],"foo:bar/baz.example.com":[{"MX":[0,"foo:bar/baz.example.com"]},{"A":"1.2.3.4"}],"e12.example.com":[{"SPF":"v=spf1 mx:example.-com"}],"e13.example.com":[{"SPF":"v=spf1 mx: -all"}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.4');
        return promise.then((result) => {
          assert.equal(result, 'PASS');
        });
      });
      it('Domain-spec may contain any visible char except %', function(){
        let email = 'foo@e11.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"},{"MX":[0,""]},{"SPF":"v=spf1 mx"}],"e1.example.com":[{"SPF":"v=spf1 mx/0 -all"},{"MX":[0,"e1.example.com"]}],"e2.example.com":[{"A":"1.1.1.1"},{"AAAA":"1234::2"},{"MX":[0,"e2.example.com"]},{"SPF":"v=spf1 mx/0 -all"}],"e2a.example.com":[{"AAAA":"1234::1"},{"MX":[0,"e2a.example.com"]},{"SPF":"v=spf1 mx//0 -all"}],"e2b.example.com":[{"A":"1.1.1.1"},{"MX":[0,"e2b.example.com"]},{"SPF":"v=spf1 mx//0 -all"}],"e3.example.com":[{"SPF":"v=spf1 mx:foo.example.com\u0000"}],"e4.example.com":[{"SPF":"v=spf1 mx"},{"A":"1.2.3.4"}],"e5.example.com":[{"SPF":"v=spf1 mx:abc.123"}],"e6.example.com":[{"SPF":"v=spf1 mx//33 -all"}],"e6a.example.com":[{"SPF":"v=spf1 mx/33 -all"}],"e7.example.com":[{"SPF":"v=spf1 mx//129 -all"}],"e9.example.com":[{"SPF":"v=spf1 mx:example.com:8080"}],"e10.example.com":[{"SPF":"v=spf1 mx:foo.example.com/24"}],"foo.example.com":[{"MX":[0,"foo1.example.com"]}],"foo1.example.com":[{"A":"1.1.1.1"},{"A":"1.2.3.5"}],"e11.example.com":[{"SPF":"v=spf1 mx:foo:bar/baz.example.com"}],"foo:bar/baz.example.com":[{"MX":[0,"foo:bar/baz.example.com"]},{"A":"1.2.3.4"}],"e12.example.com":[{"SPF":"v=spf1 mx:example.-com"}],"e13.example.com":[{"SPF":"v=spf1 mx: -all"}]}, failOnNoFake: true});
        let promise = validator.validateSender('::FFFF:1.2.3.4');
        return promise.then((result) => {
          assert.equal(result, 'PASS');
        });
      });
      it('Toplabel may not begin with -', function(){
        let email = 'foo@e12.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"},{"MX":[0,""]},{"SPF":"v=spf1 mx"}],"e1.example.com":[{"SPF":"v=spf1 mx/0 -all"},{"MX":[0,"e1.example.com"]}],"e2.example.com":[{"A":"1.1.1.1"},{"AAAA":"1234::2"},{"MX":[0,"e2.example.com"]},{"SPF":"v=spf1 mx/0 -all"}],"e2a.example.com":[{"AAAA":"1234::1"},{"MX":[0,"e2a.example.com"]},{"SPF":"v=spf1 mx//0 -all"}],"e2b.example.com":[{"A":"1.1.1.1"},{"MX":[0,"e2b.example.com"]},{"SPF":"v=spf1 mx//0 -all"}],"e3.example.com":[{"SPF":"v=spf1 mx:foo.example.com\u0000"}],"e4.example.com":[{"SPF":"v=spf1 mx"},{"A":"1.2.3.4"}],"e5.example.com":[{"SPF":"v=spf1 mx:abc.123"}],"e6.example.com":[{"SPF":"v=spf1 mx//33 -all"}],"e6a.example.com":[{"SPF":"v=spf1 mx/33 -all"}],"e7.example.com":[{"SPF":"v=spf1 mx//129 -all"}],"e9.example.com":[{"SPF":"v=spf1 mx:example.com:8080"}],"e10.example.com":[{"SPF":"v=spf1 mx:foo.example.com/24"}],"foo.example.com":[{"MX":[0,"foo1.example.com"]}],"foo1.example.com":[{"A":"1.1.1.1"},{"A":"1.2.3.5"}],"e11.example.com":[{"SPF":"v=spf1 mx:foo:bar/baz.example.com"}],"foo:bar/baz.example.com":[{"MX":[0,"foo:bar/baz.example.com"]},{"A":"1.2.3.4"}],"e12.example.com":[{"SPF":"v=spf1 mx:example.-com"}],"e13.example.com":[{"SPF":"v=spf1 mx: -all"}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.4');
        return promise.then((result) => {
          assert.equal(result, 'PERMERROR');
        });
      });
      it('test null MX', function(){
        let email = '';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"},{"MX":[0,""]},{"SPF":"v=spf1 mx"}],"e1.example.com":[{"SPF":"v=spf1 mx/0 -all"},{"MX":[0,"e1.example.com"]}],"e2.example.com":[{"A":"1.1.1.1"},{"AAAA":"1234::2"},{"MX":[0,"e2.example.com"]},{"SPF":"v=spf1 mx/0 -all"}],"e2a.example.com":[{"AAAA":"1234::1"},{"MX":[0,"e2a.example.com"]},{"SPF":"v=spf1 mx//0 -all"}],"e2b.example.com":[{"A":"1.1.1.1"},{"MX":[0,"e2b.example.com"]},{"SPF":"v=spf1 mx//0 -all"}],"e3.example.com":[{"SPF":"v=spf1 mx:foo.example.com\u0000"}],"e4.example.com":[{"SPF":"v=spf1 mx"},{"A":"1.2.3.4"}],"e5.example.com":[{"SPF":"v=spf1 mx:abc.123"}],"e6.example.com":[{"SPF":"v=spf1 mx//33 -all"}],"e6a.example.com":[{"SPF":"v=spf1 mx/33 -all"}],"e7.example.com":[{"SPF":"v=spf1 mx//129 -all"}],"e9.example.com":[{"SPF":"v=spf1 mx:example.com:8080"}],"e10.example.com":[{"SPF":"v=spf1 mx:foo.example.com/24"}],"foo.example.com":[{"MX":[0,"foo1.example.com"]}],"foo1.example.com":[{"A":"1.1.1.1"},{"A":"1.2.3.5"}],"e11.example.com":[{"SPF":"v=spf1 mx:foo:bar/baz.example.com"}],"foo:bar/baz.example.com":[{"MX":[0,"foo:bar/baz.example.com"]},{"A":"1.2.3.4"}],"e12.example.com":[{"SPF":"v=spf1 mx:example.-com"}],"e13.example.com":[{"SPF":"v=spf1 mx: -all"}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.4');
        return promise.then((result) => {
          assert.equal(result, 'NEUTRAL');
        });
      });
      it('If the target name has no MX records, check_host() MUST NOT pretend the target is its single MX, and MUST NOT default to an A lookup on the target-name directly.', function(){
        let email = 'foo@e4.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"},{"MX":[0,""]},{"SPF":"v=spf1 mx"}],"e1.example.com":[{"SPF":"v=spf1 mx/0 -all"},{"MX":[0,"e1.example.com"]}],"e2.example.com":[{"A":"1.1.1.1"},{"AAAA":"1234::2"},{"MX":[0,"e2.example.com"]},{"SPF":"v=spf1 mx/0 -all"}],"e2a.example.com":[{"AAAA":"1234::1"},{"MX":[0,"e2a.example.com"]},{"SPF":"v=spf1 mx//0 -all"}],"e2b.example.com":[{"A":"1.1.1.1"},{"MX":[0,"e2b.example.com"]},{"SPF":"v=spf1 mx//0 -all"}],"e3.example.com":[{"SPF":"v=spf1 mx:foo.example.com\u0000"}],"e4.example.com":[{"SPF":"v=spf1 mx"},{"A":"1.2.3.4"}],"e5.example.com":[{"SPF":"v=spf1 mx:abc.123"}],"e6.example.com":[{"SPF":"v=spf1 mx//33 -all"}],"e6a.example.com":[{"SPF":"v=spf1 mx/33 -all"}],"e7.example.com":[{"SPF":"v=spf1 mx//129 -all"}],"e9.example.com":[{"SPF":"v=spf1 mx:example.com:8080"}],"e10.example.com":[{"SPF":"v=spf1 mx:foo.example.com/24"}],"foo.example.com":[{"MX":[0,"foo1.example.com"]}],"foo1.example.com":[{"A":"1.1.1.1"},{"A":"1.2.3.5"}],"e11.example.com":[{"SPF":"v=spf1 mx:foo:bar/baz.example.com"}],"foo:bar/baz.example.com":[{"MX":[0,"foo:bar/baz.example.com"]},{"A":"1.2.3.4"}],"e12.example.com":[{"SPF":"v=spf1 mx:example.-com"}],"e13.example.com":[{"SPF":"v=spf1 mx: -all"}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.4');
        return promise.then((result) => {
          assert.equal(result, 'NEUTRAL');
        });
      });
      it('domain-spec cannot be empty.', function(){
        let email = 'foo@e13.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"},{"MX":[0,""]},{"SPF":"v=spf1 mx"}],"e1.example.com":[{"SPF":"v=spf1 mx/0 -all"},{"MX":[0,"e1.example.com"]}],"e2.example.com":[{"A":"1.1.1.1"},{"AAAA":"1234::2"},{"MX":[0,"e2.example.com"]},{"SPF":"v=spf1 mx/0 -all"}],"e2a.example.com":[{"AAAA":"1234::1"},{"MX":[0,"e2a.example.com"]},{"SPF":"v=spf1 mx//0 -all"}],"e2b.example.com":[{"A":"1.1.1.1"},{"MX":[0,"e2b.example.com"]},{"SPF":"v=spf1 mx//0 -all"}],"e3.example.com":[{"SPF":"v=spf1 mx:foo.example.com\u0000"}],"e4.example.com":[{"SPF":"v=spf1 mx"},{"A":"1.2.3.4"}],"e5.example.com":[{"SPF":"v=spf1 mx:abc.123"}],"e6.example.com":[{"SPF":"v=spf1 mx//33 -all"}],"e6a.example.com":[{"SPF":"v=spf1 mx/33 -all"}],"e7.example.com":[{"SPF":"v=spf1 mx//129 -all"}],"e9.example.com":[{"SPF":"v=spf1 mx:example.com:8080"}],"e10.example.com":[{"SPF":"v=spf1 mx:foo.example.com/24"}],"foo.example.com":[{"MX":[0,"foo1.example.com"]}],"foo1.example.com":[{"A":"1.1.1.1"},{"A":"1.2.3.5"}],"e11.example.com":[{"SPF":"v=spf1 mx:foo:bar/baz.example.com"}],"foo:bar/baz.example.com":[{"MX":[0,"foo:bar/baz.example.com"]},{"A":"1.2.3.4"}],"e12.example.com":[{"SPF":"v=spf1 mx:example.-com"}],"e13.example.com":[{"SPF":"v=spf1 mx: -all"}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.4');
        return promise.then((result) => {
          assert.equal(result, 'PERMERROR');
        });
      });
    });
    describe('EXISTS mechanism syntax', function(){
      it('domain-spec cannot be empty.', function(){
        let email = 'foo@e1.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"mail6.example.com":[{"AAAA":"CAFE:BABE::4"}],"err.example.com":["TIMEOUT"],"e1.example.com":[{"SPF":"v=spf1 exists:"}],"e2.example.com":[{"SPF":"v=spf1 exists"}],"e3.example.com":[{"SPF":"v=spf1 exists:mail.example.com/24"}],"e4.example.com":[{"SPF":"v=spf1 exists:mail.example.com"}],"e5.example.com":[{"SPF":"v=spf1 exists:mail6.example.com -all"}],"e6.example.com":[{"SPF":"v=spf1 exists:err.example.com -all"}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.4');
        return promise.then((result) => {
          assert.equal(result, 'PERMERROR');
        });
      });
      it('exists           = "exists"   ":" domain-spec', function(){
        let email = 'foo@e2.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"mail6.example.com":[{"AAAA":"CAFE:BABE::4"}],"err.example.com":["TIMEOUT"],"e1.example.com":[{"SPF":"v=spf1 exists:"}],"e2.example.com":[{"SPF":"v=spf1 exists"}],"e3.example.com":[{"SPF":"v=spf1 exists:mail.example.com/24"}],"e4.example.com":[{"SPF":"v=spf1 exists:mail.example.com"}],"e5.example.com":[{"SPF":"v=spf1 exists:mail6.example.com -all"}],"e6.example.com":[{"SPF":"v=spf1 exists:err.example.com -all"}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.4');
        return promise.then((result) => {
          assert.equal(result, 'PERMERROR');
        });
      });
      it('exists           = "exists"   ":" domain-spec', function(){
        let email = 'foo@e3.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"mail6.example.com":[{"AAAA":"CAFE:BABE::4"}],"err.example.com":["TIMEOUT"],"e1.example.com":[{"SPF":"v=spf1 exists:"}],"e2.example.com":[{"SPF":"v=spf1 exists"}],"e3.example.com":[{"SPF":"v=spf1 exists:mail.example.com/24"}],"e4.example.com":[{"SPF":"v=spf1 exists:mail.example.com"}],"e5.example.com":[{"SPF":"v=spf1 exists:mail6.example.com -all"}],"e6.example.com":[{"SPF":"v=spf1 exists:err.example.com -all"}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.4');
        return promise.then((result) => {
          assert.equal(result, 'PERMERROR');
        });
      });
      it('mechanism matches if any DNS A RR exists', function(){
        let email = 'foo@e4.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"mail6.example.com":[{"AAAA":"CAFE:BABE::4"}],"err.example.com":["TIMEOUT"],"e1.example.com":[{"SPF":"v=spf1 exists:"}],"e2.example.com":[{"SPF":"v=spf1 exists"}],"e3.example.com":[{"SPF":"v=spf1 exists:mail.example.com/24"}],"e4.example.com":[{"SPF":"v=spf1 exists:mail.example.com"}],"e5.example.com":[{"SPF":"v=spf1 exists:mail6.example.com -all"}],"e6.example.com":[{"SPF":"v=spf1 exists:err.example.com -all"}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.4');
        return promise.then((result) => {
          assert.equal(result, 'PASS');
        });
      });
      it('The lookup type is A even when the connection is ip6', function(){
        let email = 'foo@e4.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"mail6.example.com":[{"AAAA":"CAFE:BABE::4"}],"err.example.com":["TIMEOUT"],"e1.example.com":[{"SPF":"v=spf1 exists:"}],"e2.example.com":[{"SPF":"v=spf1 exists"}],"e3.example.com":[{"SPF":"v=spf1 exists:mail.example.com/24"}],"e4.example.com":[{"SPF":"v=spf1 exists:mail.example.com"}],"e5.example.com":[{"SPF":"v=spf1 exists:mail6.example.com -all"}],"e6.example.com":[{"SPF":"v=spf1 exists:err.example.com -all"}]}, failOnNoFake: true});
        let promise = validator.validateSender('CAFE:BABE::3');
        return promise.then((result) => {
          assert.equal(result, 'PASS');
        });
      });
      it('The lookup type is A even when the connection is ip6', function(){
        let email = 'foo@e5.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"mail6.example.com":[{"AAAA":"CAFE:BABE::4"}],"err.example.com":["TIMEOUT"],"e1.example.com":[{"SPF":"v=spf1 exists:"}],"e2.example.com":[{"SPF":"v=spf1 exists"}],"e3.example.com":[{"SPF":"v=spf1 exists:mail.example.com/24"}],"e4.example.com":[{"SPF":"v=spf1 exists:mail.example.com"}],"e5.example.com":[{"SPF":"v=spf1 exists:mail6.example.com -all"}],"e6.example.com":[{"SPF":"v=spf1 exists:err.example.com -all"}]}, failOnNoFake: true});
        let promise = validator.validateSender('CAFE:BABE::3');
        return promise.then((result) => {
          assert.equal(result, 'FAIL');
        });
      });
      it('Result for DNS error is being clarified in spfbis', function(){
        let email = 'foo@e6.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"mail6.example.com":[{"AAAA":"CAFE:BABE::4"}],"err.example.com":["TIMEOUT"],"e1.example.com":[{"SPF":"v=spf1 exists:"}],"e2.example.com":[{"SPF":"v=spf1 exists"}],"e3.example.com":[{"SPF":"v=spf1 exists:mail.example.com/24"}],"e4.example.com":[{"SPF":"v=spf1 exists:mail.example.com"}],"e5.example.com":[{"SPF":"v=spf1 exists:mail6.example.com -all"}],"e6.example.com":[{"SPF":"v=spf1 exists:err.example.com -all"}]}, failOnNoFake: true});
        let promise = validator.validateSender('CAFE:BABE::3');
        return promise.then((result) => {
          assert.include(["fail","temperror"], result.toLowerCase());
        });
      });
    });
    describe('IP4 mechanism syntax', function(){
      it('ip4-cidr-length  = "/" 1*DIGIT', function(){
        let email = 'foo@e1.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 ip4:1.1.1.1/0 -all"}],"e2.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4/32 -all"}],"e3.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4/33 -all"}],"e4.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4/032 -all"}],"e5.example.com":[{"SPF":"v=spf1 ip4"}],"e6.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4//32"}],"e7.example.com":[{"SPF":"v=spf1 -ip4:1.2.3.4 ip6:::FFFF:1.2.3.4"}],"e8.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4:8080"}],"e9.example.com":[{"SPF":"v=spf1 ip4:1.2.3"}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.4');
        return promise.then((result) => {
          assert.equal(result, 'PASS');
        });
      });
      it('ip4-cidr-length  = "/" 1*DIGIT', function(){
        let email = 'foo@e2.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 ip4:1.1.1.1/0 -all"}],"e2.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4/32 -all"}],"e3.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4/33 -all"}],"e4.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4/032 -all"}],"e5.example.com":[{"SPF":"v=spf1 ip4"}],"e6.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4//32"}],"e7.example.com":[{"SPF":"v=spf1 -ip4:1.2.3.4 ip6:::FFFF:1.2.3.4"}],"e8.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4:8080"}],"e9.example.com":[{"SPF":"v=spf1 ip4:1.2.3"}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.4');
        return promise.then((result) => {
          assert.equal(result, 'PASS');
        });
      });
      it('Invalid CIDR should get permerror.', function(){
        let email = 'foo@e3.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 ip4:1.1.1.1/0 -all"}],"e2.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4/32 -all"}],"e3.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4/33 -all"}],"e4.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4/032 -all"}],"e5.example.com":[{"SPF":"v=spf1 ip4"}],"e6.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4//32"}],"e7.example.com":[{"SPF":"v=spf1 -ip4:1.2.3.4 ip6:::FFFF:1.2.3.4"}],"e8.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4:8080"}],"e9.example.com":[{"SPF":"v=spf1 ip4:1.2.3"}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.4');
        return promise.then((result) => {
          assert.equal(result, 'PERMERROR');
        });
      });
      it('Invalid CIDR should get permerror.', function(){
        let email = 'foo@e4.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 ip4:1.1.1.1/0 -all"}],"e2.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4/32 -all"}],"e3.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4/33 -all"}],"e4.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4/032 -all"}],"e5.example.com":[{"SPF":"v=spf1 ip4"}],"e6.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4//32"}],"e7.example.com":[{"SPF":"v=spf1 -ip4:1.2.3.4 ip6:::FFFF:1.2.3.4"}],"e8.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4:8080"}],"e9.example.com":[{"SPF":"v=spf1 ip4:1.2.3"}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.4');
        return promise.then((result) => {
          assert.equal(result, 'PERMERROR');
        });
      });
      it('IP4              = "ip4"      ":" ip4-network   [ ip4-cidr-length ]', function(){
        let email = 'foo@e5.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 ip4:1.1.1.1/0 -all"}],"e2.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4/32 -all"}],"e3.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4/33 -all"}],"e4.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4/032 -all"}],"e5.example.com":[{"SPF":"v=spf1 ip4"}],"e6.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4//32"}],"e7.example.com":[{"SPF":"v=spf1 -ip4:1.2.3.4 ip6:::FFFF:1.2.3.4"}],"e8.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4:8080"}],"e9.example.com":[{"SPF":"v=spf1 ip4:1.2.3"}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.4');
        return promise.then((result) => {
          assert.equal(result, 'PERMERROR');
        });
      });
      it('IP4              = "ip4"      ":" ip4-network   [ ip4-cidr-length ]', function(){
        let email = 'foo@e8.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 ip4:1.1.1.1/0 -all"}],"e2.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4/32 -all"}],"e3.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4/33 -all"}],"e4.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4/032 -all"}],"e5.example.com":[{"SPF":"v=spf1 ip4"}],"e6.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4//32"}],"e7.example.com":[{"SPF":"v=spf1 -ip4:1.2.3.4 ip6:::FFFF:1.2.3.4"}],"e8.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4:8080"}],"e9.example.com":[{"SPF":"v=spf1 ip4:1.2.3"}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.4');
        return promise.then((result) => {
          assert.equal(result, 'PERMERROR');
        });
      });
      it('It is not permitted to omit parts of the IP address instead of using CIDR notations.', function(){
        let email = 'foo@e9.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 ip4:1.1.1.1/0 -all"}],"e2.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4/32 -all"}],"e3.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4/33 -all"}],"e4.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4/032 -all"}],"e5.example.com":[{"SPF":"v=spf1 ip4"}],"e6.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4//32"}],"e7.example.com":[{"SPF":"v=spf1 -ip4:1.2.3.4 ip6:::FFFF:1.2.3.4"}],"e8.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4:8080"}],"e9.example.com":[{"SPF":"v=spf1 ip4:1.2.3"}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.4');
        return promise.then((result) => {
          assert.equal(result, 'PERMERROR');
        });
      });
      it('dual-cidr-length not permitted on ip4', function(){
        let email = 'foo@e6.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 ip4:1.1.1.1/0 -all"}],"e2.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4/32 -all"}],"e3.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4/33 -all"}],"e4.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4/032 -all"}],"e5.example.com":[{"SPF":"v=spf1 ip4"}],"e6.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4//32"}],"e7.example.com":[{"SPF":"v=spf1 -ip4:1.2.3.4 ip6:::FFFF:1.2.3.4"}],"e8.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4:8080"}],"e9.example.com":[{"SPF":"v=spf1 ip4:1.2.3"}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.4');
        return promise.then((result) => {
          assert.equal(result, 'PERMERROR');
        });
      });
      it('IP4 mapped IP6 connections MUST be treated as IP4', function(){
        let email = 'foo@e7.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 ip4:1.1.1.1/0 -all"}],"e2.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4/32 -all"}],"e3.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4/33 -all"}],"e4.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4/032 -all"}],"e5.example.com":[{"SPF":"v=spf1 ip4"}],"e6.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4//32"}],"e7.example.com":[{"SPF":"v=spf1 -ip4:1.2.3.4 ip6:::FFFF:1.2.3.4"}],"e8.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4:8080"}],"e9.example.com":[{"SPF":"v=spf1 ip4:1.2.3"}]}, failOnNoFake: true});
        let promise = validator.validateSender('::FFFF:1.2.3.4');
        return promise.then((result) => {
          assert.equal(result, 'FAIL');
        });
      });
    });
    describe('IP6 mechanism syntax', function(){
      it('IP6              = "ip6"      ":" ip6-network   [ ip6-cidr-length ]', function(){
        let email = 'foo@e1.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 -all ip6"}],"e2.example.com":[{"SPF":"v=spf1 ip6:::1.1.1.1/0"}],"e3.example.com":[{"SPF":"v=spf1 ip6:::1.1.1.1/129"}],"e4.example.com":[{"SPF":"v=spf1 ip6:::1.1.1.1//33"}],"e5.example.com":[{"SPF":"v=spf1 ip6:CAFE:BABE:8000::/33"}],"e6.example.com":[{"SPF":"v=spf1 ip6::CAFE::BABE"}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.4');
        return promise.then((result) => {
          assert.equal(result, 'PERMERROR');
        });
      });
      it('IP4 connections do not match ip6.', function(){
        let email = 'foo@e2.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 -all ip6"}],"e2.example.com":[{"SPF":"v=spf1 ip6:::1.1.1.1/0"}],"e3.example.com":[{"SPF":"v=spf1 ip6:::1.1.1.1/129"}],"e4.example.com":[{"SPF":"v=spf1 ip6:::1.1.1.1//33"}],"e5.example.com":[{"SPF":"v=spf1 ip6:CAFE:BABE:8000::/33"}],"e6.example.com":[{"SPF":"v=spf1 ip6::CAFE::BABE"}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.4');
        return promise.then((result) => {
          assert.include(["neutral","pass"], result.toLowerCase());
        });
      });
      it('Even if the SMTP connection is via IPv6, an IPv4-mapped IPv6 IP address (see RFC 3513, Section 2.5.5) MUST still be considered an IPv4 address.', function(){
        let email = 'foo@e2.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 -all ip6"}],"e2.example.com":[{"SPF":"v=spf1 ip6:::1.1.1.1/0"}],"e3.example.com":[{"SPF":"v=spf1 ip6:::1.1.1.1/129"}],"e4.example.com":[{"SPF":"v=spf1 ip6:::1.1.1.1//33"}],"e5.example.com":[{"SPF":"v=spf1 ip6:CAFE:BABE:8000::/33"}],"e6.example.com":[{"SPF":"v=spf1 ip6::CAFE::BABE"}]}, failOnNoFake: true});
        let promise = validator.validateSender('::FFFF:1.2.3.4');
        return promise.then((result) => {
          assert.include(["neutral","pass"], result.toLowerCase());
        });
      });
      it('Match any IP6', function(){
        let email = 'foo@e2.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 -all ip6"}],"e2.example.com":[{"SPF":"v=spf1 ip6:::1.1.1.1/0"}],"e3.example.com":[{"SPF":"v=spf1 ip6:::1.1.1.1/129"}],"e4.example.com":[{"SPF":"v=spf1 ip6:::1.1.1.1//33"}],"e5.example.com":[{"SPF":"v=spf1 ip6:CAFE:BABE:8000::/33"}],"e6.example.com":[{"SPF":"v=spf1 ip6::CAFE::BABE"}]}, failOnNoFake: true});
        let promise = validator.validateSender('DEAF:BABE::CAB:FEE');
        return promise.then((result) => {
          assert.equal(result, 'PASS');
        });
      });
      it('Invalid CIDR', function(){
        let email = 'foo@e3.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 -all ip6"}],"e2.example.com":[{"SPF":"v=spf1 ip6:::1.1.1.1/0"}],"e3.example.com":[{"SPF":"v=spf1 ip6:::1.1.1.1/129"}],"e4.example.com":[{"SPF":"v=spf1 ip6:::1.1.1.1//33"}],"e5.example.com":[{"SPF":"v=spf1 ip6:CAFE:BABE:8000::/33"}],"e6.example.com":[{"SPF":"v=spf1 ip6::CAFE::BABE"}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.4');
        return promise.then((result) => {
          assert.equal(result, 'PERMERROR');
        });
      });
      it('dual-cidr syntax not used for ip6', function(){
        let email = 'foo@e4.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 -all ip6"}],"e2.example.com":[{"SPF":"v=spf1 ip6:::1.1.1.1/0"}],"e3.example.com":[{"SPF":"v=spf1 ip6:::1.1.1.1/129"}],"e4.example.com":[{"SPF":"v=spf1 ip6:::1.1.1.1//33"}],"e5.example.com":[{"SPF":"v=spf1 ip6:CAFE:BABE:8000::/33"}],"e6.example.com":[{"SPF":"v=spf1 ip6::CAFE::BABE"}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.4');
        return promise.then((result) => {
          assert.equal(result, 'PERMERROR');
        });
      });
      it('make sure ip4 cidr restriction are not used for ip6', function(){
        let email = 'foo@e5.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 -all ip6"}],"e2.example.com":[{"SPF":"v=spf1 ip6:::1.1.1.1/0"}],"e3.example.com":[{"SPF":"v=spf1 ip6:::1.1.1.1/129"}],"e4.example.com":[{"SPF":"v=spf1 ip6:::1.1.1.1//33"}],"e5.example.com":[{"SPF":"v=spf1 ip6:CAFE:BABE:8000::/33"}],"e6.example.com":[{"SPF":"v=spf1 ip6::CAFE::BABE"}]}, failOnNoFake: true});
        let promise = validator.validateSender('CAFE:BABE:8000::');
        return promise.then((result) => {
          assert.equal(result, 'PASS');
        });
      });
      it('make sure ip4 cidr restriction are not used for ip6', function(){
        let email = 'foo@e5.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 -all ip6"}],"e2.example.com":[{"SPF":"v=spf1 ip6:::1.1.1.1/0"}],"e3.example.com":[{"SPF":"v=spf1 ip6:::1.1.1.1/129"}],"e4.example.com":[{"SPF":"v=spf1 ip6:::1.1.1.1//33"}],"e5.example.com":[{"SPF":"v=spf1 ip6:CAFE:BABE:8000::/33"}],"e6.example.com":[{"SPF":"v=spf1 ip6::CAFE::BABE"}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.4');
        return promise.then((result) => {
          assert.equal(result, 'NEUTRAL');
        });
      });
      it('', function(){
        let email = 'foo@e6.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 -all ip6"}],"e2.example.com":[{"SPF":"v=spf1 ip6:::1.1.1.1/0"}],"e3.example.com":[{"SPF":"v=spf1 ip6:::1.1.1.1/129"}],"e4.example.com":[{"SPF":"v=spf1 ip6:::1.1.1.1//33"}],"e5.example.com":[{"SPF":"v=spf1 ip6:CAFE:BABE:8000::/33"}],"e6.example.com":[{"SPF":"v=spf1 ip6::CAFE::BABE"}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.4');
        return promise.then((result) => {
          assert.equal(result, 'PERMERROR');
        });
      });
    });
    describe('Semantics of exp and other modifiers', function(){
      it('If no SPF record is found, or if the target-name is malformed, the result is a "PermError" rather than "None".', function(){
        let email = 'foo@e10.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 exp=exp1.example.com redirect=e2.example.com"}],"e2.example.com":[{"SPF":"v=spf1 -all"}],"e3.example.com":[{"SPF":"v=spf1 exp=exp1.example.com redirect=e4.example.com"}],"e4.example.com":[{"SPF":"v=spf1 -all exp=exp2.example.com"}],"exp1.example.com":[{"TXT":"No-see-um"}],"exp2.example.com":[{"TXT":"See me."}],"exp3.example.com":[{"TXT":"Correct!"}],"exp4.example.com":[{"TXT":"%{l} in implementation"}],"e5.example.com":[{"SPF":"v=spf1 1up=foo"}],"e6.example.com":[{"SPF":"v=spf1 =all"}],"e7.example.com":[{"SPF":"v=spf1 include:e3.example.com -all exp=exp3.example.com"}],"e8.example.com":[{"SPF":"v=spf1 -all exp=exp4.example.com"}],"e9.example.com":[{"SPF":"v=spf1 -all foo=%abc"}],"e10.example.com":[{"SPF":"v=spf1 redirect=erehwon.example.com"}],"e11.example.com":[{"SPF":"v=spf1 -all exp=e11msg.example.com"}],"e11msg.example.com":[{"TXT":"Answer a fool according to his folly."},{"TXT":"Do not answer a fool according to his folly."}],"e12.example.com":[{"SPF":"v=spf1 exp= -all"}],"e13.example.com":[{"SPF":"v=spf1 exp=e13msg.example.com -all"}],"e13msg.example.com":[{"TXT":"The %{x}-files."}],"e14.example.com":[{"SPF":"v=spf1 exp=e13msg.example.com -all exp=e11msg.example.com"}],"e15.example.com":[{"SPF":"v=spf1 redirect=e12.example.com -all redirect=e12.example.com"}],"e16.example.com":[{"SPF":"v=spf1 exp=-all"}],"e17.example.com":[{"SPF":"v=spf1 redirect=-all ?all"}],"e18.example.com":[{"SPF":"v=spf1 ?all redirect="}],"e19.example.com":[{"SPF":"v=spf1 default=pass"}],"e20.example.com":[{"SPF":"v=spf1 default=+"}],"e21.example.com":[{"SPF":"v=spf1 exp=e21msg.example.com -all"}],"e21msg.example.com":["TIMEOUT"],"e22.example.com":[{"SPF":"v=spf1 exp=mail.example.com -all"}],"nonascii.example.com":[{"SPF":"v=spf1 exp=badexp.example.com -all"}],"badexp.example.com":[{"TXT":"ï»¿Explanation"}],"tworecs.example.com":[{"SPF":"v=spf1 exp=twoexp.example.com -all"}],"twoexp.example.com":[{"TXT":"one"},{"TXT":"two"}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.4');
        return promise.then((result) => {
          assert.equal(result, 'PERMERROR');
        });
      });
      it('when executing "redirect", exp= from the original domain MUST NOT be used.', function(){
        let email = 'foo@e1.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 exp=exp1.example.com redirect=e2.example.com"}],"e2.example.com":[{"SPF":"v=spf1 -all"}],"e3.example.com":[{"SPF":"v=spf1 exp=exp1.example.com redirect=e4.example.com"}],"e4.example.com":[{"SPF":"v=spf1 -all exp=exp2.example.com"}],"exp1.example.com":[{"TXT":"No-see-um"}],"exp2.example.com":[{"TXT":"See me."}],"exp3.example.com":[{"TXT":"Correct!"}],"exp4.example.com":[{"TXT":"%{l} in implementation"}],"e5.example.com":[{"SPF":"v=spf1 1up=foo"}],"e6.example.com":[{"SPF":"v=spf1 =all"}],"e7.example.com":[{"SPF":"v=spf1 include:e3.example.com -all exp=exp3.example.com"}],"e8.example.com":[{"SPF":"v=spf1 -all exp=exp4.example.com"}],"e9.example.com":[{"SPF":"v=spf1 -all foo=%abc"}],"e10.example.com":[{"SPF":"v=spf1 redirect=erehwon.example.com"}],"e11.example.com":[{"SPF":"v=spf1 -all exp=e11msg.example.com"}],"e11msg.example.com":[{"TXT":"Answer a fool according to his folly."},{"TXT":"Do not answer a fool according to his folly."}],"e12.example.com":[{"SPF":"v=spf1 exp= -all"}],"e13.example.com":[{"SPF":"v=spf1 exp=e13msg.example.com -all"}],"e13msg.example.com":[{"TXT":"The %{x}-files."}],"e14.example.com":[{"SPF":"v=spf1 exp=e13msg.example.com -all exp=e11msg.example.com"}],"e15.example.com":[{"SPF":"v=spf1 redirect=e12.example.com -all redirect=e12.example.com"}],"e16.example.com":[{"SPF":"v=spf1 exp=-all"}],"e17.example.com":[{"SPF":"v=spf1 redirect=-all ?all"}],"e18.example.com":[{"SPF":"v=spf1 ?all redirect="}],"e19.example.com":[{"SPF":"v=spf1 default=pass"}],"e20.example.com":[{"SPF":"v=spf1 default=+"}],"e21.example.com":[{"SPF":"v=spf1 exp=e21msg.example.com -all"}],"e21msg.example.com":["TIMEOUT"],"e22.example.com":[{"SPF":"v=spf1 exp=mail.example.com -all"}],"nonascii.example.com":[{"SPF":"v=spf1 exp=badexp.example.com -all"}],"badexp.example.com":[{"TXT":"ï»¿Explanation"}],"tworecs.example.com":[{"SPF":"v=spf1 exp=twoexp.example.com -all"}],"twoexp.example.com":[{"TXT":"one"},{"TXT":"two"}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.4');
        return promise.then((result) => {
          assert.equal(result, 'FAIL');
        });
      });
      it('redirect      = "redirect" "=" domain-spec', function(){
        let email = 'foo@e17.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 exp=exp1.example.com redirect=e2.example.com"}],"e2.example.com":[{"SPF":"v=spf1 -all"}],"e3.example.com":[{"SPF":"v=spf1 exp=exp1.example.com redirect=e4.example.com"}],"e4.example.com":[{"SPF":"v=spf1 -all exp=exp2.example.com"}],"exp1.example.com":[{"TXT":"No-see-um"}],"exp2.example.com":[{"TXT":"See me."}],"exp3.example.com":[{"TXT":"Correct!"}],"exp4.example.com":[{"TXT":"%{l} in implementation"}],"e5.example.com":[{"SPF":"v=spf1 1up=foo"}],"e6.example.com":[{"SPF":"v=spf1 =all"}],"e7.example.com":[{"SPF":"v=spf1 include:e3.example.com -all exp=exp3.example.com"}],"e8.example.com":[{"SPF":"v=spf1 -all exp=exp4.example.com"}],"e9.example.com":[{"SPF":"v=spf1 -all foo=%abc"}],"e10.example.com":[{"SPF":"v=spf1 redirect=erehwon.example.com"}],"e11.example.com":[{"SPF":"v=spf1 -all exp=e11msg.example.com"}],"e11msg.example.com":[{"TXT":"Answer a fool according to his folly."},{"TXT":"Do not answer a fool according to his folly."}],"e12.example.com":[{"SPF":"v=spf1 exp= -all"}],"e13.example.com":[{"SPF":"v=spf1 exp=e13msg.example.com -all"}],"e13msg.example.com":[{"TXT":"The %{x}-files."}],"e14.example.com":[{"SPF":"v=spf1 exp=e13msg.example.com -all exp=e11msg.example.com"}],"e15.example.com":[{"SPF":"v=spf1 redirect=e12.example.com -all redirect=e12.example.com"}],"e16.example.com":[{"SPF":"v=spf1 exp=-all"}],"e17.example.com":[{"SPF":"v=spf1 redirect=-all ?all"}],"e18.example.com":[{"SPF":"v=spf1 ?all redirect="}],"e19.example.com":[{"SPF":"v=spf1 default=pass"}],"e20.example.com":[{"SPF":"v=spf1 default=+"}],"e21.example.com":[{"SPF":"v=spf1 exp=e21msg.example.com -all"}],"e21msg.example.com":["TIMEOUT"],"e22.example.com":[{"SPF":"v=spf1 exp=mail.example.com -all"}],"nonascii.example.com":[{"SPF":"v=spf1 exp=badexp.example.com -all"}],"badexp.example.com":[{"TXT":"ï»¿Explanation"}],"tworecs.example.com":[{"SPF":"v=spf1 exp=twoexp.example.com -all"}],"twoexp.example.com":[{"TXT":"one"},{"TXT":"two"}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.4');
        return promise.then((result) => {
          assert.equal(result, 'PERMERROR');
        });
      });
      it('when executing "include", exp= from the target domain MUST NOT be used.', function(){
        let email = 'foo@e7.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 exp=exp1.example.com redirect=e2.example.com"}],"e2.example.com":[{"SPF":"v=spf1 -all"}],"e3.example.com":[{"SPF":"v=spf1 exp=exp1.example.com redirect=e4.example.com"}],"e4.example.com":[{"SPF":"v=spf1 -all exp=exp2.example.com"}],"exp1.example.com":[{"TXT":"No-see-um"}],"exp2.example.com":[{"TXT":"See me."}],"exp3.example.com":[{"TXT":"Correct!"}],"exp4.example.com":[{"TXT":"%{l} in implementation"}],"e5.example.com":[{"SPF":"v=spf1 1up=foo"}],"e6.example.com":[{"SPF":"v=spf1 =all"}],"e7.example.com":[{"SPF":"v=spf1 include:e3.example.com -all exp=exp3.example.com"}],"e8.example.com":[{"SPF":"v=spf1 -all exp=exp4.example.com"}],"e9.example.com":[{"SPF":"v=spf1 -all foo=%abc"}],"e10.example.com":[{"SPF":"v=spf1 redirect=erehwon.example.com"}],"e11.example.com":[{"SPF":"v=spf1 -all exp=e11msg.example.com"}],"e11msg.example.com":[{"TXT":"Answer a fool according to his folly."},{"TXT":"Do not answer a fool according to his folly."}],"e12.example.com":[{"SPF":"v=spf1 exp= -all"}],"e13.example.com":[{"SPF":"v=spf1 exp=e13msg.example.com -all"}],"e13msg.example.com":[{"TXT":"The %{x}-files."}],"e14.example.com":[{"SPF":"v=spf1 exp=e13msg.example.com -all exp=e11msg.example.com"}],"e15.example.com":[{"SPF":"v=spf1 redirect=e12.example.com -all redirect=e12.example.com"}],"e16.example.com":[{"SPF":"v=spf1 exp=-all"}],"e17.example.com":[{"SPF":"v=spf1 redirect=-all ?all"}],"e18.example.com":[{"SPF":"v=spf1 ?all redirect="}],"e19.example.com":[{"SPF":"v=spf1 default=pass"}],"e20.example.com":[{"SPF":"v=spf1 default=+"}],"e21.example.com":[{"SPF":"v=spf1 exp=e21msg.example.com -all"}],"e21msg.example.com":["TIMEOUT"],"e22.example.com":[{"SPF":"v=spf1 exp=mail.example.com -all"}],"nonascii.example.com":[{"SPF":"v=spf1 exp=badexp.example.com -all"}],"badexp.example.com":[{"TXT":"ï»¿Explanation"}],"tworecs.example.com":[{"SPF":"v=spf1 exp=twoexp.example.com -all"}],"twoexp.example.com":[{"TXT":"one"},{"TXT":"two"}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.4');
        return promise.then((result) => {
          assert.equal(result, 'FAIL');
        });
      });
      it('when executing "redirect", exp= from the original domain MUST NOT be used.', function(){
        let email = 'foo@e3.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 exp=exp1.example.com redirect=e2.example.com"}],"e2.example.com":[{"SPF":"v=spf1 -all"}],"e3.example.com":[{"SPF":"v=spf1 exp=exp1.example.com redirect=e4.example.com"}],"e4.example.com":[{"SPF":"v=spf1 -all exp=exp2.example.com"}],"exp1.example.com":[{"TXT":"No-see-um"}],"exp2.example.com":[{"TXT":"See me."}],"exp3.example.com":[{"TXT":"Correct!"}],"exp4.example.com":[{"TXT":"%{l} in implementation"}],"e5.example.com":[{"SPF":"v=spf1 1up=foo"}],"e6.example.com":[{"SPF":"v=spf1 =all"}],"e7.example.com":[{"SPF":"v=spf1 include:e3.example.com -all exp=exp3.example.com"}],"e8.example.com":[{"SPF":"v=spf1 -all exp=exp4.example.com"}],"e9.example.com":[{"SPF":"v=spf1 -all foo=%abc"}],"e10.example.com":[{"SPF":"v=spf1 redirect=erehwon.example.com"}],"e11.example.com":[{"SPF":"v=spf1 -all exp=e11msg.example.com"}],"e11msg.example.com":[{"TXT":"Answer a fool according to his folly."},{"TXT":"Do not answer a fool according to his folly."}],"e12.example.com":[{"SPF":"v=spf1 exp= -all"}],"e13.example.com":[{"SPF":"v=spf1 exp=e13msg.example.com -all"}],"e13msg.example.com":[{"TXT":"The %{x}-files."}],"e14.example.com":[{"SPF":"v=spf1 exp=e13msg.example.com -all exp=e11msg.example.com"}],"e15.example.com":[{"SPF":"v=spf1 redirect=e12.example.com -all redirect=e12.example.com"}],"e16.example.com":[{"SPF":"v=spf1 exp=-all"}],"e17.example.com":[{"SPF":"v=spf1 redirect=-all ?all"}],"e18.example.com":[{"SPF":"v=spf1 ?all redirect="}],"e19.example.com":[{"SPF":"v=spf1 default=pass"}],"e20.example.com":[{"SPF":"v=spf1 default=+"}],"e21.example.com":[{"SPF":"v=spf1 exp=e21msg.example.com -all"}],"e21msg.example.com":["TIMEOUT"],"e22.example.com":[{"SPF":"v=spf1 exp=mail.example.com -all"}],"nonascii.example.com":[{"SPF":"v=spf1 exp=badexp.example.com -all"}],"badexp.example.com":[{"TXT":"ï»¿Explanation"}],"tworecs.example.com":[{"SPF":"v=spf1 exp=twoexp.example.com -all"}],"twoexp.example.com":[{"TXT":"one"},{"TXT":"two"}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.4');
        return promise.then((result) => {
          assert.equal(result, 'FAIL');
        });
      });
      it('unknown-modifier = name "=" macro-string name             = ALPHA *( ALPHA / DIGIT / "-" / "_" / "." )', function(){
        let email = 'foo@e5.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 exp=exp1.example.com redirect=e2.example.com"}],"e2.example.com":[{"SPF":"v=spf1 -all"}],"e3.example.com":[{"SPF":"v=spf1 exp=exp1.example.com redirect=e4.example.com"}],"e4.example.com":[{"SPF":"v=spf1 -all exp=exp2.example.com"}],"exp1.example.com":[{"TXT":"No-see-um"}],"exp2.example.com":[{"TXT":"See me."}],"exp3.example.com":[{"TXT":"Correct!"}],"exp4.example.com":[{"TXT":"%{l} in implementation"}],"e5.example.com":[{"SPF":"v=spf1 1up=foo"}],"e6.example.com":[{"SPF":"v=spf1 =all"}],"e7.example.com":[{"SPF":"v=spf1 include:e3.example.com -all exp=exp3.example.com"}],"e8.example.com":[{"SPF":"v=spf1 -all exp=exp4.example.com"}],"e9.example.com":[{"SPF":"v=spf1 -all foo=%abc"}],"e10.example.com":[{"SPF":"v=spf1 redirect=erehwon.example.com"}],"e11.example.com":[{"SPF":"v=spf1 -all exp=e11msg.example.com"}],"e11msg.example.com":[{"TXT":"Answer a fool according to his folly."},{"TXT":"Do not answer a fool according to his folly."}],"e12.example.com":[{"SPF":"v=spf1 exp= -all"}],"e13.example.com":[{"SPF":"v=spf1 exp=e13msg.example.com -all"}],"e13msg.example.com":[{"TXT":"The %{x}-files."}],"e14.example.com":[{"SPF":"v=spf1 exp=e13msg.example.com -all exp=e11msg.example.com"}],"e15.example.com":[{"SPF":"v=spf1 redirect=e12.example.com -all redirect=e12.example.com"}],"e16.example.com":[{"SPF":"v=spf1 exp=-all"}],"e17.example.com":[{"SPF":"v=spf1 redirect=-all ?all"}],"e18.example.com":[{"SPF":"v=spf1 ?all redirect="}],"e19.example.com":[{"SPF":"v=spf1 default=pass"}],"e20.example.com":[{"SPF":"v=spf1 default=+"}],"e21.example.com":[{"SPF":"v=spf1 exp=e21msg.example.com -all"}],"e21msg.example.com":["TIMEOUT"],"e22.example.com":[{"SPF":"v=spf1 exp=mail.example.com -all"}],"nonascii.example.com":[{"SPF":"v=spf1 exp=badexp.example.com -all"}],"badexp.example.com":[{"TXT":"ï»¿Explanation"}],"tworecs.example.com":[{"SPF":"v=spf1 exp=twoexp.example.com -all"}],"twoexp.example.com":[{"TXT":"one"},{"TXT":"two"}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.4');
        return promise.then((result) => {
          assert.equal(result, 'PERMERROR');
        });
      });
      it('name             = ALPHA *( ALPHA / DIGIT / "-" / "_" / "." )', function(){
        let email = 'foo@e6.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 exp=exp1.example.com redirect=e2.example.com"}],"e2.example.com":[{"SPF":"v=spf1 -all"}],"e3.example.com":[{"SPF":"v=spf1 exp=exp1.example.com redirect=e4.example.com"}],"e4.example.com":[{"SPF":"v=spf1 -all exp=exp2.example.com"}],"exp1.example.com":[{"TXT":"No-see-um"}],"exp2.example.com":[{"TXT":"See me."}],"exp3.example.com":[{"TXT":"Correct!"}],"exp4.example.com":[{"TXT":"%{l} in implementation"}],"e5.example.com":[{"SPF":"v=spf1 1up=foo"}],"e6.example.com":[{"SPF":"v=spf1 =all"}],"e7.example.com":[{"SPF":"v=spf1 include:e3.example.com -all exp=exp3.example.com"}],"e8.example.com":[{"SPF":"v=spf1 -all exp=exp4.example.com"}],"e9.example.com":[{"SPF":"v=spf1 -all foo=%abc"}],"e10.example.com":[{"SPF":"v=spf1 redirect=erehwon.example.com"}],"e11.example.com":[{"SPF":"v=spf1 -all exp=e11msg.example.com"}],"e11msg.example.com":[{"TXT":"Answer a fool according to his folly."},{"TXT":"Do not answer a fool according to his folly."}],"e12.example.com":[{"SPF":"v=spf1 exp= -all"}],"e13.example.com":[{"SPF":"v=spf1 exp=e13msg.example.com -all"}],"e13msg.example.com":[{"TXT":"The %{x}-files."}],"e14.example.com":[{"SPF":"v=spf1 exp=e13msg.example.com -all exp=e11msg.example.com"}],"e15.example.com":[{"SPF":"v=spf1 redirect=e12.example.com -all redirect=e12.example.com"}],"e16.example.com":[{"SPF":"v=spf1 exp=-all"}],"e17.example.com":[{"SPF":"v=spf1 redirect=-all ?all"}],"e18.example.com":[{"SPF":"v=spf1 ?all redirect="}],"e19.example.com":[{"SPF":"v=spf1 default=pass"}],"e20.example.com":[{"SPF":"v=spf1 default=+"}],"e21.example.com":[{"SPF":"v=spf1 exp=e21msg.example.com -all"}],"e21msg.example.com":["TIMEOUT"],"e22.example.com":[{"SPF":"v=spf1 exp=mail.example.com -all"}],"nonascii.example.com":[{"SPF":"v=spf1 exp=badexp.example.com -all"}],"badexp.example.com":[{"TXT":"ï»¿Explanation"}],"tworecs.example.com":[{"SPF":"v=spf1 exp=twoexp.example.com -all"}],"twoexp.example.com":[{"TXT":"one"},{"TXT":"two"}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.4');
        return promise.then((result) => {
          assert.equal(result, 'PERMERROR');
        });
      });
      it('An implementation that uses a legal expansion as a sentinel.  We cannot check them all, but we can check this one.', function(){
        let email = 'Macro Error@e8.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 exp=exp1.example.com redirect=e2.example.com"}],"e2.example.com":[{"SPF":"v=spf1 -all"}],"e3.example.com":[{"SPF":"v=spf1 exp=exp1.example.com redirect=e4.example.com"}],"e4.example.com":[{"SPF":"v=spf1 -all exp=exp2.example.com"}],"exp1.example.com":[{"TXT":"No-see-um"}],"exp2.example.com":[{"TXT":"See me."}],"exp3.example.com":[{"TXT":"Correct!"}],"exp4.example.com":[{"TXT":"%{l} in implementation"}],"e5.example.com":[{"SPF":"v=spf1 1up=foo"}],"e6.example.com":[{"SPF":"v=spf1 =all"}],"e7.example.com":[{"SPF":"v=spf1 include:e3.example.com -all exp=exp3.example.com"}],"e8.example.com":[{"SPF":"v=spf1 -all exp=exp4.example.com"}],"e9.example.com":[{"SPF":"v=spf1 -all foo=%abc"}],"e10.example.com":[{"SPF":"v=spf1 redirect=erehwon.example.com"}],"e11.example.com":[{"SPF":"v=spf1 -all exp=e11msg.example.com"}],"e11msg.example.com":[{"TXT":"Answer a fool according to his folly."},{"TXT":"Do not answer a fool according to his folly."}],"e12.example.com":[{"SPF":"v=spf1 exp= -all"}],"e13.example.com":[{"SPF":"v=spf1 exp=e13msg.example.com -all"}],"e13msg.example.com":[{"TXT":"The %{x}-files."}],"e14.example.com":[{"SPF":"v=spf1 exp=e13msg.example.com -all exp=e11msg.example.com"}],"e15.example.com":[{"SPF":"v=spf1 redirect=e12.example.com -all redirect=e12.example.com"}],"e16.example.com":[{"SPF":"v=spf1 exp=-all"}],"e17.example.com":[{"SPF":"v=spf1 redirect=-all ?all"}],"e18.example.com":[{"SPF":"v=spf1 ?all redirect="}],"e19.example.com":[{"SPF":"v=spf1 default=pass"}],"e20.example.com":[{"SPF":"v=spf1 default=+"}],"e21.example.com":[{"SPF":"v=spf1 exp=e21msg.example.com -all"}],"e21msg.example.com":["TIMEOUT"],"e22.example.com":[{"SPF":"v=spf1 exp=mail.example.com -all"}],"nonascii.example.com":[{"SPF":"v=spf1 exp=badexp.example.com -all"}],"badexp.example.com":[{"TXT":"ï»¿Explanation"}],"tworecs.example.com":[{"SPF":"v=spf1 exp=twoexp.example.com -all"}],"twoexp.example.com":[{"TXT":"one"},{"TXT":"two"}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.4');
        return promise.then((result) => {
          assert.equal(result, 'FAIL');
        });
      });
      it('Ignore exp if multiple TXT records.', function(){
        let email = 'foo@e11.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 exp=exp1.example.com redirect=e2.example.com"}],"e2.example.com":[{"SPF":"v=spf1 -all"}],"e3.example.com":[{"SPF":"v=spf1 exp=exp1.example.com redirect=e4.example.com"}],"e4.example.com":[{"SPF":"v=spf1 -all exp=exp2.example.com"}],"exp1.example.com":[{"TXT":"No-see-um"}],"exp2.example.com":[{"TXT":"See me."}],"exp3.example.com":[{"TXT":"Correct!"}],"exp4.example.com":[{"TXT":"%{l} in implementation"}],"e5.example.com":[{"SPF":"v=spf1 1up=foo"}],"e6.example.com":[{"SPF":"v=spf1 =all"}],"e7.example.com":[{"SPF":"v=spf1 include:e3.example.com -all exp=exp3.example.com"}],"e8.example.com":[{"SPF":"v=spf1 -all exp=exp4.example.com"}],"e9.example.com":[{"SPF":"v=spf1 -all foo=%abc"}],"e10.example.com":[{"SPF":"v=spf1 redirect=erehwon.example.com"}],"e11.example.com":[{"SPF":"v=spf1 -all exp=e11msg.example.com"}],"e11msg.example.com":[{"TXT":"Answer a fool according to his folly."},{"TXT":"Do not answer a fool according to his folly."}],"e12.example.com":[{"SPF":"v=spf1 exp= -all"}],"e13.example.com":[{"SPF":"v=spf1 exp=e13msg.example.com -all"}],"e13msg.example.com":[{"TXT":"The %{x}-files."}],"e14.example.com":[{"SPF":"v=spf1 exp=e13msg.example.com -all exp=e11msg.example.com"}],"e15.example.com":[{"SPF":"v=spf1 redirect=e12.example.com -all redirect=e12.example.com"}],"e16.example.com":[{"SPF":"v=spf1 exp=-all"}],"e17.example.com":[{"SPF":"v=spf1 redirect=-all ?all"}],"e18.example.com":[{"SPF":"v=spf1 ?all redirect="}],"e19.example.com":[{"SPF":"v=spf1 default=pass"}],"e20.example.com":[{"SPF":"v=spf1 default=+"}],"e21.example.com":[{"SPF":"v=spf1 exp=e21msg.example.com -all"}],"e21msg.example.com":["TIMEOUT"],"e22.example.com":[{"SPF":"v=spf1 exp=mail.example.com -all"}],"nonascii.example.com":[{"SPF":"v=spf1 exp=badexp.example.com -all"}],"badexp.example.com":[{"TXT":"ï»¿Explanation"}],"tworecs.example.com":[{"SPF":"v=spf1 exp=twoexp.example.com -all"}],"twoexp.example.com":[{"TXT":"one"},{"TXT":"two"}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.4');
        return promise.then((result) => {
          assert.equal(result, 'FAIL');
        });
      });
      it('Ignore exp if no TXT records.', function(){
        let email = 'foo@e22.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 exp=exp1.example.com redirect=e2.example.com"}],"e2.example.com":[{"SPF":"v=spf1 -all"}],"e3.example.com":[{"SPF":"v=spf1 exp=exp1.example.com redirect=e4.example.com"}],"e4.example.com":[{"SPF":"v=spf1 -all exp=exp2.example.com"}],"exp1.example.com":[{"TXT":"No-see-um"}],"exp2.example.com":[{"TXT":"See me."}],"exp3.example.com":[{"TXT":"Correct!"}],"exp4.example.com":[{"TXT":"%{l} in implementation"}],"e5.example.com":[{"SPF":"v=spf1 1up=foo"}],"e6.example.com":[{"SPF":"v=spf1 =all"}],"e7.example.com":[{"SPF":"v=spf1 include:e3.example.com -all exp=exp3.example.com"}],"e8.example.com":[{"SPF":"v=spf1 -all exp=exp4.example.com"}],"e9.example.com":[{"SPF":"v=spf1 -all foo=%abc"}],"e10.example.com":[{"SPF":"v=spf1 redirect=erehwon.example.com"}],"e11.example.com":[{"SPF":"v=spf1 -all exp=e11msg.example.com"}],"e11msg.example.com":[{"TXT":"Answer a fool according to his folly."},{"TXT":"Do not answer a fool according to his folly."}],"e12.example.com":[{"SPF":"v=spf1 exp= -all"}],"e13.example.com":[{"SPF":"v=spf1 exp=e13msg.example.com -all"}],"e13msg.example.com":[{"TXT":"The %{x}-files."}],"e14.example.com":[{"SPF":"v=spf1 exp=e13msg.example.com -all exp=e11msg.example.com"}],"e15.example.com":[{"SPF":"v=spf1 redirect=e12.example.com -all redirect=e12.example.com"}],"e16.example.com":[{"SPF":"v=spf1 exp=-all"}],"e17.example.com":[{"SPF":"v=spf1 redirect=-all ?all"}],"e18.example.com":[{"SPF":"v=spf1 ?all redirect="}],"e19.example.com":[{"SPF":"v=spf1 default=pass"}],"e20.example.com":[{"SPF":"v=spf1 default=+"}],"e21.example.com":[{"SPF":"v=spf1 exp=e21msg.example.com -all"}],"e21msg.example.com":["TIMEOUT"],"e22.example.com":[{"SPF":"v=spf1 exp=mail.example.com -all"}],"nonascii.example.com":[{"SPF":"v=spf1 exp=badexp.example.com -all"}],"badexp.example.com":[{"TXT":"ï»¿Explanation"}],"tworecs.example.com":[{"SPF":"v=spf1 exp=twoexp.example.com -all"}],"twoexp.example.com":[{"TXT":"one"},{"TXT":"two"}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.4');
        return promise.then((result) => {
          assert.equal(result, 'FAIL');
        });
      });
      it('Ignore exp if DNS error.', function(){
        let email = 'foo@e21.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 exp=exp1.example.com redirect=e2.example.com"}],"e2.example.com":[{"SPF":"v=spf1 -all"}],"e3.example.com":[{"SPF":"v=spf1 exp=exp1.example.com redirect=e4.example.com"}],"e4.example.com":[{"SPF":"v=spf1 -all exp=exp2.example.com"}],"exp1.example.com":[{"TXT":"No-see-um"}],"exp2.example.com":[{"TXT":"See me."}],"exp3.example.com":[{"TXT":"Correct!"}],"exp4.example.com":[{"TXT":"%{l} in implementation"}],"e5.example.com":[{"SPF":"v=spf1 1up=foo"}],"e6.example.com":[{"SPF":"v=spf1 =all"}],"e7.example.com":[{"SPF":"v=spf1 include:e3.example.com -all exp=exp3.example.com"}],"e8.example.com":[{"SPF":"v=spf1 -all exp=exp4.example.com"}],"e9.example.com":[{"SPF":"v=spf1 -all foo=%abc"}],"e10.example.com":[{"SPF":"v=spf1 redirect=erehwon.example.com"}],"e11.example.com":[{"SPF":"v=spf1 -all exp=e11msg.example.com"}],"e11msg.example.com":[{"TXT":"Answer a fool according to his folly."},{"TXT":"Do not answer a fool according to his folly."}],"e12.example.com":[{"SPF":"v=spf1 exp= -all"}],"e13.example.com":[{"SPF":"v=spf1 exp=e13msg.example.com -all"}],"e13msg.example.com":[{"TXT":"The %{x}-files."}],"e14.example.com":[{"SPF":"v=spf1 exp=e13msg.example.com -all exp=e11msg.example.com"}],"e15.example.com":[{"SPF":"v=spf1 redirect=e12.example.com -all redirect=e12.example.com"}],"e16.example.com":[{"SPF":"v=spf1 exp=-all"}],"e17.example.com":[{"SPF":"v=spf1 redirect=-all ?all"}],"e18.example.com":[{"SPF":"v=spf1 ?all redirect="}],"e19.example.com":[{"SPF":"v=spf1 default=pass"}],"e20.example.com":[{"SPF":"v=spf1 default=+"}],"e21.example.com":[{"SPF":"v=spf1 exp=e21msg.example.com -all"}],"e21msg.example.com":["TIMEOUT"],"e22.example.com":[{"SPF":"v=spf1 exp=mail.example.com -all"}],"nonascii.example.com":[{"SPF":"v=spf1 exp=badexp.example.com -all"}],"badexp.example.com":[{"TXT":"ï»¿Explanation"}],"tworecs.example.com":[{"SPF":"v=spf1 exp=twoexp.example.com -all"}],"twoexp.example.com":[{"TXT":"one"},{"TXT":"two"}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.4');
        return promise.then((result) => {
          assert.equal(result, 'FAIL');
        });
      });
      it('PermError if exp= domain-spec is empty.', function(){
        let email = 'foo@e12.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 exp=exp1.example.com redirect=e2.example.com"}],"e2.example.com":[{"SPF":"v=spf1 -all"}],"e3.example.com":[{"SPF":"v=spf1 exp=exp1.example.com redirect=e4.example.com"}],"e4.example.com":[{"SPF":"v=spf1 -all exp=exp2.example.com"}],"exp1.example.com":[{"TXT":"No-see-um"}],"exp2.example.com":[{"TXT":"See me."}],"exp3.example.com":[{"TXT":"Correct!"}],"exp4.example.com":[{"TXT":"%{l} in implementation"}],"e5.example.com":[{"SPF":"v=spf1 1up=foo"}],"e6.example.com":[{"SPF":"v=spf1 =all"}],"e7.example.com":[{"SPF":"v=spf1 include:e3.example.com -all exp=exp3.example.com"}],"e8.example.com":[{"SPF":"v=spf1 -all exp=exp4.example.com"}],"e9.example.com":[{"SPF":"v=spf1 -all foo=%abc"}],"e10.example.com":[{"SPF":"v=spf1 redirect=erehwon.example.com"}],"e11.example.com":[{"SPF":"v=spf1 -all exp=e11msg.example.com"}],"e11msg.example.com":[{"TXT":"Answer a fool according to his folly."},{"TXT":"Do not answer a fool according to his folly."}],"e12.example.com":[{"SPF":"v=spf1 exp= -all"}],"e13.example.com":[{"SPF":"v=spf1 exp=e13msg.example.com -all"}],"e13msg.example.com":[{"TXT":"The %{x}-files."}],"e14.example.com":[{"SPF":"v=spf1 exp=e13msg.example.com -all exp=e11msg.example.com"}],"e15.example.com":[{"SPF":"v=spf1 redirect=e12.example.com -all redirect=e12.example.com"}],"e16.example.com":[{"SPF":"v=spf1 exp=-all"}],"e17.example.com":[{"SPF":"v=spf1 redirect=-all ?all"}],"e18.example.com":[{"SPF":"v=spf1 ?all redirect="}],"e19.example.com":[{"SPF":"v=spf1 default=pass"}],"e20.example.com":[{"SPF":"v=spf1 default=+"}],"e21.example.com":[{"SPF":"v=spf1 exp=e21msg.example.com -all"}],"e21msg.example.com":["TIMEOUT"],"e22.example.com":[{"SPF":"v=spf1 exp=mail.example.com -all"}],"nonascii.example.com":[{"SPF":"v=spf1 exp=badexp.example.com -all"}],"badexp.example.com":[{"TXT":"ï»¿Explanation"}],"tworecs.example.com":[{"SPF":"v=spf1 exp=twoexp.example.com -all"}],"twoexp.example.com":[{"TXT":"one"},{"TXT":"two"}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.4');
        return promise.then((result) => {
          assert.equal(result, 'PERMERROR');
        });
      });
      it('Ignore exp if the explanation string has a syntax error.', function(){
        let email = 'foo@e13.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 exp=exp1.example.com redirect=e2.example.com"}],"e2.example.com":[{"SPF":"v=spf1 -all"}],"e3.example.com":[{"SPF":"v=spf1 exp=exp1.example.com redirect=e4.example.com"}],"e4.example.com":[{"SPF":"v=spf1 -all exp=exp2.example.com"}],"exp1.example.com":[{"TXT":"No-see-um"}],"exp2.example.com":[{"TXT":"See me."}],"exp3.example.com":[{"TXT":"Correct!"}],"exp4.example.com":[{"TXT":"%{l} in implementation"}],"e5.example.com":[{"SPF":"v=spf1 1up=foo"}],"e6.example.com":[{"SPF":"v=spf1 =all"}],"e7.example.com":[{"SPF":"v=spf1 include:e3.example.com -all exp=exp3.example.com"}],"e8.example.com":[{"SPF":"v=spf1 -all exp=exp4.example.com"}],"e9.example.com":[{"SPF":"v=spf1 -all foo=%abc"}],"e10.example.com":[{"SPF":"v=spf1 redirect=erehwon.example.com"}],"e11.example.com":[{"SPF":"v=spf1 -all exp=e11msg.example.com"}],"e11msg.example.com":[{"TXT":"Answer a fool according to his folly."},{"TXT":"Do not answer a fool according to his folly."}],"e12.example.com":[{"SPF":"v=spf1 exp= -all"}],"e13.example.com":[{"SPF":"v=spf1 exp=e13msg.example.com -all"}],"e13msg.example.com":[{"TXT":"The %{x}-files."}],"e14.example.com":[{"SPF":"v=spf1 exp=e13msg.example.com -all exp=e11msg.example.com"}],"e15.example.com":[{"SPF":"v=spf1 redirect=e12.example.com -all redirect=e12.example.com"}],"e16.example.com":[{"SPF":"v=spf1 exp=-all"}],"e17.example.com":[{"SPF":"v=spf1 redirect=-all ?all"}],"e18.example.com":[{"SPF":"v=spf1 ?all redirect="}],"e19.example.com":[{"SPF":"v=spf1 default=pass"}],"e20.example.com":[{"SPF":"v=spf1 default=+"}],"e21.example.com":[{"SPF":"v=spf1 exp=e21msg.example.com -all"}],"e21msg.example.com":["TIMEOUT"],"e22.example.com":[{"SPF":"v=spf1 exp=mail.example.com -all"}],"nonascii.example.com":[{"SPF":"v=spf1 exp=badexp.example.com -all"}],"badexp.example.com":[{"TXT":"ï»¿Explanation"}],"tworecs.example.com":[{"SPF":"v=spf1 exp=twoexp.example.com -all"}],"twoexp.example.com":[{"TXT":"one"},{"TXT":"two"}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.4');
        return promise.then((result) => {
          assert.equal(result, 'FAIL');
        });
      });
      it('explanation      = "exp" "=" domain-spec', function(){
        let email = 'foo@e16.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 exp=exp1.example.com redirect=e2.example.com"}],"e2.example.com":[{"SPF":"v=spf1 -all"}],"e3.example.com":[{"SPF":"v=spf1 exp=exp1.example.com redirect=e4.example.com"}],"e4.example.com":[{"SPF":"v=spf1 -all exp=exp2.example.com"}],"exp1.example.com":[{"TXT":"No-see-um"}],"exp2.example.com":[{"TXT":"See me."}],"exp3.example.com":[{"TXT":"Correct!"}],"exp4.example.com":[{"TXT":"%{l} in implementation"}],"e5.example.com":[{"SPF":"v=spf1 1up=foo"}],"e6.example.com":[{"SPF":"v=spf1 =all"}],"e7.example.com":[{"SPF":"v=spf1 include:e3.example.com -all exp=exp3.example.com"}],"e8.example.com":[{"SPF":"v=spf1 -all exp=exp4.example.com"}],"e9.example.com":[{"SPF":"v=spf1 -all foo=%abc"}],"e10.example.com":[{"SPF":"v=spf1 redirect=erehwon.example.com"}],"e11.example.com":[{"SPF":"v=spf1 -all exp=e11msg.example.com"}],"e11msg.example.com":[{"TXT":"Answer a fool according to his folly."},{"TXT":"Do not answer a fool according to his folly."}],"e12.example.com":[{"SPF":"v=spf1 exp= -all"}],"e13.example.com":[{"SPF":"v=spf1 exp=e13msg.example.com -all"}],"e13msg.example.com":[{"TXT":"The %{x}-files."}],"e14.example.com":[{"SPF":"v=spf1 exp=e13msg.example.com -all exp=e11msg.example.com"}],"e15.example.com":[{"SPF":"v=spf1 redirect=e12.example.com -all redirect=e12.example.com"}],"e16.example.com":[{"SPF":"v=spf1 exp=-all"}],"e17.example.com":[{"SPF":"v=spf1 redirect=-all ?all"}],"e18.example.com":[{"SPF":"v=spf1 ?all redirect="}],"e19.example.com":[{"SPF":"v=spf1 default=pass"}],"e20.example.com":[{"SPF":"v=spf1 default=+"}],"e21.example.com":[{"SPF":"v=spf1 exp=e21msg.example.com -all"}],"e21msg.example.com":["TIMEOUT"],"e22.example.com":[{"SPF":"v=spf1 exp=mail.example.com -all"}],"nonascii.example.com":[{"SPF":"v=spf1 exp=badexp.example.com -all"}],"badexp.example.com":[{"TXT":"ï»¿Explanation"}],"tworecs.example.com":[{"SPF":"v=spf1 exp=twoexp.example.com -all"}],"twoexp.example.com":[{"TXT":"one"},{"TXT":"two"}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.4');
        return promise.then((result) => {
          assert.equal(result, 'PERMERROR');
        });
      });
      it('exp= appears twice.', function(){
        let email = 'foo@e14.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 exp=exp1.example.com redirect=e2.example.com"}],"e2.example.com":[{"SPF":"v=spf1 -all"}],"e3.example.com":[{"SPF":"v=spf1 exp=exp1.example.com redirect=e4.example.com"}],"e4.example.com":[{"SPF":"v=spf1 -all exp=exp2.example.com"}],"exp1.example.com":[{"TXT":"No-see-um"}],"exp2.example.com":[{"TXT":"See me."}],"exp3.example.com":[{"TXT":"Correct!"}],"exp4.example.com":[{"TXT":"%{l} in implementation"}],"e5.example.com":[{"SPF":"v=spf1 1up=foo"}],"e6.example.com":[{"SPF":"v=spf1 =all"}],"e7.example.com":[{"SPF":"v=spf1 include:e3.example.com -all exp=exp3.example.com"}],"e8.example.com":[{"SPF":"v=spf1 -all exp=exp4.example.com"}],"e9.example.com":[{"SPF":"v=spf1 -all foo=%abc"}],"e10.example.com":[{"SPF":"v=spf1 redirect=erehwon.example.com"}],"e11.example.com":[{"SPF":"v=spf1 -all exp=e11msg.example.com"}],"e11msg.example.com":[{"TXT":"Answer a fool according to his folly."},{"TXT":"Do not answer a fool according to his folly."}],"e12.example.com":[{"SPF":"v=spf1 exp= -all"}],"e13.example.com":[{"SPF":"v=spf1 exp=e13msg.example.com -all"}],"e13msg.example.com":[{"TXT":"The %{x}-files."}],"e14.example.com":[{"SPF":"v=spf1 exp=e13msg.example.com -all exp=e11msg.example.com"}],"e15.example.com":[{"SPF":"v=spf1 redirect=e12.example.com -all redirect=e12.example.com"}],"e16.example.com":[{"SPF":"v=spf1 exp=-all"}],"e17.example.com":[{"SPF":"v=spf1 redirect=-all ?all"}],"e18.example.com":[{"SPF":"v=spf1 ?all redirect="}],"e19.example.com":[{"SPF":"v=spf1 default=pass"}],"e20.example.com":[{"SPF":"v=spf1 default=+"}],"e21.example.com":[{"SPF":"v=spf1 exp=e21msg.example.com -all"}],"e21msg.example.com":["TIMEOUT"],"e22.example.com":[{"SPF":"v=spf1 exp=mail.example.com -all"}],"nonascii.example.com":[{"SPF":"v=spf1 exp=badexp.example.com -all"}],"badexp.example.com":[{"TXT":"ï»¿Explanation"}],"tworecs.example.com":[{"SPF":"v=spf1 exp=twoexp.example.com -all"}],"twoexp.example.com":[{"TXT":"one"},{"TXT":"two"}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.4');
        return promise.then((result) => {
          assert.equal(result, 'PERMERROR');
        });
      });
      it('redirect = "redirect" "=" domain-spec', function(){
        let email = 'foo@e18.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 exp=exp1.example.com redirect=e2.example.com"}],"e2.example.com":[{"SPF":"v=spf1 -all"}],"e3.example.com":[{"SPF":"v=spf1 exp=exp1.example.com redirect=e4.example.com"}],"e4.example.com":[{"SPF":"v=spf1 -all exp=exp2.example.com"}],"exp1.example.com":[{"TXT":"No-see-um"}],"exp2.example.com":[{"TXT":"See me."}],"exp3.example.com":[{"TXT":"Correct!"}],"exp4.example.com":[{"TXT":"%{l} in implementation"}],"e5.example.com":[{"SPF":"v=spf1 1up=foo"}],"e6.example.com":[{"SPF":"v=spf1 =all"}],"e7.example.com":[{"SPF":"v=spf1 include:e3.example.com -all exp=exp3.example.com"}],"e8.example.com":[{"SPF":"v=spf1 -all exp=exp4.example.com"}],"e9.example.com":[{"SPF":"v=spf1 -all foo=%abc"}],"e10.example.com":[{"SPF":"v=spf1 redirect=erehwon.example.com"}],"e11.example.com":[{"SPF":"v=spf1 -all exp=e11msg.example.com"}],"e11msg.example.com":[{"TXT":"Answer a fool according to his folly."},{"TXT":"Do not answer a fool according to his folly."}],"e12.example.com":[{"SPF":"v=spf1 exp= -all"}],"e13.example.com":[{"SPF":"v=spf1 exp=e13msg.example.com -all"}],"e13msg.example.com":[{"TXT":"The %{x}-files."}],"e14.example.com":[{"SPF":"v=spf1 exp=e13msg.example.com -all exp=e11msg.example.com"}],"e15.example.com":[{"SPF":"v=spf1 redirect=e12.example.com -all redirect=e12.example.com"}],"e16.example.com":[{"SPF":"v=spf1 exp=-all"}],"e17.example.com":[{"SPF":"v=spf1 redirect=-all ?all"}],"e18.example.com":[{"SPF":"v=spf1 ?all redirect="}],"e19.example.com":[{"SPF":"v=spf1 default=pass"}],"e20.example.com":[{"SPF":"v=spf1 default=+"}],"e21.example.com":[{"SPF":"v=spf1 exp=e21msg.example.com -all"}],"e21msg.example.com":["TIMEOUT"],"e22.example.com":[{"SPF":"v=spf1 exp=mail.example.com -all"}],"nonascii.example.com":[{"SPF":"v=spf1 exp=badexp.example.com -all"}],"badexp.example.com":[{"TXT":"ï»¿Explanation"}],"tworecs.example.com":[{"SPF":"v=spf1 exp=twoexp.example.com -all"}],"twoexp.example.com":[{"TXT":"one"},{"TXT":"two"}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.4');
        return promise.then((result) => {
          assert.equal(result, 'PERMERROR');
        });
      });
      it('redirect= appears twice.', function(){
        let email = 'foo@e15.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 exp=exp1.example.com redirect=e2.example.com"}],"e2.example.com":[{"SPF":"v=spf1 -all"}],"e3.example.com":[{"SPF":"v=spf1 exp=exp1.example.com redirect=e4.example.com"}],"e4.example.com":[{"SPF":"v=spf1 -all exp=exp2.example.com"}],"exp1.example.com":[{"TXT":"No-see-um"}],"exp2.example.com":[{"TXT":"See me."}],"exp3.example.com":[{"TXT":"Correct!"}],"exp4.example.com":[{"TXT":"%{l} in implementation"}],"e5.example.com":[{"SPF":"v=spf1 1up=foo"}],"e6.example.com":[{"SPF":"v=spf1 =all"}],"e7.example.com":[{"SPF":"v=spf1 include:e3.example.com -all exp=exp3.example.com"}],"e8.example.com":[{"SPF":"v=spf1 -all exp=exp4.example.com"}],"e9.example.com":[{"SPF":"v=spf1 -all foo=%abc"}],"e10.example.com":[{"SPF":"v=spf1 redirect=erehwon.example.com"}],"e11.example.com":[{"SPF":"v=spf1 -all exp=e11msg.example.com"}],"e11msg.example.com":[{"TXT":"Answer a fool according to his folly."},{"TXT":"Do not answer a fool according to his folly."}],"e12.example.com":[{"SPF":"v=spf1 exp= -all"}],"e13.example.com":[{"SPF":"v=spf1 exp=e13msg.example.com -all"}],"e13msg.example.com":[{"TXT":"The %{x}-files."}],"e14.example.com":[{"SPF":"v=spf1 exp=e13msg.example.com -all exp=e11msg.example.com"}],"e15.example.com":[{"SPF":"v=spf1 redirect=e12.example.com -all redirect=e12.example.com"}],"e16.example.com":[{"SPF":"v=spf1 exp=-all"}],"e17.example.com":[{"SPF":"v=spf1 redirect=-all ?all"}],"e18.example.com":[{"SPF":"v=spf1 ?all redirect="}],"e19.example.com":[{"SPF":"v=spf1 default=pass"}],"e20.example.com":[{"SPF":"v=spf1 default=+"}],"e21.example.com":[{"SPF":"v=spf1 exp=e21msg.example.com -all"}],"e21msg.example.com":["TIMEOUT"],"e22.example.com":[{"SPF":"v=spf1 exp=mail.example.com -all"}],"nonascii.example.com":[{"SPF":"v=spf1 exp=badexp.example.com -all"}],"badexp.example.com":[{"TXT":"ï»¿Explanation"}],"tworecs.example.com":[{"SPF":"v=spf1 exp=twoexp.example.com -all"}],"twoexp.example.com":[{"TXT":"one"},{"TXT":"two"}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.4');
        return promise.then((result) => {
          assert.equal(result, 'PERMERROR');
        });
      });
      it('unknown-modifier = name "=" macro-string', function(){
        let email = 'foo@e9.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 exp=exp1.example.com redirect=e2.example.com"}],"e2.example.com":[{"SPF":"v=spf1 -all"}],"e3.example.com":[{"SPF":"v=spf1 exp=exp1.example.com redirect=e4.example.com"}],"e4.example.com":[{"SPF":"v=spf1 -all exp=exp2.example.com"}],"exp1.example.com":[{"TXT":"No-see-um"}],"exp2.example.com":[{"TXT":"See me."}],"exp3.example.com":[{"TXT":"Correct!"}],"exp4.example.com":[{"TXT":"%{l} in implementation"}],"e5.example.com":[{"SPF":"v=spf1 1up=foo"}],"e6.example.com":[{"SPF":"v=spf1 =all"}],"e7.example.com":[{"SPF":"v=spf1 include:e3.example.com -all exp=exp3.example.com"}],"e8.example.com":[{"SPF":"v=spf1 -all exp=exp4.example.com"}],"e9.example.com":[{"SPF":"v=spf1 -all foo=%abc"}],"e10.example.com":[{"SPF":"v=spf1 redirect=erehwon.example.com"}],"e11.example.com":[{"SPF":"v=spf1 -all exp=e11msg.example.com"}],"e11msg.example.com":[{"TXT":"Answer a fool according to his folly."},{"TXT":"Do not answer a fool according to his folly."}],"e12.example.com":[{"SPF":"v=spf1 exp= -all"}],"e13.example.com":[{"SPF":"v=spf1 exp=e13msg.example.com -all"}],"e13msg.example.com":[{"TXT":"The %{x}-files."}],"e14.example.com":[{"SPF":"v=spf1 exp=e13msg.example.com -all exp=e11msg.example.com"}],"e15.example.com":[{"SPF":"v=spf1 redirect=e12.example.com -all redirect=e12.example.com"}],"e16.example.com":[{"SPF":"v=spf1 exp=-all"}],"e17.example.com":[{"SPF":"v=spf1 redirect=-all ?all"}],"e18.example.com":[{"SPF":"v=spf1 ?all redirect="}],"e19.example.com":[{"SPF":"v=spf1 default=pass"}],"e20.example.com":[{"SPF":"v=spf1 default=+"}],"e21.example.com":[{"SPF":"v=spf1 exp=e21msg.example.com -all"}],"e21msg.example.com":["TIMEOUT"],"e22.example.com":[{"SPF":"v=spf1 exp=mail.example.com -all"}],"nonascii.example.com":[{"SPF":"v=spf1 exp=badexp.example.com -all"}],"badexp.example.com":[{"TXT":"ï»¿Explanation"}],"tworecs.example.com":[{"SPF":"v=spf1 exp=twoexp.example.com -all"}],"twoexp.example.com":[{"TXT":"one"},{"TXT":"two"}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.4');
        return promise.then((result) => {
          assert.equal(result, 'PERMERROR');
        });
      });
      it('Unknown modifiers do not modify the RFC SPF result.', function(){
        let email = 'foo@e19.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 exp=exp1.example.com redirect=e2.example.com"}],"e2.example.com":[{"SPF":"v=spf1 -all"}],"e3.example.com":[{"SPF":"v=spf1 exp=exp1.example.com redirect=e4.example.com"}],"e4.example.com":[{"SPF":"v=spf1 -all exp=exp2.example.com"}],"exp1.example.com":[{"TXT":"No-see-um"}],"exp2.example.com":[{"TXT":"See me."}],"exp3.example.com":[{"TXT":"Correct!"}],"exp4.example.com":[{"TXT":"%{l} in implementation"}],"e5.example.com":[{"SPF":"v=spf1 1up=foo"}],"e6.example.com":[{"SPF":"v=spf1 =all"}],"e7.example.com":[{"SPF":"v=spf1 include:e3.example.com -all exp=exp3.example.com"}],"e8.example.com":[{"SPF":"v=spf1 -all exp=exp4.example.com"}],"e9.example.com":[{"SPF":"v=spf1 -all foo=%abc"}],"e10.example.com":[{"SPF":"v=spf1 redirect=erehwon.example.com"}],"e11.example.com":[{"SPF":"v=spf1 -all exp=e11msg.example.com"}],"e11msg.example.com":[{"TXT":"Answer a fool according to his folly."},{"TXT":"Do not answer a fool according to his folly."}],"e12.example.com":[{"SPF":"v=spf1 exp= -all"}],"e13.example.com":[{"SPF":"v=spf1 exp=e13msg.example.com -all"}],"e13msg.example.com":[{"TXT":"The %{x}-files."}],"e14.example.com":[{"SPF":"v=spf1 exp=e13msg.example.com -all exp=e11msg.example.com"}],"e15.example.com":[{"SPF":"v=spf1 redirect=e12.example.com -all redirect=e12.example.com"}],"e16.example.com":[{"SPF":"v=spf1 exp=-all"}],"e17.example.com":[{"SPF":"v=spf1 redirect=-all ?all"}],"e18.example.com":[{"SPF":"v=spf1 ?all redirect="}],"e19.example.com":[{"SPF":"v=spf1 default=pass"}],"e20.example.com":[{"SPF":"v=spf1 default=+"}],"e21.example.com":[{"SPF":"v=spf1 exp=e21msg.example.com -all"}],"e21msg.example.com":["TIMEOUT"],"e22.example.com":[{"SPF":"v=spf1 exp=mail.example.com -all"}],"nonascii.example.com":[{"SPF":"v=spf1 exp=badexp.example.com -all"}],"badexp.example.com":[{"TXT":"ï»¿Explanation"}],"tworecs.example.com":[{"SPF":"v=spf1 exp=twoexp.example.com -all"}],"twoexp.example.com":[{"TXT":"one"},{"TXT":"two"}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.4');
        return promise.then((result) => {
          assert.equal(result, 'NEUTRAL');
        });
      });
      it('Unknown modifiers do not modify the RFC SPF result.', function(){
        let email = 'foo@e20.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 exp=exp1.example.com redirect=e2.example.com"}],"e2.example.com":[{"SPF":"v=spf1 -all"}],"e3.example.com":[{"SPF":"v=spf1 exp=exp1.example.com redirect=e4.example.com"}],"e4.example.com":[{"SPF":"v=spf1 -all exp=exp2.example.com"}],"exp1.example.com":[{"TXT":"No-see-um"}],"exp2.example.com":[{"TXT":"See me."}],"exp3.example.com":[{"TXT":"Correct!"}],"exp4.example.com":[{"TXT":"%{l} in implementation"}],"e5.example.com":[{"SPF":"v=spf1 1up=foo"}],"e6.example.com":[{"SPF":"v=spf1 =all"}],"e7.example.com":[{"SPF":"v=spf1 include:e3.example.com -all exp=exp3.example.com"}],"e8.example.com":[{"SPF":"v=spf1 -all exp=exp4.example.com"}],"e9.example.com":[{"SPF":"v=spf1 -all foo=%abc"}],"e10.example.com":[{"SPF":"v=spf1 redirect=erehwon.example.com"}],"e11.example.com":[{"SPF":"v=spf1 -all exp=e11msg.example.com"}],"e11msg.example.com":[{"TXT":"Answer a fool according to his folly."},{"TXT":"Do not answer a fool according to his folly."}],"e12.example.com":[{"SPF":"v=spf1 exp= -all"}],"e13.example.com":[{"SPF":"v=spf1 exp=e13msg.example.com -all"}],"e13msg.example.com":[{"TXT":"The %{x}-files."}],"e14.example.com":[{"SPF":"v=spf1 exp=e13msg.example.com -all exp=e11msg.example.com"}],"e15.example.com":[{"SPF":"v=spf1 redirect=e12.example.com -all redirect=e12.example.com"}],"e16.example.com":[{"SPF":"v=spf1 exp=-all"}],"e17.example.com":[{"SPF":"v=spf1 redirect=-all ?all"}],"e18.example.com":[{"SPF":"v=spf1 ?all redirect="}],"e19.example.com":[{"SPF":"v=spf1 default=pass"}],"e20.example.com":[{"SPF":"v=spf1 default=+"}],"e21.example.com":[{"SPF":"v=spf1 exp=e21msg.example.com -all"}],"e21msg.example.com":["TIMEOUT"],"e22.example.com":[{"SPF":"v=spf1 exp=mail.example.com -all"}],"nonascii.example.com":[{"SPF":"v=spf1 exp=badexp.example.com -all"}],"badexp.example.com":[{"TXT":"ï»¿Explanation"}],"tworecs.example.com":[{"SPF":"v=spf1 exp=twoexp.example.com -all"}],"twoexp.example.com":[{"TXT":"one"},{"TXT":"two"}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.4');
        return promise.then((result) => {
          assert.equal(result, 'NEUTRAL');
        });
      });
      it('SPF explanation text is restricted to 7-bit ascii.', function(){
        let email = 'foobar@nonascii.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 exp=exp1.example.com redirect=e2.example.com"}],"e2.example.com":[{"SPF":"v=spf1 -all"}],"e3.example.com":[{"SPF":"v=spf1 exp=exp1.example.com redirect=e4.example.com"}],"e4.example.com":[{"SPF":"v=spf1 -all exp=exp2.example.com"}],"exp1.example.com":[{"TXT":"No-see-um"}],"exp2.example.com":[{"TXT":"See me."}],"exp3.example.com":[{"TXT":"Correct!"}],"exp4.example.com":[{"TXT":"%{l} in implementation"}],"e5.example.com":[{"SPF":"v=spf1 1up=foo"}],"e6.example.com":[{"SPF":"v=spf1 =all"}],"e7.example.com":[{"SPF":"v=spf1 include:e3.example.com -all exp=exp3.example.com"}],"e8.example.com":[{"SPF":"v=spf1 -all exp=exp4.example.com"}],"e9.example.com":[{"SPF":"v=spf1 -all foo=%abc"}],"e10.example.com":[{"SPF":"v=spf1 redirect=erehwon.example.com"}],"e11.example.com":[{"SPF":"v=spf1 -all exp=e11msg.example.com"}],"e11msg.example.com":[{"TXT":"Answer a fool according to his folly."},{"TXT":"Do not answer a fool according to his folly."}],"e12.example.com":[{"SPF":"v=spf1 exp= -all"}],"e13.example.com":[{"SPF":"v=spf1 exp=e13msg.example.com -all"}],"e13msg.example.com":[{"TXT":"The %{x}-files."}],"e14.example.com":[{"SPF":"v=spf1 exp=e13msg.example.com -all exp=e11msg.example.com"}],"e15.example.com":[{"SPF":"v=spf1 redirect=e12.example.com -all redirect=e12.example.com"}],"e16.example.com":[{"SPF":"v=spf1 exp=-all"}],"e17.example.com":[{"SPF":"v=spf1 redirect=-all ?all"}],"e18.example.com":[{"SPF":"v=spf1 ?all redirect="}],"e19.example.com":[{"SPF":"v=spf1 default=pass"}],"e20.example.com":[{"SPF":"v=spf1 default=+"}],"e21.example.com":[{"SPF":"v=spf1 exp=e21msg.example.com -all"}],"e21msg.example.com":["TIMEOUT"],"e22.example.com":[{"SPF":"v=spf1 exp=mail.example.com -all"}],"nonascii.example.com":[{"SPF":"v=spf1 exp=badexp.example.com -all"}],"badexp.example.com":[{"TXT":"ï»¿Explanation"}],"tworecs.example.com":[{"SPF":"v=spf1 exp=twoexp.example.com -all"}],"twoexp.example.com":[{"TXT":"one"},{"TXT":"two"}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.4');
        return promise.then((result) => {
          assert.equal(result, 'FAIL');
        });
      });
      it('Must ignore exp= if DNS returns more than one TXT record.', function(){
        let email = 'foobar@tworecs.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 exp=exp1.example.com redirect=e2.example.com"}],"e2.example.com":[{"SPF":"v=spf1 -all"}],"e3.example.com":[{"SPF":"v=spf1 exp=exp1.example.com redirect=e4.example.com"}],"e4.example.com":[{"SPF":"v=spf1 -all exp=exp2.example.com"}],"exp1.example.com":[{"TXT":"No-see-um"}],"exp2.example.com":[{"TXT":"See me."}],"exp3.example.com":[{"TXT":"Correct!"}],"exp4.example.com":[{"TXT":"%{l} in implementation"}],"e5.example.com":[{"SPF":"v=spf1 1up=foo"}],"e6.example.com":[{"SPF":"v=spf1 =all"}],"e7.example.com":[{"SPF":"v=spf1 include:e3.example.com -all exp=exp3.example.com"}],"e8.example.com":[{"SPF":"v=spf1 -all exp=exp4.example.com"}],"e9.example.com":[{"SPF":"v=spf1 -all foo=%abc"}],"e10.example.com":[{"SPF":"v=spf1 redirect=erehwon.example.com"}],"e11.example.com":[{"SPF":"v=spf1 -all exp=e11msg.example.com"}],"e11msg.example.com":[{"TXT":"Answer a fool according to his folly."},{"TXT":"Do not answer a fool according to his folly."}],"e12.example.com":[{"SPF":"v=spf1 exp= -all"}],"e13.example.com":[{"SPF":"v=spf1 exp=e13msg.example.com -all"}],"e13msg.example.com":[{"TXT":"The %{x}-files."}],"e14.example.com":[{"SPF":"v=spf1 exp=e13msg.example.com -all exp=e11msg.example.com"}],"e15.example.com":[{"SPF":"v=spf1 redirect=e12.example.com -all redirect=e12.example.com"}],"e16.example.com":[{"SPF":"v=spf1 exp=-all"}],"e17.example.com":[{"SPF":"v=spf1 redirect=-all ?all"}],"e18.example.com":[{"SPF":"v=spf1 ?all redirect="}],"e19.example.com":[{"SPF":"v=spf1 default=pass"}],"e20.example.com":[{"SPF":"v=spf1 default=+"}],"e21.example.com":[{"SPF":"v=spf1 exp=e21msg.example.com -all"}],"e21msg.example.com":["TIMEOUT"],"e22.example.com":[{"SPF":"v=spf1 exp=mail.example.com -all"}],"nonascii.example.com":[{"SPF":"v=spf1 exp=badexp.example.com -all"}],"badexp.example.com":[{"TXT":"ï»¿Explanation"}],"tworecs.example.com":[{"SPF":"v=spf1 exp=twoexp.example.com -all"}],"twoexp.example.com":[{"TXT":"one"},{"TXT":"two"}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.4');
        return promise.then((result) => {
          assert.equal(result, 'FAIL');
        });
      });
    });
    describe('Macro expansion rules', function(){
      it('trailing dot is ignored for domains', function(){
        let email = 'test@example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"example.com.d.spf.example.com":[{"SPF":"v=spf1 redirect=a.spf.example.com"}],"a.spf.example.com":[{"SPF":"v=spf1 include:o.spf.example.com. ~all"}],"o.spf.example.com":[{"SPF":"v=spf1 ip4:192.168.218.40"}],"msgbas2x.cos.example.com":[{"A":"192.168.218.40"}],"example.com":[{"A":"192.168.90.76"},{"SPF":"v=spf1 redirect=%{d}.d.spf.example.com."}],"exp.example.com":[{"SPF":"v=spf1 exp=msg.example.com. -all"}],"msg.example.com":[{"TXT":"This is a test."}],"e1.example.com":[{"SPF":"v=spf1 -exists:%(ir).sbl.example.com ?all"}],"e1e.example.com":[{"SPF":"v=spf1 exists:foo%(ir).sbl.example.com ?all"}],"e1t.example.com":[{"SPF":"v=spf1 exists:foo%.sbl.example.com ?all"}],"e1a.example.com":[{"SPF":"v=spf1 a:macro%%percent%_%_space%-url-space.example.com -all"}],"macro%percent  space%20url-space.example.com":[{"A":"1.2.3.4"}],"e2.example.com":[{"SPF":"v=spf1 -all exp=%{r}.example.com"}],"e3.example.com":[{"SPF":"v=spf1 -all exp=%{ir}.example.com"}],"40.218.168.192.example.com":[{"TXT":"Connections from %{c} not authorized."}],"somewhat.long.exp.example.com":[{"SPF":"v=spf1 -all exp=foobar.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.example.com"}],"somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.example.com":[{"TXT":"Congratulations!  That was tricky."}],"e4.example.com":[{"SPF":"v=spf1 -all exp=e4msg.example.com"}],"e4msg.example.com":[{"TXT":"%{c} is queried as %{ir}.%{v}.arpa"}],"e5.example.com":[{"SPF":"v=spf1 a:%{a}.example.com -all"}],"e6.example.com":[{"SPF":"v=spf1 -all exp=e6msg.example.com"}],"e6msg.example.com":[{"TXT":"connect from %{p}"}],"mx.example.com":[{"A":"192.168.218.41"},{"A":"192.168.218.42"},{"AAAA":"CAFE:BABE::2"},{"AAAA":"CAFE:BABE::3"}],"40.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"}],"41.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"}],"42.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"},{"PTR":"mx.e7.example.com"}],"1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.E.B.A.B.E.F.A.C.ip6.arpa":[{"PTR":"mx.example.com"}],"3.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.E.B.A.B.E.F.A.C.ip6.arpa":[{"PTR":"mx.example.com"}],"mx.e7.example.com":[{"A":"192.168.218.42"}],"mx.e7.example.com.should.example.com":[{"A":"127.0.0.2"}],"mx.example.com.ok.example.com":[{"A":"127.0.0.2"}],"e7.example.com":[{"SPF":"v=spf1 exists:%{p}.should.example.com ~exists:%{p}.ok.example.com"}],"e8.example.com":[{"SPF":"v=spf1 -all exp=msg8.%{D2}"}],"msg8.example.com":[{"TXT":"http://example.com/why.html?l=%{L}"}],"e9.example.com":[{"SPF":"v=spf1 a:%{H} -all"}],"e10.example.com":[{"SPF":"v=spf1 -include:_spfh.%{d2} ip4:1.2.3.0/24 -all"}],"_spfh.example.com":[{"SPF":"v=spf1 -a:%{h} +all"}],"e11.example.com":[{"SPF":"v=spf1 exists:%{i}.%{l2r-}.user.%{d2}"}],"1.2.3.4.gladstone.philip.user.example.com":[{"A":"127.0.0.2"}],"e12.example.com":[{"SPF":"v=spf1 exists:%{l2r+-}.user.%{d2}"}],"bar.foo.user.example.com":[{"A":"127.0.0.2"}]}, failOnNoFake: true});
        let promise = validator.validateSender('192.168.218.40');
        return promise.then((result) => {
          assert.equal(result, 'PASS');
        });
      });
      it('trailing dot is not removed from explanation', function(){
        let email = 'test@exp.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"example.com.d.spf.example.com":[{"SPF":"v=spf1 redirect=a.spf.example.com"}],"a.spf.example.com":[{"SPF":"v=spf1 include:o.spf.example.com. ~all"}],"o.spf.example.com":[{"SPF":"v=spf1 ip4:192.168.218.40"}],"msgbas2x.cos.example.com":[{"A":"192.168.218.40"}],"example.com":[{"A":"192.168.90.76"},{"SPF":"v=spf1 redirect=%{d}.d.spf.example.com."}],"exp.example.com":[{"SPF":"v=spf1 exp=msg.example.com. -all"}],"msg.example.com":[{"TXT":"This is a test."}],"e1.example.com":[{"SPF":"v=spf1 -exists:%(ir).sbl.example.com ?all"}],"e1e.example.com":[{"SPF":"v=spf1 exists:foo%(ir).sbl.example.com ?all"}],"e1t.example.com":[{"SPF":"v=spf1 exists:foo%.sbl.example.com ?all"}],"e1a.example.com":[{"SPF":"v=spf1 a:macro%%percent%_%_space%-url-space.example.com -all"}],"macro%percent  space%20url-space.example.com":[{"A":"1.2.3.4"}],"e2.example.com":[{"SPF":"v=spf1 -all exp=%{r}.example.com"}],"e3.example.com":[{"SPF":"v=spf1 -all exp=%{ir}.example.com"}],"40.218.168.192.example.com":[{"TXT":"Connections from %{c} not authorized."}],"somewhat.long.exp.example.com":[{"SPF":"v=spf1 -all exp=foobar.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.example.com"}],"somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.example.com":[{"TXT":"Congratulations!  That was tricky."}],"e4.example.com":[{"SPF":"v=spf1 -all exp=e4msg.example.com"}],"e4msg.example.com":[{"TXT":"%{c} is queried as %{ir}.%{v}.arpa"}],"e5.example.com":[{"SPF":"v=spf1 a:%{a}.example.com -all"}],"e6.example.com":[{"SPF":"v=spf1 -all exp=e6msg.example.com"}],"e6msg.example.com":[{"TXT":"connect from %{p}"}],"mx.example.com":[{"A":"192.168.218.41"},{"A":"192.168.218.42"},{"AAAA":"CAFE:BABE::2"},{"AAAA":"CAFE:BABE::3"}],"40.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"}],"41.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"}],"42.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"},{"PTR":"mx.e7.example.com"}],"1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.E.B.A.B.E.F.A.C.ip6.arpa":[{"PTR":"mx.example.com"}],"3.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.E.B.A.B.E.F.A.C.ip6.arpa":[{"PTR":"mx.example.com"}],"mx.e7.example.com":[{"A":"192.168.218.42"}],"mx.e7.example.com.should.example.com":[{"A":"127.0.0.2"}],"mx.example.com.ok.example.com":[{"A":"127.0.0.2"}],"e7.example.com":[{"SPF":"v=spf1 exists:%{p}.should.example.com ~exists:%{p}.ok.example.com"}],"e8.example.com":[{"SPF":"v=spf1 -all exp=msg8.%{D2}"}],"msg8.example.com":[{"TXT":"http://example.com/why.html?l=%{L}"}],"e9.example.com":[{"SPF":"v=spf1 a:%{H} -all"}],"e10.example.com":[{"SPF":"v=spf1 -include:_spfh.%{d2} ip4:1.2.3.0/24 -all"}],"_spfh.example.com":[{"SPF":"v=spf1 -a:%{h} +all"}],"e11.example.com":[{"SPF":"v=spf1 exists:%{i}.%{l2r-}.user.%{d2}"}],"1.2.3.4.gladstone.philip.user.example.com":[{"A":"127.0.0.2"}],"e12.example.com":[{"SPF":"v=spf1 exists:%{l2r+-}.user.%{d2}"}],"bar.foo.user.example.com":[{"A":"127.0.0.2"}]}, failOnNoFake: true});
        let promise = validator.validateSender('192.168.218.40');
        return promise.then((result) => {
          assert.equal(result, 'FAIL');
        });
      });
      it('The following macro letters are allowed only in "exp" text: c, r, t', function(){
        let email = 'test@e2.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"example.com.d.spf.example.com":[{"SPF":"v=spf1 redirect=a.spf.example.com"}],"a.spf.example.com":[{"SPF":"v=spf1 include:o.spf.example.com. ~all"}],"o.spf.example.com":[{"SPF":"v=spf1 ip4:192.168.218.40"}],"msgbas2x.cos.example.com":[{"A":"192.168.218.40"}],"example.com":[{"A":"192.168.90.76"},{"SPF":"v=spf1 redirect=%{d}.d.spf.example.com."}],"exp.example.com":[{"SPF":"v=spf1 exp=msg.example.com. -all"}],"msg.example.com":[{"TXT":"This is a test."}],"e1.example.com":[{"SPF":"v=spf1 -exists:%(ir).sbl.example.com ?all"}],"e1e.example.com":[{"SPF":"v=spf1 exists:foo%(ir).sbl.example.com ?all"}],"e1t.example.com":[{"SPF":"v=spf1 exists:foo%.sbl.example.com ?all"}],"e1a.example.com":[{"SPF":"v=spf1 a:macro%%percent%_%_space%-url-space.example.com -all"}],"macro%percent  space%20url-space.example.com":[{"A":"1.2.3.4"}],"e2.example.com":[{"SPF":"v=spf1 -all exp=%{r}.example.com"}],"e3.example.com":[{"SPF":"v=spf1 -all exp=%{ir}.example.com"}],"40.218.168.192.example.com":[{"TXT":"Connections from %{c} not authorized."}],"somewhat.long.exp.example.com":[{"SPF":"v=spf1 -all exp=foobar.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.example.com"}],"somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.example.com":[{"TXT":"Congratulations!  That was tricky."}],"e4.example.com":[{"SPF":"v=spf1 -all exp=e4msg.example.com"}],"e4msg.example.com":[{"TXT":"%{c} is queried as %{ir}.%{v}.arpa"}],"e5.example.com":[{"SPF":"v=spf1 a:%{a}.example.com -all"}],"e6.example.com":[{"SPF":"v=spf1 -all exp=e6msg.example.com"}],"e6msg.example.com":[{"TXT":"connect from %{p}"}],"mx.example.com":[{"A":"192.168.218.41"},{"A":"192.168.218.42"},{"AAAA":"CAFE:BABE::2"},{"AAAA":"CAFE:BABE::3"}],"40.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"}],"41.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"}],"42.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"},{"PTR":"mx.e7.example.com"}],"1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.E.B.A.B.E.F.A.C.ip6.arpa":[{"PTR":"mx.example.com"}],"3.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.E.B.A.B.E.F.A.C.ip6.arpa":[{"PTR":"mx.example.com"}],"mx.e7.example.com":[{"A":"192.168.218.42"}],"mx.e7.example.com.should.example.com":[{"A":"127.0.0.2"}],"mx.example.com.ok.example.com":[{"A":"127.0.0.2"}],"e7.example.com":[{"SPF":"v=spf1 exists:%{p}.should.example.com ~exists:%{p}.ok.example.com"}],"e8.example.com":[{"SPF":"v=spf1 -all exp=msg8.%{D2}"}],"msg8.example.com":[{"TXT":"http://example.com/why.html?l=%{L}"}],"e9.example.com":[{"SPF":"v=spf1 a:%{H} -all"}],"e10.example.com":[{"SPF":"v=spf1 -include:_spfh.%{d2} ip4:1.2.3.0/24 -all"}],"_spfh.example.com":[{"SPF":"v=spf1 -a:%{h} +all"}],"e11.example.com":[{"SPF":"v=spf1 exists:%{i}.%{l2r-}.user.%{d2}"}],"1.2.3.4.gladstone.philip.user.example.com":[{"A":"127.0.0.2"}],"e12.example.com":[{"SPF":"v=spf1 exists:%{l2r+-}.user.%{d2}"}],"bar.foo.user.example.com":[{"A":"127.0.0.2"}]}, failOnNoFake: true});
        let promise = validator.validateSender('192.168.218.40');
        return promise.then((result) => {
          assert.equal(result, 'PERMERROR');
        });
      });
      it('A "%" character not followed by a "{", "%", "-", or "_" character is a syntax error.', function(){
        let email = 'test@e1.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"example.com.d.spf.example.com":[{"SPF":"v=spf1 redirect=a.spf.example.com"}],"a.spf.example.com":[{"SPF":"v=spf1 include:o.spf.example.com. ~all"}],"o.spf.example.com":[{"SPF":"v=spf1 ip4:192.168.218.40"}],"msgbas2x.cos.example.com":[{"A":"192.168.218.40"}],"example.com":[{"A":"192.168.90.76"},{"SPF":"v=spf1 redirect=%{d}.d.spf.example.com."}],"exp.example.com":[{"SPF":"v=spf1 exp=msg.example.com. -all"}],"msg.example.com":[{"TXT":"This is a test."}],"e1.example.com":[{"SPF":"v=spf1 -exists:%(ir).sbl.example.com ?all"}],"e1e.example.com":[{"SPF":"v=spf1 exists:foo%(ir).sbl.example.com ?all"}],"e1t.example.com":[{"SPF":"v=spf1 exists:foo%.sbl.example.com ?all"}],"e1a.example.com":[{"SPF":"v=spf1 a:macro%%percent%_%_space%-url-space.example.com -all"}],"macro%percent  space%20url-space.example.com":[{"A":"1.2.3.4"}],"e2.example.com":[{"SPF":"v=spf1 -all exp=%{r}.example.com"}],"e3.example.com":[{"SPF":"v=spf1 -all exp=%{ir}.example.com"}],"40.218.168.192.example.com":[{"TXT":"Connections from %{c} not authorized."}],"somewhat.long.exp.example.com":[{"SPF":"v=spf1 -all exp=foobar.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.example.com"}],"somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.example.com":[{"TXT":"Congratulations!  That was tricky."}],"e4.example.com":[{"SPF":"v=spf1 -all exp=e4msg.example.com"}],"e4msg.example.com":[{"TXT":"%{c} is queried as %{ir}.%{v}.arpa"}],"e5.example.com":[{"SPF":"v=spf1 a:%{a}.example.com -all"}],"e6.example.com":[{"SPF":"v=spf1 -all exp=e6msg.example.com"}],"e6msg.example.com":[{"TXT":"connect from %{p}"}],"mx.example.com":[{"A":"192.168.218.41"},{"A":"192.168.218.42"},{"AAAA":"CAFE:BABE::2"},{"AAAA":"CAFE:BABE::3"}],"40.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"}],"41.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"}],"42.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"},{"PTR":"mx.e7.example.com"}],"1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.E.B.A.B.E.F.A.C.ip6.arpa":[{"PTR":"mx.example.com"}],"3.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.E.B.A.B.E.F.A.C.ip6.arpa":[{"PTR":"mx.example.com"}],"mx.e7.example.com":[{"A":"192.168.218.42"}],"mx.e7.example.com.should.example.com":[{"A":"127.0.0.2"}],"mx.example.com.ok.example.com":[{"A":"127.0.0.2"}],"e7.example.com":[{"SPF":"v=spf1 exists:%{p}.should.example.com ~exists:%{p}.ok.example.com"}],"e8.example.com":[{"SPF":"v=spf1 -all exp=msg8.%{D2}"}],"msg8.example.com":[{"TXT":"http://example.com/why.html?l=%{L}"}],"e9.example.com":[{"SPF":"v=spf1 a:%{H} -all"}],"e10.example.com":[{"SPF":"v=spf1 -include:_spfh.%{d2} ip4:1.2.3.0/24 -all"}],"_spfh.example.com":[{"SPF":"v=spf1 -a:%{h} +all"}],"e11.example.com":[{"SPF":"v=spf1 exists:%{i}.%{l2r-}.user.%{d2}"}],"1.2.3.4.gladstone.philip.user.example.com":[{"A":"127.0.0.2"}],"e12.example.com":[{"SPF":"v=spf1 exists:%{l2r+-}.user.%{d2}"}],"bar.foo.user.example.com":[{"A":"127.0.0.2"}]}, failOnNoFake: true});
        let promise = validator.validateSender('192.168.218.40');
        return promise.then((result) => {
          assert.equal(result, 'PERMERROR');
        });
      });
      it('A "%" character not followed by a "{", "%", "-", or "_" character is a syntax error.', function(){
        let email = 'test@e1e.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"example.com.d.spf.example.com":[{"SPF":"v=spf1 redirect=a.spf.example.com"}],"a.spf.example.com":[{"SPF":"v=spf1 include:o.spf.example.com. ~all"}],"o.spf.example.com":[{"SPF":"v=spf1 ip4:192.168.218.40"}],"msgbas2x.cos.example.com":[{"A":"192.168.218.40"}],"example.com":[{"A":"192.168.90.76"},{"SPF":"v=spf1 redirect=%{d}.d.spf.example.com."}],"exp.example.com":[{"SPF":"v=spf1 exp=msg.example.com. -all"}],"msg.example.com":[{"TXT":"This is a test."}],"e1.example.com":[{"SPF":"v=spf1 -exists:%(ir).sbl.example.com ?all"}],"e1e.example.com":[{"SPF":"v=spf1 exists:foo%(ir).sbl.example.com ?all"}],"e1t.example.com":[{"SPF":"v=spf1 exists:foo%.sbl.example.com ?all"}],"e1a.example.com":[{"SPF":"v=spf1 a:macro%%percent%_%_space%-url-space.example.com -all"}],"macro%percent  space%20url-space.example.com":[{"A":"1.2.3.4"}],"e2.example.com":[{"SPF":"v=spf1 -all exp=%{r}.example.com"}],"e3.example.com":[{"SPF":"v=spf1 -all exp=%{ir}.example.com"}],"40.218.168.192.example.com":[{"TXT":"Connections from %{c} not authorized."}],"somewhat.long.exp.example.com":[{"SPF":"v=spf1 -all exp=foobar.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.example.com"}],"somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.example.com":[{"TXT":"Congratulations!  That was tricky."}],"e4.example.com":[{"SPF":"v=spf1 -all exp=e4msg.example.com"}],"e4msg.example.com":[{"TXT":"%{c} is queried as %{ir}.%{v}.arpa"}],"e5.example.com":[{"SPF":"v=spf1 a:%{a}.example.com -all"}],"e6.example.com":[{"SPF":"v=spf1 -all exp=e6msg.example.com"}],"e6msg.example.com":[{"TXT":"connect from %{p}"}],"mx.example.com":[{"A":"192.168.218.41"},{"A":"192.168.218.42"},{"AAAA":"CAFE:BABE::2"},{"AAAA":"CAFE:BABE::3"}],"40.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"}],"41.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"}],"42.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"},{"PTR":"mx.e7.example.com"}],"1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.E.B.A.B.E.F.A.C.ip6.arpa":[{"PTR":"mx.example.com"}],"3.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.E.B.A.B.E.F.A.C.ip6.arpa":[{"PTR":"mx.example.com"}],"mx.e7.example.com":[{"A":"192.168.218.42"}],"mx.e7.example.com.should.example.com":[{"A":"127.0.0.2"}],"mx.example.com.ok.example.com":[{"A":"127.0.0.2"}],"e7.example.com":[{"SPF":"v=spf1 exists:%{p}.should.example.com ~exists:%{p}.ok.example.com"}],"e8.example.com":[{"SPF":"v=spf1 -all exp=msg8.%{D2}"}],"msg8.example.com":[{"TXT":"http://example.com/why.html?l=%{L}"}],"e9.example.com":[{"SPF":"v=spf1 a:%{H} -all"}],"e10.example.com":[{"SPF":"v=spf1 -include:_spfh.%{d2} ip4:1.2.3.0/24 -all"}],"_spfh.example.com":[{"SPF":"v=spf1 -a:%{h} +all"}],"e11.example.com":[{"SPF":"v=spf1 exists:%{i}.%{l2r-}.user.%{d2}"}],"1.2.3.4.gladstone.philip.user.example.com":[{"A":"127.0.0.2"}],"e12.example.com":[{"SPF":"v=spf1 exists:%{l2r+-}.user.%{d2}"}],"bar.foo.user.example.com":[{"A":"127.0.0.2"}]}, failOnNoFake: true});
        let promise = validator.validateSender('192.168.218.40');
        return promise.then((result) => {
          assert.equal(result, 'PERMERROR');
        });
      });
      it('A "%" character not followed by a "{", "%", "-", or "_" character is a syntax error.', function(){
        let email = 'test@e1t.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"example.com.d.spf.example.com":[{"SPF":"v=spf1 redirect=a.spf.example.com"}],"a.spf.example.com":[{"SPF":"v=spf1 include:o.spf.example.com. ~all"}],"o.spf.example.com":[{"SPF":"v=spf1 ip4:192.168.218.40"}],"msgbas2x.cos.example.com":[{"A":"192.168.218.40"}],"example.com":[{"A":"192.168.90.76"},{"SPF":"v=spf1 redirect=%{d}.d.spf.example.com."}],"exp.example.com":[{"SPF":"v=spf1 exp=msg.example.com. -all"}],"msg.example.com":[{"TXT":"This is a test."}],"e1.example.com":[{"SPF":"v=spf1 -exists:%(ir).sbl.example.com ?all"}],"e1e.example.com":[{"SPF":"v=spf1 exists:foo%(ir).sbl.example.com ?all"}],"e1t.example.com":[{"SPF":"v=spf1 exists:foo%.sbl.example.com ?all"}],"e1a.example.com":[{"SPF":"v=spf1 a:macro%%percent%_%_space%-url-space.example.com -all"}],"macro%percent  space%20url-space.example.com":[{"A":"1.2.3.4"}],"e2.example.com":[{"SPF":"v=spf1 -all exp=%{r}.example.com"}],"e3.example.com":[{"SPF":"v=spf1 -all exp=%{ir}.example.com"}],"40.218.168.192.example.com":[{"TXT":"Connections from %{c} not authorized."}],"somewhat.long.exp.example.com":[{"SPF":"v=spf1 -all exp=foobar.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.example.com"}],"somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.example.com":[{"TXT":"Congratulations!  That was tricky."}],"e4.example.com":[{"SPF":"v=spf1 -all exp=e4msg.example.com"}],"e4msg.example.com":[{"TXT":"%{c} is queried as %{ir}.%{v}.arpa"}],"e5.example.com":[{"SPF":"v=spf1 a:%{a}.example.com -all"}],"e6.example.com":[{"SPF":"v=spf1 -all exp=e6msg.example.com"}],"e6msg.example.com":[{"TXT":"connect from %{p}"}],"mx.example.com":[{"A":"192.168.218.41"},{"A":"192.168.218.42"},{"AAAA":"CAFE:BABE::2"},{"AAAA":"CAFE:BABE::3"}],"40.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"}],"41.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"}],"42.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"},{"PTR":"mx.e7.example.com"}],"1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.E.B.A.B.E.F.A.C.ip6.arpa":[{"PTR":"mx.example.com"}],"3.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.E.B.A.B.E.F.A.C.ip6.arpa":[{"PTR":"mx.example.com"}],"mx.e7.example.com":[{"A":"192.168.218.42"}],"mx.e7.example.com.should.example.com":[{"A":"127.0.0.2"}],"mx.example.com.ok.example.com":[{"A":"127.0.0.2"}],"e7.example.com":[{"SPF":"v=spf1 exists:%{p}.should.example.com ~exists:%{p}.ok.example.com"}],"e8.example.com":[{"SPF":"v=spf1 -all exp=msg8.%{D2}"}],"msg8.example.com":[{"TXT":"http://example.com/why.html?l=%{L}"}],"e9.example.com":[{"SPF":"v=spf1 a:%{H} -all"}],"e10.example.com":[{"SPF":"v=spf1 -include:_spfh.%{d2} ip4:1.2.3.0/24 -all"}],"_spfh.example.com":[{"SPF":"v=spf1 -a:%{h} +all"}],"e11.example.com":[{"SPF":"v=spf1 exists:%{i}.%{l2r-}.user.%{d2}"}],"1.2.3.4.gladstone.philip.user.example.com":[{"A":"127.0.0.2"}],"e12.example.com":[{"SPF":"v=spf1 exists:%{l2r+-}.user.%{d2}"}],"bar.foo.user.example.com":[{"A":"127.0.0.2"}]}, failOnNoFake: true});
        let promise = validator.validateSender('192.168.218.40');
        return promise.then((result) => {
          assert.equal(result, 'PERMERROR');
        });
      });
      it('macro-encoded percents (%%), spaces (%_), and URL-percent-encoded spaces (%-)', function(){
        let email = 'test@e1a.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"example.com.d.spf.example.com":[{"SPF":"v=spf1 redirect=a.spf.example.com"}],"a.spf.example.com":[{"SPF":"v=spf1 include:o.spf.example.com. ~all"}],"o.spf.example.com":[{"SPF":"v=spf1 ip4:192.168.218.40"}],"msgbas2x.cos.example.com":[{"A":"192.168.218.40"}],"example.com":[{"A":"192.168.90.76"},{"SPF":"v=spf1 redirect=%{d}.d.spf.example.com."}],"exp.example.com":[{"SPF":"v=spf1 exp=msg.example.com. -all"}],"msg.example.com":[{"TXT":"This is a test."}],"e1.example.com":[{"SPF":"v=spf1 -exists:%(ir).sbl.example.com ?all"}],"e1e.example.com":[{"SPF":"v=spf1 exists:foo%(ir).sbl.example.com ?all"}],"e1t.example.com":[{"SPF":"v=spf1 exists:foo%.sbl.example.com ?all"}],"e1a.example.com":[{"SPF":"v=spf1 a:macro%%percent%_%_space%-url-space.example.com -all"}],"macro%percent  space%20url-space.example.com":[{"A":"1.2.3.4"}],"e2.example.com":[{"SPF":"v=spf1 -all exp=%{r}.example.com"}],"e3.example.com":[{"SPF":"v=spf1 -all exp=%{ir}.example.com"}],"40.218.168.192.example.com":[{"TXT":"Connections from %{c} not authorized."}],"somewhat.long.exp.example.com":[{"SPF":"v=spf1 -all exp=foobar.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.example.com"}],"somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.example.com":[{"TXT":"Congratulations!  That was tricky."}],"e4.example.com":[{"SPF":"v=spf1 -all exp=e4msg.example.com"}],"e4msg.example.com":[{"TXT":"%{c} is queried as %{ir}.%{v}.arpa"}],"e5.example.com":[{"SPF":"v=spf1 a:%{a}.example.com -all"}],"e6.example.com":[{"SPF":"v=spf1 -all exp=e6msg.example.com"}],"e6msg.example.com":[{"TXT":"connect from %{p}"}],"mx.example.com":[{"A":"192.168.218.41"},{"A":"192.168.218.42"},{"AAAA":"CAFE:BABE::2"},{"AAAA":"CAFE:BABE::3"}],"40.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"}],"41.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"}],"42.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"},{"PTR":"mx.e7.example.com"}],"1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.E.B.A.B.E.F.A.C.ip6.arpa":[{"PTR":"mx.example.com"}],"3.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.E.B.A.B.E.F.A.C.ip6.arpa":[{"PTR":"mx.example.com"}],"mx.e7.example.com":[{"A":"192.168.218.42"}],"mx.e7.example.com.should.example.com":[{"A":"127.0.0.2"}],"mx.example.com.ok.example.com":[{"A":"127.0.0.2"}],"e7.example.com":[{"SPF":"v=spf1 exists:%{p}.should.example.com ~exists:%{p}.ok.example.com"}],"e8.example.com":[{"SPF":"v=spf1 -all exp=msg8.%{D2}"}],"msg8.example.com":[{"TXT":"http://example.com/why.html?l=%{L}"}],"e9.example.com":[{"SPF":"v=spf1 a:%{H} -all"}],"e10.example.com":[{"SPF":"v=spf1 -include:_spfh.%{d2} ip4:1.2.3.0/24 -all"}],"_spfh.example.com":[{"SPF":"v=spf1 -a:%{h} +all"}],"e11.example.com":[{"SPF":"v=spf1 exists:%{i}.%{l2r-}.user.%{d2}"}],"1.2.3.4.gladstone.philip.user.example.com":[{"A":"127.0.0.2"}],"e12.example.com":[{"SPF":"v=spf1 exists:%{l2r+-}.user.%{d2}"}],"bar.foo.user.example.com":[{"A":"127.0.0.2"}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.4');
        return promise.then((result) => {
          assert.equal(result, 'PASS');
        });
      });
      it('For IPv4 addresses, both the "i" and "c" macros expand to the standard dotted-quad format.', function(){
        let email = 'test@e3.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"example.com.d.spf.example.com":[{"SPF":"v=spf1 redirect=a.spf.example.com"}],"a.spf.example.com":[{"SPF":"v=spf1 include:o.spf.example.com. ~all"}],"o.spf.example.com":[{"SPF":"v=spf1 ip4:192.168.218.40"}],"msgbas2x.cos.example.com":[{"A":"192.168.218.40"}],"example.com":[{"A":"192.168.90.76"},{"SPF":"v=spf1 redirect=%{d}.d.spf.example.com."}],"exp.example.com":[{"SPF":"v=spf1 exp=msg.example.com. -all"}],"msg.example.com":[{"TXT":"This is a test."}],"e1.example.com":[{"SPF":"v=spf1 -exists:%(ir).sbl.example.com ?all"}],"e1e.example.com":[{"SPF":"v=spf1 exists:foo%(ir).sbl.example.com ?all"}],"e1t.example.com":[{"SPF":"v=spf1 exists:foo%.sbl.example.com ?all"}],"e1a.example.com":[{"SPF":"v=spf1 a:macro%%percent%_%_space%-url-space.example.com -all"}],"macro%percent  space%20url-space.example.com":[{"A":"1.2.3.4"}],"e2.example.com":[{"SPF":"v=spf1 -all exp=%{r}.example.com"}],"e3.example.com":[{"SPF":"v=spf1 -all exp=%{ir}.example.com"}],"40.218.168.192.example.com":[{"TXT":"Connections from %{c} not authorized."}],"somewhat.long.exp.example.com":[{"SPF":"v=spf1 -all exp=foobar.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.example.com"}],"somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.example.com":[{"TXT":"Congratulations!  That was tricky."}],"e4.example.com":[{"SPF":"v=spf1 -all exp=e4msg.example.com"}],"e4msg.example.com":[{"TXT":"%{c} is queried as %{ir}.%{v}.arpa"}],"e5.example.com":[{"SPF":"v=spf1 a:%{a}.example.com -all"}],"e6.example.com":[{"SPF":"v=spf1 -all exp=e6msg.example.com"}],"e6msg.example.com":[{"TXT":"connect from %{p}"}],"mx.example.com":[{"A":"192.168.218.41"},{"A":"192.168.218.42"},{"AAAA":"CAFE:BABE::2"},{"AAAA":"CAFE:BABE::3"}],"40.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"}],"41.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"}],"42.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"},{"PTR":"mx.e7.example.com"}],"1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.E.B.A.B.E.F.A.C.ip6.arpa":[{"PTR":"mx.example.com"}],"3.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.E.B.A.B.E.F.A.C.ip6.arpa":[{"PTR":"mx.example.com"}],"mx.e7.example.com":[{"A":"192.168.218.42"}],"mx.e7.example.com.should.example.com":[{"A":"127.0.0.2"}],"mx.example.com.ok.example.com":[{"A":"127.0.0.2"}],"e7.example.com":[{"SPF":"v=spf1 exists:%{p}.should.example.com ~exists:%{p}.ok.example.com"}],"e8.example.com":[{"SPF":"v=spf1 -all exp=msg8.%{D2}"}],"msg8.example.com":[{"TXT":"http://example.com/why.html?l=%{L}"}],"e9.example.com":[{"SPF":"v=spf1 a:%{H} -all"}],"e10.example.com":[{"SPF":"v=spf1 -include:_spfh.%{d2} ip4:1.2.3.0/24 -all"}],"_spfh.example.com":[{"SPF":"v=spf1 -a:%{h} +all"}],"e11.example.com":[{"SPF":"v=spf1 exists:%{i}.%{l2r-}.user.%{d2}"}],"1.2.3.4.gladstone.philip.user.example.com":[{"A":"127.0.0.2"}],"e12.example.com":[{"SPF":"v=spf1 exists:%{l2r+-}.user.%{d2}"}],"bar.foo.user.example.com":[{"A":"127.0.0.2"}]}, failOnNoFake: true});
        let promise = validator.validateSender('192.168.218.40');
        return promise.then((result) => {
          assert.equal(result, 'FAIL');
        });
      });
      it('When the result of macro expansion is used in a domain name query, if the expanded domain name exceeds 253 characters, the left side is truncated to fit, by removing successive domain labels until the total length does not exceed 253 characters.', function(){
        let email = 'test@somewhat.long.exp.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"example.com.d.spf.example.com":[{"SPF":"v=spf1 redirect=a.spf.example.com"}],"a.spf.example.com":[{"SPF":"v=spf1 include:o.spf.example.com. ~all"}],"o.spf.example.com":[{"SPF":"v=spf1 ip4:192.168.218.40"}],"msgbas2x.cos.example.com":[{"A":"192.168.218.40"}],"example.com":[{"A":"192.168.90.76"},{"SPF":"v=spf1 redirect=%{d}.d.spf.example.com."}],"exp.example.com":[{"SPF":"v=spf1 exp=msg.example.com. -all"}],"msg.example.com":[{"TXT":"This is a test."}],"e1.example.com":[{"SPF":"v=spf1 -exists:%(ir).sbl.example.com ?all"}],"e1e.example.com":[{"SPF":"v=spf1 exists:foo%(ir).sbl.example.com ?all"}],"e1t.example.com":[{"SPF":"v=spf1 exists:foo%.sbl.example.com ?all"}],"e1a.example.com":[{"SPF":"v=spf1 a:macro%%percent%_%_space%-url-space.example.com -all"}],"macro%percent  space%20url-space.example.com":[{"A":"1.2.3.4"}],"e2.example.com":[{"SPF":"v=spf1 -all exp=%{r}.example.com"}],"e3.example.com":[{"SPF":"v=spf1 -all exp=%{ir}.example.com"}],"40.218.168.192.example.com":[{"TXT":"Connections from %{c} not authorized."}],"somewhat.long.exp.example.com":[{"SPF":"v=spf1 -all exp=foobar.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.example.com"}],"somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.example.com":[{"TXT":"Congratulations!  That was tricky."}],"e4.example.com":[{"SPF":"v=spf1 -all exp=e4msg.example.com"}],"e4msg.example.com":[{"TXT":"%{c} is queried as %{ir}.%{v}.arpa"}],"e5.example.com":[{"SPF":"v=spf1 a:%{a}.example.com -all"}],"e6.example.com":[{"SPF":"v=spf1 -all exp=e6msg.example.com"}],"e6msg.example.com":[{"TXT":"connect from %{p}"}],"mx.example.com":[{"A":"192.168.218.41"},{"A":"192.168.218.42"},{"AAAA":"CAFE:BABE::2"},{"AAAA":"CAFE:BABE::3"}],"40.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"}],"41.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"}],"42.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"},{"PTR":"mx.e7.example.com"}],"1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.E.B.A.B.E.F.A.C.ip6.arpa":[{"PTR":"mx.example.com"}],"3.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.E.B.A.B.E.F.A.C.ip6.arpa":[{"PTR":"mx.example.com"}],"mx.e7.example.com":[{"A":"192.168.218.42"}],"mx.e7.example.com.should.example.com":[{"A":"127.0.0.2"}],"mx.example.com.ok.example.com":[{"A":"127.0.0.2"}],"e7.example.com":[{"SPF":"v=spf1 exists:%{p}.should.example.com ~exists:%{p}.ok.example.com"}],"e8.example.com":[{"SPF":"v=spf1 -all exp=msg8.%{D2}"}],"msg8.example.com":[{"TXT":"http://example.com/why.html?l=%{L}"}],"e9.example.com":[{"SPF":"v=spf1 a:%{H} -all"}],"e10.example.com":[{"SPF":"v=spf1 -include:_spfh.%{d2} ip4:1.2.3.0/24 -all"}],"_spfh.example.com":[{"SPF":"v=spf1 -a:%{h} +all"}],"e11.example.com":[{"SPF":"v=spf1 exists:%{i}.%{l2r-}.user.%{d2}"}],"1.2.3.4.gladstone.philip.user.example.com":[{"A":"127.0.0.2"}],"e12.example.com":[{"SPF":"v=spf1 exists:%{l2r+-}.user.%{d2}"}],"bar.foo.user.example.com":[{"A":"127.0.0.2"}]}, failOnNoFake: true});
        let promise = validator.validateSender('192.168.218.40');
        return promise.then((result) => {
          assert.equal(result, 'FAIL');
        });
      });
      it('v = the string "in-addr" if <ip> is ipv4, or "ip6" if <ip> is ipv6', function(){
        let email = 'test@e4.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"example.com.d.spf.example.com":[{"SPF":"v=spf1 redirect=a.spf.example.com"}],"a.spf.example.com":[{"SPF":"v=spf1 include:o.spf.example.com. ~all"}],"o.spf.example.com":[{"SPF":"v=spf1 ip4:192.168.218.40"}],"msgbas2x.cos.example.com":[{"A":"192.168.218.40"}],"example.com":[{"A":"192.168.90.76"},{"SPF":"v=spf1 redirect=%{d}.d.spf.example.com."}],"exp.example.com":[{"SPF":"v=spf1 exp=msg.example.com. -all"}],"msg.example.com":[{"TXT":"This is a test."}],"e1.example.com":[{"SPF":"v=spf1 -exists:%(ir).sbl.example.com ?all"}],"e1e.example.com":[{"SPF":"v=spf1 exists:foo%(ir).sbl.example.com ?all"}],"e1t.example.com":[{"SPF":"v=spf1 exists:foo%.sbl.example.com ?all"}],"e1a.example.com":[{"SPF":"v=spf1 a:macro%%percent%_%_space%-url-space.example.com -all"}],"macro%percent  space%20url-space.example.com":[{"A":"1.2.3.4"}],"e2.example.com":[{"SPF":"v=spf1 -all exp=%{r}.example.com"}],"e3.example.com":[{"SPF":"v=spf1 -all exp=%{ir}.example.com"}],"40.218.168.192.example.com":[{"TXT":"Connections from %{c} not authorized."}],"somewhat.long.exp.example.com":[{"SPF":"v=spf1 -all exp=foobar.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.example.com"}],"somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.example.com":[{"TXT":"Congratulations!  That was tricky."}],"e4.example.com":[{"SPF":"v=spf1 -all exp=e4msg.example.com"}],"e4msg.example.com":[{"TXT":"%{c} is queried as %{ir}.%{v}.arpa"}],"e5.example.com":[{"SPF":"v=spf1 a:%{a}.example.com -all"}],"e6.example.com":[{"SPF":"v=spf1 -all exp=e6msg.example.com"}],"e6msg.example.com":[{"TXT":"connect from %{p}"}],"mx.example.com":[{"A":"192.168.218.41"},{"A":"192.168.218.42"},{"AAAA":"CAFE:BABE::2"},{"AAAA":"CAFE:BABE::3"}],"40.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"}],"41.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"}],"42.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"},{"PTR":"mx.e7.example.com"}],"1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.E.B.A.B.E.F.A.C.ip6.arpa":[{"PTR":"mx.example.com"}],"3.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.E.B.A.B.E.F.A.C.ip6.arpa":[{"PTR":"mx.example.com"}],"mx.e7.example.com":[{"A":"192.168.218.42"}],"mx.e7.example.com.should.example.com":[{"A":"127.0.0.2"}],"mx.example.com.ok.example.com":[{"A":"127.0.0.2"}],"e7.example.com":[{"SPF":"v=spf1 exists:%{p}.should.example.com ~exists:%{p}.ok.example.com"}],"e8.example.com":[{"SPF":"v=spf1 -all exp=msg8.%{D2}"}],"msg8.example.com":[{"TXT":"http://example.com/why.html?l=%{L}"}],"e9.example.com":[{"SPF":"v=spf1 a:%{H} -all"}],"e10.example.com":[{"SPF":"v=spf1 -include:_spfh.%{d2} ip4:1.2.3.0/24 -all"}],"_spfh.example.com":[{"SPF":"v=spf1 -a:%{h} +all"}],"e11.example.com":[{"SPF":"v=spf1 exists:%{i}.%{l2r-}.user.%{d2}"}],"1.2.3.4.gladstone.philip.user.example.com":[{"A":"127.0.0.2"}],"e12.example.com":[{"SPF":"v=spf1 exists:%{l2r+-}.user.%{d2}"}],"bar.foo.user.example.com":[{"A":"127.0.0.2"}]}, failOnNoFake: true});
        let promise = validator.validateSender('192.168.218.40');
        return promise.then((result) => {
          assert.equal(result, 'FAIL');
        });
      });
      it('v = the string "in-addr" if <ip> is ipv4, or "ip6" if <ip> is ipv6', function(){
        let email = 'test@e4.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"example.com.d.spf.example.com":[{"SPF":"v=spf1 redirect=a.spf.example.com"}],"a.spf.example.com":[{"SPF":"v=spf1 include:o.spf.example.com. ~all"}],"o.spf.example.com":[{"SPF":"v=spf1 ip4:192.168.218.40"}],"msgbas2x.cos.example.com":[{"A":"192.168.218.40"}],"example.com":[{"A":"192.168.90.76"},{"SPF":"v=spf1 redirect=%{d}.d.spf.example.com."}],"exp.example.com":[{"SPF":"v=spf1 exp=msg.example.com. -all"}],"msg.example.com":[{"TXT":"This is a test."}],"e1.example.com":[{"SPF":"v=spf1 -exists:%(ir).sbl.example.com ?all"}],"e1e.example.com":[{"SPF":"v=spf1 exists:foo%(ir).sbl.example.com ?all"}],"e1t.example.com":[{"SPF":"v=spf1 exists:foo%.sbl.example.com ?all"}],"e1a.example.com":[{"SPF":"v=spf1 a:macro%%percent%_%_space%-url-space.example.com -all"}],"macro%percent  space%20url-space.example.com":[{"A":"1.2.3.4"}],"e2.example.com":[{"SPF":"v=spf1 -all exp=%{r}.example.com"}],"e3.example.com":[{"SPF":"v=spf1 -all exp=%{ir}.example.com"}],"40.218.168.192.example.com":[{"TXT":"Connections from %{c} not authorized."}],"somewhat.long.exp.example.com":[{"SPF":"v=spf1 -all exp=foobar.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.example.com"}],"somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.example.com":[{"TXT":"Congratulations!  That was tricky."}],"e4.example.com":[{"SPF":"v=spf1 -all exp=e4msg.example.com"}],"e4msg.example.com":[{"TXT":"%{c} is queried as %{ir}.%{v}.arpa"}],"e5.example.com":[{"SPF":"v=spf1 a:%{a}.example.com -all"}],"e6.example.com":[{"SPF":"v=spf1 -all exp=e6msg.example.com"}],"e6msg.example.com":[{"TXT":"connect from %{p}"}],"mx.example.com":[{"A":"192.168.218.41"},{"A":"192.168.218.42"},{"AAAA":"CAFE:BABE::2"},{"AAAA":"CAFE:BABE::3"}],"40.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"}],"41.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"}],"42.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"},{"PTR":"mx.e7.example.com"}],"1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.E.B.A.B.E.F.A.C.ip6.arpa":[{"PTR":"mx.example.com"}],"3.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.E.B.A.B.E.F.A.C.ip6.arpa":[{"PTR":"mx.example.com"}],"mx.e7.example.com":[{"A":"192.168.218.42"}],"mx.e7.example.com.should.example.com":[{"A":"127.0.0.2"}],"mx.example.com.ok.example.com":[{"A":"127.0.0.2"}],"e7.example.com":[{"SPF":"v=spf1 exists:%{p}.should.example.com ~exists:%{p}.ok.example.com"}],"e8.example.com":[{"SPF":"v=spf1 -all exp=msg8.%{D2}"}],"msg8.example.com":[{"TXT":"http://example.com/why.html?l=%{L}"}],"e9.example.com":[{"SPF":"v=spf1 a:%{H} -all"}],"e10.example.com":[{"SPF":"v=spf1 -include:_spfh.%{d2} ip4:1.2.3.0/24 -all"}],"_spfh.example.com":[{"SPF":"v=spf1 -a:%{h} +all"}],"e11.example.com":[{"SPF":"v=spf1 exists:%{i}.%{l2r-}.user.%{d2}"}],"1.2.3.4.gladstone.philip.user.example.com":[{"A":"127.0.0.2"}],"e12.example.com":[{"SPF":"v=spf1 exists:%{l2r+-}.user.%{d2}"}],"bar.foo.user.example.com":[{"A":"127.0.0.2"}]}, failOnNoFake: true});
        let promise = validator.validateSender('CAFE:BABE::1');
        return promise.then((result) => {
          assert.equal(result, 'FAIL');
        });
      });
      it('Allowed macros chars are "slodipvh" plus "crt" in explanation.', function(){
        let email = 'test@e5.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"example.com.d.spf.example.com":[{"SPF":"v=spf1 redirect=a.spf.example.com"}],"a.spf.example.com":[{"SPF":"v=spf1 include:o.spf.example.com. ~all"}],"o.spf.example.com":[{"SPF":"v=spf1 ip4:192.168.218.40"}],"msgbas2x.cos.example.com":[{"A":"192.168.218.40"}],"example.com":[{"A":"192.168.90.76"},{"SPF":"v=spf1 redirect=%{d}.d.spf.example.com."}],"exp.example.com":[{"SPF":"v=spf1 exp=msg.example.com. -all"}],"msg.example.com":[{"TXT":"This is a test."}],"e1.example.com":[{"SPF":"v=spf1 -exists:%(ir).sbl.example.com ?all"}],"e1e.example.com":[{"SPF":"v=spf1 exists:foo%(ir).sbl.example.com ?all"}],"e1t.example.com":[{"SPF":"v=spf1 exists:foo%.sbl.example.com ?all"}],"e1a.example.com":[{"SPF":"v=spf1 a:macro%%percent%_%_space%-url-space.example.com -all"}],"macro%percent  space%20url-space.example.com":[{"A":"1.2.3.4"}],"e2.example.com":[{"SPF":"v=spf1 -all exp=%{r}.example.com"}],"e3.example.com":[{"SPF":"v=spf1 -all exp=%{ir}.example.com"}],"40.218.168.192.example.com":[{"TXT":"Connections from %{c} not authorized."}],"somewhat.long.exp.example.com":[{"SPF":"v=spf1 -all exp=foobar.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.example.com"}],"somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.example.com":[{"TXT":"Congratulations!  That was tricky."}],"e4.example.com":[{"SPF":"v=spf1 -all exp=e4msg.example.com"}],"e4msg.example.com":[{"TXT":"%{c} is queried as %{ir}.%{v}.arpa"}],"e5.example.com":[{"SPF":"v=spf1 a:%{a}.example.com -all"}],"e6.example.com":[{"SPF":"v=spf1 -all exp=e6msg.example.com"}],"e6msg.example.com":[{"TXT":"connect from %{p}"}],"mx.example.com":[{"A":"192.168.218.41"},{"A":"192.168.218.42"},{"AAAA":"CAFE:BABE::2"},{"AAAA":"CAFE:BABE::3"}],"40.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"}],"41.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"}],"42.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"},{"PTR":"mx.e7.example.com"}],"1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.E.B.A.B.E.F.A.C.ip6.arpa":[{"PTR":"mx.example.com"}],"3.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.E.B.A.B.E.F.A.C.ip6.arpa":[{"PTR":"mx.example.com"}],"mx.e7.example.com":[{"A":"192.168.218.42"}],"mx.e7.example.com.should.example.com":[{"A":"127.0.0.2"}],"mx.example.com.ok.example.com":[{"A":"127.0.0.2"}],"e7.example.com":[{"SPF":"v=spf1 exists:%{p}.should.example.com ~exists:%{p}.ok.example.com"}],"e8.example.com":[{"SPF":"v=spf1 -all exp=msg8.%{D2}"}],"msg8.example.com":[{"TXT":"http://example.com/why.html?l=%{L}"}],"e9.example.com":[{"SPF":"v=spf1 a:%{H} -all"}],"e10.example.com":[{"SPF":"v=spf1 -include:_spfh.%{d2} ip4:1.2.3.0/24 -all"}],"_spfh.example.com":[{"SPF":"v=spf1 -a:%{h} +all"}],"e11.example.com":[{"SPF":"v=spf1 exists:%{i}.%{l2r-}.user.%{d2}"}],"1.2.3.4.gladstone.philip.user.example.com":[{"A":"127.0.0.2"}],"e12.example.com":[{"SPF":"v=spf1 exists:%{l2r+-}.user.%{d2}"}],"bar.foo.user.example.com":[{"A":"127.0.0.2"}]}, failOnNoFake: true});
        let promise = validator.validateSender('CAFE:BABE::192.168.218.40');
        return promise.then((result) => {
          assert.equal(result, 'PERMERROR');
        });
      });
      it('p = the validated domain name of <ip>', function(){
        let email = 'test@e6.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"example.com.d.spf.example.com":[{"SPF":"v=spf1 redirect=a.spf.example.com"}],"a.spf.example.com":[{"SPF":"v=spf1 include:o.spf.example.com. ~all"}],"o.spf.example.com":[{"SPF":"v=spf1 ip4:192.168.218.40"}],"msgbas2x.cos.example.com":[{"A":"192.168.218.40"}],"example.com":[{"A":"192.168.90.76"},{"SPF":"v=spf1 redirect=%{d}.d.spf.example.com."}],"exp.example.com":[{"SPF":"v=spf1 exp=msg.example.com. -all"}],"msg.example.com":[{"TXT":"This is a test."}],"e1.example.com":[{"SPF":"v=spf1 -exists:%(ir).sbl.example.com ?all"}],"e1e.example.com":[{"SPF":"v=spf1 exists:foo%(ir).sbl.example.com ?all"}],"e1t.example.com":[{"SPF":"v=spf1 exists:foo%.sbl.example.com ?all"}],"e1a.example.com":[{"SPF":"v=spf1 a:macro%%percent%_%_space%-url-space.example.com -all"}],"macro%percent  space%20url-space.example.com":[{"A":"1.2.3.4"}],"e2.example.com":[{"SPF":"v=spf1 -all exp=%{r}.example.com"}],"e3.example.com":[{"SPF":"v=spf1 -all exp=%{ir}.example.com"}],"40.218.168.192.example.com":[{"TXT":"Connections from %{c} not authorized."}],"somewhat.long.exp.example.com":[{"SPF":"v=spf1 -all exp=foobar.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.example.com"}],"somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.example.com":[{"TXT":"Congratulations!  That was tricky."}],"e4.example.com":[{"SPF":"v=spf1 -all exp=e4msg.example.com"}],"e4msg.example.com":[{"TXT":"%{c} is queried as %{ir}.%{v}.arpa"}],"e5.example.com":[{"SPF":"v=spf1 a:%{a}.example.com -all"}],"e6.example.com":[{"SPF":"v=spf1 -all exp=e6msg.example.com"}],"e6msg.example.com":[{"TXT":"connect from %{p}"}],"mx.example.com":[{"A":"192.168.218.41"},{"A":"192.168.218.42"},{"AAAA":"CAFE:BABE::2"},{"AAAA":"CAFE:BABE::3"}],"40.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"}],"41.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"}],"42.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"},{"PTR":"mx.e7.example.com"}],"1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.E.B.A.B.E.F.A.C.ip6.arpa":[{"PTR":"mx.example.com"}],"3.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.E.B.A.B.E.F.A.C.ip6.arpa":[{"PTR":"mx.example.com"}],"mx.e7.example.com":[{"A":"192.168.218.42"}],"mx.e7.example.com.should.example.com":[{"A":"127.0.0.2"}],"mx.example.com.ok.example.com":[{"A":"127.0.0.2"}],"e7.example.com":[{"SPF":"v=spf1 exists:%{p}.should.example.com ~exists:%{p}.ok.example.com"}],"e8.example.com":[{"SPF":"v=spf1 -all exp=msg8.%{D2}"}],"msg8.example.com":[{"TXT":"http://example.com/why.html?l=%{L}"}],"e9.example.com":[{"SPF":"v=spf1 a:%{H} -all"}],"e10.example.com":[{"SPF":"v=spf1 -include:_spfh.%{d2} ip4:1.2.3.0/24 -all"}],"_spfh.example.com":[{"SPF":"v=spf1 -a:%{h} +all"}],"e11.example.com":[{"SPF":"v=spf1 exists:%{i}.%{l2r-}.user.%{d2}"}],"1.2.3.4.gladstone.philip.user.example.com":[{"A":"127.0.0.2"}],"e12.example.com":[{"SPF":"v=spf1 exists:%{l2r+-}.user.%{d2}"}],"bar.foo.user.example.com":[{"A":"127.0.0.2"}]}, failOnNoFake: true});
        let promise = validator.validateSender('192.168.218.40');
        return promise.then((result) => {
          assert.equal(result, 'FAIL');
        });
      });
      it('p = the validated domain name of <ip>', function(){
        let email = 'test@e6.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"example.com.d.spf.example.com":[{"SPF":"v=spf1 redirect=a.spf.example.com"}],"a.spf.example.com":[{"SPF":"v=spf1 include:o.spf.example.com. ~all"}],"o.spf.example.com":[{"SPF":"v=spf1 ip4:192.168.218.40"}],"msgbas2x.cos.example.com":[{"A":"192.168.218.40"}],"example.com":[{"A":"192.168.90.76"},{"SPF":"v=spf1 redirect=%{d}.d.spf.example.com."}],"exp.example.com":[{"SPF":"v=spf1 exp=msg.example.com. -all"}],"msg.example.com":[{"TXT":"This is a test."}],"e1.example.com":[{"SPF":"v=spf1 -exists:%(ir).sbl.example.com ?all"}],"e1e.example.com":[{"SPF":"v=spf1 exists:foo%(ir).sbl.example.com ?all"}],"e1t.example.com":[{"SPF":"v=spf1 exists:foo%.sbl.example.com ?all"}],"e1a.example.com":[{"SPF":"v=spf1 a:macro%%percent%_%_space%-url-space.example.com -all"}],"macro%percent  space%20url-space.example.com":[{"A":"1.2.3.4"}],"e2.example.com":[{"SPF":"v=spf1 -all exp=%{r}.example.com"}],"e3.example.com":[{"SPF":"v=spf1 -all exp=%{ir}.example.com"}],"40.218.168.192.example.com":[{"TXT":"Connections from %{c} not authorized."}],"somewhat.long.exp.example.com":[{"SPF":"v=spf1 -all exp=foobar.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.example.com"}],"somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.example.com":[{"TXT":"Congratulations!  That was tricky."}],"e4.example.com":[{"SPF":"v=spf1 -all exp=e4msg.example.com"}],"e4msg.example.com":[{"TXT":"%{c} is queried as %{ir}.%{v}.arpa"}],"e5.example.com":[{"SPF":"v=spf1 a:%{a}.example.com -all"}],"e6.example.com":[{"SPF":"v=spf1 -all exp=e6msg.example.com"}],"e6msg.example.com":[{"TXT":"connect from %{p}"}],"mx.example.com":[{"A":"192.168.218.41"},{"A":"192.168.218.42"},{"AAAA":"CAFE:BABE::2"},{"AAAA":"CAFE:BABE::3"}],"40.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"}],"41.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"}],"42.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"},{"PTR":"mx.e7.example.com"}],"1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.E.B.A.B.E.F.A.C.ip6.arpa":[{"PTR":"mx.example.com"}],"3.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.E.B.A.B.E.F.A.C.ip6.arpa":[{"PTR":"mx.example.com"}],"mx.e7.example.com":[{"A":"192.168.218.42"}],"mx.e7.example.com.should.example.com":[{"A":"127.0.0.2"}],"mx.example.com.ok.example.com":[{"A":"127.0.0.2"}],"e7.example.com":[{"SPF":"v=spf1 exists:%{p}.should.example.com ~exists:%{p}.ok.example.com"}],"e8.example.com":[{"SPF":"v=spf1 -all exp=msg8.%{D2}"}],"msg8.example.com":[{"TXT":"http://example.com/why.html?l=%{L}"}],"e9.example.com":[{"SPF":"v=spf1 a:%{H} -all"}],"e10.example.com":[{"SPF":"v=spf1 -include:_spfh.%{d2} ip4:1.2.3.0/24 -all"}],"_spfh.example.com":[{"SPF":"v=spf1 -a:%{h} +all"}],"e11.example.com":[{"SPF":"v=spf1 exists:%{i}.%{l2r-}.user.%{d2}"}],"1.2.3.4.gladstone.philip.user.example.com":[{"A":"127.0.0.2"}],"e12.example.com":[{"SPF":"v=spf1 exists:%{l2r+-}.user.%{d2}"}],"bar.foo.user.example.com":[{"A":"127.0.0.2"}]}, failOnNoFake: true});
        let promise = validator.validateSender('192.168.218.41');
        return promise.then((result) => {
          assert.equal(result, 'FAIL');
        });
      });
      it('p = the validated domain name of <ip>', function(){
        let email = 'test@e6.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"example.com.d.spf.example.com":[{"SPF":"v=spf1 redirect=a.spf.example.com"}],"a.spf.example.com":[{"SPF":"v=spf1 include:o.spf.example.com. ~all"}],"o.spf.example.com":[{"SPF":"v=spf1 ip4:192.168.218.40"}],"msgbas2x.cos.example.com":[{"A":"192.168.218.40"}],"example.com":[{"A":"192.168.90.76"},{"SPF":"v=spf1 redirect=%{d}.d.spf.example.com."}],"exp.example.com":[{"SPF":"v=spf1 exp=msg.example.com. -all"}],"msg.example.com":[{"TXT":"This is a test."}],"e1.example.com":[{"SPF":"v=spf1 -exists:%(ir).sbl.example.com ?all"}],"e1e.example.com":[{"SPF":"v=spf1 exists:foo%(ir).sbl.example.com ?all"}],"e1t.example.com":[{"SPF":"v=spf1 exists:foo%.sbl.example.com ?all"}],"e1a.example.com":[{"SPF":"v=spf1 a:macro%%percent%_%_space%-url-space.example.com -all"}],"macro%percent  space%20url-space.example.com":[{"A":"1.2.3.4"}],"e2.example.com":[{"SPF":"v=spf1 -all exp=%{r}.example.com"}],"e3.example.com":[{"SPF":"v=spf1 -all exp=%{ir}.example.com"}],"40.218.168.192.example.com":[{"TXT":"Connections from %{c} not authorized."}],"somewhat.long.exp.example.com":[{"SPF":"v=spf1 -all exp=foobar.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.example.com"}],"somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.example.com":[{"TXT":"Congratulations!  That was tricky."}],"e4.example.com":[{"SPF":"v=spf1 -all exp=e4msg.example.com"}],"e4msg.example.com":[{"TXT":"%{c} is queried as %{ir}.%{v}.arpa"}],"e5.example.com":[{"SPF":"v=spf1 a:%{a}.example.com -all"}],"e6.example.com":[{"SPF":"v=spf1 -all exp=e6msg.example.com"}],"e6msg.example.com":[{"TXT":"connect from %{p}"}],"mx.example.com":[{"A":"192.168.218.41"},{"A":"192.168.218.42"},{"AAAA":"CAFE:BABE::2"},{"AAAA":"CAFE:BABE::3"}],"40.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"}],"41.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"}],"42.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"},{"PTR":"mx.e7.example.com"}],"1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.E.B.A.B.E.F.A.C.ip6.arpa":[{"PTR":"mx.example.com"}],"3.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.E.B.A.B.E.F.A.C.ip6.arpa":[{"PTR":"mx.example.com"}],"mx.e7.example.com":[{"A":"192.168.218.42"}],"mx.e7.example.com.should.example.com":[{"A":"127.0.0.2"}],"mx.example.com.ok.example.com":[{"A":"127.0.0.2"}],"e7.example.com":[{"SPF":"v=spf1 exists:%{p}.should.example.com ~exists:%{p}.ok.example.com"}],"e8.example.com":[{"SPF":"v=spf1 -all exp=msg8.%{D2}"}],"msg8.example.com":[{"TXT":"http://example.com/why.html?l=%{L}"}],"e9.example.com":[{"SPF":"v=spf1 a:%{H} -all"}],"e10.example.com":[{"SPF":"v=spf1 -include:_spfh.%{d2} ip4:1.2.3.0/24 -all"}],"_spfh.example.com":[{"SPF":"v=spf1 -a:%{h} +all"}],"e11.example.com":[{"SPF":"v=spf1 exists:%{i}.%{l2r-}.user.%{d2}"}],"1.2.3.4.gladstone.philip.user.example.com":[{"A":"127.0.0.2"}],"e12.example.com":[{"SPF":"v=spf1 exists:%{l2r+-}.user.%{d2}"}],"bar.foo.user.example.com":[{"A":"127.0.0.2"}]}, failOnNoFake: true});
        let promise = validator.validateSender('CAFE:BABE::1');
        return promise.then((result) => {
          assert.equal(result, 'FAIL');
        });
      });
      it('p = the validated domain name of <ip>', function(){
        let email = 'test@e6.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"example.com.d.spf.example.com":[{"SPF":"v=spf1 redirect=a.spf.example.com"}],"a.spf.example.com":[{"SPF":"v=spf1 include:o.spf.example.com. ~all"}],"o.spf.example.com":[{"SPF":"v=spf1 ip4:192.168.218.40"}],"msgbas2x.cos.example.com":[{"A":"192.168.218.40"}],"example.com":[{"A":"192.168.90.76"},{"SPF":"v=spf1 redirect=%{d}.d.spf.example.com."}],"exp.example.com":[{"SPF":"v=spf1 exp=msg.example.com. -all"}],"msg.example.com":[{"TXT":"This is a test."}],"e1.example.com":[{"SPF":"v=spf1 -exists:%(ir).sbl.example.com ?all"}],"e1e.example.com":[{"SPF":"v=spf1 exists:foo%(ir).sbl.example.com ?all"}],"e1t.example.com":[{"SPF":"v=spf1 exists:foo%.sbl.example.com ?all"}],"e1a.example.com":[{"SPF":"v=spf1 a:macro%%percent%_%_space%-url-space.example.com -all"}],"macro%percent  space%20url-space.example.com":[{"A":"1.2.3.4"}],"e2.example.com":[{"SPF":"v=spf1 -all exp=%{r}.example.com"}],"e3.example.com":[{"SPF":"v=spf1 -all exp=%{ir}.example.com"}],"40.218.168.192.example.com":[{"TXT":"Connections from %{c} not authorized."}],"somewhat.long.exp.example.com":[{"SPF":"v=spf1 -all exp=foobar.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.example.com"}],"somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.example.com":[{"TXT":"Congratulations!  That was tricky."}],"e4.example.com":[{"SPF":"v=spf1 -all exp=e4msg.example.com"}],"e4msg.example.com":[{"TXT":"%{c} is queried as %{ir}.%{v}.arpa"}],"e5.example.com":[{"SPF":"v=spf1 a:%{a}.example.com -all"}],"e6.example.com":[{"SPF":"v=spf1 -all exp=e6msg.example.com"}],"e6msg.example.com":[{"TXT":"connect from %{p}"}],"mx.example.com":[{"A":"192.168.218.41"},{"A":"192.168.218.42"},{"AAAA":"CAFE:BABE::2"},{"AAAA":"CAFE:BABE::3"}],"40.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"}],"41.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"}],"42.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"},{"PTR":"mx.e7.example.com"}],"1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.E.B.A.B.E.F.A.C.ip6.arpa":[{"PTR":"mx.example.com"}],"3.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.E.B.A.B.E.F.A.C.ip6.arpa":[{"PTR":"mx.example.com"}],"mx.e7.example.com":[{"A":"192.168.218.42"}],"mx.e7.example.com.should.example.com":[{"A":"127.0.0.2"}],"mx.example.com.ok.example.com":[{"A":"127.0.0.2"}],"e7.example.com":[{"SPF":"v=spf1 exists:%{p}.should.example.com ~exists:%{p}.ok.example.com"}],"e8.example.com":[{"SPF":"v=spf1 -all exp=msg8.%{D2}"}],"msg8.example.com":[{"TXT":"http://example.com/why.html?l=%{L}"}],"e9.example.com":[{"SPF":"v=spf1 a:%{H} -all"}],"e10.example.com":[{"SPF":"v=spf1 -include:_spfh.%{d2} ip4:1.2.3.0/24 -all"}],"_spfh.example.com":[{"SPF":"v=spf1 -a:%{h} +all"}],"e11.example.com":[{"SPF":"v=spf1 exists:%{i}.%{l2r-}.user.%{d2}"}],"1.2.3.4.gladstone.philip.user.example.com":[{"A":"127.0.0.2"}],"e12.example.com":[{"SPF":"v=spf1 exists:%{l2r+-}.user.%{d2}"}],"bar.foo.user.example.com":[{"A":"127.0.0.2"}]}, failOnNoFake: true});
        let promise = validator.validateSender('CAFE:BABE::3');
        return promise.then((result) => {
          assert.equal(result, 'FAIL');
        });
      });
      it('p = the validated domain name of <ip>', function(){
        let email = 'test@e7.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"example.com.d.spf.example.com":[{"SPF":"v=spf1 redirect=a.spf.example.com"}],"a.spf.example.com":[{"SPF":"v=spf1 include:o.spf.example.com. ~all"}],"o.spf.example.com":[{"SPF":"v=spf1 ip4:192.168.218.40"}],"msgbas2x.cos.example.com":[{"A":"192.168.218.40"}],"example.com":[{"A":"192.168.90.76"},{"SPF":"v=spf1 redirect=%{d}.d.spf.example.com."}],"exp.example.com":[{"SPF":"v=spf1 exp=msg.example.com. -all"}],"msg.example.com":[{"TXT":"This is a test."}],"e1.example.com":[{"SPF":"v=spf1 -exists:%(ir).sbl.example.com ?all"}],"e1e.example.com":[{"SPF":"v=spf1 exists:foo%(ir).sbl.example.com ?all"}],"e1t.example.com":[{"SPF":"v=spf1 exists:foo%.sbl.example.com ?all"}],"e1a.example.com":[{"SPF":"v=spf1 a:macro%%percent%_%_space%-url-space.example.com -all"}],"macro%percent  space%20url-space.example.com":[{"A":"1.2.3.4"}],"e2.example.com":[{"SPF":"v=spf1 -all exp=%{r}.example.com"}],"e3.example.com":[{"SPF":"v=spf1 -all exp=%{ir}.example.com"}],"40.218.168.192.example.com":[{"TXT":"Connections from %{c} not authorized."}],"somewhat.long.exp.example.com":[{"SPF":"v=spf1 -all exp=foobar.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.example.com"}],"somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.example.com":[{"TXT":"Congratulations!  That was tricky."}],"e4.example.com":[{"SPF":"v=spf1 -all exp=e4msg.example.com"}],"e4msg.example.com":[{"TXT":"%{c} is queried as %{ir}.%{v}.arpa"}],"e5.example.com":[{"SPF":"v=spf1 a:%{a}.example.com -all"}],"e6.example.com":[{"SPF":"v=spf1 -all exp=e6msg.example.com"}],"e6msg.example.com":[{"TXT":"connect from %{p}"}],"mx.example.com":[{"A":"192.168.218.41"},{"A":"192.168.218.42"},{"AAAA":"CAFE:BABE::2"},{"AAAA":"CAFE:BABE::3"}],"40.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"}],"41.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"}],"42.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"},{"PTR":"mx.e7.example.com"}],"1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.E.B.A.B.E.F.A.C.ip6.arpa":[{"PTR":"mx.example.com"}],"3.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.E.B.A.B.E.F.A.C.ip6.arpa":[{"PTR":"mx.example.com"}],"mx.e7.example.com":[{"A":"192.168.218.42"}],"mx.e7.example.com.should.example.com":[{"A":"127.0.0.2"}],"mx.example.com.ok.example.com":[{"A":"127.0.0.2"}],"e7.example.com":[{"SPF":"v=spf1 exists:%{p}.should.example.com ~exists:%{p}.ok.example.com"}],"e8.example.com":[{"SPF":"v=spf1 -all exp=msg8.%{D2}"}],"msg8.example.com":[{"TXT":"http://example.com/why.html?l=%{L}"}],"e9.example.com":[{"SPF":"v=spf1 a:%{H} -all"}],"e10.example.com":[{"SPF":"v=spf1 -include:_spfh.%{d2} ip4:1.2.3.0/24 -all"}],"_spfh.example.com":[{"SPF":"v=spf1 -a:%{h} +all"}],"e11.example.com":[{"SPF":"v=spf1 exists:%{i}.%{l2r-}.user.%{d2}"}],"1.2.3.4.gladstone.philip.user.example.com":[{"A":"127.0.0.2"}],"e12.example.com":[{"SPF":"v=spf1 exists:%{l2r+-}.user.%{d2}"}],"bar.foo.user.example.com":[{"A":"127.0.0.2"}]}, failOnNoFake: true});
        let promise = validator.validateSender('192.168.218.42');
        return promise.then((result) => {
          assert.include(["pass","softfail"], result.toLowerCase());
        });
      });
      it('Uppercased macros expand exactly as their lowercased equivalents, and are then URL escaped.', function(){
        let email = 'jack&jill=up@e8.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"example.com.d.spf.example.com":[{"SPF":"v=spf1 redirect=a.spf.example.com"}],"a.spf.example.com":[{"SPF":"v=spf1 include:o.spf.example.com. ~all"}],"o.spf.example.com":[{"SPF":"v=spf1 ip4:192.168.218.40"}],"msgbas2x.cos.example.com":[{"A":"192.168.218.40"}],"example.com":[{"A":"192.168.90.76"},{"SPF":"v=spf1 redirect=%{d}.d.spf.example.com."}],"exp.example.com":[{"SPF":"v=spf1 exp=msg.example.com. -all"}],"msg.example.com":[{"TXT":"This is a test."}],"e1.example.com":[{"SPF":"v=spf1 -exists:%(ir).sbl.example.com ?all"}],"e1e.example.com":[{"SPF":"v=spf1 exists:foo%(ir).sbl.example.com ?all"}],"e1t.example.com":[{"SPF":"v=spf1 exists:foo%.sbl.example.com ?all"}],"e1a.example.com":[{"SPF":"v=spf1 a:macro%%percent%_%_space%-url-space.example.com -all"}],"macro%percent  space%20url-space.example.com":[{"A":"1.2.3.4"}],"e2.example.com":[{"SPF":"v=spf1 -all exp=%{r}.example.com"}],"e3.example.com":[{"SPF":"v=spf1 -all exp=%{ir}.example.com"}],"40.218.168.192.example.com":[{"TXT":"Connections from %{c} not authorized."}],"somewhat.long.exp.example.com":[{"SPF":"v=spf1 -all exp=foobar.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.example.com"}],"somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.example.com":[{"TXT":"Congratulations!  That was tricky."}],"e4.example.com":[{"SPF":"v=spf1 -all exp=e4msg.example.com"}],"e4msg.example.com":[{"TXT":"%{c} is queried as %{ir}.%{v}.arpa"}],"e5.example.com":[{"SPF":"v=spf1 a:%{a}.example.com -all"}],"e6.example.com":[{"SPF":"v=spf1 -all exp=e6msg.example.com"}],"e6msg.example.com":[{"TXT":"connect from %{p}"}],"mx.example.com":[{"A":"192.168.218.41"},{"A":"192.168.218.42"},{"AAAA":"CAFE:BABE::2"},{"AAAA":"CAFE:BABE::3"}],"40.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"}],"41.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"}],"42.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"},{"PTR":"mx.e7.example.com"}],"1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.E.B.A.B.E.F.A.C.ip6.arpa":[{"PTR":"mx.example.com"}],"3.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.E.B.A.B.E.F.A.C.ip6.arpa":[{"PTR":"mx.example.com"}],"mx.e7.example.com":[{"A":"192.168.218.42"}],"mx.e7.example.com.should.example.com":[{"A":"127.0.0.2"}],"mx.example.com.ok.example.com":[{"A":"127.0.0.2"}],"e7.example.com":[{"SPF":"v=spf1 exists:%{p}.should.example.com ~exists:%{p}.ok.example.com"}],"e8.example.com":[{"SPF":"v=spf1 -all exp=msg8.%{D2}"}],"msg8.example.com":[{"TXT":"http://example.com/why.html?l=%{L}"}],"e9.example.com":[{"SPF":"v=spf1 a:%{H} -all"}],"e10.example.com":[{"SPF":"v=spf1 -include:_spfh.%{d2} ip4:1.2.3.0/24 -all"}],"_spfh.example.com":[{"SPF":"v=spf1 -a:%{h} +all"}],"e11.example.com":[{"SPF":"v=spf1 exists:%{i}.%{l2r-}.user.%{d2}"}],"1.2.3.4.gladstone.philip.user.example.com":[{"A":"127.0.0.2"}],"e12.example.com":[{"SPF":"v=spf1 exists:%{l2r+-}.user.%{d2}"}],"bar.foo.user.example.com":[{"A":"127.0.0.2"}]}, failOnNoFake: true});
        let promise = validator.validateSender('192.168.218.42');
        return promise.then((result) => {
          assert.equal(result, 'FAIL');
        });
      });
      it('h = HELO/EHLO domain', function(){
        let email = 'test@e9.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"example.com.d.spf.example.com":[{"SPF":"v=spf1 redirect=a.spf.example.com"}],"a.spf.example.com":[{"SPF":"v=spf1 include:o.spf.example.com. ~all"}],"o.spf.example.com":[{"SPF":"v=spf1 ip4:192.168.218.40"}],"msgbas2x.cos.example.com":[{"A":"192.168.218.40"}],"example.com":[{"A":"192.168.90.76"},{"SPF":"v=spf1 redirect=%{d}.d.spf.example.com."}],"exp.example.com":[{"SPF":"v=spf1 exp=msg.example.com. -all"}],"msg.example.com":[{"TXT":"This is a test."}],"e1.example.com":[{"SPF":"v=spf1 -exists:%(ir).sbl.example.com ?all"}],"e1e.example.com":[{"SPF":"v=spf1 exists:foo%(ir).sbl.example.com ?all"}],"e1t.example.com":[{"SPF":"v=spf1 exists:foo%.sbl.example.com ?all"}],"e1a.example.com":[{"SPF":"v=spf1 a:macro%%percent%_%_space%-url-space.example.com -all"}],"macro%percent  space%20url-space.example.com":[{"A":"1.2.3.4"}],"e2.example.com":[{"SPF":"v=spf1 -all exp=%{r}.example.com"}],"e3.example.com":[{"SPF":"v=spf1 -all exp=%{ir}.example.com"}],"40.218.168.192.example.com":[{"TXT":"Connections from %{c} not authorized."}],"somewhat.long.exp.example.com":[{"SPF":"v=spf1 -all exp=foobar.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.example.com"}],"somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.example.com":[{"TXT":"Congratulations!  That was tricky."}],"e4.example.com":[{"SPF":"v=spf1 -all exp=e4msg.example.com"}],"e4msg.example.com":[{"TXT":"%{c} is queried as %{ir}.%{v}.arpa"}],"e5.example.com":[{"SPF":"v=spf1 a:%{a}.example.com -all"}],"e6.example.com":[{"SPF":"v=spf1 -all exp=e6msg.example.com"}],"e6msg.example.com":[{"TXT":"connect from %{p}"}],"mx.example.com":[{"A":"192.168.218.41"},{"A":"192.168.218.42"},{"AAAA":"CAFE:BABE::2"},{"AAAA":"CAFE:BABE::3"}],"40.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"}],"41.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"}],"42.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"},{"PTR":"mx.e7.example.com"}],"1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.E.B.A.B.E.F.A.C.ip6.arpa":[{"PTR":"mx.example.com"}],"3.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.E.B.A.B.E.F.A.C.ip6.arpa":[{"PTR":"mx.example.com"}],"mx.e7.example.com":[{"A":"192.168.218.42"}],"mx.e7.example.com.should.example.com":[{"A":"127.0.0.2"}],"mx.example.com.ok.example.com":[{"A":"127.0.0.2"}],"e7.example.com":[{"SPF":"v=spf1 exists:%{p}.should.example.com ~exists:%{p}.ok.example.com"}],"e8.example.com":[{"SPF":"v=spf1 -all exp=msg8.%{D2}"}],"msg8.example.com":[{"TXT":"http://example.com/why.html?l=%{L}"}],"e9.example.com":[{"SPF":"v=spf1 a:%{H} -all"}],"e10.example.com":[{"SPF":"v=spf1 -include:_spfh.%{d2} ip4:1.2.3.0/24 -all"}],"_spfh.example.com":[{"SPF":"v=spf1 -a:%{h} +all"}],"e11.example.com":[{"SPF":"v=spf1 exists:%{i}.%{l2r-}.user.%{d2}"}],"1.2.3.4.gladstone.philip.user.example.com":[{"A":"127.0.0.2"}],"e12.example.com":[{"SPF":"v=spf1 exists:%{l2r+-}.user.%{d2}"}],"bar.foo.user.example.com":[{"A":"127.0.0.2"}]}, failOnNoFake: true});
        let promise = validator.validateSender('192.168.218.40');
        return promise.then((result) => {
          assert.equal(result, 'PASS');
        });
      });
      it('h = HELO/EHLO domain, but HELO is invalid', function(){
        let email = 'test@e9.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"example.com.d.spf.example.com":[{"SPF":"v=spf1 redirect=a.spf.example.com"}],"a.spf.example.com":[{"SPF":"v=spf1 include:o.spf.example.com. ~all"}],"o.spf.example.com":[{"SPF":"v=spf1 ip4:192.168.218.40"}],"msgbas2x.cos.example.com":[{"A":"192.168.218.40"}],"example.com":[{"A":"192.168.90.76"},{"SPF":"v=spf1 redirect=%{d}.d.spf.example.com."}],"exp.example.com":[{"SPF":"v=spf1 exp=msg.example.com. -all"}],"msg.example.com":[{"TXT":"This is a test."}],"e1.example.com":[{"SPF":"v=spf1 -exists:%(ir).sbl.example.com ?all"}],"e1e.example.com":[{"SPF":"v=spf1 exists:foo%(ir).sbl.example.com ?all"}],"e1t.example.com":[{"SPF":"v=spf1 exists:foo%.sbl.example.com ?all"}],"e1a.example.com":[{"SPF":"v=spf1 a:macro%%percent%_%_space%-url-space.example.com -all"}],"macro%percent  space%20url-space.example.com":[{"A":"1.2.3.4"}],"e2.example.com":[{"SPF":"v=spf1 -all exp=%{r}.example.com"}],"e3.example.com":[{"SPF":"v=spf1 -all exp=%{ir}.example.com"}],"40.218.168.192.example.com":[{"TXT":"Connections from %{c} not authorized."}],"somewhat.long.exp.example.com":[{"SPF":"v=spf1 -all exp=foobar.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.example.com"}],"somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.example.com":[{"TXT":"Congratulations!  That was tricky."}],"e4.example.com":[{"SPF":"v=spf1 -all exp=e4msg.example.com"}],"e4msg.example.com":[{"TXT":"%{c} is queried as %{ir}.%{v}.arpa"}],"e5.example.com":[{"SPF":"v=spf1 a:%{a}.example.com -all"}],"e6.example.com":[{"SPF":"v=spf1 -all exp=e6msg.example.com"}],"e6msg.example.com":[{"TXT":"connect from %{p}"}],"mx.example.com":[{"A":"192.168.218.41"},{"A":"192.168.218.42"},{"AAAA":"CAFE:BABE::2"},{"AAAA":"CAFE:BABE::3"}],"40.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"}],"41.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"}],"42.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"},{"PTR":"mx.e7.example.com"}],"1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.E.B.A.B.E.F.A.C.ip6.arpa":[{"PTR":"mx.example.com"}],"3.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.E.B.A.B.E.F.A.C.ip6.arpa":[{"PTR":"mx.example.com"}],"mx.e7.example.com":[{"A":"192.168.218.42"}],"mx.e7.example.com.should.example.com":[{"A":"127.0.0.2"}],"mx.example.com.ok.example.com":[{"A":"127.0.0.2"}],"e7.example.com":[{"SPF":"v=spf1 exists:%{p}.should.example.com ~exists:%{p}.ok.example.com"}],"e8.example.com":[{"SPF":"v=spf1 -all exp=msg8.%{D2}"}],"msg8.example.com":[{"TXT":"http://example.com/why.html?l=%{L}"}],"e9.example.com":[{"SPF":"v=spf1 a:%{H} -all"}],"e10.example.com":[{"SPF":"v=spf1 -include:_spfh.%{d2} ip4:1.2.3.0/24 -all"}],"_spfh.example.com":[{"SPF":"v=spf1 -a:%{h} +all"}],"e11.example.com":[{"SPF":"v=spf1 exists:%{i}.%{l2r-}.user.%{d2}"}],"1.2.3.4.gladstone.philip.user.example.com":[{"A":"127.0.0.2"}],"e12.example.com":[{"SPF":"v=spf1 exists:%{l2r+-}.user.%{d2}"}],"bar.foo.user.example.com":[{"A":"127.0.0.2"}]}, failOnNoFake: true});
        let promise = validator.validateSender('192.168.218.40');
        return promise.then((result) => {
          assert.equal(result, 'FAIL');
        });
      });
      it('h = HELO/EHLO domain, but HELO is a domain literal', function(){
        let email = 'test@e9.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"example.com.d.spf.example.com":[{"SPF":"v=spf1 redirect=a.spf.example.com"}],"a.spf.example.com":[{"SPF":"v=spf1 include:o.spf.example.com. ~all"}],"o.spf.example.com":[{"SPF":"v=spf1 ip4:192.168.218.40"}],"msgbas2x.cos.example.com":[{"A":"192.168.218.40"}],"example.com":[{"A":"192.168.90.76"},{"SPF":"v=spf1 redirect=%{d}.d.spf.example.com."}],"exp.example.com":[{"SPF":"v=spf1 exp=msg.example.com. -all"}],"msg.example.com":[{"TXT":"This is a test."}],"e1.example.com":[{"SPF":"v=spf1 -exists:%(ir).sbl.example.com ?all"}],"e1e.example.com":[{"SPF":"v=spf1 exists:foo%(ir).sbl.example.com ?all"}],"e1t.example.com":[{"SPF":"v=spf1 exists:foo%.sbl.example.com ?all"}],"e1a.example.com":[{"SPF":"v=spf1 a:macro%%percent%_%_space%-url-space.example.com -all"}],"macro%percent  space%20url-space.example.com":[{"A":"1.2.3.4"}],"e2.example.com":[{"SPF":"v=spf1 -all exp=%{r}.example.com"}],"e3.example.com":[{"SPF":"v=spf1 -all exp=%{ir}.example.com"}],"40.218.168.192.example.com":[{"TXT":"Connections from %{c} not authorized."}],"somewhat.long.exp.example.com":[{"SPF":"v=spf1 -all exp=foobar.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.example.com"}],"somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.example.com":[{"TXT":"Congratulations!  That was tricky."}],"e4.example.com":[{"SPF":"v=spf1 -all exp=e4msg.example.com"}],"e4msg.example.com":[{"TXT":"%{c} is queried as %{ir}.%{v}.arpa"}],"e5.example.com":[{"SPF":"v=spf1 a:%{a}.example.com -all"}],"e6.example.com":[{"SPF":"v=spf1 -all exp=e6msg.example.com"}],"e6msg.example.com":[{"TXT":"connect from %{p}"}],"mx.example.com":[{"A":"192.168.218.41"},{"A":"192.168.218.42"},{"AAAA":"CAFE:BABE::2"},{"AAAA":"CAFE:BABE::3"}],"40.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"}],"41.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"}],"42.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"},{"PTR":"mx.e7.example.com"}],"1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.E.B.A.B.E.F.A.C.ip6.arpa":[{"PTR":"mx.example.com"}],"3.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.E.B.A.B.E.F.A.C.ip6.arpa":[{"PTR":"mx.example.com"}],"mx.e7.example.com":[{"A":"192.168.218.42"}],"mx.e7.example.com.should.example.com":[{"A":"127.0.0.2"}],"mx.example.com.ok.example.com":[{"A":"127.0.0.2"}],"e7.example.com":[{"SPF":"v=spf1 exists:%{p}.should.example.com ~exists:%{p}.ok.example.com"}],"e8.example.com":[{"SPF":"v=spf1 -all exp=msg8.%{D2}"}],"msg8.example.com":[{"TXT":"http://example.com/why.html?l=%{L}"}],"e9.example.com":[{"SPF":"v=spf1 a:%{H} -all"}],"e10.example.com":[{"SPF":"v=spf1 -include:_spfh.%{d2} ip4:1.2.3.0/24 -all"}],"_spfh.example.com":[{"SPF":"v=spf1 -a:%{h} +all"}],"e11.example.com":[{"SPF":"v=spf1 exists:%{i}.%{l2r-}.user.%{d2}"}],"1.2.3.4.gladstone.philip.user.example.com":[{"A":"127.0.0.2"}],"e12.example.com":[{"SPF":"v=spf1 exists:%{l2r+-}.user.%{d2}"}],"bar.foo.user.example.com":[{"A":"127.0.0.2"}]}, failOnNoFake: true});
        let promise = validator.validateSender('192.168.218.40');
        return promise.then((result) => {
          assert.equal(result, 'FAIL');
        });
      });
      it('Example of requiring valid helo in sender policy.  This is a complex policy testing several points at once.', function(){
        let email = 'test@e10.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"example.com.d.spf.example.com":[{"SPF":"v=spf1 redirect=a.spf.example.com"}],"a.spf.example.com":[{"SPF":"v=spf1 include:o.spf.example.com. ~all"}],"o.spf.example.com":[{"SPF":"v=spf1 ip4:192.168.218.40"}],"msgbas2x.cos.example.com":[{"A":"192.168.218.40"}],"example.com":[{"A":"192.168.90.76"},{"SPF":"v=spf1 redirect=%{d}.d.spf.example.com."}],"exp.example.com":[{"SPF":"v=spf1 exp=msg.example.com. -all"}],"msg.example.com":[{"TXT":"This is a test."}],"e1.example.com":[{"SPF":"v=spf1 -exists:%(ir).sbl.example.com ?all"}],"e1e.example.com":[{"SPF":"v=spf1 exists:foo%(ir).sbl.example.com ?all"}],"e1t.example.com":[{"SPF":"v=spf1 exists:foo%.sbl.example.com ?all"}],"e1a.example.com":[{"SPF":"v=spf1 a:macro%%percent%_%_space%-url-space.example.com -all"}],"macro%percent  space%20url-space.example.com":[{"A":"1.2.3.4"}],"e2.example.com":[{"SPF":"v=spf1 -all exp=%{r}.example.com"}],"e3.example.com":[{"SPF":"v=spf1 -all exp=%{ir}.example.com"}],"40.218.168.192.example.com":[{"TXT":"Connections from %{c} not authorized."}],"somewhat.long.exp.example.com":[{"SPF":"v=spf1 -all exp=foobar.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.example.com"}],"somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.example.com":[{"TXT":"Congratulations!  That was tricky."}],"e4.example.com":[{"SPF":"v=spf1 -all exp=e4msg.example.com"}],"e4msg.example.com":[{"TXT":"%{c} is queried as %{ir}.%{v}.arpa"}],"e5.example.com":[{"SPF":"v=spf1 a:%{a}.example.com -all"}],"e6.example.com":[{"SPF":"v=spf1 -all exp=e6msg.example.com"}],"e6msg.example.com":[{"TXT":"connect from %{p}"}],"mx.example.com":[{"A":"192.168.218.41"},{"A":"192.168.218.42"},{"AAAA":"CAFE:BABE::2"},{"AAAA":"CAFE:BABE::3"}],"40.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"}],"41.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"}],"42.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"},{"PTR":"mx.e7.example.com"}],"1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.E.B.A.B.E.F.A.C.ip6.arpa":[{"PTR":"mx.example.com"}],"3.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.E.B.A.B.E.F.A.C.ip6.arpa":[{"PTR":"mx.example.com"}],"mx.e7.example.com":[{"A":"192.168.218.42"}],"mx.e7.example.com.should.example.com":[{"A":"127.0.0.2"}],"mx.example.com.ok.example.com":[{"A":"127.0.0.2"}],"e7.example.com":[{"SPF":"v=spf1 exists:%{p}.should.example.com ~exists:%{p}.ok.example.com"}],"e8.example.com":[{"SPF":"v=spf1 -all exp=msg8.%{D2}"}],"msg8.example.com":[{"TXT":"http://example.com/why.html?l=%{L}"}],"e9.example.com":[{"SPF":"v=spf1 a:%{H} -all"}],"e10.example.com":[{"SPF":"v=spf1 -include:_spfh.%{d2} ip4:1.2.3.0/24 -all"}],"_spfh.example.com":[{"SPF":"v=spf1 -a:%{h} +all"}],"e11.example.com":[{"SPF":"v=spf1 exists:%{i}.%{l2r-}.user.%{d2}"}],"1.2.3.4.gladstone.philip.user.example.com":[{"A":"127.0.0.2"}],"e12.example.com":[{"SPF":"v=spf1 exists:%{l2r+-}.user.%{d2}"}],"bar.foo.user.example.com":[{"A":"127.0.0.2"}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.4');
        return promise.then((result) => {
          assert.equal(result, 'FAIL');
        });
      });
      it('Macro value transformation (splitting on arbitrary characters, reversal, number of right-hand parts to use)', function(){
        let email = 'philip-gladstone-test@e11.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"example.com.d.spf.example.com":[{"SPF":"v=spf1 redirect=a.spf.example.com"}],"a.spf.example.com":[{"SPF":"v=spf1 include:o.spf.example.com. ~all"}],"o.spf.example.com":[{"SPF":"v=spf1 ip4:192.168.218.40"}],"msgbas2x.cos.example.com":[{"A":"192.168.218.40"}],"example.com":[{"A":"192.168.90.76"},{"SPF":"v=spf1 redirect=%{d}.d.spf.example.com."}],"exp.example.com":[{"SPF":"v=spf1 exp=msg.example.com. -all"}],"msg.example.com":[{"TXT":"This is a test."}],"e1.example.com":[{"SPF":"v=spf1 -exists:%(ir).sbl.example.com ?all"}],"e1e.example.com":[{"SPF":"v=spf1 exists:foo%(ir).sbl.example.com ?all"}],"e1t.example.com":[{"SPF":"v=spf1 exists:foo%.sbl.example.com ?all"}],"e1a.example.com":[{"SPF":"v=spf1 a:macro%%percent%_%_space%-url-space.example.com -all"}],"macro%percent  space%20url-space.example.com":[{"A":"1.2.3.4"}],"e2.example.com":[{"SPF":"v=spf1 -all exp=%{r}.example.com"}],"e3.example.com":[{"SPF":"v=spf1 -all exp=%{ir}.example.com"}],"40.218.168.192.example.com":[{"TXT":"Connections from %{c} not authorized."}],"somewhat.long.exp.example.com":[{"SPF":"v=spf1 -all exp=foobar.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.example.com"}],"somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.example.com":[{"TXT":"Congratulations!  That was tricky."}],"e4.example.com":[{"SPF":"v=spf1 -all exp=e4msg.example.com"}],"e4msg.example.com":[{"TXT":"%{c} is queried as %{ir}.%{v}.arpa"}],"e5.example.com":[{"SPF":"v=spf1 a:%{a}.example.com -all"}],"e6.example.com":[{"SPF":"v=spf1 -all exp=e6msg.example.com"}],"e6msg.example.com":[{"TXT":"connect from %{p}"}],"mx.example.com":[{"A":"192.168.218.41"},{"A":"192.168.218.42"},{"AAAA":"CAFE:BABE::2"},{"AAAA":"CAFE:BABE::3"}],"40.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"}],"41.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"}],"42.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"},{"PTR":"mx.e7.example.com"}],"1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.E.B.A.B.E.F.A.C.ip6.arpa":[{"PTR":"mx.example.com"}],"3.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.E.B.A.B.E.F.A.C.ip6.arpa":[{"PTR":"mx.example.com"}],"mx.e7.example.com":[{"A":"192.168.218.42"}],"mx.e7.example.com.should.example.com":[{"A":"127.0.0.2"}],"mx.example.com.ok.example.com":[{"A":"127.0.0.2"}],"e7.example.com":[{"SPF":"v=spf1 exists:%{p}.should.example.com ~exists:%{p}.ok.example.com"}],"e8.example.com":[{"SPF":"v=spf1 -all exp=msg8.%{D2}"}],"msg8.example.com":[{"TXT":"http://example.com/why.html?l=%{L}"}],"e9.example.com":[{"SPF":"v=spf1 a:%{H} -all"}],"e10.example.com":[{"SPF":"v=spf1 -include:_spfh.%{d2} ip4:1.2.3.0/24 -all"}],"_spfh.example.com":[{"SPF":"v=spf1 -a:%{h} +all"}],"e11.example.com":[{"SPF":"v=spf1 exists:%{i}.%{l2r-}.user.%{d2}"}],"1.2.3.4.gladstone.philip.user.example.com":[{"A":"127.0.0.2"}],"e12.example.com":[{"SPF":"v=spf1 exists:%{l2r+-}.user.%{d2}"}],"bar.foo.user.example.com":[{"A":"127.0.0.2"}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.4');
        return promise.then((result) => {
          assert.equal(result, 'PASS');
        });
      });
      it('Multiple delimiters may be specified in a macro expression.   macro-expand = ( "%{" macro-letter transformers *delimiter "}" )                  / "%%" / "%_" / "%-"', function(){
        let email = 'foo-bar+zip+quux@e12.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"example.com.d.spf.example.com":[{"SPF":"v=spf1 redirect=a.spf.example.com"}],"a.spf.example.com":[{"SPF":"v=spf1 include:o.spf.example.com. ~all"}],"o.spf.example.com":[{"SPF":"v=spf1 ip4:192.168.218.40"}],"msgbas2x.cos.example.com":[{"A":"192.168.218.40"}],"example.com":[{"A":"192.168.90.76"},{"SPF":"v=spf1 redirect=%{d}.d.spf.example.com."}],"exp.example.com":[{"SPF":"v=spf1 exp=msg.example.com. -all"}],"msg.example.com":[{"TXT":"This is a test."}],"e1.example.com":[{"SPF":"v=spf1 -exists:%(ir).sbl.example.com ?all"}],"e1e.example.com":[{"SPF":"v=spf1 exists:foo%(ir).sbl.example.com ?all"}],"e1t.example.com":[{"SPF":"v=spf1 exists:foo%.sbl.example.com ?all"}],"e1a.example.com":[{"SPF":"v=spf1 a:macro%%percent%_%_space%-url-space.example.com -all"}],"macro%percent  space%20url-space.example.com":[{"A":"1.2.3.4"}],"e2.example.com":[{"SPF":"v=spf1 -all exp=%{r}.example.com"}],"e3.example.com":[{"SPF":"v=spf1 -all exp=%{ir}.example.com"}],"40.218.168.192.example.com":[{"TXT":"Connections from %{c} not authorized."}],"somewhat.long.exp.example.com":[{"SPF":"v=spf1 -all exp=foobar.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.example.com"}],"somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.example.com":[{"TXT":"Congratulations!  That was tricky."}],"e4.example.com":[{"SPF":"v=spf1 -all exp=e4msg.example.com"}],"e4msg.example.com":[{"TXT":"%{c} is queried as %{ir}.%{v}.arpa"}],"e5.example.com":[{"SPF":"v=spf1 a:%{a}.example.com -all"}],"e6.example.com":[{"SPF":"v=spf1 -all exp=e6msg.example.com"}],"e6msg.example.com":[{"TXT":"connect from %{p}"}],"mx.example.com":[{"A":"192.168.218.41"},{"A":"192.168.218.42"},{"AAAA":"CAFE:BABE::2"},{"AAAA":"CAFE:BABE::3"}],"40.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"}],"41.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"}],"42.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"},{"PTR":"mx.e7.example.com"}],"1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.E.B.A.B.E.F.A.C.ip6.arpa":[{"PTR":"mx.example.com"}],"3.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.E.B.A.B.E.F.A.C.ip6.arpa":[{"PTR":"mx.example.com"}],"mx.e7.example.com":[{"A":"192.168.218.42"}],"mx.e7.example.com.should.example.com":[{"A":"127.0.0.2"}],"mx.example.com.ok.example.com":[{"A":"127.0.0.2"}],"e7.example.com":[{"SPF":"v=spf1 exists:%{p}.should.example.com ~exists:%{p}.ok.example.com"}],"e8.example.com":[{"SPF":"v=spf1 -all exp=msg8.%{D2}"}],"msg8.example.com":[{"TXT":"http://example.com/why.html?l=%{L}"}],"e9.example.com":[{"SPF":"v=spf1 a:%{H} -all"}],"e10.example.com":[{"SPF":"v=spf1 -include:_spfh.%{d2} ip4:1.2.3.0/24 -all"}],"_spfh.example.com":[{"SPF":"v=spf1 -a:%{h} +all"}],"e11.example.com":[{"SPF":"v=spf1 exists:%{i}.%{l2r-}.user.%{d2}"}],"1.2.3.4.gladstone.philip.user.example.com":[{"A":"127.0.0.2"}],"e12.example.com":[{"SPF":"v=spf1 exists:%{l2r+-}.user.%{d2}"}],"bar.foo.user.example.com":[{"A":"127.0.0.2"}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.4');
        return promise.then((result) => {
          assert.equal(result, 'PASS');
        });
      });
    });
    describe('Processing limits', function(){
      it('SPF implementations MUST limit the number of mechanisms and modifiers that do DNS lookups to at most 10 per SPF check.', function(){
        let email = 'foo@e1.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 ip4:1.1.1.1 redirect=e1.example.com"},{"A":"1.2.3.6"}],"e2.example.com":[{"SPF":"v=spf1 include:e3.example.com"},{"A":"1.2.3.7"}],"e3.example.com":[{"SPF":"v=spf1 include:e2.example.com"},{"A":"1.2.3.8"}],"e4.example.com":[{"SPF":"v=spf1 mx"},{"MX":[0,"mail.example.com"]},{"MX":[1,"mail.example.com"]},{"MX":[2,"mail.example.com"]},{"MX":[3,"mail.example.com"]},{"MX":[4,"mail.example.com"]},{"MX":[5,"mail.example.com"]},{"MX":[6,"mail.example.com"]},{"MX":[7,"mail.example.com"]},{"MX":[8,"mail.example.com"]},{"MX":[9,"mail.example.com"]},{"MX":[10,"e4.example.com"]},{"A":"1.2.3.5"}],"e5.example.com":[{"SPF":"v=spf1 ptr"},{"A":"1.2.3.5"}],"5.3.2.1.in-addr.arpa":[{"PTR":"e1.example.com."},{"PTR":"e2.example.com."},{"PTR":"e3.example.com."},{"PTR":"e4.example.com."},{"PTR":"example.com."},{"PTR":"e6.example.com."},{"PTR":"e7.example.com."},{"PTR":"e8.example.com."},{"PTR":"e9.example.com."},{"PTR":"e10.example.com."},{"PTR":"e5.example.com."}],"e6.example.com":[{"SPF":"v=spf1 a mx a mx a mx a mx a ptr ip4:1.2.3.4 -all"},{"A":"1.2.3.8"},{"MX":[10,"e6.example.com"]}],"e7.example.com":[{"SPF":"v=spf1 a mx a mx a mx a mx a ptr a ip4:1.2.3.4 -all"},{"A":"1.2.3.20"}],"e8.example.com":[{"SPF":"v=spf1 a include:inc.example.com ip4:1.2.3.4 mx -all"},{"A":"1.2.3.4"}],"inc.example.com":[{"SPF":"v=spf1 a a a a a a a a"},{"A":"1.2.3.10"}],"e9.example.com":[{"SPF":"v=spf1 a include:inc.example.com a ip4:1.2.3.4 -all"},{"A":"1.2.3.21"}],"e10.example.com":[{"SPF":"v=spf1 a -all"},{"A":"1.2.3.1"},{"A":"1.2.3.2"},{"A":"1.2.3.3"},{"A":"1.2.3.4"},{"A":"1.2.3.5"},{"A":"1.2.3.6"},{"A":"1.2.3.7"},{"A":"1.2.3.8"},{"A":"1.2.3.9"},{"A":"1.2.3.10"},{"A":"1.2.3.11"},{"A":"1.2.3.12"}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.4');
        return promise.then((result) => {
          assert.equal(result, 'PERMERROR');
        });
      });
      it('SPF implementations MUST limit the number of mechanisms and modifiers that do DNS lookups to at most 10 per SPF check.', function(){
        let email = 'foo@e2.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 ip4:1.1.1.1 redirect=e1.example.com"},{"A":"1.2.3.6"}],"e2.example.com":[{"SPF":"v=spf1 include:e3.example.com"},{"A":"1.2.3.7"}],"e3.example.com":[{"SPF":"v=spf1 include:e2.example.com"},{"A":"1.2.3.8"}],"e4.example.com":[{"SPF":"v=spf1 mx"},{"MX":[0,"mail.example.com"]},{"MX":[1,"mail.example.com"]},{"MX":[2,"mail.example.com"]},{"MX":[3,"mail.example.com"]},{"MX":[4,"mail.example.com"]},{"MX":[5,"mail.example.com"]},{"MX":[6,"mail.example.com"]},{"MX":[7,"mail.example.com"]},{"MX":[8,"mail.example.com"]},{"MX":[9,"mail.example.com"]},{"MX":[10,"e4.example.com"]},{"A":"1.2.3.5"}],"e5.example.com":[{"SPF":"v=spf1 ptr"},{"A":"1.2.3.5"}],"5.3.2.1.in-addr.arpa":[{"PTR":"e1.example.com."},{"PTR":"e2.example.com."},{"PTR":"e3.example.com."},{"PTR":"e4.example.com."},{"PTR":"example.com."},{"PTR":"e6.example.com."},{"PTR":"e7.example.com."},{"PTR":"e8.example.com."},{"PTR":"e9.example.com."},{"PTR":"e10.example.com."},{"PTR":"e5.example.com."}],"e6.example.com":[{"SPF":"v=spf1 a mx a mx a mx a mx a ptr ip4:1.2.3.4 -all"},{"A":"1.2.3.8"},{"MX":[10,"e6.example.com"]}],"e7.example.com":[{"SPF":"v=spf1 a mx a mx a mx a mx a ptr a ip4:1.2.3.4 -all"},{"A":"1.2.3.20"}],"e8.example.com":[{"SPF":"v=spf1 a include:inc.example.com ip4:1.2.3.4 mx -all"},{"A":"1.2.3.4"}],"inc.example.com":[{"SPF":"v=spf1 a a a a a a a a"},{"A":"1.2.3.10"}],"e9.example.com":[{"SPF":"v=spf1 a include:inc.example.com a ip4:1.2.3.4 -all"},{"A":"1.2.3.21"}],"e10.example.com":[{"SPF":"v=spf1 a -all"},{"A":"1.2.3.1"},{"A":"1.2.3.2"},{"A":"1.2.3.3"},{"A":"1.2.3.4"},{"A":"1.2.3.5"},{"A":"1.2.3.6"},{"A":"1.2.3.7"},{"A":"1.2.3.8"},{"A":"1.2.3.9"},{"A":"1.2.3.10"},{"A":"1.2.3.11"},{"A":"1.2.3.12"}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.4');
        return promise.then((result) => {
          assert.equal(result, 'PERMERROR');
        });
      });
      it('there MUST be a limit of no more than 10 MX looked up and checked.', function(){
        let email = 'foo@e4.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 ip4:1.1.1.1 redirect=e1.example.com"},{"A":"1.2.3.6"}],"e2.example.com":[{"SPF":"v=spf1 include:e3.example.com"},{"A":"1.2.3.7"}],"e3.example.com":[{"SPF":"v=spf1 include:e2.example.com"},{"A":"1.2.3.8"}],"e4.example.com":[{"SPF":"v=spf1 mx"},{"MX":[0,"mail.example.com"]},{"MX":[1,"mail.example.com"]},{"MX":[2,"mail.example.com"]},{"MX":[3,"mail.example.com"]},{"MX":[4,"mail.example.com"]},{"MX":[5,"mail.example.com"]},{"MX":[6,"mail.example.com"]},{"MX":[7,"mail.example.com"]},{"MX":[8,"mail.example.com"]},{"MX":[9,"mail.example.com"]},{"MX":[10,"e4.example.com"]},{"A":"1.2.3.5"}],"e5.example.com":[{"SPF":"v=spf1 ptr"},{"A":"1.2.3.5"}],"5.3.2.1.in-addr.arpa":[{"PTR":"e1.example.com."},{"PTR":"e2.example.com."},{"PTR":"e3.example.com."},{"PTR":"e4.example.com."},{"PTR":"example.com."},{"PTR":"e6.example.com."},{"PTR":"e7.example.com."},{"PTR":"e8.example.com."},{"PTR":"e9.example.com."},{"PTR":"e10.example.com."},{"PTR":"e5.example.com."}],"e6.example.com":[{"SPF":"v=spf1 a mx a mx a mx a mx a ptr ip4:1.2.3.4 -all"},{"A":"1.2.3.8"},{"MX":[10,"e6.example.com"]}],"e7.example.com":[{"SPF":"v=spf1 a mx a mx a mx a mx a ptr a ip4:1.2.3.4 -all"},{"A":"1.2.3.20"}],"e8.example.com":[{"SPF":"v=spf1 a include:inc.example.com ip4:1.2.3.4 mx -all"},{"A":"1.2.3.4"}],"inc.example.com":[{"SPF":"v=spf1 a a a a a a a a"},{"A":"1.2.3.10"}],"e9.example.com":[{"SPF":"v=spf1 a include:inc.example.com a ip4:1.2.3.4 -all"},{"A":"1.2.3.21"}],"e10.example.com":[{"SPF":"v=spf1 a -all"},{"A":"1.2.3.1"},{"A":"1.2.3.2"},{"A":"1.2.3.3"},{"A":"1.2.3.4"},{"A":"1.2.3.5"},{"A":"1.2.3.6"},{"A":"1.2.3.7"},{"A":"1.2.3.8"},{"A":"1.2.3.9"},{"A":"1.2.3.10"},{"A":"1.2.3.11"},{"A":"1.2.3.12"}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.5');
        return promise.then((result) => {
          assert.include(["neutral","pass","permerror"], result.toLowerCase());
        });
      });
      it('there MUST be a limit of no more than 10 PTR looked up and checked.', function(){
        let email = 'foo@e5.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 ip4:1.1.1.1 redirect=e1.example.com"},{"A":"1.2.3.6"}],"e2.example.com":[{"SPF":"v=spf1 include:e3.example.com"},{"A":"1.2.3.7"}],"e3.example.com":[{"SPF":"v=spf1 include:e2.example.com"},{"A":"1.2.3.8"}],"e4.example.com":[{"SPF":"v=spf1 mx"},{"MX":[0,"mail.example.com"]},{"MX":[1,"mail.example.com"]},{"MX":[2,"mail.example.com"]},{"MX":[3,"mail.example.com"]},{"MX":[4,"mail.example.com"]},{"MX":[5,"mail.example.com"]},{"MX":[6,"mail.example.com"]},{"MX":[7,"mail.example.com"]},{"MX":[8,"mail.example.com"]},{"MX":[9,"mail.example.com"]},{"MX":[10,"e4.example.com"]},{"A":"1.2.3.5"}],"e5.example.com":[{"SPF":"v=spf1 ptr"},{"A":"1.2.3.5"}],"5.3.2.1.in-addr.arpa":[{"PTR":"e1.example.com."},{"PTR":"e2.example.com."},{"PTR":"e3.example.com."},{"PTR":"e4.example.com."},{"PTR":"example.com."},{"PTR":"e6.example.com."},{"PTR":"e7.example.com."},{"PTR":"e8.example.com."},{"PTR":"e9.example.com."},{"PTR":"e10.example.com."},{"PTR":"e5.example.com."}],"e6.example.com":[{"SPF":"v=spf1 a mx a mx a mx a mx a ptr ip4:1.2.3.4 -all"},{"A":"1.2.3.8"},{"MX":[10,"e6.example.com"]}],"e7.example.com":[{"SPF":"v=spf1 a mx a mx a mx a mx a ptr a ip4:1.2.3.4 -all"},{"A":"1.2.3.20"}],"e8.example.com":[{"SPF":"v=spf1 a include:inc.example.com ip4:1.2.3.4 mx -all"},{"A":"1.2.3.4"}],"inc.example.com":[{"SPF":"v=spf1 a a a a a a a a"},{"A":"1.2.3.10"}],"e9.example.com":[{"SPF":"v=spf1 a include:inc.example.com a ip4:1.2.3.4 -all"},{"A":"1.2.3.21"}],"e10.example.com":[{"SPF":"v=spf1 a -all"},{"A":"1.2.3.1"},{"A":"1.2.3.2"},{"A":"1.2.3.3"},{"A":"1.2.3.4"},{"A":"1.2.3.5"},{"A":"1.2.3.6"},{"A":"1.2.3.7"},{"A":"1.2.3.8"},{"A":"1.2.3.9"},{"A":"1.2.3.10"},{"A":"1.2.3.11"},{"A":"1.2.3.12"}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.5');
        return promise.then((result) => {
          assert.include(["neutral","pass"], result.toLowerCase());
        });
      });
      it('unlike MX, PTR, there is no RR limit for A', function(){
        let email = 'foo@e10.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 ip4:1.1.1.1 redirect=e1.example.com"},{"A":"1.2.3.6"}],"e2.example.com":[{"SPF":"v=spf1 include:e3.example.com"},{"A":"1.2.3.7"}],"e3.example.com":[{"SPF":"v=spf1 include:e2.example.com"},{"A":"1.2.3.8"}],"e4.example.com":[{"SPF":"v=spf1 mx"},{"MX":[0,"mail.example.com"]},{"MX":[1,"mail.example.com"]},{"MX":[2,"mail.example.com"]},{"MX":[3,"mail.example.com"]},{"MX":[4,"mail.example.com"]},{"MX":[5,"mail.example.com"]},{"MX":[6,"mail.example.com"]},{"MX":[7,"mail.example.com"]},{"MX":[8,"mail.example.com"]},{"MX":[9,"mail.example.com"]},{"MX":[10,"e4.example.com"]},{"A":"1.2.3.5"}],"e5.example.com":[{"SPF":"v=spf1 ptr"},{"A":"1.2.3.5"}],"5.3.2.1.in-addr.arpa":[{"PTR":"e1.example.com."},{"PTR":"e2.example.com."},{"PTR":"e3.example.com."},{"PTR":"e4.example.com."},{"PTR":"example.com."},{"PTR":"e6.example.com."},{"PTR":"e7.example.com."},{"PTR":"e8.example.com."},{"PTR":"e9.example.com."},{"PTR":"e10.example.com."},{"PTR":"e5.example.com."}],"e6.example.com":[{"SPF":"v=spf1 a mx a mx a mx a mx a ptr ip4:1.2.3.4 -all"},{"A":"1.2.3.8"},{"MX":[10,"e6.example.com"]}],"e7.example.com":[{"SPF":"v=spf1 a mx a mx a mx a mx a ptr a ip4:1.2.3.4 -all"},{"A":"1.2.3.20"}],"e8.example.com":[{"SPF":"v=spf1 a include:inc.example.com ip4:1.2.3.4 mx -all"},{"A":"1.2.3.4"}],"inc.example.com":[{"SPF":"v=spf1 a a a a a a a a"},{"A":"1.2.3.10"}],"e9.example.com":[{"SPF":"v=spf1 a include:inc.example.com a ip4:1.2.3.4 -all"},{"A":"1.2.3.21"}],"e10.example.com":[{"SPF":"v=spf1 a -all"},{"A":"1.2.3.1"},{"A":"1.2.3.2"},{"A":"1.2.3.3"},{"A":"1.2.3.4"},{"A":"1.2.3.5"},{"A":"1.2.3.6"},{"A":"1.2.3.7"},{"A":"1.2.3.8"},{"A":"1.2.3.9"},{"A":"1.2.3.10"},{"A":"1.2.3.11"},{"A":"1.2.3.12"}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.12');
        return promise.then((result) => {
          assert.equal(result, 'PASS');
        });
      });
      it('SPF implementations MUST limit the number of mechanisms and modifiers that do DNS lookups to at most 10 per SPF check.', function(){
        let email = 'foo@e6.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 ip4:1.1.1.1 redirect=e1.example.com"},{"A":"1.2.3.6"}],"e2.example.com":[{"SPF":"v=spf1 include:e3.example.com"},{"A":"1.2.3.7"}],"e3.example.com":[{"SPF":"v=spf1 include:e2.example.com"},{"A":"1.2.3.8"}],"e4.example.com":[{"SPF":"v=spf1 mx"},{"MX":[0,"mail.example.com"]},{"MX":[1,"mail.example.com"]},{"MX":[2,"mail.example.com"]},{"MX":[3,"mail.example.com"]},{"MX":[4,"mail.example.com"]},{"MX":[5,"mail.example.com"]},{"MX":[6,"mail.example.com"]},{"MX":[7,"mail.example.com"]},{"MX":[8,"mail.example.com"]},{"MX":[9,"mail.example.com"]},{"MX":[10,"e4.example.com"]},{"A":"1.2.3.5"}],"e5.example.com":[{"SPF":"v=spf1 ptr"},{"A":"1.2.3.5"}],"5.3.2.1.in-addr.arpa":[{"PTR":"e1.example.com."},{"PTR":"e2.example.com."},{"PTR":"e3.example.com."},{"PTR":"e4.example.com."},{"PTR":"example.com."},{"PTR":"e6.example.com."},{"PTR":"e7.example.com."},{"PTR":"e8.example.com."},{"PTR":"e9.example.com."},{"PTR":"e10.example.com."},{"PTR":"e5.example.com."}],"e6.example.com":[{"SPF":"v=spf1 a mx a mx a mx a mx a ptr ip4:1.2.3.4 -all"},{"A":"1.2.3.8"},{"MX":[10,"e6.example.com"]}],"e7.example.com":[{"SPF":"v=spf1 a mx a mx a mx a mx a ptr a ip4:1.2.3.4 -all"},{"A":"1.2.3.20"}],"e8.example.com":[{"SPF":"v=spf1 a include:inc.example.com ip4:1.2.3.4 mx -all"},{"A":"1.2.3.4"}],"inc.example.com":[{"SPF":"v=spf1 a a a a a a a a"},{"A":"1.2.3.10"}],"e9.example.com":[{"SPF":"v=spf1 a include:inc.example.com a ip4:1.2.3.4 -all"},{"A":"1.2.3.21"}],"e10.example.com":[{"SPF":"v=spf1 a -all"},{"A":"1.2.3.1"},{"A":"1.2.3.2"},{"A":"1.2.3.3"},{"A":"1.2.3.4"},{"A":"1.2.3.5"},{"A":"1.2.3.6"},{"A":"1.2.3.7"},{"A":"1.2.3.8"},{"A":"1.2.3.9"},{"A":"1.2.3.10"},{"A":"1.2.3.11"},{"A":"1.2.3.12"}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.4');
        return promise.then((result) => {
          assert.equal(result, 'PASS');
        });
      });
      it('SPF implementations MUST limit the number of mechanisms and modifiers that do DNS lookups to at most 10 per SPF check.', function(){
        let email = 'foo@e7.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 ip4:1.1.1.1 redirect=e1.example.com"},{"A":"1.2.3.6"}],"e2.example.com":[{"SPF":"v=spf1 include:e3.example.com"},{"A":"1.2.3.7"}],"e3.example.com":[{"SPF":"v=spf1 include:e2.example.com"},{"A":"1.2.3.8"}],"e4.example.com":[{"SPF":"v=spf1 mx"},{"MX":[0,"mail.example.com"]},{"MX":[1,"mail.example.com"]},{"MX":[2,"mail.example.com"]},{"MX":[3,"mail.example.com"]},{"MX":[4,"mail.example.com"]},{"MX":[5,"mail.example.com"]},{"MX":[6,"mail.example.com"]},{"MX":[7,"mail.example.com"]},{"MX":[8,"mail.example.com"]},{"MX":[9,"mail.example.com"]},{"MX":[10,"e4.example.com"]},{"A":"1.2.3.5"}],"e5.example.com":[{"SPF":"v=spf1 ptr"},{"A":"1.2.3.5"}],"5.3.2.1.in-addr.arpa":[{"PTR":"e1.example.com."},{"PTR":"e2.example.com."},{"PTR":"e3.example.com."},{"PTR":"e4.example.com."},{"PTR":"example.com."},{"PTR":"e6.example.com."},{"PTR":"e7.example.com."},{"PTR":"e8.example.com."},{"PTR":"e9.example.com."},{"PTR":"e10.example.com."},{"PTR":"e5.example.com."}],"e6.example.com":[{"SPF":"v=spf1 a mx a mx a mx a mx a ptr ip4:1.2.3.4 -all"},{"A":"1.2.3.8"},{"MX":[10,"e6.example.com"]}],"e7.example.com":[{"SPF":"v=spf1 a mx a mx a mx a mx a ptr a ip4:1.2.3.4 -all"},{"A":"1.2.3.20"}],"e8.example.com":[{"SPF":"v=spf1 a include:inc.example.com ip4:1.2.3.4 mx -all"},{"A":"1.2.3.4"}],"inc.example.com":[{"SPF":"v=spf1 a a a a a a a a"},{"A":"1.2.3.10"}],"e9.example.com":[{"SPF":"v=spf1 a include:inc.example.com a ip4:1.2.3.4 -all"},{"A":"1.2.3.21"}],"e10.example.com":[{"SPF":"v=spf1 a -all"},{"A":"1.2.3.1"},{"A":"1.2.3.2"},{"A":"1.2.3.3"},{"A":"1.2.3.4"},{"A":"1.2.3.5"},{"A":"1.2.3.6"},{"A":"1.2.3.7"},{"A":"1.2.3.8"},{"A":"1.2.3.9"},{"A":"1.2.3.10"},{"A":"1.2.3.11"},{"A":"1.2.3.12"}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.4');
        return promise.then((result) => {
          assert.equal(result, 'PERMERROR');
        });
      });
      it('SPF implementations MUST limit the number of mechanisms and modifiers that do DNS lookups to at most 10 per SPF check.', function(){
        let email = 'foo@e8.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 ip4:1.1.1.1 redirect=e1.example.com"},{"A":"1.2.3.6"}],"e2.example.com":[{"SPF":"v=spf1 include:e3.example.com"},{"A":"1.2.3.7"}],"e3.example.com":[{"SPF":"v=spf1 include:e2.example.com"},{"A":"1.2.3.8"}],"e4.example.com":[{"SPF":"v=spf1 mx"},{"MX":[0,"mail.example.com"]},{"MX":[1,"mail.example.com"]},{"MX":[2,"mail.example.com"]},{"MX":[3,"mail.example.com"]},{"MX":[4,"mail.example.com"]},{"MX":[5,"mail.example.com"]},{"MX":[6,"mail.example.com"]},{"MX":[7,"mail.example.com"]},{"MX":[8,"mail.example.com"]},{"MX":[9,"mail.example.com"]},{"MX":[10,"e4.example.com"]},{"A":"1.2.3.5"}],"e5.example.com":[{"SPF":"v=spf1 ptr"},{"A":"1.2.3.5"}],"5.3.2.1.in-addr.arpa":[{"PTR":"e1.example.com."},{"PTR":"e2.example.com."},{"PTR":"e3.example.com."},{"PTR":"e4.example.com."},{"PTR":"example.com."},{"PTR":"e6.example.com."},{"PTR":"e7.example.com."},{"PTR":"e8.example.com."},{"PTR":"e9.example.com."},{"PTR":"e10.example.com."},{"PTR":"e5.example.com."}],"e6.example.com":[{"SPF":"v=spf1 a mx a mx a mx a mx a ptr ip4:1.2.3.4 -all"},{"A":"1.2.3.8"},{"MX":[10,"e6.example.com"]}],"e7.example.com":[{"SPF":"v=spf1 a mx a mx a mx a mx a ptr a ip4:1.2.3.4 -all"},{"A":"1.2.3.20"}],"e8.example.com":[{"SPF":"v=spf1 a include:inc.example.com ip4:1.2.3.4 mx -all"},{"A":"1.2.3.4"}],"inc.example.com":[{"SPF":"v=spf1 a a a a a a a a"},{"A":"1.2.3.10"}],"e9.example.com":[{"SPF":"v=spf1 a include:inc.example.com a ip4:1.2.3.4 -all"},{"A":"1.2.3.21"}],"e10.example.com":[{"SPF":"v=spf1 a -all"},{"A":"1.2.3.1"},{"A":"1.2.3.2"},{"A":"1.2.3.3"},{"A":"1.2.3.4"},{"A":"1.2.3.5"},{"A":"1.2.3.6"},{"A":"1.2.3.7"},{"A":"1.2.3.8"},{"A":"1.2.3.9"},{"A":"1.2.3.10"},{"A":"1.2.3.11"},{"A":"1.2.3.12"}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.4');
        return promise.then((result) => {
          assert.equal(result, 'PASS');
        });
      });
      it('SPF implementations MUST limit the number of mechanisms and modifiers that do DNS lookups to at most 10 per SPF check.', function(){
        let email = 'foo@e9.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 ip4:1.1.1.1 redirect=e1.example.com"},{"A":"1.2.3.6"}],"e2.example.com":[{"SPF":"v=spf1 include:e3.example.com"},{"A":"1.2.3.7"}],"e3.example.com":[{"SPF":"v=spf1 include:e2.example.com"},{"A":"1.2.3.8"}],"e4.example.com":[{"SPF":"v=spf1 mx"},{"MX":[0,"mail.example.com"]},{"MX":[1,"mail.example.com"]},{"MX":[2,"mail.example.com"]},{"MX":[3,"mail.example.com"]},{"MX":[4,"mail.example.com"]},{"MX":[5,"mail.example.com"]},{"MX":[6,"mail.example.com"]},{"MX":[7,"mail.example.com"]},{"MX":[8,"mail.example.com"]},{"MX":[9,"mail.example.com"]},{"MX":[10,"e4.example.com"]},{"A":"1.2.3.5"}],"e5.example.com":[{"SPF":"v=spf1 ptr"},{"A":"1.2.3.5"}],"5.3.2.1.in-addr.arpa":[{"PTR":"e1.example.com."},{"PTR":"e2.example.com."},{"PTR":"e3.example.com."},{"PTR":"e4.example.com."},{"PTR":"example.com."},{"PTR":"e6.example.com."},{"PTR":"e7.example.com."},{"PTR":"e8.example.com."},{"PTR":"e9.example.com."},{"PTR":"e10.example.com."},{"PTR":"e5.example.com."}],"e6.example.com":[{"SPF":"v=spf1 a mx a mx a mx a mx a ptr ip4:1.2.3.4 -all"},{"A":"1.2.3.8"},{"MX":[10,"e6.example.com"]}],"e7.example.com":[{"SPF":"v=spf1 a mx a mx a mx a mx a ptr a ip4:1.2.3.4 -all"},{"A":"1.2.3.20"}],"e8.example.com":[{"SPF":"v=spf1 a include:inc.example.com ip4:1.2.3.4 mx -all"},{"A":"1.2.3.4"}],"inc.example.com":[{"SPF":"v=spf1 a a a a a a a a"},{"A":"1.2.3.10"}],"e9.example.com":[{"SPF":"v=spf1 a include:inc.example.com a ip4:1.2.3.4 -all"},{"A":"1.2.3.21"}],"e10.example.com":[{"SPF":"v=spf1 a -all"},{"A":"1.2.3.1"},{"A":"1.2.3.2"},{"A":"1.2.3.3"},{"A":"1.2.3.4"},{"A":"1.2.3.5"},{"A":"1.2.3.6"},{"A":"1.2.3.7"},{"A":"1.2.3.8"},{"A":"1.2.3.9"},{"A":"1.2.3.10"},{"A":"1.2.3.11"},{"A":"1.2.3.12"}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.4');
        return promise.then((result) => {
          assert.equal(result, 'PERMERROR');
        });
      });
    });
  });
  describe('RFC7208', function(){
    describe('Initial processing', function(){
      it('DNS labels limited to 63 chars.', function(){
        let email = 'lyme.eater@A123456789012345678901234567890123456789012345678901234567890123.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"example.com":["TIMEOUT"],"example.net":[{"SPF":"v=spf1 -all exp=exp.example.net"}],"a.example.net":[{"SPF":"v=spf1 -all exp=exp.example.net"}],"exp.example.net":[{"TXT":"%{l}"}],"a12345678901234567890123456789012345678901234567890123456789012.example.com":[{"SPF":"v=spf1 -all"}],"hosed.example.com":[{"SPF":"v=spf1 a:ï»¿garbage.example.net -all"}],"hosed2.example.com":[{"SPF":"v=spf1 a:example.net -all"}],"hosed3.example.com":[{"SPF":"v=spf1 a:example.net all"}],"nothosed.example.com":[{"SPF":"v=spf1 a:example.net -all"},{"SPF":""}],"ctrl.example.com":[{"SPF":"v=spf1 a:ctrl.example.com\rptr -all"},{"A":"192.0.2.3"}],"fine.example.com":[{"SPF":"v=spf1 a  -all"}],"trail.example.com":[{"SPF":"v=spf1 a -all "}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.5');
        return promise.then((result) => {
          assert.equal(result, 'NONE');
        });
      });
      it('DNS labels limited to 63 chars.', function(){
        let email = 'lyme.eater@A12345678901234567890123456789012345678901234567890123456789012.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"example.com":["TIMEOUT"],"example.net":[{"SPF":"v=spf1 -all exp=exp.example.net"}],"a.example.net":[{"SPF":"v=spf1 -all exp=exp.example.net"}],"exp.example.net":[{"TXT":"%{l}"}],"a12345678901234567890123456789012345678901234567890123456789012.example.com":[{"SPF":"v=spf1 -all"}],"hosed.example.com":[{"SPF":"v=spf1 a:ï»¿garbage.example.net -all"}],"hosed2.example.com":[{"SPF":"v=spf1 a:example.net -all"}],"hosed3.example.com":[{"SPF":"v=spf1 a:example.net all"}],"nothosed.example.com":[{"SPF":"v=spf1 a:example.net -all"},{"SPF":""}],"ctrl.example.com":[{"SPF":"v=spf1 a:ctrl.example.com\rptr -all"},{"A":"192.0.2.3"}],"fine.example.com":[{"SPF":"v=spf1 a  -all"}],"trail.example.com":[{"SPF":"v=spf1 a -all "}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.5');
        return promise.then((result) => {
          assert.equal(result, 'FAIL');
        });
      });
      it('emptylabel', function(){
        let email = 'lyme.eater@A...example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"example.com":["TIMEOUT"],"example.net":[{"SPF":"v=spf1 -all exp=exp.example.net"}],"a.example.net":[{"SPF":"v=spf1 -all exp=exp.example.net"}],"exp.example.net":[{"TXT":"%{l}"}],"a12345678901234567890123456789012345678901234567890123456789012.example.com":[{"SPF":"v=spf1 -all"}],"hosed.example.com":[{"SPF":"v=spf1 a:ï»¿garbage.example.net -all"}],"hosed2.example.com":[{"SPF":"v=spf1 a:example.net -all"}],"hosed3.example.com":[{"SPF":"v=spf1 a:example.net all"}],"nothosed.example.com":[{"SPF":"v=spf1 a:example.net -all"},{"SPF":""}],"ctrl.example.com":[{"SPF":"v=spf1 a:ctrl.example.com\rptr -all"},{"A":"192.0.2.3"}],"fine.example.com":[{"SPF":"v=spf1 a  -all"}],"trail.example.com":[{"SPF":"v=spf1 a -all "}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.5');
        return promise.then((result) => {
          assert.equal(result, 'NONE');
        });
      });
      it('helo-not-fqdn', function(){
        let email = '';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"example.com":["TIMEOUT"],"example.net":[{"SPF":"v=spf1 -all exp=exp.example.net"}],"a.example.net":[{"SPF":"v=spf1 -all exp=exp.example.net"}],"exp.example.net":[{"TXT":"%{l}"}],"a12345678901234567890123456789012345678901234567890123456789012.example.com":[{"SPF":"v=spf1 -all"}],"hosed.example.com":[{"SPF":"v=spf1 a:ï»¿garbage.example.net -all"}],"hosed2.example.com":[{"SPF":"v=spf1 a:example.net -all"}],"hosed3.example.com":[{"SPF":"v=spf1 a:example.net all"}],"nothosed.example.com":[{"SPF":"v=spf1 a:example.net -all"},{"SPF":""}],"ctrl.example.com":[{"SPF":"v=spf1 a:ctrl.example.com\rptr -all"},{"A":"192.0.2.3"}],"fine.example.com":[{"SPF":"v=spf1 a  -all"}],"trail.example.com":[{"SPF":"v=spf1 a -all "}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.5');
        return promise.then((result) => {
          assert.equal(result, 'NONE');
        });
      });
      it('helo-domain-literal', function(){
        let email = '';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"example.com":["TIMEOUT"],"example.net":[{"SPF":"v=spf1 -all exp=exp.example.net"}],"a.example.net":[{"SPF":"v=spf1 -all exp=exp.example.net"}],"exp.example.net":[{"TXT":"%{l}"}],"a12345678901234567890123456789012345678901234567890123456789012.example.com":[{"SPF":"v=spf1 -all"}],"hosed.example.com":[{"SPF":"v=spf1 a:ï»¿garbage.example.net -all"}],"hosed2.example.com":[{"SPF":"v=spf1 a:example.net -all"}],"hosed3.example.com":[{"SPF":"v=spf1 a:example.net all"}],"nothosed.example.com":[{"SPF":"v=spf1 a:example.net -all"},{"SPF":""}],"ctrl.example.com":[{"SPF":"v=spf1 a:ctrl.example.com\rptr -all"},{"A":"192.0.2.3"}],"fine.example.com":[{"SPF":"v=spf1 a  -all"}],"trail.example.com":[{"SPF":"v=spf1 a -all "}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.5');
        return promise.then((result) => {
          assert.equal(result, 'NONE');
        });
      });
      it('nolocalpart', function(){
        let email = '@example.net';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"example.com":["TIMEOUT"],"example.net":[{"SPF":"v=spf1 -all exp=exp.example.net"}],"a.example.net":[{"SPF":"v=spf1 -all exp=exp.example.net"}],"exp.example.net":[{"TXT":"%{l}"}],"a12345678901234567890123456789012345678901234567890123456789012.example.com":[{"SPF":"v=spf1 -all"}],"hosed.example.com":[{"SPF":"v=spf1 a:ï»¿garbage.example.net -all"}],"hosed2.example.com":[{"SPF":"v=spf1 a:example.net -all"}],"hosed3.example.com":[{"SPF":"v=spf1 a:example.net all"}],"nothosed.example.com":[{"SPF":"v=spf1 a:example.net -all"},{"SPF":""}],"ctrl.example.com":[{"SPF":"v=spf1 a:ctrl.example.com\rptr -all"},{"A":"192.0.2.3"}],"fine.example.com":[{"SPF":"v=spf1 a  -all"}],"trail.example.com":[{"SPF":"v=spf1 a -all "}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.4');
        return promise.then((result) => {
          assert.equal(result, 'FAIL');
        });
      });
      it('domain-literal', function(){
        let email = 'foo@[1.2.3.5]';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"example.com":["TIMEOUT"],"example.net":[{"SPF":"v=spf1 -all exp=exp.example.net"}],"a.example.net":[{"SPF":"v=spf1 -all exp=exp.example.net"}],"exp.example.net":[{"TXT":"%{l}"}],"a12345678901234567890123456789012345678901234567890123456789012.example.com":[{"SPF":"v=spf1 -all"}],"hosed.example.com":[{"SPF":"v=spf1 a:ï»¿garbage.example.net -all"}],"hosed2.example.com":[{"SPF":"v=spf1 a:example.net -all"}],"hosed3.example.com":[{"SPF":"v=spf1 a:example.net all"}],"nothosed.example.com":[{"SPF":"v=spf1 a:example.net -all"},{"SPF":""}],"ctrl.example.com":[{"SPF":"v=spf1 a:ctrl.example.com\rptr -all"},{"A":"192.0.2.3"}],"fine.example.com":[{"SPF":"v=spf1 a  -all"}],"trail.example.com":[{"SPF":"v=spf1 a -all "}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.5');
        return promise.then((result) => {
          assert.equal(result, 'NONE');
        });
      });
      it('SPF policies are restricted to 7-bit ascii.', function(){
        let email = 'foobar@hosed.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"example.com":["TIMEOUT"],"example.net":[{"SPF":"v=spf1 -all exp=exp.example.net"}],"a.example.net":[{"SPF":"v=spf1 -all exp=exp.example.net"}],"exp.example.net":[{"TXT":"%{l}"}],"a12345678901234567890123456789012345678901234567890123456789012.example.com":[{"SPF":"v=spf1 -all"}],"hosed.example.com":[{"SPF":"v=spf1 a:ï»¿garbage.example.net -all"}],"hosed2.example.com":[{"SPF":"v=spf1 a:example.net -all"}],"hosed3.example.com":[{"SPF":"v=spf1 a:example.net all"}],"nothosed.example.com":[{"SPF":"v=spf1 a:example.net -all"},{"SPF":""}],"ctrl.example.com":[{"SPF":"v=spf1 a:ctrl.example.com\rptr -all"},{"A":"192.0.2.3"}],"fine.example.com":[{"SPF":"v=spf1 a  -all"}],"trail.example.com":[{"SPF":"v=spf1 a -all "}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.4');
        return promise.then((result) => {
          assert.equal(result, 'PERMERROR');
        });
      });
      it('SPF policies are restricted to 7-bit ascii.', function(){
        let email = 'foobar@hosed2.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"example.com":["TIMEOUT"],"example.net":[{"SPF":"v=spf1 -all exp=exp.example.net"}],"a.example.net":[{"SPF":"v=spf1 -all exp=exp.example.net"}],"exp.example.net":[{"TXT":"%{l}"}],"a12345678901234567890123456789012345678901234567890123456789012.example.com":[{"SPF":"v=spf1 -all"}],"hosed.example.com":[{"SPF":"v=spf1 a:ï»¿garbage.example.net -all"}],"hosed2.example.com":[{"SPF":"v=spf1 a:example.net -all"}],"hosed3.example.com":[{"SPF":"v=spf1 a:example.net all"}],"nothosed.example.com":[{"SPF":"v=spf1 a:example.net -all"},{"SPF":""}],"ctrl.example.com":[{"SPF":"v=spf1 a:ctrl.example.com\rptr -all"},{"A":"192.0.2.3"}],"fine.example.com":[{"SPF":"v=spf1 a  -all"}],"trail.example.com":[{"SPF":"v=spf1 a -all "}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.4');
        return promise.then((result) => {
          assert.equal(result, 'PERMERROR');
        });
      });
      it('SPF policies are restricted to 7-bit ascii.', function(){
        let email = 'foobar@hosed3.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"example.com":["TIMEOUT"],"example.net":[{"SPF":"v=spf1 -all exp=exp.example.net"}],"a.example.net":[{"SPF":"v=spf1 -all exp=exp.example.net"}],"exp.example.net":[{"TXT":"%{l}"}],"a12345678901234567890123456789012345678901234567890123456789012.example.com":[{"SPF":"v=spf1 -all"}],"hosed.example.com":[{"SPF":"v=spf1 a:ï»¿garbage.example.net -all"}],"hosed2.example.com":[{"SPF":"v=spf1 a:example.net -all"}],"hosed3.example.com":[{"SPF":"v=spf1 a:example.net all"}],"nothosed.example.com":[{"SPF":"v=spf1 a:example.net -all"},{"SPF":""}],"ctrl.example.com":[{"SPF":"v=spf1 a:ctrl.example.com\rptr -all"},{"A":"192.0.2.3"}],"fine.example.com":[{"SPF":"v=spf1 a  -all"}],"trail.example.com":[{"SPF":"v=spf1 a -all "}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.4');
        return promise.then((result) => {
          assert.equal(result, 'PERMERROR');
        });
      });
      it('Non-ascii content in non-SPF related records.', function(){
        let email = 'foobar@nothosed.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"example.com":["TIMEOUT"],"example.net":[{"SPF":"v=spf1 -all exp=exp.example.net"}],"a.example.net":[{"SPF":"v=spf1 -all exp=exp.example.net"}],"exp.example.net":[{"TXT":"%{l}"}],"a12345678901234567890123456789012345678901234567890123456789012.example.com":[{"SPF":"v=spf1 -all"}],"hosed.example.com":[{"SPF":"v=spf1 a:ï»¿garbage.example.net -all"}],"hosed2.example.com":[{"SPF":"v=spf1 a:example.net -all"}],"hosed3.example.com":[{"SPF":"v=spf1 a:example.net all"}],"nothosed.example.com":[{"SPF":"v=spf1 a:example.net -all"},{"SPF":""}],"ctrl.example.com":[{"SPF":"v=spf1 a:ctrl.example.com\rptr -all"},{"A":"192.0.2.3"}],"fine.example.com":[{"SPF":"v=spf1 a  -all"}],"trail.example.com":[{"SPF":"v=spf1 a -all "}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.4');
        return promise.then((result) => {
          assert.equal(result, 'FAIL');
        });
      });
      it('Mechanisms are separated by spaces only, not any control char.', function(){
        let email = 'foobar@ctrl.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"example.com":["TIMEOUT"],"example.net":[{"SPF":"v=spf1 -all exp=exp.example.net"}],"a.example.net":[{"SPF":"v=spf1 -all exp=exp.example.net"}],"exp.example.net":[{"TXT":"%{l}"}],"a12345678901234567890123456789012345678901234567890123456789012.example.com":[{"SPF":"v=spf1 -all"}],"hosed.example.com":[{"SPF":"v=spf1 a:ï»¿garbage.example.net -all"}],"hosed2.example.com":[{"SPF":"v=spf1 a:example.net -all"}],"hosed3.example.com":[{"SPF":"v=spf1 a:example.net all"}],"nothosed.example.com":[{"SPF":"v=spf1 a:example.net -all"},{"SPF":""}],"ctrl.example.com":[{"SPF":"v=spf1 a:ctrl.example.com\rptr -all"},{"A":"192.0.2.3"}],"fine.example.com":[{"SPF":"v=spf1 a  -all"}],"trail.example.com":[{"SPF":"v=spf1 a -all "}]}, failOnNoFake: true});
        let promise = validator.validateSender('192.0.2.3');
        return promise.then((result) => {
          assert.equal(result, 'PERMERROR');
        });
      });
      it('ABNF for term separation is one or more spaces, not just one.', function(){
        let email = 'actually@fine.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"example.com":["TIMEOUT"],"example.net":[{"SPF":"v=spf1 -all exp=exp.example.net"}],"a.example.net":[{"SPF":"v=spf1 -all exp=exp.example.net"}],"exp.example.net":[{"TXT":"%{l}"}],"a12345678901234567890123456789012345678901234567890123456789012.example.com":[{"SPF":"v=spf1 -all"}],"hosed.example.com":[{"SPF":"v=spf1 a:ï»¿garbage.example.net -all"}],"hosed2.example.com":[{"SPF":"v=spf1 a:example.net -all"}],"hosed3.example.com":[{"SPF":"v=spf1 a:example.net all"}],"nothosed.example.com":[{"SPF":"v=spf1 a:example.net -all"},{"SPF":""}],"ctrl.example.com":[{"SPF":"v=spf1 a:ctrl.example.com\rptr -all"},{"A":"192.0.2.3"}],"fine.example.com":[{"SPF":"v=spf1 a  -all"}],"trail.example.com":[{"SPF":"v=spf1 a -all "}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.4');
        return promise.then((result) => {
          assert.equal(result, 'FAIL');
        });
      });
      it('ABNF for record does allow trailing spaces.', function(){
        let email = 'silly@trail.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"example.com":["TIMEOUT"],"example.net":[{"SPF":"v=spf1 -all exp=exp.example.net"}],"a.example.net":[{"SPF":"v=spf1 -all exp=exp.example.net"}],"exp.example.net":[{"TXT":"%{l}"}],"a12345678901234567890123456789012345678901234567890123456789012.example.com":[{"SPF":"v=spf1 -all"}],"hosed.example.com":[{"SPF":"v=spf1 a:ï»¿garbage.example.net -all"}],"hosed2.example.com":[{"SPF":"v=spf1 a:example.net -all"}],"hosed3.example.com":[{"SPF":"v=spf1 a:example.net all"}],"nothosed.example.com":[{"SPF":"v=spf1 a:example.net -all"},{"SPF":""}],"ctrl.example.com":[{"SPF":"v=spf1 a:ctrl.example.com\rptr -all"},{"A":"192.0.2.3"}],"fine.example.com":[{"SPF":"v=spf1 a  -all"}],"trail.example.com":[{"SPF":"v=spf1 a -all "}]}, failOnNoFake: true});
        let promise = validator.validateSender('192.0.2.5');
        return promise.then((result) => {
          assert.equal(result, 'FAIL');
        });
      });
    });
    describe('Record lookup', function(){
      it('both', function(){
        let email = 'foo@both.example.net';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"both.example.net":[{"TXT":"v=spf1 -all"},{"SPF":"v=spf1 -all"}],"txtonly.example.net":[{"TXT":"v=spf1 -all"}],"spfonly.example.net":[{"SPF":"v=spf1 -all"},{"TXT":"NONE"}],"spftimeout.example.net":[{"TXT":"v=spf1 -all"},"TIMEOUT"],"txttimeout.example.net":[{"SPF":"v=spf1 -all"},{"TXT":"NONE"},"TIMEOUT"],"nospftxttimeout.example.net":[{"SPF":"v=spf3 !a:yahoo.com -all"},{"TXT":"NONE"},"TIMEOUT"],"alltimeout.example.net":["TIMEOUT"]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.4');
        return promise.then((result) => {
          assert.equal(result, 'FAIL');
        });
      });
      it('Result is none if checking SPF records only (which you should not be doing).', function(){
        let email = 'foo@txtonly.example.net';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"both.example.net":[{"TXT":"v=spf1 -all"},{"SPF":"v=spf1 -all"}],"txtonly.example.net":[{"TXT":"v=spf1 -all"}],"spfonly.example.net":[{"SPF":"v=spf1 -all"},{"TXT":"NONE"}],"spftimeout.example.net":[{"TXT":"v=spf1 -all"},"TIMEOUT"],"txttimeout.example.net":[{"SPF":"v=spf1 -all"},{"TXT":"NONE"},"TIMEOUT"],"nospftxttimeout.example.net":[{"SPF":"v=spf3 !a:yahoo.com -all"},{"TXT":"NONE"},"TIMEOUT"],"alltimeout.example.net":["TIMEOUT"]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.4');
        return promise.then((result) => {
          assert.equal(result, 'FAIL');
        });
      });
      it('Result is none if checking TXT records only.', function(){
        let email = 'foo@spfonly.example.net';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"both.example.net":[{"TXT":"v=spf1 -all"},{"SPF":"v=spf1 -all"}],"txtonly.example.net":[{"TXT":"v=spf1 -all"}],"spfonly.example.net":[{"SPF":"v=spf1 -all"},{"TXT":"NONE"}],"spftimeout.example.net":[{"TXT":"v=spf1 -all"},"TIMEOUT"],"txttimeout.example.net":[{"SPF":"v=spf1 -all"},{"TXT":"NONE"},"TIMEOUT"],"nospftxttimeout.example.net":[{"SPF":"v=spf3 !a:yahoo.com -all"},{"TXT":"NONE"},"TIMEOUT"],"alltimeout.example.net":["TIMEOUT"]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.4');
        return promise.then((result) => {
          assert.equal(result, 'NONE');
        });
      });
      it('TXT record present, but SPF lookup times out. Result is temperror if checking SPF records only.  Fortunately, we don"t do type SPF anymore.', function(){
        let email = 'foo@spftimeout.example.net';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"both.example.net":[{"TXT":"v=spf1 -all"},{"SPF":"v=spf1 -all"}],"txtonly.example.net":[{"TXT":"v=spf1 -all"}],"spfonly.example.net":[{"SPF":"v=spf1 -all"},{"TXT":"NONE"}],"spftimeout.example.net":[{"TXT":"v=spf1 -all"},"TIMEOUT"],"txttimeout.example.net":[{"SPF":"v=spf1 -all"},{"TXT":"NONE"},"TIMEOUT"],"nospftxttimeout.example.net":[{"SPF":"v=spf3 !a:yahoo.com -all"},{"TXT":"NONE"},"TIMEOUT"],"alltimeout.example.net":["TIMEOUT"]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.4');
        return promise.then((result) => {
          assert.equal(result, 'FAIL');
        });
      });
      it('SPF record present, but TXT lookup times out. If only TXT records are checked, result is temperror.', function(){
        let email = 'foo@txttimeout.example.net';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"both.example.net":[{"TXT":"v=spf1 -all"},{"SPF":"v=spf1 -all"}],"txtonly.example.net":[{"TXT":"v=spf1 -all"}],"spfonly.example.net":[{"SPF":"v=spf1 -all"},{"TXT":"NONE"}],"spftimeout.example.net":[{"TXT":"v=spf1 -all"},"TIMEOUT"],"txttimeout.example.net":[{"SPF":"v=spf1 -all"},{"TXT":"NONE"},"TIMEOUT"],"nospftxttimeout.example.net":[{"SPF":"v=spf3 !a:yahoo.com -all"},{"TXT":"NONE"},"TIMEOUT"],"alltimeout.example.net":["TIMEOUT"]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.4');
        return promise.then((result) => {
          assert.equal(result, 'TEMPERROR');
        });
      });
      it('No SPF record present, and TXT lookup times out. If only TXT records are checked, result is temperror.', function(){
        let email = 'foo@nospftxttimeout.example.net';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"both.example.net":[{"TXT":"v=spf1 -all"},{"SPF":"v=spf1 -all"}],"txtonly.example.net":[{"TXT":"v=spf1 -all"}],"spfonly.example.net":[{"SPF":"v=spf1 -all"},{"TXT":"NONE"}],"spftimeout.example.net":[{"TXT":"v=spf1 -all"},"TIMEOUT"],"txttimeout.example.net":[{"SPF":"v=spf1 -all"},{"TXT":"NONE"},"TIMEOUT"],"nospftxttimeout.example.net":[{"SPF":"v=spf3 !a:yahoo.com -all"},{"TXT":"NONE"},"TIMEOUT"],"alltimeout.example.net":["TIMEOUT"]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.4');
        return promise.then((result) => {
          assert.equal(result, 'TEMPERROR');
        });
      });
      it('Both TXT and SPF queries time out', function(){
        let email = 'foo@alltimeout.example.net';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"both.example.net":[{"TXT":"v=spf1 -all"},{"SPF":"v=spf1 -all"}],"txtonly.example.net":[{"TXT":"v=spf1 -all"}],"spfonly.example.net":[{"SPF":"v=spf1 -all"},{"TXT":"NONE"}],"spftimeout.example.net":[{"TXT":"v=spf1 -all"},"TIMEOUT"],"txttimeout.example.net":[{"SPF":"v=spf1 -all"},{"TXT":"NONE"},"TIMEOUT"],"nospftxttimeout.example.net":[{"SPF":"v=spf3 !a:yahoo.com -all"},{"TXT":"NONE"},"TIMEOUT"],"alltimeout.example.net":["TIMEOUT"]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.4');
        return promise.then((result) => {
          assert.equal(result, 'TEMPERROR');
        });
      });
    });
    describe('Selecting records', function(){
      it('Version must be terminated by space or end of record.  TXT pieces are joined without intervening spaces.', function(){
        let email = 'foo@example2.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"example3.com":[{"SPF":"v=spf10"},{"SPF":"v=spf1 mx"},{"MX":[0,"mail.example1.com"]}],"example1.com":[{"SPF":"v=spf1"}],"example2.com":[{"SPF":["v=spf1","mx"]}],"mail.example1.com":[{"A":"1.2.3.4"}],"example4.com":[{"SPF":"v=spf1 +all"},{"TXT":"v=spf1 -all"}],"example5.com":[{"SPF":"v=spf1 +all"},{"TXT":"v=spf1 -all"},{"TXT":"v=spf1 +all"}],"example6.com":[{"SPF":"v=spf1 -all"},{"SPF":"V=sPf1 +all"}],"example7.com":[{"SPF":"v=spf1 -all"},{"SPF":"v=spf1 -all"}],"example8.com":[{"SPF":"V=spf1 -all"},{"SPF":"v=spf1 -all"},{"TXT":"v=spf1 +all"}],"example9.com":[{"SPF":"v=SpF1 ~all"}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.4');
        return promise.then((result) => {
          assert.equal(result, 'NONE');
        });
      });
      it('Empty SPF record.', function(){
        let email = 'foo@example1.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"example3.com":[{"SPF":"v=spf10"},{"SPF":"v=spf1 mx"},{"MX":[0,"mail.example1.com"]}],"example1.com":[{"SPF":"v=spf1"}],"example2.com":[{"SPF":["v=spf1","mx"]}],"mail.example1.com":[{"A":"1.2.3.4"}],"example4.com":[{"SPF":"v=spf1 +all"},{"TXT":"v=spf1 -all"}],"example5.com":[{"SPF":"v=spf1 +all"},{"TXT":"v=spf1 -all"},{"TXT":"v=spf1 +all"}],"example6.com":[{"SPF":"v=spf1 -all"},{"SPF":"V=sPf1 +all"}],"example7.com":[{"SPF":"v=spf1 -all"},{"SPF":"v=spf1 -all"}],"example8.com":[{"SPF":"V=spf1 -all"},{"SPF":"v=spf1 -all"},{"TXT":"v=spf1 +all"}],"example9.com":[{"SPF":"v=SpF1 ~all"}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.4');
        return promise.then((result) => {
          assert.equal(result, 'NEUTRAL');
        });
      });
      it('nospace2', function(){
        let email = 'foo@example3.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"example3.com":[{"SPF":"v=spf10"},{"SPF":"v=spf1 mx"},{"MX":[0,"mail.example1.com"]}],"example1.com":[{"SPF":"v=spf1"}],"example2.com":[{"SPF":["v=spf1","mx"]}],"mail.example1.com":[{"A":"1.2.3.4"}],"example4.com":[{"SPF":"v=spf1 +all"},{"TXT":"v=spf1 -all"}],"example5.com":[{"SPF":"v=spf1 +all"},{"TXT":"v=spf1 -all"},{"TXT":"v=spf1 +all"}],"example6.com":[{"SPF":"v=spf1 -all"},{"SPF":"V=sPf1 +all"}],"example7.com":[{"SPF":"v=spf1 -all"},{"SPF":"v=spf1 -all"}],"example8.com":[{"SPF":"V=spf1 -all"},{"SPF":"v=spf1 -all"},{"TXT":"v=spf1 +all"}],"example9.com":[{"SPF":"v=SpF1 ~all"}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.4');
        return promise.then((result) => {
          assert.equal(result, 'PASS');
        });
      });
      it('SPF records no longer used.', function(){
        let email = 'foo@example4.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"example3.com":[{"SPF":"v=spf10"},{"SPF":"v=spf1 mx"},{"MX":[0,"mail.example1.com"]}],"example1.com":[{"SPF":"v=spf1"}],"example2.com":[{"SPF":["v=spf1","mx"]}],"mail.example1.com":[{"A":"1.2.3.4"}],"example4.com":[{"SPF":"v=spf1 +all"},{"TXT":"v=spf1 -all"}],"example5.com":[{"SPF":"v=spf1 +all"},{"TXT":"v=spf1 -all"},{"TXT":"v=spf1 +all"}],"example6.com":[{"SPF":"v=spf1 -all"},{"SPF":"V=sPf1 +all"}],"example7.com":[{"SPF":"v=spf1 -all"},{"SPF":"v=spf1 -all"}],"example8.com":[{"SPF":"V=spf1 -all"},{"SPF":"v=spf1 -all"},{"TXT":"v=spf1 +all"}],"example9.com":[{"SPF":"v=SpF1 ~all"}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.4');
        return promise.then((result) => {
          assert.equal(result, 'FAIL');
        });
      });
      it('Implementations should give permerror/unknown because of the conflicting TXT records.', function(){
        let email = 'foo@example5.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"example3.com":[{"SPF":"v=spf10"},{"SPF":"v=spf1 mx"},{"MX":[0,"mail.example1.com"]}],"example1.com":[{"SPF":"v=spf1"}],"example2.com":[{"SPF":["v=spf1","mx"]}],"mail.example1.com":[{"A":"1.2.3.4"}],"example4.com":[{"SPF":"v=spf1 +all"},{"TXT":"v=spf1 -all"}],"example5.com":[{"SPF":"v=spf1 +all"},{"TXT":"v=spf1 -all"},{"TXT":"v=spf1 +all"}],"example6.com":[{"SPF":"v=spf1 -all"},{"SPF":"V=sPf1 +all"}],"example7.com":[{"SPF":"v=spf1 -all"},{"SPF":"v=spf1 -all"}],"example8.com":[{"SPF":"V=spf1 -all"},{"SPF":"v=spf1 -all"},{"TXT":"v=spf1 +all"}],"example9.com":[{"SPF":"v=SpF1 ~all"}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.4');
        return promise.then((result) => {
          assert.equal(result, 'PERMERROR');
        });
      });
      it('Multiple records is a permerror, v=spf1 is case insensitive', function(){
        let email = 'foo@example6.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"example3.com":[{"SPF":"v=spf10"},{"SPF":"v=spf1 mx"},{"MX":[0,"mail.example1.com"]}],"example1.com":[{"SPF":"v=spf1"}],"example2.com":[{"SPF":["v=spf1","mx"]}],"mail.example1.com":[{"A":"1.2.3.4"}],"example4.com":[{"SPF":"v=spf1 +all"},{"TXT":"v=spf1 -all"}],"example5.com":[{"SPF":"v=spf1 +all"},{"TXT":"v=spf1 -all"},{"TXT":"v=spf1 +all"}],"example6.com":[{"SPF":"v=spf1 -all"},{"SPF":"V=sPf1 +all"}],"example7.com":[{"SPF":"v=spf1 -all"},{"SPF":"v=spf1 -all"}],"example8.com":[{"SPF":"V=spf1 -all"},{"SPF":"v=spf1 -all"},{"TXT":"v=spf1 +all"}],"example9.com":[{"SPF":"v=SpF1 ~all"}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.4');
        return promise.then((result) => {
          assert.equal(result, 'PERMERROR');
        });
      });
      it('Multiple records is a permerror, even when they are identical. However, this situation cannot be reliably reproduced with live DNS since cache and resolvers are allowed to combine identical records.', function(){
        let email = 'foo@example7.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"example3.com":[{"SPF":"v=spf10"},{"SPF":"v=spf1 mx"},{"MX":[0,"mail.example1.com"]}],"example1.com":[{"SPF":"v=spf1"}],"example2.com":[{"SPF":["v=spf1","mx"]}],"mail.example1.com":[{"A":"1.2.3.4"}],"example4.com":[{"SPF":"v=spf1 +all"},{"TXT":"v=spf1 -all"}],"example5.com":[{"SPF":"v=spf1 +all"},{"TXT":"v=spf1 -all"},{"TXT":"v=spf1 +all"}],"example6.com":[{"SPF":"v=spf1 -all"},{"SPF":"V=sPf1 +all"}],"example7.com":[{"SPF":"v=spf1 -all"},{"SPF":"v=spf1 -all"}],"example8.com":[{"SPF":"V=spf1 -all"},{"SPF":"v=spf1 -all"},{"TXT":"v=spf1 +all"}],"example9.com":[{"SPF":"v=SpF1 ~all"}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.4');
        return promise.then((result) => {
          assert.include(["permerror","fail"], result.toLowerCase());
        });
      });
      it('Ignoring SPF-type records will give pass because there is a (single) TXT record.', function(){
        let email = 'foo@example8.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"example3.com":[{"SPF":"v=spf10"},{"SPF":"v=spf1 mx"},{"MX":[0,"mail.example1.com"]}],"example1.com":[{"SPF":"v=spf1"}],"example2.com":[{"SPF":["v=spf1","mx"]}],"mail.example1.com":[{"A":"1.2.3.4"}],"example4.com":[{"SPF":"v=spf1 +all"},{"TXT":"v=spf1 -all"}],"example5.com":[{"SPF":"v=spf1 +all"},{"TXT":"v=spf1 -all"},{"TXT":"v=spf1 +all"}],"example6.com":[{"SPF":"v=spf1 -all"},{"SPF":"V=sPf1 +all"}],"example7.com":[{"SPF":"v=spf1 -all"},{"SPF":"v=spf1 -all"}],"example8.com":[{"SPF":"V=spf1 -all"},{"SPF":"v=spf1 -all"},{"TXT":"v=spf1 +all"}],"example9.com":[{"SPF":"v=SpF1 ~all"}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.4');
        return promise.then((result) => {
          assert.equal(result, 'PASS');
        });
      });
      it('nospf', function(){
        let email = 'foo@mail.example1.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"example3.com":[{"SPF":"v=spf10"},{"SPF":"v=spf1 mx"},{"MX":[0,"mail.example1.com"]}],"example1.com":[{"SPF":"v=spf1"}],"example2.com":[{"SPF":["v=spf1","mx"]}],"mail.example1.com":[{"A":"1.2.3.4"}],"example4.com":[{"SPF":"v=spf1 +all"},{"TXT":"v=spf1 -all"}],"example5.com":[{"SPF":"v=spf1 +all"},{"TXT":"v=spf1 -all"},{"TXT":"v=spf1 +all"}],"example6.com":[{"SPF":"v=spf1 -all"},{"SPF":"V=sPf1 +all"}],"example7.com":[{"SPF":"v=spf1 -all"},{"SPF":"v=spf1 -all"}],"example8.com":[{"SPF":"V=spf1 -all"},{"SPF":"v=spf1 -all"},{"TXT":"v=spf1 +all"}],"example9.com":[{"SPF":"v=SpF1 ~all"}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.4');
        return promise.then((result) => {
          assert.equal(result, 'NONE');
        });
      });
      it('v=spf1 is case insensitive', function(){
        let email = 'foo@example9.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"example3.com":[{"SPF":"v=spf10"},{"SPF":"v=spf1 mx"},{"MX":[0,"mail.example1.com"]}],"example1.com":[{"SPF":"v=spf1"}],"example2.com":[{"SPF":["v=spf1","mx"]}],"mail.example1.com":[{"A":"1.2.3.4"}],"example4.com":[{"SPF":"v=spf1 +all"},{"TXT":"v=spf1 -all"}],"example5.com":[{"SPF":"v=spf1 +all"},{"TXT":"v=spf1 -all"},{"TXT":"v=spf1 +all"}],"example6.com":[{"SPF":"v=spf1 -all"},{"SPF":"V=sPf1 +all"}],"example7.com":[{"SPF":"v=spf1 -all"},{"SPF":"v=spf1 -all"}],"example8.com":[{"SPF":"V=spf1 -all"},{"SPF":"v=spf1 -all"},{"TXT":"v=spf1 +all"}],"example9.com":[{"SPF":"v=SpF1 ~all"}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.4');
        return promise.then((result) => {
          assert.equal(result, 'SOFTFAIL');
        });
      });
    });
    describe('Record evaluation', function(){
      it('Any syntax errors anywhere in the record MUST be detected.', function(){
        let email = 'foo@t1.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"t1.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4 -all moo"}],"t2.example.com":[{"SPF":"v=spf1 moo.cow-far_out=man:dog/cat ip4:1.2.3.4 -all"}],"t3.example.com":[{"SPF":"v=spf1 moo.cow/far_out=man:dog/cat ip4:1.2.3.4 -all"}],"t4.example.com":[{"SPF":"v=spf1 moo.cow:far_out=man:dog/cat ip4:1.2.3.4 -all"}],"t5.example.com":[{"SPF":"v=spf1 redirect=t5.example.com ~all"}],"t6.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4 redirect=t2.example.com"}],"t7.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4"}],"t8.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4 redirect:t2.example.com"}],"t9.example.com":[{"SPF":"v=spf1 a:foo-bar -all"}],"t10.example.com":[{"SPF":"v=spf1 a:mail.example...com -all"}],"t11.example.com":[{"SPF":"v=spf1 a:a123456789012345678901234567890123456789012345678901234567890123.example.com -all"}],"t12.example.com":[{"SPF":"v=spf1 a:%{H}.bar -all"}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.4');
        return promise.then((result) => {
          assert.equal(result, 'PERMERROR');
        });
      });
      it('name = ALPHA *( ALPHA / DIGIT / "-" / "_" / "." )', function(){
        let email = 'foo@t2.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"t1.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4 -all moo"}],"t2.example.com":[{"SPF":"v=spf1 moo.cow-far_out=man:dog/cat ip4:1.2.3.4 -all"}],"t3.example.com":[{"SPF":"v=spf1 moo.cow/far_out=man:dog/cat ip4:1.2.3.4 -all"}],"t4.example.com":[{"SPF":"v=spf1 moo.cow:far_out=man:dog/cat ip4:1.2.3.4 -all"}],"t5.example.com":[{"SPF":"v=spf1 redirect=t5.example.com ~all"}],"t6.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4 redirect=t2.example.com"}],"t7.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4"}],"t8.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4 redirect:t2.example.com"}],"t9.example.com":[{"SPF":"v=spf1 a:foo-bar -all"}],"t10.example.com":[{"SPF":"v=spf1 a:mail.example...com -all"}],"t11.example.com":[{"SPF":"v=spf1 a:a123456789012345678901234567890123456789012345678901234567890123.example.com -all"}],"t12.example.com":[{"SPF":"v=spf1 a:%{H}.bar -all"}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.4');
        return promise.then((result) => {
          assert.equal(result, 'PASS');
        });
      });
      it('"=" character immediately after the name and before any ":" or "/"', function(){
        let email = 'foo@t3.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"t1.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4 -all moo"}],"t2.example.com":[{"SPF":"v=spf1 moo.cow-far_out=man:dog/cat ip4:1.2.3.4 -all"}],"t3.example.com":[{"SPF":"v=spf1 moo.cow/far_out=man:dog/cat ip4:1.2.3.4 -all"}],"t4.example.com":[{"SPF":"v=spf1 moo.cow:far_out=man:dog/cat ip4:1.2.3.4 -all"}],"t5.example.com":[{"SPF":"v=spf1 redirect=t5.example.com ~all"}],"t6.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4 redirect=t2.example.com"}],"t7.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4"}],"t8.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4 redirect:t2.example.com"}],"t9.example.com":[{"SPF":"v=spf1 a:foo-bar -all"}],"t10.example.com":[{"SPF":"v=spf1 a:mail.example...com -all"}],"t11.example.com":[{"SPF":"v=spf1 a:a123456789012345678901234567890123456789012345678901234567890123.example.com -all"}],"t12.example.com":[{"SPF":"v=spf1 a:%{H}.bar -all"}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.4');
        return promise.then((result) => {
          assert.equal(result, 'PERMERROR');
        });
      });
      it('"=" character immediately after the name and before any ":" or "/"', function(){
        let email = 'foo@t4.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"t1.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4 -all moo"}],"t2.example.com":[{"SPF":"v=spf1 moo.cow-far_out=man:dog/cat ip4:1.2.3.4 -all"}],"t3.example.com":[{"SPF":"v=spf1 moo.cow/far_out=man:dog/cat ip4:1.2.3.4 -all"}],"t4.example.com":[{"SPF":"v=spf1 moo.cow:far_out=man:dog/cat ip4:1.2.3.4 -all"}],"t5.example.com":[{"SPF":"v=spf1 redirect=t5.example.com ~all"}],"t6.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4 redirect=t2.example.com"}],"t7.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4"}],"t8.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4 redirect:t2.example.com"}],"t9.example.com":[{"SPF":"v=spf1 a:foo-bar -all"}],"t10.example.com":[{"SPF":"v=spf1 a:mail.example...com -all"}],"t11.example.com":[{"SPF":"v=spf1 a:a123456789012345678901234567890123456789012345678901234567890123.example.com -all"}],"t12.example.com":[{"SPF":"v=spf1 a:%{H}.bar -all"}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.4');
        return promise.then((result) => {
          assert.equal(result, 'PERMERROR');
        });
      });
      it('The "redirect" modifier has an effect after all the mechanisms.', function(){
        let email = 'foo@t5.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"t1.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4 -all moo"}],"t2.example.com":[{"SPF":"v=spf1 moo.cow-far_out=man:dog/cat ip4:1.2.3.4 -all"}],"t3.example.com":[{"SPF":"v=spf1 moo.cow/far_out=man:dog/cat ip4:1.2.3.4 -all"}],"t4.example.com":[{"SPF":"v=spf1 moo.cow:far_out=man:dog/cat ip4:1.2.3.4 -all"}],"t5.example.com":[{"SPF":"v=spf1 redirect=t5.example.com ~all"}],"t6.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4 redirect=t2.example.com"}],"t7.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4"}],"t8.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4 redirect:t2.example.com"}],"t9.example.com":[{"SPF":"v=spf1 a:foo-bar -all"}],"t10.example.com":[{"SPF":"v=spf1 a:mail.example...com -all"}],"t11.example.com":[{"SPF":"v=spf1 a:a123456789012345678901234567890123456789012345678901234567890123.example.com -all"}],"t12.example.com":[{"SPF":"v=spf1 a:%{H}.bar -all"}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.4');
        return promise.then((result) => {
          assert.equal(result, 'SOFTFAIL');
        });
      });
      it('The "redirect" modifier has an effect after all the mechanisms.', function(){
        let email = 'foo@t6.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"t1.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4 -all moo"}],"t2.example.com":[{"SPF":"v=spf1 moo.cow-far_out=man:dog/cat ip4:1.2.3.4 -all"}],"t3.example.com":[{"SPF":"v=spf1 moo.cow/far_out=man:dog/cat ip4:1.2.3.4 -all"}],"t4.example.com":[{"SPF":"v=spf1 moo.cow:far_out=man:dog/cat ip4:1.2.3.4 -all"}],"t5.example.com":[{"SPF":"v=spf1 redirect=t5.example.com ~all"}],"t6.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4 redirect=t2.example.com"}],"t7.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4"}],"t8.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4 redirect:t2.example.com"}],"t9.example.com":[{"SPF":"v=spf1 a:foo-bar -all"}],"t10.example.com":[{"SPF":"v=spf1 a:mail.example...com -all"}],"t11.example.com":[{"SPF":"v=spf1 a:a123456789012345678901234567890123456789012345678901234567890123.example.com -all"}],"t12.example.com":[{"SPF":"v=spf1 a:%{H}.bar -all"}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.5');
        return promise.then((result) => {
          assert.equal(result, 'FAIL');
        });
      });
      it('Default result is neutral.', function(){
        let email = 'foo@t7.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"t1.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4 -all moo"}],"t2.example.com":[{"SPF":"v=spf1 moo.cow-far_out=man:dog/cat ip4:1.2.3.4 -all"}],"t3.example.com":[{"SPF":"v=spf1 moo.cow/far_out=man:dog/cat ip4:1.2.3.4 -all"}],"t4.example.com":[{"SPF":"v=spf1 moo.cow:far_out=man:dog/cat ip4:1.2.3.4 -all"}],"t5.example.com":[{"SPF":"v=spf1 redirect=t5.example.com ~all"}],"t6.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4 redirect=t2.example.com"}],"t7.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4"}],"t8.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4 redirect:t2.example.com"}],"t9.example.com":[{"SPF":"v=spf1 a:foo-bar -all"}],"t10.example.com":[{"SPF":"v=spf1 a:mail.example...com -all"}],"t11.example.com":[{"SPF":"v=spf1 a:a123456789012345678901234567890123456789012345678901234567890123.example.com -all"}],"t12.example.com":[{"SPF":"v=spf1 a:%{H}.bar -all"}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.5');
        return promise.then((result) => {
          assert.equal(result, 'NEUTRAL');
        });
      });
      it('Invalid mechanism.  Redirect is a modifier.', function(){
        let email = 'foo@t8.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"t1.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4 -all moo"}],"t2.example.com":[{"SPF":"v=spf1 moo.cow-far_out=man:dog/cat ip4:1.2.3.4 -all"}],"t3.example.com":[{"SPF":"v=spf1 moo.cow/far_out=man:dog/cat ip4:1.2.3.4 -all"}],"t4.example.com":[{"SPF":"v=spf1 moo.cow:far_out=man:dog/cat ip4:1.2.3.4 -all"}],"t5.example.com":[{"SPF":"v=spf1 redirect=t5.example.com ~all"}],"t6.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4 redirect=t2.example.com"}],"t7.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4"}],"t8.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4 redirect:t2.example.com"}],"t9.example.com":[{"SPF":"v=spf1 a:foo-bar -all"}],"t10.example.com":[{"SPF":"v=spf1 a:mail.example...com -all"}],"t11.example.com":[{"SPF":"v=spf1 a:a123456789012345678901234567890123456789012345678901234567890123.example.com -all"}],"t12.example.com":[{"SPF":"v=spf1 a:%{H}.bar -all"}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.4');
        return promise.then((result) => {
          assert.equal(result, 'PERMERROR');
        });
      });
      it('Domain-spec must end in macro-expand or valid toplabel.', function(){
        let email = 'foo@t9.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"t1.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4 -all moo"}],"t2.example.com":[{"SPF":"v=spf1 moo.cow-far_out=man:dog/cat ip4:1.2.3.4 -all"}],"t3.example.com":[{"SPF":"v=spf1 moo.cow/far_out=man:dog/cat ip4:1.2.3.4 -all"}],"t4.example.com":[{"SPF":"v=spf1 moo.cow:far_out=man:dog/cat ip4:1.2.3.4 -all"}],"t5.example.com":[{"SPF":"v=spf1 redirect=t5.example.com ~all"}],"t6.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4 redirect=t2.example.com"}],"t7.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4"}],"t8.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4 redirect:t2.example.com"}],"t9.example.com":[{"SPF":"v=spf1 a:foo-bar -all"}],"t10.example.com":[{"SPF":"v=spf1 a:mail.example...com -all"}],"t11.example.com":[{"SPF":"v=spf1 a:a123456789012345678901234567890123456789012345678901234567890123.example.com -all"}],"t12.example.com":[{"SPF":"v=spf1 a:%{H}.bar -all"}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.4');
        return promise.then((result) => {
          assert.equal(result, 'PERMERROR');
        });
      });
      it('target-name that is a valid domain-spec per RFC 4408 and RFC 7208 but an invalid domain name per RFC 1035 (empty label) should be treated as non-existent.', function(){
        let email = 'foo@t10.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"t1.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4 -all moo"}],"t2.example.com":[{"SPF":"v=spf1 moo.cow-far_out=man:dog/cat ip4:1.2.3.4 -all"}],"t3.example.com":[{"SPF":"v=spf1 moo.cow/far_out=man:dog/cat ip4:1.2.3.4 -all"}],"t4.example.com":[{"SPF":"v=spf1 moo.cow:far_out=man:dog/cat ip4:1.2.3.4 -all"}],"t5.example.com":[{"SPF":"v=spf1 redirect=t5.example.com ~all"}],"t6.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4 redirect=t2.example.com"}],"t7.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4"}],"t8.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4 redirect:t2.example.com"}],"t9.example.com":[{"SPF":"v=spf1 a:foo-bar -all"}],"t10.example.com":[{"SPF":"v=spf1 a:mail.example...com -all"}],"t11.example.com":[{"SPF":"v=spf1 a:a123456789012345678901234567890123456789012345678901234567890123.example.com -all"}],"t12.example.com":[{"SPF":"v=spf1 a:%{H}.bar -all"}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.4');
        return promise.then((result) => {
          assert.include(["fail","permerror"], result.toLowerCase());
        });
      });
      it('target-name that is a valid domain-spec per RFC 4408 and RFC 7208 but an invalid domain name per RFC 1035 (long label) must be treated as non-existent.', function(){
        let email = 'foo@t11.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"t1.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4 -all moo"}],"t2.example.com":[{"SPF":"v=spf1 moo.cow-far_out=man:dog/cat ip4:1.2.3.4 -all"}],"t3.example.com":[{"SPF":"v=spf1 moo.cow/far_out=man:dog/cat ip4:1.2.3.4 -all"}],"t4.example.com":[{"SPF":"v=spf1 moo.cow:far_out=man:dog/cat ip4:1.2.3.4 -all"}],"t5.example.com":[{"SPF":"v=spf1 redirect=t5.example.com ~all"}],"t6.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4 redirect=t2.example.com"}],"t7.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4"}],"t8.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4 redirect:t2.example.com"}],"t9.example.com":[{"SPF":"v=spf1 a:foo-bar -all"}],"t10.example.com":[{"SPF":"v=spf1 a:mail.example...com -all"}],"t11.example.com":[{"SPF":"v=spf1 a:a123456789012345678901234567890123456789012345678901234567890123.example.com -all"}],"t12.example.com":[{"SPF":"v=spf1 a:%{H}.bar -all"}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.4');
        return promise.then((result) => {
          assert.include(["fail","permerror"], result.toLowerCase());
        });
      });
      it('target-name that is a valid domain-spec per RFC 4408 and RFC 7208 but an invalid domain name per RFC 1035 (long label) must be treated as non-existent.', function(){
        let email = 'foo@t12.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"t1.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4 -all moo"}],"t2.example.com":[{"SPF":"v=spf1 moo.cow-far_out=man:dog/cat ip4:1.2.3.4 -all"}],"t3.example.com":[{"SPF":"v=spf1 moo.cow/far_out=man:dog/cat ip4:1.2.3.4 -all"}],"t4.example.com":[{"SPF":"v=spf1 moo.cow:far_out=man:dog/cat ip4:1.2.3.4 -all"}],"t5.example.com":[{"SPF":"v=spf1 redirect=t5.example.com ~all"}],"t6.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4 redirect=t2.example.com"}],"t7.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4"}],"t8.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4 redirect:t2.example.com"}],"t9.example.com":[{"SPF":"v=spf1 a:foo-bar -all"}],"t10.example.com":[{"SPF":"v=spf1 a:mail.example...com -all"}],"t11.example.com":[{"SPF":"v=spf1 a:a123456789012345678901234567890123456789012345678901234567890123.example.com -all"}],"t12.example.com":[{"SPF":"v=spf1 a:%{H}.bar -all"}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.4');
        return promise.then((result) => {
          assert.include(["fail","permerror"], result.toLowerCase());
        });
      });
    });
    describe('ALL mechanism syntax', function(){
      it('all              = "all"', function(){
        let email = 'foo@e1.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 -all."}],"e2.example.com":[{"SPF":"v=spf1 -all:foobar"}],"e3.example.com":[{"SPF":"v=spf1 -all/8"}],"e4.example.com":[{"SPF":"v=spf1 ?all"}],"e5.example.com":[{"SPF":"v=spf1 all -all"}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.4');
        return promise.then((result) => {
          assert.equal(result, 'PERMERROR');
        });
      });
      it('all              = "all"', function(){
        let email = 'foo@e2.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 -all."}],"e2.example.com":[{"SPF":"v=spf1 -all:foobar"}],"e3.example.com":[{"SPF":"v=spf1 -all/8"}],"e4.example.com":[{"SPF":"v=spf1 ?all"}],"e5.example.com":[{"SPF":"v=spf1 all -all"}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.4');
        return promise.then((result) => {
          assert.equal(result, 'PERMERROR');
        });
      });
      it('all              = "all"', function(){
        let email = 'foo@e3.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 -all."}],"e2.example.com":[{"SPF":"v=spf1 -all:foobar"}],"e3.example.com":[{"SPF":"v=spf1 -all/8"}],"e4.example.com":[{"SPF":"v=spf1 ?all"}],"e5.example.com":[{"SPF":"v=spf1 all -all"}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.4');
        return promise.then((result) => {
          assert.equal(result, 'PERMERROR');
        });
      });
      it('all              = "all"', function(){
        let email = 'foo@e4.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 -all."}],"e2.example.com":[{"SPF":"v=spf1 -all:foobar"}],"e3.example.com":[{"SPF":"v=spf1 -all/8"}],"e4.example.com":[{"SPF":"v=spf1 ?all"}],"e5.example.com":[{"SPF":"v=spf1 all -all"}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.4');
        return promise.then((result) => {
          assert.equal(result, 'NEUTRAL');
        });
      });
      it('all              = "all"', function(){
        let email = 'foo@e5.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 -all."}],"e2.example.com":[{"SPF":"v=spf1 -all:foobar"}],"e3.example.com":[{"SPF":"v=spf1 -all/8"}],"e4.example.com":[{"SPF":"v=spf1 ?all"}],"e5.example.com":[{"SPF":"v=spf1 all -all"}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.4');
        return promise.then((result) => {
          assert.equal(result, 'PASS');
        });
      });
    });
    describe('PTR mechanism syntax', function(){
      it('PTR              = "ptr"    [ ":" domain-spec ]', function(){
        let email = 'foo@e1.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"},{"AAAA":"2001:db8::1"}],"e1.example.com":[{"SPF":"v=spf1 ptr/0 -all"}],"e2.example.com":[{"SPF":"v=spf1 ptr:example.com -all"}],"4.3.2.1.in-addr.arpa":[{"PTR":"e3.example.com"},{"PTR":"e4.example.com"},{"PTR":"mail.example.com"}],"1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.E.B.A.B.E.F.A.C.ip6.arpa":[{"PTR":"e3.example.com"}],"1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.D.0.1.0.0.2.ip6.arpa":[{"PTR":"mail.Example.com"}],"e3.example.com":[{"SPF":"v=spf1 ptr -all"},{"A":"1.2.3.4"},{"AAAA":"CAFE:BABE::1"}],"e4.example.com":[{"SPF":"v=spf1 ptr -all"}],"e5.example.com":[{"SPF":"v=spf1 ptr:"}],"e6.example.com":[{"SPF":"v=spf1 ptr:example.Com -all"}],"loop.example.com":[{"SPF":"v=spf1 ptr"}],"4.2.0.192.in-addr.arpa":[{"PTR":"loop4.example.com."}],"loop4.example.com":[{"CNAME":"CNAME.example.com."}],"cname.example.com":[{"CNAME":"CNAME.example.com."}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.4');
        return promise.then((result) => {
          assert.equal(result, 'PERMERROR');
        });
      });
      it('Check all validated domain names to see if they end in the <target-name> domain.', function(){
        let email = 'foo@e2.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"},{"AAAA":"2001:db8::1"}],"e1.example.com":[{"SPF":"v=spf1 ptr/0 -all"}],"e2.example.com":[{"SPF":"v=spf1 ptr:example.com -all"}],"4.3.2.1.in-addr.arpa":[{"PTR":"e3.example.com"},{"PTR":"e4.example.com"},{"PTR":"mail.example.com"}],"1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.E.B.A.B.E.F.A.C.ip6.arpa":[{"PTR":"e3.example.com"}],"1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.D.0.1.0.0.2.ip6.arpa":[{"PTR":"mail.Example.com"}],"e3.example.com":[{"SPF":"v=spf1 ptr -all"},{"A":"1.2.3.4"},{"AAAA":"CAFE:BABE::1"}],"e4.example.com":[{"SPF":"v=spf1 ptr -all"}],"e5.example.com":[{"SPF":"v=spf1 ptr:"}],"e6.example.com":[{"SPF":"v=spf1 ptr:example.Com -all"}],"loop.example.com":[{"SPF":"v=spf1 ptr"}],"4.2.0.192.in-addr.arpa":[{"PTR":"loop4.example.com."}],"loop4.example.com":[{"CNAME":"CNAME.example.com."}],"cname.example.com":[{"CNAME":"CNAME.example.com."}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.4');
        return promise.then((result) => {
          assert.equal(result, 'PASS');
        });
      });
      it('Check all validated domain names to see if they end in the <target-name> domain.', function(){
        let email = 'foo@e3.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"},{"AAAA":"2001:db8::1"}],"e1.example.com":[{"SPF":"v=spf1 ptr/0 -all"}],"e2.example.com":[{"SPF":"v=spf1 ptr:example.com -all"}],"4.3.2.1.in-addr.arpa":[{"PTR":"e3.example.com"},{"PTR":"e4.example.com"},{"PTR":"mail.example.com"}],"1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.E.B.A.B.E.F.A.C.ip6.arpa":[{"PTR":"e3.example.com"}],"1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.D.0.1.0.0.2.ip6.arpa":[{"PTR":"mail.Example.com"}],"e3.example.com":[{"SPF":"v=spf1 ptr -all"},{"A":"1.2.3.4"},{"AAAA":"CAFE:BABE::1"}],"e4.example.com":[{"SPF":"v=spf1 ptr -all"}],"e5.example.com":[{"SPF":"v=spf1 ptr:"}],"e6.example.com":[{"SPF":"v=spf1 ptr:example.Com -all"}],"loop.example.com":[{"SPF":"v=spf1 ptr"}],"4.2.0.192.in-addr.arpa":[{"PTR":"loop4.example.com."}],"loop4.example.com":[{"CNAME":"CNAME.example.com."}],"cname.example.com":[{"CNAME":"CNAME.example.com."}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.4');
        return promise.then((result) => {
          assert.equal(result, 'PASS');
        });
      });
      it('Check all validated domain names to see if they end in the <target-name> domain.', function(){
        let email = 'foo@e4.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"},{"AAAA":"2001:db8::1"}],"e1.example.com":[{"SPF":"v=spf1 ptr/0 -all"}],"e2.example.com":[{"SPF":"v=spf1 ptr:example.com -all"}],"4.3.2.1.in-addr.arpa":[{"PTR":"e3.example.com"},{"PTR":"e4.example.com"},{"PTR":"mail.example.com"}],"1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.E.B.A.B.E.F.A.C.ip6.arpa":[{"PTR":"e3.example.com"}],"1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.D.0.1.0.0.2.ip6.arpa":[{"PTR":"mail.Example.com"}],"e3.example.com":[{"SPF":"v=spf1 ptr -all"},{"A":"1.2.3.4"},{"AAAA":"CAFE:BABE::1"}],"e4.example.com":[{"SPF":"v=spf1 ptr -all"}],"e5.example.com":[{"SPF":"v=spf1 ptr:"}],"e6.example.com":[{"SPF":"v=spf1 ptr:example.Com -all"}],"loop.example.com":[{"SPF":"v=spf1 ptr"}],"4.2.0.192.in-addr.arpa":[{"PTR":"loop4.example.com."}],"loop4.example.com":[{"CNAME":"CNAME.example.com."}],"cname.example.com":[{"CNAME":"CNAME.example.com."}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.4');
        return promise.then((result) => {
          assert.equal(result, 'FAIL');
        });
      });
      it('Check all validated domain names to see if they end in the <target-name> domain.', function(){
        let email = 'foo@e3.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"},{"AAAA":"2001:db8::1"}],"e1.example.com":[{"SPF":"v=spf1 ptr/0 -all"}],"e2.example.com":[{"SPF":"v=spf1 ptr:example.com -all"}],"4.3.2.1.in-addr.arpa":[{"PTR":"e3.example.com"},{"PTR":"e4.example.com"},{"PTR":"mail.example.com"}],"1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.E.B.A.B.E.F.A.C.ip6.arpa":[{"PTR":"e3.example.com"}],"1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.D.0.1.0.0.2.ip6.arpa":[{"PTR":"mail.Example.com"}],"e3.example.com":[{"SPF":"v=spf1 ptr -all"},{"A":"1.2.3.4"},{"AAAA":"CAFE:BABE::1"}],"e4.example.com":[{"SPF":"v=spf1 ptr -all"}],"e5.example.com":[{"SPF":"v=spf1 ptr:"}],"e6.example.com":[{"SPF":"v=spf1 ptr:example.Com -all"}],"loop.example.com":[{"SPF":"v=spf1 ptr"}],"4.2.0.192.in-addr.arpa":[{"PTR":"loop4.example.com."}],"loop4.example.com":[{"CNAME":"CNAME.example.com."}],"cname.example.com":[{"CNAME":"CNAME.example.com."}]}, failOnNoFake: true});
        let promise = validator.validateSender('CAFE:BABE::1');
        return promise.then((result) => {
          assert.equal(result, 'PASS');
        });
      });
      it('domain-spec cannot be empty.', function(){
        let email = 'foo@e5.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"},{"AAAA":"2001:db8::1"}],"e1.example.com":[{"SPF":"v=spf1 ptr/0 -all"}],"e2.example.com":[{"SPF":"v=spf1 ptr:example.com -all"}],"4.3.2.1.in-addr.arpa":[{"PTR":"e3.example.com"},{"PTR":"e4.example.com"},{"PTR":"mail.example.com"}],"1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.E.B.A.B.E.F.A.C.ip6.arpa":[{"PTR":"e3.example.com"}],"1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.D.0.1.0.0.2.ip6.arpa":[{"PTR":"mail.Example.com"}],"e3.example.com":[{"SPF":"v=spf1 ptr -all"},{"A":"1.2.3.4"},{"AAAA":"CAFE:BABE::1"}],"e4.example.com":[{"SPF":"v=spf1 ptr -all"}],"e5.example.com":[{"SPF":"v=spf1 ptr:"}],"e6.example.com":[{"SPF":"v=spf1 ptr:example.Com -all"}],"loop.example.com":[{"SPF":"v=spf1 ptr"}],"4.2.0.192.in-addr.arpa":[{"PTR":"loop4.example.com."}],"loop4.example.com":[{"CNAME":"CNAME.example.com."}],"cname.example.com":[{"CNAME":"CNAME.example.com."}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.4');
        return promise.then((result) => {
          assert.equal(result, 'PERMERROR');
        });
      });
      it('arpa domain is case insensitive.', function(){
        let email = 'bar@e6.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"},{"AAAA":"2001:db8::1"}],"e1.example.com":[{"SPF":"v=spf1 ptr/0 -all"}],"e2.example.com":[{"SPF":"v=spf1 ptr:example.com -all"}],"4.3.2.1.in-addr.arpa":[{"PTR":"e3.example.com"},{"PTR":"e4.example.com"},{"PTR":"mail.example.com"}],"1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.E.B.A.B.E.F.A.C.ip6.arpa":[{"PTR":"e3.example.com"}],"1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.D.0.1.0.0.2.ip6.arpa":[{"PTR":"mail.Example.com"}],"e3.example.com":[{"SPF":"v=spf1 ptr -all"},{"A":"1.2.3.4"},{"AAAA":"CAFE:BABE::1"}],"e4.example.com":[{"SPF":"v=spf1 ptr -all"}],"e5.example.com":[{"SPF":"v=spf1 ptr:"}],"e6.example.com":[{"SPF":"v=spf1 ptr:example.Com -all"}],"loop.example.com":[{"SPF":"v=spf1 ptr"}],"4.2.0.192.in-addr.arpa":[{"PTR":"loop4.example.com."}],"loop4.example.com":[{"CNAME":"CNAME.example.com."}],"cname.example.com":[{"CNAME":"CNAME.example.com."}]}, failOnNoFake: true});
        let promise = validator.validateSender('2001:db8::1');
        return promise.then((result) => {
          assert.equal(result, 'PASS');
        });
      });
      it('a PTR with CNAME loop and inconsistent case in domain.', function(){
        let email = 'postmaster@loop.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"},{"AAAA":"2001:db8::1"}],"e1.example.com":[{"SPF":"v=spf1 ptr/0 -all"}],"e2.example.com":[{"SPF":"v=spf1 ptr:example.com -all"}],"4.3.2.1.in-addr.arpa":[{"PTR":"e3.example.com"},{"PTR":"e4.example.com"},{"PTR":"mail.example.com"}],"1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.E.B.A.B.E.F.A.C.ip6.arpa":[{"PTR":"e3.example.com"}],"1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.D.0.1.0.0.2.ip6.arpa":[{"PTR":"mail.Example.com"}],"e3.example.com":[{"SPF":"v=spf1 ptr -all"},{"A":"1.2.3.4"},{"AAAA":"CAFE:BABE::1"}],"e4.example.com":[{"SPF":"v=spf1 ptr -all"}],"e5.example.com":[{"SPF":"v=spf1 ptr:"}],"e6.example.com":[{"SPF":"v=spf1 ptr:example.Com -all"}],"loop.example.com":[{"SPF":"v=spf1 ptr"}],"4.2.0.192.in-addr.arpa":[{"PTR":"loop4.example.com."}],"loop4.example.com":[{"CNAME":"CNAME.example.com."}],"cname.example.com":[{"CNAME":"CNAME.example.com."}]}, failOnNoFake: true});
        let promise = validator.validateSender('192.0.2.4');
        return promise.then((result) => {
          assert.equal(result, 'NEUTRAL');
        });
      });
    });
    describe('A mechanism syntax', function(){
      it('A                = "a"      [ ":" domain-spec ] [ dual-cidr-length ] dual-cidr-length = [ ip4-cidr-length ] [ "/" ip6-cidr-length ]', function(){
        let email = 'foo@e6.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 a/0 -all"}],"e2.example.com":[{"A":"1.1.1.1"},{"AAAA":"1234::2"},{"SPF":"v=spf1 a/0 -all"}],"e2a.example.com":[{"AAAA":"1234::1"},{"SPF":"v=spf1 a//0 -all"}],"e2b.example.com":[{"A":"1.1.1.1"},{"SPF":"v=spf1 a//0 -all"}],"ipv6.example.com":[{"AAAA":"1234::1"},{"A":"1.1.1.1"},{"SPF":"v=spf1 a -all"}],"e3.example.com":[{"SPF":"v=spf1 a:foo.example.com\u0000"}],"e4.example.com":[{"SPF":"v=spf1 a:111.222.33.44"}],"e5.example.com":[{"SPF":"v=spf1 a:abc.123"}],"e5a.example.com":[{"SPF":"v=spf1 a:museum"}],"e5b.example.com":[{"SPF":"v=spf1 a:museum."}],"e6.example.com":[{"SPF":"v=spf1 a//33 -all"}],"e6a.example.com":[{"SPF":"v=spf1 a/33 -all"}],"e7.example.com":[{"SPF":"v=spf1 a//129 -all"}],"e8.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24//64 -all"}],"e8e.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24/64 -all"}],"e8a.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24 -all"}],"e8b.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a//64 -all"}],"e9.example.com":[{"SPF":"v=spf1 a:example.com:8080"}],"e10.example.com":[{"SPF":"v=spf1 a:foo.example.com/24"}],"foo.example.com":[{"A":"1.1.1.1"},{"A":"1.2.3.5"}],"e11.example.com":[{"SPF":"v=spf1 a:foo:bar/baz.example.com"}],"foo:bar/baz.example.com":[{"A":"1.2.3.4"}],"e12.example.com":[{"SPF":"v=spf1 a:example.-com"}],"e13.example.com":[{"SPF":"v=spf1 a:"}],"e14.example.com":[{"SPF":"v=spf1 a:foo.example.xn--zckzah -all"}],"foo.example.xn--zckzah":[{"A":"1.2.3.4"}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.4');
        return promise.then((result) => {
          assert.equal(result, 'FAIL');
        });
      });
      it('A                = "a"      [ ":" domain-spec ] [ dual-cidr-length ] dual-cidr-length = [ ip4-cidr-length ] [ "/" ip6-cidr-length ]', function(){
        let email = 'foo@e6a.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 a/0 -all"}],"e2.example.com":[{"A":"1.1.1.1"},{"AAAA":"1234::2"},{"SPF":"v=spf1 a/0 -all"}],"e2a.example.com":[{"AAAA":"1234::1"},{"SPF":"v=spf1 a//0 -all"}],"e2b.example.com":[{"A":"1.1.1.1"},{"SPF":"v=spf1 a//0 -all"}],"ipv6.example.com":[{"AAAA":"1234::1"},{"A":"1.1.1.1"},{"SPF":"v=spf1 a -all"}],"e3.example.com":[{"SPF":"v=spf1 a:foo.example.com\u0000"}],"e4.example.com":[{"SPF":"v=spf1 a:111.222.33.44"}],"e5.example.com":[{"SPF":"v=spf1 a:abc.123"}],"e5a.example.com":[{"SPF":"v=spf1 a:museum"}],"e5b.example.com":[{"SPF":"v=spf1 a:museum."}],"e6.example.com":[{"SPF":"v=spf1 a//33 -all"}],"e6a.example.com":[{"SPF":"v=spf1 a/33 -all"}],"e7.example.com":[{"SPF":"v=spf1 a//129 -all"}],"e8.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24//64 -all"}],"e8e.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24/64 -all"}],"e8a.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24 -all"}],"e8b.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a//64 -all"}],"e9.example.com":[{"SPF":"v=spf1 a:example.com:8080"}],"e10.example.com":[{"SPF":"v=spf1 a:foo.example.com/24"}],"foo.example.com":[{"A":"1.1.1.1"},{"A":"1.2.3.5"}],"e11.example.com":[{"SPF":"v=spf1 a:foo:bar/baz.example.com"}],"foo:bar/baz.example.com":[{"A":"1.2.3.4"}],"e12.example.com":[{"SPF":"v=spf1 a:example.-com"}],"e13.example.com":[{"SPF":"v=spf1 a:"}],"e14.example.com":[{"SPF":"v=spf1 a:foo.example.xn--zckzah -all"}],"foo.example.xn--zckzah":[{"A":"1.2.3.4"}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.4');
        return promise.then((result) => {
          assert.equal(result, 'PERMERROR');
        });
      });
      it('A                = "a"      [ ":" domain-spec ] [ dual-cidr-length ] dual-cidr-length = [ ip4-cidr-length ] [ "/" ip6-cidr-length ]', function(){
        let email = 'foo@e7.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 a/0 -all"}],"e2.example.com":[{"A":"1.1.1.1"},{"AAAA":"1234::2"},{"SPF":"v=spf1 a/0 -all"}],"e2a.example.com":[{"AAAA":"1234::1"},{"SPF":"v=spf1 a//0 -all"}],"e2b.example.com":[{"A":"1.1.1.1"},{"SPF":"v=spf1 a//0 -all"}],"ipv6.example.com":[{"AAAA":"1234::1"},{"A":"1.1.1.1"},{"SPF":"v=spf1 a -all"}],"e3.example.com":[{"SPF":"v=spf1 a:foo.example.com\u0000"}],"e4.example.com":[{"SPF":"v=spf1 a:111.222.33.44"}],"e5.example.com":[{"SPF":"v=spf1 a:abc.123"}],"e5a.example.com":[{"SPF":"v=spf1 a:museum"}],"e5b.example.com":[{"SPF":"v=spf1 a:museum."}],"e6.example.com":[{"SPF":"v=spf1 a//33 -all"}],"e6a.example.com":[{"SPF":"v=spf1 a/33 -all"}],"e7.example.com":[{"SPF":"v=spf1 a//129 -all"}],"e8.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24//64 -all"}],"e8e.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24/64 -all"}],"e8a.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24 -all"}],"e8b.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a//64 -all"}],"e9.example.com":[{"SPF":"v=spf1 a:example.com:8080"}],"e10.example.com":[{"SPF":"v=spf1 a:foo.example.com/24"}],"foo.example.com":[{"A":"1.1.1.1"},{"A":"1.2.3.5"}],"e11.example.com":[{"SPF":"v=spf1 a:foo:bar/baz.example.com"}],"foo:bar/baz.example.com":[{"A":"1.2.3.4"}],"e12.example.com":[{"SPF":"v=spf1 a:example.-com"}],"e13.example.com":[{"SPF":"v=spf1 a:"}],"e14.example.com":[{"SPF":"v=spf1 a:foo.example.xn--zckzah -all"}],"foo.example.xn--zckzah":[{"A":"1.2.3.4"}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.4');
        return promise.then((result) => {
          assert.equal(result, 'PERMERROR');
        });
      });
      it('A                = "a"      [ ":" domain-spec ] [ dual-cidr-length ] dual-cidr-length = [ ip4-cidr-length ] [ "/" ip6-cidr-length ]', function(){
        let email = 'foo@e8.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 a/0 -all"}],"e2.example.com":[{"A":"1.1.1.1"},{"AAAA":"1234::2"},{"SPF":"v=spf1 a/0 -all"}],"e2a.example.com":[{"AAAA":"1234::1"},{"SPF":"v=spf1 a//0 -all"}],"e2b.example.com":[{"A":"1.1.1.1"},{"SPF":"v=spf1 a//0 -all"}],"ipv6.example.com":[{"AAAA":"1234::1"},{"A":"1.1.1.1"},{"SPF":"v=spf1 a -all"}],"e3.example.com":[{"SPF":"v=spf1 a:foo.example.com\u0000"}],"e4.example.com":[{"SPF":"v=spf1 a:111.222.33.44"}],"e5.example.com":[{"SPF":"v=spf1 a:abc.123"}],"e5a.example.com":[{"SPF":"v=spf1 a:museum"}],"e5b.example.com":[{"SPF":"v=spf1 a:museum."}],"e6.example.com":[{"SPF":"v=spf1 a//33 -all"}],"e6a.example.com":[{"SPF":"v=spf1 a/33 -all"}],"e7.example.com":[{"SPF":"v=spf1 a//129 -all"}],"e8.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24//64 -all"}],"e8e.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24/64 -all"}],"e8a.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24 -all"}],"e8b.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a//64 -all"}],"e9.example.com":[{"SPF":"v=spf1 a:example.com:8080"}],"e10.example.com":[{"SPF":"v=spf1 a:foo.example.com/24"}],"foo.example.com":[{"A":"1.1.1.1"},{"A":"1.2.3.5"}],"e11.example.com":[{"SPF":"v=spf1 a:foo:bar/baz.example.com"}],"foo:bar/baz.example.com":[{"A":"1.2.3.4"}],"e12.example.com":[{"SPF":"v=spf1 a:example.-com"}],"e13.example.com":[{"SPF":"v=spf1 a:"}],"e14.example.com":[{"SPF":"v=spf1 a:foo.example.xn--zckzah -all"}],"foo.example.xn--zckzah":[{"A":"1.2.3.4"}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.4');
        return promise.then((result) => {
          assert.equal(result, 'PASS');
        });
      });
      it('A                = "a"      [ ":" domain-spec ] [ dual-cidr-length ] dual-cidr-length = [ ip4-cidr-length ] [ "/" ip6-cidr-length ]', function(){
        let email = 'foo@e8e.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 a/0 -all"}],"e2.example.com":[{"A":"1.1.1.1"},{"AAAA":"1234::2"},{"SPF":"v=spf1 a/0 -all"}],"e2a.example.com":[{"AAAA":"1234::1"},{"SPF":"v=spf1 a//0 -all"}],"e2b.example.com":[{"A":"1.1.1.1"},{"SPF":"v=spf1 a//0 -all"}],"ipv6.example.com":[{"AAAA":"1234::1"},{"A":"1.1.1.1"},{"SPF":"v=spf1 a -all"}],"e3.example.com":[{"SPF":"v=spf1 a:foo.example.com\u0000"}],"e4.example.com":[{"SPF":"v=spf1 a:111.222.33.44"}],"e5.example.com":[{"SPF":"v=spf1 a:abc.123"}],"e5a.example.com":[{"SPF":"v=spf1 a:museum"}],"e5b.example.com":[{"SPF":"v=spf1 a:museum."}],"e6.example.com":[{"SPF":"v=spf1 a//33 -all"}],"e6a.example.com":[{"SPF":"v=spf1 a/33 -all"}],"e7.example.com":[{"SPF":"v=spf1 a//129 -all"}],"e8.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24//64 -all"}],"e8e.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24/64 -all"}],"e8a.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24 -all"}],"e8b.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a//64 -all"}],"e9.example.com":[{"SPF":"v=spf1 a:example.com:8080"}],"e10.example.com":[{"SPF":"v=spf1 a:foo.example.com/24"}],"foo.example.com":[{"A":"1.1.1.1"},{"A":"1.2.3.5"}],"e11.example.com":[{"SPF":"v=spf1 a:foo:bar/baz.example.com"}],"foo:bar/baz.example.com":[{"A":"1.2.3.4"}],"e12.example.com":[{"SPF":"v=spf1 a:example.-com"}],"e13.example.com":[{"SPF":"v=spf1 a:"}],"e14.example.com":[{"SPF":"v=spf1 a:foo.example.xn--zckzah -all"}],"foo.example.xn--zckzah":[{"A":"1.2.3.4"}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.4');
        return promise.then((result) => {
          assert.equal(result, 'PERMERROR');
        });
      });
      it('A                = "a"      [ ":" domain-spec ] [ dual-cidr-length ] dual-cidr-length = [ ip4-cidr-length ] [ "/" ip6-cidr-length ]', function(){
        let email = 'foo@e8.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 a/0 -all"}],"e2.example.com":[{"A":"1.1.1.1"},{"AAAA":"1234::2"},{"SPF":"v=spf1 a/0 -all"}],"e2a.example.com":[{"AAAA":"1234::1"},{"SPF":"v=spf1 a//0 -all"}],"e2b.example.com":[{"A":"1.1.1.1"},{"SPF":"v=spf1 a//0 -all"}],"ipv6.example.com":[{"AAAA":"1234::1"},{"A":"1.1.1.1"},{"SPF":"v=spf1 a -all"}],"e3.example.com":[{"SPF":"v=spf1 a:foo.example.com\u0000"}],"e4.example.com":[{"SPF":"v=spf1 a:111.222.33.44"}],"e5.example.com":[{"SPF":"v=spf1 a:abc.123"}],"e5a.example.com":[{"SPF":"v=spf1 a:museum"}],"e5b.example.com":[{"SPF":"v=spf1 a:museum."}],"e6.example.com":[{"SPF":"v=spf1 a//33 -all"}],"e6a.example.com":[{"SPF":"v=spf1 a/33 -all"}],"e7.example.com":[{"SPF":"v=spf1 a//129 -all"}],"e8.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24//64 -all"}],"e8e.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24/64 -all"}],"e8a.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24 -all"}],"e8b.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a//64 -all"}],"e9.example.com":[{"SPF":"v=spf1 a:example.com:8080"}],"e10.example.com":[{"SPF":"v=spf1 a:foo.example.com/24"}],"foo.example.com":[{"A":"1.1.1.1"},{"A":"1.2.3.5"}],"e11.example.com":[{"SPF":"v=spf1 a:foo:bar/baz.example.com"}],"foo:bar/baz.example.com":[{"A":"1.2.3.4"}],"e12.example.com":[{"SPF":"v=spf1 a:example.-com"}],"e13.example.com":[{"SPF":"v=spf1 a:"}],"e14.example.com":[{"SPF":"v=spf1 a:foo.example.xn--zckzah -all"}],"foo.example.xn--zckzah":[{"A":"1.2.3.4"}]}, failOnNoFake: true});
        let promise = validator.validateSender('2001:db8:1234::cafe:babe');
        return promise.then((result) => {
          assert.equal(result, 'PASS');
        });
      });
      it('A                = "a"      [ ":" domain-spec ] [ dual-cidr-length ] dual-cidr-length = [ ip4-cidr-length ] [ "/" ip6-cidr-length ]', function(){
        let email = 'foo@e8b.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 a/0 -all"}],"e2.example.com":[{"A":"1.1.1.1"},{"AAAA":"1234::2"},{"SPF":"v=spf1 a/0 -all"}],"e2a.example.com":[{"AAAA":"1234::1"},{"SPF":"v=spf1 a//0 -all"}],"e2b.example.com":[{"A":"1.1.1.1"},{"SPF":"v=spf1 a//0 -all"}],"ipv6.example.com":[{"AAAA":"1234::1"},{"A":"1.1.1.1"},{"SPF":"v=spf1 a -all"}],"e3.example.com":[{"SPF":"v=spf1 a:foo.example.com\u0000"}],"e4.example.com":[{"SPF":"v=spf1 a:111.222.33.44"}],"e5.example.com":[{"SPF":"v=spf1 a:abc.123"}],"e5a.example.com":[{"SPF":"v=spf1 a:museum"}],"e5b.example.com":[{"SPF":"v=spf1 a:museum."}],"e6.example.com":[{"SPF":"v=spf1 a//33 -all"}],"e6a.example.com":[{"SPF":"v=spf1 a/33 -all"}],"e7.example.com":[{"SPF":"v=spf1 a//129 -all"}],"e8.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24//64 -all"}],"e8e.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24/64 -all"}],"e8a.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24 -all"}],"e8b.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a//64 -all"}],"e9.example.com":[{"SPF":"v=spf1 a:example.com:8080"}],"e10.example.com":[{"SPF":"v=spf1 a:foo.example.com/24"}],"foo.example.com":[{"A":"1.1.1.1"},{"A":"1.2.3.5"}],"e11.example.com":[{"SPF":"v=spf1 a:foo:bar/baz.example.com"}],"foo:bar/baz.example.com":[{"A":"1.2.3.4"}],"e12.example.com":[{"SPF":"v=spf1 a:example.-com"}],"e13.example.com":[{"SPF":"v=spf1 a:"}],"e14.example.com":[{"SPF":"v=spf1 a:foo.example.xn--zckzah -all"}],"foo.example.xn--zckzah":[{"A":"1.2.3.4"}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.4');
        return promise.then((result) => {
          assert.equal(result, 'FAIL');
        });
      });
      it('A                = "a"      [ ":" domain-spec ] [ dual-cidr-length ] dual-cidr-length = [ ip4-cidr-length ] [ "/" ip6-cidr-length ]', function(){
        let email = 'foo@e8a.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 a/0 -all"}],"e2.example.com":[{"A":"1.1.1.1"},{"AAAA":"1234::2"},{"SPF":"v=spf1 a/0 -all"}],"e2a.example.com":[{"AAAA":"1234::1"},{"SPF":"v=spf1 a//0 -all"}],"e2b.example.com":[{"A":"1.1.1.1"},{"SPF":"v=spf1 a//0 -all"}],"ipv6.example.com":[{"AAAA":"1234::1"},{"A":"1.1.1.1"},{"SPF":"v=spf1 a -all"}],"e3.example.com":[{"SPF":"v=spf1 a:foo.example.com\u0000"}],"e4.example.com":[{"SPF":"v=spf1 a:111.222.33.44"}],"e5.example.com":[{"SPF":"v=spf1 a:abc.123"}],"e5a.example.com":[{"SPF":"v=spf1 a:museum"}],"e5b.example.com":[{"SPF":"v=spf1 a:museum."}],"e6.example.com":[{"SPF":"v=spf1 a//33 -all"}],"e6a.example.com":[{"SPF":"v=spf1 a/33 -all"}],"e7.example.com":[{"SPF":"v=spf1 a//129 -all"}],"e8.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24//64 -all"}],"e8e.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24/64 -all"}],"e8a.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24 -all"}],"e8b.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a//64 -all"}],"e9.example.com":[{"SPF":"v=spf1 a:example.com:8080"}],"e10.example.com":[{"SPF":"v=spf1 a:foo.example.com/24"}],"foo.example.com":[{"A":"1.1.1.1"},{"A":"1.2.3.5"}],"e11.example.com":[{"SPF":"v=spf1 a:foo:bar/baz.example.com"}],"foo:bar/baz.example.com":[{"A":"1.2.3.4"}],"e12.example.com":[{"SPF":"v=spf1 a:example.-com"}],"e13.example.com":[{"SPF":"v=spf1 a:"}],"e14.example.com":[{"SPF":"v=spf1 a:foo.example.xn--zckzah -all"}],"foo.example.xn--zckzah":[{"A":"1.2.3.4"}]}, failOnNoFake: true});
        let promise = validator.validateSender('2001:db8:1234::cafe:babe');
        return promise.then((result) => {
          assert.equal(result, 'FAIL');
        });
      });
      it('A matches any returned IP.', function(){
        let email = 'foo@e10.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 a/0 -all"}],"e2.example.com":[{"A":"1.1.1.1"},{"AAAA":"1234::2"},{"SPF":"v=spf1 a/0 -all"}],"e2a.example.com":[{"AAAA":"1234::1"},{"SPF":"v=spf1 a//0 -all"}],"e2b.example.com":[{"A":"1.1.1.1"},{"SPF":"v=spf1 a//0 -all"}],"ipv6.example.com":[{"AAAA":"1234::1"},{"A":"1.1.1.1"},{"SPF":"v=spf1 a -all"}],"e3.example.com":[{"SPF":"v=spf1 a:foo.example.com\u0000"}],"e4.example.com":[{"SPF":"v=spf1 a:111.222.33.44"}],"e5.example.com":[{"SPF":"v=spf1 a:abc.123"}],"e5a.example.com":[{"SPF":"v=spf1 a:museum"}],"e5b.example.com":[{"SPF":"v=spf1 a:museum."}],"e6.example.com":[{"SPF":"v=spf1 a//33 -all"}],"e6a.example.com":[{"SPF":"v=spf1 a/33 -all"}],"e7.example.com":[{"SPF":"v=spf1 a//129 -all"}],"e8.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24//64 -all"}],"e8e.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24/64 -all"}],"e8a.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24 -all"}],"e8b.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a//64 -all"}],"e9.example.com":[{"SPF":"v=spf1 a:example.com:8080"}],"e10.example.com":[{"SPF":"v=spf1 a:foo.example.com/24"}],"foo.example.com":[{"A":"1.1.1.1"},{"A":"1.2.3.5"}],"e11.example.com":[{"SPF":"v=spf1 a:foo:bar/baz.example.com"}],"foo:bar/baz.example.com":[{"A":"1.2.3.4"}],"e12.example.com":[{"SPF":"v=spf1 a:example.-com"}],"e13.example.com":[{"SPF":"v=spf1 a:"}],"e14.example.com":[{"SPF":"v=spf1 a:foo.example.xn--zckzah -all"}],"foo.example.xn--zckzah":[{"A":"1.2.3.4"}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.4');
        return promise.then((result) => {
          assert.equal(result, 'PASS');
        });
      });
      it('A matches any returned IP.', function(){
        let email = 'foo@e10.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 a/0 -all"}],"e2.example.com":[{"A":"1.1.1.1"},{"AAAA":"1234::2"},{"SPF":"v=spf1 a/0 -all"}],"e2a.example.com":[{"AAAA":"1234::1"},{"SPF":"v=spf1 a//0 -all"}],"e2b.example.com":[{"A":"1.1.1.1"},{"SPF":"v=spf1 a//0 -all"}],"ipv6.example.com":[{"AAAA":"1234::1"},{"A":"1.1.1.1"},{"SPF":"v=spf1 a -all"}],"e3.example.com":[{"SPF":"v=spf1 a:foo.example.com\u0000"}],"e4.example.com":[{"SPF":"v=spf1 a:111.222.33.44"}],"e5.example.com":[{"SPF":"v=spf1 a:abc.123"}],"e5a.example.com":[{"SPF":"v=spf1 a:museum"}],"e5b.example.com":[{"SPF":"v=spf1 a:museum."}],"e6.example.com":[{"SPF":"v=spf1 a//33 -all"}],"e6a.example.com":[{"SPF":"v=spf1 a/33 -all"}],"e7.example.com":[{"SPF":"v=spf1 a//129 -all"}],"e8.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24//64 -all"}],"e8e.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24/64 -all"}],"e8a.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24 -all"}],"e8b.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a//64 -all"}],"e9.example.com":[{"SPF":"v=spf1 a:example.com:8080"}],"e10.example.com":[{"SPF":"v=spf1 a:foo.example.com/24"}],"foo.example.com":[{"A":"1.1.1.1"},{"A":"1.2.3.5"}],"e11.example.com":[{"SPF":"v=spf1 a:foo:bar/baz.example.com"}],"foo:bar/baz.example.com":[{"A":"1.2.3.4"}],"e12.example.com":[{"SPF":"v=spf1 a:example.-com"}],"e13.example.com":[{"SPF":"v=spf1 a:"}],"e14.example.com":[{"SPF":"v=spf1 a:foo.example.xn--zckzah -all"}],"foo.example.xn--zckzah":[{"A":"1.2.3.4"}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.4');
        return promise.then((result) => {
          assert.equal(result, 'PASS');
        });
      });
      it('domain-spec must pass basic syntax checks; a ":" may appear in domain-spec, but not in top-label', function(){
        let email = 'foo@e9.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 a/0 -all"}],"e2.example.com":[{"A":"1.1.1.1"},{"AAAA":"1234::2"},{"SPF":"v=spf1 a/0 -all"}],"e2a.example.com":[{"AAAA":"1234::1"},{"SPF":"v=spf1 a//0 -all"}],"e2b.example.com":[{"A":"1.1.1.1"},{"SPF":"v=spf1 a//0 -all"}],"ipv6.example.com":[{"AAAA":"1234::1"},{"A":"1.1.1.1"},{"SPF":"v=spf1 a -all"}],"e3.example.com":[{"SPF":"v=spf1 a:foo.example.com\u0000"}],"e4.example.com":[{"SPF":"v=spf1 a:111.222.33.44"}],"e5.example.com":[{"SPF":"v=spf1 a:abc.123"}],"e5a.example.com":[{"SPF":"v=spf1 a:museum"}],"e5b.example.com":[{"SPF":"v=spf1 a:museum."}],"e6.example.com":[{"SPF":"v=spf1 a//33 -all"}],"e6a.example.com":[{"SPF":"v=spf1 a/33 -all"}],"e7.example.com":[{"SPF":"v=spf1 a//129 -all"}],"e8.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24//64 -all"}],"e8e.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24/64 -all"}],"e8a.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24 -all"}],"e8b.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a//64 -all"}],"e9.example.com":[{"SPF":"v=spf1 a:example.com:8080"}],"e10.example.com":[{"SPF":"v=spf1 a:foo.example.com/24"}],"foo.example.com":[{"A":"1.1.1.1"},{"A":"1.2.3.5"}],"e11.example.com":[{"SPF":"v=spf1 a:foo:bar/baz.example.com"}],"foo:bar/baz.example.com":[{"A":"1.2.3.4"}],"e12.example.com":[{"SPF":"v=spf1 a:example.-com"}],"e13.example.com":[{"SPF":"v=spf1 a:"}],"e14.example.com":[{"SPF":"v=spf1 a:foo.example.xn--zckzah -all"}],"foo.example.xn--zckzah":[{"A":"1.2.3.4"}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.4');
        return promise.then((result) => {
          assert.equal(result, 'PERMERROR');
        });
      });
      it('If no ips are returned, A mechanism does not match, even with /0.', function(){
        let email = 'foo@e1.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 a/0 -all"}],"e2.example.com":[{"A":"1.1.1.1"},{"AAAA":"1234::2"},{"SPF":"v=spf1 a/0 -all"}],"e2a.example.com":[{"AAAA":"1234::1"},{"SPF":"v=spf1 a//0 -all"}],"e2b.example.com":[{"A":"1.1.1.1"},{"SPF":"v=spf1 a//0 -all"}],"ipv6.example.com":[{"AAAA":"1234::1"},{"A":"1.1.1.1"},{"SPF":"v=spf1 a -all"}],"e3.example.com":[{"SPF":"v=spf1 a:foo.example.com\u0000"}],"e4.example.com":[{"SPF":"v=spf1 a:111.222.33.44"}],"e5.example.com":[{"SPF":"v=spf1 a:abc.123"}],"e5a.example.com":[{"SPF":"v=spf1 a:museum"}],"e5b.example.com":[{"SPF":"v=spf1 a:museum."}],"e6.example.com":[{"SPF":"v=spf1 a//33 -all"}],"e6a.example.com":[{"SPF":"v=spf1 a/33 -all"}],"e7.example.com":[{"SPF":"v=spf1 a//129 -all"}],"e8.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24//64 -all"}],"e8e.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24/64 -all"}],"e8a.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24 -all"}],"e8b.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a//64 -all"}],"e9.example.com":[{"SPF":"v=spf1 a:example.com:8080"}],"e10.example.com":[{"SPF":"v=spf1 a:foo.example.com/24"}],"foo.example.com":[{"A":"1.1.1.1"},{"A":"1.2.3.5"}],"e11.example.com":[{"SPF":"v=spf1 a:foo:bar/baz.example.com"}],"foo:bar/baz.example.com":[{"A":"1.2.3.4"}],"e12.example.com":[{"SPF":"v=spf1 a:example.-com"}],"e13.example.com":[{"SPF":"v=spf1 a:"}],"e14.example.com":[{"SPF":"v=spf1 a:foo.example.xn--zckzah -all"}],"foo.example.xn--zckzah":[{"A":"1.2.3.4"}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.4');
        return promise.then((result) => {
          assert.equal(result, 'FAIL');
        });
      });
      it('Matches if any A records are present in DNS.', function(){
        let email = 'foo@e2.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 a/0 -all"}],"e2.example.com":[{"A":"1.1.1.1"},{"AAAA":"1234::2"},{"SPF":"v=spf1 a/0 -all"}],"e2a.example.com":[{"AAAA":"1234::1"},{"SPF":"v=spf1 a//0 -all"}],"e2b.example.com":[{"A":"1.1.1.1"},{"SPF":"v=spf1 a//0 -all"}],"ipv6.example.com":[{"AAAA":"1234::1"},{"A":"1.1.1.1"},{"SPF":"v=spf1 a -all"}],"e3.example.com":[{"SPF":"v=spf1 a:foo.example.com\u0000"}],"e4.example.com":[{"SPF":"v=spf1 a:111.222.33.44"}],"e5.example.com":[{"SPF":"v=spf1 a:abc.123"}],"e5a.example.com":[{"SPF":"v=spf1 a:museum"}],"e5b.example.com":[{"SPF":"v=spf1 a:museum."}],"e6.example.com":[{"SPF":"v=spf1 a//33 -all"}],"e6a.example.com":[{"SPF":"v=spf1 a/33 -all"}],"e7.example.com":[{"SPF":"v=spf1 a//129 -all"}],"e8.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24//64 -all"}],"e8e.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24/64 -all"}],"e8a.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24 -all"}],"e8b.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a//64 -all"}],"e9.example.com":[{"SPF":"v=spf1 a:example.com:8080"}],"e10.example.com":[{"SPF":"v=spf1 a:foo.example.com/24"}],"foo.example.com":[{"A":"1.1.1.1"},{"A":"1.2.3.5"}],"e11.example.com":[{"SPF":"v=spf1 a:foo:bar/baz.example.com"}],"foo:bar/baz.example.com":[{"A":"1.2.3.4"}],"e12.example.com":[{"SPF":"v=spf1 a:example.-com"}],"e13.example.com":[{"SPF":"v=spf1 a:"}],"e14.example.com":[{"SPF":"v=spf1 a:foo.example.xn--zckzah -all"}],"foo.example.xn--zckzah":[{"A":"1.2.3.4"}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.4');
        return promise.then((result) => {
          assert.equal(result, 'PASS');
        });
      });
      it('Matches if any A records are present in DNS.', function(){
        let email = 'foo@e2.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 a/0 -all"}],"e2.example.com":[{"A":"1.1.1.1"},{"AAAA":"1234::2"},{"SPF":"v=spf1 a/0 -all"}],"e2a.example.com":[{"AAAA":"1234::1"},{"SPF":"v=spf1 a//0 -all"}],"e2b.example.com":[{"A":"1.1.1.1"},{"SPF":"v=spf1 a//0 -all"}],"ipv6.example.com":[{"AAAA":"1234::1"},{"A":"1.1.1.1"},{"SPF":"v=spf1 a -all"}],"e3.example.com":[{"SPF":"v=spf1 a:foo.example.com\u0000"}],"e4.example.com":[{"SPF":"v=spf1 a:111.222.33.44"}],"e5.example.com":[{"SPF":"v=spf1 a:abc.123"}],"e5a.example.com":[{"SPF":"v=spf1 a:museum"}],"e5b.example.com":[{"SPF":"v=spf1 a:museum."}],"e6.example.com":[{"SPF":"v=spf1 a//33 -all"}],"e6a.example.com":[{"SPF":"v=spf1 a/33 -all"}],"e7.example.com":[{"SPF":"v=spf1 a//129 -all"}],"e8.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24//64 -all"}],"e8e.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24/64 -all"}],"e8a.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24 -all"}],"e8b.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a//64 -all"}],"e9.example.com":[{"SPF":"v=spf1 a:example.com:8080"}],"e10.example.com":[{"SPF":"v=spf1 a:foo.example.com/24"}],"foo.example.com":[{"A":"1.1.1.1"},{"A":"1.2.3.5"}],"e11.example.com":[{"SPF":"v=spf1 a:foo:bar/baz.example.com"}],"foo:bar/baz.example.com":[{"A":"1.2.3.4"}],"e12.example.com":[{"SPF":"v=spf1 a:example.-com"}],"e13.example.com":[{"SPF":"v=spf1 a:"}],"e14.example.com":[{"SPF":"v=spf1 a:foo.example.xn--zckzah -all"}],"foo.example.xn--zckzah":[{"A":"1.2.3.4"}]}, failOnNoFake: true});
        let promise = validator.validateSender('1234::1');
        return promise.then((result) => {
          assert.equal(result, 'FAIL');
        });
      });
      it('Would match if any AAAA records are present in DNS, but not for an IP4 connection.', function(){
        let email = 'foo@e2a.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 a/0 -all"}],"e2.example.com":[{"A":"1.1.1.1"},{"AAAA":"1234::2"},{"SPF":"v=spf1 a/0 -all"}],"e2a.example.com":[{"AAAA":"1234::1"},{"SPF":"v=spf1 a//0 -all"}],"e2b.example.com":[{"A":"1.1.1.1"},{"SPF":"v=spf1 a//0 -all"}],"ipv6.example.com":[{"AAAA":"1234::1"},{"A":"1.1.1.1"},{"SPF":"v=spf1 a -all"}],"e3.example.com":[{"SPF":"v=spf1 a:foo.example.com\u0000"}],"e4.example.com":[{"SPF":"v=spf1 a:111.222.33.44"}],"e5.example.com":[{"SPF":"v=spf1 a:abc.123"}],"e5a.example.com":[{"SPF":"v=spf1 a:museum"}],"e5b.example.com":[{"SPF":"v=spf1 a:museum."}],"e6.example.com":[{"SPF":"v=spf1 a//33 -all"}],"e6a.example.com":[{"SPF":"v=spf1 a/33 -all"}],"e7.example.com":[{"SPF":"v=spf1 a//129 -all"}],"e8.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24//64 -all"}],"e8e.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24/64 -all"}],"e8a.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24 -all"}],"e8b.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a//64 -all"}],"e9.example.com":[{"SPF":"v=spf1 a:example.com:8080"}],"e10.example.com":[{"SPF":"v=spf1 a:foo.example.com/24"}],"foo.example.com":[{"A":"1.1.1.1"},{"A":"1.2.3.5"}],"e11.example.com":[{"SPF":"v=spf1 a:foo:bar/baz.example.com"}],"foo:bar/baz.example.com":[{"A":"1.2.3.4"}],"e12.example.com":[{"SPF":"v=spf1 a:example.-com"}],"e13.example.com":[{"SPF":"v=spf1 a:"}],"e14.example.com":[{"SPF":"v=spf1 a:foo.example.xn--zckzah -all"}],"foo.example.xn--zckzah":[{"A":"1.2.3.4"}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.4');
        return promise.then((result) => {
          assert.equal(result, 'FAIL');
        });
      });
      it('Would match if any AAAA records are present in DNS, but not for an IP4 connection.', function(){
        let email = 'foo@e2a.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 a/0 -all"}],"e2.example.com":[{"A":"1.1.1.1"},{"AAAA":"1234::2"},{"SPF":"v=spf1 a/0 -all"}],"e2a.example.com":[{"AAAA":"1234::1"},{"SPF":"v=spf1 a//0 -all"}],"e2b.example.com":[{"A":"1.1.1.1"},{"SPF":"v=spf1 a//0 -all"}],"ipv6.example.com":[{"AAAA":"1234::1"},{"A":"1.1.1.1"},{"SPF":"v=spf1 a -all"}],"e3.example.com":[{"SPF":"v=spf1 a:foo.example.com\u0000"}],"e4.example.com":[{"SPF":"v=spf1 a:111.222.33.44"}],"e5.example.com":[{"SPF":"v=spf1 a:abc.123"}],"e5a.example.com":[{"SPF":"v=spf1 a:museum"}],"e5b.example.com":[{"SPF":"v=spf1 a:museum."}],"e6.example.com":[{"SPF":"v=spf1 a//33 -all"}],"e6a.example.com":[{"SPF":"v=spf1 a/33 -all"}],"e7.example.com":[{"SPF":"v=spf1 a//129 -all"}],"e8.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24//64 -all"}],"e8e.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24/64 -all"}],"e8a.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24 -all"}],"e8b.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a//64 -all"}],"e9.example.com":[{"SPF":"v=spf1 a:example.com:8080"}],"e10.example.com":[{"SPF":"v=spf1 a:foo.example.com/24"}],"foo.example.com":[{"A":"1.1.1.1"},{"A":"1.2.3.5"}],"e11.example.com":[{"SPF":"v=spf1 a:foo:bar/baz.example.com"}],"foo:bar/baz.example.com":[{"A":"1.2.3.4"}],"e12.example.com":[{"SPF":"v=spf1 a:example.-com"}],"e13.example.com":[{"SPF":"v=spf1 a:"}],"e14.example.com":[{"SPF":"v=spf1 a:foo.example.xn--zckzah -all"}],"foo.example.xn--zckzah":[{"A":"1.2.3.4"}]}, failOnNoFake: true});
        let promise = validator.validateSender('::FFFF:1.2.3.4');
        return promise.then((result) => {
          assert.equal(result, 'FAIL');
        });
      });
      it('Matches if any AAAA records are present in DNS.', function(){
        let email = 'foo@e2a.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 a/0 -all"}],"e2.example.com":[{"A":"1.1.1.1"},{"AAAA":"1234::2"},{"SPF":"v=spf1 a/0 -all"}],"e2a.example.com":[{"AAAA":"1234::1"},{"SPF":"v=spf1 a//0 -all"}],"e2b.example.com":[{"A":"1.1.1.1"},{"SPF":"v=spf1 a//0 -all"}],"ipv6.example.com":[{"AAAA":"1234::1"},{"A":"1.1.1.1"},{"SPF":"v=spf1 a -all"}],"e3.example.com":[{"SPF":"v=spf1 a:foo.example.com\u0000"}],"e4.example.com":[{"SPF":"v=spf1 a:111.222.33.44"}],"e5.example.com":[{"SPF":"v=spf1 a:abc.123"}],"e5a.example.com":[{"SPF":"v=spf1 a:museum"}],"e5b.example.com":[{"SPF":"v=spf1 a:museum."}],"e6.example.com":[{"SPF":"v=spf1 a//33 -all"}],"e6a.example.com":[{"SPF":"v=spf1 a/33 -all"}],"e7.example.com":[{"SPF":"v=spf1 a//129 -all"}],"e8.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24//64 -all"}],"e8e.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24/64 -all"}],"e8a.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24 -all"}],"e8b.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a//64 -all"}],"e9.example.com":[{"SPF":"v=spf1 a:example.com:8080"}],"e10.example.com":[{"SPF":"v=spf1 a:foo.example.com/24"}],"foo.example.com":[{"A":"1.1.1.1"},{"A":"1.2.3.5"}],"e11.example.com":[{"SPF":"v=spf1 a:foo:bar/baz.example.com"}],"foo:bar/baz.example.com":[{"A":"1.2.3.4"}],"e12.example.com":[{"SPF":"v=spf1 a:example.-com"}],"e13.example.com":[{"SPF":"v=spf1 a:"}],"e14.example.com":[{"SPF":"v=spf1 a:foo.example.xn--zckzah -all"}],"foo.example.xn--zckzah":[{"A":"1.2.3.4"}]}, failOnNoFake: true});
        let promise = validator.validateSender('1234::1');
        return promise.then((result) => {
          assert.equal(result, 'PASS');
        });
      });
      it('Simple IP6 Address match with dual stack.', function(){
        let email = 'foo@ipv6.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 a/0 -all"}],"e2.example.com":[{"A":"1.1.1.1"},{"AAAA":"1234::2"},{"SPF":"v=spf1 a/0 -all"}],"e2a.example.com":[{"AAAA":"1234::1"},{"SPF":"v=spf1 a//0 -all"}],"e2b.example.com":[{"A":"1.1.1.1"},{"SPF":"v=spf1 a//0 -all"}],"ipv6.example.com":[{"AAAA":"1234::1"},{"A":"1.1.1.1"},{"SPF":"v=spf1 a -all"}],"e3.example.com":[{"SPF":"v=spf1 a:foo.example.com\u0000"}],"e4.example.com":[{"SPF":"v=spf1 a:111.222.33.44"}],"e5.example.com":[{"SPF":"v=spf1 a:abc.123"}],"e5a.example.com":[{"SPF":"v=spf1 a:museum"}],"e5b.example.com":[{"SPF":"v=spf1 a:museum."}],"e6.example.com":[{"SPF":"v=spf1 a//33 -all"}],"e6a.example.com":[{"SPF":"v=spf1 a/33 -all"}],"e7.example.com":[{"SPF":"v=spf1 a//129 -all"}],"e8.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24//64 -all"}],"e8e.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24/64 -all"}],"e8a.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24 -all"}],"e8b.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a//64 -all"}],"e9.example.com":[{"SPF":"v=spf1 a:example.com:8080"}],"e10.example.com":[{"SPF":"v=spf1 a:foo.example.com/24"}],"foo.example.com":[{"A":"1.1.1.1"},{"A":"1.2.3.5"}],"e11.example.com":[{"SPF":"v=spf1 a:foo:bar/baz.example.com"}],"foo:bar/baz.example.com":[{"A":"1.2.3.4"}],"e12.example.com":[{"SPF":"v=spf1 a:example.-com"}],"e13.example.com":[{"SPF":"v=spf1 a:"}],"e14.example.com":[{"SPF":"v=spf1 a:foo.example.xn--zckzah -all"}],"foo.example.xn--zckzah":[{"A":"1.2.3.4"}]}, failOnNoFake: true});
        let promise = validator.validateSender('1234::1');
        return promise.then((result) => {
          assert.equal(result, 'PASS');
        });
      });
      it('No match if no AAAA records are present in DNS.', function(){
        let email = 'foo@e2b.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 a/0 -all"}],"e2.example.com":[{"A":"1.1.1.1"},{"AAAA":"1234::2"},{"SPF":"v=spf1 a/0 -all"}],"e2a.example.com":[{"AAAA":"1234::1"},{"SPF":"v=spf1 a//0 -all"}],"e2b.example.com":[{"A":"1.1.1.1"},{"SPF":"v=spf1 a//0 -all"}],"ipv6.example.com":[{"AAAA":"1234::1"},{"A":"1.1.1.1"},{"SPF":"v=spf1 a -all"}],"e3.example.com":[{"SPF":"v=spf1 a:foo.example.com\u0000"}],"e4.example.com":[{"SPF":"v=spf1 a:111.222.33.44"}],"e5.example.com":[{"SPF":"v=spf1 a:abc.123"}],"e5a.example.com":[{"SPF":"v=spf1 a:museum"}],"e5b.example.com":[{"SPF":"v=spf1 a:museum."}],"e6.example.com":[{"SPF":"v=spf1 a//33 -all"}],"e6a.example.com":[{"SPF":"v=spf1 a/33 -all"}],"e7.example.com":[{"SPF":"v=spf1 a//129 -all"}],"e8.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24//64 -all"}],"e8e.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24/64 -all"}],"e8a.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24 -all"}],"e8b.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a//64 -all"}],"e9.example.com":[{"SPF":"v=spf1 a:example.com:8080"}],"e10.example.com":[{"SPF":"v=spf1 a:foo.example.com/24"}],"foo.example.com":[{"A":"1.1.1.1"},{"A":"1.2.3.5"}],"e11.example.com":[{"SPF":"v=spf1 a:foo:bar/baz.example.com"}],"foo:bar/baz.example.com":[{"A":"1.2.3.4"}],"e12.example.com":[{"SPF":"v=spf1 a:example.-com"}],"e13.example.com":[{"SPF":"v=spf1 a:"}],"e14.example.com":[{"SPF":"v=spf1 a:foo.example.xn--zckzah -all"}],"foo.example.xn--zckzah":[{"A":"1.2.3.4"}]}, failOnNoFake: true});
        let promise = validator.validateSender('1234::1');
        return promise.then((result) => {
          assert.equal(result, 'FAIL');
        });
      });
      it('Null octets not allowed in toplabel', function(){
        let email = 'foo@e3.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 a/0 -all"}],"e2.example.com":[{"A":"1.1.1.1"},{"AAAA":"1234::2"},{"SPF":"v=spf1 a/0 -all"}],"e2a.example.com":[{"AAAA":"1234::1"},{"SPF":"v=spf1 a//0 -all"}],"e2b.example.com":[{"A":"1.1.1.1"},{"SPF":"v=spf1 a//0 -all"}],"ipv6.example.com":[{"AAAA":"1234::1"},{"A":"1.1.1.1"},{"SPF":"v=spf1 a -all"}],"e3.example.com":[{"SPF":"v=spf1 a:foo.example.com\u0000"}],"e4.example.com":[{"SPF":"v=spf1 a:111.222.33.44"}],"e5.example.com":[{"SPF":"v=spf1 a:abc.123"}],"e5a.example.com":[{"SPF":"v=spf1 a:museum"}],"e5b.example.com":[{"SPF":"v=spf1 a:museum."}],"e6.example.com":[{"SPF":"v=spf1 a//33 -all"}],"e6a.example.com":[{"SPF":"v=spf1 a/33 -all"}],"e7.example.com":[{"SPF":"v=spf1 a//129 -all"}],"e8.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24//64 -all"}],"e8e.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24/64 -all"}],"e8a.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24 -all"}],"e8b.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a//64 -all"}],"e9.example.com":[{"SPF":"v=spf1 a:example.com:8080"}],"e10.example.com":[{"SPF":"v=spf1 a:foo.example.com/24"}],"foo.example.com":[{"A":"1.1.1.1"},{"A":"1.2.3.5"}],"e11.example.com":[{"SPF":"v=spf1 a:foo:bar/baz.example.com"}],"foo:bar/baz.example.com":[{"A":"1.2.3.4"}],"e12.example.com":[{"SPF":"v=spf1 a:example.-com"}],"e13.example.com":[{"SPF":"v=spf1 a:"}],"e14.example.com":[{"SPF":"v=spf1 a:foo.example.xn--zckzah -all"}],"foo.example.xn--zckzah":[{"A":"1.2.3.4"}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.5');
        return promise.then((result) => {
          assert.equal(result, 'PERMERROR');
        });
      });
      it('toplabel may not be all numeric', function(){
        let email = 'foo@e4.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 a/0 -all"}],"e2.example.com":[{"A":"1.1.1.1"},{"AAAA":"1234::2"},{"SPF":"v=spf1 a/0 -all"}],"e2a.example.com":[{"AAAA":"1234::1"},{"SPF":"v=spf1 a//0 -all"}],"e2b.example.com":[{"A":"1.1.1.1"},{"SPF":"v=spf1 a//0 -all"}],"ipv6.example.com":[{"AAAA":"1234::1"},{"A":"1.1.1.1"},{"SPF":"v=spf1 a -all"}],"e3.example.com":[{"SPF":"v=spf1 a:foo.example.com\u0000"}],"e4.example.com":[{"SPF":"v=spf1 a:111.222.33.44"}],"e5.example.com":[{"SPF":"v=spf1 a:abc.123"}],"e5a.example.com":[{"SPF":"v=spf1 a:museum"}],"e5b.example.com":[{"SPF":"v=spf1 a:museum."}],"e6.example.com":[{"SPF":"v=spf1 a//33 -all"}],"e6a.example.com":[{"SPF":"v=spf1 a/33 -all"}],"e7.example.com":[{"SPF":"v=spf1 a//129 -all"}],"e8.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24//64 -all"}],"e8e.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24/64 -all"}],"e8a.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24 -all"}],"e8b.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a//64 -all"}],"e9.example.com":[{"SPF":"v=spf1 a:example.com:8080"}],"e10.example.com":[{"SPF":"v=spf1 a:foo.example.com/24"}],"foo.example.com":[{"A":"1.1.1.1"},{"A":"1.2.3.5"}],"e11.example.com":[{"SPF":"v=spf1 a:foo:bar/baz.example.com"}],"foo:bar/baz.example.com":[{"A":"1.2.3.4"}],"e12.example.com":[{"SPF":"v=spf1 a:example.-com"}],"e13.example.com":[{"SPF":"v=spf1 a:"}],"e14.example.com":[{"SPF":"v=spf1 a:foo.example.xn--zckzah -all"}],"foo.example.xn--zckzah":[{"A":"1.2.3.4"}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.4');
        return promise.then((result) => {
          assert.equal(result, 'PERMERROR');
        });
      });
      it('toplabel may not be all numeric', function(){
        let email = 'foo@e5.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 a/0 -all"}],"e2.example.com":[{"A":"1.1.1.1"},{"AAAA":"1234::2"},{"SPF":"v=spf1 a/0 -all"}],"e2a.example.com":[{"AAAA":"1234::1"},{"SPF":"v=spf1 a//0 -all"}],"e2b.example.com":[{"A":"1.1.1.1"},{"SPF":"v=spf1 a//0 -all"}],"ipv6.example.com":[{"AAAA":"1234::1"},{"A":"1.1.1.1"},{"SPF":"v=spf1 a -all"}],"e3.example.com":[{"SPF":"v=spf1 a:foo.example.com\u0000"}],"e4.example.com":[{"SPF":"v=spf1 a:111.222.33.44"}],"e5.example.com":[{"SPF":"v=spf1 a:abc.123"}],"e5a.example.com":[{"SPF":"v=spf1 a:museum"}],"e5b.example.com":[{"SPF":"v=spf1 a:museum."}],"e6.example.com":[{"SPF":"v=spf1 a//33 -all"}],"e6a.example.com":[{"SPF":"v=spf1 a/33 -all"}],"e7.example.com":[{"SPF":"v=spf1 a//129 -all"}],"e8.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24//64 -all"}],"e8e.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24/64 -all"}],"e8a.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24 -all"}],"e8b.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a//64 -all"}],"e9.example.com":[{"SPF":"v=spf1 a:example.com:8080"}],"e10.example.com":[{"SPF":"v=spf1 a:foo.example.com/24"}],"foo.example.com":[{"A":"1.1.1.1"},{"A":"1.2.3.5"}],"e11.example.com":[{"SPF":"v=spf1 a:foo:bar/baz.example.com"}],"foo:bar/baz.example.com":[{"A":"1.2.3.4"}],"e12.example.com":[{"SPF":"v=spf1 a:example.-com"}],"e13.example.com":[{"SPF":"v=spf1 a:"}],"e14.example.com":[{"SPF":"v=spf1 a:foo.example.xn--zckzah -all"}],"foo.example.xn--zckzah":[{"A":"1.2.3.4"}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.4');
        return promise.then((result) => {
          assert.equal(result, 'PERMERROR');
        });
      });
      it('toplabel may contain dashes', function(){
        let email = 'foo@e14.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 a/0 -all"}],"e2.example.com":[{"A":"1.1.1.1"},{"AAAA":"1234::2"},{"SPF":"v=spf1 a/0 -all"}],"e2a.example.com":[{"AAAA":"1234::1"},{"SPF":"v=spf1 a//0 -all"}],"e2b.example.com":[{"A":"1.1.1.1"},{"SPF":"v=spf1 a//0 -all"}],"ipv6.example.com":[{"AAAA":"1234::1"},{"A":"1.1.1.1"},{"SPF":"v=spf1 a -all"}],"e3.example.com":[{"SPF":"v=spf1 a:foo.example.com\u0000"}],"e4.example.com":[{"SPF":"v=spf1 a:111.222.33.44"}],"e5.example.com":[{"SPF":"v=spf1 a:abc.123"}],"e5a.example.com":[{"SPF":"v=spf1 a:museum"}],"e5b.example.com":[{"SPF":"v=spf1 a:museum."}],"e6.example.com":[{"SPF":"v=spf1 a//33 -all"}],"e6a.example.com":[{"SPF":"v=spf1 a/33 -all"}],"e7.example.com":[{"SPF":"v=spf1 a//129 -all"}],"e8.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24//64 -all"}],"e8e.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24/64 -all"}],"e8a.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24 -all"}],"e8b.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a//64 -all"}],"e9.example.com":[{"SPF":"v=spf1 a:example.com:8080"}],"e10.example.com":[{"SPF":"v=spf1 a:foo.example.com/24"}],"foo.example.com":[{"A":"1.1.1.1"},{"A":"1.2.3.5"}],"e11.example.com":[{"SPF":"v=spf1 a:foo:bar/baz.example.com"}],"foo:bar/baz.example.com":[{"A":"1.2.3.4"}],"e12.example.com":[{"SPF":"v=spf1 a:example.-com"}],"e13.example.com":[{"SPF":"v=spf1 a:"}],"e14.example.com":[{"SPF":"v=spf1 a:foo.example.xn--zckzah -all"}],"foo.example.xn--zckzah":[{"A":"1.2.3.4"}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.4');
        return promise.then((result) => {
          assert.equal(result, 'PASS');
        });
      });
      it('toplabel may not begin with a dash', function(){
        let email = 'foo@e12.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 a/0 -all"}],"e2.example.com":[{"A":"1.1.1.1"},{"AAAA":"1234::2"},{"SPF":"v=spf1 a/0 -all"}],"e2a.example.com":[{"AAAA":"1234::1"},{"SPF":"v=spf1 a//0 -all"}],"e2b.example.com":[{"A":"1.1.1.1"},{"SPF":"v=spf1 a//0 -all"}],"ipv6.example.com":[{"AAAA":"1234::1"},{"A":"1.1.1.1"},{"SPF":"v=spf1 a -all"}],"e3.example.com":[{"SPF":"v=spf1 a:foo.example.com\u0000"}],"e4.example.com":[{"SPF":"v=spf1 a:111.222.33.44"}],"e5.example.com":[{"SPF":"v=spf1 a:abc.123"}],"e5a.example.com":[{"SPF":"v=spf1 a:museum"}],"e5b.example.com":[{"SPF":"v=spf1 a:museum."}],"e6.example.com":[{"SPF":"v=spf1 a//33 -all"}],"e6a.example.com":[{"SPF":"v=spf1 a/33 -all"}],"e7.example.com":[{"SPF":"v=spf1 a//129 -all"}],"e8.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24//64 -all"}],"e8e.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24/64 -all"}],"e8a.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24 -all"}],"e8b.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a//64 -all"}],"e9.example.com":[{"SPF":"v=spf1 a:example.com:8080"}],"e10.example.com":[{"SPF":"v=spf1 a:foo.example.com/24"}],"foo.example.com":[{"A":"1.1.1.1"},{"A":"1.2.3.5"}],"e11.example.com":[{"SPF":"v=spf1 a:foo:bar/baz.example.com"}],"foo:bar/baz.example.com":[{"A":"1.2.3.4"}],"e12.example.com":[{"SPF":"v=spf1 a:example.-com"}],"e13.example.com":[{"SPF":"v=spf1 a:"}],"e14.example.com":[{"SPF":"v=spf1 a:foo.example.xn--zckzah -all"}],"foo.example.xn--zckzah":[{"A":"1.2.3.4"}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.4');
        return promise.then((result) => {
          assert.equal(result, 'PERMERROR');
        });
      });
      it('domain-spec may not consist of only a toplabel.', function(){
        let email = 'foo@e5a.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 a/0 -all"}],"e2.example.com":[{"A":"1.1.1.1"},{"AAAA":"1234::2"},{"SPF":"v=spf1 a/0 -all"}],"e2a.example.com":[{"AAAA":"1234::1"},{"SPF":"v=spf1 a//0 -all"}],"e2b.example.com":[{"A":"1.1.1.1"},{"SPF":"v=spf1 a//0 -all"}],"ipv6.example.com":[{"AAAA":"1234::1"},{"A":"1.1.1.1"},{"SPF":"v=spf1 a -all"}],"e3.example.com":[{"SPF":"v=spf1 a:foo.example.com\u0000"}],"e4.example.com":[{"SPF":"v=spf1 a:111.222.33.44"}],"e5.example.com":[{"SPF":"v=spf1 a:abc.123"}],"e5a.example.com":[{"SPF":"v=spf1 a:museum"}],"e5b.example.com":[{"SPF":"v=spf1 a:museum."}],"e6.example.com":[{"SPF":"v=spf1 a//33 -all"}],"e6a.example.com":[{"SPF":"v=spf1 a/33 -all"}],"e7.example.com":[{"SPF":"v=spf1 a//129 -all"}],"e8.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24//64 -all"}],"e8e.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24/64 -all"}],"e8a.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24 -all"}],"e8b.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a//64 -all"}],"e9.example.com":[{"SPF":"v=spf1 a:example.com:8080"}],"e10.example.com":[{"SPF":"v=spf1 a:foo.example.com/24"}],"foo.example.com":[{"A":"1.1.1.1"},{"A":"1.2.3.5"}],"e11.example.com":[{"SPF":"v=spf1 a:foo:bar/baz.example.com"}],"foo:bar/baz.example.com":[{"A":"1.2.3.4"}],"e12.example.com":[{"SPF":"v=spf1 a:example.-com"}],"e13.example.com":[{"SPF":"v=spf1 a:"}],"e14.example.com":[{"SPF":"v=spf1 a:foo.example.xn--zckzah -all"}],"foo.example.xn--zckzah":[{"A":"1.2.3.4"}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.4');
        return promise.then((result) => {
          assert.equal(result, 'PERMERROR');
        });
      });
      it('domain-spec may not consist of only a toplabel.', function(){
        let email = 'foo@e5b.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 a/0 -all"}],"e2.example.com":[{"A":"1.1.1.1"},{"AAAA":"1234::2"},{"SPF":"v=spf1 a/0 -all"}],"e2a.example.com":[{"AAAA":"1234::1"},{"SPF":"v=spf1 a//0 -all"}],"e2b.example.com":[{"A":"1.1.1.1"},{"SPF":"v=spf1 a//0 -all"}],"ipv6.example.com":[{"AAAA":"1234::1"},{"A":"1.1.1.1"},{"SPF":"v=spf1 a -all"}],"e3.example.com":[{"SPF":"v=spf1 a:foo.example.com\u0000"}],"e4.example.com":[{"SPF":"v=spf1 a:111.222.33.44"}],"e5.example.com":[{"SPF":"v=spf1 a:abc.123"}],"e5a.example.com":[{"SPF":"v=spf1 a:museum"}],"e5b.example.com":[{"SPF":"v=spf1 a:museum."}],"e6.example.com":[{"SPF":"v=spf1 a//33 -all"}],"e6a.example.com":[{"SPF":"v=spf1 a/33 -all"}],"e7.example.com":[{"SPF":"v=spf1 a//129 -all"}],"e8.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24//64 -all"}],"e8e.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24/64 -all"}],"e8a.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24 -all"}],"e8b.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a//64 -all"}],"e9.example.com":[{"SPF":"v=spf1 a:example.com:8080"}],"e10.example.com":[{"SPF":"v=spf1 a:foo.example.com/24"}],"foo.example.com":[{"A":"1.1.1.1"},{"A":"1.2.3.5"}],"e11.example.com":[{"SPF":"v=spf1 a:foo:bar/baz.example.com"}],"foo:bar/baz.example.com":[{"A":"1.2.3.4"}],"e12.example.com":[{"SPF":"v=spf1 a:example.-com"}],"e13.example.com":[{"SPF":"v=spf1 a:"}],"e14.example.com":[{"SPF":"v=spf1 a:foo.example.xn--zckzah -all"}],"foo.example.xn--zckzah":[{"A":"1.2.3.4"}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.4');
        return promise.then((result) => {
          assert.equal(result, 'PERMERROR');
        });
      });
      it('domain-spec may contain any visible char except %', function(){
        let email = 'foo@e11.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 a/0 -all"}],"e2.example.com":[{"A":"1.1.1.1"},{"AAAA":"1234::2"},{"SPF":"v=spf1 a/0 -all"}],"e2a.example.com":[{"AAAA":"1234::1"},{"SPF":"v=spf1 a//0 -all"}],"e2b.example.com":[{"A":"1.1.1.1"},{"SPF":"v=spf1 a//0 -all"}],"ipv6.example.com":[{"AAAA":"1234::1"},{"A":"1.1.1.1"},{"SPF":"v=spf1 a -all"}],"e3.example.com":[{"SPF":"v=spf1 a:foo.example.com\u0000"}],"e4.example.com":[{"SPF":"v=spf1 a:111.222.33.44"}],"e5.example.com":[{"SPF":"v=spf1 a:abc.123"}],"e5a.example.com":[{"SPF":"v=spf1 a:museum"}],"e5b.example.com":[{"SPF":"v=spf1 a:museum."}],"e6.example.com":[{"SPF":"v=spf1 a//33 -all"}],"e6a.example.com":[{"SPF":"v=spf1 a/33 -all"}],"e7.example.com":[{"SPF":"v=spf1 a//129 -all"}],"e8.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24//64 -all"}],"e8e.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24/64 -all"}],"e8a.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24 -all"}],"e8b.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a//64 -all"}],"e9.example.com":[{"SPF":"v=spf1 a:example.com:8080"}],"e10.example.com":[{"SPF":"v=spf1 a:foo.example.com/24"}],"foo.example.com":[{"A":"1.1.1.1"},{"A":"1.2.3.5"}],"e11.example.com":[{"SPF":"v=spf1 a:foo:bar/baz.example.com"}],"foo:bar/baz.example.com":[{"A":"1.2.3.4"}],"e12.example.com":[{"SPF":"v=spf1 a:example.-com"}],"e13.example.com":[{"SPF":"v=spf1 a:"}],"e14.example.com":[{"SPF":"v=spf1 a:foo.example.xn--zckzah -all"}],"foo.example.xn--zckzah":[{"A":"1.2.3.4"}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.4');
        return promise.then((result) => {
          assert.equal(result, 'PASS');
        });
      });
      it('domain-spec may contain any visible char except %', function(){
        let email = 'foo@e11.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 a/0 -all"}],"e2.example.com":[{"A":"1.1.1.1"},{"AAAA":"1234::2"},{"SPF":"v=spf1 a/0 -all"}],"e2a.example.com":[{"AAAA":"1234::1"},{"SPF":"v=spf1 a//0 -all"}],"e2b.example.com":[{"A":"1.1.1.1"},{"SPF":"v=spf1 a//0 -all"}],"ipv6.example.com":[{"AAAA":"1234::1"},{"A":"1.1.1.1"},{"SPF":"v=spf1 a -all"}],"e3.example.com":[{"SPF":"v=spf1 a:foo.example.com\u0000"}],"e4.example.com":[{"SPF":"v=spf1 a:111.222.33.44"}],"e5.example.com":[{"SPF":"v=spf1 a:abc.123"}],"e5a.example.com":[{"SPF":"v=spf1 a:museum"}],"e5b.example.com":[{"SPF":"v=spf1 a:museum."}],"e6.example.com":[{"SPF":"v=spf1 a//33 -all"}],"e6a.example.com":[{"SPF":"v=spf1 a/33 -all"}],"e7.example.com":[{"SPF":"v=spf1 a//129 -all"}],"e8.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24//64 -all"}],"e8e.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24/64 -all"}],"e8a.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24 -all"}],"e8b.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a//64 -all"}],"e9.example.com":[{"SPF":"v=spf1 a:example.com:8080"}],"e10.example.com":[{"SPF":"v=spf1 a:foo.example.com/24"}],"foo.example.com":[{"A":"1.1.1.1"},{"A":"1.2.3.5"}],"e11.example.com":[{"SPF":"v=spf1 a:foo:bar/baz.example.com"}],"foo:bar/baz.example.com":[{"A":"1.2.3.4"}],"e12.example.com":[{"SPF":"v=spf1 a:example.-com"}],"e13.example.com":[{"SPF":"v=spf1 a:"}],"e14.example.com":[{"SPF":"v=spf1 a:foo.example.xn--zckzah -all"}],"foo.example.xn--zckzah":[{"A":"1.2.3.4"}]}, failOnNoFake: true});
        let promise = validator.validateSender('::FFFF:1.2.3.4');
        return promise.then((result) => {
          assert.equal(result, 'PASS');
        });
      });
      it('domain-spec cannot be empty.', function(){
        let email = 'foo@e13.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 a/0 -all"}],"e2.example.com":[{"A":"1.1.1.1"},{"AAAA":"1234::2"},{"SPF":"v=spf1 a/0 -all"}],"e2a.example.com":[{"AAAA":"1234::1"},{"SPF":"v=spf1 a//0 -all"}],"e2b.example.com":[{"A":"1.1.1.1"},{"SPF":"v=spf1 a//0 -all"}],"ipv6.example.com":[{"AAAA":"1234::1"},{"A":"1.1.1.1"},{"SPF":"v=spf1 a -all"}],"e3.example.com":[{"SPF":"v=spf1 a:foo.example.com\u0000"}],"e4.example.com":[{"SPF":"v=spf1 a:111.222.33.44"}],"e5.example.com":[{"SPF":"v=spf1 a:abc.123"}],"e5a.example.com":[{"SPF":"v=spf1 a:museum"}],"e5b.example.com":[{"SPF":"v=spf1 a:museum."}],"e6.example.com":[{"SPF":"v=spf1 a//33 -all"}],"e6a.example.com":[{"SPF":"v=spf1 a/33 -all"}],"e7.example.com":[{"SPF":"v=spf1 a//129 -all"}],"e8.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24//64 -all"}],"e8e.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24/64 -all"}],"e8a.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24 -all"}],"e8b.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a//64 -all"}],"e9.example.com":[{"SPF":"v=spf1 a:example.com:8080"}],"e10.example.com":[{"SPF":"v=spf1 a:foo.example.com/24"}],"foo.example.com":[{"A":"1.1.1.1"},{"A":"1.2.3.5"}],"e11.example.com":[{"SPF":"v=spf1 a:foo:bar/baz.example.com"}],"foo:bar/baz.example.com":[{"A":"1.2.3.4"}],"e12.example.com":[{"SPF":"v=spf1 a:example.-com"}],"e13.example.com":[{"SPF":"v=spf1 a:"}],"e14.example.com":[{"SPF":"v=spf1 a:foo.example.xn--zckzah -all"}],"foo.example.xn--zckzah":[{"A":"1.2.3.4"}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.4');
        return promise.then((result) => {
          assert.equal(result, 'PERMERROR');
        });
      });
    });
    describe('Include mechanism semantics and syntax', function(){
      it('recursive check_host() result of fail causes include to not match.', function(){
        let email = 'foo@e1.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"ip5.example.com":[{"SPF":"v=spf1 ip4:1.2.3.5 -all"}],"ip6.example.com":[{"SPF":"v=spf1 ip4:1.2.3.6 ~all"}],"ip7.example.com":[{"SPF":"v=spf1 ip4:1.2.3.7 ?all"}],"ip8.example.com":["TIMEOUT"],"erehwon.example.com":[{"TXT":"v=spfl am not an SPF record"}],"e1.example.com":[{"SPF":"v=spf1 include:ip5.example.com ~all"}],"e2.example.com":[{"SPF":"v=spf1 include:ip6.example.com all"}],"e3.example.com":[{"SPF":"v=spf1 include:ip7.example.com -all"}],"e4.example.com":[{"SPF":"v=spf1 include:ip8.example.com -all"}],"e5.example.com":[{"SPF":"v=spf1 include:e6.example.com -all"}],"e6.example.com":[{"SPF":"v=spf1 include +all"}],"e7.example.com":[{"SPF":"v=spf1 include:erehwon.example.com -all"}],"e8.example.com":[{"SPF":"v=spf1 include: -all"}],"e9.example.com":[{"SPF":"v=spf1 include:ip5.example.com/24 -all"}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.4');
        return promise.then((result) => {
          assert.equal(result, 'SOFTFAIL');
        });
      });
      it('recursive check_host() result of softfail causes include to not match.', function(){
        let email = 'foo@e2.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"ip5.example.com":[{"SPF":"v=spf1 ip4:1.2.3.5 -all"}],"ip6.example.com":[{"SPF":"v=spf1 ip4:1.2.3.6 ~all"}],"ip7.example.com":[{"SPF":"v=spf1 ip4:1.2.3.7 ?all"}],"ip8.example.com":["TIMEOUT"],"erehwon.example.com":[{"TXT":"v=spfl am not an SPF record"}],"e1.example.com":[{"SPF":"v=spf1 include:ip5.example.com ~all"}],"e2.example.com":[{"SPF":"v=spf1 include:ip6.example.com all"}],"e3.example.com":[{"SPF":"v=spf1 include:ip7.example.com -all"}],"e4.example.com":[{"SPF":"v=spf1 include:ip8.example.com -all"}],"e5.example.com":[{"SPF":"v=spf1 include:e6.example.com -all"}],"e6.example.com":[{"SPF":"v=spf1 include +all"}],"e7.example.com":[{"SPF":"v=spf1 include:erehwon.example.com -all"}],"e8.example.com":[{"SPF":"v=spf1 include: -all"}],"e9.example.com":[{"SPF":"v=spf1 include:ip5.example.com/24 -all"}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.4');
        return promise.then((result) => {
          assert.equal(result, 'PASS');
        });
      });
      it('recursive check_host() result of neutral causes include to not match.', function(){
        let email = 'foo@e3.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"ip5.example.com":[{"SPF":"v=spf1 ip4:1.2.3.5 -all"}],"ip6.example.com":[{"SPF":"v=spf1 ip4:1.2.3.6 ~all"}],"ip7.example.com":[{"SPF":"v=spf1 ip4:1.2.3.7 ?all"}],"ip8.example.com":["TIMEOUT"],"erehwon.example.com":[{"TXT":"v=spfl am not an SPF record"}],"e1.example.com":[{"SPF":"v=spf1 include:ip5.example.com ~all"}],"e2.example.com":[{"SPF":"v=spf1 include:ip6.example.com all"}],"e3.example.com":[{"SPF":"v=spf1 include:ip7.example.com -all"}],"e4.example.com":[{"SPF":"v=spf1 include:ip8.example.com -all"}],"e5.example.com":[{"SPF":"v=spf1 include:e6.example.com -all"}],"e6.example.com":[{"SPF":"v=spf1 include +all"}],"e7.example.com":[{"SPF":"v=spf1 include:erehwon.example.com -all"}],"e8.example.com":[{"SPF":"v=spf1 include: -all"}],"e9.example.com":[{"SPF":"v=spf1 include:ip5.example.com/24 -all"}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.4');
        return promise.then((result) => {
          assert.equal(result, 'FAIL');
        });
      });
      it('recursive check_host() result of temperror causes include to temperror', function(){
        let email = 'foo@e4.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"ip5.example.com":[{"SPF":"v=spf1 ip4:1.2.3.5 -all"}],"ip6.example.com":[{"SPF":"v=spf1 ip4:1.2.3.6 ~all"}],"ip7.example.com":[{"SPF":"v=spf1 ip4:1.2.3.7 ?all"}],"ip8.example.com":["TIMEOUT"],"erehwon.example.com":[{"TXT":"v=spfl am not an SPF record"}],"e1.example.com":[{"SPF":"v=spf1 include:ip5.example.com ~all"}],"e2.example.com":[{"SPF":"v=spf1 include:ip6.example.com all"}],"e3.example.com":[{"SPF":"v=spf1 include:ip7.example.com -all"}],"e4.example.com":[{"SPF":"v=spf1 include:ip8.example.com -all"}],"e5.example.com":[{"SPF":"v=spf1 include:e6.example.com -all"}],"e6.example.com":[{"SPF":"v=spf1 include +all"}],"e7.example.com":[{"SPF":"v=spf1 include:erehwon.example.com -all"}],"e8.example.com":[{"SPF":"v=spf1 include: -all"}],"e9.example.com":[{"SPF":"v=spf1 include:ip5.example.com/24 -all"}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.4');
        return promise.then((result) => {
          assert.equal(result, 'TEMPERROR');
        });
      });
      it('recursive check_host() result of permerror causes include to permerror', function(){
        let email = 'foo@e5.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"ip5.example.com":[{"SPF":"v=spf1 ip4:1.2.3.5 -all"}],"ip6.example.com":[{"SPF":"v=spf1 ip4:1.2.3.6 ~all"}],"ip7.example.com":[{"SPF":"v=spf1 ip4:1.2.3.7 ?all"}],"ip8.example.com":["TIMEOUT"],"erehwon.example.com":[{"TXT":"v=spfl am not an SPF record"}],"e1.example.com":[{"SPF":"v=spf1 include:ip5.example.com ~all"}],"e2.example.com":[{"SPF":"v=spf1 include:ip6.example.com all"}],"e3.example.com":[{"SPF":"v=spf1 include:ip7.example.com -all"}],"e4.example.com":[{"SPF":"v=spf1 include:ip8.example.com -all"}],"e5.example.com":[{"SPF":"v=spf1 include:e6.example.com -all"}],"e6.example.com":[{"SPF":"v=spf1 include +all"}],"e7.example.com":[{"SPF":"v=spf1 include:erehwon.example.com -all"}],"e8.example.com":[{"SPF":"v=spf1 include: -all"}],"e9.example.com":[{"SPF":"v=spf1 include:ip5.example.com/24 -all"}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.4');
        return promise.then((result) => {
          assert.equal(result, 'PERMERROR');
        });
      });
      it('include          = "include"  ":" domain-spec', function(){
        let email = 'foo@e6.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"ip5.example.com":[{"SPF":"v=spf1 ip4:1.2.3.5 -all"}],"ip6.example.com":[{"SPF":"v=spf1 ip4:1.2.3.6 ~all"}],"ip7.example.com":[{"SPF":"v=spf1 ip4:1.2.3.7 ?all"}],"ip8.example.com":["TIMEOUT"],"erehwon.example.com":[{"TXT":"v=spfl am not an SPF record"}],"e1.example.com":[{"SPF":"v=spf1 include:ip5.example.com ~all"}],"e2.example.com":[{"SPF":"v=spf1 include:ip6.example.com all"}],"e3.example.com":[{"SPF":"v=spf1 include:ip7.example.com -all"}],"e4.example.com":[{"SPF":"v=spf1 include:ip8.example.com -all"}],"e5.example.com":[{"SPF":"v=spf1 include:e6.example.com -all"}],"e6.example.com":[{"SPF":"v=spf1 include +all"}],"e7.example.com":[{"SPF":"v=spf1 include:erehwon.example.com -all"}],"e8.example.com":[{"SPF":"v=spf1 include: -all"}],"e9.example.com":[{"SPF":"v=spf1 include:ip5.example.com/24 -all"}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.4');
        return promise.then((result) => {
          assert.equal(result, 'PERMERROR');
        });
      });
      it('include          = "include"  ":" domain-spec', function(){
        let email = 'foo@e9.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"ip5.example.com":[{"SPF":"v=spf1 ip4:1.2.3.5 -all"}],"ip6.example.com":[{"SPF":"v=spf1 ip4:1.2.3.6 ~all"}],"ip7.example.com":[{"SPF":"v=spf1 ip4:1.2.3.7 ?all"}],"ip8.example.com":["TIMEOUT"],"erehwon.example.com":[{"TXT":"v=spfl am not an SPF record"}],"e1.example.com":[{"SPF":"v=spf1 include:ip5.example.com ~all"}],"e2.example.com":[{"SPF":"v=spf1 include:ip6.example.com all"}],"e3.example.com":[{"SPF":"v=spf1 include:ip7.example.com -all"}],"e4.example.com":[{"SPF":"v=spf1 include:ip8.example.com -all"}],"e5.example.com":[{"SPF":"v=spf1 include:e6.example.com -all"}],"e6.example.com":[{"SPF":"v=spf1 include +all"}],"e7.example.com":[{"SPF":"v=spf1 include:erehwon.example.com -all"}],"e8.example.com":[{"SPF":"v=spf1 include: -all"}],"e9.example.com":[{"SPF":"v=spf1 include:ip5.example.com/24 -all"}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.4');
        return promise.then((result) => {
          assert.equal(result, 'PERMERROR');
        });
      });
      it('recursive check_host() result of none causes include to permerror', function(){
        let email = 'foo@e7.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"ip5.example.com":[{"SPF":"v=spf1 ip4:1.2.3.5 -all"}],"ip6.example.com":[{"SPF":"v=spf1 ip4:1.2.3.6 ~all"}],"ip7.example.com":[{"SPF":"v=spf1 ip4:1.2.3.7 ?all"}],"ip8.example.com":["TIMEOUT"],"erehwon.example.com":[{"TXT":"v=spfl am not an SPF record"}],"e1.example.com":[{"SPF":"v=spf1 include:ip5.example.com ~all"}],"e2.example.com":[{"SPF":"v=spf1 include:ip6.example.com all"}],"e3.example.com":[{"SPF":"v=spf1 include:ip7.example.com -all"}],"e4.example.com":[{"SPF":"v=spf1 include:ip8.example.com -all"}],"e5.example.com":[{"SPF":"v=spf1 include:e6.example.com -all"}],"e6.example.com":[{"SPF":"v=spf1 include +all"}],"e7.example.com":[{"SPF":"v=spf1 include:erehwon.example.com -all"}],"e8.example.com":[{"SPF":"v=spf1 include: -all"}],"e9.example.com":[{"SPF":"v=spf1 include:ip5.example.com/24 -all"}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.4');
        return promise.then((result) => {
          assert.equal(result, 'PERMERROR');
        });
      });
      it('domain-spec cannot be empty.', function(){
        let email = 'foo@e8.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"ip5.example.com":[{"SPF":"v=spf1 ip4:1.2.3.5 -all"}],"ip6.example.com":[{"SPF":"v=spf1 ip4:1.2.3.6 ~all"}],"ip7.example.com":[{"SPF":"v=spf1 ip4:1.2.3.7 ?all"}],"ip8.example.com":["TIMEOUT"],"erehwon.example.com":[{"TXT":"v=spfl am not an SPF record"}],"e1.example.com":[{"SPF":"v=spf1 include:ip5.example.com ~all"}],"e2.example.com":[{"SPF":"v=spf1 include:ip6.example.com all"}],"e3.example.com":[{"SPF":"v=spf1 include:ip7.example.com -all"}],"e4.example.com":[{"SPF":"v=spf1 include:ip8.example.com -all"}],"e5.example.com":[{"SPF":"v=spf1 include:e6.example.com -all"}],"e6.example.com":[{"SPF":"v=spf1 include +all"}],"e7.example.com":[{"SPF":"v=spf1 include:erehwon.example.com -all"}],"e8.example.com":[{"SPF":"v=spf1 include: -all"}],"e9.example.com":[{"SPF":"v=spf1 include:ip5.example.com/24 -all"}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.4');
        return promise.then((result) => {
          assert.equal(result, 'PERMERROR');
        });
      });
    });
    describe('MX mechanism syntax', function(){
      it('MX                = "mx"      [ ":" domain-spec ] [ dual-cidr-length ] dual-cidr-length = [ ip4-cidr-length ] [ "/" ip6-cidr-length ]', function(){
        let email = 'foo@e6.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"},{"MX":[0,""]},{"SPF":"v=spf1 mx"}],"e1.example.com":[{"SPF":"v=spf1 mx/0 -all"},{"MX":[0,"e1.example.com"]}],"e2.example.com":[{"A":"1.1.1.1"},{"AAAA":"1234::2"},{"MX":[0,"e2.example.com"]},{"SPF":"v=spf1 mx/0 -all"}],"e2a.example.com":[{"AAAA":"1234::1"},{"MX":[0,"e2a.example.com"]},{"SPF":"v=spf1 mx//0 -all"}],"e2b.example.com":[{"A":"1.1.1.1"},{"MX":[0,"e2b.example.com"]},{"SPF":"v=spf1 mx//0 -all"}],"e3.example.com":[{"SPF":"v=spf1 mx:foo.example.com\u0000"}],"e4.example.com":[{"SPF":"v=spf1 mx"},{"A":"1.2.3.4"}],"e5.example.com":[{"SPF":"v=spf1 mx:abc.123"}],"e6.example.com":[{"SPF":"v=spf1 mx//33 -all"}],"e6a.example.com":[{"SPF":"v=spf1 mx/33 -all"}],"e7.example.com":[{"SPF":"v=spf1 mx//129 -all"}],"e9.example.com":[{"SPF":"v=spf1 mx:example.com:8080"}],"e10.example.com":[{"SPF":"v=spf1 mx:foo.example.com/24"}],"foo.example.com":[{"MX":[0,"foo1.example.com"]}],"foo1.example.com":[{"A":"1.1.1.1"},{"A":"1.2.3.5"}],"e11.example.com":[{"SPF":"v=spf1 mx:foo:bar/baz.example.com"}],"foo:bar/baz.example.com":[{"MX":[0,"foo:bar/baz.example.com"]},{"A":"1.2.3.4"}],"e12.example.com":[{"SPF":"v=spf1 mx:example.-com"}],"e13.example.com":[{"SPF":"v=spf1 mx: -all"}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.4');
        return promise.then((result) => {
          assert.equal(result, 'FAIL');
        });
      });
      it('MX                = "mx"      [ ":" domain-spec ] [ dual-cidr-length ] dual-cidr-length = [ ip4-cidr-length ] [ "/" ip6-cidr-length ]', function(){
        let email = 'foo@e6a.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"},{"MX":[0,""]},{"SPF":"v=spf1 mx"}],"e1.example.com":[{"SPF":"v=spf1 mx/0 -all"},{"MX":[0,"e1.example.com"]}],"e2.example.com":[{"A":"1.1.1.1"},{"AAAA":"1234::2"},{"MX":[0,"e2.example.com"]},{"SPF":"v=spf1 mx/0 -all"}],"e2a.example.com":[{"AAAA":"1234::1"},{"MX":[0,"e2a.example.com"]},{"SPF":"v=spf1 mx//0 -all"}],"e2b.example.com":[{"A":"1.1.1.1"},{"MX":[0,"e2b.example.com"]},{"SPF":"v=spf1 mx//0 -all"}],"e3.example.com":[{"SPF":"v=spf1 mx:foo.example.com\u0000"}],"e4.example.com":[{"SPF":"v=spf1 mx"},{"A":"1.2.3.4"}],"e5.example.com":[{"SPF":"v=spf1 mx:abc.123"}],"e6.example.com":[{"SPF":"v=spf1 mx//33 -all"}],"e6a.example.com":[{"SPF":"v=spf1 mx/33 -all"}],"e7.example.com":[{"SPF":"v=spf1 mx//129 -all"}],"e9.example.com":[{"SPF":"v=spf1 mx:example.com:8080"}],"e10.example.com":[{"SPF":"v=spf1 mx:foo.example.com/24"}],"foo.example.com":[{"MX":[0,"foo1.example.com"]}],"foo1.example.com":[{"A":"1.1.1.1"},{"A":"1.2.3.5"}],"e11.example.com":[{"SPF":"v=spf1 mx:foo:bar/baz.example.com"}],"foo:bar/baz.example.com":[{"MX":[0,"foo:bar/baz.example.com"]},{"A":"1.2.3.4"}],"e12.example.com":[{"SPF":"v=spf1 mx:example.-com"}],"e13.example.com":[{"SPF":"v=spf1 mx: -all"}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.4');
        return promise.then((result) => {
          assert.equal(result, 'PERMERROR');
        });
      });
      it('MX                = "mx"      [ ":" domain-spec ] [ dual-cidr-length ] dual-cidr-length = [ ip4-cidr-length ] [ "/" ip6-cidr-length ]', function(){
        let email = 'foo@e7.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"},{"MX":[0,""]},{"SPF":"v=spf1 mx"}],"e1.example.com":[{"SPF":"v=spf1 mx/0 -all"},{"MX":[0,"e1.example.com"]}],"e2.example.com":[{"A":"1.1.1.1"},{"AAAA":"1234::2"},{"MX":[0,"e2.example.com"]},{"SPF":"v=spf1 mx/0 -all"}],"e2a.example.com":[{"AAAA":"1234::1"},{"MX":[0,"e2a.example.com"]},{"SPF":"v=spf1 mx//0 -all"}],"e2b.example.com":[{"A":"1.1.1.1"},{"MX":[0,"e2b.example.com"]},{"SPF":"v=spf1 mx//0 -all"}],"e3.example.com":[{"SPF":"v=spf1 mx:foo.example.com\u0000"}],"e4.example.com":[{"SPF":"v=spf1 mx"},{"A":"1.2.3.4"}],"e5.example.com":[{"SPF":"v=spf1 mx:abc.123"}],"e6.example.com":[{"SPF":"v=spf1 mx//33 -all"}],"e6a.example.com":[{"SPF":"v=spf1 mx/33 -all"}],"e7.example.com":[{"SPF":"v=spf1 mx//129 -all"}],"e9.example.com":[{"SPF":"v=spf1 mx:example.com:8080"}],"e10.example.com":[{"SPF":"v=spf1 mx:foo.example.com/24"}],"foo.example.com":[{"MX":[0,"foo1.example.com"]}],"foo1.example.com":[{"A":"1.1.1.1"},{"A":"1.2.3.5"}],"e11.example.com":[{"SPF":"v=spf1 mx:foo:bar/baz.example.com"}],"foo:bar/baz.example.com":[{"MX":[0,"foo:bar/baz.example.com"]},{"A":"1.2.3.4"}],"e12.example.com":[{"SPF":"v=spf1 mx:example.-com"}],"e13.example.com":[{"SPF":"v=spf1 mx: -all"}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.4');
        return promise.then((result) => {
          assert.equal(result, 'PERMERROR');
        });
      });
      it('MX matches any returned IP.', function(){
        let email = 'foo@e10.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"},{"MX":[0,""]},{"SPF":"v=spf1 mx"}],"e1.example.com":[{"SPF":"v=spf1 mx/0 -all"},{"MX":[0,"e1.example.com"]}],"e2.example.com":[{"A":"1.1.1.1"},{"AAAA":"1234::2"},{"MX":[0,"e2.example.com"]},{"SPF":"v=spf1 mx/0 -all"}],"e2a.example.com":[{"AAAA":"1234::1"},{"MX":[0,"e2a.example.com"]},{"SPF":"v=spf1 mx//0 -all"}],"e2b.example.com":[{"A":"1.1.1.1"},{"MX":[0,"e2b.example.com"]},{"SPF":"v=spf1 mx//0 -all"}],"e3.example.com":[{"SPF":"v=spf1 mx:foo.example.com\u0000"}],"e4.example.com":[{"SPF":"v=spf1 mx"},{"A":"1.2.3.4"}],"e5.example.com":[{"SPF":"v=spf1 mx:abc.123"}],"e6.example.com":[{"SPF":"v=spf1 mx//33 -all"}],"e6a.example.com":[{"SPF":"v=spf1 mx/33 -all"}],"e7.example.com":[{"SPF":"v=spf1 mx//129 -all"}],"e9.example.com":[{"SPF":"v=spf1 mx:example.com:8080"}],"e10.example.com":[{"SPF":"v=spf1 mx:foo.example.com/24"}],"foo.example.com":[{"MX":[0,"foo1.example.com"]}],"foo1.example.com":[{"A":"1.1.1.1"},{"A":"1.2.3.5"}],"e11.example.com":[{"SPF":"v=spf1 mx:foo:bar/baz.example.com"}],"foo:bar/baz.example.com":[{"MX":[0,"foo:bar/baz.example.com"]},{"A":"1.2.3.4"}],"e12.example.com":[{"SPF":"v=spf1 mx:example.-com"}],"e13.example.com":[{"SPF":"v=spf1 mx: -all"}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.4');
        return promise.then((result) => {
          assert.equal(result, 'PASS');
        });
      });
      it('MX matches any returned IP.', function(){
        let email = 'foo@e10.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"},{"MX":[0,""]},{"SPF":"v=spf1 mx"}],"e1.example.com":[{"SPF":"v=spf1 mx/0 -all"},{"MX":[0,"e1.example.com"]}],"e2.example.com":[{"A":"1.1.1.1"},{"AAAA":"1234::2"},{"MX":[0,"e2.example.com"]},{"SPF":"v=spf1 mx/0 -all"}],"e2a.example.com":[{"AAAA":"1234::1"},{"MX":[0,"e2a.example.com"]},{"SPF":"v=spf1 mx//0 -all"}],"e2b.example.com":[{"A":"1.1.1.1"},{"MX":[0,"e2b.example.com"]},{"SPF":"v=spf1 mx//0 -all"}],"e3.example.com":[{"SPF":"v=spf1 mx:foo.example.com\u0000"}],"e4.example.com":[{"SPF":"v=spf1 mx"},{"A":"1.2.3.4"}],"e5.example.com":[{"SPF":"v=spf1 mx:abc.123"}],"e6.example.com":[{"SPF":"v=spf1 mx//33 -all"}],"e6a.example.com":[{"SPF":"v=spf1 mx/33 -all"}],"e7.example.com":[{"SPF":"v=spf1 mx//129 -all"}],"e9.example.com":[{"SPF":"v=spf1 mx:example.com:8080"}],"e10.example.com":[{"SPF":"v=spf1 mx:foo.example.com/24"}],"foo.example.com":[{"MX":[0,"foo1.example.com"]}],"foo1.example.com":[{"A":"1.1.1.1"},{"A":"1.2.3.5"}],"e11.example.com":[{"SPF":"v=spf1 mx:foo:bar/baz.example.com"}],"foo:bar/baz.example.com":[{"MX":[0,"foo:bar/baz.example.com"]},{"A":"1.2.3.4"}],"e12.example.com":[{"SPF":"v=spf1 mx:example.-com"}],"e13.example.com":[{"SPF":"v=spf1 mx: -all"}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.4');
        return promise.then((result) => {
          assert.equal(result, 'PASS');
        });
      });
      it('domain-spec must pass basic syntax checks', function(){
        let email = 'foo@e9.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"},{"MX":[0,""]},{"SPF":"v=spf1 mx"}],"e1.example.com":[{"SPF":"v=spf1 mx/0 -all"},{"MX":[0,"e1.example.com"]}],"e2.example.com":[{"A":"1.1.1.1"},{"AAAA":"1234::2"},{"MX":[0,"e2.example.com"]},{"SPF":"v=spf1 mx/0 -all"}],"e2a.example.com":[{"AAAA":"1234::1"},{"MX":[0,"e2a.example.com"]},{"SPF":"v=spf1 mx//0 -all"}],"e2b.example.com":[{"A":"1.1.1.1"},{"MX":[0,"e2b.example.com"]},{"SPF":"v=spf1 mx//0 -all"}],"e3.example.com":[{"SPF":"v=spf1 mx:foo.example.com\u0000"}],"e4.example.com":[{"SPF":"v=spf1 mx"},{"A":"1.2.3.4"}],"e5.example.com":[{"SPF":"v=spf1 mx:abc.123"}],"e6.example.com":[{"SPF":"v=spf1 mx//33 -all"}],"e6a.example.com":[{"SPF":"v=spf1 mx/33 -all"}],"e7.example.com":[{"SPF":"v=spf1 mx//129 -all"}],"e9.example.com":[{"SPF":"v=spf1 mx:example.com:8080"}],"e10.example.com":[{"SPF":"v=spf1 mx:foo.example.com/24"}],"foo.example.com":[{"MX":[0,"foo1.example.com"]}],"foo1.example.com":[{"A":"1.1.1.1"},{"A":"1.2.3.5"}],"e11.example.com":[{"SPF":"v=spf1 mx:foo:bar/baz.example.com"}],"foo:bar/baz.example.com":[{"MX":[0,"foo:bar/baz.example.com"]},{"A":"1.2.3.4"}],"e12.example.com":[{"SPF":"v=spf1 mx:example.-com"}],"e13.example.com":[{"SPF":"v=spf1 mx: -all"}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.4');
        return promise.then((result) => {
          assert.equal(result, 'PERMERROR');
        });
      });
      it('If no ips are returned, MX mechanism does not match, even with /0.', function(){
        let email = 'foo@e1.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"},{"MX":[0,""]},{"SPF":"v=spf1 mx"}],"e1.example.com":[{"SPF":"v=spf1 mx/0 -all"},{"MX":[0,"e1.example.com"]}],"e2.example.com":[{"A":"1.1.1.1"},{"AAAA":"1234::2"},{"MX":[0,"e2.example.com"]},{"SPF":"v=spf1 mx/0 -all"}],"e2a.example.com":[{"AAAA":"1234::1"},{"MX":[0,"e2a.example.com"]},{"SPF":"v=spf1 mx//0 -all"}],"e2b.example.com":[{"A":"1.1.1.1"},{"MX":[0,"e2b.example.com"]},{"SPF":"v=spf1 mx//0 -all"}],"e3.example.com":[{"SPF":"v=spf1 mx:foo.example.com\u0000"}],"e4.example.com":[{"SPF":"v=spf1 mx"},{"A":"1.2.3.4"}],"e5.example.com":[{"SPF":"v=spf1 mx:abc.123"}],"e6.example.com":[{"SPF":"v=spf1 mx//33 -all"}],"e6a.example.com":[{"SPF":"v=spf1 mx/33 -all"}],"e7.example.com":[{"SPF":"v=spf1 mx//129 -all"}],"e9.example.com":[{"SPF":"v=spf1 mx:example.com:8080"}],"e10.example.com":[{"SPF":"v=spf1 mx:foo.example.com/24"}],"foo.example.com":[{"MX":[0,"foo1.example.com"]}],"foo1.example.com":[{"A":"1.1.1.1"},{"A":"1.2.3.5"}],"e11.example.com":[{"SPF":"v=spf1 mx:foo:bar/baz.example.com"}],"foo:bar/baz.example.com":[{"MX":[0,"foo:bar/baz.example.com"]},{"A":"1.2.3.4"}],"e12.example.com":[{"SPF":"v=spf1 mx:example.-com"}],"e13.example.com":[{"SPF":"v=spf1 mx: -all"}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.4');
        return promise.then((result) => {
          assert.equal(result, 'FAIL');
        });
      });
      it('Matches if any A records for any MX records are present in DNS.', function(){
        let email = 'foo@e2.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"},{"MX":[0,""]},{"SPF":"v=spf1 mx"}],"e1.example.com":[{"SPF":"v=spf1 mx/0 -all"},{"MX":[0,"e1.example.com"]}],"e2.example.com":[{"A":"1.1.1.1"},{"AAAA":"1234::2"},{"MX":[0,"e2.example.com"]},{"SPF":"v=spf1 mx/0 -all"}],"e2a.example.com":[{"AAAA":"1234::1"},{"MX":[0,"e2a.example.com"]},{"SPF":"v=spf1 mx//0 -all"}],"e2b.example.com":[{"A":"1.1.1.1"},{"MX":[0,"e2b.example.com"]},{"SPF":"v=spf1 mx//0 -all"}],"e3.example.com":[{"SPF":"v=spf1 mx:foo.example.com\u0000"}],"e4.example.com":[{"SPF":"v=spf1 mx"},{"A":"1.2.3.4"}],"e5.example.com":[{"SPF":"v=spf1 mx:abc.123"}],"e6.example.com":[{"SPF":"v=spf1 mx//33 -all"}],"e6a.example.com":[{"SPF":"v=spf1 mx/33 -all"}],"e7.example.com":[{"SPF":"v=spf1 mx//129 -all"}],"e9.example.com":[{"SPF":"v=spf1 mx:example.com:8080"}],"e10.example.com":[{"SPF":"v=spf1 mx:foo.example.com/24"}],"foo.example.com":[{"MX":[0,"foo1.example.com"]}],"foo1.example.com":[{"A":"1.1.1.1"},{"A":"1.2.3.5"}],"e11.example.com":[{"SPF":"v=spf1 mx:foo:bar/baz.example.com"}],"foo:bar/baz.example.com":[{"MX":[0,"foo:bar/baz.example.com"]},{"A":"1.2.3.4"}],"e12.example.com":[{"SPF":"v=spf1 mx:example.-com"}],"e13.example.com":[{"SPF":"v=spf1 mx: -all"}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.4');
        return promise.then((result) => {
          assert.equal(result, 'PASS');
        });
      });
      it('cidr4 doesn"t apply to IP6 connections.', function(){
        let email = 'foo@e2.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"},{"MX":[0,""]},{"SPF":"v=spf1 mx"}],"e1.example.com":[{"SPF":"v=spf1 mx/0 -all"},{"MX":[0,"e1.example.com"]}],"e2.example.com":[{"A":"1.1.1.1"},{"AAAA":"1234::2"},{"MX":[0,"e2.example.com"]},{"SPF":"v=spf1 mx/0 -all"}],"e2a.example.com":[{"AAAA":"1234::1"},{"MX":[0,"e2a.example.com"]},{"SPF":"v=spf1 mx//0 -all"}],"e2b.example.com":[{"A":"1.1.1.1"},{"MX":[0,"e2b.example.com"]},{"SPF":"v=spf1 mx//0 -all"}],"e3.example.com":[{"SPF":"v=spf1 mx:foo.example.com\u0000"}],"e4.example.com":[{"SPF":"v=spf1 mx"},{"A":"1.2.3.4"}],"e5.example.com":[{"SPF":"v=spf1 mx:abc.123"}],"e6.example.com":[{"SPF":"v=spf1 mx//33 -all"}],"e6a.example.com":[{"SPF":"v=spf1 mx/33 -all"}],"e7.example.com":[{"SPF":"v=spf1 mx//129 -all"}],"e9.example.com":[{"SPF":"v=spf1 mx:example.com:8080"}],"e10.example.com":[{"SPF":"v=spf1 mx:foo.example.com/24"}],"foo.example.com":[{"MX":[0,"foo1.example.com"]}],"foo1.example.com":[{"A":"1.1.1.1"},{"A":"1.2.3.5"}],"e11.example.com":[{"SPF":"v=spf1 mx:foo:bar/baz.example.com"}],"foo:bar/baz.example.com":[{"MX":[0,"foo:bar/baz.example.com"]},{"A":"1.2.3.4"}],"e12.example.com":[{"SPF":"v=spf1 mx:example.-com"}],"e13.example.com":[{"SPF":"v=spf1 mx: -all"}]}, failOnNoFake: true});
        let promise = validator.validateSender('1234::1');
        return promise.then((result) => {
          assert.equal(result, 'FAIL');
        });
      });
      it('Would match if any AAAA records for MX records are present in DNS, but not for an IP4 connection.', function(){
        let email = 'foo@e2a.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"},{"MX":[0,""]},{"SPF":"v=spf1 mx"}],"e1.example.com":[{"SPF":"v=spf1 mx/0 -all"},{"MX":[0,"e1.example.com"]}],"e2.example.com":[{"A":"1.1.1.1"},{"AAAA":"1234::2"},{"MX":[0,"e2.example.com"]},{"SPF":"v=spf1 mx/0 -all"}],"e2a.example.com":[{"AAAA":"1234::1"},{"MX":[0,"e2a.example.com"]},{"SPF":"v=spf1 mx//0 -all"}],"e2b.example.com":[{"A":"1.1.1.1"},{"MX":[0,"e2b.example.com"]},{"SPF":"v=spf1 mx//0 -all"}],"e3.example.com":[{"SPF":"v=spf1 mx:foo.example.com\u0000"}],"e4.example.com":[{"SPF":"v=spf1 mx"},{"A":"1.2.3.4"}],"e5.example.com":[{"SPF":"v=spf1 mx:abc.123"}],"e6.example.com":[{"SPF":"v=spf1 mx//33 -all"}],"e6a.example.com":[{"SPF":"v=spf1 mx/33 -all"}],"e7.example.com":[{"SPF":"v=spf1 mx//129 -all"}],"e9.example.com":[{"SPF":"v=spf1 mx:example.com:8080"}],"e10.example.com":[{"SPF":"v=spf1 mx:foo.example.com/24"}],"foo.example.com":[{"MX":[0,"foo1.example.com"]}],"foo1.example.com":[{"A":"1.1.1.1"},{"A":"1.2.3.5"}],"e11.example.com":[{"SPF":"v=spf1 mx:foo:bar/baz.example.com"}],"foo:bar/baz.example.com":[{"MX":[0,"foo:bar/baz.example.com"]},{"A":"1.2.3.4"}],"e12.example.com":[{"SPF":"v=spf1 mx:example.-com"}],"e13.example.com":[{"SPF":"v=spf1 mx: -all"}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.4');
        return promise.then((result) => {
          assert.equal(result, 'FAIL');
        });
      });
      it('Would match if any AAAA records for MX records are present in DNS, but not for an IP4 connection.', function(){
        let email = 'foo@e2a.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"},{"MX":[0,""]},{"SPF":"v=spf1 mx"}],"e1.example.com":[{"SPF":"v=spf1 mx/0 -all"},{"MX":[0,"e1.example.com"]}],"e2.example.com":[{"A":"1.1.1.1"},{"AAAA":"1234::2"},{"MX":[0,"e2.example.com"]},{"SPF":"v=spf1 mx/0 -all"}],"e2a.example.com":[{"AAAA":"1234::1"},{"MX":[0,"e2a.example.com"]},{"SPF":"v=spf1 mx//0 -all"}],"e2b.example.com":[{"A":"1.1.1.1"},{"MX":[0,"e2b.example.com"]},{"SPF":"v=spf1 mx//0 -all"}],"e3.example.com":[{"SPF":"v=spf1 mx:foo.example.com\u0000"}],"e4.example.com":[{"SPF":"v=spf1 mx"},{"A":"1.2.3.4"}],"e5.example.com":[{"SPF":"v=spf1 mx:abc.123"}],"e6.example.com":[{"SPF":"v=spf1 mx//33 -all"}],"e6a.example.com":[{"SPF":"v=spf1 mx/33 -all"}],"e7.example.com":[{"SPF":"v=spf1 mx//129 -all"}],"e9.example.com":[{"SPF":"v=spf1 mx:example.com:8080"}],"e10.example.com":[{"SPF":"v=spf1 mx:foo.example.com/24"}],"foo.example.com":[{"MX":[0,"foo1.example.com"]}],"foo1.example.com":[{"A":"1.1.1.1"},{"A":"1.2.3.5"}],"e11.example.com":[{"SPF":"v=spf1 mx:foo:bar/baz.example.com"}],"foo:bar/baz.example.com":[{"MX":[0,"foo:bar/baz.example.com"]},{"A":"1.2.3.4"}],"e12.example.com":[{"SPF":"v=spf1 mx:example.-com"}],"e13.example.com":[{"SPF":"v=spf1 mx: -all"}]}, failOnNoFake: true});
        let promise = validator.validateSender('::FFFF:1.2.3.4');
        return promise.then((result) => {
          assert.equal(result, 'FAIL');
        });
      });
      it('Matches if any AAAA records for any MX records are present in DNS.', function(){
        let email = 'foo@e2a.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"},{"MX":[0,""]},{"SPF":"v=spf1 mx"}],"e1.example.com":[{"SPF":"v=spf1 mx/0 -all"},{"MX":[0,"e1.example.com"]}],"e2.example.com":[{"A":"1.1.1.1"},{"AAAA":"1234::2"},{"MX":[0,"e2.example.com"]},{"SPF":"v=spf1 mx/0 -all"}],"e2a.example.com":[{"AAAA":"1234::1"},{"MX":[0,"e2a.example.com"]},{"SPF":"v=spf1 mx//0 -all"}],"e2b.example.com":[{"A":"1.1.1.1"},{"MX":[0,"e2b.example.com"]},{"SPF":"v=spf1 mx//0 -all"}],"e3.example.com":[{"SPF":"v=spf1 mx:foo.example.com\u0000"}],"e4.example.com":[{"SPF":"v=spf1 mx"},{"A":"1.2.3.4"}],"e5.example.com":[{"SPF":"v=spf1 mx:abc.123"}],"e6.example.com":[{"SPF":"v=spf1 mx//33 -all"}],"e6a.example.com":[{"SPF":"v=spf1 mx/33 -all"}],"e7.example.com":[{"SPF":"v=spf1 mx//129 -all"}],"e9.example.com":[{"SPF":"v=spf1 mx:example.com:8080"}],"e10.example.com":[{"SPF":"v=spf1 mx:foo.example.com/24"}],"foo.example.com":[{"MX":[0,"foo1.example.com"]}],"foo1.example.com":[{"A":"1.1.1.1"},{"A":"1.2.3.5"}],"e11.example.com":[{"SPF":"v=spf1 mx:foo:bar/baz.example.com"}],"foo:bar/baz.example.com":[{"MX":[0,"foo:bar/baz.example.com"]},{"A":"1.2.3.4"}],"e12.example.com":[{"SPF":"v=spf1 mx:example.-com"}],"e13.example.com":[{"SPF":"v=spf1 mx: -all"}]}, failOnNoFake: true});
        let promise = validator.validateSender('1234::1');
        return promise.then((result) => {
          assert.equal(result, 'PASS');
        });
      });
      it('No match if no AAAA records for any MX records are present in DNS.', function(){
        let email = 'foo@e2b.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"},{"MX":[0,""]},{"SPF":"v=spf1 mx"}],"e1.example.com":[{"SPF":"v=spf1 mx/0 -all"},{"MX":[0,"e1.example.com"]}],"e2.example.com":[{"A":"1.1.1.1"},{"AAAA":"1234::2"},{"MX":[0,"e2.example.com"]},{"SPF":"v=spf1 mx/0 -all"}],"e2a.example.com":[{"AAAA":"1234::1"},{"MX":[0,"e2a.example.com"]},{"SPF":"v=spf1 mx//0 -all"}],"e2b.example.com":[{"A":"1.1.1.1"},{"MX":[0,"e2b.example.com"]},{"SPF":"v=spf1 mx//0 -all"}],"e3.example.com":[{"SPF":"v=spf1 mx:foo.example.com\u0000"}],"e4.example.com":[{"SPF":"v=spf1 mx"},{"A":"1.2.3.4"}],"e5.example.com":[{"SPF":"v=spf1 mx:abc.123"}],"e6.example.com":[{"SPF":"v=spf1 mx//33 -all"}],"e6a.example.com":[{"SPF":"v=spf1 mx/33 -all"}],"e7.example.com":[{"SPF":"v=spf1 mx//129 -all"}],"e9.example.com":[{"SPF":"v=spf1 mx:example.com:8080"}],"e10.example.com":[{"SPF":"v=spf1 mx:foo.example.com/24"}],"foo.example.com":[{"MX":[0,"foo1.example.com"]}],"foo1.example.com":[{"A":"1.1.1.1"},{"A":"1.2.3.5"}],"e11.example.com":[{"SPF":"v=spf1 mx:foo:bar/baz.example.com"}],"foo:bar/baz.example.com":[{"MX":[0,"foo:bar/baz.example.com"]},{"A":"1.2.3.4"}],"e12.example.com":[{"SPF":"v=spf1 mx:example.-com"}],"e13.example.com":[{"SPF":"v=spf1 mx: -all"}]}, failOnNoFake: true});
        let promise = validator.validateSender('1234::1');
        return promise.then((result) => {
          assert.equal(result, 'FAIL');
        });
      });
      it('Null not allowed in top-label.', function(){
        let email = 'foo@e3.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"},{"MX":[0,""]},{"SPF":"v=spf1 mx"}],"e1.example.com":[{"SPF":"v=spf1 mx/0 -all"},{"MX":[0,"e1.example.com"]}],"e2.example.com":[{"A":"1.1.1.1"},{"AAAA":"1234::2"},{"MX":[0,"e2.example.com"]},{"SPF":"v=spf1 mx/0 -all"}],"e2a.example.com":[{"AAAA":"1234::1"},{"MX":[0,"e2a.example.com"]},{"SPF":"v=spf1 mx//0 -all"}],"e2b.example.com":[{"A":"1.1.1.1"},{"MX":[0,"e2b.example.com"]},{"SPF":"v=spf1 mx//0 -all"}],"e3.example.com":[{"SPF":"v=spf1 mx:foo.example.com\u0000"}],"e4.example.com":[{"SPF":"v=spf1 mx"},{"A":"1.2.3.4"}],"e5.example.com":[{"SPF":"v=spf1 mx:abc.123"}],"e6.example.com":[{"SPF":"v=spf1 mx//33 -all"}],"e6a.example.com":[{"SPF":"v=spf1 mx/33 -all"}],"e7.example.com":[{"SPF":"v=spf1 mx//129 -all"}],"e9.example.com":[{"SPF":"v=spf1 mx:example.com:8080"}],"e10.example.com":[{"SPF":"v=spf1 mx:foo.example.com/24"}],"foo.example.com":[{"MX":[0,"foo1.example.com"]}],"foo1.example.com":[{"A":"1.1.1.1"},{"A":"1.2.3.5"}],"e11.example.com":[{"SPF":"v=spf1 mx:foo:bar/baz.example.com"}],"foo:bar/baz.example.com":[{"MX":[0,"foo:bar/baz.example.com"]},{"A":"1.2.3.4"}],"e12.example.com":[{"SPF":"v=spf1 mx:example.-com"}],"e13.example.com":[{"SPF":"v=spf1 mx: -all"}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.5');
        return promise.then((result) => {
          assert.equal(result, 'PERMERROR');
        });
      });
      it('Top-label may not be all numeric', function(){
        let email = 'foo@e5.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"},{"MX":[0,""]},{"SPF":"v=spf1 mx"}],"e1.example.com":[{"SPF":"v=spf1 mx/0 -all"},{"MX":[0,"e1.example.com"]}],"e2.example.com":[{"A":"1.1.1.1"},{"AAAA":"1234::2"},{"MX":[0,"e2.example.com"]},{"SPF":"v=spf1 mx/0 -all"}],"e2a.example.com":[{"AAAA":"1234::1"},{"MX":[0,"e2a.example.com"]},{"SPF":"v=spf1 mx//0 -all"}],"e2b.example.com":[{"A":"1.1.1.1"},{"MX":[0,"e2b.example.com"]},{"SPF":"v=spf1 mx//0 -all"}],"e3.example.com":[{"SPF":"v=spf1 mx:foo.example.com\u0000"}],"e4.example.com":[{"SPF":"v=spf1 mx"},{"A":"1.2.3.4"}],"e5.example.com":[{"SPF":"v=spf1 mx:abc.123"}],"e6.example.com":[{"SPF":"v=spf1 mx//33 -all"}],"e6a.example.com":[{"SPF":"v=spf1 mx/33 -all"}],"e7.example.com":[{"SPF":"v=spf1 mx//129 -all"}],"e9.example.com":[{"SPF":"v=spf1 mx:example.com:8080"}],"e10.example.com":[{"SPF":"v=spf1 mx:foo.example.com/24"}],"foo.example.com":[{"MX":[0,"foo1.example.com"]}],"foo1.example.com":[{"A":"1.1.1.1"},{"A":"1.2.3.5"}],"e11.example.com":[{"SPF":"v=spf1 mx:foo:bar/baz.example.com"}],"foo:bar/baz.example.com":[{"MX":[0,"foo:bar/baz.example.com"]},{"A":"1.2.3.4"}],"e12.example.com":[{"SPF":"v=spf1 mx:example.-com"}],"e13.example.com":[{"SPF":"v=spf1 mx: -all"}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.4');
        return promise.then((result) => {
          assert.equal(result, 'PERMERROR');
        });
      });
      it('Domain-spec may contain any visible char except %', function(){
        let email = 'foo@e11.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"},{"MX":[0,""]},{"SPF":"v=spf1 mx"}],"e1.example.com":[{"SPF":"v=spf1 mx/0 -all"},{"MX":[0,"e1.example.com"]}],"e2.example.com":[{"A":"1.1.1.1"},{"AAAA":"1234::2"},{"MX":[0,"e2.example.com"]},{"SPF":"v=spf1 mx/0 -all"}],"e2a.example.com":[{"AAAA":"1234::1"},{"MX":[0,"e2a.example.com"]},{"SPF":"v=spf1 mx//0 -all"}],"e2b.example.com":[{"A":"1.1.1.1"},{"MX":[0,"e2b.example.com"]},{"SPF":"v=spf1 mx//0 -all"}],"e3.example.com":[{"SPF":"v=spf1 mx:foo.example.com\u0000"}],"e4.example.com":[{"SPF":"v=spf1 mx"},{"A":"1.2.3.4"}],"e5.example.com":[{"SPF":"v=spf1 mx:abc.123"}],"e6.example.com":[{"SPF":"v=spf1 mx//33 -all"}],"e6a.example.com":[{"SPF":"v=spf1 mx/33 -all"}],"e7.example.com":[{"SPF":"v=spf1 mx//129 -all"}],"e9.example.com":[{"SPF":"v=spf1 mx:example.com:8080"}],"e10.example.com":[{"SPF":"v=spf1 mx:foo.example.com/24"}],"foo.example.com":[{"MX":[0,"foo1.example.com"]}],"foo1.example.com":[{"A":"1.1.1.1"},{"A":"1.2.3.5"}],"e11.example.com":[{"SPF":"v=spf1 mx:foo:bar/baz.example.com"}],"foo:bar/baz.example.com":[{"MX":[0,"foo:bar/baz.example.com"]},{"A":"1.2.3.4"}],"e12.example.com":[{"SPF":"v=spf1 mx:example.-com"}],"e13.example.com":[{"SPF":"v=spf1 mx: -all"}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.4');
        return promise.then((result) => {
          assert.equal(result, 'PASS');
        });
      });
      it('Domain-spec may contain any visible char except %', function(){
        let email = 'foo@e11.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"},{"MX":[0,""]},{"SPF":"v=spf1 mx"}],"e1.example.com":[{"SPF":"v=spf1 mx/0 -all"},{"MX":[0,"e1.example.com"]}],"e2.example.com":[{"A":"1.1.1.1"},{"AAAA":"1234::2"},{"MX":[0,"e2.example.com"]},{"SPF":"v=spf1 mx/0 -all"}],"e2a.example.com":[{"AAAA":"1234::1"},{"MX":[0,"e2a.example.com"]},{"SPF":"v=spf1 mx//0 -all"}],"e2b.example.com":[{"A":"1.1.1.1"},{"MX":[0,"e2b.example.com"]},{"SPF":"v=spf1 mx//0 -all"}],"e3.example.com":[{"SPF":"v=spf1 mx:foo.example.com\u0000"}],"e4.example.com":[{"SPF":"v=spf1 mx"},{"A":"1.2.3.4"}],"e5.example.com":[{"SPF":"v=spf1 mx:abc.123"}],"e6.example.com":[{"SPF":"v=spf1 mx//33 -all"}],"e6a.example.com":[{"SPF":"v=spf1 mx/33 -all"}],"e7.example.com":[{"SPF":"v=spf1 mx//129 -all"}],"e9.example.com":[{"SPF":"v=spf1 mx:example.com:8080"}],"e10.example.com":[{"SPF":"v=spf1 mx:foo.example.com/24"}],"foo.example.com":[{"MX":[0,"foo1.example.com"]}],"foo1.example.com":[{"A":"1.1.1.1"},{"A":"1.2.3.5"}],"e11.example.com":[{"SPF":"v=spf1 mx:foo:bar/baz.example.com"}],"foo:bar/baz.example.com":[{"MX":[0,"foo:bar/baz.example.com"]},{"A":"1.2.3.4"}],"e12.example.com":[{"SPF":"v=spf1 mx:example.-com"}],"e13.example.com":[{"SPF":"v=spf1 mx: -all"}]}, failOnNoFake: true});
        let promise = validator.validateSender('::FFFF:1.2.3.4');
        return promise.then((result) => {
          assert.equal(result, 'PASS');
        });
      });
      it('Toplabel may not begin with -', function(){
        let email = 'foo@e12.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"},{"MX":[0,""]},{"SPF":"v=spf1 mx"}],"e1.example.com":[{"SPF":"v=spf1 mx/0 -all"},{"MX":[0,"e1.example.com"]}],"e2.example.com":[{"A":"1.1.1.1"},{"AAAA":"1234::2"},{"MX":[0,"e2.example.com"]},{"SPF":"v=spf1 mx/0 -all"}],"e2a.example.com":[{"AAAA":"1234::1"},{"MX":[0,"e2a.example.com"]},{"SPF":"v=spf1 mx//0 -all"}],"e2b.example.com":[{"A":"1.1.1.1"},{"MX":[0,"e2b.example.com"]},{"SPF":"v=spf1 mx//0 -all"}],"e3.example.com":[{"SPF":"v=spf1 mx:foo.example.com\u0000"}],"e4.example.com":[{"SPF":"v=spf1 mx"},{"A":"1.2.3.4"}],"e5.example.com":[{"SPF":"v=spf1 mx:abc.123"}],"e6.example.com":[{"SPF":"v=spf1 mx//33 -all"}],"e6a.example.com":[{"SPF":"v=spf1 mx/33 -all"}],"e7.example.com":[{"SPF":"v=spf1 mx//129 -all"}],"e9.example.com":[{"SPF":"v=spf1 mx:example.com:8080"}],"e10.example.com":[{"SPF":"v=spf1 mx:foo.example.com/24"}],"foo.example.com":[{"MX":[0,"foo1.example.com"]}],"foo1.example.com":[{"A":"1.1.1.1"},{"A":"1.2.3.5"}],"e11.example.com":[{"SPF":"v=spf1 mx:foo:bar/baz.example.com"}],"foo:bar/baz.example.com":[{"MX":[0,"foo:bar/baz.example.com"]},{"A":"1.2.3.4"}],"e12.example.com":[{"SPF":"v=spf1 mx:example.-com"}],"e13.example.com":[{"SPF":"v=spf1 mx: -all"}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.4');
        return promise.then((result) => {
          assert.equal(result, 'PERMERROR');
        });
      });
      it('test null MX', function(){
        let email = '';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"},{"MX":[0,""]},{"SPF":"v=spf1 mx"}],"e1.example.com":[{"SPF":"v=spf1 mx/0 -all"},{"MX":[0,"e1.example.com"]}],"e2.example.com":[{"A":"1.1.1.1"},{"AAAA":"1234::2"},{"MX":[0,"e2.example.com"]},{"SPF":"v=spf1 mx/0 -all"}],"e2a.example.com":[{"AAAA":"1234::1"},{"MX":[0,"e2a.example.com"]},{"SPF":"v=spf1 mx//0 -all"}],"e2b.example.com":[{"A":"1.1.1.1"},{"MX":[0,"e2b.example.com"]},{"SPF":"v=spf1 mx//0 -all"}],"e3.example.com":[{"SPF":"v=spf1 mx:foo.example.com\u0000"}],"e4.example.com":[{"SPF":"v=spf1 mx"},{"A":"1.2.3.4"}],"e5.example.com":[{"SPF":"v=spf1 mx:abc.123"}],"e6.example.com":[{"SPF":"v=spf1 mx//33 -all"}],"e6a.example.com":[{"SPF":"v=spf1 mx/33 -all"}],"e7.example.com":[{"SPF":"v=spf1 mx//129 -all"}],"e9.example.com":[{"SPF":"v=spf1 mx:example.com:8080"}],"e10.example.com":[{"SPF":"v=spf1 mx:foo.example.com/24"}],"foo.example.com":[{"MX":[0,"foo1.example.com"]}],"foo1.example.com":[{"A":"1.1.1.1"},{"A":"1.2.3.5"}],"e11.example.com":[{"SPF":"v=spf1 mx:foo:bar/baz.example.com"}],"foo:bar/baz.example.com":[{"MX":[0,"foo:bar/baz.example.com"]},{"A":"1.2.3.4"}],"e12.example.com":[{"SPF":"v=spf1 mx:example.-com"}],"e13.example.com":[{"SPF":"v=spf1 mx: -all"}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.4');
        return promise.then((result) => {
          assert.equal(result, 'NEUTRAL');
        });
      });
      it('If the target name has no MX records, check_host() MUST NOT pretend the target is its single MX, and MUST NOT default to an A lookup on the target-name directly.', function(){
        let email = 'foo@e4.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"},{"MX":[0,""]},{"SPF":"v=spf1 mx"}],"e1.example.com":[{"SPF":"v=spf1 mx/0 -all"},{"MX":[0,"e1.example.com"]}],"e2.example.com":[{"A":"1.1.1.1"},{"AAAA":"1234::2"},{"MX":[0,"e2.example.com"]},{"SPF":"v=spf1 mx/0 -all"}],"e2a.example.com":[{"AAAA":"1234::1"},{"MX":[0,"e2a.example.com"]},{"SPF":"v=spf1 mx//0 -all"}],"e2b.example.com":[{"A":"1.1.1.1"},{"MX":[0,"e2b.example.com"]},{"SPF":"v=spf1 mx//0 -all"}],"e3.example.com":[{"SPF":"v=spf1 mx:foo.example.com\u0000"}],"e4.example.com":[{"SPF":"v=spf1 mx"},{"A":"1.2.3.4"}],"e5.example.com":[{"SPF":"v=spf1 mx:abc.123"}],"e6.example.com":[{"SPF":"v=spf1 mx//33 -all"}],"e6a.example.com":[{"SPF":"v=spf1 mx/33 -all"}],"e7.example.com":[{"SPF":"v=spf1 mx//129 -all"}],"e9.example.com":[{"SPF":"v=spf1 mx:example.com:8080"}],"e10.example.com":[{"SPF":"v=spf1 mx:foo.example.com/24"}],"foo.example.com":[{"MX":[0,"foo1.example.com"]}],"foo1.example.com":[{"A":"1.1.1.1"},{"A":"1.2.3.5"}],"e11.example.com":[{"SPF":"v=spf1 mx:foo:bar/baz.example.com"}],"foo:bar/baz.example.com":[{"MX":[0,"foo:bar/baz.example.com"]},{"A":"1.2.3.4"}],"e12.example.com":[{"SPF":"v=spf1 mx:example.-com"}],"e13.example.com":[{"SPF":"v=spf1 mx: -all"}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.4');
        return promise.then((result) => {
          assert.equal(result, 'NEUTRAL');
        });
      });
      it('domain-spec cannot be empty.', function(){
        let email = 'foo@e13.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"},{"MX":[0,""]},{"SPF":"v=spf1 mx"}],"e1.example.com":[{"SPF":"v=spf1 mx/0 -all"},{"MX":[0,"e1.example.com"]}],"e2.example.com":[{"A":"1.1.1.1"},{"AAAA":"1234::2"},{"MX":[0,"e2.example.com"]},{"SPF":"v=spf1 mx/0 -all"}],"e2a.example.com":[{"AAAA":"1234::1"},{"MX":[0,"e2a.example.com"]},{"SPF":"v=spf1 mx//0 -all"}],"e2b.example.com":[{"A":"1.1.1.1"},{"MX":[0,"e2b.example.com"]},{"SPF":"v=spf1 mx//0 -all"}],"e3.example.com":[{"SPF":"v=spf1 mx:foo.example.com\u0000"}],"e4.example.com":[{"SPF":"v=spf1 mx"},{"A":"1.2.3.4"}],"e5.example.com":[{"SPF":"v=spf1 mx:abc.123"}],"e6.example.com":[{"SPF":"v=spf1 mx//33 -all"}],"e6a.example.com":[{"SPF":"v=spf1 mx/33 -all"}],"e7.example.com":[{"SPF":"v=spf1 mx//129 -all"}],"e9.example.com":[{"SPF":"v=spf1 mx:example.com:8080"}],"e10.example.com":[{"SPF":"v=spf1 mx:foo.example.com/24"}],"foo.example.com":[{"MX":[0,"foo1.example.com"]}],"foo1.example.com":[{"A":"1.1.1.1"},{"A":"1.2.3.5"}],"e11.example.com":[{"SPF":"v=spf1 mx:foo:bar/baz.example.com"}],"foo:bar/baz.example.com":[{"MX":[0,"foo:bar/baz.example.com"]},{"A":"1.2.3.4"}],"e12.example.com":[{"SPF":"v=spf1 mx:example.-com"}],"e13.example.com":[{"SPF":"v=spf1 mx: -all"}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.4');
        return promise.then((result) => {
          assert.equal(result, 'PERMERROR');
        });
      });
    });
    describe('EXISTS mechanism syntax', function(){
      it('domain-spec cannot be empty.', function(){
        let email = 'foo@e1.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"mail6.example.com":[{"AAAA":"CAFE:BABE::4"}],"err.example.com":["TIMEOUT"],"e1.example.com":[{"SPF":"v=spf1 exists:"}],"e2.example.com":[{"SPF":"v=spf1 exists"}],"e3.example.com":[{"SPF":"v=spf1 exists:mail.example.com/24"}],"e4.example.com":[{"SPF":"v=spf1 exists:mail.example.com"}],"e5.example.com":[{"SPF":"v=spf1 exists:mail6.example.com -all"}],"e6.example.com":[{"SPF":"v=spf1 exists:err.example.com -all"}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.4');
        return promise.then((result) => {
          assert.equal(result, 'PERMERROR');
        });
      });
      it('exists           = "exists"   ":" domain-spec', function(){
        let email = 'foo@e2.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"mail6.example.com":[{"AAAA":"CAFE:BABE::4"}],"err.example.com":["TIMEOUT"],"e1.example.com":[{"SPF":"v=spf1 exists:"}],"e2.example.com":[{"SPF":"v=spf1 exists"}],"e3.example.com":[{"SPF":"v=spf1 exists:mail.example.com/24"}],"e4.example.com":[{"SPF":"v=spf1 exists:mail.example.com"}],"e5.example.com":[{"SPF":"v=spf1 exists:mail6.example.com -all"}],"e6.example.com":[{"SPF":"v=spf1 exists:err.example.com -all"}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.4');
        return promise.then((result) => {
          assert.equal(result, 'PERMERROR');
        });
      });
      it('exists           = "exists"   ":" domain-spec', function(){
        let email = 'foo@e3.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"mail6.example.com":[{"AAAA":"CAFE:BABE::4"}],"err.example.com":["TIMEOUT"],"e1.example.com":[{"SPF":"v=spf1 exists:"}],"e2.example.com":[{"SPF":"v=spf1 exists"}],"e3.example.com":[{"SPF":"v=spf1 exists:mail.example.com/24"}],"e4.example.com":[{"SPF":"v=spf1 exists:mail.example.com"}],"e5.example.com":[{"SPF":"v=spf1 exists:mail6.example.com -all"}],"e6.example.com":[{"SPF":"v=spf1 exists:err.example.com -all"}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.4');
        return promise.then((result) => {
          assert.equal(result, 'PERMERROR');
        });
      });
      it('mechanism matches if any DNS A RR exists', function(){
        let email = 'foo@e4.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"mail6.example.com":[{"AAAA":"CAFE:BABE::4"}],"err.example.com":["TIMEOUT"],"e1.example.com":[{"SPF":"v=spf1 exists:"}],"e2.example.com":[{"SPF":"v=spf1 exists"}],"e3.example.com":[{"SPF":"v=spf1 exists:mail.example.com/24"}],"e4.example.com":[{"SPF":"v=spf1 exists:mail.example.com"}],"e5.example.com":[{"SPF":"v=spf1 exists:mail6.example.com -all"}],"e6.example.com":[{"SPF":"v=spf1 exists:err.example.com -all"}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.4');
        return promise.then((result) => {
          assert.equal(result, 'PASS');
        });
      });
      it('The lookup type is A even when the connection is ip6', function(){
        let email = 'foo@e4.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"mail6.example.com":[{"AAAA":"CAFE:BABE::4"}],"err.example.com":["TIMEOUT"],"e1.example.com":[{"SPF":"v=spf1 exists:"}],"e2.example.com":[{"SPF":"v=spf1 exists"}],"e3.example.com":[{"SPF":"v=spf1 exists:mail.example.com/24"}],"e4.example.com":[{"SPF":"v=spf1 exists:mail.example.com"}],"e5.example.com":[{"SPF":"v=spf1 exists:mail6.example.com -all"}],"e6.example.com":[{"SPF":"v=spf1 exists:err.example.com -all"}]}, failOnNoFake: true});
        let promise = validator.validateSender('CAFE:BABE::3');
        return promise.then((result) => {
          assert.equal(result, 'PASS');
        });
      });
      it('The lookup type is A even when the connection is ip6', function(){
        let email = 'foo@e5.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"mail6.example.com":[{"AAAA":"CAFE:BABE::4"}],"err.example.com":["TIMEOUT"],"e1.example.com":[{"SPF":"v=spf1 exists:"}],"e2.example.com":[{"SPF":"v=spf1 exists"}],"e3.example.com":[{"SPF":"v=spf1 exists:mail.example.com/24"}],"e4.example.com":[{"SPF":"v=spf1 exists:mail.example.com"}],"e5.example.com":[{"SPF":"v=spf1 exists:mail6.example.com -all"}],"e6.example.com":[{"SPF":"v=spf1 exists:err.example.com -all"}]}, failOnNoFake: true});
        let promise = validator.validateSender('CAFE:BABE::3');
        return promise.then((result) => {
          assert.equal(result, 'FAIL');
        });
      });
      it('Result for DNS error clarified in RFC7208: MTAs or other processors  SHOULD impose a limit on the maximum amount of elapsed time to evaluate  check_host().  Such a limit SHOULD allow at least 20 seconds.  If such  a limit is exceeded, the result of authorization SHOULD be "temperror".', function(){
        let email = 'foo@e6.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"mail6.example.com":[{"AAAA":"CAFE:BABE::4"}],"err.example.com":["TIMEOUT"],"e1.example.com":[{"SPF":"v=spf1 exists:"}],"e2.example.com":[{"SPF":"v=spf1 exists"}],"e3.example.com":[{"SPF":"v=spf1 exists:mail.example.com/24"}],"e4.example.com":[{"SPF":"v=spf1 exists:mail.example.com"}],"e5.example.com":[{"SPF":"v=spf1 exists:mail6.example.com -all"}],"e6.example.com":[{"SPF":"v=spf1 exists:err.example.com -all"}]}, failOnNoFake: true});
        let promise = validator.validateSender('CAFE:BABE::3');
        return promise.then((result) => {
          assert.equal(result, 'TEMPERROR');
        });
      });
    });
    describe('IP4 mechanism syntax', function(){
      it('ip4-cidr-length  = "/" 1*DIGIT', function(){
        let email = 'foo@e1.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 ip4:1.1.1.1/0 -all"}],"e2.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4/32 -all"}],"e3.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4/33 -all"}],"e4.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4/032 -all"}],"e5.example.com":[{"SPF":"v=spf1 ip4"}],"e6.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4//32"}],"e7.example.com":[{"SPF":"v=spf1 -ip4:1.2.3.4 ip6:::FFFF:1.2.3.4"}],"e8.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4:8080"}],"e9.example.com":[{"SPF":"v=spf1 ip4:1.2.3"}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.4');
        return promise.then((result) => {
          assert.equal(result, 'PASS');
        });
      });
      it('ip4-cidr-length  = "/" 1*DIGIT', function(){
        let email = 'foo@e2.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 ip4:1.1.1.1/0 -all"}],"e2.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4/32 -all"}],"e3.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4/33 -all"}],"e4.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4/032 -all"}],"e5.example.com":[{"SPF":"v=spf1 ip4"}],"e6.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4//32"}],"e7.example.com":[{"SPF":"v=spf1 -ip4:1.2.3.4 ip6:::FFFF:1.2.3.4"}],"e8.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4:8080"}],"e9.example.com":[{"SPF":"v=spf1 ip4:1.2.3"}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.4');
        return promise.then((result) => {
          assert.equal(result, 'PASS');
        });
      });
      it('Invalid CIDR should get permerror.', function(){
        let email = 'foo@e3.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 ip4:1.1.1.1/0 -all"}],"e2.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4/32 -all"}],"e3.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4/33 -all"}],"e4.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4/032 -all"}],"e5.example.com":[{"SPF":"v=spf1 ip4"}],"e6.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4//32"}],"e7.example.com":[{"SPF":"v=spf1 -ip4:1.2.3.4 ip6:::FFFF:1.2.3.4"}],"e8.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4:8080"}],"e9.example.com":[{"SPF":"v=spf1 ip4:1.2.3"}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.4');
        return promise.then((result) => {
          assert.equal(result, 'PERMERROR');
        });
      });
      it('Invalid CIDR should get permerror.', function(){
        let email = 'foo@e4.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 ip4:1.1.1.1/0 -all"}],"e2.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4/32 -all"}],"e3.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4/33 -all"}],"e4.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4/032 -all"}],"e5.example.com":[{"SPF":"v=spf1 ip4"}],"e6.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4//32"}],"e7.example.com":[{"SPF":"v=spf1 -ip4:1.2.3.4 ip6:::FFFF:1.2.3.4"}],"e8.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4:8080"}],"e9.example.com":[{"SPF":"v=spf1 ip4:1.2.3"}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.4');
        return promise.then((result) => {
          assert.equal(result, 'PERMERROR');
        });
      });
      it('IP4              = "ip4"      ":" ip4-network   [ ip4-cidr-length ]', function(){
        let email = 'foo@e5.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 ip4:1.1.1.1/0 -all"}],"e2.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4/32 -all"}],"e3.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4/33 -all"}],"e4.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4/032 -all"}],"e5.example.com":[{"SPF":"v=spf1 ip4"}],"e6.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4//32"}],"e7.example.com":[{"SPF":"v=spf1 -ip4:1.2.3.4 ip6:::FFFF:1.2.3.4"}],"e8.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4:8080"}],"e9.example.com":[{"SPF":"v=spf1 ip4:1.2.3"}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.4');
        return promise.then((result) => {
          assert.equal(result, 'PERMERROR');
        });
      });
      it('IP4              = "ip4"      ":" ip4-network   [ ip4-cidr-length ]', function(){
        let email = 'foo@e8.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 ip4:1.1.1.1/0 -all"}],"e2.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4/32 -all"}],"e3.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4/33 -all"}],"e4.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4/032 -all"}],"e5.example.com":[{"SPF":"v=spf1 ip4"}],"e6.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4//32"}],"e7.example.com":[{"SPF":"v=spf1 -ip4:1.2.3.4 ip6:::FFFF:1.2.3.4"}],"e8.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4:8080"}],"e9.example.com":[{"SPF":"v=spf1 ip4:1.2.3"}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.4');
        return promise.then((result) => {
          assert.equal(result, 'PERMERROR');
        });
      });
      it('It is not permitted to omit parts of the IP address instead of using CIDR notations.', function(){
        let email = 'foo@e9.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 ip4:1.1.1.1/0 -all"}],"e2.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4/32 -all"}],"e3.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4/33 -all"}],"e4.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4/032 -all"}],"e5.example.com":[{"SPF":"v=spf1 ip4"}],"e6.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4//32"}],"e7.example.com":[{"SPF":"v=spf1 -ip4:1.2.3.4 ip6:::FFFF:1.2.3.4"}],"e8.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4:8080"}],"e9.example.com":[{"SPF":"v=spf1 ip4:1.2.3"}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.4');
        return promise.then((result) => {
          assert.equal(result, 'PERMERROR');
        });
      });
      it('dual-cidr-length not permitted on ip4', function(){
        let email = 'foo@e6.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 ip4:1.1.1.1/0 -all"}],"e2.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4/32 -all"}],"e3.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4/33 -all"}],"e4.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4/032 -all"}],"e5.example.com":[{"SPF":"v=spf1 ip4"}],"e6.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4//32"}],"e7.example.com":[{"SPF":"v=spf1 -ip4:1.2.3.4 ip6:::FFFF:1.2.3.4"}],"e8.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4:8080"}],"e9.example.com":[{"SPF":"v=spf1 ip4:1.2.3"}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.4');
        return promise.then((result) => {
          assert.equal(result, 'PERMERROR');
        });
      });
      it('IP4 mapped IP6 connections MUST be treated as IP4', function(){
        let email = 'foo@e7.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 ip4:1.1.1.1/0 -all"}],"e2.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4/32 -all"}],"e3.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4/33 -all"}],"e4.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4/032 -all"}],"e5.example.com":[{"SPF":"v=spf1 ip4"}],"e6.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4//32"}],"e7.example.com":[{"SPF":"v=spf1 -ip4:1.2.3.4 ip6:::FFFF:1.2.3.4"}],"e8.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4:8080"}],"e9.example.com":[{"SPF":"v=spf1 ip4:1.2.3"}]}, failOnNoFake: true});
        let promise = validator.validateSender('::FFFF:1.2.3.4');
        return promise.then((result) => {
          assert.equal(result, 'FAIL');
        });
      });
    });
    describe('IP6 mechanism syntax', function(){
      it('IP6              = "ip6"      ":" ip6-network   [ ip6-cidr-length ]', function(){
        let email = 'foo@e1.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 -all ip6"}],"e2.example.com":[{"SPF":"v=spf1 ip6:::1.1.1.1/0"}],"e3.example.com":[{"SPF":"v=spf1 ip6:::1.1.1.1/129"}],"e4.example.com":[{"SPF":"v=spf1 ip6:::1.1.1.1//33"}],"e5.example.com":[{"SPF":"v=spf1 ip6:Cafe:Babe:8000::/33"}],"e6.example.com":[{"SPF":"v=spf1 ip6::CAFE::BABE"}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.4');
        return promise.then((result) => {
          assert.equal(result, 'PERMERROR');
        });
      });
      it('IP4 connections do not match ip6.', function(){
        let email = 'foo@e2.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 -all ip6"}],"e2.example.com":[{"SPF":"v=spf1 ip6:::1.1.1.1/0"}],"e3.example.com":[{"SPF":"v=spf1 ip6:::1.1.1.1/129"}],"e4.example.com":[{"SPF":"v=spf1 ip6:::1.1.1.1//33"}],"e5.example.com":[{"SPF":"v=spf1 ip6:Cafe:Babe:8000::/33"}],"e6.example.com":[{"SPF":"v=spf1 ip6::CAFE::BABE"}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.4');
        return promise.then((result) => {
          assert.equal(result, 'NEUTRAL');
        });
      });
      it('Even if the SMTP connection is via IPv6, an IPv4-mapped IPv6 IP address (see RFC 3513, Section 2.5.5) MUST still be considered an IPv4 address.', function(){
        let email = 'foo@e2.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 -all ip6"}],"e2.example.com":[{"SPF":"v=spf1 ip6:::1.1.1.1/0"}],"e3.example.com":[{"SPF":"v=spf1 ip6:::1.1.1.1/129"}],"e4.example.com":[{"SPF":"v=spf1 ip6:::1.1.1.1//33"}],"e5.example.com":[{"SPF":"v=spf1 ip6:Cafe:Babe:8000::/33"}],"e6.example.com":[{"SPF":"v=spf1 ip6::CAFE::BABE"}]}, failOnNoFake: true});
        let promise = validator.validateSender('::FFFF:1.2.3.4');
        return promise.then((result) => {
          assert.equal(result, 'NEUTRAL');
        });
      });
      it('Match any IP6', function(){
        let email = 'foo@e2.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 -all ip6"}],"e2.example.com":[{"SPF":"v=spf1 ip6:::1.1.1.1/0"}],"e3.example.com":[{"SPF":"v=spf1 ip6:::1.1.1.1/129"}],"e4.example.com":[{"SPF":"v=spf1 ip6:::1.1.1.1//33"}],"e5.example.com":[{"SPF":"v=spf1 ip6:Cafe:Babe:8000::/33"}],"e6.example.com":[{"SPF":"v=spf1 ip6::CAFE::BABE"}]}, failOnNoFake: true});
        let promise = validator.validateSender('DEAF:BABE::CAB:FEE');
        return promise.then((result) => {
          assert.equal(result, 'PASS');
        });
      });
      it('Invalid CIDR', function(){
        let email = 'foo@e3.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 -all ip6"}],"e2.example.com":[{"SPF":"v=spf1 ip6:::1.1.1.1/0"}],"e3.example.com":[{"SPF":"v=spf1 ip6:::1.1.1.1/129"}],"e4.example.com":[{"SPF":"v=spf1 ip6:::1.1.1.1//33"}],"e5.example.com":[{"SPF":"v=spf1 ip6:Cafe:Babe:8000::/33"}],"e6.example.com":[{"SPF":"v=spf1 ip6::CAFE::BABE"}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.4');
        return promise.then((result) => {
          assert.equal(result, 'PERMERROR');
        });
      });
      it('dual-cidr syntax not used for ip6', function(){
        let email = 'foo@e4.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 -all ip6"}],"e2.example.com":[{"SPF":"v=spf1 ip6:::1.1.1.1/0"}],"e3.example.com":[{"SPF":"v=spf1 ip6:::1.1.1.1/129"}],"e4.example.com":[{"SPF":"v=spf1 ip6:::1.1.1.1//33"}],"e5.example.com":[{"SPF":"v=spf1 ip6:Cafe:Babe:8000::/33"}],"e6.example.com":[{"SPF":"v=spf1 ip6::CAFE::BABE"}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.4');
        return promise.then((result) => {
          assert.equal(result, 'PERMERROR');
        });
      });
      it('make sure ip4 cidr restriction are not used for ip6', function(){
        let email = 'foo@e5.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 -all ip6"}],"e2.example.com":[{"SPF":"v=spf1 ip6:::1.1.1.1/0"}],"e3.example.com":[{"SPF":"v=spf1 ip6:::1.1.1.1/129"}],"e4.example.com":[{"SPF":"v=spf1 ip6:::1.1.1.1//33"}],"e5.example.com":[{"SPF":"v=spf1 ip6:Cafe:Babe:8000::/33"}],"e6.example.com":[{"SPF":"v=spf1 ip6::CAFE::BABE"}]}, failOnNoFake: true});
        let promise = validator.validateSender('CAFE:BABE:8000::');
        return promise.then((result) => {
          assert.equal(result, 'PASS');
        });
      });
      it('make sure ip4 cidr restriction are not used for ip6', function(){
        let email = 'foo@e5.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 -all ip6"}],"e2.example.com":[{"SPF":"v=spf1 ip6:::1.1.1.1/0"}],"e3.example.com":[{"SPF":"v=spf1 ip6:::1.1.1.1/129"}],"e4.example.com":[{"SPF":"v=spf1 ip6:::1.1.1.1//33"}],"e5.example.com":[{"SPF":"v=spf1 ip6:Cafe:Babe:8000::/33"}],"e6.example.com":[{"SPF":"v=spf1 ip6::CAFE::BABE"}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.4');
        return promise.then((result) => {
          assert.equal(result, 'NEUTRAL');
        });
      });
      it('', function(){
        let email = 'foo@e6.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 -all ip6"}],"e2.example.com":[{"SPF":"v=spf1 ip6:::1.1.1.1/0"}],"e3.example.com":[{"SPF":"v=spf1 ip6:::1.1.1.1/129"}],"e4.example.com":[{"SPF":"v=spf1 ip6:::1.1.1.1//33"}],"e5.example.com":[{"SPF":"v=spf1 ip6:Cafe:Babe:8000::/33"}],"e6.example.com":[{"SPF":"v=spf1 ip6::CAFE::BABE"}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.4');
        return promise.then((result) => {
          assert.equal(result, 'PERMERROR');
        });
      });
    });
    describe('Semantics of exp and other modifiers', function(){
      it('If no SPF record is found, or if the target-name is malformed, the result is a "PermError" rather than "None".', function(){
        let email = 'foo@e10.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 exp=exp1.example.com redirect=e2.example.com"}],"e2.example.com":[{"SPF":"v=spf1 -all"}],"e3.example.com":[{"SPF":"v=spf1 exp=exp1.example.com redirect=e4.example.com"}],"e4.example.com":[{"SPF":"v=spf1 -all exp=exp2.example.com"}],"exp1.example.com":[{"TXT":"No-see-um"}],"exp2.example.com":[{"TXT":"See me."}],"exp3.example.com":[{"TXT":"Correct!"}],"exp4.example.com":[{"TXT":"%{l} in implementation"}],"e5.example.com":[{"SPF":"v=spf1 1up=foo"}],"e6.example.com":[{"SPF":"v=spf1 =all"}],"e7.example.com":[{"SPF":"v=spf1 include:e3.example.com -all exp=exp3.example.com"}],"e8.example.com":[{"SPF":"v=spf1 -all exp=exp4.example.com"}],"e9.example.com":[{"SPF":"v=spf1 -all foo=%abc"}],"e10.example.com":[{"SPF":"v=spf1 redirect=erehwon.example.com"}],"e11.example.com":[{"SPF":"v=spf1 -all exp=e11msg.example.com"}],"e11msg.example.com":[{"TXT":"Answer a fool according to his folly."},{"TXT":"Do not answer a fool according to his folly."}],"e12.example.com":[{"SPF":"v=spf1 exp= -all"}],"e13.example.com":[{"SPF":"v=spf1 exp=e13msg.example.com -all"}],"e13msg.example.com":[{"TXT":"The %{x}-files."}],"e14.example.com":[{"SPF":"v=spf1 exp=e13msg.example.com -all exp=e11msg.example.com"}],"e15.example.com":[{"SPF":"v=spf1 redirect=e12.example.com -all redirect=e12.example.com"}],"e16.example.com":[{"SPF":"v=spf1 exp=-all"}],"e17.example.com":[{"SPF":"v=spf1 redirect=-all ?all"}],"e18.example.com":[{"SPF":"v=spf1 ?all redirect="}],"e19.example.com":[{"SPF":"v=spf1 default=pass"}],"e20.example.com":[{"SPF":"v=spf1 default=+"}],"e21.example.com":[{"SPF":"v=spf1 exp=e21msg.example.com -all"}],"e21msg.example.com":["TIMEOUT"],"e22.example.com":[{"SPF":"v=spf1 exp=mail.example.com -all"}],"nonascii.example.com":[{"SPF":"v=spf1 exp=badexp.example.com -all"}],"badexp.example.com":[{"TXT":"ï»¿Explanation"}],"tworecs.example.com":[{"SPF":"v=spf1 exp=twoexp.example.com -all"}],"twoexp.example.com":[{"TXT":"one"},{"TXT":"two"}],"e23.example.com":[{"SPF":"v=spf1 a:erehwon.example.com a:foobar.com exp=nxdomain.com -all"}],"e24.example.com":[{"SPF":"v=spf1 redirect=testimplicit.example.com"},{"A":"192.0.2.1"}],"testimplicit.example.com":[{"SPF":"v=spf1 a -all"},{"A":"192.0.2.2"}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.4');
        return promise.then((result) => {
          assert.equal(result, 'PERMERROR');
        });
      });
      it('when executing "redirect", exp= from the original domain MUST NOT be used.', function(){
        let email = 'foo@e1.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 exp=exp1.example.com redirect=e2.example.com"}],"e2.example.com":[{"SPF":"v=spf1 -all"}],"e3.example.com":[{"SPF":"v=spf1 exp=exp1.example.com redirect=e4.example.com"}],"e4.example.com":[{"SPF":"v=spf1 -all exp=exp2.example.com"}],"exp1.example.com":[{"TXT":"No-see-um"}],"exp2.example.com":[{"TXT":"See me."}],"exp3.example.com":[{"TXT":"Correct!"}],"exp4.example.com":[{"TXT":"%{l} in implementation"}],"e5.example.com":[{"SPF":"v=spf1 1up=foo"}],"e6.example.com":[{"SPF":"v=spf1 =all"}],"e7.example.com":[{"SPF":"v=spf1 include:e3.example.com -all exp=exp3.example.com"}],"e8.example.com":[{"SPF":"v=spf1 -all exp=exp4.example.com"}],"e9.example.com":[{"SPF":"v=spf1 -all foo=%abc"}],"e10.example.com":[{"SPF":"v=spf1 redirect=erehwon.example.com"}],"e11.example.com":[{"SPF":"v=spf1 -all exp=e11msg.example.com"}],"e11msg.example.com":[{"TXT":"Answer a fool according to his folly."},{"TXT":"Do not answer a fool according to his folly."}],"e12.example.com":[{"SPF":"v=spf1 exp= -all"}],"e13.example.com":[{"SPF":"v=spf1 exp=e13msg.example.com -all"}],"e13msg.example.com":[{"TXT":"The %{x}-files."}],"e14.example.com":[{"SPF":"v=spf1 exp=e13msg.example.com -all exp=e11msg.example.com"}],"e15.example.com":[{"SPF":"v=spf1 redirect=e12.example.com -all redirect=e12.example.com"}],"e16.example.com":[{"SPF":"v=spf1 exp=-all"}],"e17.example.com":[{"SPF":"v=spf1 redirect=-all ?all"}],"e18.example.com":[{"SPF":"v=spf1 ?all redirect="}],"e19.example.com":[{"SPF":"v=spf1 default=pass"}],"e20.example.com":[{"SPF":"v=spf1 default=+"}],"e21.example.com":[{"SPF":"v=spf1 exp=e21msg.example.com -all"}],"e21msg.example.com":["TIMEOUT"],"e22.example.com":[{"SPF":"v=spf1 exp=mail.example.com -all"}],"nonascii.example.com":[{"SPF":"v=spf1 exp=badexp.example.com -all"}],"badexp.example.com":[{"TXT":"ï»¿Explanation"}],"tworecs.example.com":[{"SPF":"v=spf1 exp=twoexp.example.com -all"}],"twoexp.example.com":[{"TXT":"one"},{"TXT":"two"}],"e23.example.com":[{"SPF":"v=spf1 a:erehwon.example.com a:foobar.com exp=nxdomain.com -all"}],"e24.example.com":[{"SPF":"v=spf1 redirect=testimplicit.example.com"},{"A":"192.0.2.1"}],"testimplicit.example.com":[{"SPF":"v=spf1 a -all"},{"A":"192.0.2.2"}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.4');
        return promise.then((result) => {
          assert.equal(result, 'FAIL');
        });
      });
      it('redirect      = "redirect" "=" domain-spec', function(){
        let email = 'foo@e17.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 exp=exp1.example.com redirect=e2.example.com"}],"e2.example.com":[{"SPF":"v=spf1 -all"}],"e3.example.com":[{"SPF":"v=spf1 exp=exp1.example.com redirect=e4.example.com"}],"e4.example.com":[{"SPF":"v=spf1 -all exp=exp2.example.com"}],"exp1.example.com":[{"TXT":"No-see-um"}],"exp2.example.com":[{"TXT":"See me."}],"exp3.example.com":[{"TXT":"Correct!"}],"exp4.example.com":[{"TXT":"%{l} in implementation"}],"e5.example.com":[{"SPF":"v=spf1 1up=foo"}],"e6.example.com":[{"SPF":"v=spf1 =all"}],"e7.example.com":[{"SPF":"v=spf1 include:e3.example.com -all exp=exp3.example.com"}],"e8.example.com":[{"SPF":"v=spf1 -all exp=exp4.example.com"}],"e9.example.com":[{"SPF":"v=spf1 -all foo=%abc"}],"e10.example.com":[{"SPF":"v=spf1 redirect=erehwon.example.com"}],"e11.example.com":[{"SPF":"v=spf1 -all exp=e11msg.example.com"}],"e11msg.example.com":[{"TXT":"Answer a fool according to his folly."},{"TXT":"Do not answer a fool according to his folly."}],"e12.example.com":[{"SPF":"v=spf1 exp= -all"}],"e13.example.com":[{"SPF":"v=spf1 exp=e13msg.example.com -all"}],"e13msg.example.com":[{"TXT":"The %{x}-files."}],"e14.example.com":[{"SPF":"v=spf1 exp=e13msg.example.com -all exp=e11msg.example.com"}],"e15.example.com":[{"SPF":"v=spf1 redirect=e12.example.com -all redirect=e12.example.com"}],"e16.example.com":[{"SPF":"v=spf1 exp=-all"}],"e17.example.com":[{"SPF":"v=spf1 redirect=-all ?all"}],"e18.example.com":[{"SPF":"v=spf1 ?all redirect="}],"e19.example.com":[{"SPF":"v=spf1 default=pass"}],"e20.example.com":[{"SPF":"v=spf1 default=+"}],"e21.example.com":[{"SPF":"v=spf1 exp=e21msg.example.com -all"}],"e21msg.example.com":["TIMEOUT"],"e22.example.com":[{"SPF":"v=spf1 exp=mail.example.com -all"}],"nonascii.example.com":[{"SPF":"v=spf1 exp=badexp.example.com -all"}],"badexp.example.com":[{"TXT":"ï»¿Explanation"}],"tworecs.example.com":[{"SPF":"v=spf1 exp=twoexp.example.com -all"}],"twoexp.example.com":[{"TXT":"one"},{"TXT":"two"}],"e23.example.com":[{"SPF":"v=spf1 a:erehwon.example.com a:foobar.com exp=nxdomain.com -all"}],"e24.example.com":[{"SPF":"v=spf1 redirect=testimplicit.example.com"},{"A":"192.0.2.1"}],"testimplicit.example.com":[{"SPF":"v=spf1 a -all"},{"A":"192.0.2.2"}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.4');
        return promise.then((result) => {
          assert.equal(result, 'PERMERROR');
        });
      });
      it('when executing "include", exp= from the target domain MUST NOT be used.', function(){
        let email = 'foo@e7.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 exp=exp1.example.com redirect=e2.example.com"}],"e2.example.com":[{"SPF":"v=spf1 -all"}],"e3.example.com":[{"SPF":"v=spf1 exp=exp1.example.com redirect=e4.example.com"}],"e4.example.com":[{"SPF":"v=spf1 -all exp=exp2.example.com"}],"exp1.example.com":[{"TXT":"No-see-um"}],"exp2.example.com":[{"TXT":"See me."}],"exp3.example.com":[{"TXT":"Correct!"}],"exp4.example.com":[{"TXT":"%{l} in implementation"}],"e5.example.com":[{"SPF":"v=spf1 1up=foo"}],"e6.example.com":[{"SPF":"v=spf1 =all"}],"e7.example.com":[{"SPF":"v=spf1 include:e3.example.com -all exp=exp3.example.com"}],"e8.example.com":[{"SPF":"v=spf1 -all exp=exp4.example.com"}],"e9.example.com":[{"SPF":"v=spf1 -all foo=%abc"}],"e10.example.com":[{"SPF":"v=spf1 redirect=erehwon.example.com"}],"e11.example.com":[{"SPF":"v=spf1 -all exp=e11msg.example.com"}],"e11msg.example.com":[{"TXT":"Answer a fool according to his folly."},{"TXT":"Do not answer a fool according to his folly."}],"e12.example.com":[{"SPF":"v=spf1 exp= -all"}],"e13.example.com":[{"SPF":"v=spf1 exp=e13msg.example.com -all"}],"e13msg.example.com":[{"TXT":"The %{x}-files."}],"e14.example.com":[{"SPF":"v=spf1 exp=e13msg.example.com -all exp=e11msg.example.com"}],"e15.example.com":[{"SPF":"v=spf1 redirect=e12.example.com -all redirect=e12.example.com"}],"e16.example.com":[{"SPF":"v=spf1 exp=-all"}],"e17.example.com":[{"SPF":"v=spf1 redirect=-all ?all"}],"e18.example.com":[{"SPF":"v=spf1 ?all redirect="}],"e19.example.com":[{"SPF":"v=spf1 default=pass"}],"e20.example.com":[{"SPF":"v=spf1 default=+"}],"e21.example.com":[{"SPF":"v=spf1 exp=e21msg.example.com -all"}],"e21msg.example.com":["TIMEOUT"],"e22.example.com":[{"SPF":"v=spf1 exp=mail.example.com -all"}],"nonascii.example.com":[{"SPF":"v=spf1 exp=badexp.example.com -all"}],"badexp.example.com":[{"TXT":"ï»¿Explanation"}],"tworecs.example.com":[{"SPF":"v=spf1 exp=twoexp.example.com -all"}],"twoexp.example.com":[{"TXT":"one"},{"TXT":"two"}],"e23.example.com":[{"SPF":"v=spf1 a:erehwon.example.com a:foobar.com exp=nxdomain.com -all"}],"e24.example.com":[{"SPF":"v=spf1 redirect=testimplicit.example.com"},{"A":"192.0.2.1"}],"testimplicit.example.com":[{"SPF":"v=spf1 a -all"},{"A":"192.0.2.2"}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.4');
        return promise.then((result) => {
          assert.equal(result, 'FAIL');
        });
      });
      it('when executing "redirect", exp= from the original domain MUST NOT be used.', function(){
        let email = 'foo@e3.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 exp=exp1.example.com redirect=e2.example.com"}],"e2.example.com":[{"SPF":"v=spf1 -all"}],"e3.example.com":[{"SPF":"v=spf1 exp=exp1.example.com redirect=e4.example.com"}],"e4.example.com":[{"SPF":"v=spf1 -all exp=exp2.example.com"}],"exp1.example.com":[{"TXT":"No-see-um"}],"exp2.example.com":[{"TXT":"See me."}],"exp3.example.com":[{"TXT":"Correct!"}],"exp4.example.com":[{"TXT":"%{l} in implementation"}],"e5.example.com":[{"SPF":"v=spf1 1up=foo"}],"e6.example.com":[{"SPF":"v=spf1 =all"}],"e7.example.com":[{"SPF":"v=spf1 include:e3.example.com -all exp=exp3.example.com"}],"e8.example.com":[{"SPF":"v=spf1 -all exp=exp4.example.com"}],"e9.example.com":[{"SPF":"v=spf1 -all foo=%abc"}],"e10.example.com":[{"SPF":"v=spf1 redirect=erehwon.example.com"}],"e11.example.com":[{"SPF":"v=spf1 -all exp=e11msg.example.com"}],"e11msg.example.com":[{"TXT":"Answer a fool according to his folly."},{"TXT":"Do not answer a fool according to his folly."}],"e12.example.com":[{"SPF":"v=spf1 exp= -all"}],"e13.example.com":[{"SPF":"v=spf1 exp=e13msg.example.com -all"}],"e13msg.example.com":[{"TXT":"The %{x}-files."}],"e14.example.com":[{"SPF":"v=spf1 exp=e13msg.example.com -all exp=e11msg.example.com"}],"e15.example.com":[{"SPF":"v=spf1 redirect=e12.example.com -all redirect=e12.example.com"}],"e16.example.com":[{"SPF":"v=spf1 exp=-all"}],"e17.example.com":[{"SPF":"v=spf1 redirect=-all ?all"}],"e18.example.com":[{"SPF":"v=spf1 ?all redirect="}],"e19.example.com":[{"SPF":"v=spf1 default=pass"}],"e20.example.com":[{"SPF":"v=spf1 default=+"}],"e21.example.com":[{"SPF":"v=spf1 exp=e21msg.example.com -all"}],"e21msg.example.com":["TIMEOUT"],"e22.example.com":[{"SPF":"v=spf1 exp=mail.example.com -all"}],"nonascii.example.com":[{"SPF":"v=spf1 exp=badexp.example.com -all"}],"badexp.example.com":[{"TXT":"ï»¿Explanation"}],"tworecs.example.com":[{"SPF":"v=spf1 exp=twoexp.example.com -all"}],"twoexp.example.com":[{"TXT":"one"},{"TXT":"two"}],"e23.example.com":[{"SPF":"v=spf1 a:erehwon.example.com a:foobar.com exp=nxdomain.com -all"}],"e24.example.com":[{"SPF":"v=spf1 redirect=testimplicit.example.com"},{"A":"192.0.2.1"}],"testimplicit.example.com":[{"SPF":"v=spf1 a -all"},{"A":"192.0.2.2"}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.4');
        return promise.then((result) => {
          assert.equal(result, 'FAIL');
        });
      });
      it('unknown-modifier = name "=" macro-string name             = ALPHA *( ALPHA / DIGIT / "-" / "_" / "." )', function(){
        let email = 'foo@e5.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 exp=exp1.example.com redirect=e2.example.com"}],"e2.example.com":[{"SPF":"v=spf1 -all"}],"e3.example.com":[{"SPF":"v=spf1 exp=exp1.example.com redirect=e4.example.com"}],"e4.example.com":[{"SPF":"v=spf1 -all exp=exp2.example.com"}],"exp1.example.com":[{"TXT":"No-see-um"}],"exp2.example.com":[{"TXT":"See me."}],"exp3.example.com":[{"TXT":"Correct!"}],"exp4.example.com":[{"TXT":"%{l} in implementation"}],"e5.example.com":[{"SPF":"v=spf1 1up=foo"}],"e6.example.com":[{"SPF":"v=spf1 =all"}],"e7.example.com":[{"SPF":"v=spf1 include:e3.example.com -all exp=exp3.example.com"}],"e8.example.com":[{"SPF":"v=spf1 -all exp=exp4.example.com"}],"e9.example.com":[{"SPF":"v=spf1 -all foo=%abc"}],"e10.example.com":[{"SPF":"v=spf1 redirect=erehwon.example.com"}],"e11.example.com":[{"SPF":"v=spf1 -all exp=e11msg.example.com"}],"e11msg.example.com":[{"TXT":"Answer a fool according to his folly."},{"TXT":"Do not answer a fool according to his folly."}],"e12.example.com":[{"SPF":"v=spf1 exp= -all"}],"e13.example.com":[{"SPF":"v=spf1 exp=e13msg.example.com -all"}],"e13msg.example.com":[{"TXT":"The %{x}-files."}],"e14.example.com":[{"SPF":"v=spf1 exp=e13msg.example.com -all exp=e11msg.example.com"}],"e15.example.com":[{"SPF":"v=spf1 redirect=e12.example.com -all redirect=e12.example.com"}],"e16.example.com":[{"SPF":"v=spf1 exp=-all"}],"e17.example.com":[{"SPF":"v=spf1 redirect=-all ?all"}],"e18.example.com":[{"SPF":"v=spf1 ?all redirect="}],"e19.example.com":[{"SPF":"v=spf1 default=pass"}],"e20.example.com":[{"SPF":"v=spf1 default=+"}],"e21.example.com":[{"SPF":"v=spf1 exp=e21msg.example.com -all"}],"e21msg.example.com":["TIMEOUT"],"e22.example.com":[{"SPF":"v=spf1 exp=mail.example.com -all"}],"nonascii.example.com":[{"SPF":"v=spf1 exp=badexp.example.com -all"}],"badexp.example.com":[{"TXT":"ï»¿Explanation"}],"tworecs.example.com":[{"SPF":"v=spf1 exp=twoexp.example.com -all"}],"twoexp.example.com":[{"TXT":"one"},{"TXT":"two"}],"e23.example.com":[{"SPF":"v=spf1 a:erehwon.example.com a:foobar.com exp=nxdomain.com -all"}],"e24.example.com":[{"SPF":"v=spf1 redirect=testimplicit.example.com"},{"A":"192.0.2.1"}],"testimplicit.example.com":[{"SPF":"v=spf1 a -all"},{"A":"192.0.2.2"}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.4');
        return promise.then((result) => {
          assert.equal(result, 'PERMERROR');
        });
      });
      it('name             = ALPHA *( ALPHA / DIGIT / "-" / "_" / "." )', function(){
        let email = 'foo@e6.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 exp=exp1.example.com redirect=e2.example.com"}],"e2.example.com":[{"SPF":"v=spf1 -all"}],"e3.example.com":[{"SPF":"v=spf1 exp=exp1.example.com redirect=e4.example.com"}],"e4.example.com":[{"SPF":"v=spf1 -all exp=exp2.example.com"}],"exp1.example.com":[{"TXT":"No-see-um"}],"exp2.example.com":[{"TXT":"See me."}],"exp3.example.com":[{"TXT":"Correct!"}],"exp4.example.com":[{"TXT":"%{l} in implementation"}],"e5.example.com":[{"SPF":"v=spf1 1up=foo"}],"e6.example.com":[{"SPF":"v=spf1 =all"}],"e7.example.com":[{"SPF":"v=spf1 include:e3.example.com -all exp=exp3.example.com"}],"e8.example.com":[{"SPF":"v=spf1 -all exp=exp4.example.com"}],"e9.example.com":[{"SPF":"v=spf1 -all foo=%abc"}],"e10.example.com":[{"SPF":"v=spf1 redirect=erehwon.example.com"}],"e11.example.com":[{"SPF":"v=spf1 -all exp=e11msg.example.com"}],"e11msg.example.com":[{"TXT":"Answer a fool according to his folly."},{"TXT":"Do not answer a fool according to his folly."}],"e12.example.com":[{"SPF":"v=spf1 exp= -all"}],"e13.example.com":[{"SPF":"v=spf1 exp=e13msg.example.com -all"}],"e13msg.example.com":[{"TXT":"The %{x}-files."}],"e14.example.com":[{"SPF":"v=spf1 exp=e13msg.example.com -all exp=e11msg.example.com"}],"e15.example.com":[{"SPF":"v=spf1 redirect=e12.example.com -all redirect=e12.example.com"}],"e16.example.com":[{"SPF":"v=spf1 exp=-all"}],"e17.example.com":[{"SPF":"v=spf1 redirect=-all ?all"}],"e18.example.com":[{"SPF":"v=spf1 ?all redirect="}],"e19.example.com":[{"SPF":"v=spf1 default=pass"}],"e20.example.com":[{"SPF":"v=spf1 default=+"}],"e21.example.com":[{"SPF":"v=spf1 exp=e21msg.example.com -all"}],"e21msg.example.com":["TIMEOUT"],"e22.example.com":[{"SPF":"v=spf1 exp=mail.example.com -all"}],"nonascii.example.com":[{"SPF":"v=spf1 exp=badexp.example.com -all"}],"badexp.example.com":[{"TXT":"ï»¿Explanation"}],"tworecs.example.com":[{"SPF":"v=spf1 exp=twoexp.example.com -all"}],"twoexp.example.com":[{"TXT":"one"},{"TXT":"two"}],"e23.example.com":[{"SPF":"v=spf1 a:erehwon.example.com a:foobar.com exp=nxdomain.com -all"}],"e24.example.com":[{"SPF":"v=spf1 redirect=testimplicit.example.com"},{"A":"192.0.2.1"}],"testimplicit.example.com":[{"SPF":"v=spf1 a -all"},{"A":"192.0.2.2"}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.4');
        return promise.then((result) => {
          assert.equal(result, 'PERMERROR');
        });
      });
      it('An implementation that uses a legal expansion as a sentinel.  We cannot check them all, but we can check this one.', function(){
        let email = 'Macro Error@e8.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 exp=exp1.example.com redirect=e2.example.com"}],"e2.example.com":[{"SPF":"v=spf1 -all"}],"e3.example.com":[{"SPF":"v=spf1 exp=exp1.example.com redirect=e4.example.com"}],"e4.example.com":[{"SPF":"v=spf1 -all exp=exp2.example.com"}],"exp1.example.com":[{"TXT":"No-see-um"}],"exp2.example.com":[{"TXT":"See me."}],"exp3.example.com":[{"TXT":"Correct!"}],"exp4.example.com":[{"TXT":"%{l} in implementation"}],"e5.example.com":[{"SPF":"v=spf1 1up=foo"}],"e6.example.com":[{"SPF":"v=spf1 =all"}],"e7.example.com":[{"SPF":"v=spf1 include:e3.example.com -all exp=exp3.example.com"}],"e8.example.com":[{"SPF":"v=spf1 -all exp=exp4.example.com"}],"e9.example.com":[{"SPF":"v=spf1 -all foo=%abc"}],"e10.example.com":[{"SPF":"v=spf1 redirect=erehwon.example.com"}],"e11.example.com":[{"SPF":"v=spf1 -all exp=e11msg.example.com"}],"e11msg.example.com":[{"TXT":"Answer a fool according to his folly."},{"TXT":"Do not answer a fool according to his folly."}],"e12.example.com":[{"SPF":"v=spf1 exp= -all"}],"e13.example.com":[{"SPF":"v=spf1 exp=e13msg.example.com -all"}],"e13msg.example.com":[{"TXT":"The %{x}-files."}],"e14.example.com":[{"SPF":"v=spf1 exp=e13msg.example.com -all exp=e11msg.example.com"}],"e15.example.com":[{"SPF":"v=spf1 redirect=e12.example.com -all redirect=e12.example.com"}],"e16.example.com":[{"SPF":"v=spf1 exp=-all"}],"e17.example.com":[{"SPF":"v=spf1 redirect=-all ?all"}],"e18.example.com":[{"SPF":"v=spf1 ?all redirect="}],"e19.example.com":[{"SPF":"v=spf1 default=pass"}],"e20.example.com":[{"SPF":"v=spf1 default=+"}],"e21.example.com":[{"SPF":"v=spf1 exp=e21msg.example.com -all"}],"e21msg.example.com":["TIMEOUT"],"e22.example.com":[{"SPF":"v=spf1 exp=mail.example.com -all"}],"nonascii.example.com":[{"SPF":"v=spf1 exp=badexp.example.com -all"}],"badexp.example.com":[{"TXT":"ï»¿Explanation"}],"tworecs.example.com":[{"SPF":"v=spf1 exp=twoexp.example.com -all"}],"twoexp.example.com":[{"TXT":"one"},{"TXT":"two"}],"e23.example.com":[{"SPF":"v=spf1 a:erehwon.example.com a:foobar.com exp=nxdomain.com -all"}],"e24.example.com":[{"SPF":"v=spf1 redirect=testimplicit.example.com"},{"A":"192.0.2.1"}],"testimplicit.example.com":[{"SPF":"v=spf1 a -all"},{"A":"192.0.2.2"}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.4');
        return promise.then((result) => {
          assert.equal(result, 'FAIL');
        });
      });
      it('Ignore exp if multiple TXT records.', function(){
        let email = 'foo@e11.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 exp=exp1.example.com redirect=e2.example.com"}],"e2.example.com":[{"SPF":"v=spf1 -all"}],"e3.example.com":[{"SPF":"v=spf1 exp=exp1.example.com redirect=e4.example.com"}],"e4.example.com":[{"SPF":"v=spf1 -all exp=exp2.example.com"}],"exp1.example.com":[{"TXT":"No-see-um"}],"exp2.example.com":[{"TXT":"See me."}],"exp3.example.com":[{"TXT":"Correct!"}],"exp4.example.com":[{"TXT":"%{l} in implementation"}],"e5.example.com":[{"SPF":"v=spf1 1up=foo"}],"e6.example.com":[{"SPF":"v=spf1 =all"}],"e7.example.com":[{"SPF":"v=spf1 include:e3.example.com -all exp=exp3.example.com"}],"e8.example.com":[{"SPF":"v=spf1 -all exp=exp4.example.com"}],"e9.example.com":[{"SPF":"v=spf1 -all foo=%abc"}],"e10.example.com":[{"SPF":"v=spf1 redirect=erehwon.example.com"}],"e11.example.com":[{"SPF":"v=spf1 -all exp=e11msg.example.com"}],"e11msg.example.com":[{"TXT":"Answer a fool according to his folly."},{"TXT":"Do not answer a fool according to his folly."}],"e12.example.com":[{"SPF":"v=spf1 exp= -all"}],"e13.example.com":[{"SPF":"v=spf1 exp=e13msg.example.com -all"}],"e13msg.example.com":[{"TXT":"The %{x}-files."}],"e14.example.com":[{"SPF":"v=spf1 exp=e13msg.example.com -all exp=e11msg.example.com"}],"e15.example.com":[{"SPF":"v=spf1 redirect=e12.example.com -all redirect=e12.example.com"}],"e16.example.com":[{"SPF":"v=spf1 exp=-all"}],"e17.example.com":[{"SPF":"v=spf1 redirect=-all ?all"}],"e18.example.com":[{"SPF":"v=spf1 ?all redirect="}],"e19.example.com":[{"SPF":"v=spf1 default=pass"}],"e20.example.com":[{"SPF":"v=spf1 default=+"}],"e21.example.com":[{"SPF":"v=spf1 exp=e21msg.example.com -all"}],"e21msg.example.com":["TIMEOUT"],"e22.example.com":[{"SPF":"v=spf1 exp=mail.example.com -all"}],"nonascii.example.com":[{"SPF":"v=spf1 exp=badexp.example.com -all"}],"badexp.example.com":[{"TXT":"ï»¿Explanation"}],"tworecs.example.com":[{"SPF":"v=spf1 exp=twoexp.example.com -all"}],"twoexp.example.com":[{"TXT":"one"},{"TXT":"two"}],"e23.example.com":[{"SPF":"v=spf1 a:erehwon.example.com a:foobar.com exp=nxdomain.com -all"}],"e24.example.com":[{"SPF":"v=spf1 redirect=testimplicit.example.com"},{"A":"192.0.2.1"}],"testimplicit.example.com":[{"SPF":"v=spf1 a -all"},{"A":"192.0.2.2"}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.4');
        return promise.then((result) => {
          assert.equal(result, 'FAIL');
        });
      });
      it('Ignore exp if no TXT records.', function(){
        let email = 'foo@e22.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 exp=exp1.example.com redirect=e2.example.com"}],"e2.example.com":[{"SPF":"v=spf1 -all"}],"e3.example.com":[{"SPF":"v=spf1 exp=exp1.example.com redirect=e4.example.com"}],"e4.example.com":[{"SPF":"v=spf1 -all exp=exp2.example.com"}],"exp1.example.com":[{"TXT":"No-see-um"}],"exp2.example.com":[{"TXT":"See me."}],"exp3.example.com":[{"TXT":"Correct!"}],"exp4.example.com":[{"TXT":"%{l} in implementation"}],"e5.example.com":[{"SPF":"v=spf1 1up=foo"}],"e6.example.com":[{"SPF":"v=spf1 =all"}],"e7.example.com":[{"SPF":"v=spf1 include:e3.example.com -all exp=exp3.example.com"}],"e8.example.com":[{"SPF":"v=spf1 -all exp=exp4.example.com"}],"e9.example.com":[{"SPF":"v=spf1 -all foo=%abc"}],"e10.example.com":[{"SPF":"v=spf1 redirect=erehwon.example.com"}],"e11.example.com":[{"SPF":"v=spf1 -all exp=e11msg.example.com"}],"e11msg.example.com":[{"TXT":"Answer a fool according to his folly."},{"TXT":"Do not answer a fool according to his folly."}],"e12.example.com":[{"SPF":"v=spf1 exp= -all"}],"e13.example.com":[{"SPF":"v=spf1 exp=e13msg.example.com -all"}],"e13msg.example.com":[{"TXT":"The %{x}-files."}],"e14.example.com":[{"SPF":"v=spf1 exp=e13msg.example.com -all exp=e11msg.example.com"}],"e15.example.com":[{"SPF":"v=spf1 redirect=e12.example.com -all redirect=e12.example.com"}],"e16.example.com":[{"SPF":"v=spf1 exp=-all"}],"e17.example.com":[{"SPF":"v=spf1 redirect=-all ?all"}],"e18.example.com":[{"SPF":"v=spf1 ?all redirect="}],"e19.example.com":[{"SPF":"v=spf1 default=pass"}],"e20.example.com":[{"SPF":"v=spf1 default=+"}],"e21.example.com":[{"SPF":"v=spf1 exp=e21msg.example.com -all"}],"e21msg.example.com":["TIMEOUT"],"e22.example.com":[{"SPF":"v=spf1 exp=mail.example.com -all"}],"nonascii.example.com":[{"SPF":"v=spf1 exp=badexp.example.com -all"}],"badexp.example.com":[{"TXT":"ï»¿Explanation"}],"tworecs.example.com":[{"SPF":"v=spf1 exp=twoexp.example.com -all"}],"twoexp.example.com":[{"TXT":"one"},{"TXT":"two"}],"e23.example.com":[{"SPF":"v=spf1 a:erehwon.example.com a:foobar.com exp=nxdomain.com -all"}],"e24.example.com":[{"SPF":"v=spf1 redirect=testimplicit.example.com"},{"A":"192.0.2.1"}],"testimplicit.example.com":[{"SPF":"v=spf1 a -all"},{"A":"192.0.2.2"}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.4');
        return promise.then((result) => {
          assert.equal(result, 'FAIL');
        });
      });
      it('Ignore exp if DNS error.', function(){
        let email = 'foo@e21.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 exp=exp1.example.com redirect=e2.example.com"}],"e2.example.com":[{"SPF":"v=spf1 -all"}],"e3.example.com":[{"SPF":"v=spf1 exp=exp1.example.com redirect=e4.example.com"}],"e4.example.com":[{"SPF":"v=spf1 -all exp=exp2.example.com"}],"exp1.example.com":[{"TXT":"No-see-um"}],"exp2.example.com":[{"TXT":"See me."}],"exp3.example.com":[{"TXT":"Correct!"}],"exp4.example.com":[{"TXT":"%{l} in implementation"}],"e5.example.com":[{"SPF":"v=spf1 1up=foo"}],"e6.example.com":[{"SPF":"v=spf1 =all"}],"e7.example.com":[{"SPF":"v=spf1 include:e3.example.com -all exp=exp3.example.com"}],"e8.example.com":[{"SPF":"v=spf1 -all exp=exp4.example.com"}],"e9.example.com":[{"SPF":"v=spf1 -all foo=%abc"}],"e10.example.com":[{"SPF":"v=spf1 redirect=erehwon.example.com"}],"e11.example.com":[{"SPF":"v=spf1 -all exp=e11msg.example.com"}],"e11msg.example.com":[{"TXT":"Answer a fool according to his folly."},{"TXT":"Do not answer a fool according to his folly."}],"e12.example.com":[{"SPF":"v=spf1 exp= -all"}],"e13.example.com":[{"SPF":"v=spf1 exp=e13msg.example.com -all"}],"e13msg.example.com":[{"TXT":"The %{x}-files."}],"e14.example.com":[{"SPF":"v=spf1 exp=e13msg.example.com -all exp=e11msg.example.com"}],"e15.example.com":[{"SPF":"v=spf1 redirect=e12.example.com -all redirect=e12.example.com"}],"e16.example.com":[{"SPF":"v=spf1 exp=-all"}],"e17.example.com":[{"SPF":"v=spf1 redirect=-all ?all"}],"e18.example.com":[{"SPF":"v=spf1 ?all redirect="}],"e19.example.com":[{"SPF":"v=spf1 default=pass"}],"e20.example.com":[{"SPF":"v=spf1 default=+"}],"e21.example.com":[{"SPF":"v=spf1 exp=e21msg.example.com -all"}],"e21msg.example.com":["TIMEOUT"],"e22.example.com":[{"SPF":"v=spf1 exp=mail.example.com -all"}],"nonascii.example.com":[{"SPF":"v=spf1 exp=badexp.example.com -all"}],"badexp.example.com":[{"TXT":"ï»¿Explanation"}],"tworecs.example.com":[{"SPF":"v=spf1 exp=twoexp.example.com -all"}],"twoexp.example.com":[{"TXT":"one"},{"TXT":"two"}],"e23.example.com":[{"SPF":"v=spf1 a:erehwon.example.com a:foobar.com exp=nxdomain.com -all"}],"e24.example.com":[{"SPF":"v=spf1 redirect=testimplicit.example.com"},{"A":"192.0.2.1"}],"testimplicit.example.com":[{"SPF":"v=spf1 a -all"},{"A":"192.0.2.2"}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.4');
        return promise.then((result) => {
          assert.equal(result, 'FAIL');
        });
      });
      it('PermError if exp= domain-spec is empty.', function(){
        let email = 'foo@e12.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 exp=exp1.example.com redirect=e2.example.com"}],"e2.example.com":[{"SPF":"v=spf1 -all"}],"e3.example.com":[{"SPF":"v=spf1 exp=exp1.example.com redirect=e4.example.com"}],"e4.example.com":[{"SPF":"v=spf1 -all exp=exp2.example.com"}],"exp1.example.com":[{"TXT":"No-see-um"}],"exp2.example.com":[{"TXT":"See me."}],"exp3.example.com":[{"TXT":"Correct!"}],"exp4.example.com":[{"TXT":"%{l} in implementation"}],"e5.example.com":[{"SPF":"v=spf1 1up=foo"}],"e6.example.com":[{"SPF":"v=spf1 =all"}],"e7.example.com":[{"SPF":"v=spf1 include:e3.example.com -all exp=exp3.example.com"}],"e8.example.com":[{"SPF":"v=spf1 -all exp=exp4.example.com"}],"e9.example.com":[{"SPF":"v=spf1 -all foo=%abc"}],"e10.example.com":[{"SPF":"v=spf1 redirect=erehwon.example.com"}],"e11.example.com":[{"SPF":"v=spf1 -all exp=e11msg.example.com"}],"e11msg.example.com":[{"TXT":"Answer a fool according to his folly."},{"TXT":"Do not answer a fool according to his folly."}],"e12.example.com":[{"SPF":"v=spf1 exp= -all"}],"e13.example.com":[{"SPF":"v=spf1 exp=e13msg.example.com -all"}],"e13msg.example.com":[{"TXT":"The %{x}-files."}],"e14.example.com":[{"SPF":"v=spf1 exp=e13msg.example.com -all exp=e11msg.example.com"}],"e15.example.com":[{"SPF":"v=spf1 redirect=e12.example.com -all redirect=e12.example.com"}],"e16.example.com":[{"SPF":"v=spf1 exp=-all"}],"e17.example.com":[{"SPF":"v=spf1 redirect=-all ?all"}],"e18.example.com":[{"SPF":"v=spf1 ?all redirect="}],"e19.example.com":[{"SPF":"v=spf1 default=pass"}],"e20.example.com":[{"SPF":"v=spf1 default=+"}],"e21.example.com":[{"SPF":"v=spf1 exp=e21msg.example.com -all"}],"e21msg.example.com":["TIMEOUT"],"e22.example.com":[{"SPF":"v=spf1 exp=mail.example.com -all"}],"nonascii.example.com":[{"SPF":"v=spf1 exp=badexp.example.com -all"}],"badexp.example.com":[{"TXT":"ï»¿Explanation"}],"tworecs.example.com":[{"SPF":"v=spf1 exp=twoexp.example.com -all"}],"twoexp.example.com":[{"TXT":"one"},{"TXT":"two"}],"e23.example.com":[{"SPF":"v=spf1 a:erehwon.example.com a:foobar.com exp=nxdomain.com -all"}],"e24.example.com":[{"SPF":"v=spf1 redirect=testimplicit.example.com"},{"A":"192.0.2.1"}],"testimplicit.example.com":[{"SPF":"v=spf1 a -all"},{"A":"192.0.2.2"}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.4');
        return promise.then((result) => {
          assert.equal(result, 'PERMERROR');
        });
      });
      it('Ignore exp if the explanation string has a syntax error.', function(){
        let email = 'foo@e13.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 exp=exp1.example.com redirect=e2.example.com"}],"e2.example.com":[{"SPF":"v=spf1 -all"}],"e3.example.com":[{"SPF":"v=spf1 exp=exp1.example.com redirect=e4.example.com"}],"e4.example.com":[{"SPF":"v=spf1 -all exp=exp2.example.com"}],"exp1.example.com":[{"TXT":"No-see-um"}],"exp2.example.com":[{"TXT":"See me."}],"exp3.example.com":[{"TXT":"Correct!"}],"exp4.example.com":[{"TXT":"%{l} in implementation"}],"e5.example.com":[{"SPF":"v=spf1 1up=foo"}],"e6.example.com":[{"SPF":"v=spf1 =all"}],"e7.example.com":[{"SPF":"v=spf1 include:e3.example.com -all exp=exp3.example.com"}],"e8.example.com":[{"SPF":"v=spf1 -all exp=exp4.example.com"}],"e9.example.com":[{"SPF":"v=spf1 -all foo=%abc"}],"e10.example.com":[{"SPF":"v=spf1 redirect=erehwon.example.com"}],"e11.example.com":[{"SPF":"v=spf1 -all exp=e11msg.example.com"}],"e11msg.example.com":[{"TXT":"Answer a fool according to his folly."},{"TXT":"Do not answer a fool according to his folly."}],"e12.example.com":[{"SPF":"v=spf1 exp= -all"}],"e13.example.com":[{"SPF":"v=spf1 exp=e13msg.example.com -all"}],"e13msg.example.com":[{"TXT":"The %{x}-files."}],"e14.example.com":[{"SPF":"v=spf1 exp=e13msg.example.com -all exp=e11msg.example.com"}],"e15.example.com":[{"SPF":"v=spf1 redirect=e12.example.com -all redirect=e12.example.com"}],"e16.example.com":[{"SPF":"v=spf1 exp=-all"}],"e17.example.com":[{"SPF":"v=spf1 redirect=-all ?all"}],"e18.example.com":[{"SPF":"v=spf1 ?all redirect="}],"e19.example.com":[{"SPF":"v=spf1 default=pass"}],"e20.example.com":[{"SPF":"v=spf1 default=+"}],"e21.example.com":[{"SPF":"v=spf1 exp=e21msg.example.com -all"}],"e21msg.example.com":["TIMEOUT"],"e22.example.com":[{"SPF":"v=spf1 exp=mail.example.com -all"}],"nonascii.example.com":[{"SPF":"v=spf1 exp=badexp.example.com -all"}],"badexp.example.com":[{"TXT":"ï»¿Explanation"}],"tworecs.example.com":[{"SPF":"v=spf1 exp=twoexp.example.com -all"}],"twoexp.example.com":[{"TXT":"one"},{"TXT":"two"}],"e23.example.com":[{"SPF":"v=spf1 a:erehwon.example.com a:foobar.com exp=nxdomain.com -all"}],"e24.example.com":[{"SPF":"v=spf1 redirect=testimplicit.example.com"},{"A":"192.0.2.1"}],"testimplicit.example.com":[{"SPF":"v=spf1 a -all"},{"A":"192.0.2.2"}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.4');
        return promise.then((result) => {
          assert.equal(result, 'FAIL');
        });
      });
      it('explanation      = "exp" "=" domain-spec', function(){
        let email = 'foo@e16.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 exp=exp1.example.com redirect=e2.example.com"}],"e2.example.com":[{"SPF":"v=spf1 -all"}],"e3.example.com":[{"SPF":"v=spf1 exp=exp1.example.com redirect=e4.example.com"}],"e4.example.com":[{"SPF":"v=spf1 -all exp=exp2.example.com"}],"exp1.example.com":[{"TXT":"No-see-um"}],"exp2.example.com":[{"TXT":"See me."}],"exp3.example.com":[{"TXT":"Correct!"}],"exp4.example.com":[{"TXT":"%{l} in implementation"}],"e5.example.com":[{"SPF":"v=spf1 1up=foo"}],"e6.example.com":[{"SPF":"v=spf1 =all"}],"e7.example.com":[{"SPF":"v=spf1 include:e3.example.com -all exp=exp3.example.com"}],"e8.example.com":[{"SPF":"v=spf1 -all exp=exp4.example.com"}],"e9.example.com":[{"SPF":"v=spf1 -all foo=%abc"}],"e10.example.com":[{"SPF":"v=spf1 redirect=erehwon.example.com"}],"e11.example.com":[{"SPF":"v=spf1 -all exp=e11msg.example.com"}],"e11msg.example.com":[{"TXT":"Answer a fool according to his folly."},{"TXT":"Do not answer a fool according to his folly."}],"e12.example.com":[{"SPF":"v=spf1 exp= -all"}],"e13.example.com":[{"SPF":"v=spf1 exp=e13msg.example.com -all"}],"e13msg.example.com":[{"TXT":"The %{x}-files."}],"e14.example.com":[{"SPF":"v=spf1 exp=e13msg.example.com -all exp=e11msg.example.com"}],"e15.example.com":[{"SPF":"v=spf1 redirect=e12.example.com -all redirect=e12.example.com"}],"e16.example.com":[{"SPF":"v=spf1 exp=-all"}],"e17.example.com":[{"SPF":"v=spf1 redirect=-all ?all"}],"e18.example.com":[{"SPF":"v=spf1 ?all redirect="}],"e19.example.com":[{"SPF":"v=spf1 default=pass"}],"e20.example.com":[{"SPF":"v=spf1 default=+"}],"e21.example.com":[{"SPF":"v=spf1 exp=e21msg.example.com -all"}],"e21msg.example.com":["TIMEOUT"],"e22.example.com":[{"SPF":"v=spf1 exp=mail.example.com -all"}],"nonascii.example.com":[{"SPF":"v=spf1 exp=badexp.example.com -all"}],"badexp.example.com":[{"TXT":"ï»¿Explanation"}],"tworecs.example.com":[{"SPF":"v=spf1 exp=twoexp.example.com -all"}],"twoexp.example.com":[{"TXT":"one"},{"TXT":"two"}],"e23.example.com":[{"SPF":"v=spf1 a:erehwon.example.com a:foobar.com exp=nxdomain.com -all"}],"e24.example.com":[{"SPF":"v=spf1 redirect=testimplicit.example.com"},{"A":"192.0.2.1"}],"testimplicit.example.com":[{"SPF":"v=spf1 a -all"},{"A":"192.0.2.2"}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.4');
        return promise.then((result) => {
          assert.equal(result, 'PERMERROR');
        });
      });
      it('exp= appears twice.', function(){
        let email = 'foo@e14.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 exp=exp1.example.com redirect=e2.example.com"}],"e2.example.com":[{"SPF":"v=spf1 -all"}],"e3.example.com":[{"SPF":"v=spf1 exp=exp1.example.com redirect=e4.example.com"}],"e4.example.com":[{"SPF":"v=spf1 -all exp=exp2.example.com"}],"exp1.example.com":[{"TXT":"No-see-um"}],"exp2.example.com":[{"TXT":"See me."}],"exp3.example.com":[{"TXT":"Correct!"}],"exp4.example.com":[{"TXT":"%{l} in implementation"}],"e5.example.com":[{"SPF":"v=spf1 1up=foo"}],"e6.example.com":[{"SPF":"v=spf1 =all"}],"e7.example.com":[{"SPF":"v=spf1 include:e3.example.com -all exp=exp3.example.com"}],"e8.example.com":[{"SPF":"v=spf1 -all exp=exp4.example.com"}],"e9.example.com":[{"SPF":"v=spf1 -all foo=%abc"}],"e10.example.com":[{"SPF":"v=spf1 redirect=erehwon.example.com"}],"e11.example.com":[{"SPF":"v=spf1 -all exp=e11msg.example.com"}],"e11msg.example.com":[{"TXT":"Answer a fool according to his folly."},{"TXT":"Do not answer a fool according to his folly."}],"e12.example.com":[{"SPF":"v=spf1 exp= -all"}],"e13.example.com":[{"SPF":"v=spf1 exp=e13msg.example.com -all"}],"e13msg.example.com":[{"TXT":"The %{x}-files."}],"e14.example.com":[{"SPF":"v=spf1 exp=e13msg.example.com -all exp=e11msg.example.com"}],"e15.example.com":[{"SPF":"v=spf1 redirect=e12.example.com -all redirect=e12.example.com"}],"e16.example.com":[{"SPF":"v=spf1 exp=-all"}],"e17.example.com":[{"SPF":"v=spf1 redirect=-all ?all"}],"e18.example.com":[{"SPF":"v=spf1 ?all redirect="}],"e19.example.com":[{"SPF":"v=spf1 default=pass"}],"e20.example.com":[{"SPF":"v=spf1 default=+"}],"e21.example.com":[{"SPF":"v=spf1 exp=e21msg.example.com -all"}],"e21msg.example.com":["TIMEOUT"],"e22.example.com":[{"SPF":"v=spf1 exp=mail.example.com -all"}],"nonascii.example.com":[{"SPF":"v=spf1 exp=badexp.example.com -all"}],"badexp.example.com":[{"TXT":"ï»¿Explanation"}],"tworecs.example.com":[{"SPF":"v=spf1 exp=twoexp.example.com -all"}],"twoexp.example.com":[{"TXT":"one"},{"TXT":"two"}],"e23.example.com":[{"SPF":"v=spf1 a:erehwon.example.com a:foobar.com exp=nxdomain.com -all"}],"e24.example.com":[{"SPF":"v=spf1 redirect=testimplicit.example.com"},{"A":"192.0.2.1"}],"testimplicit.example.com":[{"SPF":"v=spf1 a -all"},{"A":"192.0.2.2"}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.4');
        return promise.then((result) => {
          assert.equal(result, 'PERMERROR');
        });
      });
      it('redirect = "redirect" "=" domain-spec', function(){
        let email = 'foo@e18.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 exp=exp1.example.com redirect=e2.example.com"}],"e2.example.com":[{"SPF":"v=spf1 -all"}],"e3.example.com":[{"SPF":"v=spf1 exp=exp1.example.com redirect=e4.example.com"}],"e4.example.com":[{"SPF":"v=spf1 -all exp=exp2.example.com"}],"exp1.example.com":[{"TXT":"No-see-um"}],"exp2.example.com":[{"TXT":"See me."}],"exp3.example.com":[{"TXT":"Correct!"}],"exp4.example.com":[{"TXT":"%{l} in implementation"}],"e5.example.com":[{"SPF":"v=spf1 1up=foo"}],"e6.example.com":[{"SPF":"v=spf1 =all"}],"e7.example.com":[{"SPF":"v=spf1 include:e3.example.com -all exp=exp3.example.com"}],"e8.example.com":[{"SPF":"v=spf1 -all exp=exp4.example.com"}],"e9.example.com":[{"SPF":"v=spf1 -all foo=%abc"}],"e10.example.com":[{"SPF":"v=spf1 redirect=erehwon.example.com"}],"e11.example.com":[{"SPF":"v=spf1 -all exp=e11msg.example.com"}],"e11msg.example.com":[{"TXT":"Answer a fool according to his folly."},{"TXT":"Do not answer a fool according to his folly."}],"e12.example.com":[{"SPF":"v=spf1 exp= -all"}],"e13.example.com":[{"SPF":"v=spf1 exp=e13msg.example.com -all"}],"e13msg.example.com":[{"TXT":"The %{x}-files."}],"e14.example.com":[{"SPF":"v=spf1 exp=e13msg.example.com -all exp=e11msg.example.com"}],"e15.example.com":[{"SPF":"v=spf1 redirect=e12.example.com -all redirect=e12.example.com"}],"e16.example.com":[{"SPF":"v=spf1 exp=-all"}],"e17.example.com":[{"SPF":"v=spf1 redirect=-all ?all"}],"e18.example.com":[{"SPF":"v=spf1 ?all redirect="}],"e19.example.com":[{"SPF":"v=spf1 default=pass"}],"e20.example.com":[{"SPF":"v=spf1 default=+"}],"e21.example.com":[{"SPF":"v=spf1 exp=e21msg.example.com -all"}],"e21msg.example.com":["TIMEOUT"],"e22.example.com":[{"SPF":"v=spf1 exp=mail.example.com -all"}],"nonascii.example.com":[{"SPF":"v=spf1 exp=badexp.example.com -all"}],"badexp.example.com":[{"TXT":"ï»¿Explanation"}],"tworecs.example.com":[{"SPF":"v=spf1 exp=twoexp.example.com -all"}],"twoexp.example.com":[{"TXT":"one"},{"TXT":"two"}],"e23.example.com":[{"SPF":"v=spf1 a:erehwon.example.com a:foobar.com exp=nxdomain.com -all"}],"e24.example.com":[{"SPF":"v=spf1 redirect=testimplicit.example.com"},{"A":"192.0.2.1"}],"testimplicit.example.com":[{"SPF":"v=spf1 a -all"},{"A":"192.0.2.2"}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.4');
        return promise.then((result) => {
          assert.equal(result, 'PERMERROR');
        });
      });
      it('redirect= appears twice.', function(){
        let email = 'foo@e15.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 exp=exp1.example.com redirect=e2.example.com"}],"e2.example.com":[{"SPF":"v=spf1 -all"}],"e3.example.com":[{"SPF":"v=spf1 exp=exp1.example.com redirect=e4.example.com"}],"e4.example.com":[{"SPF":"v=spf1 -all exp=exp2.example.com"}],"exp1.example.com":[{"TXT":"No-see-um"}],"exp2.example.com":[{"TXT":"See me."}],"exp3.example.com":[{"TXT":"Correct!"}],"exp4.example.com":[{"TXT":"%{l} in implementation"}],"e5.example.com":[{"SPF":"v=spf1 1up=foo"}],"e6.example.com":[{"SPF":"v=spf1 =all"}],"e7.example.com":[{"SPF":"v=spf1 include:e3.example.com -all exp=exp3.example.com"}],"e8.example.com":[{"SPF":"v=spf1 -all exp=exp4.example.com"}],"e9.example.com":[{"SPF":"v=spf1 -all foo=%abc"}],"e10.example.com":[{"SPF":"v=spf1 redirect=erehwon.example.com"}],"e11.example.com":[{"SPF":"v=spf1 -all exp=e11msg.example.com"}],"e11msg.example.com":[{"TXT":"Answer a fool according to his folly."},{"TXT":"Do not answer a fool according to his folly."}],"e12.example.com":[{"SPF":"v=spf1 exp= -all"}],"e13.example.com":[{"SPF":"v=spf1 exp=e13msg.example.com -all"}],"e13msg.example.com":[{"TXT":"The %{x}-files."}],"e14.example.com":[{"SPF":"v=spf1 exp=e13msg.example.com -all exp=e11msg.example.com"}],"e15.example.com":[{"SPF":"v=spf1 redirect=e12.example.com -all redirect=e12.example.com"}],"e16.example.com":[{"SPF":"v=spf1 exp=-all"}],"e17.example.com":[{"SPF":"v=spf1 redirect=-all ?all"}],"e18.example.com":[{"SPF":"v=spf1 ?all redirect="}],"e19.example.com":[{"SPF":"v=spf1 default=pass"}],"e20.example.com":[{"SPF":"v=spf1 default=+"}],"e21.example.com":[{"SPF":"v=spf1 exp=e21msg.example.com -all"}],"e21msg.example.com":["TIMEOUT"],"e22.example.com":[{"SPF":"v=spf1 exp=mail.example.com -all"}],"nonascii.example.com":[{"SPF":"v=spf1 exp=badexp.example.com -all"}],"badexp.example.com":[{"TXT":"ï»¿Explanation"}],"tworecs.example.com":[{"SPF":"v=spf1 exp=twoexp.example.com -all"}],"twoexp.example.com":[{"TXT":"one"},{"TXT":"two"}],"e23.example.com":[{"SPF":"v=spf1 a:erehwon.example.com a:foobar.com exp=nxdomain.com -all"}],"e24.example.com":[{"SPF":"v=spf1 redirect=testimplicit.example.com"},{"A":"192.0.2.1"}],"testimplicit.example.com":[{"SPF":"v=spf1 a -all"},{"A":"192.0.2.2"}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.4');
        return promise.then((result) => {
          assert.equal(result, 'PERMERROR');
        });
      });
      it('unknown-modifier = name "=" macro-string', function(){
        let email = 'foo@e9.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 exp=exp1.example.com redirect=e2.example.com"}],"e2.example.com":[{"SPF":"v=spf1 -all"}],"e3.example.com":[{"SPF":"v=spf1 exp=exp1.example.com redirect=e4.example.com"}],"e4.example.com":[{"SPF":"v=spf1 -all exp=exp2.example.com"}],"exp1.example.com":[{"TXT":"No-see-um"}],"exp2.example.com":[{"TXT":"See me."}],"exp3.example.com":[{"TXT":"Correct!"}],"exp4.example.com":[{"TXT":"%{l} in implementation"}],"e5.example.com":[{"SPF":"v=spf1 1up=foo"}],"e6.example.com":[{"SPF":"v=spf1 =all"}],"e7.example.com":[{"SPF":"v=spf1 include:e3.example.com -all exp=exp3.example.com"}],"e8.example.com":[{"SPF":"v=spf1 -all exp=exp4.example.com"}],"e9.example.com":[{"SPF":"v=spf1 -all foo=%abc"}],"e10.example.com":[{"SPF":"v=spf1 redirect=erehwon.example.com"}],"e11.example.com":[{"SPF":"v=spf1 -all exp=e11msg.example.com"}],"e11msg.example.com":[{"TXT":"Answer a fool according to his folly."},{"TXT":"Do not answer a fool according to his folly."}],"e12.example.com":[{"SPF":"v=spf1 exp= -all"}],"e13.example.com":[{"SPF":"v=spf1 exp=e13msg.example.com -all"}],"e13msg.example.com":[{"TXT":"The %{x}-files."}],"e14.example.com":[{"SPF":"v=spf1 exp=e13msg.example.com -all exp=e11msg.example.com"}],"e15.example.com":[{"SPF":"v=spf1 redirect=e12.example.com -all redirect=e12.example.com"}],"e16.example.com":[{"SPF":"v=spf1 exp=-all"}],"e17.example.com":[{"SPF":"v=spf1 redirect=-all ?all"}],"e18.example.com":[{"SPF":"v=spf1 ?all redirect="}],"e19.example.com":[{"SPF":"v=spf1 default=pass"}],"e20.example.com":[{"SPF":"v=spf1 default=+"}],"e21.example.com":[{"SPF":"v=spf1 exp=e21msg.example.com -all"}],"e21msg.example.com":["TIMEOUT"],"e22.example.com":[{"SPF":"v=spf1 exp=mail.example.com -all"}],"nonascii.example.com":[{"SPF":"v=spf1 exp=badexp.example.com -all"}],"badexp.example.com":[{"TXT":"ï»¿Explanation"}],"tworecs.example.com":[{"SPF":"v=spf1 exp=twoexp.example.com -all"}],"twoexp.example.com":[{"TXT":"one"},{"TXT":"two"}],"e23.example.com":[{"SPF":"v=spf1 a:erehwon.example.com a:foobar.com exp=nxdomain.com -all"}],"e24.example.com":[{"SPF":"v=spf1 redirect=testimplicit.example.com"},{"A":"192.0.2.1"}],"testimplicit.example.com":[{"SPF":"v=spf1 a -all"},{"A":"192.0.2.2"}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.4');
        return promise.then((result) => {
          assert.equal(result, 'PERMERROR');
        });
      });
      it('Unknown modifiers do not modify the RFC SPF result.', function(){
        let email = 'foo@e19.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 exp=exp1.example.com redirect=e2.example.com"}],"e2.example.com":[{"SPF":"v=spf1 -all"}],"e3.example.com":[{"SPF":"v=spf1 exp=exp1.example.com redirect=e4.example.com"}],"e4.example.com":[{"SPF":"v=spf1 -all exp=exp2.example.com"}],"exp1.example.com":[{"TXT":"No-see-um"}],"exp2.example.com":[{"TXT":"See me."}],"exp3.example.com":[{"TXT":"Correct!"}],"exp4.example.com":[{"TXT":"%{l} in implementation"}],"e5.example.com":[{"SPF":"v=spf1 1up=foo"}],"e6.example.com":[{"SPF":"v=spf1 =all"}],"e7.example.com":[{"SPF":"v=spf1 include:e3.example.com -all exp=exp3.example.com"}],"e8.example.com":[{"SPF":"v=spf1 -all exp=exp4.example.com"}],"e9.example.com":[{"SPF":"v=spf1 -all foo=%abc"}],"e10.example.com":[{"SPF":"v=spf1 redirect=erehwon.example.com"}],"e11.example.com":[{"SPF":"v=spf1 -all exp=e11msg.example.com"}],"e11msg.example.com":[{"TXT":"Answer a fool according to his folly."},{"TXT":"Do not answer a fool according to his folly."}],"e12.example.com":[{"SPF":"v=spf1 exp= -all"}],"e13.example.com":[{"SPF":"v=spf1 exp=e13msg.example.com -all"}],"e13msg.example.com":[{"TXT":"The %{x}-files."}],"e14.example.com":[{"SPF":"v=spf1 exp=e13msg.example.com -all exp=e11msg.example.com"}],"e15.example.com":[{"SPF":"v=spf1 redirect=e12.example.com -all redirect=e12.example.com"}],"e16.example.com":[{"SPF":"v=spf1 exp=-all"}],"e17.example.com":[{"SPF":"v=spf1 redirect=-all ?all"}],"e18.example.com":[{"SPF":"v=spf1 ?all redirect="}],"e19.example.com":[{"SPF":"v=spf1 default=pass"}],"e20.example.com":[{"SPF":"v=spf1 default=+"}],"e21.example.com":[{"SPF":"v=spf1 exp=e21msg.example.com -all"}],"e21msg.example.com":["TIMEOUT"],"e22.example.com":[{"SPF":"v=spf1 exp=mail.example.com -all"}],"nonascii.example.com":[{"SPF":"v=spf1 exp=badexp.example.com -all"}],"badexp.example.com":[{"TXT":"ï»¿Explanation"}],"tworecs.example.com":[{"SPF":"v=spf1 exp=twoexp.example.com -all"}],"twoexp.example.com":[{"TXT":"one"},{"TXT":"two"}],"e23.example.com":[{"SPF":"v=spf1 a:erehwon.example.com a:foobar.com exp=nxdomain.com -all"}],"e24.example.com":[{"SPF":"v=spf1 redirect=testimplicit.example.com"},{"A":"192.0.2.1"}],"testimplicit.example.com":[{"SPF":"v=spf1 a -all"},{"A":"192.0.2.2"}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.4');
        return promise.then((result) => {
          assert.equal(result, 'NEUTRAL');
        });
      });
      it('Unknown modifiers do not modify the RFC SPF result.', function(){
        let email = 'foo@e20.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 exp=exp1.example.com redirect=e2.example.com"}],"e2.example.com":[{"SPF":"v=spf1 -all"}],"e3.example.com":[{"SPF":"v=spf1 exp=exp1.example.com redirect=e4.example.com"}],"e4.example.com":[{"SPF":"v=spf1 -all exp=exp2.example.com"}],"exp1.example.com":[{"TXT":"No-see-um"}],"exp2.example.com":[{"TXT":"See me."}],"exp3.example.com":[{"TXT":"Correct!"}],"exp4.example.com":[{"TXT":"%{l} in implementation"}],"e5.example.com":[{"SPF":"v=spf1 1up=foo"}],"e6.example.com":[{"SPF":"v=spf1 =all"}],"e7.example.com":[{"SPF":"v=spf1 include:e3.example.com -all exp=exp3.example.com"}],"e8.example.com":[{"SPF":"v=spf1 -all exp=exp4.example.com"}],"e9.example.com":[{"SPF":"v=spf1 -all foo=%abc"}],"e10.example.com":[{"SPF":"v=spf1 redirect=erehwon.example.com"}],"e11.example.com":[{"SPF":"v=spf1 -all exp=e11msg.example.com"}],"e11msg.example.com":[{"TXT":"Answer a fool according to his folly."},{"TXT":"Do not answer a fool according to his folly."}],"e12.example.com":[{"SPF":"v=spf1 exp= -all"}],"e13.example.com":[{"SPF":"v=spf1 exp=e13msg.example.com -all"}],"e13msg.example.com":[{"TXT":"The %{x}-files."}],"e14.example.com":[{"SPF":"v=spf1 exp=e13msg.example.com -all exp=e11msg.example.com"}],"e15.example.com":[{"SPF":"v=spf1 redirect=e12.example.com -all redirect=e12.example.com"}],"e16.example.com":[{"SPF":"v=spf1 exp=-all"}],"e17.example.com":[{"SPF":"v=spf1 redirect=-all ?all"}],"e18.example.com":[{"SPF":"v=spf1 ?all redirect="}],"e19.example.com":[{"SPF":"v=spf1 default=pass"}],"e20.example.com":[{"SPF":"v=spf1 default=+"}],"e21.example.com":[{"SPF":"v=spf1 exp=e21msg.example.com -all"}],"e21msg.example.com":["TIMEOUT"],"e22.example.com":[{"SPF":"v=spf1 exp=mail.example.com -all"}],"nonascii.example.com":[{"SPF":"v=spf1 exp=badexp.example.com -all"}],"badexp.example.com":[{"TXT":"ï»¿Explanation"}],"tworecs.example.com":[{"SPF":"v=spf1 exp=twoexp.example.com -all"}],"twoexp.example.com":[{"TXT":"one"},{"TXT":"two"}],"e23.example.com":[{"SPF":"v=spf1 a:erehwon.example.com a:foobar.com exp=nxdomain.com -all"}],"e24.example.com":[{"SPF":"v=spf1 redirect=testimplicit.example.com"},{"A":"192.0.2.1"}],"testimplicit.example.com":[{"SPF":"v=spf1 a -all"},{"A":"192.0.2.2"}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.4');
        return promise.then((result) => {
          assert.equal(result, 'NEUTRAL');
        });
      });
      it('SPF explanation text is restricted to 7-bit ascii.', function(){
        let email = 'foobar@nonascii.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 exp=exp1.example.com redirect=e2.example.com"}],"e2.example.com":[{"SPF":"v=spf1 -all"}],"e3.example.com":[{"SPF":"v=spf1 exp=exp1.example.com redirect=e4.example.com"}],"e4.example.com":[{"SPF":"v=spf1 -all exp=exp2.example.com"}],"exp1.example.com":[{"TXT":"No-see-um"}],"exp2.example.com":[{"TXT":"See me."}],"exp3.example.com":[{"TXT":"Correct!"}],"exp4.example.com":[{"TXT":"%{l} in implementation"}],"e5.example.com":[{"SPF":"v=spf1 1up=foo"}],"e6.example.com":[{"SPF":"v=spf1 =all"}],"e7.example.com":[{"SPF":"v=spf1 include:e3.example.com -all exp=exp3.example.com"}],"e8.example.com":[{"SPF":"v=spf1 -all exp=exp4.example.com"}],"e9.example.com":[{"SPF":"v=spf1 -all foo=%abc"}],"e10.example.com":[{"SPF":"v=spf1 redirect=erehwon.example.com"}],"e11.example.com":[{"SPF":"v=spf1 -all exp=e11msg.example.com"}],"e11msg.example.com":[{"TXT":"Answer a fool according to his folly."},{"TXT":"Do not answer a fool according to his folly."}],"e12.example.com":[{"SPF":"v=spf1 exp= -all"}],"e13.example.com":[{"SPF":"v=spf1 exp=e13msg.example.com -all"}],"e13msg.example.com":[{"TXT":"The %{x}-files."}],"e14.example.com":[{"SPF":"v=spf1 exp=e13msg.example.com -all exp=e11msg.example.com"}],"e15.example.com":[{"SPF":"v=spf1 redirect=e12.example.com -all redirect=e12.example.com"}],"e16.example.com":[{"SPF":"v=spf1 exp=-all"}],"e17.example.com":[{"SPF":"v=spf1 redirect=-all ?all"}],"e18.example.com":[{"SPF":"v=spf1 ?all redirect="}],"e19.example.com":[{"SPF":"v=spf1 default=pass"}],"e20.example.com":[{"SPF":"v=spf1 default=+"}],"e21.example.com":[{"SPF":"v=spf1 exp=e21msg.example.com -all"}],"e21msg.example.com":["TIMEOUT"],"e22.example.com":[{"SPF":"v=spf1 exp=mail.example.com -all"}],"nonascii.example.com":[{"SPF":"v=spf1 exp=badexp.example.com -all"}],"badexp.example.com":[{"TXT":"ï»¿Explanation"}],"tworecs.example.com":[{"SPF":"v=spf1 exp=twoexp.example.com -all"}],"twoexp.example.com":[{"TXT":"one"},{"TXT":"two"}],"e23.example.com":[{"SPF":"v=spf1 a:erehwon.example.com a:foobar.com exp=nxdomain.com -all"}],"e24.example.com":[{"SPF":"v=spf1 redirect=testimplicit.example.com"},{"A":"192.0.2.1"}],"testimplicit.example.com":[{"SPF":"v=spf1 a -all"},{"A":"192.0.2.2"}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.4');
        return promise.then((result) => {
          assert.equal(result, 'FAIL');
        });
      });
      it('Must ignore exp= if DNS returns more than one TXT record.', function(){
        let email = 'foobar@tworecs.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 exp=exp1.example.com redirect=e2.example.com"}],"e2.example.com":[{"SPF":"v=spf1 -all"}],"e3.example.com":[{"SPF":"v=spf1 exp=exp1.example.com redirect=e4.example.com"}],"e4.example.com":[{"SPF":"v=spf1 -all exp=exp2.example.com"}],"exp1.example.com":[{"TXT":"No-see-um"}],"exp2.example.com":[{"TXT":"See me."}],"exp3.example.com":[{"TXT":"Correct!"}],"exp4.example.com":[{"TXT":"%{l} in implementation"}],"e5.example.com":[{"SPF":"v=spf1 1up=foo"}],"e6.example.com":[{"SPF":"v=spf1 =all"}],"e7.example.com":[{"SPF":"v=spf1 include:e3.example.com -all exp=exp3.example.com"}],"e8.example.com":[{"SPF":"v=spf1 -all exp=exp4.example.com"}],"e9.example.com":[{"SPF":"v=spf1 -all foo=%abc"}],"e10.example.com":[{"SPF":"v=spf1 redirect=erehwon.example.com"}],"e11.example.com":[{"SPF":"v=spf1 -all exp=e11msg.example.com"}],"e11msg.example.com":[{"TXT":"Answer a fool according to his folly."},{"TXT":"Do not answer a fool according to his folly."}],"e12.example.com":[{"SPF":"v=spf1 exp= -all"}],"e13.example.com":[{"SPF":"v=spf1 exp=e13msg.example.com -all"}],"e13msg.example.com":[{"TXT":"The %{x}-files."}],"e14.example.com":[{"SPF":"v=spf1 exp=e13msg.example.com -all exp=e11msg.example.com"}],"e15.example.com":[{"SPF":"v=spf1 redirect=e12.example.com -all redirect=e12.example.com"}],"e16.example.com":[{"SPF":"v=spf1 exp=-all"}],"e17.example.com":[{"SPF":"v=spf1 redirect=-all ?all"}],"e18.example.com":[{"SPF":"v=spf1 ?all redirect="}],"e19.example.com":[{"SPF":"v=spf1 default=pass"}],"e20.example.com":[{"SPF":"v=spf1 default=+"}],"e21.example.com":[{"SPF":"v=spf1 exp=e21msg.example.com -all"}],"e21msg.example.com":["TIMEOUT"],"e22.example.com":[{"SPF":"v=spf1 exp=mail.example.com -all"}],"nonascii.example.com":[{"SPF":"v=spf1 exp=badexp.example.com -all"}],"badexp.example.com":[{"TXT":"ï»¿Explanation"}],"tworecs.example.com":[{"SPF":"v=spf1 exp=twoexp.example.com -all"}],"twoexp.example.com":[{"TXT":"one"},{"TXT":"two"}],"e23.example.com":[{"SPF":"v=spf1 a:erehwon.example.com a:foobar.com exp=nxdomain.com -all"}],"e24.example.com":[{"SPF":"v=spf1 redirect=testimplicit.example.com"},{"A":"192.0.2.1"}],"testimplicit.example.com":[{"SPF":"v=spf1 a -all"},{"A":"192.0.2.2"}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.4');
        return promise.then((result) => {
          assert.equal(result, 'FAIL');
        });
      });
      it('exp=nxdomain.tld', function(){
        let email = 'foo@e23.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 exp=exp1.example.com redirect=e2.example.com"}],"e2.example.com":[{"SPF":"v=spf1 -all"}],"e3.example.com":[{"SPF":"v=spf1 exp=exp1.example.com redirect=e4.example.com"}],"e4.example.com":[{"SPF":"v=spf1 -all exp=exp2.example.com"}],"exp1.example.com":[{"TXT":"No-see-um"}],"exp2.example.com":[{"TXT":"See me."}],"exp3.example.com":[{"TXT":"Correct!"}],"exp4.example.com":[{"TXT":"%{l} in implementation"}],"e5.example.com":[{"SPF":"v=spf1 1up=foo"}],"e6.example.com":[{"SPF":"v=spf1 =all"}],"e7.example.com":[{"SPF":"v=spf1 include:e3.example.com -all exp=exp3.example.com"}],"e8.example.com":[{"SPF":"v=spf1 -all exp=exp4.example.com"}],"e9.example.com":[{"SPF":"v=spf1 -all foo=%abc"}],"e10.example.com":[{"SPF":"v=spf1 redirect=erehwon.example.com"}],"e11.example.com":[{"SPF":"v=spf1 -all exp=e11msg.example.com"}],"e11msg.example.com":[{"TXT":"Answer a fool according to his folly."},{"TXT":"Do not answer a fool according to his folly."}],"e12.example.com":[{"SPF":"v=spf1 exp= -all"}],"e13.example.com":[{"SPF":"v=spf1 exp=e13msg.example.com -all"}],"e13msg.example.com":[{"TXT":"The %{x}-files."}],"e14.example.com":[{"SPF":"v=spf1 exp=e13msg.example.com -all exp=e11msg.example.com"}],"e15.example.com":[{"SPF":"v=spf1 redirect=e12.example.com -all redirect=e12.example.com"}],"e16.example.com":[{"SPF":"v=spf1 exp=-all"}],"e17.example.com":[{"SPF":"v=spf1 redirect=-all ?all"}],"e18.example.com":[{"SPF":"v=spf1 ?all redirect="}],"e19.example.com":[{"SPF":"v=spf1 default=pass"}],"e20.example.com":[{"SPF":"v=spf1 default=+"}],"e21.example.com":[{"SPF":"v=spf1 exp=e21msg.example.com -all"}],"e21msg.example.com":["TIMEOUT"],"e22.example.com":[{"SPF":"v=spf1 exp=mail.example.com -all"}],"nonascii.example.com":[{"SPF":"v=spf1 exp=badexp.example.com -all"}],"badexp.example.com":[{"TXT":"ï»¿Explanation"}],"tworecs.example.com":[{"SPF":"v=spf1 exp=twoexp.example.com -all"}],"twoexp.example.com":[{"TXT":"one"},{"TXT":"two"}],"e23.example.com":[{"SPF":"v=spf1 a:erehwon.example.com a:foobar.com exp=nxdomain.com -all"}],"e24.example.com":[{"SPF":"v=spf1 redirect=testimplicit.example.com"},{"A":"192.0.2.1"}],"testimplicit.example.com":[{"SPF":"v=spf1 a -all"},{"A":"192.0.2.2"}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.4');
        return promise.then((result) => {
          assert.equal(result, 'FAIL');
        });
      });
      it('redirect changes implicit domain', function(){
        let email = 'bar@e24.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 exp=exp1.example.com redirect=e2.example.com"}],"e2.example.com":[{"SPF":"v=spf1 -all"}],"e3.example.com":[{"SPF":"v=spf1 exp=exp1.example.com redirect=e4.example.com"}],"e4.example.com":[{"SPF":"v=spf1 -all exp=exp2.example.com"}],"exp1.example.com":[{"TXT":"No-see-um"}],"exp2.example.com":[{"TXT":"See me."}],"exp3.example.com":[{"TXT":"Correct!"}],"exp4.example.com":[{"TXT":"%{l} in implementation"}],"e5.example.com":[{"SPF":"v=spf1 1up=foo"}],"e6.example.com":[{"SPF":"v=spf1 =all"}],"e7.example.com":[{"SPF":"v=spf1 include:e3.example.com -all exp=exp3.example.com"}],"e8.example.com":[{"SPF":"v=spf1 -all exp=exp4.example.com"}],"e9.example.com":[{"SPF":"v=spf1 -all foo=%abc"}],"e10.example.com":[{"SPF":"v=spf1 redirect=erehwon.example.com"}],"e11.example.com":[{"SPF":"v=spf1 -all exp=e11msg.example.com"}],"e11msg.example.com":[{"TXT":"Answer a fool according to his folly."},{"TXT":"Do not answer a fool according to his folly."}],"e12.example.com":[{"SPF":"v=spf1 exp= -all"}],"e13.example.com":[{"SPF":"v=spf1 exp=e13msg.example.com -all"}],"e13msg.example.com":[{"TXT":"The %{x}-files."}],"e14.example.com":[{"SPF":"v=spf1 exp=e13msg.example.com -all exp=e11msg.example.com"}],"e15.example.com":[{"SPF":"v=spf1 redirect=e12.example.com -all redirect=e12.example.com"}],"e16.example.com":[{"SPF":"v=spf1 exp=-all"}],"e17.example.com":[{"SPF":"v=spf1 redirect=-all ?all"}],"e18.example.com":[{"SPF":"v=spf1 ?all redirect="}],"e19.example.com":[{"SPF":"v=spf1 default=pass"}],"e20.example.com":[{"SPF":"v=spf1 default=+"}],"e21.example.com":[{"SPF":"v=spf1 exp=e21msg.example.com -all"}],"e21msg.example.com":["TIMEOUT"],"e22.example.com":[{"SPF":"v=spf1 exp=mail.example.com -all"}],"nonascii.example.com":[{"SPF":"v=spf1 exp=badexp.example.com -all"}],"badexp.example.com":[{"TXT":"ï»¿Explanation"}],"tworecs.example.com":[{"SPF":"v=spf1 exp=twoexp.example.com -all"}],"twoexp.example.com":[{"TXT":"one"},{"TXT":"two"}],"e23.example.com":[{"SPF":"v=spf1 a:erehwon.example.com a:foobar.com exp=nxdomain.com -all"}],"e24.example.com":[{"SPF":"v=spf1 redirect=testimplicit.example.com"},{"A":"192.0.2.1"}],"testimplicit.example.com":[{"SPF":"v=spf1 a -all"},{"A":"192.0.2.2"}]}, failOnNoFake: true});
        let promise = validator.validateSender('192.0.2.2');
        return promise.then((result) => {
          assert.equal(result, 'PASS');
        });
      });
    });
    describe('Macro expansion rules', function(){
      it('trailing dot is ignored for domains', function(){
        let email = 'test@example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"example.com.d.spf.example.com":[{"SPF":"v=spf1 redirect=a.spf.example.com"}],"a.spf.example.com":[{"SPF":"v=spf1 include:o.spf.example.com. ~all"}],"o.spf.example.com":[{"SPF":"v=spf1 ip4:192.168.218.40"}],"msgbas2x.cos.example.com":[{"A":"192.168.218.40"}],"example.com":[{"A":"192.168.90.76"},{"SPF":"v=spf1 redirect=%{d}.d.spf.example.com."}],"exp.example.com":[{"SPF":"v=spf1 exp=msg.example.com. -all"}],"msg.example.com":[{"TXT":"This is a test."}],"e1.example.com":[{"SPF":"v=spf1 -exists:%(ir).sbl.example.com ?all"}],"e1e.example.com":[{"SPF":"v=spf1 exists:foo%(ir).sbl.example.com ?all"}],"e1t.example.com":[{"SPF":"v=spf1 exists:foo%.sbl.example.com ?all"}],"e1a.example.com":[{"SPF":"v=spf1 a:macro%%percent%_%_space%-url-space.example.com -all"}],"macro%percent  space%20url-space.example.com":[{"A":"1.2.3.4"}],"e2.example.com":[{"SPF":"v=spf1 -all exp=%{r}.example.com"}],"e3.example.com":[{"SPF":"v=spf1 -all exp=%{ir}.example.com"}],"40.218.168.192.example.com":[{"TXT":"Connections from %{c} not authorized."}],"somewhat.long.exp.example.com":[{"SPF":"v=spf1 -all exp=foobar.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.example.com"}],"somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.example.com":[{"TXT":"Congratulations!  That was tricky."}],"e4.example.com":[{"SPF":"v=spf1 -all exp=e4msg.example.com"}],"e4msg.example.com":[{"TXT":"%{c} is queried as %{ir}.%{v}.arpa"}],"e5.example.com":[{"SPF":"v=spf1 a:%{a}.example.com -all"}],"e6.example.com":[{"SPF":"v=spf1 -all exp=e6msg.example.com"}],"e6msg.example.com":[{"TXT":"connect from %{p}"}],"mx.example.com":[{"A":"192.168.218.41"},{"A":"192.168.218.42"},{"AAAA":"CAFE:BABE::2"},{"AAAA":"CAFE:BABE::3"}],"40.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"}],"41.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"}],"42.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"},{"PTR":"mx.e7.example.com"}],"1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.E.B.A.B.E.F.A.C.ip6.arpa":[{"PTR":"mx.example.com"}],"3.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.E.B.A.B.E.F.A.C.ip6.arpa":[{"PTR":"mx.example.com"}],"mx.e7.example.com":[{"A":"192.168.218.42"}],"mx.e7.example.com.should.example.com":[{"A":"127.0.0.2"}],"mx.example.com.ok.example.com":[{"A":"127.0.0.2"}],"e7.example.com":[{"SPF":"v=spf1 exists:%{p}.should.example.com ~exists:%{p}.ok.example.com"}],"e8.example.com":[{"SPF":"v=spf1 -all exp=msg8.%{D2}"}],"msg8.example.com":[{"TXT":"http://example.com/why.html?l=%{L}"}],"e9.example.com":[{"SPF":"v=spf1 a:%{H} -all"}],"e10.example.com":[{"SPF":"v=spf1 -include:_spfh.%{d2} ip4:1.2.3.0/24 -all"}],"_spfh.example.com":[{"SPF":"v=spf1 -a:%{h} +all"}],"e11.example.com":[{"SPF":"v=spf1 exists:%{i}.%{l2r-}.user.%{d2}"}],"1.2.3.4.gladstone.philip.user.example.com":[{"A":"127.0.0.2"}],"e12.example.com":[{"SPF":"v=spf1 exists:%{l2r+-}.user.%{d2}"}],"bar.foo.user.example.com":[{"A":"127.0.0.2"}]}, failOnNoFake: true});
        let promise = validator.validateSender('192.168.218.40');
        return promise.then((result) => {
          assert.equal(result, 'PASS');
        });
      });
      it('trailing dot is not removed from explanation', function(){
        let email = 'test@exp.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"example.com.d.spf.example.com":[{"SPF":"v=spf1 redirect=a.spf.example.com"}],"a.spf.example.com":[{"SPF":"v=spf1 include:o.spf.example.com. ~all"}],"o.spf.example.com":[{"SPF":"v=spf1 ip4:192.168.218.40"}],"msgbas2x.cos.example.com":[{"A":"192.168.218.40"}],"example.com":[{"A":"192.168.90.76"},{"SPF":"v=spf1 redirect=%{d}.d.spf.example.com."}],"exp.example.com":[{"SPF":"v=spf1 exp=msg.example.com. -all"}],"msg.example.com":[{"TXT":"This is a test."}],"e1.example.com":[{"SPF":"v=spf1 -exists:%(ir).sbl.example.com ?all"}],"e1e.example.com":[{"SPF":"v=spf1 exists:foo%(ir).sbl.example.com ?all"}],"e1t.example.com":[{"SPF":"v=spf1 exists:foo%.sbl.example.com ?all"}],"e1a.example.com":[{"SPF":"v=spf1 a:macro%%percent%_%_space%-url-space.example.com -all"}],"macro%percent  space%20url-space.example.com":[{"A":"1.2.3.4"}],"e2.example.com":[{"SPF":"v=spf1 -all exp=%{r}.example.com"}],"e3.example.com":[{"SPF":"v=spf1 -all exp=%{ir}.example.com"}],"40.218.168.192.example.com":[{"TXT":"Connections from %{c} not authorized."}],"somewhat.long.exp.example.com":[{"SPF":"v=spf1 -all exp=foobar.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.example.com"}],"somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.example.com":[{"TXT":"Congratulations!  That was tricky."}],"e4.example.com":[{"SPF":"v=spf1 -all exp=e4msg.example.com"}],"e4msg.example.com":[{"TXT":"%{c} is queried as %{ir}.%{v}.arpa"}],"e5.example.com":[{"SPF":"v=spf1 a:%{a}.example.com -all"}],"e6.example.com":[{"SPF":"v=spf1 -all exp=e6msg.example.com"}],"e6msg.example.com":[{"TXT":"connect from %{p}"}],"mx.example.com":[{"A":"192.168.218.41"},{"A":"192.168.218.42"},{"AAAA":"CAFE:BABE::2"},{"AAAA":"CAFE:BABE::3"}],"40.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"}],"41.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"}],"42.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"},{"PTR":"mx.e7.example.com"}],"1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.E.B.A.B.E.F.A.C.ip6.arpa":[{"PTR":"mx.example.com"}],"3.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.E.B.A.B.E.F.A.C.ip6.arpa":[{"PTR":"mx.example.com"}],"mx.e7.example.com":[{"A":"192.168.218.42"}],"mx.e7.example.com.should.example.com":[{"A":"127.0.0.2"}],"mx.example.com.ok.example.com":[{"A":"127.0.0.2"}],"e7.example.com":[{"SPF":"v=spf1 exists:%{p}.should.example.com ~exists:%{p}.ok.example.com"}],"e8.example.com":[{"SPF":"v=spf1 -all exp=msg8.%{D2}"}],"msg8.example.com":[{"TXT":"http://example.com/why.html?l=%{L}"}],"e9.example.com":[{"SPF":"v=spf1 a:%{H} -all"}],"e10.example.com":[{"SPF":"v=spf1 -include:_spfh.%{d2} ip4:1.2.3.0/24 -all"}],"_spfh.example.com":[{"SPF":"v=spf1 -a:%{h} +all"}],"e11.example.com":[{"SPF":"v=spf1 exists:%{i}.%{l2r-}.user.%{d2}"}],"1.2.3.4.gladstone.philip.user.example.com":[{"A":"127.0.0.2"}],"e12.example.com":[{"SPF":"v=spf1 exists:%{l2r+-}.user.%{d2}"}],"bar.foo.user.example.com":[{"A":"127.0.0.2"}]}, failOnNoFake: true});
        let promise = validator.validateSender('192.168.218.40');
        return promise.then((result) => {
          assert.equal(result, 'FAIL');
        });
      });
      it('The following macro letters are allowed only in "exp" text: c, r, t', function(){
        let email = 'test@e2.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"example.com.d.spf.example.com":[{"SPF":"v=spf1 redirect=a.spf.example.com"}],"a.spf.example.com":[{"SPF":"v=spf1 include:o.spf.example.com. ~all"}],"o.spf.example.com":[{"SPF":"v=spf1 ip4:192.168.218.40"}],"msgbas2x.cos.example.com":[{"A":"192.168.218.40"}],"example.com":[{"A":"192.168.90.76"},{"SPF":"v=spf1 redirect=%{d}.d.spf.example.com."}],"exp.example.com":[{"SPF":"v=spf1 exp=msg.example.com. -all"}],"msg.example.com":[{"TXT":"This is a test."}],"e1.example.com":[{"SPF":"v=spf1 -exists:%(ir).sbl.example.com ?all"}],"e1e.example.com":[{"SPF":"v=spf1 exists:foo%(ir).sbl.example.com ?all"}],"e1t.example.com":[{"SPF":"v=spf1 exists:foo%.sbl.example.com ?all"}],"e1a.example.com":[{"SPF":"v=spf1 a:macro%%percent%_%_space%-url-space.example.com -all"}],"macro%percent  space%20url-space.example.com":[{"A":"1.2.3.4"}],"e2.example.com":[{"SPF":"v=spf1 -all exp=%{r}.example.com"}],"e3.example.com":[{"SPF":"v=spf1 -all exp=%{ir}.example.com"}],"40.218.168.192.example.com":[{"TXT":"Connections from %{c} not authorized."}],"somewhat.long.exp.example.com":[{"SPF":"v=spf1 -all exp=foobar.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.example.com"}],"somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.example.com":[{"TXT":"Congratulations!  That was tricky."}],"e4.example.com":[{"SPF":"v=spf1 -all exp=e4msg.example.com"}],"e4msg.example.com":[{"TXT":"%{c} is queried as %{ir}.%{v}.arpa"}],"e5.example.com":[{"SPF":"v=spf1 a:%{a}.example.com -all"}],"e6.example.com":[{"SPF":"v=spf1 -all exp=e6msg.example.com"}],"e6msg.example.com":[{"TXT":"connect from %{p}"}],"mx.example.com":[{"A":"192.168.218.41"},{"A":"192.168.218.42"},{"AAAA":"CAFE:BABE::2"},{"AAAA":"CAFE:BABE::3"}],"40.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"}],"41.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"}],"42.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"},{"PTR":"mx.e7.example.com"}],"1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.E.B.A.B.E.F.A.C.ip6.arpa":[{"PTR":"mx.example.com"}],"3.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.E.B.A.B.E.F.A.C.ip6.arpa":[{"PTR":"mx.example.com"}],"mx.e7.example.com":[{"A":"192.168.218.42"}],"mx.e7.example.com.should.example.com":[{"A":"127.0.0.2"}],"mx.example.com.ok.example.com":[{"A":"127.0.0.2"}],"e7.example.com":[{"SPF":"v=spf1 exists:%{p}.should.example.com ~exists:%{p}.ok.example.com"}],"e8.example.com":[{"SPF":"v=spf1 -all exp=msg8.%{D2}"}],"msg8.example.com":[{"TXT":"http://example.com/why.html?l=%{L}"}],"e9.example.com":[{"SPF":"v=spf1 a:%{H} -all"}],"e10.example.com":[{"SPF":"v=spf1 -include:_spfh.%{d2} ip4:1.2.3.0/24 -all"}],"_spfh.example.com":[{"SPF":"v=spf1 -a:%{h} +all"}],"e11.example.com":[{"SPF":"v=spf1 exists:%{i}.%{l2r-}.user.%{d2}"}],"1.2.3.4.gladstone.philip.user.example.com":[{"A":"127.0.0.2"}],"e12.example.com":[{"SPF":"v=spf1 exists:%{l2r+-}.user.%{d2}"}],"bar.foo.user.example.com":[{"A":"127.0.0.2"}]}, failOnNoFake: true});
        let promise = validator.validateSender('192.168.218.40');
        return promise.then((result) => {
          assert.equal(result, 'PERMERROR');
        });
      });
      it('A "%" character not followed by a "{", "%", "-", or "_" character is a syntax error.', function(){
        let email = 'test@e1.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"example.com.d.spf.example.com":[{"SPF":"v=spf1 redirect=a.spf.example.com"}],"a.spf.example.com":[{"SPF":"v=spf1 include:o.spf.example.com. ~all"}],"o.spf.example.com":[{"SPF":"v=spf1 ip4:192.168.218.40"}],"msgbas2x.cos.example.com":[{"A":"192.168.218.40"}],"example.com":[{"A":"192.168.90.76"},{"SPF":"v=spf1 redirect=%{d}.d.spf.example.com."}],"exp.example.com":[{"SPF":"v=spf1 exp=msg.example.com. -all"}],"msg.example.com":[{"TXT":"This is a test."}],"e1.example.com":[{"SPF":"v=spf1 -exists:%(ir).sbl.example.com ?all"}],"e1e.example.com":[{"SPF":"v=spf1 exists:foo%(ir).sbl.example.com ?all"}],"e1t.example.com":[{"SPF":"v=spf1 exists:foo%.sbl.example.com ?all"}],"e1a.example.com":[{"SPF":"v=spf1 a:macro%%percent%_%_space%-url-space.example.com -all"}],"macro%percent  space%20url-space.example.com":[{"A":"1.2.3.4"}],"e2.example.com":[{"SPF":"v=spf1 -all exp=%{r}.example.com"}],"e3.example.com":[{"SPF":"v=spf1 -all exp=%{ir}.example.com"}],"40.218.168.192.example.com":[{"TXT":"Connections from %{c} not authorized."}],"somewhat.long.exp.example.com":[{"SPF":"v=spf1 -all exp=foobar.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.example.com"}],"somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.example.com":[{"TXT":"Congratulations!  That was tricky."}],"e4.example.com":[{"SPF":"v=spf1 -all exp=e4msg.example.com"}],"e4msg.example.com":[{"TXT":"%{c} is queried as %{ir}.%{v}.arpa"}],"e5.example.com":[{"SPF":"v=spf1 a:%{a}.example.com -all"}],"e6.example.com":[{"SPF":"v=spf1 -all exp=e6msg.example.com"}],"e6msg.example.com":[{"TXT":"connect from %{p}"}],"mx.example.com":[{"A":"192.168.218.41"},{"A":"192.168.218.42"},{"AAAA":"CAFE:BABE::2"},{"AAAA":"CAFE:BABE::3"}],"40.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"}],"41.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"}],"42.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"},{"PTR":"mx.e7.example.com"}],"1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.E.B.A.B.E.F.A.C.ip6.arpa":[{"PTR":"mx.example.com"}],"3.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.E.B.A.B.E.F.A.C.ip6.arpa":[{"PTR":"mx.example.com"}],"mx.e7.example.com":[{"A":"192.168.218.42"}],"mx.e7.example.com.should.example.com":[{"A":"127.0.0.2"}],"mx.example.com.ok.example.com":[{"A":"127.0.0.2"}],"e7.example.com":[{"SPF":"v=spf1 exists:%{p}.should.example.com ~exists:%{p}.ok.example.com"}],"e8.example.com":[{"SPF":"v=spf1 -all exp=msg8.%{D2}"}],"msg8.example.com":[{"TXT":"http://example.com/why.html?l=%{L}"}],"e9.example.com":[{"SPF":"v=spf1 a:%{H} -all"}],"e10.example.com":[{"SPF":"v=spf1 -include:_spfh.%{d2} ip4:1.2.3.0/24 -all"}],"_spfh.example.com":[{"SPF":"v=spf1 -a:%{h} +all"}],"e11.example.com":[{"SPF":"v=spf1 exists:%{i}.%{l2r-}.user.%{d2}"}],"1.2.3.4.gladstone.philip.user.example.com":[{"A":"127.0.0.2"}],"e12.example.com":[{"SPF":"v=spf1 exists:%{l2r+-}.user.%{d2}"}],"bar.foo.user.example.com":[{"A":"127.0.0.2"}]}, failOnNoFake: true});
        let promise = validator.validateSender('192.168.218.40');
        return promise.then((result) => {
          assert.equal(result, 'PERMERROR');
        });
      });
      it('A "%" character not followed by a "{", "%", "-", or "_" character is a syntax error.', function(){
        let email = 'test@e1e.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"example.com.d.spf.example.com":[{"SPF":"v=spf1 redirect=a.spf.example.com"}],"a.spf.example.com":[{"SPF":"v=spf1 include:o.spf.example.com. ~all"}],"o.spf.example.com":[{"SPF":"v=spf1 ip4:192.168.218.40"}],"msgbas2x.cos.example.com":[{"A":"192.168.218.40"}],"example.com":[{"A":"192.168.90.76"},{"SPF":"v=spf1 redirect=%{d}.d.spf.example.com."}],"exp.example.com":[{"SPF":"v=spf1 exp=msg.example.com. -all"}],"msg.example.com":[{"TXT":"This is a test."}],"e1.example.com":[{"SPF":"v=spf1 -exists:%(ir).sbl.example.com ?all"}],"e1e.example.com":[{"SPF":"v=spf1 exists:foo%(ir).sbl.example.com ?all"}],"e1t.example.com":[{"SPF":"v=spf1 exists:foo%.sbl.example.com ?all"}],"e1a.example.com":[{"SPF":"v=spf1 a:macro%%percent%_%_space%-url-space.example.com -all"}],"macro%percent  space%20url-space.example.com":[{"A":"1.2.3.4"}],"e2.example.com":[{"SPF":"v=spf1 -all exp=%{r}.example.com"}],"e3.example.com":[{"SPF":"v=spf1 -all exp=%{ir}.example.com"}],"40.218.168.192.example.com":[{"TXT":"Connections from %{c} not authorized."}],"somewhat.long.exp.example.com":[{"SPF":"v=spf1 -all exp=foobar.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.example.com"}],"somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.example.com":[{"TXT":"Congratulations!  That was tricky."}],"e4.example.com":[{"SPF":"v=spf1 -all exp=e4msg.example.com"}],"e4msg.example.com":[{"TXT":"%{c} is queried as %{ir}.%{v}.arpa"}],"e5.example.com":[{"SPF":"v=spf1 a:%{a}.example.com -all"}],"e6.example.com":[{"SPF":"v=spf1 -all exp=e6msg.example.com"}],"e6msg.example.com":[{"TXT":"connect from %{p}"}],"mx.example.com":[{"A":"192.168.218.41"},{"A":"192.168.218.42"},{"AAAA":"CAFE:BABE::2"},{"AAAA":"CAFE:BABE::3"}],"40.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"}],"41.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"}],"42.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"},{"PTR":"mx.e7.example.com"}],"1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.E.B.A.B.E.F.A.C.ip6.arpa":[{"PTR":"mx.example.com"}],"3.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.E.B.A.B.E.F.A.C.ip6.arpa":[{"PTR":"mx.example.com"}],"mx.e7.example.com":[{"A":"192.168.218.42"}],"mx.e7.example.com.should.example.com":[{"A":"127.0.0.2"}],"mx.example.com.ok.example.com":[{"A":"127.0.0.2"}],"e7.example.com":[{"SPF":"v=spf1 exists:%{p}.should.example.com ~exists:%{p}.ok.example.com"}],"e8.example.com":[{"SPF":"v=spf1 -all exp=msg8.%{D2}"}],"msg8.example.com":[{"TXT":"http://example.com/why.html?l=%{L}"}],"e9.example.com":[{"SPF":"v=spf1 a:%{H} -all"}],"e10.example.com":[{"SPF":"v=spf1 -include:_spfh.%{d2} ip4:1.2.3.0/24 -all"}],"_spfh.example.com":[{"SPF":"v=spf1 -a:%{h} +all"}],"e11.example.com":[{"SPF":"v=spf1 exists:%{i}.%{l2r-}.user.%{d2}"}],"1.2.3.4.gladstone.philip.user.example.com":[{"A":"127.0.0.2"}],"e12.example.com":[{"SPF":"v=spf1 exists:%{l2r+-}.user.%{d2}"}],"bar.foo.user.example.com":[{"A":"127.0.0.2"}]}, failOnNoFake: true});
        let promise = validator.validateSender('192.168.218.40');
        return promise.then((result) => {
          assert.equal(result, 'PERMERROR');
        });
      });
      it('A "%" character not followed by a "{", "%", "-", or "_" character is a syntax error.', function(){
        let email = 'test@e1t.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"example.com.d.spf.example.com":[{"SPF":"v=spf1 redirect=a.spf.example.com"}],"a.spf.example.com":[{"SPF":"v=spf1 include:o.spf.example.com. ~all"}],"o.spf.example.com":[{"SPF":"v=spf1 ip4:192.168.218.40"}],"msgbas2x.cos.example.com":[{"A":"192.168.218.40"}],"example.com":[{"A":"192.168.90.76"},{"SPF":"v=spf1 redirect=%{d}.d.spf.example.com."}],"exp.example.com":[{"SPF":"v=spf1 exp=msg.example.com. -all"}],"msg.example.com":[{"TXT":"This is a test."}],"e1.example.com":[{"SPF":"v=spf1 -exists:%(ir).sbl.example.com ?all"}],"e1e.example.com":[{"SPF":"v=spf1 exists:foo%(ir).sbl.example.com ?all"}],"e1t.example.com":[{"SPF":"v=spf1 exists:foo%.sbl.example.com ?all"}],"e1a.example.com":[{"SPF":"v=spf1 a:macro%%percent%_%_space%-url-space.example.com -all"}],"macro%percent  space%20url-space.example.com":[{"A":"1.2.3.4"}],"e2.example.com":[{"SPF":"v=spf1 -all exp=%{r}.example.com"}],"e3.example.com":[{"SPF":"v=spf1 -all exp=%{ir}.example.com"}],"40.218.168.192.example.com":[{"TXT":"Connections from %{c} not authorized."}],"somewhat.long.exp.example.com":[{"SPF":"v=spf1 -all exp=foobar.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.example.com"}],"somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.example.com":[{"TXT":"Congratulations!  That was tricky."}],"e4.example.com":[{"SPF":"v=spf1 -all exp=e4msg.example.com"}],"e4msg.example.com":[{"TXT":"%{c} is queried as %{ir}.%{v}.arpa"}],"e5.example.com":[{"SPF":"v=spf1 a:%{a}.example.com -all"}],"e6.example.com":[{"SPF":"v=spf1 -all exp=e6msg.example.com"}],"e6msg.example.com":[{"TXT":"connect from %{p}"}],"mx.example.com":[{"A":"192.168.218.41"},{"A":"192.168.218.42"},{"AAAA":"CAFE:BABE::2"},{"AAAA":"CAFE:BABE::3"}],"40.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"}],"41.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"}],"42.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"},{"PTR":"mx.e7.example.com"}],"1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.E.B.A.B.E.F.A.C.ip6.arpa":[{"PTR":"mx.example.com"}],"3.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.E.B.A.B.E.F.A.C.ip6.arpa":[{"PTR":"mx.example.com"}],"mx.e7.example.com":[{"A":"192.168.218.42"}],"mx.e7.example.com.should.example.com":[{"A":"127.0.0.2"}],"mx.example.com.ok.example.com":[{"A":"127.0.0.2"}],"e7.example.com":[{"SPF":"v=spf1 exists:%{p}.should.example.com ~exists:%{p}.ok.example.com"}],"e8.example.com":[{"SPF":"v=spf1 -all exp=msg8.%{D2}"}],"msg8.example.com":[{"TXT":"http://example.com/why.html?l=%{L}"}],"e9.example.com":[{"SPF":"v=spf1 a:%{H} -all"}],"e10.example.com":[{"SPF":"v=spf1 -include:_spfh.%{d2} ip4:1.2.3.0/24 -all"}],"_spfh.example.com":[{"SPF":"v=spf1 -a:%{h} +all"}],"e11.example.com":[{"SPF":"v=spf1 exists:%{i}.%{l2r-}.user.%{d2}"}],"1.2.3.4.gladstone.philip.user.example.com":[{"A":"127.0.0.2"}],"e12.example.com":[{"SPF":"v=spf1 exists:%{l2r+-}.user.%{d2}"}],"bar.foo.user.example.com":[{"A":"127.0.0.2"}]}, failOnNoFake: true});
        let promise = validator.validateSender('192.168.218.40');
        return promise.then((result) => {
          assert.equal(result, 'PERMERROR');
        });
      });
      it('macro-encoded percents (%%), spaces (%_), and URL-percent-encoded spaces (%-)', function(){
        let email = 'test@e1a.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"example.com.d.spf.example.com":[{"SPF":"v=spf1 redirect=a.spf.example.com"}],"a.spf.example.com":[{"SPF":"v=spf1 include:o.spf.example.com. ~all"}],"o.spf.example.com":[{"SPF":"v=spf1 ip4:192.168.218.40"}],"msgbas2x.cos.example.com":[{"A":"192.168.218.40"}],"example.com":[{"A":"192.168.90.76"},{"SPF":"v=spf1 redirect=%{d}.d.spf.example.com."}],"exp.example.com":[{"SPF":"v=spf1 exp=msg.example.com. -all"}],"msg.example.com":[{"TXT":"This is a test."}],"e1.example.com":[{"SPF":"v=spf1 -exists:%(ir).sbl.example.com ?all"}],"e1e.example.com":[{"SPF":"v=spf1 exists:foo%(ir).sbl.example.com ?all"}],"e1t.example.com":[{"SPF":"v=spf1 exists:foo%.sbl.example.com ?all"}],"e1a.example.com":[{"SPF":"v=spf1 a:macro%%percent%_%_space%-url-space.example.com -all"}],"macro%percent  space%20url-space.example.com":[{"A":"1.2.3.4"}],"e2.example.com":[{"SPF":"v=spf1 -all exp=%{r}.example.com"}],"e3.example.com":[{"SPF":"v=spf1 -all exp=%{ir}.example.com"}],"40.218.168.192.example.com":[{"TXT":"Connections from %{c} not authorized."}],"somewhat.long.exp.example.com":[{"SPF":"v=spf1 -all exp=foobar.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.example.com"}],"somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.example.com":[{"TXT":"Congratulations!  That was tricky."}],"e4.example.com":[{"SPF":"v=spf1 -all exp=e4msg.example.com"}],"e4msg.example.com":[{"TXT":"%{c} is queried as %{ir}.%{v}.arpa"}],"e5.example.com":[{"SPF":"v=spf1 a:%{a}.example.com -all"}],"e6.example.com":[{"SPF":"v=spf1 -all exp=e6msg.example.com"}],"e6msg.example.com":[{"TXT":"connect from %{p}"}],"mx.example.com":[{"A":"192.168.218.41"},{"A":"192.168.218.42"},{"AAAA":"CAFE:BABE::2"},{"AAAA":"CAFE:BABE::3"}],"40.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"}],"41.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"}],"42.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"},{"PTR":"mx.e7.example.com"}],"1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.E.B.A.B.E.F.A.C.ip6.arpa":[{"PTR":"mx.example.com"}],"3.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.E.B.A.B.E.F.A.C.ip6.arpa":[{"PTR":"mx.example.com"}],"mx.e7.example.com":[{"A":"192.168.218.42"}],"mx.e7.example.com.should.example.com":[{"A":"127.0.0.2"}],"mx.example.com.ok.example.com":[{"A":"127.0.0.2"}],"e7.example.com":[{"SPF":"v=spf1 exists:%{p}.should.example.com ~exists:%{p}.ok.example.com"}],"e8.example.com":[{"SPF":"v=spf1 -all exp=msg8.%{D2}"}],"msg8.example.com":[{"TXT":"http://example.com/why.html?l=%{L}"}],"e9.example.com":[{"SPF":"v=spf1 a:%{H} -all"}],"e10.example.com":[{"SPF":"v=spf1 -include:_spfh.%{d2} ip4:1.2.3.0/24 -all"}],"_spfh.example.com":[{"SPF":"v=spf1 -a:%{h} +all"}],"e11.example.com":[{"SPF":"v=spf1 exists:%{i}.%{l2r-}.user.%{d2}"}],"1.2.3.4.gladstone.philip.user.example.com":[{"A":"127.0.0.2"}],"e12.example.com":[{"SPF":"v=spf1 exists:%{l2r+-}.user.%{d2}"}],"bar.foo.user.example.com":[{"A":"127.0.0.2"}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.4');
        return promise.then((result) => {
          assert.equal(result, 'PASS');
        });
      });
      it('For IPv4 addresses, both the "i" and "c" macros expand to the standard dotted-quad format.', function(){
        let email = 'test@e3.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"example.com.d.spf.example.com":[{"SPF":"v=spf1 redirect=a.spf.example.com"}],"a.spf.example.com":[{"SPF":"v=spf1 include:o.spf.example.com. ~all"}],"o.spf.example.com":[{"SPF":"v=spf1 ip4:192.168.218.40"}],"msgbas2x.cos.example.com":[{"A":"192.168.218.40"}],"example.com":[{"A":"192.168.90.76"},{"SPF":"v=spf1 redirect=%{d}.d.spf.example.com."}],"exp.example.com":[{"SPF":"v=spf1 exp=msg.example.com. -all"}],"msg.example.com":[{"TXT":"This is a test."}],"e1.example.com":[{"SPF":"v=spf1 -exists:%(ir).sbl.example.com ?all"}],"e1e.example.com":[{"SPF":"v=spf1 exists:foo%(ir).sbl.example.com ?all"}],"e1t.example.com":[{"SPF":"v=spf1 exists:foo%.sbl.example.com ?all"}],"e1a.example.com":[{"SPF":"v=spf1 a:macro%%percent%_%_space%-url-space.example.com -all"}],"macro%percent  space%20url-space.example.com":[{"A":"1.2.3.4"}],"e2.example.com":[{"SPF":"v=spf1 -all exp=%{r}.example.com"}],"e3.example.com":[{"SPF":"v=spf1 -all exp=%{ir}.example.com"}],"40.218.168.192.example.com":[{"TXT":"Connections from %{c} not authorized."}],"somewhat.long.exp.example.com":[{"SPF":"v=spf1 -all exp=foobar.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.example.com"}],"somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.example.com":[{"TXT":"Congratulations!  That was tricky."}],"e4.example.com":[{"SPF":"v=spf1 -all exp=e4msg.example.com"}],"e4msg.example.com":[{"TXT":"%{c} is queried as %{ir}.%{v}.arpa"}],"e5.example.com":[{"SPF":"v=spf1 a:%{a}.example.com -all"}],"e6.example.com":[{"SPF":"v=spf1 -all exp=e6msg.example.com"}],"e6msg.example.com":[{"TXT":"connect from %{p}"}],"mx.example.com":[{"A":"192.168.218.41"},{"A":"192.168.218.42"},{"AAAA":"CAFE:BABE::2"},{"AAAA":"CAFE:BABE::3"}],"40.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"}],"41.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"}],"42.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"},{"PTR":"mx.e7.example.com"}],"1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.E.B.A.B.E.F.A.C.ip6.arpa":[{"PTR":"mx.example.com"}],"3.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.E.B.A.B.E.F.A.C.ip6.arpa":[{"PTR":"mx.example.com"}],"mx.e7.example.com":[{"A":"192.168.218.42"}],"mx.e7.example.com.should.example.com":[{"A":"127.0.0.2"}],"mx.example.com.ok.example.com":[{"A":"127.0.0.2"}],"e7.example.com":[{"SPF":"v=spf1 exists:%{p}.should.example.com ~exists:%{p}.ok.example.com"}],"e8.example.com":[{"SPF":"v=spf1 -all exp=msg8.%{D2}"}],"msg8.example.com":[{"TXT":"http://example.com/why.html?l=%{L}"}],"e9.example.com":[{"SPF":"v=spf1 a:%{H} -all"}],"e10.example.com":[{"SPF":"v=spf1 -include:_spfh.%{d2} ip4:1.2.3.0/24 -all"}],"_spfh.example.com":[{"SPF":"v=spf1 -a:%{h} +all"}],"e11.example.com":[{"SPF":"v=spf1 exists:%{i}.%{l2r-}.user.%{d2}"}],"1.2.3.4.gladstone.philip.user.example.com":[{"A":"127.0.0.2"}],"e12.example.com":[{"SPF":"v=spf1 exists:%{l2r+-}.user.%{d2}"}],"bar.foo.user.example.com":[{"A":"127.0.0.2"}]}, failOnNoFake: true});
        let promise = validator.validateSender('192.168.218.40');
        return promise.then((result) => {
          assert.equal(result, 'FAIL');
        });
      });
      it('When the result of macro expansion is used in a domain name query, if the expanded domain name exceeds 253 characters, the left side is truncated to fit, by removing successive domain labels until the total length does not exceed 253 characters.', function(){
        let email = 'test@somewhat.long.exp.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"example.com.d.spf.example.com":[{"SPF":"v=spf1 redirect=a.spf.example.com"}],"a.spf.example.com":[{"SPF":"v=spf1 include:o.spf.example.com. ~all"}],"o.spf.example.com":[{"SPF":"v=spf1 ip4:192.168.218.40"}],"msgbas2x.cos.example.com":[{"A":"192.168.218.40"}],"example.com":[{"A":"192.168.90.76"},{"SPF":"v=spf1 redirect=%{d}.d.spf.example.com."}],"exp.example.com":[{"SPF":"v=spf1 exp=msg.example.com. -all"}],"msg.example.com":[{"TXT":"This is a test."}],"e1.example.com":[{"SPF":"v=spf1 -exists:%(ir).sbl.example.com ?all"}],"e1e.example.com":[{"SPF":"v=spf1 exists:foo%(ir).sbl.example.com ?all"}],"e1t.example.com":[{"SPF":"v=spf1 exists:foo%.sbl.example.com ?all"}],"e1a.example.com":[{"SPF":"v=spf1 a:macro%%percent%_%_space%-url-space.example.com -all"}],"macro%percent  space%20url-space.example.com":[{"A":"1.2.3.4"}],"e2.example.com":[{"SPF":"v=spf1 -all exp=%{r}.example.com"}],"e3.example.com":[{"SPF":"v=spf1 -all exp=%{ir}.example.com"}],"40.218.168.192.example.com":[{"TXT":"Connections from %{c} not authorized."}],"somewhat.long.exp.example.com":[{"SPF":"v=spf1 -all exp=foobar.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.example.com"}],"somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.example.com":[{"TXT":"Congratulations!  That was tricky."}],"e4.example.com":[{"SPF":"v=spf1 -all exp=e4msg.example.com"}],"e4msg.example.com":[{"TXT":"%{c} is queried as %{ir}.%{v}.arpa"}],"e5.example.com":[{"SPF":"v=spf1 a:%{a}.example.com -all"}],"e6.example.com":[{"SPF":"v=spf1 -all exp=e6msg.example.com"}],"e6msg.example.com":[{"TXT":"connect from %{p}"}],"mx.example.com":[{"A":"192.168.218.41"},{"A":"192.168.218.42"},{"AAAA":"CAFE:BABE::2"},{"AAAA":"CAFE:BABE::3"}],"40.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"}],"41.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"}],"42.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"},{"PTR":"mx.e7.example.com"}],"1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.E.B.A.B.E.F.A.C.ip6.arpa":[{"PTR":"mx.example.com"}],"3.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.E.B.A.B.E.F.A.C.ip6.arpa":[{"PTR":"mx.example.com"}],"mx.e7.example.com":[{"A":"192.168.218.42"}],"mx.e7.example.com.should.example.com":[{"A":"127.0.0.2"}],"mx.example.com.ok.example.com":[{"A":"127.0.0.2"}],"e7.example.com":[{"SPF":"v=spf1 exists:%{p}.should.example.com ~exists:%{p}.ok.example.com"}],"e8.example.com":[{"SPF":"v=spf1 -all exp=msg8.%{D2}"}],"msg8.example.com":[{"TXT":"http://example.com/why.html?l=%{L}"}],"e9.example.com":[{"SPF":"v=spf1 a:%{H} -all"}],"e10.example.com":[{"SPF":"v=spf1 -include:_spfh.%{d2} ip4:1.2.3.0/24 -all"}],"_spfh.example.com":[{"SPF":"v=spf1 -a:%{h} +all"}],"e11.example.com":[{"SPF":"v=spf1 exists:%{i}.%{l2r-}.user.%{d2}"}],"1.2.3.4.gladstone.philip.user.example.com":[{"A":"127.0.0.2"}],"e12.example.com":[{"SPF":"v=spf1 exists:%{l2r+-}.user.%{d2}"}],"bar.foo.user.example.com":[{"A":"127.0.0.2"}]}, failOnNoFake: true});
        let promise = validator.validateSender('192.168.218.40');
        return promise.then((result) => {
          assert.equal(result, 'FAIL');
        });
      });
      it('v = the string "in-addr" if <ip> is ipv4, or "ip6" if <ip> is ipv6', function(){
        let email = 'test@e4.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"example.com.d.spf.example.com":[{"SPF":"v=spf1 redirect=a.spf.example.com"}],"a.spf.example.com":[{"SPF":"v=spf1 include:o.spf.example.com. ~all"}],"o.spf.example.com":[{"SPF":"v=spf1 ip4:192.168.218.40"}],"msgbas2x.cos.example.com":[{"A":"192.168.218.40"}],"example.com":[{"A":"192.168.90.76"},{"SPF":"v=spf1 redirect=%{d}.d.spf.example.com."}],"exp.example.com":[{"SPF":"v=spf1 exp=msg.example.com. -all"}],"msg.example.com":[{"TXT":"This is a test."}],"e1.example.com":[{"SPF":"v=spf1 -exists:%(ir).sbl.example.com ?all"}],"e1e.example.com":[{"SPF":"v=spf1 exists:foo%(ir).sbl.example.com ?all"}],"e1t.example.com":[{"SPF":"v=spf1 exists:foo%.sbl.example.com ?all"}],"e1a.example.com":[{"SPF":"v=spf1 a:macro%%percent%_%_space%-url-space.example.com -all"}],"macro%percent  space%20url-space.example.com":[{"A":"1.2.3.4"}],"e2.example.com":[{"SPF":"v=spf1 -all exp=%{r}.example.com"}],"e3.example.com":[{"SPF":"v=spf1 -all exp=%{ir}.example.com"}],"40.218.168.192.example.com":[{"TXT":"Connections from %{c} not authorized."}],"somewhat.long.exp.example.com":[{"SPF":"v=spf1 -all exp=foobar.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.example.com"}],"somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.example.com":[{"TXT":"Congratulations!  That was tricky."}],"e4.example.com":[{"SPF":"v=spf1 -all exp=e4msg.example.com"}],"e4msg.example.com":[{"TXT":"%{c} is queried as %{ir}.%{v}.arpa"}],"e5.example.com":[{"SPF":"v=spf1 a:%{a}.example.com -all"}],"e6.example.com":[{"SPF":"v=spf1 -all exp=e6msg.example.com"}],"e6msg.example.com":[{"TXT":"connect from %{p}"}],"mx.example.com":[{"A":"192.168.218.41"},{"A":"192.168.218.42"},{"AAAA":"CAFE:BABE::2"},{"AAAA":"CAFE:BABE::3"}],"40.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"}],"41.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"}],"42.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"},{"PTR":"mx.e7.example.com"}],"1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.E.B.A.B.E.F.A.C.ip6.arpa":[{"PTR":"mx.example.com"}],"3.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.E.B.A.B.E.F.A.C.ip6.arpa":[{"PTR":"mx.example.com"}],"mx.e7.example.com":[{"A":"192.168.218.42"}],"mx.e7.example.com.should.example.com":[{"A":"127.0.0.2"}],"mx.example.com.ok.example.com":[{"A":"127.0.0.2"}],"e7.example.com":[{"SPF":"v=spf1 exists:%{p}.should.example.com ~exists:%{p}.ok.example.com"}],"e8.example.com":[{"SPF":"v=spf1 -all exp=msg8.%{D2}"}],"msg8.example.com":[{"TXT":"http://example.com/why.html?l=%{L}"}],"e9.example.com":[{"SPF":"v=spf1 a:%{H} -all"}],"e10.example.com":[{"SPF":"v=spf1 -include:_spfh.%{d2} ip4:1.2.3.0/24 -all"}],"_spfh.example.com":[{"SPF":"v=spf1 -a:%{h} +all"}],"e11.example.com":[{"SPF":"v=spf1 exists:%{i}.%{l2r-}.user.%{d2}"}],"1.2.3.4.gladstone.philip.user.example.com":[{"A":"127.0.0.2"}],"e12.example.com":[{"SPF":"v=spf1 exists:%{l2r+-}.user.%{d2}"}],"bar.foo.user.example.com":[{"A":"127.0.0.2"}]}, failOnNoFake: true});
        let promise = validator.validateSender('192.168.218.40');
        return promise.then((result) => {
          assert.equal(result, 'FAIL');
        });
      });
      it('v = the string "in-addr" if <ip> is ipv4, or "ip6" if <ip> is ipv6', function(){
        let email = 'test@e4.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"example.com.d.spf.example.com":[{"SPF":"v=spf1 redirect=a.spf.example.com"}],"a.spf.example.com":[{"SPF":"v=spf1 include:o.spf.example.com. ~all"}],"o.spf.example.com":[{"SPF":"v=spf1 ip4:192.168.218.40"}],"msgbas2x.cos.example.com":[{"A":"192.168.218.40"}],"example.com":[{"A":"192.168.90.76"},{"SPF":"v=spf1 redirect=%{d}.d.spf.example.com."}],"exp.example.com":[{"SPF":"v=spf1 exp=msg.example.com. -all"}],"msg.example.com":[{"TXT":"This is a test."}],"e1.example.com":[{"SPF":"v=spf1 -exists:%(ir).sbl.example.com ?all"}],"e1e.example.com":[{"SPF":"v=spf1 exists:foo%(ir).sbl.example.com ?all"}],"e1t.example.com":[{"SPF":"v=spf1 exists:foo%.sbl.example.com ?all"}],"e1a.example.com":[{"SPF":"v=spf1 a:macro%%percent%_%_space%-url-space.example.com -all"}],"macro%percent  space%20url-space.example.com":[{"A":"1.2.3.4"}],"e2.example.com":[{"SPF":"v=spf1 -all exp=%{r}.example.com"}],"e3.example.com":[{"SPF":"v=spf1 -all exp=%{ir}.example.com"}],"40.218.168.192.example.com":[{"TXT":"Connections from %{c} not authorized."}],"somewhat.long.exp.example.com":[{"SPF":"v=spf1 -all exp=foobar.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.example.com"}],"somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.example.com":[{"TXT":"Congratulations!  That was tricky."}],"e4.example.com":[{"SPF":"v=spf1 -all exp=e4msg.example.com"}],"e4msg.example.com":[{"TXT":"%{c} is queried as %{ir}.%{v}.arpa"}],"e5.example.com":[{"SPF":"v=spf1 a:%{a}.example.com -all"}],"e6.example.com":[{"SPF":"v=spf1 -all exp=e6msg.example.com"}],"e6msg.example.com":[{"TXT":"connect from %{p}"}],"mx.example.com":[{"A":"192.168.218.41"},{"A":"192.168.218.42"},{"AAAA":"CAFE:BABE::2"},{"AAAA":"CAFE:BABE::3"}],"40.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"}],"41.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"}],"42.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"},{"PTR":"mx.e7.example.com"}],"1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.E.B.A.B.E.F.A.C.ip6.arpa":[{"PTR":"mx.example.com"}],"3.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.E.B.A.B.E.F.A.C.ip6.arpa":[{"PTR":"mx.example.com"}],"mx.e7.example.com":[{"A":"192.168.218.42"}],"mx.e7.example.com.should.example.com":[{"A":"127.0.0.2"}],"mx.example.com.ok.example.com":[{"A":"127.0.0.2"}],"e7.example.com":[{"SPF":"v=spf1 exists:%{p}.should.example.com ~exists:%{p}.ok.example.com"}],"e8.example.com":[{"SPF":"v=spf1 -all exp=msg8.%{D2}"}],"msg8.example.com":[{"TXT":"http://example.com/why.html?l=%{L}"}],"e9.example.com":[{"SPF":"v=spf1 a:%{H} -all"}],"e10.example.com":[{"SPF":"v=spf1 -include:_spfh.%{d2} ip4:1.2.3.0/24 -all"}],"_spfh.example.com":[{"SPF":"v=spf1 -a:%{h} +all"}],"e11.example.com":[{"SPF":"v=spf1 exists:%{i}.%{l2r-}.user.%{d2}"}],"1.2.3.4.gladstone.philip.user.example.com":[{"A":"127.0.0.2"}],"e12.example.com":[{"SPF":"v=spf1 exists:%{l2r+-}.user.%{d2}"}],"bar.foo.user.example.com":[{"A":"127.0.0.2"}]}, failOnNoFake: true});
        let promise = validator.validateSender('CAFE:BABE::1');
        return promise.then((result) => {
          assert.equal(result, 'FAIL');
        });
      });
      it('Allowed macros chars are "slodipvh" plus "crt" in explanation.', function(){
        let email = 'test@e5.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"example.com.d.spf.example.com":[{"SPF":"v=spf1 redirect=a.spf.example.com"}],"a.spf.example.com":[{"SPF":"v=spf1 include:o.spf.example.com. ~all"}],"o.spf.example.com":[{"SPF":"v=spf1 ip4:192.168.218.40"}],"msgbas2x.cos.example.com":[{"A":"192.168.218.40"}],"example.com":[{"A":"192.168.90.76"},{"SPF":"v=spf1 redirect=%{d}.d.spf.example.com."}],"exp.example.com":[{"SPF":"v=spf1 exp=msg.example.com. -all"}],"msg.example.com":[{"TXT":"This is a test."}],"e1.example.com":[{"SPF":"v=spf1 -exists:%(ir).sbl.example.com ?all"}],"e1e.example.com":[{"SPF":"v=spf1 exists:foo%(ir).sbl.example.com ?all"}],"e1t.example.com":[{"SPF":"v=spf1 exists:foo%.sbl.example.com ?all"}],"e1a.example.com":[{"SPF":"v=spf1 a:macro%%percent%_%_space%-url-space.example.com -all"}],"macro%percent  space%20url-space.example.com":[{"A":"1.2.3.4"}],"e2.example.com":[{"SPF":"v=spf1 -all exp=%{r}.example.com"}],"e3.example.com":[{"SPF":"v=spf1 -all exp=%{ir}.example.com"}],"40.218.168.192.example.com":[{"TXT":"Connections from %{c} not authorized."}],"somewhat.long.exp.example.com":[{"SPF":"v=spf1 -all exp=foobar.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.example.com"}],"somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.example.com":[{"TXT":"Congratulations!  That was tricky."}],"e4.example.com":[{"SPF":"v=spf1 -all exp=e4msg.example.com"}],"e4msg.example.com":[{"TXT":"%{c} is queried as %{ir}.%{v}.arpa"}],"e5.example.com":[{"SPF":"v=spf1 a:%{a}.example.com -all"}],"e6.example.com":[{"SPF":"v=spf1 -all exp=e6msg.example.com"}],"e6msg.example.com":[{"TXT":"connect from %{p}"}],"mx.example.com":[{"A":"192.168.218.41"},{"A":"192.168.218.42"},{"AAAA":"CAFE:BABE::2"},{"AAAA":"CAFE:BABE::3"}],"40.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"}],"41.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"}],"42.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"},{"PTR":"mx.e7.example.com"}],"1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.E.B.A.B.E.F.A.C.ip6.arpa":[{"PTR":"mx.example.com"}],"3.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.E.B.A.B.E.F.A.C.ip6.arpa":[{"PTR":"mx.example.com"}],"mx.e7.example.com":[{"A":"192.168.218.42"}],"mx.e7.example.com.should.example.com":[{"A":"127.0.0.2"}],"mx.example.com.ok.example.com":[{"A":"127.0.0.2"}],"e7.example.com":[{"SPF":"v=spf1 exists:%{p}.should.example.com ~exists:%{p}.ok.example.com"}],"e8.example.com":[{"SPF":"v=spf1 -all exp=msg8.%{D2}"}],"msg8.example.com":[{"TXT":"http://example.com/why.html?l=%{L}"}],"e9.example.com":[{"SPF":"v=spf1 a:%{H} -all"}],"e10.example.com":[{"SPF":"v=spf1 -include:_spfh.%{d2} ip4:1.2.3.0/24 -all"}],"_spfh.example.com":[{"SPF":"v=spf1 -a:%{h} +all"}],"e11.example.com":[{"SPF":"v=spf1 exists:%{i}.%{l2r-}.user.%{d2}"}],"1.2.3.4.gladstone.philip.user.example.com":[{"A":"127.0.0.2"}],"e12.example.com":[{"SPF":"v=spf1 exists:%{l2r+-}.user.%{d2}"}],"bar.foo.user.example.com":[{"A":"127.0.0.2"}]}, failOnNoFake: true});
        let promise = validator.validateSender('CAFE:BABE::192.168.218.40');
        return promise.then((result) => {
          assert.equal(result, 'PERMERROR');
        });
      });
      it('p = the validated domain name of <ip>', function(){
        let email = 'test@e6.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"example.com.d.spf.example.com":[{"SPF":"v=spf1 redirect=a.spf.example.com"}],"a.spf.example.com":[{"SPF":"v=spf1 include:o.spf.example.com. ~all"}],"o.spf.example.com":[{"SPF":"v=spf1 ip4:192.168.218.40"}],"msgbas2x.cos.example.com":[{"A":"192.168.218.40"}],"example.com":[{"A":"192.168.90.76"},{"SPF":"v=spf1 redirect=%{d}.d.spf.example.com."}],"exp.example.com":[{"SPF":"v=spf1 exp=msg.example.com. -all"}],"msg.example.com":[{"TXT":"This is a test."}],"e1.example.com":[{"SPF":"v=spf1 -exists:%(ir).sbl.example.com ?all"}],"e1e.example.com":[{"SPF":"v=spf1 exists:foo%(ir).sbl.example.com ?all"}],"e1t.example.com":[{"SPF":"v=spf1 exists:foo%.sbl.example.com ?all"}],"e1a.example.com":[{"SPF":"v=spf1 a:macro%%percent%_%_space%-url-space.example.com -all"}],"macro%percent  space%20url-space.example.com":[{"A":"1.2.3.4"}],"e2.example.com":[{"SPF":"v=spf1 -all exp=%{r}.example.com"}],"e3.example.com":[{"SPF":"v=spf1 -all exp=%{ir}.example.com"}],"40.218.168.192.example.com":[{"TXT":"Connections from %{c} not authorized."}],"somewhat.long.exp.example.com":[{"SPF":"v=spf1 -all exp=foobar.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.example.com"}],"somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.example.com":[{"TXT":"Congratulations!  That was tricky."}],"e4.example.com":[{"SPF":"v=spf1 -all exp=e4msg.example.com"}],"e4msg.example.com":[{"TXT":"%{c} is queried as %{ir}.%{v}.arpa"}],"e5.example.com":[{"SPF":"v=spf1 a:%{a}.example.com -all"}],"e6.example.com":[{"SPF":"v=spf1 -all exp=e6msg.example.com"}],"e6msg.example.com":[{"TXT":"connect from %{p}"}],"mx.example.com":[{"A":"192.168.218.41"},{"A":"192.168.218.42"},{"AAAA":"CAFE:BABE::2"},{"AAAA":"CAFE:BABE::3"}],"40.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"}],"41.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"}],"42.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"},{"PTR":"mx.e7.example.com"}],"1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.E.B.A.B.E.F.A.C.ip6.arpa":[{"PTR":"mx.example.com"}],"3.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.E.B.A.B.E.F.A.C.ip6.arpa":[{"PTR":"mx.example.com"}],"mx.e7.example.com":[{"A":"192.168.218.42"}],"mx.e7.example.com.should.example.com":[{"A":"127.0.0.2"}],"mx.example.com.ok.example.com":[{"A":"127.0.0.2"}],"e7.example.com":[{"SPF":"v=spf1 exists:%{p}.should.example.com ~exists:%{p}.ok.example.com"}],"e8.example.com":[{"SPF":"v=spf1 -all exp=msg8.%{D2}"}],"msg8.example.com":[{"TXT":"http://example.com/why.html?l=%{L}"}],"e9.example.com":[{"SPF":"v=spf1 a:%{H} -all"}],"e10.example.com":[{"SPF":"v=spf1 -include:_spfh.%{d2} ip4:1.2.3.0/24 -all"}],"_spfh.example.com":[{"SPF":"v=spf1 -a:%{h} +all"}],"e11.example.com":[{"SPF":"v=spf1 exists:%{i}.%{l2r-}.user.%{d2}"}],"1.2.3.4.gladstone.philip.user.example.com":[{"A":"127.0.0.2"}],"e12.example.com":[{"SPF":"v=spf1 exists:%{l2r+-}.user.%{d2}"}],"bar.foo.user.example.com":[{"A":"127.0.0.2"}]}, failOnNoFake: true});
        let promise = validator.validateSender('192.168.218.40');
        return promise.then((result) => {
          assert.equal(result, 'FAIL');
        });
      });
      it('p = the validated domain name of <ip>', function(){
        let email = 'test@e6.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"example.com.d.spf.example.com":[{"SPF":"v=spf1 redirect=a.spf.example.com"}],"a.spf.example.com":[{"SPF":"v=spf1 include:o.spf.example.com. ~all"}],"o.spf.example.com":[{"SPF":"v=spf1 ip4:192.168.218.40"}],"msgbas2x.cos.example.com":[{"A":"192.168.218.40"}],"example.com":[{"A":"192.168.90.76"},{"SPF":"v=spf1 redirect=%{d}.d.spf.example.com."}],"exp.example.com":[{"SPF":"v=spf1 exp=msg.example.com. -all"}],"msg.example.com":[{"TXT":"This is a test."}],"e1.example.com":[{"SPF":"v=spf1 -exists:%(ir).sbl.example.com ?all"}],"e1e.example.com":[{"SPF":"v=spf1 exists:foo%(ir).sbl.example.com ?all"}],"e1t.example.com":[{"SPF":"v=spf1 exists:foo%.sbl.example.com ?all"}],"e1a.example.com":[{"SPF":"v=spf1 a:macro%%percent%_%_space%-url-space.example.com -all"}],"macro%percent  space%20url-space.example.com":[{"A":"1.2.3.4"}],"e2.example.com":[{"SPF":"v=spf1 -all exp=%{r}.example.com"}],"e3.example.com":[{"SPF":"v=spf1 -all exp=%{ir}.example.com"}],"40.218.168.192.example.com":[{"TXT":"Connections from %{c} not authorized."}],"somewhat.long.exp.example.com":[{"SPF":"v=spf1 -all exp=foobar.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.example.com"}],"somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.example.com":[{"TXT":"Congratulations!  That was tricky."}],"e4.example.com":[{"SPF":"v=spf1 -all exp=e4msg.example.com"}],"e4msg.example.com":[{"TXT":"%{c} is queried as %{ir}.%{v}.arpa"}],"e5.example.com":[{"SPF":"v=spf1 a:%{a}.example.com -all"}],"e6.example.com":[{"SPF":"v=spf1 -all exp=e6msg.example.com"}],"e6msg.example.com":[{"TXT":"connect from %{p}"}],"mx.example.com":[{"A":"192.168.218.41"},{"A":"192.168.218.42"},{"AAAA":"CAFE:BABE::2"},{"AAAA":"CAFE:BABE::3"}],"40.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"}],"41.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"}],"42.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"},{"PTR":"mx.e7.example.com"}],"1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.E.B.A.B.E.F.A.C.ip6.arpa":[{"PTR":"mx.example.com"}],"3.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.E.B.A.B.E.F.A.C.ip6.arpa":[{"PTR":"mx.example.com"}],"mx.e7.example.com":[{"A":"192.168.218.42"}],"mx.e7.example.com.should.example.com":[{"A":"127.0.0.2"}],"mx.example.com.ok.example.com":[{"A":"127.0.0.2"}],"e7.example.com":[{"SPF":"v=spf1 exists:%{p}.should.example.com ~exists:%{p}.ok.example.com"}],"e8.example.com":[{"SPF":"v=spf1 -all exp=msg8.%{D2}"}],"msg8.example.com":[{"TXT":"http://example.com/why.html?l=%{L}"}],"e9.example.com":[{"SPF":"v=spf1 a:%{H} -all"}],"e10.example.com":[{"SPF":"v=spf1 -include:_spfh.%{d2} ip4:1.2.3.0/24 -all"}],"_spfh.example.com":[{"SPF":"v=spf1 -a:%{h} +all"}],"e11.example.com":[{"SPF":"v=spf1 exists:%{i}.%{l2r-}.user.%{d2}"}],"1.2.3.4.gladstone.philip.user.example.com":[{"A":"127.0.0.2"}],"e12.example.com":[{"SPF":"v=spf1 exists:%{l2r+-}.user.%{d2}"}],"bar.foo.user.example.com":[{"A":"127.0.0.2"}]}, failOnNoFake: true});
        let promise = validator.validateSender('192.168.218.41');
        return promise.then((result) => {
          assert.equal(result, 'FAIL');
        });
      });
      it('p = the validated domain name of <ip>', function(){
        let email = 'test@e6.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"example.com.d.spf.example.com":[{"SPF":"v=spf1 redirect=a.spf.example.com"}],"a.spf.example.com":[{"SPF":"v=spf1 include:o.spf.example.com. ~all"}],"o.spf.example.com":[{"SPF":"v=spf1 ip4:192.168.218.40"}],"msgbas2x.cos.example.com":[{"A":"192.168.218.40"}],"example.com":[{"A":"192.168.90.76"},{"SPF":"v=spf1 redirect=%{d}.d.spf.example.com."}],"exp.example.com":[{"SPF":"v=spf1 exp=msg.example.com. -all"}],"msg.example.com":[{"TXT":"This is a test."}],"e1.example.com":[{"SPF":"v=spf1 -exists:%(ir).sbl.example.com ?all"}],"e1e.example.com":[{"SPF":"v=spf1 exists:foo%(ir).sbl.example.com ?all"}],"e1t.example.com":[{"SPF":"v=spf1 exists:foo%.sbl.example.com ?all"}],"e1a.example.com":[{"SPF":"v=spf1 a:macro%%percent%_%_space%-url-space.example.com -all"}],"macro%percent  space%20url-space.example.com":[{"A":"1.2.3.4"}],"e2.example.com":[{"SPF":"v=spf1 -all exp=%{r}.example.com"}],"e3.example.com":[{"SPF":"v=spf1 -all exp=%{ir}.example.com"}],"40.218.168.192.example.com":[{"TXT":"Connections from %{c} not authorized."}],"somewhat.long.exp.example.com":[{"SPF":"v=spf1 -all exp=foobar.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.example.com"}],"somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.example.com":[{"TXT":"Congratulations!  That was tricky."}],"e4.example.com":[{"SPF":"v=spf1 -all exp=e4msg.example.com"}],"e4msg.example.com":[{"TXT":"%{c} is queried as %{ir}.%{v}.arpa"}],"e5.example.com":[{"SPF":"v=spf1 a:%{a}.example.com -all"}],"e6.example.com":[{"SPF":"v=spf1 -all exp=e6msg.example.com"}],"e6msg.example.com":[{"TXT":"connect from %{p}"}],"mx.example.com":[{"A":"192.168.218.41"},{"A":"192.168.218.42"},{"AAAA":"CAFE:BABE::2"},{"AAAA":"CAFE:BABE::3"}],"40.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"}],"41.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"}],"42.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"},{"PTR":"mx.e7.example.com"}],"1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.E.B.A.B.E.F.A.C.ip6.arpa":[{"PTR":"mx.example.com"}],"3.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.E.B.A.B.E.F.A.C.ip6.arpa":[{"PTR":"mx.example.com"}],"mx.e7.example.com":[{"A":"192.168.218.42"}],"mx.e7.example.com.should.example.com":[{"A":"127.0.0.2"}],"mx.example.com.ok.example.com":[{"A":"127.0.0.2"}],"e7.example.com":[{"SPF":"v=spf1 exists:%{p}.should.example.com ~exists:%{p}.ok.example.com"}],"e8.example.com":[{"SPF":"v=spf1 -all exp=msg8.%{D2}"}],"msg8.example.com":[{"TXT":"http://example.com/why.html?l=%{L}"}],"e9.example.com":[{"SPF":"v=spf1 a:%{H} -all"}],"e10.example.com":[{"SPF":"v=spf1 -include:_spfh.%{d2} ip4:1.2.3.0/24 -all"}],"_spfh.example.com":[{"SPF":"v=spf1 -a:%{h} +all"}],"e11.example.com":[{"SPF":"v=spf1 exists:%{i}.%{l2r-}.user.%{d2}"}],"1.2.3.4.gladstone.philip.user.example.com":[{"A":"127.0.0.2"}],"e12.example.com":[{"SPF":"v=spf1 exists:%{l2r+-}.user.%{d2}"}],"bar.foo.user.example.com":[{"A":"127.0.0.2"}]}, failOnNoFake: true});
        let promise = validator.validateSender('CAFE:BABE::1');
        return promise.then((result) => {
          assert.equal(result, 'FAIL');
        });
      });
      it('p = the validated domain name of <ip>', function(){
        let email = 'test@e6.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"example.com.d.spf.example.com":[{"SPF":"v=spf1 redirect=a.spf.example.com"}],"a.spf.example.com":[{"SPF":"v=spf1 include:o.spf.example.com. ~all"}],"o.spf.example.com":[{"SPF":"v=spf1 ip4:192.168.218.40"}],"msgbas2x.cos.example.com":[{"A":"192.168.218.40"}],"example.com":[{"A":"192.168.90.76"},{"SPF":"v=spf1 redirect=%{d}.d.spf.example.com."}],"exp.example.com":[{"SPF":"v=spf1 exp=msg.example.com. -all"}],"msg.example.com":[{"TXT":"This is a test."}],"e1.example.com":[{"SPF":"v=spf1 -exists:%(ir).sbl.example.com ?all"}],"e1e.example.com":[{"SPF":"v=spf1 exists:foo%(ir).sbl.example.com ?all"}],"e1t.example.com":[{"SPF":"v=spf1 exists:foo%.sbl.example.com ?all"}],"e1a.example.com":[{"SPF":"v=spf1 a:macro%%percent%_%_space%-url-space.example.com -all"}],"macro%percent  space%20url-space.example.com":[{"A":"1.2.3.4"}],"e2.example.com":[{"SPF":"v=spf1 -all exp=%{r}.example.com"}],"e3.example.com":[{"SPF":"v=spf1 -all exp=%{ir}.example.com"}],"40.218.168.192.example.com":[{"TXT":"Connections from %{c} not authorized."}],"somewhat.long.exp.example.com":[{"SPF":"v=spf1 -all exp=foobar.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.example.com"}],"somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.example.com":[{"TXT":"Congratulations!  That was tricky."}],"e4.example.com":[{"SPF":"v=spf1 -all exp=e4msg.example.com"}],"e4msg.example.com":[{"TXT":"%{c} is queried as %{ir}.%{v}.arpa"}],"e5.example.com":[{"SPF":"v=spf1 a:%{a}.example.com -all"}],"e6.example.com":[{"SPF":"v=spf1 -all exp=e6msg.example.com"}],"e6msg.example.com":[{"TXT":"connect from %{p}"}],"mx.example.com":[{"A":"192.168.218.41"},{"A":"192.168.218.42"},{"AAAA":"CAFE:BABE::2"},{"AAAA":"CAFE:BABE::3"}],"40.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"}],"41.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"}],"42.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"},{"PTR":"mx.e7.example.com"}],"1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.E.B.A.B.E.F.A.C.ip6.arpa":[{"PTR":"mx.example.com"}],"3.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.E.B.A.B.E.F.A.C.ip6.arpa":[{"PTR":"mx.example.com"}],"mx.e7.example.com":[{"A":"192.168.218.42"}],"mx.e7.example.com.should.example.com":[{"A":"127.0.0.2"}],"mx.example.com.ok.example.com":[{"A":"127.0.0.2"}],"e7.example.com":[{"SPF":"v=spf1 exists:%{p}.should.example.com ~exists:%{p}.ok.example.com"}],"e8.example.com":[{"SPF":"v=spf1 -all exp=msg8.%{D2}"}],"msg8.example.com":[{"TXT":"http://example.com/why.html?l=%{L}"}],"e9.example.com":[{"SPF":"v=spf1 a:%{H} -all"}],"e10.example.com":[{"SPF":"v=spf1 -include:_spfh.%{d2} ip4:1.2.3.0/24 -all"}],"_spfh.example.com":[{"SPF":"v=spf1 -a:%{h} +all"}],"e11.example.com":[{"SPF":"v=spf1 exists:%{i}.%{l2r-}.user.%{d2}"}],"1.2.3.4.gladstone.philip.user.example.com":[{"A":"127.0.0.2"}],"e12.example.com":[{"SPF":"v=spf1 exists:%{l2r+-}.user.%{d2}"}],"bar.foo.user.example.com":[{"A":"127.0.0.2"}]}, failOnNoFake: true});
        let promise = validator.validateSender('CAFE:BABE::3');
        return promise.then((result) => {
          assert.equal(result, 'FAIL');
        });
      });
      it('p = the validated domain name of <ip>', function(){
        let email = 'test@e7.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"example.com.d.spf.example.com":[{"SPF":"v=spf1 redirect=a.spf.example.com"}],"a.spf.example.com":[{"SPF":"v=spf1 include:o.spf.example.com. ~all"}],"o.spf.example.com":[{"SPF":"v=spf1 ip4:192.168.218.40"}],"msgbas2x.cos.example.com":[{"A":"192.168.218.40"}],"example.com":[{"A":"192.168.90.76"},{"SPF":"v=spf1 redirect=%{d}.d.spf.example.com."}],"exp.example.com":[{"SPF":"v=spf1 exp=msg.example.com. -all"}],"msg.example.com":[{"TXT":"This is a test."}],"e1.example.com":[{"SPF":"v=spf1 -exists:%(ir).sbl.example.com ?all"}],"e1e.example.com":[{"SPF":"v=spf1 exists:foo%(ir).sbl.example.com ?all"}],"e1t.example.com":[{"SPF":"v=spf1 exists:foo%.sbl.example.com ?all"}],"e1a.example.com":[{"SPF":"v=spf1 a:macro%%percent%_%_space%-url-space.example.com -all"}],"macro%percent  space%20url-space.example.com":[{"A":"1.2.3.4"}],"e2.example.com":[{"SPF":"v=spf1 -all exp=%{r}.example.com"}],"e3.example.com":[{"SPF":"v=spf1 -all exp=%{ir}.example.com"}],"40.218.168.192.example.com":[{"TXT":"Connections from %{c} not authorized."}],"somewhat.long.exp.example.com":[{"SPF":"v=spf1 -all exp=foobar.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.example.com"}],"somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.example.com":[{"TXT":"Congratulations!  That was tricky."}],"e4.example.com":[{"SPF":"v=spf1 -all exp=e4msg.example.com"}],"e4msg.example.com":[{"TXT":"%{c} is queried as %{ir}.%{v}.arpa"}],"e5.example.com":[{"SPF":"v=spf1 a:%{a}.example.com -all"}],"e6.example.com":[{"SPF":"v=spf1 -all exp=e6msg.example.com"}],"e6msg.example.com":[{"TXT":"connect from %{p}"}],"mx.example.com":[{"A":"192.168.218.41"},{"A":"192.168.218.42"},{"AAAA":"CAFE:BABE::2"},{"AAAA":"CAFE:BABE::3"}],"40.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"}],"41.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"}],"42.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"},{"PTR":"mx.e7.example.com"}],"1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.E.B.A.B.E.F.A.C.ip6.arpa":[{"PTR":"mx.example.com"}],"3.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.E.B.A.B.E.F.A.C.ip6.arpa":[{"PTR":"mx.example.com"}],"mx.e7.example.com":[{"A":"192.168.218.42"}],"mx.e7.example.com.should.example.com":[{"A":"127.0.0.2"}],"mx.example.com.ok.example.com":[{"A":"127.0.0.2"}],"e7.example.com":[{"SPF":"v=spf1 exists:%{p}.should.example.com ~exists:%{p}.ok.example.com"}],"e8.example.com":[{"SPF":"v=spf1 -all exp=msg8.%{D2}"}],"msg8.example.com":[{"TXT":"http://example.com/why.html?l=%{L}"}],"e9.example.com":[{"SPF":"v=spf1 a:%{H} -all"}],"e10.example.com":[{"SPF":"v=spf1 -include:_spfh.%{d2} ip4:1.2.3.0/24 -all"}],"_spfh.example.com":[{"SPF":"v=spf1 -a:%{h} +all"}],"e11.example.com":[{"SPF":"v=spf1 exists:%{i}.%{l2r-}.user.%{d2}"}],"1.2.3.4.gladstone.philip.user.example.com":[{"A":"127.0.0.2"}],"e12.example.com":[{"SPF":"v=spf1 exists:%{l2r+-}.user.%{d2}"}],"bar.foo.user.example.com":[{"A":"127.0.0.2"}]}, failOnNoFake: true});
        let promise = validator.validateSender('192.168.218.42');
        return promise.then((result) => {
          assert.include(["pass","softfail"], result.toLowerCase());
        });
      });
      it('Uppercased macros expand exactly as their lowercased equivalents, and are then URL escaped.  All chars not in the unreserved set MUST be escaped.', function(){
        let email = '~jack&jill=up-a_b3.c@e8.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"example.com.d.spf.example.com":[{"SPF":"v=spf1 redirect=a.spf.example.com"}],"a.spf.example.com":[{"SPF":"v=spf1 include:o.spf.example.com. ~all"}],"o.spf.example.com":[{"SPF":"v=spf1 ip4:192.168.218.40"}],"msgbas2x.cos.example.com":[{"A":"192.168.218.40"}],"example.com":[{"A":"192.168.90.76"},{"SPF":"v=spf1 redirect=%{d}.d.spf.example.com."}],"exp.example.com":[{"SPF":"v=spf1 exp=msg.example.com. -all"}],"msg.example.com":[{"TXT":"This is a test."}],"e1.example.com":[{"SPF":"v=spf1 -exists:%(ir).sbl.example.com ?all"}],"e1e.example.com":[{"SPF":"v=spf1 exists:foo%(ir).sbl.example.com ?all"}],"e1t.example.com":[{"SPF":"v=spf1 exists:foo%.sbl.example.com ?all"}],"e1a.example.com":[{"SPF":"v=spf1 a:macro%%percent%_%_space%-url-space.example.com -all"}],"macro%percent  space%20url-space.example.com":[{"A":"1.2.3.4"}],"e2.example.com":[{"SPF":"v=spf1 -all exp=%{r}.example.com"}],"e3.example.com":[{"SPF":"v=spf1 -all exp=%{ir}.example.com"}],"40.218.168.192.example.com":[{"TXT":"Connections from %{c} not authorized."}],"somewhat.long.exp.example.com":[{"SPF":"v=spf1 -all exp=foobar.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.example.com"}],"somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.example.com":[{"TXT":"Congratulations!  That was tricky."}],"e4.example.com":[{"SPF":"v=spf1 -all exp=e4msg.example.com"}],"e4msg.example.com":[{"TXT":"%{c} is queried as %{ir}.%{v}.arpa"}],"e5.example.com":[{"SPF":"v=spf1 a:%{a}.example.com -all"}],"e6.example.com":[{"SPF":"v=spf1 -all exp=e6msg.example.com"}],"e6msg.example.com":[{"TXT":"connect from %{p}"}],"mx.example.com":[{"A":"192.168.218.41"},{"A":"192.168.218.42"},{"AAAA":"CAFE:BABE::2"},{"AAAA":"CAFE:BABE::3"}],"40.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"}],"41.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"}],"42.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"},{"PTR":"mx.e7.example.com"}],"1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.E.B.A.B.E.F.A.C.ip6.arpa":[{"PTR":"mx.example.com"}],"3.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.E.B.A.B.E.F.A.C.ip6.arpa":[{"PTR":"mx.example.com"}],"mx.e7.example.com":[{"A":"192.168.218.42"}],"mx.e7.example.com.should.example.com":[{"A":"127.0.0.2"}],"mx.example.com.ok.example.com":[{"A":"127.0.0.2"}],"e7.example.com":[{"SPF":"v=spf1 exists:%{p}.should.example.com ~exists:%{p}.ok.example.com"}],"e8.example.com":[{"SPF":"v=spf1 -all exp=msg8.%{D2}"}],"msg8.example.com":[{"TXT":"http://example.com/why.html?l=%{L}"}],"e9.example.com":[{"SPF":"v=spf1 a:%{H} -all"}],"e10.example.com":[{"SPF":"v=spf1 -include:_spfh.%{d2} ip4:1.2.3.0/24 -all"}],"_spfh.example.com":[{"SPF":"v=spf1 -a:%{h} +all"}],"e11.example.com":[{"SPF":"v=spf1 exists:%{i}.%{l2r-}.user.%{d2}"}],"1.2.3.4.gladstone.philip.user.example.com":[{"A":"127.0.0.2"}],"e12.example.com":[{"SPF":"v=spf1 exists:%{l2r+-}.user.%{d2}"}],"bar.foo.user.example.com":[{"A":"127.0.0.2"}]}, failOnNoFake: true});
        let promise = validator.validateSender('192.168.218.42');
        return promise.then((result) => {
          assert.equal(result, 'FAIL');
        });
      });
      it('h = HELO/EHLO domain', function(){
        let email = 'test@e9.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"example.com.d.spf.example.com":[{"SPF":"v=spf1 redirect=a.spf.example.com"}],"a.spf.example.com":[{"SPF":"v=spf1 include:o.spf.example.com. ~all"}],"o.spf.example.com":[{"SPF":"v=spf1 ip4:192.168.218.40"}],"msgbas2x.cos.example.com":[{"A":"192.168.218.40"}],"example.com":[{"A":"192.168.90.76"},{"SPF":"v=spf1 redirect=%{d}.d.spf.example.com."}],"exp.example.com":[{"SPF":"v=spf1 exp=msg.example.com. -all"}],"msg.example.com":[{"TXT":"This is a test."}],"e1.example.com":[{"SPF":"v=spf1 -exists:%(ir).sbl.example.com ?all"}],"e1e.example.com":[{"SPF":"v=spf1 exists:foo%(ir).sbl.example.com ?all"}],"e1t.example.com":[{"SPF":"v=spf1 exists:foo%.sbl.example.com ?all"}],"e1a.example.com":[{"SPF":"v=spf1 a:macro%%percent%_%_space%-url-space.example.com -all"}],"macro%percent  space%20url-space.example.com":[{"A":"1.2.3.4"}],"e2.example.com":[{"SPF":"v=spf1 -all exp=%{r}.example.com"}],"e3.example.com":[{"SPF":"v=spf1 -all exp=%{ir}.example.com"}],"40.218.168.192.example.com":[{"TXT":"Connections from %{c} not authorized."}],"somewhat.long.exp.example.com":[{"SPF":"v=spf1 -all exp=foobar.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.example.com"}],"somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.example.com":[{"TXT":"Congratulations!  That was tricky."}],"e4.example.com":[{"SPF":"v=spf1 -all exp=e4msg.example.com"}],"e4msg.example.com":[{"TXT":"%{c} is queried as %{ir}.%{v}.arpa"}],"e5.example.com":[{"SPF":"v=spf1 a:%{a}.example.com -all"}],"e6.example.com":[{"SPF":"v=spf1 -all exp=e6msg.example.com"}],"e6msg.example.com":[{"TXT":"connect from %{p}"}],"mx.example.com":[{"A":"192.168.218.41"},{"A":"192.168.218.42"},{"AAAA":"CAFE:BABE::2"},{"AAAA":"CAFE:BABE::3"}],"40.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"}],"41.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"}],"42.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"},{"PTR":"mx.e7.example.com"}],"1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.E.B.A.B.E.F.A.C.ip6.arpa":[{"PTR":"mx.example.com"}],"3.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.E.B.A.B.E.F.A.C.ip6.arpa":[{"PTR":"mx.example.com"}],"mx.e7.example.com":[{"A":"192.168.218.42"}],"mx.e7.example.com.should.example.com":[{"A":"127.0.0.2"}],"mx.example.com.ok.example.com":[{"A":"127.0.0.2"}],"e7.example.com":[{"SPF":"v=spf1 exists:%{p}.should.example.com ~exists:%{p}.ok.example.com"}],"e8.example.com":[{"SPF":"v=spf1 -all exp=msg8.%{D2}"}],"msg8.example.com":[{"TXT":"http://example.com/why.html?l=%{L}"}],"e9.example.com":[{"SPF":"v=spf1 a:%{H} -all"}],"e10.example.com":[{"SPF":"v=spf1 -include:_spfh.%{d2} ip4:1.2.3.0/24 -all"}],"_spfh.example.com":[{"SPF":"v=spf1 -a:%{h} +all"}],"e11.example.com":[{"SPF":"v=spf1 exists:%{i}.%{l2r-}.user.%{d2}"}],"1.2.3.4.gladstone.philip.user.example.com":[{"A":"127.0.0.2"}],"e12.example.com":[{"SPF":"v=spf1 exists:%{l2r+-}.user.%{d2}"}],"bar.foo.user.example.com":[{"A":"127.0.0.2"}]}, failOnNoFake: true});
        let promise = validator.validateSender('192.168.218.40');
        return promise.then((result) => {
          assert.equal(result, 'PASS');
        });
      });
      it('h = HELO/EHLO domain, but HELO is invalid', function(){
        let email = 'test@e9.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"example.com.d.spf.example.com":[{"SPF":"v=spf1 redirect=a.spf.example.com"}],"a.spf.example.com":[{"SPF":"v=spf1 include:o.spf.example.com. ~all"}],"o.spf.example.com":[{"SPF":"v=spf1 ip4:192.168.218.40"}],"msgbas2x.cos.example.com":[{"A":"192.168.218.40"}],"example.com":[{"A":"192.168.90.76"},{"SPF":"v=spf1 redirect=%{d}.d.spf.example.com."}],"exp.example.com":[{"SPF":"v=spf1 exp=msg.example.com. -all"}],"msg.example.com":[{"TXT":"This is a test."}],"e1.example.com":[{"SPF":"v=spf1 -exists:%(ir).sbl.example.com ?all"}],"e1e.example.com":[{"SPF":"v=spf1 exists:foo%(ir).sbl.example.com ?all"}],"e1t.example.com":[{"SPF":"v=spf1 exists:foo%.sbl.example.com ?all"}],"e1a.example.com":[{"SPF":"v=spf1 a:macro%%percent%_%_space%-url-space.example.com -all"}],"macro%percent  space%20url-space.example.com":[{"A":"1.2.3.4"}],"e2.example.com":[{"SPF":"v=spf1 -all exp=%{r}.example.com"}],"e3.example.com":[{"SPF":"v=spf1 -all exp=%{ir}.example.com"}],"40.218.168.192.example.com":[{"TXT":"Connections from %{c} not authorized."}],"somewhat.long.exp.example.com":[{"SPF":"v=spf1 -all exp=foobar.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.example.com"}],"somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.example.com":[{"TXT":"Congratulations!  That was tricky."}],"e4.example.com":[{"SPF":"v=spf1 -all exp=e4msg.example.com"}],"e4msg.example.com":[{"TXT":"%{c} is queried as %{ir}.%{v}.arpa"}],"e5.example.com":[{"SPF":"v=spf1 a:%{a}.example.com -all"}],"e6.example.com":[{"SPF":"v=spf1 -all exp=e6msg.example.com"}],"e6msg.example.com":[{"TXT":"connect from %{p}"}],"mx.example.com":[{"A":"192.168.218.41"},{"A":"192.168.218.42"},{"AAAA":"CAFE:BABE::2"},{"AAAA":"CAFE:BABE::3"}],"40.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"}],"41.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"}],"42.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"},{"PTR":"mx.e7.example.com"}],"1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.E.B.A.B.E.F.A.C.ip6.arpa":[{"PTR":"mx.example.com"}],"3.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.E.B.A.B.E.F.A.C.ip6.arpa":[{"PTR":"mx.example.com"}],"mx.e7.example.com":[{"A":"192.168.218.42"}],"mx.e7.example.com.should.example.com":[{"A":"127.0.0.2"}],"mx.example.com.ok.example.com":[{"A":"127.0.0.2"}],"e7.example.com":[{"SPF":"v=spf1 exists:%{p}.should.example.com ~exists:%{p}.ok.example.com"}],"e8.example.com":[{"SPF":"v=spf1 -all exp=msg8.%{D2}"}],"msg8.example.com":[{"TXT":"http://example.com/why.html?l=%{L}"}],"e9.example.com":[{"SPF":"v=spf1 a:%{H} -all"}],"e10.example.com":[{"SPF":"v=spf1 -include:_spfh.%{d2} ip4:1.2.3.0/24 -all"}],"_spfh.example.com":[{"SPF":"v=spf1 -a:%{h} +all"}],"e11.example.com":[{"SPF":"v=spf1 exists:%{i}.%{l2r-}.user.%{d2}"}],"1.2.3.4.gladstone.philip.user.example.com":[{"A":"127.0.0.2"}],"e12.example.com":[{"SPF":"v=spf1 exists:%{l2r+-}.user.%{d2}"}],"bar.foo.user.example.com":[{"A":"127.0.0.2"}]}, failOnNoFake: true});
        let promise = validator.validateSender('192.168.218.40');
        return promise.then((result) => {
          assert.equal(result, 'FAIL');
        });
      });
      it('h = HELO/EHLO domain, but HELO is a domain literal', function(){
        let email = 'test@e9.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"example.com.d.spf.example.com":[{"SPF":"v=spf1 redirect=a.spf.example.com"}],"a.spf.example.com":[{"SPF":"v=spf1 include:o.spf.example.com. ~all"}],"o.spf.example.com":[{"SPF":"v=spf1 ip4:192.168.218.40"}],"msgbas2x.cos.example.com":[{"A":"192.168.218.40"}],"example.com":[{"A":"192.168.90.76"},{"SPF":"v=spf1 redirect=%{d}.d.spf.example.com."}],"exp.example.com":[{"SPF":"v=spf1 exp=msg.example.com. -all"}],"msg.example.com":[{"TXT":"This is a test."}],"e1.example.com":[{"SPF":"v=spf1 -exists:%(ir).sbl.example.com ?all"}],"e1e.example.com":[{"SPF":"v=spf1 exists:foo%(ir).sbl.example.com ?all"}],"e1t.example.com":[{"SPF":"v=spf1 exists:foo%.sbl.example.com ?all"}],"e1a.example.com":[{"SPF":"v=spf1 a:macro%%percent%_%_space%-url-space.example.com -all"}],"macro%percent  space%20url-space.example.com":[{"A":"1.2.3.4"}],"e2.example.com":[{"SPF":"v=spf1 -all exp=%{r}.example.com"}],"e3.example.com":[{"SPF":"v=spf1 -all exp=%{ir}.example.com"}],"40.218.168.192.example.com":[{"TXT":"Connections from %{c} not authorized."}],"somewhat.long.exp.example.com":[{"SPF":"v=spf1 -all exp=foobar.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.example.com"}],"somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.example.com":[{"TXT":"Congratulations!  That was tricky."}],"e4.example.com":[{"SPF":"v=spf1 -all exp=e4msg.example.com"}],"e4msg.example.com":[{"TXT":"%{c} is queried as %{ir}.%{v}.arpa"}],"e5.example.com":[{"SPF":"v=spf1 a:%{a}.example.com -all"}],"e6.example.com":[{"SPF":"v=spf1 -all exp=e6msg.example.com"}],"e6msg.example.com":[{"TXT":"connect from %{p}"}],"mx.example.com":[{"A":"192.168.218.41"},{"A":"192.168.218.42"},{"AAAA":"CAFE:BABE::2"},{"AAAA":"CAFE:BABE::3"}],"40.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"}],"41.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"}],"42.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"},{"PTR":"mx.e7.example.com"}],"1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.E.B.A.B.E.F.A.C.ip6.arpa":[{"PTR":"mx.example.com"}],"3.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.E.B.A.B.E.F.A.C.ip6.arpa":[{"PTR":"mx.example.com"}],"mx.e7.example.com":[{"A":"192.168.218.42"}],"mx.e7.example.com.should.example.com":[{"A":"127.0.0.2"}],"mx.example.com.ok.example.com":[{"A":"127.0.0.2"}],"e7.example.com":[{"SPF":"v=spf1 exists:%{p}.should.example.com ~exists:%{p}.ok.example.com"}],"e8.example.com":[{"SPF":"v=spf1 -all exp=msg8.%{D2}"}],"msg8.example.com":[{"TXT":"http://example.com/why.html?l=%{L}"}],"e9.example.com":[{"SPF":"v=spf1 a:%{H} -all"}],"e10.example.com":[{"SPF":"v=spf1 -include:_spfh.%{d2} ip4:1.2.3.0/24 -all"}],"_spfh.example.com":[{"SPF":"v=spf1 -a:%{h} +all"}],"e11.example.com":[{"SPF":"v=spf1 exists:%{i}.%{l2r-}.user.%{d2}"}],"1.2.3.4.gladstone.philip.user.example.com":[{"A":"127.0.0.2"}],"e12.example.com":[{"SPF":"v=spf1 exists:%{l2r+-}.user.%{d2}"}],"bar.foo.user.example.com":[{"A":"127.0.0.2"}]}, failOnNoFake: true});
        let promise = validator.validateSender('192.168.218.40');
        return promise.then((result) => {
          assert.equal(result, 'FAIL');
        });
      });
      it('Example of requiring valid helo in sender policy.  This is a complex policy testing several points at once.', function(){
        let email = 'test@e10.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"example.com.d.spf.example.com":[{"SPF":"v=spf1 redirect=a.spf.example.com"}],"a.spf.example.com":[{"SPF":"v=spf1 include:o.spf.example.com. ~all"}],"o.spf.example.com":[{"SPF":"v=spf1 ip4:192.168.218.40"}],"msgbas2x.cos.example.com":[{"A":"192.168.218.40"}],"example.com":[{"A":"192.168.90.76"},{"SPF":"v=spf1 redirect=%{d}.d.spf.example.com."}],"exp.example.com":[{"SPF":"v=spf1 exp=msg.example.com. -all"}],"msg.example.com":[{"TXT":"This is a test."}],"e1.example.com":[{"SPF":"v=spf1 -exists:%(ir).sbl.example.com ?all"}],"e1e.example.com":[{"SPF":"v=spf1 exists:foo%(ir).sbl.example.com ?all"}],"e1t.example.com":[{"SPF":"v=spf1 exists:foo%.sbl.example.com ?all"}],"e1a.example.com":[{"SPF":"v=spf1 a:macro%%percent%_%_space%-url-space.example.com -all"}],"macro%percent  space%20url-space.example.com":[{"A":"1.2.3.4"}],"e2.example.com":[{"SPF":"v=spf1 -all exp=%{r}.example.com"}],"e3.example.com":[{"SPF":"v=spf1 -all exp=%{ir}.example.com"}],"40.218.168.192.example.com":[{"TXT":"Connections from %{c} not authorized."}],"somewhat.long.exp.example.com":[{"SPF":"v=spf1 -all exp=foobar.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.example.com"}],"somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.example.com":[{"TXT":"Congratulations!  That was tricky."}],"e4.example.com":[{"SPF":"v=spf1 -all exp=e4msg.example.com"}],"e4msg.example.com":[{"TXT":"%{c} is queried as %{ir}.%{v}.arpa"}],"e5.example.com":[{"SPF":"v=spf1 a:%{a}.example.com -all"}],"e6.example.com":[{"SPF":"v=spf1 -all exp=e6msg.example.com"}],"e6msg.example.com":[{"TXT":"connect from %{p}"}],"mx.example.com":[{"A":"192.168.218.41"},{"A":"192.168.218.42"},{"AAAA":"CAFE:BABE::2"},{"AAAA":"CAFE:BABE::3"}],"40.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"}],"41.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"}],"42.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"},{"PTR":"mx.e7.example.com"}],"1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.E.B.A.B.E.F.A.C.ip6.arpa":[{"PTR":"mx.example.com"}],"3.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.E.B.A.B.E.F.A.C.ip6.arpa":[{"PTR":"mx.example.com"}],"mx.e7.example.com":[{"A":"192.168.218.42"}],"mx.e7.example.com.should.example.com":[{"A":"127.0.0.2"}],"mx.example.com.ok.example.com":[{"A":"127.0.0.2"}],"e7.example.com":[{"SPF":"v=spf1 exists:%{p}.should.example.com ~exists:%{p}.ok.example.com"}],"e8.example.com":[{"SPF":"v=spf1 -all exp=msg8.%{D2}"}],"msg8.example.com":[{"TXT":"http://example.com/why.html?l=%{L}"}],"e9.example.com":[{"SPF":"v=spf1 a:%{H} -all"}],"e10.example.com":[{"SPF":"v=spf1 -include:_spfh.%{d2} ip4:1.2.3.0/24 -all"}],"_spfh.example.com":[{"SPF":"v=spf1 -a:%{h} +all"}],"e11.example.com":[{"SPF":"v=spf1 exists:%{i}.%{l2r-}.user.%{d2}"}],"1.2.3.4.gladstone.philip.user.example.com":[{"A":"127.0.0.2"}],"e12.example.com":[{"SPF":"v=spf1 exists:%{l2r+-}.user.%{d2}"}],"bar.foo.user.example.com":[{"A":"127.0.0.2"}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.4');
        return promise.then((result) => {
          assert.equal(result, 'FAIL');
        });
      });
      it('Macro value transformation (splitting on arbitrary characters, reversal, number of right-hand parts to use)', function(){
        let email = 'philip-gladstone-test@e11.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"example.com.d.spf.example.com":[{"SPF":"v=spf1 redirect=a.spf.example.com"}],"a.spf.example.com":[{"SPF":"v=spf1 include:o.spf.example.com. ~all"}],"o.spf.example.com":[{"SPF":"v=spf1 ip4:192.168.218.40"}],"msgbas2x.cos.example.com":[{"A":"192.168.218.40"}],"example.com":[{"A":"192.168.90.76"},{"SPF":"v=spf1 redirect=%{d}.d.spf.example.com."}],"exp.example.com":[{"SPF":"v=spf1 exp=msg.example.com. -all"}],"msg.example.com":[{"TXT":"This is a test."}],"e1.example.com":[{"SPF":"v=spf1 -exists:%(ir).sbl.example.com ?all"}],"e1e.example.com":[{"SPF":"v=spf1 exists:foo%(ir).sbl.example.com ?all"}],"e1t.example.com":[{"SPF":"v=spf1 exists:foo%.sbl.example.com ?all"}],"e1a.example.com":[{"SPF":"v=spf1 a:macro%%percent%_%_space%-url-space.example.com -all"}],"macro%percent  space%20url-space.example.com":[{"A":"1.2.3.4"}],"e2.example.com":[{"SPF":"v=spf1 -all exp=%{r}.example.com"}],"e3.example.com":[{"SPF":"v=spf1 -all exp=%{ir}.example.com"}],"40.218.168.192.example.com":[{"TXT":"Connections from %{c} not authorized."}],"somewhat.long.exp.example.com":[{"SPF":"v=spf1 -all exp=foobar.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.example.com"}],"somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.example.com":[{"TXT":"Congratulations!  That was tricky."}],"e4.example.com":[{"SPF":"v=spf1 -all exp=e4msg.example.com"}],"e4msg.example.com":[{"TXT":"%{c} is queried as %{ir}.%{v}.arpa"}],"e5.example.com":[{"SPF":"v=spf1 a:%{a}.example.com -all"}],"e6.example.com":[{"SPF":"v=spf1 -all exp=e6msg.example.com"}],"e6msg.example.com":[{"TXT":"connect from %{p}"}],"mx.example.com":[{"A":"192.168.218.41"},{"A":"192.168.218.42"},{"AAAA":"CAFE:BABE::2"},{"AAAA":"CAFE:BABE::3"}],"40.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"}],"41.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"}],"42.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"},{"PTR":"mx.e7.example.com"}],"1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.E.B.A.B.E.F.A.C.ip6.arpa":[{"PTR":"mx.example.com"}],"3.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.E.B.A.B.E.F.A.C.ip6.arpa":[{"PTR":"mx.example.com"}],"mx.e7.example.com":[{"A":"192.168.218.42"}],"mx.e7.example.com.should.example.com":[{"A":"127.0.0.2"}],"mx.example.com.ok.example.com":[{"A":"127.0.0.2"}],"e7.example.com":[{"SPF":"v=spf1 exists:%{p}.should.example.com ~exists:%{p}.ok.example.com"}],"e8.example.com":[{"SPF":"v=spf1 -all exp=msg8.%{D2}"}],"msg8.example.com":[{"TXT":"http://example.com/why.html?l=%{L}"}],"e9.example.com":[{"SPF":"v=spf1 a:%{H} -all"}],"e10.example.com":[{"SPF":"v=spf1 -include:_spfh.%{d2} ip4:1.2.3.0/24 -all"}],"_spfh.example.com":[{"SPF":"v=spf1 -a:%{h} +all"}],"e11.example.com":[{"SPF":"v=spf1 exists:%{i}.%{l2r-}.user.%{d2}"}],"1.2.3.4.gladstone.philip.user.example.com":[{"A":"127.0.0.2"}],"e12.example.com":[{"SPF":"v=spf1 exists:%{l2r+-}.user.%{d2}"}],"bar.foo.user.example.com":[{"A":"127.0.0.2"}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.4');
        return promise.then((result) => {
          assert.equal(result, 'PASS');
        });
      });
      it('Multiple delimiters may be specified in a macro expression.   macro-expand = ( "%{" macro-letter transformers *delimiter "}" )                  / "%%" / "%_" / "%-"', function(){
        let email = 'foo-bar+zip+quux@e12.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"example.com.d.spf.example.com":[{"SPF":"v=spf1 redirect=a.spf.example.com"}],"a.spf.example.com":[{"SPF":"v=spf1 include:o.spf.example.com. ~all"}],"o.spf.example.com":[{"SPF":"v=spf1 ip4:192.168.218.40"}],"msgbas2x.cos.example.com":[{"A":"192.168.218.40"}],"example.com":[{"A":"192.168.90.76"},{"SPF":"v=spf1 redirect=%{d}.d.spf.example.com."}],"exp.example.com":[{"SPF":"v=spf1 exp=msg.example.com. -all"}],"msg.example.com":[{"TXT":"This is a test."}],"e1.example.com":[{"SPF":"v=spf1 -exists:%(ir).sbl.example.com ?all"}],"e1e.example.com":[{"SPF":"v=spf1 exists:foo%(ir).sbl.example.com ?all"}],"e1t.example.com":[{"SPF":"v=spf1 exists:foo%.sbl.example.com ?all"}],"e1a.example.com":[{"SPF":"v=spf1 a:macro%%percent%_%_space%-url-space.example.com -all"}],"macro%percent  space%20url-space.example.com":[{"A":"1.2.3.4"}],"e2.example.com":[{"SPF":"v=spf1 -all exp=%{r}.example.com"}],"e3.example.com":[{"SPF":"v=spf1 -all exp=%{ir}.example.com"}],"40.218.168.192.example.com":[{"TXT":"Connections from %{c} not authorized."}],"somewhat.long.exp.example.com":[{"SPF":"v=spf1 -all exp=foobar.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.example.com"}],"somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.example.com":[{"TXT":"Congratulations!  That was tricky."}],"e4.example.com":[{"SPF":"v=spf1 -all exp=e4msg.example.com"}],"e4msg.example.com":[{"TXT":"%{c} is queried as %{ir}.%{v}.arpa"}],"e5.example.com":[{"SPF":"v=spf1 a:%{a}.example.com -all"}],"e6.example.com":[{"SPF":"v=spf1 -all exp=e6msg.example.com"}],"e6msg.example.com":[{"TXT":"connect from %{p}"}],"mx.example.com":[{"A":"192.168.218.41"},{"A":"192.168.218.42"},{"AAAA":"CAFE:BABE::2"},{"AAAA":"CAFE:BABE::3"}],"40.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"}],"41.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"}],"42.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"},{"PTR":"mx.e7.example.com"}],"1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.E.B.A.B.E.F.A.C.ip6.arpa":[{"PTR":"mx.example.com"}],"3.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.E.B.A.B.E.F.A.C.ip6.arpa":[{"PTR":"mx.example.com"}],"mx.e7.example.com":[{"A":"192.168.218.42"}],"mx.e7.example.com.should.example.com":[{"A":"127.0.0.2"}],"mx.example.com.ok.example.com":[{"A":"127.0.0.2"}],"e7.example.com":[{"SPF":"v=spf1 exists:%{p}.should.example.com ~exists:%{p}.ok.example.com"}],"e8.example.com":[{"SPF":"v=spf1 -all exp=msg8.%{D2}"}],"msg8.example.com":[{"TXT":"http://example.com/why.html?l=%{L}"}],"e9.example.com":[{"SPF":"v=spf1 a:%{H} -all"}],"e10.example.com":[{"SPF":"v=spf1 -include:_spfh.%{d2} ip4:1.2.3.0/24 -all"}],"_spfh.example.com":[{"SPF":"v=spf1 -a:%{h} +all"}],"e11.example.com":[{"SPF":"v=spf1 exists:%{i}.%{l2r-}.user.%{d2}"}],"1.2.3.4.gladstone.philip.user.example.com":[{"A":"127.0.0.2"}],"e12.example.com":[{"SPF":"v=spf1 exists:%{l2r+-}.user.%{d2}"}],"bar.foo.user.example.com":[{"A":"127.0.0.2"}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.4');
        return promise.then((result) => {
          assert.equal(result, 'PASS');
        });
      });
    });
    describe('Processing limits', function(){
      it('SPF implementations MUST limit the number of mechanisms and modifiers that do DNS lookups to at most 10 per SPF check.', function(){
        let email = 'foo@e1.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 ip4:1.1.1.1 redirect=e1.example.com"},{"A":"1.2.3.6"}],"e2.example.com":[{"SPF":"v=spf1 include:e3.example.com"},{"A":"1.2.3.7"}],"e3.example.com":[{"SPF":"v=spf1 include:e2.example.com"},{"A":"1.2.3.8"}],"e4.example.com":[{"SPF":"v=spf1 mx"},{"MX":[0,"mail.example.com"]},{"MX":[1,"mail.example.com"]},{"MX":[2,"mail.example.com"]},{"MX":[3,"mail.example.com"]},{"MX":[4,"mail.example.com"]},{"MX":[5,"mail.example.com"]},{"MX":[6,"mail.example.com"]},{"MX":[7,"mail.example.com"]},{"MX":[8,"mail.example.com"]},{"MX":[9,"mail.example.com"]},{"MX":[10,"e4.example.com"]},{"A":"1.2.3.5"}],"e5.example.com":[{"SPF":"v=spf1 ptr"},{"A":"1.2.3.5"}],"5.3.2.1.in-addr.arpa":[{"PTR":"e1.example.com."},{"PTR":"e2.example.com."},{"PTR":"e3.example.com."},{"PTR":"e4.example.com."},{"PTR":"example.com."},{"PTR":"e6.example.com."},{"PTR":"e7.example.com."},{"PTR":"e8.example.com."},{"PTR":"e9.example.com."},{"PTR":"e10.example.com."},{"PTR":"e5.example.com."}],"e6.example.com":[{"SPF":"v=spf1 a mx a mx a mx a mx a ptr ip4:1.2.3.4 -all"},{"A":"1.2.3.8"},{"MX":[10,"e6.example.com"]}],"e7.example.com":[{"SPF":"v=spf1 a mx a mx a mx a mx a ptr a ip4:1.2.3.4 -all"},{"A":"1.2.3.20"}],"e8.example.com":[{"SPF":"v=spf1 a include:inc.example.com ip4:1.2.3.4 mx -all"},{"A":"1.2.3.4"}],"inc.example.com":[{"SPF":"v=spf1 a a a a a a a a"},{"A":"1.2.3.10"}],"e9.example.com":[{"SPF":"v=spf1 a include:inc.example.com a ip4:1.2.3.4 -all"},{"A":"1.2.3.21"}],"e10.example.com":[{"SPF":"v=spf1 a -all"},{"A":"1.2.3.1"},{"A":"1.2.3.2"},{"A":"1.2.3.3"},{"A":"1.2.3.4"},{"A":"1.2.3.5"},{"A":"1.2.3.6"},{"A":"1.2.3.7"},{"A":"1.2.3.8"},{"A":"1.2.3.9"},{"A":"1.2.3.10"},{"A":"1.2.3.11"},{"A":"1.2.3.12"}],"e11.example.com":[{"TXT":"v=spf1 a:err.example.com a:err1.example.com a:err2.example.com ?all"}],"e12.example.com":[{"TXT":"v=spf1 a:err.example.com a:err1.example.com ?all"}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.4');
        return promise.then((result) => {
          assert.equal(result, 'PERMERROR');
        });
      });
      it('SPF implementations MUST limit the number of mechanisms and modifiers that do DNS lookups to at most 10 per SPF check.', function(){
        let email = 'foo@e2.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 ip4:1.1.1.1 redirect=e1.example.com"},{"A":"1.2.3.6"}],"e2.example.com":[{"SPF":"v=spf1 include:e3.example.com"},{"A":"1.2.3.7"}],"e3.example.com":[{"SPF":"v=spf1 include:e2.example.com"},{"A":"1.2.3.8"}],"e4.example.com":[{"SPF":"v=spf1 mx"},{"MX":[0,"mail.example.com"]},{"MX":[1,"mail.example.com"]},{"MX":[2,"mail.example.com"]},{"MX":[3,"mail.example.com"]},{"MX":[4,"mail.example.com"]},{"MX":[5,"mail.example.com"]},{"MX":[6,"mail.example.com"]},{"MX":[7,"mail.example.com"]},{"MX":[8,"mail.example.com"]},{"MX":[9,"mail.example.com"]},{"MX":[10,"e4.example.com"]},{"A":"1.2.3.5"}],"e5.example.com":[{"SPF":"v=spf1 ptr"},{"A":"1.2.3.5"}],"5.3.2.1.in-addr.arpa":[{"PTR":"e1.example.com."},{"PTR":"e2.example.com."},{"PTR":"e3.example.com."},{"PTR":"e4.example.com."},{"PTR":"example.com."},{"PTR":"e6.example.com."},{"PTR":"e7.example.com."},{"PTR":"e8.example.com."},{"PTR":"e9.example.com."},{"PTR":"e10.example.com."},{"PTR":"e5.example.com."}],"e6.example.com":[{"SPF":"v=spf1 a mx a mx a mx a mx a ptr ip4:1.2.3.4 -all"},{"A":"1.2.3.8"},{"MX":[10,"e6.example.com"]}],"e7.example.com":[{"SPF":"v=spf1 a mx a mx a mx a mx a ptr a ip4:1.2.3.4 -all"},{"A":"1.2.3.20"}],"e8.example.com":[{"SPF":"v=spf1 a include:inc.example.com ip4:1.2.3.4 mx -all"},{"A":"1.2.3.4"}],"inc.example.com":[{"SPF":"v=spf1 a a a a a a a a"},{"A":"1.2.3.10"}],"e9.example.com":[{"SPF":"v=spf1 a include:inc.example.com a ip4:1.2.3.4 -all"},{"A":"1.2.3.21"}],"e10.example.com":[{"SPF":"v=spf1 a -all"},{"A":"1.2.3.1"},{"A":"1.2.3.2"},{"A":"1.2.3.3"},{"A":"1.2.3.4"},{"A":"1.2.3.5"},{"A":"1.2.3.6"},{"A":"1.2.3.7"},{"A":"1.2.3.8"},{"A":"1.2.3.9"},{"A":"1.2.3.10"},{"A":"1.2.3.11"},{"A":"1.2.3.12"}],"e11.example.com":[{"TXT":"v=spf1 a:err.example.com a:err1.example.com a:err2.example.com ?all"}],"e12.example.com":[{"TXT":"v=spf1 a:err.example.com a:err1.example.com ?all"}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.4');
        return promise.then((result) => {
          assert.equal(result, 'PERMERROR');
        });
      });
      it('there MUST be a limit of no more than 10 MX looked up and checked.', function(){
        let email = 'foo@e4.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 ip4:1.1.1.1 redirect=e1.example.com"},{"A":"1.2.3.6"}],"e2.example.com":[{"SPF":"v=spf1 include:e3.example.com"},{"A":"1.2.3.7"}],"e3.example.com":[{"SPF":"v=spf1 include:e2.example.com"},{"A":"1.2.3.8"}],"e4.example.com":[{"SPF":"v=spf1 mx"},{"MX":[0,"mail.example.com"]},{"MX":[1,"mail.example.com"]},{"MX":[2,"mail.example.com"]},{"MX":[3,"mail.example.com"]},{"MX":[4,"mail.example.com"]},{"MX":[5,"mail.example.com"]},{"MX":[6,"mail.example.com"]},{"MX":[7,"mail.example.com"]},{"MX":[8,"mail.example.com"]},{"MX":[9,"mail.example.com"]},{"MX":[10,"e4.example.com"]},{"A":"1.2.3.5"}],"e5.example.com":[{"SPF":"v=spf1 ptr"},{"A":"1.2.3.5"}],"5.3.2.1.in-addr.arpa":[{"PTR":"e1.example.com."},{"PTR":"e2.example.com."},{"PTR":"e3.example.com."},{"PTR":"e4.example.com."},{"PTR":"example.com."},{"PTR":"e6.example.com."},{"PTR":"e7.example.com."},{"PTR":"e8.example.com."},{"PTR":"e9.example.com."},{"PTR":"e10.example.com."},{"PTR":"e5.example.com."}],"e6.example.com":[{"SPF":"v=spf1 a mx a mx a mx a mx a ptr ip4:1.2.3.4 -all"},{"A":"1.2.3.8"},{"MX":[10,"e6.example.com"]}],"e7.example.com":[{"SPF":"v=spf1 a mx a mx a mx a mx a ptr a ip4:1.2.3.4 -all"},{"A":"1.2.3.20"}],"e8.example.com":[{"SPF":"v=spf1 a include:inc.example.com ip4:1.2.3.4 mx -all"},{"A":"1.2.3.4"}],"inc.example.com":[{"SPF":"v=spf1 a a a a a a a a"},{"A":"1.2.3.10"}],"e9.example.com":[{"SPF":"v=spf1 a include:inc.example.com a ip4:1.2.3.4 -all"},{"A":"1.2.3.21"}],"e10.example.com":[{"SPF":"v=spf1 a -all"},{"A":"1.2.3.1"},{"A":"1.2.3.2"},{"A":"1.2.3.3"},{"A":"1.2.3.4"},{"A":"1.2.3.5"},{"A":"1.2.3.6"},{"A":"1.2.3.7"},{"A":"1.2.3.8"},{"A":"1.2.3.9"},{"A":"1.2.3.10"},{"A":"1.2.3.11"},{"A":"1.2.3.12"}],"e11.example.com":[{"TXT":"v=spf1 a:err.example.com a:err1.example.com a:err2.example.com ?all"}],"e12.example.com":[{"TXT":"v=spf1 a:err.example.com a:err1.example.com ?all"}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.5');
        return promise.then((result) => {
          assert.equal(result, 'PERMERROR');
        });
      });
      it('there MUST be a limit of no more than 10 PTR looked up and checked.', function(){
        let email = 'foo@e5.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 ip4:1.1.1.1 redirect=e1.example.com"},{"A":"1.2.3.6"}],"e2.example.com":[{"SPF":"v=spf1 include:e3.example.com"},{"A":"1.2.3.7"}],"e3.example.com":[{"SPF":"v=spf1 include:e2.example.com"},{"A":"1.2.3.8"}],"e4.example.com":[{"SPF":"v=spf1 mx"},{"MX":[0,"mail.example.com"]},{"MX":[1,"mail.example.com"]},{"MX":[2,"mail.example.com"]},{"MX":[3,"mail.example.com"]},{"MX":[4,"mail.example.com"]},{"MX":[5,"mail.example.com"]},{"MX":[6,"mail.example.com"]},{"MX":[7,"mail.example.com"]},{"MX":[8,"mail.example.com"]},{"MX":[9,"mail.example.com"]},{"MX":[10,"e4.example.com"]},{"A":"1.2.3.5"}],"e5.example.com":[{"SPF":"v=spf1 ptr"},{"A":"1.2.3.5"}],"5.3.2.1.in-addr.arpa":[{"PTR":"e1.example.com."},{"PTR":"e2.example.com."},{"PTR":"e3.example.com."},{"PTR":"e4.example.com."},{"PTR":"example.com."},{"PTR":"e6.example.com."},{"PTR":"e7.example.com."},{"PTR":"e8.example.com."},{"PTR":"e9.example.com."},{"PTR":"e10.example.com."},{"PTR":"e5.example.com."}],"e6.example.com":[{"SPF":"v=spf1 a mx a mx a mx a mx a ptr ip4:1.2.3.4 -all"},{"A":"1.2.3.8"},{"MX":[10,"e6.example.com"]}],"e7.example.com":[{"SPF":"v=spf1 a mx a mx a mx a mx a ptr a ip4:1.2.3.4 -all"},{"A":"1.2.3.20"}],"e8.example.com":[{"SPF":"v=spf1 a include:inc.example.com ip4:1.2.3.4 mx -all"},{"A":"1.2.3.4"}],"inc.example.com":[{"SPF":"v=spf1 a a a a a a a a"},{"A":"1.2.3.10"}],"e9.example.com":[{"SPF":"v=spf1 a include:inc.example.com a ip4:1.2.3.4 -all"},{"A":"1.2.3.21"}],"e10.example.com":[{"SPF":"v=spf1 a -all"},{"A":"1.2.3.1"},{"A":"1.2.3.2"},{"A":"1.2.3.3"},{"A":"1.2.3.4"},{"A":"1.2.3.5"},{"A":"1.2.3.6"},{"A":"1.2.3.7"},{"A":"1.2.3.8"},{"A":"1.2.3.9"},{"A":"1.2.3.10"},{"A":"1.2.3.11"},{"A":"1.2.3.12"}],"e11.example.com":[{"TXT":"v=spf1 a:err.example.com a:err1.example.com a:err2.example.com ?all"}],"e12.example.com":[{"TXT":"v=spf1 a:err.example.com a:err1.example.com ?all"}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.5');
        return promise.then((result) => {
          assert.include(["neutral","pass"], result.toLowerCase());
        });
      });
      it('unlike MX, PTR, there is no RR limit for A', function(){
        let email = 'foo@e10.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 ip4:1.1.1.1 redirect=e1.example.com"},{"A":"1.2.3.6"}],"e2.example.com":[{"SPF":"v=spf1 include:e3.example.com"},{"A":"1.2.3.7"}],"e3.example.com":[{"SPF":"v=spf1 include:e2.example.com"},{"A":"1.2.3.8"}],"e4.example.com":[{"SPF":"v=spf1 mx"},{"MX":[0,"mail.example.com"]},{"MX":[1,"mail.example.com"]},{"MX":[2,"mail.example.com"]},{"MX":[3,"mail.example.com"]},{"MX":[4,"mail.example.com"]},{"MX":[5,"mail.example.com"]},{"MX":[6,"mail.example.com"]},{"MX":[7,"mail.example.com"]},{"MX":[8,"mail.example.com"]},{"MX":[9,"mail.example.com"]},{"MX":[10,"e4.example.com"]},{"A":"1.2.3.5"}],"e5.example.com":[{"SPF":"v=spf1 ptr"},{"A":"1.2.3.5"}],"5.3.2.1.in-addr.arpa":[{"PTR":"e1.example.com."},{"PTR":"e2.example.com."},{"PTR":"e3.example.com."},{"PTR":"e4.example.com."},{"PTR":"example.com."},{"PTR":"e6.example.com."},{"PTR":"e7.example.com."},{"PTR":"e8.example.com."},{"PTR":"e9.example.com."},{"PTR":"e10.example.com."},{"PTR":"e5.example.com."}],"e6.example.com":[{"SPF":"v=spf1 a mx a mx a mx a mx a ptr ip4:1.2.3.4 -all"},{"A":"1.2.3.8"},{"MX":[10,"e6.example.com"]}],"e7.example.com":[{"SPF":"v=spf1 a mx a mx a mx a mx a ptr a ip4:1.2.3.4 -all"},{"A":"1.2.3.20"}],"e8.example.com":[{"SPF":"v=spf1 a include:inc.example.com ip4:1.2.3.4 mx -all"},{"A":"1.2.3.4"}],"inc.example.com":[{"SPF":"v=spf1 a a a a a a a a"},{"A":"1.2.3.10"}],"e9.example.com":[{"SPF":"v=spf1 a include:inc.example.com a ip4:1.2.3.4 -all"},{"A":"1.2.3.21"}],"e10.example.com":[{"SPF":"v=spf1 a -all"},{"A":"1.2.3.1"},{"A":"1.2.3.2"},{"A":"1.2.3.3"},{"A":"1.2.3.4"},{"A":"1.2.3.5"},{"A":"1.2.3.6"},{"A":"1.2.3.7"},{"A":"1.2.3.8"},{"A":"1.2.3.9"},{"A":"1.2.3.10"},{"A":"1.2.3.11"},{"A":"1.2.3.12"}],"e11.example.com":[{"TXT":"v=spf1 a:err.example.com a:err1.example.com a:err2.example.com ?all"}],"e12.example.com":[{"TXT":"v=spf1 a:err.example.com a:err1.example.com ?all"}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.12');
        return promise.then((result) => {
          assert.equal(result, 'PASS');
        });
      });
      it('SPF implementations MUST limit the number of mechanisms and modifiers that do DNS lookups to at most 10 per SPF check.', function(){
        let email = 'foo@e6.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 ip4:1.1.1.1 redirect=e1.example.com"},{"A":"1.2.3.6"}],"e2.example.com":[{"SPF":"v=spf1 include:e3.example.com"},{"A":"1.2.3.7"}],"e3.example.com":[{"SPF":"v=spf1 include:e2.example.com"},{"A":"1.2.3.8"}],"e4.example.com":[{"SPF":"v=spf1 mx"},{"MX":[0,"mail.example.com"]},{"MX":[1,"mail.example.com"]},{"MX":[2,"mail.example.com"]},{"MX":[3,"mail.example.com"]},{"MX":[4,"mail.example.com"]},{"MX":[5,"mail.example.com"]},{"MX":[6,"mail.example.com"]},{"MX":[7,"mail.example.com"]},{"MX":[8,"mail.example.com"]},{"MX":[9,"mail.example.com"]},{"MX":[10,"e4.example.com"]},{"A":"1.2.3.5"}],"e5.example.com":[{"SPF":"v=spf1 ptr"},{"A":"1.2.3.5"}],"5.3.2.1.in-addr.arpa":[{"PTR":"e1.example.com."},{"PTR":"e2.example.com."},{"PTR":"e3.example.com."},{"PTR":"e4.example.com."},{"PTR":"example.com."},{"PTR":"e6.example.com."},{"PTR":"e7.example.com."},{"PTR":"e8.example.com."},{"PTR":"e9.example.com."},{"PTR":"e10.example.com."},{"PTR":"e5.example.com."}],"e6.example.com":[{"SPF":"v=spf1 a mx a mx a mx a mx a ptr ip4:1.2.3.4 -all"},{"A":"1.2.3.8"},{"MX":[10,"e6.example.com"]}],"e7.example.com":[{"SPF":"v=spf1 a mx a mx a mx a mx a ptr a ip4:1.2.3.4 -all"},{"A":"1.2.3.20"}],"e8.example.com":[{"SPF":"v=spf1 a include:inc.example.com ip4:1.2.3.4 mx -all"},{"A":"1.2.3.4"}],"inc.example.com":[{"SPF":"v=spf1 a a a a a a a a"},{"A":"1.2.3.10"}],"e9.example.com":[{"SPF":"v=spf1 a include:inc.example.com a ip4:1.2.3.4 -all"},{"A":"1.2.3.21"}],"e10.example.com":[{"SPF":"v=spf1 a -all"},{"A":"1.2.3.1"},{"A":"1.2.3.2"},{"A":"1.2.3.3"},{"A":"1.2.3.4"},{"A":"1.2.3.5"},{"A":"1.2.3.6"},{"A":"1.2.3.7"},{"A":"1.2.3.8"},{"A":"1.2.3.9"},{"A":"1.2.3.10"},{"A":"1.2.3.11"},{"A":"1.2.3.12"}],"e11.example.com":[{"TXT":"v=spf1 a:err.example.com a:err1.example.com a:err2.example.com ?all"}],"e12.example.com":[{"TXT":"v=spf1 a:err.example.com a:err1.example.com ?all"}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.4');
        return promise.then((result) => {
          assert.equal(result, 'PASS');
        });
      });
      it('SPF implementations MUST limit the number of mechanisms and modifiers that do DNS lookups to at most 10 per SPF check.', function(){
        let email = 'foo@e7.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 ip4:1.1.1.1 redirect=e1.example.com"},{"A":"1.2.3.6"}],"e2.example.com":[{"SPF":"v=spf1 include:e3.example.com"},{"A":"1.2.3.7"}],"e3.example.com":[{"SPF":"v=spf1 include:e2.example.com"},{"A":"1.2.3.8"}],"e4.example.com":[{"SPF":"v=spf1 mx"},{"MX":[0,"mail.example.com"]},{"MX":[1,"mail.example.com"]},{"MX":[2,"mail.example.com"]},{"MX":[3,"mail.example.com"]},{"MX":[4,"mail.example.com"]},{"MX":[5,"mail.example.com"]},{"MX":[6,"mail.example.com"]},{"MX":[7,"mail.example.com"]},{"MX":[8,"mail.example.com"]},{"MX":[9,"mail.example.com"]},{"MX":[10,"e4.example.com"]},{"A":"1.2.3.5"}],"e5.example.com":[{"SPF":"v=spf1 ptr"},{"A":"1.2.3.5"}],"5.3.2.1.in-addr.arpa":[{"PTR":"e1.example.com."},{"PTR":"e2.example.com."},{"PTR":"e3.example.com."},{"PTR":"e4.example.com."},{"PTR":"example.com."},{"PTR":"e6.example.com."},{"PTR":"e7.example.com."},{"PTR":"e8.example.com."},{"PTR":"e9.example.com."},{"PTR":"e10.example.com."},{"PTR":"e5.example.com."}],"e6.example.com":[{"SPF":"v=spf1 a mx a mx a mx a mx a ptr ip4:1.2.3.4 -all"},{"A":"1.2.3.8"},{"MX":[10,"e6.example.com"]}],"e7.example.com":[{"SPF":"v=spf1 a mx a mx a mx a mx a ptr a ip4:1.2.3.4 -all"},{"A":"1.2.3.20"}],"e8.example.com":[{"SPF":"v=spf1 a include:inc.example.com ip4:1.2.3.4 mx -all"},{"A":"1.2.3.4"}],"inc.example.com":[{"SPF":"v=spf1 a a a a a a a a"},{"A":"1.2.3.10"}],"e9.example.com":[{"SPF":"v=spf1 a include:inc.example.com a ip4:1.2.3.4 -all"},{"A":"1.2.3.21"}],"e10.example.com":[{"SPF":"v=spf1 a -all"},{"A":"1.2.3.1"},{"A":"1.2.3.2"},{"A":"1.2.3.3"},{"A":"1.2.3.4"},{"A":"1.2.3.5"},{"A":"1.2.3.6"},{"A":"1.2.3.7"},{"A":"1.2.3.8"},{"A":"1.2.3.9"},{"A":"1.2.3.10"},{"A":"1.2.3.11"},{"A":"1.2.3.12"}],"e11.example.com":[{"TXT":"v=spf1 a:err.example.com a:err1.example.com a:err2.example.com ?all"}],"e12.example.com":[{"TXT":"v=spf1 a:err.example.com a:err1.example.com ?all"}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.4');
        return promise.then((result) => {
          assert.equal(result, 'PERMERROR');
        });
      });
      it('SPF implementations MUST limit the number of mechanisms and modifiers that do DNS lookups to at most 10 per SPF check.', function(){
        let email = 'foo@e8.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 ip4:1.1.1.1 redirect=e1.example.com"},{"A":"1.2.3.6"}],"e2.example.com":[{"SPF":"v=spf1 include:e3.example.com"},{"A":"1.2.3.7"}],"e3.example.com":[{"SPF":"v=spf1 include:e2.example.com"},{"A":"1.2.3.8"}],"e4.example.com":[{"SPF":"v=spf1 mx"},{"MX":[0,"mail.example.com"]},{"MX":[1,"mail.example.com"]},{"MX":[2,"mail.example.com"]},{"MX":[3,"mail.example.com"]},{"MX":[4,"mail.example.com"]},{"MX":[5,"mail.example.com"]},{"MX":[6,"mail.example.com"]},{"MX":[7,"mail.example.com"]},{"MX":[8,"mail.example.com"]},{"MX":[9,"mail.example.com"]},{"MX":[10,"e4.example.com"]},{"A":"1.2.3.5"}],"e5.example.com":[{"SPF":"v=spf1 ptr"},{"A":"1.2.3.5"}],"5.3.2.1.in-addr.arpa":[{"PTR":"e1.example.com."},{"PTR":"e2.example.com."},{"PTR":"e3.example.com."},{"PTR":"e4.example.com."},{"PTR":"example.com."},{"PTR":"e6.example.com."},{"PTR":"e7.example.com."},{"PTR":"e8.example.com."},{"PTR":"e9.example.com."},{"PTR":"e10.example.com."},{"PTR":"e5.example.com."}],"e6.example.com":[{"SPF":"v=spf1 a mx a mx a mx a mx a ptr ip4:1.2.3.4 -all"},{"A":"1.2.3.8"},{"MX":[10,"e6.example.com"]}],"e7.example.com":[{"SPF":"v=spf1 a mx a mx a mx a mx a ptr a ip4:1.2.3.4 -all"},{"A":"1.2.3.20"}],"e8.example.com":[{"SPF":"v=spf1 a include:inc.example.com ip4:1.2.3.4 mx -all"},{"A":"1.2.3.4"}],"inc.example.com":[{"SPF":"v=spf1 a a a a a a a a"},{"A":"1.2.3.10"}],"e9.example.com":[{"SPF":"v=spf1 a include:inc.example.com a ip4:1.2.3.4 -all"},{"A":"1.2.3.21"}],"e10.example.com":[{"SPF":"v=spf1 a -all"},{"A":"1.2.3.1"},{"A":"1.2.3.2"},{"A":"1.2.3.3"},{"A":"1.2.3.4"},{"A":"1.2.3.5"},{"A":"1.2.3.6"},{"A":"1.2.3.7"},{"A":"1.2.3.8"},{"A":"1.2.3.9"},{"A":"1.2.3.10"},{"A":"1.2.3.11"},{"A":"1.2.3.12"}],"e11.example.com":[{"TXT":"v=spf1 a:err.example.com a:err1.example.com a:err2.example.com ?all"}],"e12.example.com":[{"TXT":"v=spf1 a:err.example.com a:err1.example.com ?all"}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.4');
        return promise.then((result) => {
          assert.equal(result, 'PASS');
        });
      });
      it('SPF implementations MUST limit the number of mechanisms and modifiers that do DNS lookups to at most 10 per SPF check.', function(){
        let email = 'foo@e9.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 ip4:1.1.1.1 redirect=e1.example.com"},{"A":"1.2.3.6"}],"e2.example.com":[{"SPF":"v=spf1 include:e3.example.com"},{"A":"1.2.3.7"}],"e3.example.com":[{"SPF":"v=spf1 include:e2.example.com"},{"A":"1.2.3.8"}],"e4.example.com":[{"SPF":"v=spf1 mx"},{"MX":[0,"mail.example.com"]},{"MX":[1,"mail.example.com"]},{"MX":[2,"mail.example.com"]},{"MX":[3,"mail.example.com"]},{"MX":[4,"mail.example.com"]},{"MX":[5,"mail.example.com"]},{"MX":[6,"mail.example.com"]},{"MX":[7,"mail.example.com"]},{"MX":[8,"mail.example.com"]},{"MX":[9,"mail.example.com"]},{"MX":[10,"e4.example.com"]},{"A":"1.2.3.5"}],"e5.example.com":[{"SPF":"v=spf1 ptr"},{"A":"1.2.3.5"}],"5.3.2.1.in-addr.arpa":[{"PTR":"e1.example.com."},{"PTR":"e2.example.com."},{"PTR":"e3.example.com."},{"PTR":"e4.example.com."},{"PTR":"example.com."},{"PTR":"e6.example.com."},{"PTR":"e7.example.com."},{"PTR":"e8.example.com."},{"PTR":"e9.example.com."},{"PTR":"e10.example.com."},{"PTR":"e5.example.com."}],"e6.example.com":[{"SPF":"v=spf1 a mx a mx a mx a mx a ptr ip4:1.2.3.4 -all"},{"A":"1.2.3.8"},{"MX":[10,"e6.example.com"]}],"e7.example.com":[{"SPF":"v=spf1 a mx a mx a mx a mx a ptr a ip4:1.2.3.4 -all"},{"A":"1.2.3.20"}],"e8.example.com":[{"SPF":"v=spf1 a include:inc.example.com ip4:1.2.3.4 mx -all"},{"A":"1.2.3.4"}],"inc.example.com":[{"SPF":"v=spf1 a a a a a a a a"},{"A":"1.2.3.10"}],"e9.example.com":[{"SPF":"v=spf1 a include:inc.example.com a ip4:1.2.3.4 -all"},{"A":"1.2.3.21"}],"e10.example.com":[{"SPF":"v=spf1 a -all"},{"A":"1.2.3.1"},{"A":"1.2.3.2"},{"A":"1.2.3.3"},{"A":"1.2.3.4"},{"A":"1.2.3.5"},{"A":"1.2.3.6"},{"A":"1.2.3.7"},{"A":"1.2.3.8"},{"A":"1.2.3.9"},{"A":"1.2.3.10"},{"A":"1.2.3.11"},{"A":"1.2.3.12"}],"e11.example.com":[{"TXT":"v=spf1 a:err.example.com a:err1.example.com a:err2.example.com ?all"}],"e12.example.com":[{"TXT":"v=spf1 a:err.example.com a:err1.example.com ?all"}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.4');
        return promise.then((result) => {
          assert.equal(result, 'PERMERROR');
        });
      });
      it('SPF implementations SHOULD limit "void lookups" to two.  An  implementation MAY choose to make such a limit configurable. In this case, a default of two is RECOMMENDED.', function(){
        let email = 'foo@e12.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 ip4:1.1.1.1 redirect=e1.example.com"},{"A":"1.2.3.6"}],"e2.example.com":[{"SPF":"v=spf1 include:e3.example.com"},{"A":"1.2.3.7"}],"e3.example.com":[{"SPF":"v=spf1 include:e2.example.com"},{"A":"1.2.3.8"}],"e4.example.com":[{"SPF":"v=spf1 mx"},{"MX":[0,"mail.example.com"]},{"MX":[1,"mail.example.com"]},{"MX":[2,"mail.example.com"]},{"MX":[3,"mail.example.com"]},{"MX":[4,"mail.example.com"]},{"MX":[5,"mail.example.com"]},{"MX":[6,"mail.example.com"]},{"MX":[7,"mail.example.com"]},{"MX":[8,"mail.example.com"]},{"MX":[9,"mail.example.com"]},{"MX":[10,"e4.example.com"]},{"A":"1.2.3.5"}],"e5.example.com":[{"SPF":"v=spf1 ptr"},{"A":"1.2.3.5"}],"5.3.2.1.in-addr.arpa":[{"PTR":"e1.example.com."},{"PTR":"e2.example.com."},{"PTR":"e3.example.com."},{"PTR":"e4.example.com."},{"PTR":"example.com."},{"PTR":"e6.example.com."},{"PTR":"e7.example.com."},{"PTR":"e8.example.com."},{"PTR":"e9.example.com."},{"PTR":"e10.example.com."},{"PTR":"e5.example.com."}],"e6.example.com":[{"SPF":"v=spf1 a mx a mx a mx a mx a ptr ip4:1.2.3.4 -all"},{"A":"1.2.3.8"},{"MX":[10,"e6.example.com"]}],"e7.example.com":[{"SPF":"v=spf1 a mx a mx a mx a mx a ptr a ip4:1.2.3.4 -all"},{"A":"1.2.3.20"}],"e8.example.com":[{"SPF":"v=spf1 a include:inc.example.com ip4:1.2.3.4 mx -all"},{"A":"1.2.3.4"}],"inc.example.com":[{"SPF":"v=spf1 a a a a a a a a"},{"A":"1.2.3.10"}],"e9.example.com":[{"SPF":"v=spf1 a include:inc.example.com a ip4:1.2.3.4 -all"},{"A":"1.2.3.21"}],"e10.example.com":[{"SPF":"v=spf1 a -all"},{"A":"1.2.3.1"},{"A":"1.2.3.2"},{"A":"1.2.3.3"},{"A":"1.2.3.4"},{"A":"1.2.3.5"},{"A":"1.2.3.6"},{"A":"1.2.3.7"},{"A":"1.2.3.8"},{"A":"1.2.3.9"},{"A":"1.2.3.10"},{"A":"1.2.3.11"},{"A":"1.2.3.12"}],"e11.example.com":[{"TXT":"v=spf1 a:err.example.com a:err1.example.com a:err2.example.com ?all"}],"e12.example.com":[{"TXT":"v=spf1 a:err.example.com a:err1.example.com ?all"}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.4');
        return promise.then((result) => {
          assert.equal(result, 'NEUTRAL');
        });
      });
      it('SPF implementations SHOULD limit "void lookups" to two.  An implementation MAY choose to make such a limit configurable. In this case, a default of two is RECOMMENDED.', function(){
        let email = 'foo@e11.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 ip4:1.1.1.1 redirect=e1.example.com"},{"A":"1.2.3.6"}],"e2.example.com":[{"SPF":"v=spf1 include:e3.example.com"},{"A":"1.2.3.7"}],"e3.example.com":[{"SPF":"v=spf1 include:e2.example.com"},{"A":"1.2.3.8"}],"e4.example.com":[{"SPF":"v=spf1 mx"},{"MX":[0,"mail.example.com"]},{"MX":[1,"mail.example.com"]},{"MX":[2,"mail.example.com"]},{"MX":[3,"mail.example.com"]},{"MX":[4,"mail.example.com"]},{"MX":[5,"mail.example.com"]},{"MX":[6,"mail.example.com"]},{"MX":[7,"mail.example.com"]},{"MX":[8,"mail.example.com"]},{"MX":[9,"mail.example.com"]},{"MX":[10,"e4.example.com"]},{"A":"1.2.3.5"}],"e5.example.com":[{"SPF":"v=spf1 ptr"},{"A":"1.2.3.5"}],"5.3.2.1.in-addr.arpa":[{"PTR":"e1.example.com."},{"PTR":"e2.example.com."},{"PTR":"e3.example.com."},{"PTR":"e4.example.com."},{"PTR":"example.com."},{"PTR":"e6.example.com."},{"PTR":"e7.example.com."},{"PTR":"e8.example.com."},{"PTR":"e9.example.com."},{"PTR":"e10.example.com."},{"PTR":"e5.example.com."}],"e6.example.com":[{"SPF":"v=spf1 a mx a mx a mx a mx a ptr ip4:1.2.3.4 -all"},{"A":"1.2.3.8"},{"MX":[10,"e6.example.com"]}],"e7.example.com":[{"SPF":"v=spf1 a mx a mx a mx a mx a ptr a ip4:1.2.3.4 -all"},{"A":"1.2.3.20"}],"e8.example.com":[{"SPF":"v=spf1 a include:inc.example.com ip4:1.2.3.4 mx -all"},{"A":"1.2.3.4"}],"inc.example.com":[{"SPF":"v=spf1 a a a a a a a a"},{"A":"1.2.3.10"}],"e9.example.com":[{"SPF":"v=spf1 a include:inc.example.com a ip4:1.2.3.4 -all"},{"A":"1.2.3.21"}],"e10.example.com":[{"SPF":"v=spf1 a -all"},{"A":"1.2.3.1"},{"A":"1.2.3.2"},{"A":"1.2.3.3"},{"A":"1.2.3.4"},{"A":"1.2.3.5"},{"A":"1.2.3.6"},{"A":"1.2.3.7"},{"A":"1.2.3.8"},{"A":"1.2.3.9"},{"A":"1.2.3.10"},{"A":"1.2.3.11"},{"A":"1.2.3.12"}],"e11.example.com":[{"TXT":"v=spf1 a:err.example.com a:err1.example.com a:err2.example.com ?all"}],"e12.example.com":[{"TXT":"v=spf1 a:err.example.com a:err1.example.com ?all"}]}, failOnNoFake: true});
        let promise = validator.validateSender('1.2.3.4');
        return promise.then((result) => {
          assert.equal(result, 'PERMERROR');
        });
      });
    });
    describe('Test cases from implementation bugs', function(){
      it('Bytes vs str bug from pyspf.', function(){
        let email = 'test@example.org';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let validator = new spf({domain: emailSplit[1], expandInclude: true, fakeDNSData: {"example.org":[{"SPF":"v=spf1 mx redirect=_spf.example.com"},{"MX":[10,"smtp.example.org"]},{"MX":[10,"smtp1.example.com"]}],"smtp.example.org":[{"A":"198.51.100.2"},{"AAAA":"2001:db8:ff0:100::3"}],"smtp1.example.com":[{"A":"192.0.2.26"},{"AAAA":"2001:db8:ff0:200::2"}],"2.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.1.0.0.F.F.0.8.B.D.0.1.0.0.2.ip6.arpa":[{"PTR":"smtp6-v.fe.example.org"}],"smtp6-v.fe.example.org":[{"AAAA":"2001:db8:ff0:100::2"}],"_spf.example.com":[{"SPF":"v=spf1 ptr:fe.example.org ptr:sgp.example.com exp=_expspf.example.org -all"}],"_expspf.example.org":[{"TXT":"Sender domain not allowed from this host. Please see http://www.openspf.org/Why?s=mfrom&id=%{S}&ip=%{C}&r=%{R}"}]}, failOnNoFake: true});
        let promise = validator.validateSender('2001:db8:ff0:100::2');
        return promise.then((result) => {
          assert.equal(result, 'PASS');
        });
      });
    });
  });
});
