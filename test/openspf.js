var spf = require('../index');
var assert = require('chai').assert;

describe('OpenSPF', function(){
  describe('RFC4408', function(){
    describe('Initial processing', function(){
      it('toolonglabel', function(){
        let email = 'lyme.eater@A123456789012345678901234567890123456789012345678901234567890123.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"example.com":["TIMEOUT"],"example.net":[{"SPF":"v=spf1 -all exp=exp.example.net"}],"a.example.net":[{"SPF":"v=spf1 -all exp=exp.example.net"}],"exp.example.net":[{"TXT":"%{l}"}],"a12345678901234567890123456789012345678901234567890123456789012.example.com":[{"SPF":"v=spf1 -all"}],"hosed.example.com":[{"SPF":"v=spf1 a:ï»¿garbage.example.net -all"}],"hosed2.example.com":[{"SPF":"v=spf1 a:example.net -all"}],"hosed3.example.com":[{"SPF":"v=spf1 a:example.net all"}],"nothosed.example.com":[{"SPF":"v=spf1 a:example.net -all"},{"SPF":""}],"fine.example.com":[{"TXT":"v=spf1 a  -all"}]}, failOnNoFake: true, helo: "mail.example.net"}
        let promise = spf.check_host('1.2.3.5', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'NONE');
        });
      });
      it('longlabel', function(){
        let email = 'lyme.eater@A12345678901234567890123456789012345678901234567890123456789012.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"example.com":["TIMEOUT"],"example.net":[{"SPF":"v=spf1 -all exp=exp.example.net"}],"a.example.net":[{"SPF":"v=spf1 -all exp=exp.example.net"}],"exp.example.net":[{"TXT":"%{l}"}],"a12345678901234567890123456789012345678901234567890123456789012.example.com":[{"SPF":"v=spf1 -all"}],"hosed.example.com":[{"SPF":"v=spf1 a:ï»¿garbage.example.net -all"}],"hosed2.example.com":[{"SPF":"v=spf1 a:example.net -all"}],"hosed3.example.com":[{"SPF":"v=spf1 a:example.net all"}],"nothosed.example.com":[{"SPF":"v=spf1 a:example.net -all"},{"SPF":""}],"fine.example.com":[{"TXT":"v=spf1 a  -all"}]}, failOnNoFake: true, helo: "mail.example.net"}
        let promise = spf.check_host('1.2.3.5', emailSplit[1], email, opts);
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
        let opts = {fakeDNSData: {"example.com":["TIMEOUT"],"example.net":[{"SPF":"v=spf1 -all exp=exp.example.net"}],"a.example.net":[{"SPF":"v=spf1 -all exp=exp.example.net"}],"exp.example.net":[{"TXT":"%{l}"}],"a12345678901234567890123456789012345678901234567890123456789012.example.com":[{"SPF":"v=spf1 -all"}],"hosed.example.com":[{"SPF":"v=spf1 a:ï»¿garbage.example.net -all"}],"hosed2.example.com":[{"SPF":"v=spf1 a:example.net -all"}],"hosed3.example.com":[{"SPF":"v=spf1 a:example.net all"}],"nothosed.example.com":[{"SPF":"v=spf1 a:example.net -all"},{"SPF":""}],"fine.example.com":[{"TXT":"v=spf1 a  -all"}]}, failOnNoFake: true, helo: "mail.example.net"}
        let promise = spf.check_host('1.2.3.5', emailSplit[1], email, opts);
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
        let opts = {fakeDNSData: {"example.com":["TIMEOUT"],"example.net":[{"SPF":"v=spf1 -all exp=exp.example.net"}],"a.example.net":[{"SPF":"v=spf1 -all exp=exp.example.net"}],"exp.example.net":[{"TXT":"%{l}"}],"a12345678901234567890123456789012345678901234567890123456789012.example.com":[{"SPF":"v=spf1 -all"}],"hosed.example.com":[{"SPF":"v=spf1 a:ï»¿garbage.example.net -all"}],"hosed2.example.com":[{"SPF":"v=spf1 a:example.net -all"}],"hosed3.example.com":[{"SPF":"v=spf1 a:example.net all"}],"nothosed.example.com":[{"SPF":"v=spf1 a:example.net -all"},{"SPF":""}],"fine.example.com":[{"TXT":"v=spf1 a  -all"}]}, failOnNoFake: true, helo: "A2345678"}
        let promise = spf.check_host('1.2.3.5', emailSplit[1], email, opts);
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
        let opts = {fakeDNSData: {"example.com":["TIMEOUT"],"example.net":[{"SPF":"v=spf1 -all exp=exp.example.net"}],"a.example.net":[{"SPF":"v=spf1 -all exp=exp.example.net"}],"exp.example.net":[{"TXT":"%{l}"}],"a12345678901234567890123456789012345678901234567890123456789012.example.com":[{"SPF":"v=spf1 -all"}],"hosed.example.com":[{"SPF":"v=spf1 a:ï»¿garbage.example.net -all"}],"hosed2.example.com":[{"SPF":"v=spf1 a:example.net -all"}],"hosed3.example.com":[{"SPF":"v=spf1 a:example.net all"}],"nothosed.example.com":[{"SPF":"v=spf1 a:example.net -all"},{"SPF":""}],"fine.example.com":[{"TXT":"v=spf1 a  -all"}]}, failOnNoFake: true, helo: "[1.2.3.5]"}
        let promise = spf.check_host('1.2.3.5', emailSplit[1], email, opts);
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
        let opts = {fakeDNSData: {"example.com":["TIMEOUT"],"example.net":[{"SPF":"v=spf1 -all exp=exp.example.net"}],"a.example.net":[{"SPF":"v=spf1 -all exp=exp.example.net"}],"exp.example.net":[{"TXT":"%{l}"}],"a12345678901234567890123456789012345678901234567890123456789012.example.com":[{"SPF":"v=spf1 -all"}],"hosed.example.com":[{"SPF":"v=spf1 a:ï»¿garbage.example.net -all"}],"hosed2.example.com":[{"SPF":"v=spf1 a:example.net -all"}],"hosed3.example.com":[{"SPF":"v=spf1 a:example.net all"}],"nothosed.example.com":[{"SPF":"v=spf1 a:example.net -all"},{"SPF":""}],"fine.example.com":[{"TXT":"v=spf1 a  -all"}]}, failOnNoFake: true, helo: "mail.example.net"}
        let promise = spf.check_host('1.2.3.4', emailSplit[1], email, opts);
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
        let opts = {fakeDNSData: {"example.com":["TIMEOUT"],"example.net":[{"SPF":"v=spf1 -all exp=exp.example.net"}],"a.example.net":[{"SPF":"v=spf1 -all exp=exp.example.net"}],"exp.example.net":[{"TXT":"%{l}"}],"a12345678901234567890123456789012345678901234567890123456789012.example.com":[{"SPF":"v=spf1 -all"}],"hosed.example.com":[{"SPF":"v=spf1 a:ï»¿garbage.example.net -all"}],"hosed2.example.com":[{"SPF":"v=spf1 a:example.net -all"}],"hosed3.example.com":[{"SPF":"v=spf1 a:example.net all"}],"nothosed.example.com":[{"SPF":"v=spf1 a:example.net -all"},{"SPF":""}],"fine.example.com":[{"TXT":"v=spf1 a  -all"}]}, failOnNoFake: true, helo: "OEMCOMPUTER"}
        let promise = spf.check_host('1.2.3.5', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'NONE');
        });
      });
      it('non-ascii-policy', function(){
        let email = 'foobar@hosed.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"example.com":["TIMEOUT"],"example.net":[{"SPF":"v=spf1 -all exp=exp.example.net"}],"a.example.net":[{"SPF":"v=spf1 -all exp=exp.example.net"}],"exp.example.net":[{"TXT":"%{l}"}],"a12345678901234567890123456789012345678901234567890123456789012.example.com":[{"SPF":"v=spf1 -all"}],"hosed.example.com":[{"SPF":"v=spf1 a:ï»¿garbage.example.net -all"}],"hosed2.example.com":[{"SPF":"v=spf1 a:example.net -all"}],"hosed3.example.com":[{"SPF":"v=spf1 a:example.net all"}],"nothosed.example.com":[{"SPF":"v=spf1 a:example.net -all"},{"SPF":""}],"fine.example.com":[{"TXT":"v=spf1 a  -all"}]}, failOnNoFake: true, helo: "hosed"}
        let promise = spf.check_host('1.2.3.4', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'PERMERROR');
        });
      });
      it('non-ascii-mech', function(){
        let email = 'foobar@hosed2.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"example.com":["TIMEOUT"],"example.net":[{"SPF":"v=spf1 -all exp=exp.example.net"}],"a.example.net":[{"SPF":"v=spf1 -all exp=exp.example.net"}],"exp.example.net":[{"TXT":"%{l}"}],"a12345678901234567890123456789012345678901234567890123456789012.example.com":[{"SPF":"v=spf1 -all"}],"hosed.example.com":[{"SPF":"v=spf1 a:ï»¿garbage.example.net -all"}],"hosed2.example.com":[{"SPF":"v=spf1 a:example.net -all"}],"hosed3.example.com":[{"SPF":"v=spf1 a:example.net all"}],"nothosed.example.com":[{"SPF":"v=spf1 a:example.net -all"},{"SPF":""}],"fine.example.com":[{"TXT":"v=spf1 a  -all"}]}, failOnNoFake: true, helo: "hosed"}
        let promise = spf.check_host('1.2.3.4', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'PERMERROR');
        });
      });
      it('non-ascii-result', function(){
        let email = 'foobar@hosed3.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"example.com":["TIMEOUT"],"example.net":[{"SPF":"v=spf1 -all exp=exp.example.net"}],"a.example.net":[{"SPF":"v=spf1 -all exp=exp.example.net"}],"exp.example.net":[{"TXT":"%{l}"}],"a12345678901234567890123456789012345678901234567890123456789012.example.com":[{"SPF":"v=spf1 -all"}],"hosed.example.com":[{"SPF":"v=spf1 a:ï»¿garbage.example.net -all"}],"hosed2.example.com":[{"SPF":"v=spf1 a:example.net -all"}],"hosed3.example.com":[{"SPF":"v=spf1 a:example.net all"}],"nothosed.example.com":[{"SPF":"v=spf1 a:example.net -all"},{"SPF":""}],"fine.example.com":[{"TXT":"v=spf1 a  -all"}]}, failOnNoFake: true, helo: "hosed"}
        let promise = spf.check_host('1.2.3.4', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'PERMERROR');
        });
      });
      it('non-ascii-non-spf', function(){
        let email = 'foobar@nothosed.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"example.com":["TIMEOUT"],"example.net":[{"SPF":"v=spf1 -all exp=exp.example.net"}],"a.example.net":[{"SPF":"v=spf1 -all exp=exp.example.net"}],"exp.example.net":[{"TXT":"%{l}"}],"a12345678901234567890123456789012345678901234567890123456789012.example.com":[{"SPF":"v=spf1 -all"}],"hosed.example.com":[{"SPF":"v=spf1 a:ï»¿garbage.example.net -all"}],"hosed2.example.com":[{"SPF":"v=spf1 a:example.net -all"}],"hosed3.example.com":[{"SPF":"v=spf1 a:example.net all"}],"nothosed.example.com":[{"SPF":"v=spf1 a:example.net -all"},{"SPF":""}],"fine.example.com":[{"TXT":"v=spf1 a  -all"}]}, failOnNoFake: true, helo: "hosed"}
        let promise = spf.check_host('1.2.3.4', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'FAIL');
        });
      });
      it('two-spaces', function(){
        let email = 'actually@fine.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"example.com":["TIMEOUT"],"example.net":[{"SPF":"v=spf1 -all exp=exp.example.net"}],"a.example.net":[{"SPF":"v=spf1 -all exp=exp.example.net"}],"exp.example.net":[{"TXT":"%{l}"}],"a12345678901234567890123456789012345678901234567890123456789012.example.com":[{"SPF":"v=spf1 -all"}],"hosed.example.com":[{"SPF":"v=spf1 a:ï»¿garbage.example.net -all"}],"hosed2.example.com":[{"SPF":"v=spf1 a:example.net -all"}],"hosed3.example.com":[{"SPF":"v=spf1 a:example.net all"}],"nothosed.example.com":[{"SPF":"v=spf1 a:example.net -all"},{"SPF":""}],"fine.example.com":[{"TXT":"v=spf1 a  -all"}]}, failOnNoFake: true, helo: "hosed"}
        let promise = spf.check_host('1.2.3.4', emailSplit[1], email, opts);
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
        let opts = {fakeDNSData: {"both.example.net":[{"TXT":"v=spf1 -all"},{"SPF":"v=spf1 -all"}],"txtonly.example.net":[{"TXT":"v=spf1 -all"}],"spfonly.example.net":[{"SPF":"v=spf1 -all"},{"TXT":"NONE"}],"spftimeout.example.net":[{"TXT":"v=spf1 -all"},"TIMEOUT"],"txttimeout.example.net":[{"SPF":"v=spf1 -all"},{"TXT":"NONE"},"TIMEOUT"],"nospftxttimeout.example.net":[{"SPF":"v=spf3 !a:yahoo.com -all"},{"TXT":"NONE"},"TIMEOUT"],"alltimeout.example.net":["TIMEOUT"]}, failOnNoFake: true, helo: "mail.example.net"}
        let promise = spf.check_host('1.2.3.4', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'FAIL');
        });
      });
      it('txtonly', function(){
        let email = 'foo@txtonly.example.net';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"both.example.net":[{"TXT":"v=spf1 -all"},{"SPF":"v=spf1 -all"}],"txtonly.example.net":[{"TXT":"v=spf1 -all"}],"spfonly.example.net":[{"SPF":"v=spf1 -all"},{"TXT":"NONE"}],"spftimeout.example.net":[{"TXT":"v=spf1 -all"},"TIMEOUT"],"txttimeout.example.net":[{"SPF":"v=spf1 -all"},{"TXT":"NONE"},"TIMEOUT"],"nospftxttimeout.example.net":[{"SPF":"v=spf3 !a:yahoo.com -all"},{"TXT":"NONE"},"TIMEOUT"],"alltimeout.example.net":["TIMEOUT"]}, failOnNoFake: true, helo: "mail.example.net"}
        let promise = spf.check_host('1.2.3.4', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.include(["fail","none"], result.toLowerCase());
        });
      });
      it('spfonly', function(){
        let email = 'foo@spfonly.example.net';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"both.example.net":[{"TXT":"v=spf1 -all"},{"SPF":"v=spf1 -all"}],"txtonly.example.net":[{"TXT":"v=spf1 -all"}],"spfonly.example.net":[{"SPF":"v=spf1 -all"},{"TXT":"NONE"}],"spftimeout.example.net":[{"TXT":"v=spf1 -all"},"TIMEOUT"],"txttimeout.example.net":[{"SPF":"v=spf1 -all"},{"TXT":"NONE"},"TIMEOUT"],"nospftxttimeout.example.net":[{"SPF":"v=spf3 !a:yahoo.com -all"},{"TXT":"NONE"},"TIMEOUT"],"alltimeout.example.net":["TIMEOUT"]}, failOnNoFake: true, helo: "mail.example.net"}
        let promise = spf.check_host('1.2.3.4', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.include(["fail","none"], result.toLowerCase());
        });
      });
      it('spftimeout', function(){
        let email = 'foo@spftimeout.example.net';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"both.example.net":[{"TXT":"v=spf1 -all"},{"SPF":"v=spf1 -all"}],"txtonly.example.net":[{"TXT":"v=spf1 -all"}],"spfonly.example.net":[{"SPF":"v=spf1 -all"},{"TXT":"NONE"}],"spftimeout.example.net":[{"TXT":"v=spf1 -all"},"TIMEOUT"],"txttimeout.example.net":[{"SPF":"v=spf1 -all"},{"TXT":"NONE"},"TIMEOUT"],"nospftxttimeout.example.net":[{"SPF":"v=spf3 !a:yahoo.com -all"},{"TXT":"NONE"},"TIMEOUT"],"alltimeout.example.net":["TIMEOUT"]}, failOnNoFake: true, helo: "mail.example.net"}
        let promise = spf.check_host('1.2.3.4', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.include(["fail","temperror"], result.toLowerCase());
        });
      });
      it('txttimeout', function(){
        let email = 'foo@txttimeout.example.net';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"both.example.net":[{"TXT":"v=spf1 -all"},{"SPF":"v=spf1 -all"}],"txtonly.example.net":[{"TXT":"v=spf1 -all"}],"spfonly.example.net":[{"SPF":"v=spf1 -all"},{"TXT":"NONE"}],"spftimeout.example.net":[{"TXT":"v=spf1 -all"},"TIMEOUT"],"txttimeout.example.net":[{"SPF":"v=spf1 -all"},{"TXT":"NONE"},"TIMEOUT"],"nospftxttimeout.example.net":[{"SPF":"v=spf3 !a:yahoo.com -all"},{"TXT":"NONE"},"TIMEOUT"],"alltimeout.example.net":["TIMEOUT"]}, failOnNoFake: true, helo: "mail.example.net"}
        let promise = spf.check_host('1.2.3.4', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.include(["fail","temperror"], result.toLowerCase());
        });
      });
      it('nospftxttimeout', function(){
        let email = 'foo@nospftxttimeout.example.net';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"both.example.net":[{"TXT":"v=spf1 -all"},{"SPF":"v=spf1 -all"}],"txtonly.example.net":[{"TXT":"v=spf1 -all"}],"spfonly.example.net":[{"SPF":"v=spf1 -all"},{"TXT":"NONE"}],"spftimeout.example.net":[{"TXT":"v=spf1 -all"},"TIMEOUT"],"txttimeout.example.net":[{"SPF":"v=spf1 -all"},{"TXT":"NONE"},"TIMEOUT"],"nospftxttimeout.example.net":[{"SPF":"v=spf3 !a:yahoo.com -all"},{"TXT":"NONE"},"TIMEOUT"],"alltimeout.example.net":["TIMEOUT"]}, failOnNoFake: true, helo: "mail.example.net"}
        let promise = spf.check_host('1.2.3.4', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.include(["temperror","none"], result.toLowerCase());
        });
      });
      it('alltimeout', function(){
        let email = 'foo@alltimeout.example.net';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"both.example.net":[{"TXT":"v=spf1 -all"},{"SPF":"v=spf1 -all"}],"txtonly.example.net":[{"TXT":"v=spf1 -all"}],"spfonly.example.net":[{"SPF":"v=spf1 -all"},{"TXT":"NONE"}],"spftimeout.example.net":[{"TXT":"v=spf1 -all"},"TIMEOUT"],"txttimeout.example.net":[{"SPF":"v=spf1 -all"},{"TXT":"NONE"},"TIMEOUT"],"nospftxttimeout.example.net":[{"SPF":"v=spf3 !a:yahoo.com -all"},{"TXT":"NONE"},"TIMEOUT"],"alltimeout.example.net":["TIMEOUT"]}, failOnNoFake: true, helo: "mail.example.net"}
        let promise = spf.check_host('1.2.3.4', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'TEMPERROR');
        });
      });
    });
    describe('Selecting records', function(){
      it('nospace1', function(){
        let email = 'foo@example2.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"example3.com":[{"SPF":"v=spf10"},{"SPF":"v=spf1 mx"},{"MX":[0,"mail.example1.com"]}],"example1.com":[{"SPF":"v=spf1"}],"example2.com":[{"SPF":["v=spf1","mx"]}],"mail.example1.com":[{"A":"1.2.3.4"}],"example4.com":[{"SPF":"v=spf1 +all"},{"TXT":"v=spf1 -all"}],"example5.com":[{"SPF":"v=spf1 +all"},{"TXT":"v=spf1 -all"},{"TXT":"v=spf1 +all"}],"example6.com":[{"SPF":"v=spf1 -all"},{"SPF":"V=sPf1 +all"}],"example7.com":[{"SPF":"v=spf1 -all"},{"SPF":"v=spf1 -all"}],"example8.com":[{"SPF":"V=spf1 -all"},{"SPF":"v=spf1 -all"},{"TXT":"v=spf1 +all"}],"example9.com":[{"SPF":"v=SpF1 ~all"}]}, failOnNoFake: true, helo: "mail.example1.com"}
        let promise = spf.check_host('1.2.3.4', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'NONE');
        });
      });
      it('empty', function(){
        let email = 'foo@example1.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"example3.com":[{"SPF":"v=spf10"},{"SPF":"v=spf1 mx"},{"MX":[0,"mail.example1.com"]}],"example1.com":[{"SPF":"v=spf1"}],"example2.com":[{"SPF":["v=spf1","mx"]}],"mail.example1.com":[{"A":"1.2.3.4"}],"example4.com":[{"SPF":"v=spf1 +all"},{"TXT":"v=spf1 -all"}],"example5.com":[{"SPF":"v=spf1 +all"},{"TXT":"v=spf1 -all"},{"TXT":"v=spf1 +all"}],"example6.com":[{"SPF":"v=spf1 -all"},{"SPF":"V=sPf1 +all"}],"example7.com":[{"SPF":"v=spf1 -all"},{"SPF":"v=spf1 -all"}],"example8.com":[{"SPF":"V=spf1 -all"},{"SPF":"v=spf1 -all"},{"TXT":"v=spf1 +all"}],"example9.com":[{"SPF":"v=SpF1 ~all"}]}, failOnNoFake: true, helo: "mail1.example1.com"}
        let promise = spf.check_host('1.2.3.4', emailSplit[1], email, opts);
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
        let opts = {fakeDNSData: {"example3.com":[{"SPF":"v=spf10"},{"SPF":"v=spf1 mx"},{"MX":[0,"mail.example1.com"]}],"example1.com":[{"SPF":"v=spf1"}],"example2.com":[{"SPF":["v=spf1","mx"]}],"mail.example1.com":[{"A":"1.2.3.4"}],"example4.com":[{"SPF":"v=spf1 +all"},{"TXT":"v=spf1 -all"}],"example5.com":[{"SPF":"v=spf1 +all"},{"TXT":"v=spf1 -all"},{"TXT":"v=spf1 +all"}],"example6.com":[{"SPF":"v=spf1 -all"},{"SPF":"V=sPf1 +all"}],"example7.com":[{"SPF":"v=spf1 -all"},{"SPF":"v=spf1 -all"}],"example8.com":[{"SPF":"V=spf1 -all"},{"SPF":"v=spf1 -all"},{"TXT":"v=spf1 +all"}],"example9.com":[{"SPF":"v=SpF1 ~all"}]}, failOnNoFake: true, helo: "mail.example1.com"}
        let promise = spf.check_host('1.2.3.4', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'PASS');
        });
      });
      it('spfoverride', function(){
        let email = 'foo@example4.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"example3.com":[{"SPF":"v=spf10"},{"SPF":"v=spf1 mx"},{"MX":[0,"mail.example1.com"]}],"example1.com":[{"SPF":"v=spf1"}],"example2.com":[{"SPF":["v=spf1","mx"]}],"mail.example1.com":[{"A":"1.2.3.4"}],"example4.com":[{"SPF":"v=spf1 +all"},{"TXT":"v=spf1 -all"}],"example5.com":[{"SPF":"v=spf1 +all"},{"TXT":"v=spf1 -all"},{"TXT":"v=spf1 +all"}],"example6.com":[{"SPF":"v=spf1 -all"},{"SPF":"V=sPf1 +all"}],"example7.com":[{"SPF":"v=spf1 -all"},{"SPF":"v=spf1 -all"}],"example8.com":[{"SPF":"V=spf1 -all"},{"SPF":"v=spf1 -all"},{"TXT":"v=spf1 +all"}],"example9.com":[{"SPF":"v=SpF1 ~all"}]}, failOnNoFake: true, helo: "mail.example1.com"}
        let promise = spf.check_host('1.2.3.4', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.include(["pass","fail"], result.toLowerCase());
        });
      });
      it('multitxt1', function(){
        let email = 'foo@example5.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"example3.com":[{"SPF":"v=spf10"},{"SPF":"v=spf1 mx"},{"MX":[0,"mail.example1.com"]}],"example1.com":[{"SPF":"v=spf1"}],"example2.com":[{"SPF":["v=spf1","mx"]}],"mail.example1.com":[{"A":"1.2.3.4"}],"example4.com":[{"SPF":"v=spf1 +all"},{"TXT":"v=spf1 -all"}],"example5.com":[{"SPF":"v=spf1 +all"},{"TXT":"v=spf1 -all"},{"TXT":"v=spf1 +all"}],"example6.com":[{"SPF":"v=spf1 -all"},{"SPF":"V=sPf1 +all"}],"example7.com":[{"SPF":"v=spf1 -all"},{"SPF":"v=spf1 -all"}],"example8.com":[{"SPF":"V=spf1 -all"},{"SPF":"v=spf1 -all"},{"TXT":"v=spf1 +all"}],"example9.com":[{"SPF":"v=SpF1 ~all"}]}, failOnNoFake: true, helo: "mail.example1.com"}
        let promise = spf.check_host('1.2.3.4', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.include(["pass","permerror"], result.toLowerCase());
        });
      });
      it('multitxt2', function(){
        let email = 'foo@example6.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"example3.com":[{"SPF":"v=spf10"},{"SPF":"v=spf1 mx"},{"MX":[0,"mail.example1.com"]}],"example1.com":[{"SPF":"v=spf1"}],"example2.com":[{"SPF":["v=spf1","mx"]}],"mail.example1.com":[{"A":"1.2.3.4"}],"example4.com":[{"SPF":"v=spf1 +all"},{"TXT":"v=spf1 -all"}],"example5.com":[{"SPF":"v=spf1 +all"},{"TXT":"v=spf1 -all"},{"TXT":"v=spf1 +all"}],"example6.com":[{"SPF":"v=spf1 -all"},{"SPF":"V=sPf1 +all"}],"example7.com":[{"SPF":"v=spf1 -all"},{"SPF":"v=spf1 -all"}],"example8.com":[{"SPF":"V=spf1 -all"},{"SPF":"v=spf1 -all"},{"TXT":"v=spf1 +all"}],"example9.com":[{"SPF":"v=SpF1 ~all"}]}, failOnNoFake: true, helo: "mail.example1.com"}
        let promise = spf.check_host('1.2.3.4', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'PERMERROR');
        });
      });
      it('multispf1', function(){
        let email = 'foo@example7.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"example3.com":[{"SPF":"v=spf10"},{"SPF":"v=spf1 mx"},{"MX":[0,"mail.example1.com"]}],"example1.com":[{"SPF":"v=spf1"}],"example2.com":[{"SPF":["v=spf1","mx"]}],"mail.example1.com":[{"A":"1.2.3.4"}],"example4.com":[{"SPF":"v=spf1 +all"},{"TXT":"v=spf1 -all"}],"example5.com":[{"SPF":"v=spf1 +all"},{"TXT":"v=spf1 -all"},{"TXT":"v=spf1 +all"}],"example6.com":[{"SPF":"v=spf1 -all"},{"SPF":"V=sPf1 +all"}],"example7.com":[{"SPF":"v=spf1 -all"},{"SPF":"v=spf1 -all"}],"example8.com":[{"SPF":"V=spf1 -all"},{"SPF":"v=spf1 -all"},{"TXT":"v=spf1 +all"}],"example9.com":[{"SPF":"v=SpF1 ~all"}]}, failOnNoFake: true, helo: "mail.example1.com"}
        let promise = spf.check_host('1.2.3.4', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.include(["permerror","fail"], result.toLowerCase());
        });
      });
      it('multispf2', function(){
        let email = 'foo@example8.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"example3.com":[{"SPF":"v=spf10"},{"SPF":"v=spf1 mx"},{"MX":[0,"mail.example1.com"]}],"example1.com":[{"SPF":"v=spf1"}],"example2.com":[{"SPF":["v=spf1","mx"]}],"mail.example1.com":[{"A":"1.2.3.4"}],"example4.com":[{"SPF":"v=spf1 +all"},{"TXT":"v=spf1 -all"}],"example5.com":[{"SPF":"v=spf1 +all"},{"TXT":"v=spf1 -all"},{"TXT":"v=spf1 +all"}],"example6.com":[{"SPF":"v=spf1 -all"},{"SPF":"V=sPf1 +all"}],"example7.com":[{"SPF":"v=spf1 -all"},{"SPF":"v=spf1 -all"}],"example8.com":[{"SPF":"V=spf1 -all"},{"SPF":"v=spf1 -all"},{"TXT":"v=spf1 +all"}],"example9.com":[{"SPF":"v=SpF1 ~all"}]}, failOnNoFake: true, helo: "mail.example1.com"}
        let promise = spf.check_host('1.2.3.4', emailSplit[1], email, opts);
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
        let opts = {fakeDNSData: {"example3.com":[{"SPF":"v=spf10"},{"SPF":"v=spf1 mx"},{"MX":[0,"mail.example1.com"]}],"example1.com":[{"SPF":"v=spf1"}],"example2.com":[{"SPF":["v=spf1","mx"]}],"mail.example1.com":[{"A":"1.2.3.4"}],"example4.com":[{"SPF":"v=spf1 +all"},{"TXT":"v=spf1 -all"}],"example5.com":[{"SPF":"v=spf1 +all"},{"TXT":"v=spf1 -all"},{"TXT":"v=spf1 +all"}],"example6.com":[{"SPF":"v=spf1 -all"},{"SPF":"V=sPf1 +all"}],"example7.com":[{"SPF":"v=spf1 -all"},{"SPF":"v=spf1 -all"}],"example8.com":[{"SPF":"V=spf1 -all"},{"SPF":"v=spf1 -all"},{"TXT":"v=spf1 +all"}],"example9.com":[{"SPF":"v=SpF1 ~all"}]}, failOnNoFake: true, helo: "mail.example1.com"}
        let promise = spf.check_host('1.2.3.4', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'NONE');
        });
      });
      it('case-insensitive', function(){
        let email = 'foo@example9.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"example3.com":[{"SPF":"v=spf10"},{"SPF":"v=spf1 mx"},{"MX":[0,"mail.example1.com"]}],"example1.com":[{"SPF":"v=spf1"}],"example2.com":[{"SPF":["v=spf1","mx"]}],"mail.example1.com":[{"A":"1.2.3.4"}],"example4.com":[{"SPF":"v=spf1 +all"},{"TXT":"v=spf1 -all"}],"example5.com":[{"SPF":"v=spf1 +all"},{"TXT":"v=spf1 -all"},{"TXT":"v=spf1 +all"}],"example6.com":[{"SPF":"v=spf1 -all"},{"SPF":"V=sPf1 +all"}],"example7.com":[{"SPF":"v=spf1 -all"},{"SPF":"v=spf1 -all"}],"example8.com":[{"SPF":"V=spf1 -all"},{"SPF":"v=spf1 -all"},{"TXT":"v=spf1 +all"}],"example9.com":[{"SPF":"v=SpF1 ~all"}]}, failOnNoFake: true, helo: "mail.example1.com"}
        let promise = spf.check_host('1.2.3.4', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'SOFTFAIL');
        });
      });
    });
    describe('Record evaluation', function(){
      it('detect-errors-anywhere', function(){
        let email = 'foo@t1.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"t1.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4 -all moo"}],"t2.example.com":[{"SPF":"v=spf1 moo.cow-far_out=man:dog/cat ip4:1.2.3.4 -all"}],"t3.example.com":[{"SPF":"v=spf1 moo.cow/far_out=man:dog/cat ip4:1.2.3.4 -all"}],"t4.example.com":[{"SPF":"v=spf1 moo.cow:far_out=man:dog/cat ip4:1.2.3.4 -all"}],"t5.example.com":[{"SPF":"v=spf1 redirect=t5.example.com ~all"}],"t6.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4 redirect=t2.example.com"}],"t7.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4"}],"t8.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4 redirect:t2.example.com"}],"t9.example.com":[{"SPF":"v=spf1 a:foo-bar -all"}],"t10.example.com":[{"SPF":"v=spf1 a:mail.example...com -all"}],"t11.example.com":[{"SPF":"v=spf1 a:a123456789012345678901234567890123456789012345678901234567890123.example.com -all"}],"t12.example.com":[{"SPF":"v=spf1 a:%{H}.bar -all"}]}, failOnNoFake: true, helo: "mail.example.com"}
        let promise = spf.check_host('1.2.3.4', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'PERMERROR');
        });
      });
      it('modifier-charset-good', function(){
        let email = 'foo@t2.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"t1.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4 -all moo"}],"t2.example.com":[{"SPF":"v=spf1 moo.cow-far_out=man:dog/cat ip4:1.2.3.4 -all"}],"t3.example.com":[{"SPF":"v=spf1 moo.cow/far_out=man:dog/cat ip4:1.2.3.4 -all"}],"t4.example.com":[{"SPF":"v=spf1 moo.cow:far_out=man:dog/cat ip4:1.2.3.4 -all"}],"t5.example.com":[{"SPF":"v=spf1 redirect=t5.example.com ~all"}],"t6.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4 redirect=t2.example.com"}],"t7.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4"}],"t8.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4 redirect:t2.example.com"}],"t9.example.com":[{"SPF":"v=spf1 a:foo-bar -all"}],"t10.example.com":[{"SPF":"v=spf1 a:mail.example...com -all"}],"t11.example.com":[{"SPF":"v=spf1 a:a123456789012345678901234567890123456789012345678901234567890123.example.com -all"}],"t12.example.com":[{"SPF":"v=spf1 a:%{H}.bar -all"}]}, failOnNoFake: true, helo: "mail.example.com"}
        let promise = spf.check_host('1.2.3.4', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'PASS');
        });
      });
      it('modifier-charset-bad1', function(){
        let email = 'foo@t3.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"t1.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4 -all moo"}],"t2.example.com":[{"SPF":"v=spf1 moo.cow-far_out=man:dog/cat ip4:1.2.3.4 -all"}],"t3.example.com":[{"SPF":"v=spf1 moo.cow/far_out=man:dog/cat ip4:1.2.3.4 -all"}],"t4.example.com":[{"SPF":"v=spf1 moo.cow:far_out=man:dog/cat ip4:1.2.3.4 -all"}],"t5.example.com":[{"SPF":"v=spf1 redirect=t5.example.com ~all"}],"t6.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4 redirect=t2.example.com"}],"t7.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4"}],"t8.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4 redirect:t2.example.com"}],"t9.example.com":[{"SPF":"v=spf1 a:foo-bar -all"}],"t10.example.com":[{"SPF":"v=spf1 a:mail.example...com -all"}],"t11.example.com":[{"SPF":"v=spf1 a:a123456789012345678901234567890123456789012345678901234567890123.example.com -all"}],"t12.example.com":[{"SPF":"v=spf1 a:%{H}.bar -all"}]}, failOnNoFake: true, helo: "mail.example.com"}
        let promise = spf.check_host('1.2.3.4', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'PERMERROR');
        });
      });
      it('modifier-charset-bad2', function(){
        let email = 'foo@t4.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"t1.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4 -all moo"}],"t2.example.com":[{"SPF":"v=spf1 moo.cow-far_out=man:dog/cat ip4:1.2.3.4 -all"}],"t3.example.com":[{"SPF":"v=spf1 moo.cow/far_out=man:dog/cat ip4:1.2.3.4 -all"}],"t4.example.com":[{"SPF":"v=spf1 moo.cow:far_out=man:dog/cat ip4:1.2.3.4 -all"}],"t5.example.com":[{"SPF":"v=spf1 redirect=t5.example.com ~all"}],"t6.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4 redirect=t2.example.com"}],"t7.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4"}],"t8.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4 redirect:t2.example.com"}],"t9.example.com":[{"SPF":"v=spf1 a:foo-bar -all"}],"t10.example.com":[{"SPF":"v=spf1 a:mail.example...com -all"}],"t11.example.com":[{"SPF":"v=spf1 a:a123456789012345678901234567890123456789012345678901234567890123.example.com -all"}],"t12.example.com":[{"SPF":"v=spf1 a:%{H}.bar -all"}]}, failOnNoFake: true, helo: "mail.example.com"}
        let promise = spf.check_host('1.2.3.4', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'PERMERROR');
        });
      });
      it('redirect-after-mechanisms1', function(){
        let email = 'foo@t5.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"t1.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4 -all moo"}],"t2.example.com":[{"SPF":"v=spf1 moo.cow-far_out=man:dog/cat ip4:1.2.3.4 -all"}],"t3.example.com":[{"SPF":"v=spf1 moo.cow/far_out=man:dog/cat ip4:1.2.3.4 -all"}],"t4.example.com":[{"SPF":"v=spf1 moo.cow:far_out=man:dog/cat ip4:1.2.3.4 -all"}],"t5.example.com":[{"SPF":"v=spf1 redirect=t5.example.com ~all"}],"t6.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4 redirect=t2.example.com"}],"t7.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4"}],"t8.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4 redirect:t2.example.com"}],"t9.example.com":[{"SPF":"v=spf1 a:foo-bar -all"}],"t10.example.com":[{"SPF":"v=spf1 a:mail.example...com -all"}],"t11.example.com":[{"SPF":"v=spf1 a:a123456789012345678901234567890123456789012345678901234567890123.example.com -all"}],"t12.example.com":[{"SPF":"v=spf1 a:%{H}.bar -all"}]}, failOnNoFake: true, helo: "mail.example.com"}
        let promise = spf.check_host('1.2.3.4', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'SOFTFAIL');
        });
      });
      it('redirect-after-mechanisms2', function(){
        let email = 'foo@t6.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"t1.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4 -all moo"}],"t2.example.com":[{"SPF":"v=spf1 moo.cow-far_out=man:dog/cat ip4:1.2.3.4 -all"}],"t3.example.com":[{"SPF":"v=spf1 moo.cow/far_out=man:dog/cat ip4:1.2.3.4 -all"}],"t4.example.com":[{"SPF":"v=spf1 moo.cow:far_out=man:dog/cat ip4:1.2.3.4 -all"}],"t5.example.com":[{"SPF":"v=spf1 redirect=t5.example.com ~all"}],"t6.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4 redirect=t2.example.com"}],"t7.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4"}],"t8.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4 redirect:t2.example.com"}],"t9.example.com":[{"SPF":"v=spf1 a:foo-bar -all"}],"t10.example.com":[{"SPF":"v=spf1 a:mail.example...com -all"}],"t11.example.com":[{"SPF":"v=spf1 a:a123456789012345678901234567890123456789012345678901234567890123.example.com -all"}],"t12.example.com":[{"SPF":"v=spf1 a:%{H}.bar -all"}]}, failOnNoFake: true, helo: "mail.example.com"}
        let promise = spf.check_host('1.2.3.5', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'FAIL');
        });
      });
      it('default-result', function(){
        let email = 'foo@t7.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"t1.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4 -all moo"}],"t2.example.com":[{"SPF":"v=spf1 moo.cow-far_out=man:dog/cat ip4:1.2.3.4 -all"}],"t3.example.com":[{"SPF":"v=spf1 moo.cow/far_out=man:dog/cat ip4:1.2.3.4 -all"}],"t4.example.com":[{"SPF":"v=spf1 moo.cow:far_out=man:dog/cat ip4:1.2.3.4 -all"}],"t5.example.com":[{"SPF":"v=spf1 redirect=t5.example.com ~all"}],"t6.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4 redirect=t2.example.com"}],"t7.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4"}],"t8.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4 redirect:t2.example.com"}],"t9.example.com":[{"SPF":"v=spf1 a:foo-bar -all"}],"t10.example.com":[{"SPF":"v=spf1 a:mail.example...com -all"}],"t11.example.com":[{"SPF":"v=spf1 a:a123456789012345678901234567890123456789012345678901234567890123.example.com -all"}],"t12.example.com":[{"SPF":"v=spf1 a:%{H}.bar -all"}]}, failOnNoFake: true, helo: "mail.example.com"}
        let promise = spf.check_host('1.2.3.5', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'NEUTRAL');
        });
      });
      it('redirect-is-modifier', function(){
        let email = 'foo@t8.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"t1.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4 -all moo"}],"t2.example.com":[{"SPF":"v=spf1 moo.cow-far_out=man:dog/cat ip4:1.2.3.4 -all"}],"t3.example.com":[{"SPF":"v=spf1 moo.cow/far_out=man:dog/cat ip4:1.2.3.4 -all"}],"t4.example.com":[{"SPF":"v=spf1 moo.cow:far_out=man:dog/cat ip4:1.2.3.4 -all"}],"t5.example.com":[{"SPF":"v=spf1 redirect=t5.example.com ~all"}],"t6.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4 redirect=t2.example.com"}],"t7.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4"}],"t8.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4 redirect:t2.example.com"}],"t9.example.com":[{"SPF":"v=spf1 a:foo-bar -all"}],"t10.example.com":[{"SPF":"v=spf1 a:mail.example...com -all"}],"t11.example.com":[{"SPF":"v=spf1 a:a123456789012345678901234567890123456789012345678901234567890123.example.com -all"}],"t12.example.com":[{"SPF":"v=spf1 a:%{H}.bar -all"}]}, failOnNoFake: true, helo: "mail.example.com"}
        let promise = spf.check_host('1.2.3.4', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'PERMERROR');
        });
      });
      it('invalid-domain', function(){
        let email = 'foo@t9.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"t1.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4 -all moo"}],"t2.example.com":[{"SPF":"v=spf1 moo.cow-far_out=man:dog/cat ip4:1.2.3.4 -all"}],"t3.example.com":[{"SPF":"v=spf1 moo.cow/far_out=man:dog/cat ip4:1.2.3.4 -all"}],"t4.example.com":[{"SPF":"v=spf1 moo.cow:far_out=man:dog/cat ip4:1.2.3.4 -all"}],"t5.example.com":[{"SPF":"v=spf1 redirect=t5.example.com ~all"}],"t6.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4 redirect=t2.example.com"}],"t7.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4"}],"t8.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4 redirect:t2.example.com"}],"t9.example.com":[{"SPF":"v=spf1 a:foo-bar -all"}],"t10.example.com":[{"SPF":"v=spf1 a:mail.example...com -all"}],"t11.example.com":[{"SPF":"v=spf1 a:a123456789012345678901234567890123456789012345678901234567890123.example.com -all"}],"t12.example.com":[{"SPF":"v=spf1 a:%{H}.bar -all"}]}, failOnNoFake: true, helo: "mail.example.com"}
        let promise = spf.check_host('1.2.3.4', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'PERMERROR');
        });
      });
      it('invalid-domain-empty-label', function(){
        let email = 'foo@t10.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"t1.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4 -all moo"}],"t2.example.com":[{"SPF":"v=spf1 moo.cow-far_out=man:dog/cat ip4:1.2.3.4 -all"}],"t3.example.com":[{"SPF":"v=spf1 moo.cow/far_out=man:dog/cat ip4:1.2.3.4 -all"}],"t4.example.com":[{"SPF":"v=spf1 moo.cow:far_out=man:dog/cat ip4:1.2.3.4 -all"}],"t5.example.com":[{"SPF":"v=spf1 redirect=t5.example.com ~all"}],"t6.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4 redirect=t2.example.com"}],"t7.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4"}],"t8.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4 redirect:t2.example.com"}],"t9.example.com":[{"SPF":"v=spf1 a:foo-bar -all"}],"t10.example.com":[{"SPF":"v=spf1 a:mail.example...com -all"}],"t11.example.com":[{"SPF":"v=spf1 a:a123456789012345678901234567890123456789012345678901234567890123.example.com -all"}],"t12.example.com":[{"SPF":"v=spf1 a:%{H}.bar -all"}]}, failOnNoFake: true, helo: "mail.example.com"}
        let promise = spf.check_host('1.2.3.4', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.include(["permerror","fail"], result.toLowerCase());
        });
      });
      it('invalid-domain-long', function(){
        let email = 'foo@t11.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"t1.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4 -all moo"}],"t2.example.com":[{"SPF":"v=spf1 moo.cow-far_out=man:dog/cat ip4:1.2.3.4 -all"}],"t3.example.com":[{"SPF":"v=spf1 moo.cow/far_out=man:dog/cat ip4:1.2.3.4 -all"}],"t4.example.com":[{"SPF":"v=spf1 moo.cow:far_out=man:dog/cat ip4:1.2.3.4 -all"}],"t5.example.com":[{"SPF":"v=spf1 redirect=t5.example.com ~all"}],"t6.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4 redirect=t2.example.com"}],"t7.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4"}],"t8.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4 redirect:t2.example.com"}],"t9.example.com":[{"SPF":"v=spf1 a:foo-bar -all"}],"t10.example.com":[{"SPF":"v=spf1 a:mail.example...com -all"}],"t11.example.com":[{"SPF":"v=spf1 a:a123456789012345678901234567890123456789012345678901234567890123.example.com -all"}],"t12.example.com":[{"SPF":"v=spf1 a:%{H}.bar -all"}]}, failOnNoFake: true, helo: "mail.example.com"}
        let promise = spf.check_host('1.2.3.4', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.include(["permerror","fail"], result.toLowerCase());
        });
      });
      it('invalid-domain-long-via-macro', function(){
        let email = 'foo@t12.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"t1.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4 -all moo"}],"t2.example.com":[{"SPF":"v=spf1 moo.cow-far_out=man:dog/cat ip4:1.2.3.4 -all"}],"t3.example.com":[{"SPF":"v=spf1 moo.cow/far_out=man:dog/cat ip4:1.2.3.4 -all"}],"t4.example.com":[{"SPF":"v=spf1 moo.cow:far_out=man:dog/cat ip4:1.2.3.4 -all"}],"t5.example.com":[{"SPF":"v=spf1 redirect=t5.example.com ~all"}],"t6.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4 redirect=t2.example.com"}],"t7.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4"}],"t8.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4 redirect:t2.example.com"}],"t9.example.com":[{"SPF":"v=spf1 a:foo-bar -all"}],"t10.example.com":[{"SPF":"v=spf1 a:mail.example...com -all"}],"t11.example.com":[{"SPF":"v=spf1 a:a123456789012345678901234567890123456789012345678901234567890123.example.com -all"}],"t12.example.com":[{"SPF":"v=spf1 a:%{H}.bar -all"}]}, failOnNoFake: true, helo: "%%%%%%%%%%%%%%%%%%%%%%"}
        let promise = spf.check_host('1.2.3.4', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.include(["permerror","fail"], result.toLowerCase());
        });
      });
    });
    describe('ALL mechanism syntax', function(){
      it('all-dot', function(){
        let email = 'foo@e1.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 -all."}],"e2.example.com":[{"SPF":"v=spf1 -all:foobar"}],"e3.example.com":[{"SPF":"v=spf1 -all/8"}],"e4.example.com":[{"SPF":"v=spf1 ?all"}],"e5.example.com":[{"SPF":"v=spf1 all -all"}]}, failOnNoFake: true, helo: "mail.example.com"}
        let promise = spf.check_host('1.2.3.4', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'PERMERROR');
        });
      });
      it('all-arg', function(){
        let email = 'foo@e2.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 -all."}],"e2.example.com":[{"SPF":"v=spf1 -all:foobar"}],"e3.example.com":[{"SPF":"v=spf1 -all/8"}],"e4.example.com":[{"SPF":"v=spf1 ?all"}],"e5.example.com":[{"SPF":"v=spf1 all -all"}]}, failOnNoFake: true, helo: "mail.example.com"}
        let promise = spf.check_host('1.2.3.4', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'PERMERROR');
        });
      });
      it('all-cidr', function(){
        let email = 'foo@e3.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 -all."}],"e2.example.com":[{"SPF":"v=spf1 -all:foobar"}],"e3.example.com":[{"SPF":"v=spf1 -all/8"}],"e4.example.com":[{"SPF":"v=spf1 ?all"}],"e5.example.com":[{"SPF":"v=spf1 all -all"}]}, failOnNoFake: true, helo: "mail.example.com"}
        let promise = spf.check_host('1.2.3.4', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'PERMERROR');
        });
      });
      it('all-neutral', function(){
        let email = 'foo@e4.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 -all."}],"e2.example.com":[{"SPF":"v=spf1 -all:foobar"}],"e3.example.com":[{"SPF":"v=spf1 -all/8"}],"e4.example.com":[{"SPF":"v=spf1 ?all"}],"e5.example.com":[{"SPF":"v=spf1 all -all"}]}, failOnNoFake: true, helo: "mail.example.com"}
        let promise = spf.check_host('1.2.3.4', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'NEUTRAL');
        });
      });
      it('all-double', function(){
        let email = 'foo@e5.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 -all."}],"e2.example.com":[{"SPF":"v=spf1 -all:foobar"}],"e3.example.com":[{"SPF":"v=spf1 -all/8"}],"e4.example.com":[{"SPF":"v=spf1 ?all"}],"e5.example.com":[{"SPF":"v=spf1 all -all"}]}, failOnNoFake: true, helo: "mail.example.com"}
        let promise = spf.check_host('1.2.3.4', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'PASS');
        });
      });
    });
    describe('PTR mechanism syntax', function(){
      it('ptr-cidr', function(){
        let email = 'foo@e1.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 ptr/0 -all"}],"e2.example.com":[{"SPF":"v=spf1 ptr:example.com -all"}],"4.3.2.1.in-addr.arpa":[{"PTR":"e3.example.com"},{"PTR":"e4.example.com"},{"PTR":"mail.example.com"}],"1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.E.B.A.B.E.F.A.C.ip6.arpa":[{"PTR":"e3.example.com"}],"e3.example.com":[{"SPF":"v=spf1 ptr -all"},{"A":"1.2.3.4"},{"AAAA":"CAFE:BABE::1"}],"e4.example.com":[{"SPF":"v=spf1 ptr -all"}],"e5.example.com":[{"SPF":"v=spf1 ptr:"}]}, failOnNoFake: true, helo: "mail.example.com"}
        let promise = spf.check_host('1.2.3.4', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'PERMERROR');
        });
      });
      it('ptr-match-target', function(){
        let email = 'foo@e2.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 ptr/0 -all"}],"e2.example.com":[{"SPF":"v=spf1 ptr:example.com -all"}],"4.3.2.1.in-addr.arpa":[{"PTR":"e3.example.com"},{"PTR":"e4.example.com"},{"PTR":"mail.example.com"}],"1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.E.B.A.B.E.F.A.C.ip6.arpa":[{"PTR":"e3.example.com"}],"e3.example.com":[{"SPF":"v=spf1 ptr -all"},{"A":"1.2.3.4"},{"AAAA":"CAFE:BABE::1"}],"e4.example.com":[{"SPF":"v=spf1 ptr -all"}],"e5.example.com":[{"SPF":"v=spf1 ptr:"}]}, failOnNoFake: true, helo: "mail.example.com"}
        let promise = spf.check_host('1.2.3.4', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'PASS');
        });
      });
      it('ptr-match-implicit', function(){
        let email = 'foo@e3.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 ptr/0 -all"}],"e2.example.com":[{"SPF":"v=spf1 ptr:example.com -all"}],"4.3.2.1.in-addr.arpa":[{"PTR":"e3.example.com"},{"PTR":"e4.example.com"},{"PTR":"mail.example.com"}],"1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.E.B.A.B.E.F.A.C.ip6.arpa":[{"PTR":"e3.example.com"}],"e3.example.com":[{"SPF":"v=spf1 ptr -all"},{"A":"1.2.3.4"},{"AAAA":"CAFE:BABE::1"}],"e4.example.com":[{"SPF":"v=spf1 ptr -all"}],"e5.example.com":[{"SPF":"v=spf1 ptr:"}]}, failOnNoFake: true, helo: "mail.example.com"}
        let promise = spf.check_host('1.2.3.4', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'PASS');
        });
      });
      it('ptr-nomatch-invalid', function(){
        let email = 'foo@e4.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 ptr/0 -all"}],"e2.example.com":[{"SPF":"v=spf1 ptr:example.com -all"}],"4.3.2.1.in-addr.arpa":[{"PTR":"e3.example.com"},{"PTR":"e4.example.com"},{"PTR":"mail.example.com"}],"1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.E.B.A.B.E.F.A.C.ip6.arpa":[{"PTR":"e3.example.com"}],"e3.example.com":[{"SPF":"v=spf1 ptr -all"},{"A":"1.2.3.4"},{"AAAA":"CAFE:BABE::1"}],"e4.example.com":[{"SPF":"v=spf1 ptr -all"}],"e5.example.com":[{"SPF":"v=spf1 ptr:"}]}, failOnNoFake: true, helo: "mail.example.com"}
        let promise = spf.check_host('1.2.3.4', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'FAIL');
        });
      });
      it('ptr-match-ip6', function(){
        let email = 'foo@e3.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 ptr/0 -all"}],"e2.example.com":[{"SPF":"v=spf1 ptr:example.com -all"}],"4.3.2.1.in-addr.arpa":[{"PTR":"e3.example.com"},{"PTR":"e4.example.com"},{"PTR":"mail.example.com"}],"1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.E.B.A.B.E.F.A.C.ip6.arpa":[{"PTR":"e3.example.com"}],"e3.example.com":[{"SPF":"v=spf1 ptr -all"},{"A":"1.2.3.4"},{"AAAA":"CAFE:BABE::1"}],"e4.example.com":[{"SPF":"v=spf1 ptr -all"}],"e5.example.com":[{"SPF":"v=spf1 ptr:"}]}, failOnNoFake: true, helo: "mail.example.com"}
        let promise = spf.check_host('CAFE:BABE::1', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'PASS');
        });
      });
      it('ptr-empty-domain', function(){
        let email = 'foo@e5.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 ptr/0 -all"}],"e2.example.com":[{"SPF":"v=spf1 ptr:example.com -all"}],"4.3.2.1.in-addr.arpa":[{"PTR":"e3.example.com"},{"PTR":"e4.example.com"},{"PTR":"mail.example.com"}],"1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.E.B.A.B.E.F.A.C.ip6.arpa":[{"PTR":"e3.example.com"}],"e3.example.com":[{"SPF":"v=spf1 ptr -all"},{"A":"1.2.3.4"},{"AAAA":"CAFE:BABE::1"}],"e4.example.com":[{"SPF":"v=spf1 ptr -all"}],"e5.example.com":[{"SPF":"v=spf1 ptr:"}]}, failOnNoFake: true, helo: "mail.example.com"}
        let promise = spf.check_host('1.2.3.4', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'PERMERROR');
        });
      });
    });
    describe('A mechanism syntax', function(){
      it('a-cidr6', function(){
        let email = 'foo@e6.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 a/0 -all"}],"e2.example.com":[{"A":"1.1.1.1"},{"AAAA":"1234::2"},{"SPF":"v=spf1 a/0 -all"}],"e2a.example.com":[{"AAAA":"1234::1"},{"SPF":"v=spf1 a//0 -all"}],"e2b.example.com":[{"A":"1.1.1.1"},{"SPF":"v=spf1 a//0 -all"}],"ipv6.example.com":[{"AAAA":"1234::1"},{"A":"1.1.1.1"},{"SPF":"v=spf1 a -all"}],"e3.example.com":[{"SPF":"v=spf1 a:foo.example.com\u0000"}],"e4.example.com":[{"SPF":"v=spf1 a:111.222.33.44"}],"e5.example.com":[{"SPF":"v=spf1 a:abc.123"}],"e5a.example.com":[{"SPF":"v=spf1 a:museum"}],"e5b.example.com":[{"SPF":"v=spf1 a:museum."}],"e6.example.com":[{"SPF":"v=spf1 a//33 -all"}],"e6a.example.com":[{"SPF":"v=spf1 a/33 -all"}],"e7.example.com":[{"SPF":"v=spf1 a//129 -all"}],"e8.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24//64 -all"}],"e8e.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24/64 -all"}],"e8a.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24 -all"}],"e8b.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a//64 -all"}],"e9.example.com":[{"SPF":"v=spf1 a:example.com:8080"}],"e10.example.com":[{"SPF":"v=spf1 a:foo.example.com/24"}],"foo.example.com":[{"A":"1.1.1.1"},{"A":"1.2.3.5"}],"e11.example.com":[{"SPF":"v=spf1 a:foo:bar/baz.example.com"}],"foo:bar/baz.example.com":[{"A":"1.2.3.4"}],"e12.example.com":[{"SPF":"v=spf1 a:example.-com"}],"e13.example.com":[{"SPF":"v=spf1 a:"}],"e14.example.com":[{"SPF":"v=spf1 a:foo.example.xn--zckzah -all"}],"foo.example.xn--zckzah":[{"A":"1.2.3.4"}]}, failOnNoFake: true, helo: "mail.example.com"}
        let promise = spf.check_host('1.2.3.4', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'FAIL');
        });
      });
      it('a-bad-cidr4', function(){
        let email = 'foo@e6a.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 a/0 -all"}],"e2.example.com":[{"A":"1.1.1.1"},{"AAAA":"1234::2"},{"SPF":"v=spf1 a/0 -all"}],"e2a.example.com":[{"AAAA":"1234::1"},{"SPF":"v=spf1 a//0 -all"}],"e2b.example.com":[{"A":"1.1.1.1"},{"SPF":"v=spf1 a//0 -all"}],"ipv6.example.com":[{"AAAA":"1234::1"},{"A":"1.1.1.1"},{"SPF":"v=spf1 a -all"}],"e3.example.com":[{"SPF":"v=spf1 a:foo.example.com\u0000"}],"e4.example.com":[{"SPF":"v=spf1 a:111.222.33.44"}],"e5.example.com":[{"SPF":"v=spf1 a:abc.123"}],"e5a.example.com":[{"SPF":"v=spf1 a:museum"}],"e5b.example.com":[{"SPF":"v=spf1 a:museum."}],"e6.example.com":[{"SPF":"v=spf1 a//33 -all"}],"e6a.example.com":[{"SPF":"v=spf1 a/33 -all"}],"e7.example.com":[{"SPF":"v=spf1 a//129 -all"}],"e8.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24//64 -all"}],"e8e.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24/64 -all"}],"e8a.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24 -all"}],"e8b.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a//64 -all"}],"e9.example.com":[{"SPF":"v=spf1 a:example.com:8080"}],"e10.example.com":[{"SPF":"v=spf1 a:foo.example.com/24"}],"foo.example.com":[{"A":"1.1.1.1"},{"A":"1.2.3.5"}],"e11.example.com":[{"SPF":"v=spf1 a:foo:bar/baz.example.com"}],"foo:bar/baz.example.com":[{"A":"1.2.3.4"}],"e12.example.com":[{"SPF":"v=spf1 a:example.-com"}],"e13.example.com":[{"SPF":"v=spf1 a:"}],"e14.example.com":[{"SPF":"v=spf1 a:foo.example.xn--zckzah -all"}],"foo.example.xn--zckzah":[{"A":"1.2.3.4"}]}, failOnNoFake: true, helo: "mail.example.com"}
        let promise = spf.check_host('1.2.3.4', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'PERMERROR');
        });
      });
      it('a-bad-cidr6', function(){
        let email = 'foo@e7.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 a/0 -all"}],"e2.example.com":[{"A":"1.1.1.1"},{"AAAA":"1234::2"},{"SPF":"v=spf1 a/0 -all"}],"e2a.example.com":[{"AAAA":"1234::1"},{"SPF":"v=spf1 a//0 -all"}],"e2b.example.com":[{"A":"1.1.1.1"},{"SPF":"v=spf1 a//0 -all"}],"ipv6.example.com":[{"AAAA":"1234::1"},{"A":"1.1.1.1"},{"SPF":"v=spf1 a -all"}],"e3.example.com":[{"SPF":"v=spf1 a:foo.example.com\u0000"}],"e4.example.com":[{"SPF":"v=spf1 a:111.222.33.44"}],"e5.example.com":[{"SPF":"v=spf1 a:abc.123"}],"e5a.example.com":[{"SPF":"v=spf1 a:museum"}],"e5b.example.com":[{"SPF":"v=spf1 a:museum."}],"e6.example.com":[{"SPF":"v=spf1 a//33 -all"}],"e6a.example.com":[{"SPF":"v=spf1 a/33 -all"}],"e7.example.com":[{"SPF":"v=spf1 a//129 -all"}],"e8.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24//64 -all"}],"e8e.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24/64 -all"}],"e8a.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24 -all"}],"e8b.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a//64 -all"}],"e9.example.com":[{"SPF":"v=spf1 a:example.com:8080"}],"e10.example.com":[{"SPF":"v=spf1 a:foo.example.com/24"}],"foo.example.com":[{"A":"1.1.1.1"},{"A":"1.2.3.5"}],"e11.example.com":[{"SPF":"v=spf1 a:foo:bar/baz.example.com"}],"foo:bar/baz.example.com":[{"A":"1.2.3.4"}],"e12.example.com":[{"SPF":"v=spf1 a:example.-com"}],"e13.example.com":[{"SPF":"v=spf1 a:"}],"e14.example.com":[{"SPF":"v=spf1 a:foo.example.xn--zckzah -all"}],"foo.example.xn--zckzah":[{"A":"1.2.3.4"}]}, failOnNoFake: true, helo: "mail.example.com"}
        let promise = spf.check_host('1.2.3.4', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'PERMERROR');
        });
      });
      it('a-dual-cidr-ip4-match', function(){
        let email = 'foo@e8.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 a/0 -all"}],"e2.example.com":[{"A":"1.1.1.1"},{"AAAA":"1234::2"},{"SPF":"v=spf1 a/0 -all"}],"e2a.example.com":[{"AAAA":"1234::1"},{"SPF":"v=spf1 a//0 -all"}],"e2b.example.com":[{"A":"1.1.1.1"},{"SPF":"v=spf1 a//0 -all"}],"ipv6.example.com":[{"AAAA":"1234::1"},{"A":"1.1.1.1"},{"SPF":"v=spf1 a -all"}],"e3.example.com":[{"SPF":"v=spf1 a:foo.example.com\u0000"}],"e4.example.com":[{"SPF":"v=spf1 a:111.222.33.44"}],"e5.example.com":[{"SPF":"v=spf1 a:abc.123"}],"e5a.example.com":[{"SPF":"v=spf1 a:museum"}],"e5b.example.com":[{"SPF":"v=spf1 a:museum."}],"e6.example.com":[{"SPF":"v=spf1 a//33 -all"}],"e6a.example.com":[{"SPF":"v=spf1 a/33 -all"}],"e7.example.com":[{"SPF":"v=spf1 a//129 -all"}],"e8.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24//64 -all"}],"e8e.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24/64 -all"}],"e8a.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24 -all"}],"e8b.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a//64 -all"}],"e9.example.com":[{"SPF":"v=spf1 a:example.com:8080"}],"e10.example.com":[{"SPF":"v=spf1 a:foo.example.com/24"}],"foo.example.com":[{"A":"1.1.1.1"},{"A":"1.2.3.5"}],"e11.example.com":[{"SPF":"v=spf1 a:foo:bar/baz.example.com"}],"foo:bar/baz.example.com":[{"A":"1.2.3.4"}],"e12.example.com":[{"SPF":"v=spf1 a:example.-com"}],"e13.example.com":[{"SPF":"v=spf1 a:"}],"e14.example.com":[{"SPF":"v=spf1 a:foo.example.xn--zckzah -all"}],"foo.example.xn--zckzah":[{"A":"1.2.3.4"}]}, failOnNoFake: true, helo: "mail.example.com"}
        let promise = spf.check_host('1.2.3.4', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'PASS');
        });
      });
      it('a-dual-cidr-ip4-err', function(){
        let email = 'foo@e8e.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 a/0 -all"}],"e2.example.com":[{"A":"1.1.1.1"},{"AAAA":"1234::2"},{"SPF":"v=spf1 a/0 -all"}],"e2a.example.com":[{"AAAA":"1234::1"},{"SPF":"v=spf1 a//0 -all"}],"e2b.example.com":[{"A":"1.1.1.1"},{"SPF":"v=spf1 a//0 -all"}],"ipv6.example.com":[{"AAAA":"1234::1"},{"A":"1.1.1.1"},{"SPF":"v=spf1 a -all"}],"e3.example.com":[{"SPF":"v=spf1 a:foo.example.com\u0000"}],"e4.example.com":[{"SPF":"v=spf1 a:111.222.33.44"}],"e5.example.com":[{"SPF":"v=spf1 a:abc.123"}],"e5a.example.com":[{"SPF":"v=spf1 a:museum"}],"e5b.example.com":[{"SPF":"v=spf1 a:museum."}],"e6.example.com":[{"SPF":"v=spf1 a//33 -all"}],"e6a.example.com":[{"SPF":"v=spf1 a/33 -all"}],"e7.example.com":[{"SPF":"v=spf1 a//129 -all"}],"e8.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24//64 -all"}],"e8e.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24/64 -all"}],"e8a.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24 -all"}],"e8b.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a//64 -all"}],"e9.example.com":[{"SPF":"v=spf1 a:example.com:8080"}],"e10.example.com":[{"SPF":"v=spf1 a:foo.example.com/24"}],"foo.example.com":[{"A":"1.1.1.1"},{"A":"1.2.3.5"}],"e11.example.com":[{"SPF":"v=spf1 a:foo:bar/baz.example.com"}],"foo:bar/baz.example.com":[{"A":"1.2.3.4"}],"e12.example.com":[{"SPF":"v=spf1 a:example.-com"}],"e13.example.com":[{"SPF":"v=spf1 a:"}],"e14.example.com":[{"SPF":"v=spf1 a:foo.example.xn--zckzah -all"}],"foo.example.xn--zckzah":[{"A":"1.2.3.4"}]}, failOnNoFake: true, helo: "mail.example.com"}
        let promise = spf.check_host('1.2.3.4', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'PERMERROR');
        });
      });
      it('a-dual-cidr-ip6-match', function(){
        let email = 'foo@e8.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 a/0 -all"}],"e2.example.com":[{"A":"1.1.1.1"},{"AAAA":"1234::2"},{"SPF":"v=spf1 a/0 -all"}],"e2a.example.com":[{"AAAA":"1234::1"},{"SPF":"v=spf1 a//0 -all"}],"e2b.example.com":[{"A":"1.1.1.1"},{"SPF":"v=spf1 a//0 -all"}],"ipv6.example.com":[{"AAAA":"1234::1"},{"A":"1.1.1.1"},{"SPF":"v=spf1 a -all"}],"e3.example.com":[{"SPF":"v=spf1 a:foo.example.com\u0000"}],"e4.example.com":[{"SPF":"v=spf1 a:111.222.33.44"}],"e5.example.com":[{"SPF":"v=spf1 a:abc.123"}],"e5a.example.com":[{"SPF":"v=spf1 a:museum"}],"e5b.example.com":[{"SPF":"v=spf1 a:museum."}],"e6.example.com":[{"SPF":"v=spf1 a//33 -all"}],"e6a.example.com":[{"SPF":"v=spf1 a/33 -all"}],"e7.example.com":[{"SPF":"v=spf1 a//129 -all"}],"e8.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24//64 -all"}],"e8e.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24/64 -all"}],"e8a.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24 -all"}],"e8b.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a//64 -all"}],"e9.example.com":[{"SPF":"v=spf1 a:example.com:8080"}],"e10.example.com":[{"SPF":"v=spf1 a:foo.example.com/24"}],"foo.example.com":[{"A":"1.1.1.1"},{"A":"1.2.3.5"}],"e11.example.com":[{"SPF":"v=spf1 a:foo:bar/baz.example.com"}],"foo:bar/baz.example.com":[{"A":"1.2.3.4"}],"e12.example.com":[{"SPF":"v=spf1 a:example.-com"}],"e13.example.com":[{"SPF":"v=spf1 a:"}],"e14.example.com":[{"SPF":"v=spf1 a:foo.example.xn--zckzah -all"}],"foo.example.xn--zckzah":[{"A":"1.2.3.4"}]}, failOnNoFake: true, helo: "mail.example.com"}
        let promise = spf.check_host('2001:db8:1234::cafe:babe', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'PASS');
        });
      });
      it('a-dual-cidr-ip4-default', function(){
        let email = 'foo@e8b.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 a/0 -all"}],"e2.example.com":[{"A":"1.1.1.1"},{"AAAA":"1234::2"},{"SPF":"v=spf1 a/0 -all"}],"e2a.example.com":[{"AAAA":"1234::1"},{"SPF":"v=spf1 a//0 -all"}],"e2b.example.com":[{"A":"1.1.1.1"},{"SPF":"v=spf1 a//0 -all"}],"ipv6.example.com":[{"AAAA":"1234::1"},{"A":"1.1.1.1"},{"SPF":"v=spf1 a -all"}],"e3.example.com":[{"SPF":"v=spf1 a:foo.example.com\u0000"}],"e4.example.com":[{"SPF":"v=spf1 a:111.222.33.44"}],"e5.example.com":[{"SPF":"v=spf1 a:abc.123"}],"e5a.example.com":[{"SPF":"v=spf1 a:museum"}],"e5b.example.com":[{"SPF":"v=spf1 a:museum."}],"e6.example.com":[{"SPF":"v=spf1 a//33 -all"}],"e6a.example.com":[{"SPF":"v=spf1 a/33 -all"}],"e7.example.com":[{"SPF":"v=spf1 a//129 -all"}],"e8.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24//64 -all"}],"e8e.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24/64 -all"}],"e8a.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24 -all"}],"e8b.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a//64 -all"}],"e9.example.com":[{"SPF":"v=spf1 a:example.com:8080"}],"e10.example.com":[{"SPF":"v=spf1 a:foo.example.com/24"}],"foo.example.com":[{"A":"1.1.1.1"},{"A":"1.2.3.5"}],"e11.example.com":[{"SPF":"v=spf1 a:foo:bar/baz.example.com"}],"foo:bar/baz.example.com":[{"A":"1.2.3.4"}],"e12.example.com":[{"SPF":"v=spf1 a:example.-com"}],"e13.example.com":[{"SPF":"v=spf1 a:"}],"e14.example.com":[{"SPF":"v=spf1 a:foo.example.xn--zckzah -all"}],"foo.example.xn--zckzah":[{"A":"1.2.3.4"}]}, failOnNoFake: true, helo: "mail.example.com"}
        let promise = spf.check_host('1.2.3.4', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'FAIL');
        });
      });
      it('a-dual-cidr-ip6-default', function(){
        let email = 'foo@e8a.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 a/0 -all"}],"e2.example.com":[{"A":"1.1.1.1"},{"AAAA":"1234::2"},{"SPF":"v=spf1 a/0 -all"}],"e2a.example.com":[{"AAAA":"1234::1"},{"SPF":"v=spf1 a//0 -all"}],"e2b.example.com":[{"A":"1.1.1.1"},{"SPF":"v=spf1 a//0 -all"}],"ipv6.example.com":[{"AAAA":"1234::1"},{"A":"1.1.1.1"},{"SPF":"v=spf1 a -all"}],"e3.example.com":[{"SPF":"v=spf1 a:foo.example.com\u0000"}],"e4.example.com":[{"SPF":"v=spf1 a:111.222.33.44"}],"e5.example.com":[{"SPF":"v=spf1 a:abc.123"}],"e5a.example.com":[{"SPF":"v=spf1 a:museum"}],"e5b.example.com":[{"SPF":"v=spf1 a:museum."}],"e6.example.com":[{"SPF":"v=spf1 a//33 -all"}],"e6a.example.com":[{"SPF":"v=spf1 a/33 -all"}],"e7.example.com":[{"SPF":"v=spf1 a//129 -all"}],"e8.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24//64 -all"}],"e8e.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24/64 -all"}],"e8a.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24 -all"}],"e8b.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a//64 -all"}],"e9.example.com":[{"SPF":"v=spf1 a:example.com:8080"}],"e10.example.com":[{"SPF":"v=spf1 a:foo.example.com/24"}],"foo.example.com":[{"A":"1.1.1.1"},{"A":"1.2.3.5"}],"e11.example.com":[{"SPF":"v=spf1 a:foo:bar/baz.example.com"}],"foo:bar/baz.example.com":[{"A":"1.2.3.4"}],"e12.example.com":[{"SPF":"v=spf1 a:example.-com"}],"e13.example.com":[{"SPF":"v=spf1 a:"}],"e14.example.com":[{"SPF":"v=spf1 a:foo.example.xn--zckzah -all"}],"foo.example.xn--zckzah":[{"A":"1.2.3.4"}]}, failOnNoFake: true, helo: "mail.example.com"}
        let promise = spf.check_host('2001:db8:1234::cafe:babe', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'FAIL');
        });
      });
      it('a-multi-ip1', function(){
        let email = 'foo@e10.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 a/0 -all"}],"e2.example.com":[{"A":"1.1.1.1"},{"AAAA":"1234::2"},{"SPF":"v=spf1 a/0 -all"}],"e2a.example.com":[{"AAAA":"1234::1"},{"SPF":"v=spf1 a//0 -all"}],"e2b.example.com":[{"A":"1.1.1.1"},{"SPF":"v=spf1 a//0 -all"}],"ipv6.example.com":[{"AAAA":"1234::1"},{"A":"1.1.1.1"},{"SPF":"v=spf1 a -all"}],"e3.example.com":[{"SPF":"v=spf1 a:foo.example.com\u0000"}],"e4.example.com":[{"SPF":"v=spf1 a:111.222.33.44"}],"e5.example.com":[{"SPF":"v=spf1 a:abc.123"}],"e5a.example.com":[{"SPF":"v=spf1 a:museum"}],"e5b.example.com":[{"SPF":"v=spf1 a:museum."}],"e6.example.com":[{"SPF":"v=spf1 a//33 -all"}],"e6a.example.com":[{"SPF":"v=spf1 a/33 -all"}],"e7.example.com":[{"SPF":"v=spf1 a//129 -all"}],"e8.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24//64 -all"}],"e8e.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24/64 -all"}],"e8a.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24 -all"}],"e8b.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a//64 -all"}],"e9.example.com":[{"SPF":"v=spf1 a:example.com:8080"}],"e10.example.com":[{"SPF":"v=spf1 a:foo.example.com/24"}],"foo.example.com":[{"A":"1.1.1.1"},{"A":"1.2.3.5"}],"e11.example.com":[{"SPF":"v=spf1 a:foo:bar/baz.example.com"}],"foo:bar/baz.example.com":[{"A":"1.2.3.4"}],"e12.example.com":[{"SPF":"v=spf1 a:example.-com"}],"e13.example.com":[{"SPF":"v=spf1 a:"}],"e14.example.com":[{"SPF":"v=spf1 a:foo.example.xn--zckzah -all"}],"foo.example.xn--zckzah":[{"A":"1.2.3.4"}]}, failOnNoFake: true, helo: "mail.example.com"}
        let promise = spf.check_host('1.2.3.4', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'PASS');
        });
      });
      it('a-multi-ip2', function(){
        let email = 'foo@e10.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 a/0 -all"}],"e2.example.com":[{"A":"1.1.1.1"},{"AAAA":"1234::2"},{"SPF":"v=spf1 a/0 -all"}],"e2a.example.com":[{"AAAA":"1234::1"},{"SPF":"v=spf1 a//0 -all"}],"e2b.example.com":[{"A":"1.1.1.1"},{"SPF":"v=spf1 a//0 -all"}],"ipv6.example.com":[{"AAAA":"1234::1"},{"A":"1.1.1.1"},{"SPF":"v=spf1 a -all"}],"e3.example.com":[{"SPF":"v=spf1 a:foo.example.com\u0000"}],"e4.example.com":[{"SPF":"v=spf1 a:111.222.33.44"}],"e5.example.com":[{"SPF":"v=spf1 a:abc.123"}],"e5a.example.com":[{"SPF":"v=spf1 a:museum"}],"e5b.example.com":[{"SPF":"v=spf1 a:museum."}],"e6.example.com":[{"SPF":"v=spf1 a//33 -all"}],"e6a.example.com":[{"SPF":"v=spf1 a/33 -all"}],"e7.example.com":[{"SPF":"v=spf1 a//129 -all"}],"e8.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24//64 -all"}],"e8e.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24/64 -all"}],"e8a.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24 -all"}],"e8b.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a//64 -all"}],"e9.example.com":[{"SPF":"v=spf1 a:example.com:8080"}],"e10.example.com":[{"SPF":"v=spf1 a:foo.example.com/24"}],"foo.example.com":[{"A":"1.1.1.1"},{"A":"1.2.3.5"}],"e11.example.com":[{"SPF":"v=spf1 a:foo:bar/baz.example.com"}],"foo:bar/baz.example.com":[{"A":"1.2.3.4"}],"e12.example.com":[{"SPF":"v=spf1 a:example.-com"}],"e13.example.com":[{"SPF":"v=spf1 a:"}],"e14.example.com":[{"SPF":"v=spf1 a:foo.example.xn--zckzah -all"}],"foo.example.xn--zckzah":[{"A":"1.2.3.4"}]}, failOnNoFake: true, helo: "mail.example.com"}
        let promise = spf.check_host('1.2.3.4', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'PASS');
        });
      });
      it('a-bad-domain', function(){
        let email = 'foo@e9.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 a/0 -all"}],"e2.example.com":[{"A":"1.1.1.1"},{"AAAA":"1234::2"},{"SPF":"v=spf1 a/0 -all"}],"e2a.example.com":[{"AAAA":"1234::1"},{"SPF":"v=spf1 a//0 -all"}],"e2b.example.com":[{"A":"1.1.1.1"},{"SPF":"v=spf1 a//0 -all"}],"ipv6.example.com":[{"AAAA":"1234::1"},{"A":"1.1.1.1"},{"SPF":"v=spf1 a -all"}],"e3.example.com":[{"SPF":"v=spf1 a:foo.example.com\u0000"}],"e4.example.com":[{"SPF":"v=spf1 a:111.222.33.44"}],"e5.example.com":[{"SPF":"v=spf1 a:abc.123"}],"e5a.example.com":[{"SPF":"v=spf1 a:museum"}],"e5b.example.com":[{"SPF":"v=spf1 a:museum."}],"e6.example.com":[{"SPF":"v=spf1 a//33 -all"}],"e6a.example.com":[{"SPF":"v=spf1 a/33 -all"}],"e7.example.com":[{"SPF":"v=spf1 a//129 -all"}],"e8.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24//64 -all"}],"e8e.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24/64 -all"}],"e8a.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24 -all"}],"e8b.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a//64 -all"}],"e9.example.com":[{"SPF":"v=spf1 a:example.com:8080"}],"e10.example.com":[{"SPF":"v=spf1 a:foo.example.com/24"}],"foo.example.com":[{"A":"1.1.1.1"},{"A":"1.2.3.5"}],"e11.example.com":[{"SPF":"v=spf1 a:foo:bar/baz.example.com"}],"foo:bar/baz.example.com":[{"A":"1.2.3.4"}],"e12.example.com":[{"SPF":"v=spf1 a:example.-com"}],"e13.example.com":[{"SPF":"v=spf1 a:"}],"e14.example.com":[{"SPF":"v=spf1 a:foo.example.xn--zckzah -all"}],"foo.example.xn--zckzah":[{"A":"1.2.3.4"}]}, failOnNoFake: true, helo: "mail.example.com"}
        let promise = spf.check_host('1.2.3.4', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'PERMERROR');
        });
      });
      it('a-nxdomain', function(){
        let email = 'foo@e1.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 a/0 -all"}],"e2.example.com":[{"A":"1.1.1.1"},{"AAAA":"1234::2"},{"SPF":"v=spf1 a/0 -all"}],"e2a.example.com":[{"AAAA":"1234::1"},{"SPF":"v=spf1 a//0 -all"}],"e2b.example.com":[{"A":"1.1.1.1"},{"SPF":"v=spf1 a//0 -all"}],"ipv6.example.com":[{"AAAA":"1234::1"},{"A":"1.1.1.1"},{"SPF":"v=spf1 a -all"}],"e3.example.com":[{"SPF":"v=spf1 a:foo.example.com\u0000"}],"e4.example.com":[{"SPF":"v=spf1 a:111.222.33.44"}],"e5.example.com":[{"SPF":"v=spf1 a:abc.123"}],"e5a.example.com":[{"SPF":"v=spf1 a:museum"}],"e5b.example.com":[{"SPF":"v=spf1 a:museum."}],"e6.example.com":[{"SPF":"v=spf1 a//33 -all"}],"e6a.example.com":[{"SPF":"v=spf1 a/33 -all"}],"e7.example.com":[{"SPF":"v=spf1 a//129 -all"}],"e8.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24//64 -all"}],"e8e.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24/64 -all"}],"e8a.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24 -all"}],"e8b.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a//64 -all"}],"e9.example.com":[{"SPF":"v=spf1 a:example.com:8080"}],"e10.example.com":[{"SPF":"v=spf1 a:foo.example.com/24"}],"foo.example.com":[{"A":"1.1.1.1"},{"A":"1.2.3.5"}],"e11.example.com":[{"SPF":"v=spf1 a:foo:bar/baz.example.com"}],"foo:bar/baz.example.com":[{"A":"1.2.3.4"}],"e12.example.com":[{"SPF":"v=spf1 a:example.-com"}],"e13.example.com":[{"SPF":"v=spf1 a:"}],"e14.example.com":[{"SPF":"v=spf1 a:foo.example.xn--zckzah -all"}],"foo.example.xn--zckzah":[{"A":"1.2.3.4"}]}, failOnNoFake: true, helo: "mail.example.com"}
        let promise = spf.check_host('1.2.3.4', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'FAIL');
        });
      });
      it('a-cidr4-0', function(){
        let email = 'foo@e2.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 a/0 -all"}],"e2.example.com":[{"A":"1.1.1.1"},{"AAAA":"1234::2"},{"SPF":"v=spf1 a/0 -all"}],"e2a.example.com":[{"AAAA":"1234::1"},{"SPF":"v=spf1 a//0 -all"}],"e2b.example.com":[{"A":"1.1.1.1"},{"SPF":"v=spf1 a//0 -all"}],"ipv6.example.com":[{"AAAA":"1234::1"},{"A":"1.1.1.1"},{"SPF":"v=spf1 a -all"}],"e3.example.com":[{"SPF":"v=spf1 a:foo.example.com\u0000"}],"e4.example.com":[{"SPF":"v=spf1 a:111.222.33.44"}],"e5.example.com":[{"SPF":"v=spf1 a:abc.123"}],"e5a.example.com":[{"SPF":"v=spf1 a:museum"}],"e5b.example.com":[{"SPF":"v=spf1 a:museum."}],"e6.example.com":[{"SPF":"v=spf1 a//33 -all"}],"e6a.example.com":[{"SPF":"v=spf1 a/33 -all"}],"e7.example.com":[{"SPF":"v=spf1 a//129 -all"}],"e8.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24//64 -all"}],"e8e.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24/64 -all"}],"e8a.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24 -all"}],"e8b.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a//64 -all"}],"e9.example.com":[{"SPF":"v=spf1 a:example.com:8080"}],"e10.example.com":[{"SPF":"v=spf1 a:foo.example.com/24"}],"foo.example.com":[{"A":"1.1.1.1"},{"A":"1.2.3.5"}],"e11.example.com":[{"SPF":"v=spf1 a:foo:bar/baz.example.com"}],"foo:bar/baz.example.com":[{"A":"1.2.3.4"}],"e12.example.com":[{"SPF":"v=spf1 a:example.-com"}],"e13.example.com":[{"SPF":"v=spf1 a:"}],"e14.example.com":[{"SPF":"v=spf1 a:foo.example.xn--zckzah -all"}],"foo.example.xn--zckzah":[{"A":"1.2.3.4"}]}, failOnNoFake: true, helo: "mail.example.com"}
        let promise = spf.check_host('1.2.3.4', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'PASS');
        });
      });
      it('a-cidr4-0-ip6', function(){
        let email = 'foo@e2.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 a/0 -all"}],"e2.example.com":[{"A":"1.1.1.1"},{"AAAA":"1234::2"},{"SPF":"v=spf1 a/0 -all"}],"e2a.example.com":[{"AAAA":"1234::1"},{"SPF":"v=spf1 a//0 -all"}],"e2b.example.com":[{"A":"1.1.1.1"},{"SPF":"v=spf1 a//0 -all"}],"ipv6.example.com":[{"AAAA":"1234::1"},{"A":"1.1.1.1"},{"SPF":"v=spf1 a -all"}],"e3.example.com":[{"SPF":"v=spf1 a:foo.example.com\u0000"}],"e4.example.com":[{"SPF":"v=spf1 a:111.222.33.44"}],"e5.example.com":[{"SPF":"v=spf1 a:abc.123"}],"e5a.example.com":[{"SPF":"v=spf1 a:museum"}],"e5b.example.com":[{"SPF":"v=spf1 a:museum."}],"e6.example.com":[{"SPF":"v=spf1 a//33 -all"}],"e6a.example.com":[{"SPF":"v=spf1 a/33 -all"}],"e7.example.com":[{"SPF":"v=spf1 a//129 -all"}],"e8.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24//64 -all"}],"e8e.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24/64 -all"}],"e8a.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24 -all"}],"e8b.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a//64 -all"}],"e9.example.com":[{"SPF":"v=spf1 a:example.com:8080"}],"e10.example.com":[{"SPF":"v=spf1 a:foo.example.com/24"}],"foo.example.com":[{"A":"1.1.1.1"},{"A":"1.2.3.5"}],"e11.example.com":[{"SPF":"v=spf1 a:foo:bar/baz.example.com"}],"foo:bar/baz.example.com":[{"A":"1.2.3.4"}],"e12.example.com":[{"SPF":"v=spf1 a:example.-com"}],"e13.example.com":[{"SPF":"v=spf1 a:"}],"e14.example.com":[{"SPF":"v=spf1 a:foo.example.xn--zckzah -all"}],"foo.example.xn--zckzah":[{"A":"1.2.3.4"}]}, failOnNoFake: true, helo: "mail.example.com"}
        let promise = spf.check_host('1234::1', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'FAIL');
        });
      });
      it('a-cidr6-0-ip4', function(){
        let email = 'foo@e2a.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 a/0 -all"}],"e2.example.com":[{"A":"1.1.1.1"},{"AAAA":"1234::2"},{"SPF":"v=spf1 a/0 -all"}],"e2a.example.com":[{"AAAA":"1234::1"},{"SPF":"v=spf1 a//0 -all"}],"e2b.example.com":[{"A":"1.1.1.1"},{"SPF":"v=spf1 a//0 -all"}],"ipv6.example.com":[{"AAAA":"1234::1"},{"A":"1.1.1.1"},{"SPF":"v=spf1 a -all"}],"e3.example.com":[{"SPF":"v=spf1 a:foo.example.com\u0000"}],"e4.example.com":[{"SPF":"v=spf1 a:111.222.33.44"}],"e5.example.com":[{"SPF":"v=spf1 a:abc.123"}],"e5a.example.com":[{"SPF":"v=spf1 a:museum"}],"e5b.example.com":[{"SPF":"v=spf1 a:museum."}],"e6.example.com":[{"SPF":"v=spf1 a//33 -all"}],"e6a.example.com":[{"SPF":"v=spf1 a/33 -all"}],"e7.example.com":[{"SPF":"v=spf1 a//129 -all"}],"e8.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24//64 -all"}],"e8e.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24/64 -all"}],"e8a.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24 -all"}],"e8b.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a//64 -all"}],"e9.example.com":[{"SPF":"v=spf1 a:example.com:8080"}],"e10.example.com":[{"SPF":"v=spf1 a:foo.example.com/24"}],"foo.example.com":[{"A":"1.1.1.1"},{"A":"1.2.3.5"}],"e11.example.com":[{"SPF":"v=spf1 a:foo:bar/baz.example.com"}],"foo:bar/baz.example.com":[{"A":"1.2.3.4"}],"e12.example.com":[{"SPF":"v=spf1 a:example.-com"}],"e13.example.com":[{"SPF":"v=spf1 a:"}],"e14.example.com":[{"SPF":"v=spf1 a:foo.example.xn--zckzah -all"}],"foo.example.xn--zckzah":[{"A":"1.2.3.4"}]}, failOnNoFake: true, helo: "mail.example.com"}
        let promise = spf.check_host('1.2.3.4', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'FAIL');
        });
      });
      it('a-cidr6-0-ip4mapped', function(){
        let email = 'foo@e2a.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 a/0 -all"}],"e2.example.com":[{"A":"1.1.1.1"},{"AAAA":"1234::2"},{"SPF":"v=spf1 a/0 -all"}],"e2a.example.com":[{"AAAA":"1234::1"},{"SPF":"v=spf1 a//0 -all"}],"e2b.example.com":[{"A":"1.1.1.1"},{"SPF":"v=spf1 a//0 -all"}],"ipv6.example.com":[{"AAAA":"1234::1"},{"A":"1.1.1.1"},{"SPF":"v=spf1 a -all"}],"e3.example.com":[{"SPF":"v=spf1 a:foo.example.com\u0000"}],"e4.example.com":[{"SPF":"v=spf1 a:111.222.33.44"}],"e5.example.com":[{"SPF":"v=spf1 a:abc.123"}],"e5a.example.com":[{"SPF":"v=spf1 a:museum"}],"e5b.example.com":[{"SPF":"v=spf1 a:museum."}],"e6.example.com":[{"SPF":"v=spf1 a//33 -all"}],"e6a.example.com":[{"SPF":"v=spf1 a/33 -all"}],"e7.example.com":[{"SPF":"v=spf1 a//129 -all"}],"e8.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24//64 -all"}],"e8e.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24/64 -all"}],"e8a.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24 -all"}],"e8b.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a//64 -all"}],"e9.example.com":[{"SPF":"v=spf1 a:example.com:8080"}],"e10.example.com":[{"SPF":"v=spf1 a:foo.example.com/24"}],"foo.example.com":[{"A":"1.1.1.1"},{"A":"1.2.3.5"}],"e11.example.com":[{"SPF":"v=spf1 a:foo:bar/baz.example.com"}],"foo:bar/baz.example.com":[{"A":"1.2.3.4"}],"e12.example.com":[{"SPF":"v=spf1 a:example.-com"}],"e13.example.com":[{"SPF":"v=spf1 a:"}],"e14.example.com":[{"SPF":"v=spf1 a:foo.example.xn--zckzah -all"}],"foo.example.xn--zckzah":[{"A":"1.2.3.4"}]}, failOnNoFake: true, helo: "mail.example.com"}
        let promise = spf.check_host('::FFFF:1.2.3.4', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'FAIL');
        });
      });
      it('a-cidr6-0-ip6', function(){
        let email = 'foo@e2a.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 a/0 -all"}],"e2.example.com":[{"A":"1.1.1.1"},{"AAAA":"1234::2"},{"SPF":"v=spf1 a/0 -all"}],"e2a.example.com":[{"AAAA":"1234::1"},{"SPF":"v=spf1 a//0 -all"}],"e2b.example.com":[{"A":"1.1.1.1"},{"SPF":"v=spf1 a//0 -all"}],"ipv6.example.com":[{"AAAA":"1234::1"},{"A":"1.1.1.1"},{"SPF":"v=spf1 a -all"}],"e3.example.com":[{"SPF":"v=spf1 a:foo.example.com\u0000"}],"e4.example.com":[{"SPF":"v=spf1 a:111.222.33.44"}],"e5.example.com":[{"SPF":"v=spf1 a:abc.123"}],"e5a.example.com":[{"SPF":"v=spf1 a:museum"}],"e5b.example.com":[{"SPF":"v=spf1 a:museum."}],"e6.example.com":[{"SPF":"v=spf1 a//33 -all"}],"e6a.example.com":[{"SPF":"v=spf1 a/33 -all"}],"e7.example.com":[{"SPF":"v=spf1 a//129 -all"}],"e8.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24//64 -all"}],"e8e.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24/64 -all"}],"e8a.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24 -all"}],"e8b.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a//64 -all"}],"e9.example.com":[{"SPF":"v=spf1 a:example.com:8080"}],"e10.example.com":[{"SPF":"v=spf1 a:foo.example.com/24"}],"foo.example.com":[{"A":"1.1.1.1"},{"A":"1.2.3.5"}],"e11.example.com":[{"SPF":"v=spf1 a:foo:bar/baz.example.com"}],"foo:bar/baz.example.com":[{"A":"1.2.3.4"}],"e12.example.com":[{"SPF":"v=spf1 a:example.-com"}],"e13.example.com":[{"SPF":"v=spf1 a:"}],"e14.example.com":[{"SPF":"v=spf1 a:foo.example.xn--zckzah -all"}],"foo.example.xn--zckzah":[{"A":"1.2.3.4"}]}, failOnNoFake: true, helo: "mail.example.com"}
        let promise = spf.check_host('1234::1', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'PASS');
        });
      });
      it('a-ip6-dualstack', function(){
        let email = 'foo@ipv6.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 a/0 -all"}],"e2.example.com":[{"A":"1.1.1.1"},{"AAAA":"1234::2"},{"SPF":"v=spf1 a/0 -all"}],"e2a.example.com":[{"AAAA":"1234::1"},{"SPF":"v=spf1 a//0 -all"}],"e2b.example.com":[{"A":"1.1.1.1"},{"SPF":"v=spf1 a//0 -all"}],"ipv6.example.com":[{"AAAA":"1234::1"},{"A":"1.1.1.1"},{"SPF":"v=spf1 a -all"}],"e3.example.com":[{"SPF":"v=spf1 a:foo.example.com\u0000"}],"e4.example.com":[{"SPF":"v=spf1 a:111.222.33.44"}],"e5.example.com":[{"SPF":"v=spf1 a:abc.123"}],"e5a.example.com":[{"SPF":"v=spf1 a:museum"}],"e5b.example.com":[{"SPF":"v=spf1 a:museum."}],"e6.example.com":[{"SPF":"v=spf1 a//33 -all"}],"e6a.example.com":[{"SPF":"v=spf1 a/33 -all"}],"e7.example.com":[{"SPF":"v=spf1 a//129 -all"}],"e8.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24//64 -all"}],"e8e.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24/64 -all"}],"e8a.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24 -all"}],"e8b.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a//64 -all"}],"e9.example.com":[{"SPF":"v=spf1 a:example.com:8080"}],"e10.example.com":[{"SPF":"v=spf1 a:foo.example.com/24"}],"foo.example.com":[{"A":"1.1.1.1"},{"A":"1.2.3.5"}],"e11.example.com":[{"SPF":"v=spf1 a:foo:bar/baz.example.com"}],"foo:bar/baz.example.com":[{"A":"1.2.3.4"}],"e12.example.com":[{"SPF":"v=spf1 a:example.-com"}],"e13.example.com":[{"SPF":"v=spf1 a:"}],"e14.example.com":[{"SPF":"v=spf1 a:foo.example.xn--zckzah -all"}],"foo.example.xn--zckzah":[{"A":"1.2.3.4"}]}, failOnNoFake: true, helo: "mail.example.com"}
        let promise = spf.check_host('1234::1', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'PASS');
        });
      });
      it('a-cidr6-0-nxdomain', function(){
        let email = 'foo@e2b.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 a/0 -all"}],"e2.example.com":[{"A":"1.1.1.1"},{"AAAA":"1234::2"},{"SPF":"v=spf1 a/0 -all"}],"e2a.example.com":[{"AAAA":"1234::1"},{"SPF":"v=spf1 a//0 -all"}],"e2b.example.com":[{"A":"1.1.1.1"},{"SPF":"v=spf1 a//0 -all"}],"ipv6.example.com":[{"AAAA":"1234::1"},{"A":"1.1.1.1"},{"SPF":"v=spf1 a -all"}],"e3.example.com":[{"SPF":"v=spf1 a:foo.example.com\u0000"}],"e4.example.com":[{"SPF":"v=spf1 a:111.222.33.44"}],"e5.example.com":[{"SPF":"v=spf1 a:abc.123"}],"e5a.example.com":[{"SPF":"v=spf1 a:museum"}],"e5b.example.com":[{"SPF":"v=spf1 a:museum."}],"e6.example.com":[{"SPF":"v=spf1 a//33 -all"}],"e6a.example.com":[{"SPF":"v=spf1 a/33 -all"}],"e7.example.com":[{"SPF":"v=spf1 a//129 -all"}],"e8.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24//64 -all"}],"e8e.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24/64 -all"}],"e8a.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24 -all"}],"e8b.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a//64 -all"}],"e9.example.com":[{"SPF":"v=spf1 a:example.com:8080"}],"e10.example.com":[{"SPF":"v=spf1 a:foo.example.com/24"}],"foo.example.com":[{"A":"1.1.1.1"},{"A":"1.2.3.5"}],"e11.example.com":[{"SPF":"v=spf1 a:foo:bar/baz.example.com"}],"foo:bar/baz.example.com":[{"A":"1.2.3.4"}],"e12.example.com":[{"SPF":"v=spf1 a:example.-com"}],"e13.example.com":[{"SPF":"v=spf1 a:"}],"e14.example.com":[{"SPF":"v=spf1 a:foo.example.xn--zckzah -all"}],"foo.example.xn--zckzah":[{"A":"1.2.3.4"}]}, failOnNoFake: true, helo: "mail.example.com"}
        let promise = spf.check_host('1234::1', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'FAIL');
        });
      });
      it('a-null', function(){
        let email = 'foo@e3.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 a/0 -all"}],"e2.example.com":[{"A":"1.1.1.1"},{"AAAA":"1234::2"},{"SPF":"v=spf1 a/0 -all"}],"e2a.example.com":[{"AAAA":"1234::1"},{"SPF":"v=spf1 a//0 -all"}],"e2b.example.com":[{"A":"1.1.1.1"},{"SPF":"v=spf1 a//0 -all"}],"ipv6.example.com":[{"AAAA":"1234::1"},{"A":"1.1.1.1"},{"SPF":"v=spf1 a -all"}],"e3.example.com":[{"SPF":"v=spf1 a:foo.example.com\u0000"}],"e4.example.com":[{"SPF":"v=spf1 a:111.222.33.44"}],"e5.example.com":[{"SPF":"v=spf1 a:abc.123"}],"e5a.example.com":[{"SPF":"v=spf1 a:museum"}],"e5b.example.com":[{"SPF":"v=spf1 a:museum."}],"e6.example.com":[{"SPF":"v=spf1 a//33 -all"}],"e6a.example.com":[{"SPF":"v=spf1 a/33 -all"}],"e7.example.com":[{"SPF":"v=spf1 a//129 -all"}],"e8.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24//64 -all"}],"e8e.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24/64 -all"}],"e8a.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24 -all"}],"e8b.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a//64 -all"}],"e9.example.com":[{"SPF":"v=spf1 a:example.com:8080"}],"e10.example.com":[{"SPF":"v=spf1 a:foo.example.com/24"}],"foo.example.com":[{"A":"1.1.1.1"},{"A":"1.2.3.5"}],"e11.example.com":[{"SPF":"v=spf1 a:foo:bar/baz.example.com"}],"foo:bar/baz.example.com":[{"A":"1.2.3.4"}],"e12.example.com":[{"SPF":"v=spf1 a:example.-com"}],"e13.example.com":[{"SPF":"v=spf1 a:"}],"e14.example.com":[{"SPF":"v=spf1 a:foo.example.xn--zckzah -all"}],"foo.example.xn--zckzah":[{"A":"1.2.3.4"}]}, failOnNoFake: true, helo: "mail.example.com"}
        let promise = spf.check_host('1.2.3.5', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'PERMERROR');
        });
      });
      it('a-numeric', function(){
        let email = 'foo@e4.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 a/0 -all"}],"e2.example.com":[{"A":"1.1.1.1"},{"AAAA":"1234::2"},{"SPF":"v=spf1 a/0 -all"}],"e2a.example.com":[{"AAAA":"1234::1"},{"SPF":"v=spf1 a//0 -all"}],"e2b.example.com":[{"A":"1.1.1.1"},{"SPF":"v=spf1 a//0 -all"}],"ipv6.example.com":[{"AAAA":"1234::1"},{"A":"1.1.1.1"},{"SPF":"v=spf1 a -all"}],"e3.example.com":[{"SPF":"v=spf1 a:foo.example.com\u0000"}],"e4.example.com":[{"SPF":"v=spf1 a:111.222.33.44"}],"e5.example.com":[{"SPF":"v=spf1 a:abc.123"}],"e5a.example.com":[{"SPF":"v=spf1 a:museum"}],"e5b.example.com":[{"SPF":"v=spf1 a:museum."}],"e6.example.com":[{"SPF":"v=spf1 a//33 -all"}],"e6a.example.com":[{"SPF":"v=spf1 a/33 -all"}],"e7.example.com":[{"SPF":"v=spf1 a//129 -all"}],"e8.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24//64 -all"}],"e8e.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24/64 -all"}],"e8a.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24 -all"}],"e8b.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a//64 -all"}],"e9.example.com":[{"SPF":"v=spf1 a:example.com:8080"}],"e10.example.com":[{"SPF":"v=spf1 a:foo.example.com/24"}],"foo.example.com":[{"A":"1.1.1.1"},{"A":"1.2.3.5"}],"e11.example.com":[{"SPF":"v=spf1 a:foo:bar/baz.example.com"}],"foo:bar/baz.example.com":[{"A":"1.2.3.4"}],"e12.example.com":[{"SPF":"v=spf1 a:example.-com"}],"e13.example.com":[{"SPF":"v=spf1 a:"}],"e14.example.com":[{"SPF":"v=spf1 a:foo.example.xn--zckzah -all"}],"foo.example.xn--zckzah":[{"A":"1.2.3.4"}]}, failOnNoFake: true, helo: "mail.example.com"}
        let promise = spf.check_host('1.2.3.4', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'PERMERROR');
        });
      });
      it('a-numeric-toplabel', function(){
        let email = 'foo@e5.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 a/0 -all"}],"e2.example.com":[{"A":"1.1.1.1"},{"AAAA":"1234::2"},{"SPF":"v=spf1 a/0 -all"}],"e2a.example.com":[{"AAAA":"1234::1"},{"SPF":"v=spf1 a//0 -all"}],"e2b.example.com":[{"A":"1.1.1.1"},{"SPF":"v=spf1 a//0 -all"}],"ipv6.example.com":[{"AAAA":"1234::1"},{"A":"1.1.1.1"},{"SPF":"v=spf1 a -all"}],"e3.example.com":[{"SPF":"v=spf1 a:foo.example.com\u0000"}],"e4.example.com":[{"SPF":"v=spf1 a:111.222.33.44"}],"e5.example.com":[{"SPF":"v=spf1 a:abc.123"}],"e5a.example.com":[{"SPF":"v=spf1 a:museum"}],"e5b.example.com":[{"SPF":"v=spf1 a:museum."}],"e6.example.com":[{"SPF":"v=spf1 a//33 -all"}],"e6a.example.com":[{"SPF":"v=spf1 a/33 -all"}],"e7.example.com":[{"SPF":"v=spf1 a//129 -all"}],"e8.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24//64 -all"}],"e8e.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24/64 -all"}],"e8a.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24 -all"}],"e8b.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a//64 -all"}],"e9.example.com":[{"SPF":"v=spf1 a:example.com:8080"}],"e10.example.com":[{"SPF":"v=spf1 a:foo.example.com/24"}],"foo.example.com":[{"A":"1.1.1.1"},{"A":"1.2.3.5"}],"e11.example.com":[{"SPF":"v=spf1 a:foo:bar/baz.example.com"}],"foo:bar/baz.example.com":[{"A":"1.2.3.4"}],"e12.example.com":[{"SPF":"v=spf1 a:example.-com"}],"e13.example.com":[{"SPF":"v=spf1 a:"}],"e14.example.com":[{"SPF":"v=spf1 a:foo.example.xn--zckzah -all"}],"foo.example.xn--zckzah":[{"A":"1.2.3.4"}]}, failOnNoFake: true, helo: "mail.example.com"}
        let promise = spf.check_host('1.2.3.4', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'PERMERROR');
        });
      });
      it('a-dash-in-toplabel', function(){
        let email = 'foo@e14.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 a/0 -all"}],"e2.example.com":[{"A":"1.1.1.1"},{"AAAA":"1234::2"},{"SPF":"v=spf1 a/0 -all"}],"e2a.example.com":[{"AAAA":"1234::1"},{"SPF":"v=spf1 a//0 -all"}],"e2b.example.com":[{"A":"1.1.1.1"},{"SPF":"v=spf1 a//0 -all"}],"ipv6.example.com":[{"AAAA":"1234::1"},{"A":"1.1.1.1"},{"SPF":"v=spf1 a -all"}],"e3.example.com":[{"SPF":"v=spf1 a:foo.example.com\u0000"}],"e4.example.com":[{"SPF":"v=spf1 a:111.222.33.44"}],"e5.example.com":[{"SPF":"v=spf1 a:abc.123"}],"e5a.example.com":[{"SPF":"v=spf1 a:museum"}],"e5b.example.com":[{"SPF":"v=spf1 a:museum."}],"e6.example.com":[{"SPF":"v=spf1 a//33 -all"}],"e6a.example.com":[{"SPF":"v=spf1 a/33 -all"}],"e7.example.com":[{"SPF":"v=spf1 a//129 -all"}],"e8.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24//64 -all"}],"e8e.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24/64 -all"}],"e8a.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24 -all"}],"e8b.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a//64 -all"}],"e9.example.com":[{"SPF":"v=spf1 a:example.com:8080"}],"e10.example.com":[{"SPF":"v=spf1 a:foo.example.com/24"}],"foo.example.com":[{"A":"1.1.1.1"},{"A":"1.2.3.5"}],"e11.example.com":[{"SPF":"v=spf1 a:foo:bar/baz.example.com"}],"foo:bar/baz.example.com":[{"A":"1.2.3.4"}],"e12.example.com":[{"SPF":"v=spf1 a:example.-com"}],"e13.example.com":[{"SPF":"v=spf1 a:"}],"e14.example.com":[{"SPF":"v=spf1 a:foo.example.xn--zckzah -all"}],"foo.example.xn--zckzah":[{"A":"1.2.3.4"}]}, failOnNoFake: true, helo: "mail.example.com"}
        let promise = spf.check_host('1.2.3.4', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'PASS');
        });
      });
      it('a-bad-toplabel', function(){
        let email = 'foo@e12.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 a/0 -all"}],"e2.example.com":[{"A":"1.1.1.1"},{"AAAA":"1234::2"},{"SPF":"v=spf1 a/0 -all"}],"e2a.example.com":[{"AAAA":"1234::1"},{"SPF":"v=spf1 a//0 -all"}],"e2b.example.com":[{"A":"1.1.1.1"},{"SPF":"v=spf1 a//0 -all"}],"ipv6.example.com":[{"AAAA":"1234::1"},{"A":"1.1.1.1"},{"SPF":"v=spf1 a -all"}],"e3.example.com":[{"SPF":"v=spf1 a:foo.example.com\u0000"}],"e4.example.com":[{"SPF":"v=spf1 a:111.222.33.44"}],"e5.example.com":[{"SPF":"v=spf1 a:abc.123"}],"e5a.example.com":[{"SPF":"v=spf1 a:museum"}],"e5b.example.com":[{"SPF":"v=spf1 a:museum."}],"e6.example.com":[{"SPF":"v=spf1 a//33 -all"}],"e6a.example.com":[{"SPF":"v=spf1 a/33 -all"}],"e7.example.com":[{"SPF":"v=spf1 a//129 -all"}],"e8.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24//64 -all"}],"e8e.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24/64 -all"}],"e8a.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24 -all"}],"e8b.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a//64 -all"}],"e9.example.com":[{"SPF":"v=spf1 a:example.com:8080"}],"e10.example.com":[{"SPF":"v=spf1 a:foo.example.com/24"}],"foo.example.com":[{"A":"1.1.1.1"},{"A":"1.2.3.5"}],"e11.example.com":[{"SPF":"v=spf1 a:foo:bar/baz.example.com"}],"foo:bar/baz.example.com":[{"A":"1.2.3.4"}],"e12.example.com":[{"SPF":"v=spf1 a:example.-com"}],"e13.example.com":[{"SPF":"v=spf1 a:"}],"e14.example.com":[{"SPF":"v=spf1 a:foo.example.xn--zckzah -all"}],"foo.example.xn--zckzah":[{"A":"1.2.3.4"}]}, failOnNoFake: true, helo: "mail.example.com"}
        let promise = spf.check_host('1.2.3.4', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'PERMERROR');
        });
      });
      it('a-only-toplabel', function(){
        let email = 'foo@e5a.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 a/0 -all"}],"e2.example.com":[{"A":"1.1.1.1"},{"AAAA":"1234::2"},{"SPF":"v=spf1 a/0 -all"}],"e2a.example.com":[{"AAAA":"1234::1"},{"SPF":"v=spf1 a//0 -all"}],"e2b.example.com":[{"A":"1.1.1.1"},{"SPF":"v=spf1 a//0 -all"}],"ipv6.example.com":[{"AAAA":"1234::1"},{"A":"1.1.1.1"},{"SPF":"v=spf1 a -all"}],"e3.example.com":[{"SPF":"v=spf1 a:foo.example.com\u0000"}],"e4.example.com":[{"SPF":"v=spf1 a:111.222.33.44"}],"e5.example.com":[{"SPF":"v=spf1 a:abc.123"}],"e5a.example.com":[{"SPF":"v=spf1 a:museum"}],"e5b.example.com":[{"SPF":"v=spf1 a:museum."}],"e6.example.com":[{"SPF":"v=spf1 a//33 -all"}],"e6a.example.com":[{"SPF":"v=spf1 a/33 -all"}],"e7.example.com":[{"SPF":"v=spf1 a//129 -all"}],"e8.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24//64 -all"}],"e8e.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24/64 -all"}],"e8a.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24 -all"}],"e8b.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a//64 -all"}],"e9.example.com":[{"SPF":"v=spf1 a:example.com:8080"}],"e10.example.com":[{"SPF":"v=spf1 a:foo.example.com/24"}],"foo.example.com":[{"A":"1.1.1.1"},{"A":"1.2.3.5"}],"e11.example.com":[{"SPF":"v=spf1 a:foo:bar/baz.example.com"}],"foo:bar/baz.example.com":[{"A":"1.2.3.4"}],"e12.example.com":[{"SPF":"v=spf1 a:example.-com"}],"e13.example.com":[{"SPF":"v=spf1 a:"}],"e14.example.com":[{"SPF":"v=spf1 a:foo.example.xn--zckzah -all"}],"foo.example.xn--zckzah":[{"A":"1.2.3.4"}]}, failOnNoFake: true, helo: "mail.example.com"}
        let promise = spf.check_host('1.2.3.4', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'PERMERROR');
        });
      });
      it('a-only-toplabel-trailing-dot', function(){
        let email = 'foo@e5b.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 a/0 -all"}],"e2.example.com":[{"A":"1.1.1.1"},{"AAAA":"1234::2"},{"SPF":"v=spf1 a/0 -all"}],"e2a.example.com":[{"AAAA":"1234::1"},{"SPF":"v=spf1 a//0 -all"}],"e2b.example.com":[{"A":"1.1.1.1"},{"SPF":"v=spf1 a//0 -all"}],"ipv6.example.com":[{"AAAA":"1234::1"},{"A":"1.1.1.1"},{"SPF":"v=spf1 a -all"}],"e3.example.com":[{"SPF":"v=spf1 a:foo.example.com\u0000"}],"e4.example.com":[{"SPF":"v=spf1 a:111.222.33.44"}],"e5.example.com":[{"SPF":"v=spf1 a:abc.123"}],"e5a.example.com":[{"SPF":"v=spf1 a:museum"}],"e5b.example.com":[{"SPF":"v=spf1 a:museum."}],"e6.example.com":[{"SPF":"v=spf1 a//33 -all"}],"e6a.example.com":[{"SPF":"v=spf1 a/33 -all"}],"e7.example.com":[{"SPF":"v=spf1 a//129 -all"}],"e8.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24//64 -all"}],"e8e.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24/64 -all"}],"e8a.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24 -all"}],"e8b.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a//64 -all"}],"e9.example.com":[{"SPF":"v=spf1 a:example.com:8080"}],"e10.example.com":[{"SPF":"v=spf1 a:foo.example.com/24"}],"foo.example.com":[{"A":"1.1.1.1"},{"A":"1.2.3.5"}],"e11.example.com":[{"SPF":"v=spf1 a:foo:bar/baz.example.com"}],"foo:bar/baz.example.com":[{"A":"1.2.3.4"}],"e12.example.com":[{"SPF":"v=spf1 a:example.-com"}],"e13.example.com":[{"SPF":"v=spf1 a:"}],"e14.example.com":[{"SPF":"v=spf1 a:foo.example.xn--zckzah -all"}],"foo.example.xn--zckzah":[{"A":"1.2.3.4"}]}, failOnNoFake: true, helo: "mail.example.com"}
        let promise = spf.check_host('1.2.3.4', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'PERMERROR');
        });
      });
      it('a-colon-domain', function(){
        let email = 'foo@e11.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 a/0 -all"}],"e2.example.com":[{"A":"1.1.1.1"},{"AAAA":"1234::2"},{"SPF":"v=spf1 a/0 -all"}],"e2a.example.com":[{"AAAA":"1234::1"},{"SPF":"v=spf1 a//0 -all"}],"e2b.example.com":[{"A":"1.1.1.1"},{"SPF":"v=spf1 a//0 -all"}],"ipv6.example.com":[{"AAAA":"1234::1"},{"A":"1.1.1.1"},{"SPF":"v=spf1 a -all"}],"e3.example.com":[{"SPF":"v=spf1 a:foo.example.com\u0000"}],"e4.example.com":[{"SPF":"v=spf1 a:111.222.33.44"}],"e5.example.com":[{"SPF":"v=spf1 a:abc.123"}],"e5a.example.com":[{"SPF":"v=spf1 a:museum"}],"e5b.example.com":[{"SPF":"v=spf1 a:museum."}],"e6.example.com":[{"SPF":"v=spf1 a//33 -all"}],"e6a.example.com":[{"SPF":"v=spf1 a/33 -all"}],"e7.example.com":[{"SPF":"v=spf1 a//129 -all"}],"e8.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24//64 -all"}],"e8e.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24/64 -all"}],"e8a.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24 -all"}],"e8b.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a//64 -all"}],"e9.example.com":[{"SPF":"v=spf1 a:example.com:8080"}],"e10.example.com":[{"SPF":"v=spf1 a:foo.example.com/24"}],"foo.example.com":[{"A":"1.1.1.1"},{"A":"1.2.3.5"}],"e11.example.com":[{"SPF":"v=spf1 a:foo:bar/baz.example.com"}],"foo:bar/baz.example.com":[{"A":"1.2.3.4"}],"e12.example.com":[{"SPF":"v=spf1 a:example.-com"}],"e13.example.com":[{"SPF":"v=spf1 a:"}],"e14.example.com":[{"SPF":"v=spf1 a:foo.example.xn--zckzah -all"}],"foo.example.xn--zckzah":[{"A":"1.2.3.4"}]}, failOnNoFake: true, helo: "mail.example.com"}
        let promise = spf.check_host('1.2.3.4', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'PASS');
        });
      });
      it('a-colon-domain-ip4mapped', function(){
        let email = 'foo@e11.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 a/0 -all"}],"e2.example.com":[{"A":"1.1.1.1"},{"AAAA":"1234::2"},{"SPF":"v=spf1 a/0 -all"}],"e2a.example.com":[{"AAAA":"1234::1"},{"SPF":"v=spf1 a//0 -all"}],"e2b.example.com":[{"A":"1.1.1.1"},{"SPF":"v=spf1 a//0 -all"}],"ipv6.example.com":[{"AAAA":"1234::1"},{"A":"1.1.1.1"},{"SPF":"v=spf1 a -all"}],"e3.example.com":[{"SPF":"v=spf1 a:foo.example.com\u0000"}],"e4.example.com":[{"SPF":"v=spf1 a:111.222.33.44"}],"e5.example.com":[{"SPF":"v=spf1 a:abc.123"}],"e5a.example.com":[{"SPF":"v=spf1 a:museum"}],"e5b.example.com":[{"SPF":"v=spf1 a:museum."}],"e6.example.com":[{"SPF":"v=spf1 a//33 -all"}],"e6a.example.com":[{"SPF":"v=spf1 a/33 -all"}],"e7.example.com":[{"SPF":"v=spf1 a//129 -all"}],"e8.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24//64 -all"}],"e8e.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24/64 -all"}],"e8a.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24 -all"}],"e8b.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a//64 -all"}],"e9.example.com":[{"SPF":"v=spf1 a:example.com:8080"}],"e10.example.com":[{"SPF":"v=spf1 a:foo.example.com/24"}],"foo.example.com":[{"A":"1.1.1.1"},{"A":"1.2.3.5"}],"e11.example.com":[{"SPF":"v=spf1 a:foo:bar/baz.example.com"}],"foo:bar/baz.example.com":[{"A":"1.2.3.4"}],"e12.example.com":[{"SPF":"v=spf1 a:example.-com"}],"e13.example.com":[{"SPF":"v=spf1 a:"}],"e14.example.com":[{"SPF":"v=spf1 a:foo.example.xn--zckzah -all"}],"foo.example.xn--zckzah":[{"A":"1.2.3.4"}]}, failOnNoFake: true, helo: "mail.example.com"}
        let promise = spf.check_host('::FFFF:1.2.3.4', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'PASS');
        });
      });
      it('a-empty-domain', function(){
        let email = 'foo@e13.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 a/0 -all"}],"e2.example.com":[{"A":"1.1.1.1"},{"AAAA":"1234::2"},{"SPF":"v=spf1 a/0 -all"}],"e2a.example.com":[{"AAAA":"1234::1"},{"SPF":"v=spf1 a//0 -all"}],"e2b.example.com":[{"A":"1.1.1.1"},{"SPF":"v=spf1 a//0 -all"}],"ipv6.example.com":[{"AAAA":"1234::1"},{"A":"1.1.1.1"},{"SPF":"v=spf1 a -all"}],"e3.example.com":[{"SPF":"v=spf1 a:foo.example.com\u0000"}],"e4.example.com":[{"SPF":"v=spf1 a:111.222.33.44"}],"e5.example.com":[{"SPF":"v=spf1 a:abc.123"}],"e5a.example.com":[{"SPF":"v=spf1 a:museum"}],"e5b.example.com":[{"SPF":"v=spf1 a:museum."}],"e6.example.com":[{"SPF":"v=spf1 a//33 -all"}],"e6a.example.com":[{"SPF":"v=spf1 a/33 -all"}],"e7.example.com":[{"SPF":"v=spf1 a//129 -all"}],"e8.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24//64 -all"}],"e8e.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24/64 -all"}],"e8a.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24 -all"}],"e8b.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a//64 -all"}],"e9.example.com":[{"SPF":"v=spf1 a:example.com:8080"}],"e10.example.com":[{"SPF":"v=spf1 a:foo.example.com/24"}],"foo.example.com":[{"A":"1.1.1.1"},{"A":"1.2.3.5"}],"e11.example.com":[{"SPF":"v=spf1 a:foo:bar/baz.example.com"}],"foo:bar/baz.example.com":[{"A":"1.2.3.4"}],"e12.example.com":[{"SPF":"v=spf1 a:example.-com"}],"e13.example.com":[{"SPF":"v=spf1 a:"}],"e14.example.com":[{"SPF":"v=spf1 a:foo.example.xn--zckzah -all"}],"foo.example.xn--zckzah":[{"A":"1.2.3.4"}]}, failOnNoFake: true, helo: "mail.example.com"}
        let promise = spf.check_host('1.2.3.4', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'PERMERROR');
        });
      });
    });
    describe('Include mechanism semantics and syntax', function(){
      it('include-fail', function(){
        let email = 'foo@e1.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"ip5.example.com":[{"SPF":"v=spf1 ip4:1.2.3.5 -all"}],"ip6.example.com":[{"SPF":"v=spf1 ip4:1.2.3.6 ~all"}],"ip7.example.com":[{"SPF":"v=spf1 ip4:1.2.3.7 ?all"}],"ip8.example.com":["TIMEOUT"],"erehwon.example.com":[{"TXT":"v=spfl am not an SPF record"}],"e1.example.com":[{"SPF":"v=spf1 include:ip5.example.com ~all"}],"e2.example.com":[{"SPF":"v=spf1 include:ip6.example.com all"}],"e3.example.com":[{"SPF":"v=spf1 include:ip7.example.com -all"}],"e4.example.com":[{"SPF":"v=spf1 include:ip8.example.com -all"}],"e5.example.com":[{"SPF":"v=spf1 include:e6.example.com -all"}],"e6.example.com":[{"SPF":"v=spf1 include +all"}],"e7.example.com":[{"SPF":"v=spf1 include:erehwon.example.com -all"}],"e8.example.com":[{"SPF":"v=spf1 include: -all"}],"e9.example.com":[{"SPF":"v=spf1 include:ip5.example.com/24 -all"}]}, failOnNoFake: true, helo: "mail.example.com"}
        let promise = spf.check_host('1.2.3.4', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'SOFTFAIL');
        });
      });
      it('include-softfail', function(){
        let email = 'foo@e2.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"ip5.example.com":[{"SPF":"v=spf1 ip4:1.2.3.5 -all"}],"ip6.example.com":[{"SPF":"v=spf1 ip4:1.2.3.6 ~all"}],"ip7.example.com":[{"SPF":"v=spf1 ip4:1.2.3.7 ?all"}],"ip8.example.com":["TIMEOUT"],"erehwon.example.com":[{"TXT":"v=spfl am not an SPF record"}],"e1.example.com":[{"SPF":"v=spf1 include:ip5.example.com ~all"}],"e2.example.com":[{"SPF":"v=spf1 include:ip6.example.com all"}],"e3.example.com":[{"SPF":"v=spf1 include:ip7.example.com -all"}],"e4.example.com":[{"SPF":"v=spf1 include:ip8.example.com -all"}],"e5.example.com":[{"SPF":"v=spf1 include:e6.example.com -all"}],"e6.example.com":[{"SPF":"v=spf1 include +all"}],"e7.example.com":[{"SPF":"v=spf1 include:erehwon.example.com -all"}],"e8.example.com":[{"SPF":"v=spf1 include: -all"}],"e9.example.com":[{"SPF":"v=spf1 include:ip5.example.com/24 -all"}]}, failOnNoFake: true, helo: "mail.example.com"}
        let promise = spf.check_host('1.2.3.4', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'PASS');
        });
      });
      it('include-neutral', function(){
        let email = 'foo@e3.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"ip5.example.com":[{"SPF":"v=spf1 ip4:1.2.3.5 -all"}],"ip6.example.com":[{"SPF":"v=spf1 ip4:1.2.3.6 ~all"}],"ip7.example.com":[{"SPF":"v=spf1 ip4:1.2.3.7 ?all"}],"ip8.example.com":["TIMEOUT"],"erehwon.example.com":[{"TXT":"v=spfl am not an SPF record"}],"e1.example.com":[{"SPF":"v=spf1 include:ip5.example.com ~all"}],"e2.example.com":[{"SPF":"v=spf1 include:ip6.example.com all"}],"e3.example.com":[{"SPF":"v=spf1 include:ip7.example.com -all"}],"e4.example.com":[{"SPF":"v=spf1 include:ip8.example.com -all"}],"e5.example.com":[{"SPF":"v=spf1 include:e6.example.com -all"}],"e6.example.com":[{"SPF":"v=spf1 include +all"}],"e7.example.com":[{"SPF":"v=spf1 include:erehwon.example.com -all"}],"e8.example.com":[{"SPF":"v=spf1 include: -all"}],"e9.example.com":[{"SPF":"v=spf1 include:ip5.example.com/24 -all"}]}, failOnNoFake: true, helo: "mail.example.com"}
        let promise = spf.check_host('1.2.3.4', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'FAIL');
        });
      });
      it('include-temperror', function(){
        let email = 'foo@e4.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"ip5.example.com":[{"SPF":"v=spf1 ip4:1.2.3.5 -all"}],"ip6.example.com":[{"SPF":"v=spf1 ip4:1.2.3.6 ~all"}],"ip7.example.com":[{"SPF":"v=spf1 ip4:1.2.3.7 ?all"}],"ip8.example.com":["TIMEOUT"],"erehwon.example.com":[{"TXT":"v=spfl am not an SPF record"}],"e1.example.com":[{"SPF":"v=spf1 include:ip5.example.com ~all"}],"e2.example.com":[{"SPF":"v=spf1 include:ip6.example.com all"}],"e3.example.com":[{"SPF":"v=spf1 include:ip7.example.com -all"}],"e4.example.com":[{"SPF":"v=spf1 include:ip8.example.com -all"}],"e5.example.com":[{"SPF":"v=spf1 include:e6.example.com -all"}],"e6.example.com":[{"SPF":"v=spf1 include +all"}],"e7.example.com":[{"SPF":"v=spf1 include:erehwon.example.com -all"}],"e8.example.com":[{"SPF":"v=spf1 include: -all"}],"e9.example.com":[{"SPF":"v=spf1 include:ip5.example.com/24 -all"}]}, failOnNoFake: true, helo: "mail.example.com"}
        let promise = spf.check_host('1.2.3.4', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'TEMPERROR');
        });
      });
      it('include-permerror', function(){
        let email = 'foo@e5.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"ip5.example.com":[{"SPF":"v=spf1 ip4:1.2.3.5 -all"}],"ip6.example.com":[{"SPF":"v=spf1 ip4:1.2.3.6 ~all"}],"ip7.example.com":[{"SPF":"v=spf1 ip4:1.2.3.7 ?all"}],"ip8.example.com":["TIMEOUT"],"erehwon.example.com":[{"TXT":"v=spfl am not an SPF record"}],"e1.example.com":[{"SPF":"v=spf1 include:ip5.example.com ~all"}],"e2.example.com":[{"SPF":"v=spf1 include:ip6.example.com all"}],"e3.example.com":[{"SPF":"v=spf1 include:ip7.example.com -all"}],"e4.example.com":[{"SPF":"v=spf1 include:ip8.example.com -all"}],"e5.example.com":[{"SPF":"v=spf1 include:e6.example.com -all"}],"e6.example.com":[{"SPF":"v=spf1 include +all"}],"e7.example.com":[{"SPF":"v=spf1 include:erehwon.example.com -all"}],"e8.example.com":[{"SPF":"v=spf1 include: -all"}],"e9.example.com":[{"SPF":"v=spf1 include:ip5.example.com/24 -all"}]}, failOnNoFake: true, helo: "mail.example.com"}
        let promise = spf.check_host('1.2.3.4', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'PERMERROR');
        });
      });
      it('include-syntax-error', function(){
        let email = 'foo@e6.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"ip5.example.com":[{"SPF":"v=spf1 ip4:1.2.3.5 -all"}],"ip6.example.com":[{"SPF":"v=spf1 ip4:1.2.3.6 ~all"}],"ip7.example.com":[{"SPF":"v=spf1 ip4:1.2.3.7 ?all"}],"ip8.example.com":["TIMEOUT"],"erehwon.example.com":[{"TXT":"v=spfl am not an SPF record"}],"e1.example.com":[{"SPF":"v=spf1 include:ip5.example.com ~all"}],"e2.example.com":[{"SPF":"v=spf1 include:ip6.example.com all"}],"e3.example.com":[{"SPF":"v=spf1 include:ip7.example.com -all"}],"e4.example.com":[{"SPF":"v=spf1 include:ip8.example.com -all"}],"e5.example.com":[{"SPF":"v=spf1 include:e6.example.com -all"}],"e6.example.com":[{"SPF":"v=spf1 include +all"}],"e7.example.com":[{"SPF":"v=spf1 include:erehwon.example.com -all"}],"e8.example.com":[{"SPF":"v=spf1 include: -all"}],"e9.example.com":[{"SPF":"v=spf1 include:ip5.example.com/24 -all"}]}, failOnNoFake: true, helo: "mail.example.com"}
        let promise = spf.check_host('1.2.3.4', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'PERMERROR');
        });
      });
      it('include-cidr', function(){
        let email = 'foo@e9.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"ip5.example.com":[{"SPF":"v=spf1 ip4:1.2.3.5 -all"}],"ip6.example.com":[{"SPF":"v=spf1 ip4:1.2.3.6 ~all"}],"ip7.example.com":[{"SPF":"v=spf1 ip4:1.2.3.7 ?all"}],"ip8.example.com":["TIMEOUT"],"erehwon.example.com":[{"TXT":"v=spfl am not an SPF record"}],"e1.example.com":[{"SPF":"v=spf1 include:ip5.example.com ~all"}],"e2.example.com":[{"SPF":"v=spf1 include:ip6.example.com all"}],"e3.example.com":[{"SPF":"v=spf1 include:ip7.example.com -all"}],"e4.example.com":[{"SPF":"v=spf1 include:ip8.example.com -all"}],"e5.example.com":[{"SPF":"v=spf1 include:e6.example.com -all"}],"e6.example.com":[{"SPF":"v=spf1 include +all"}],"e7.example.com":[{"SPF":"v=spf1 include:erehwon.example.com -all"}],"e8.example.com":[{"SPF":"v=spf1 include: -all"}],"e9.example.com":[{"SPF":"v=spf1 include:ip5.example.com/24 -all"}]}, failOnNoFake: true, helo: "mail.example.com"}
        let promise = spf.check_host('1.2.3.4', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'PERMERROR');
        });
      });
      it('include-none', function(){
        let email = 'foo@e7.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"ip5.example.com":[{"SPF":"v=spf1 ip4:1.2.3.5 -all"}],"ip6.example.com":[{"SPF":"v=spf1 ip4:1.2.3.6 ~all"}],"ip7.example.com":[{"SPF":"v=spf1 ip4:1.2.3.7 ?all"}],"ip8.example.com":["TIMEOUT"],"erehwon.example.com":[{"TXT":"v=spfl am not an SPF record"}],"e1.example.com":[{"SPF":"v=spf1 include:ip5.example.com ~all"}],"e2.example.com":[{"SPF":"v=spf1 include:ip6.example.com all"}],"e3.example.com":[{"SPF":"v=spf1 include:ip7.example.com -all"}],"e4.example.com":[{"SPF":"v=spf1 include:ip8.example.com -all"}],"e5.example.com":[{"SPF":"v=spf1 include:e6.example.com -all"}],"e6.example.com":[{"SPF":"v=spf1 include +all"}],"e7.example.com":[{"SPF":"v=spf1 include:erehwon.example.com -all"}],"e8.example.com":[{"SPF":"v=spf1 include: -all"}],"e9.example.com":[{"SPF":"v=spf1 include:ip5.example.com/24 -all"}]}, failOnNoFake: true, helo: "mail.example.com"}
        let promise = spf.check_host('1.2.3.4', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'PERMERROR');
        });
      });
      it('include-empty-domain', function(){
        let email = 'foo@e8.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"ip5.example.com":[{"SPF":"v=spf1 ip4:1.2.3.5 -all"}],"ip6.example.com":[{"SPF":"v=spf1 ip4:1.2.3.6 ~all"}],"ip7.example.com":[{"SPF":"v=spf1 ip4:1.2.3.7 ?all"}],"ip8.example.com":["TIMEOUT"],"erehwon.example.com":[{"TXT":"v=spfl am not an SPF record"}],"e1.example.com":[{"SPF":"v=spf1 include:ip5.example.com ~all"}],"e2.example.com":[{"SPF":"v=spf1 include:ip6.example.com all"}],"e3.example.com":[{"SPF":"v=spf1 include:ip7.example.com -all"}],"e4.example.com":[{"SPF":"v=spf1 include:ip8.example.com -all"}],"e5.example.com":[{"SPF":"v=spf1 include:e6.example.com -all"}],"e6.example.com":[{"SPF":"v=spf1 include +all"}],"e7.example.com":[{"SPF":"v=spf1 include:erehwon.example.com -all"}],"e8.example.com":[{"SPF":"v=spf1 include: -all"}],"e9.example.com":[{"SPF":"v=spf1 include:ip5.example.com/24 -all"}]}, failOnNoFake: true, helo: "mail.example.com"}
        let promise = spf.check_host('1.2.3.4', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'PERMERROR');
        });
      });
    });
    describe('MX mechanism syntax', function(){
      it('mx-cidr6', function(){
        let email = 'foo@e6.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"},{"MX":[0,""]},{"SPF":"v=spf1 mx"}],"e1.example.com":[{"SPF":"v=spf1 mx/0 -all"},{"MX":[0,"e1.example.com"]}],"e2.example.com":[{"A":"1.1.1.1"},{"AAAA":"1234::2"},{"MX":[0,"e2.example.com"]},{"SPF":"v=spf1 mx/0 -all"}],"e2a.example.com":[{"AAAA":"1234::1"},{"MX":[0,"e2a.example.com"]},{"SPF":"v=spf1 mx//0 -all"}],"e2b.example.com":[{"A":"1.1.1.1"},{"MX":[0,"e2b.example.com"]},{"SPF":"v=spf1 mx//0 -all"}],"e3.example.com":[{"SPF":"v=spf1 mx:foo.example.com\u0000"}],"e4.example.com":[{"SPF":"v=spf1 mx"},{"A":"1.2.3.4"}],"e5.example.com":[{"SPF":"v=spf1 mx:abc.123"}],"e6.example.com":[{"SPF":"v=spf1 mx//33 -all"}],"e6a.example.com":[{"SPF":"v=spf1 mx/33 -all"}],"e7.example.com":[{"SPF":"v=spf1 mx//129 -all"}],"e9.example.com":[{"SPF":"v=spf1 mx:example.com:8080"}],"e10.example.com":[{"SPF":"v=spf1 mx:foo.example.com/24"}],"foo.example.com":[{"MX":[0,"foo1.example.com"]}],"foo1.example.com":[{"A":"1.1.1.1"},{"A":"1.2.3.5"}],"e11.example.com":[{"SPF":"v=spf1 mx:foo:bar/baz.example.com"}],"foo:bar/baz.example.com":[{"MX":[0,"foo:bar/baz.example.com"]},{"A":"1.2.3.4"}],"e12.example.com":[{"SPF":"v=spf1 mx:example.-com"}],"e13.example.com":[{"SPF":"v=spf1 mx: -all"}]}, failOnNoFake: true, helo: "mail.example.com"}
        let promise = spf.check_host('1.2.3.4', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'FAIL');
        });
      });
      it('mx-bad-cidr4', function(){
        let email = 'foo@e6a.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"},{"MX":[0,""]},{"SPF":"v=spf1 mx"}],"e1.example.com":[{"SPF":"v=spf1 mx/0 -all"},{"MX":[0,"e1.example.com"]}],"e2.example.com":[{"A":"1.1.1.1"},{"AAAA":"1234::2"},{"MX":[0,"e2.example.com"]},{"SPF":"v=spf1 mx/0 -all"}],"e2a.example.com":[{"AAAA":"1234::1"},{"MX":[0,"e2a.example.com"]},{"SPF":"v=spf1 mx//0 -all"}],"e2b.example.com":[{"A":"1.1.1.1"},{"MX":[0,"e2b.example.com"]},{"SPF":"v=spf1 mx//0 -all"}],"e3.example.com":[{"SPF":"v=spf1 mx:foo.example.com\u0000"}],"e4.example.com":[{"SPF":"v=spf1 mx"},{"A":"1.2.3.4"}],"e5.example.com":[{"SPF":"v=spf1 mx:abc.123"}],"e6.example.com":[{"SPF":"v=spf1 mx//33 -all"}],"e6a.example.com":[{"SPF":"v=spf1 mx/33 -all"}],"e7.example.com":[{"SPF":"v=spf1 mx//129 -all"}],"e9.example.com":[{"SPF":"v=spf1 mx:example.com:8080"}],"e10.example.com":[{"SPF":"v=spf1 mx:foo.example.com/24"}],"foo.example.com":[{"MX":[0,"foo1.example.com"]}],"foo1.example.com":[{"A":"1.1.1.1"},{"A":"1.2.3.5"}],"e11.example.com":[{"SPF":"v=spf1 mx:foo:bar/baz.example.com"}],"foo:bar/baz.example.com":[{"MX":[0,"foo:bar/baz.example.com"]},{"A":"1.2.3.4"}],"e12.example.com":[{"SPF":"v=spf1 mx:example.-com"}],"e13.example.com":[{"SPF":"v=spf1 mx: -all"}]}, failOnNoFake: true, helo: "mail.example.com"}
        let promise = spf.check_host('1.2.3.4', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'PERMERROR');
        });
      });
      it('mx-bad-cidr6', function(){
        let email = 'foo@e7.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"},{"MX":[0,""]},{"SPF":"v=spf1 mx"}],"e1.example.com":[{"SPF":"v=spf1 mx/0 -all"},{"MX":[0,"e1.example.com"]}],"e2.example.com":[{"A":"1.1.1.1"},{"AAAA":"1234::2"},{"MX":[0,"e2.example.com"]},{"SPF":"v=spf1 mx/0 -all"}],"e2a.example.com":[{"AAAA":"1234::1"},{"MX":[0,"e2a.example.com"]},{"SPF":"v=spf1 mx//0 -all"}],"e2b.example.com":[{"A":"1.1.1.1"},{"MX":[0,"e2b.example.com"]},{"SPF":"v=spf1 mx//0 -all"}],"e3.example.com":[{"SPF":"v=spf1 mx:foo.example.com\u0000"}],"e4.example.com":[{"SPF":"v=spf1 mx"},{"A":"1.2.3.4"}],"e5.example.com":[{"SPF":"v=spf1 mx:abc.123"}],"e6.example.com":[{"SPF":"v=spf1 mx//33 -all"}],"e6a.example.com":[{"SPF":"v=spf1 mx/33 -all"}],"e7.example.com":[{"SPF":"v=spf1 mx//129 -all"}],"e9.example.com":[{"SPF":"v=spf1 mx:example.com:8080"}],"e10.example.com":[{"SPF":"v=spf1 mx:foo.example.com/24"}],"foo.example.com":[{"MX":[0,"foo1.example.com"]}],"foo1.example.com":[{"A":"1.1.1.1"},{"A":"1.2.3.5"}],"e11.example.com":[{"SPF":"v=spf1 mx:foo:bar/baz.example.com"}],"foo:bar/baz.example.com":[{"MX":[0,"foo:bar/baz.example.com"]},{"A":"1.2.3.4"}],"e12.example.com":[{"SPF":"v=spf1 mx:example.-com"}],"e13.example.com":[{"SPF":"v=spf1 mx: -all"}]}, failOnNoFake: true, helo: "mail.example.com"}
        let promise = spf.check_host('1.2.3.4', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'PERMERROR');
        });
      });
      it('mx-multi-ip1', function(){
        let email = 'foo@e10.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"},{"MX":[0,""]},{"SPF":"v=spf1 mx"}],"e1.example.com":[{"SPF":"v=spf1 mx/0 -all"},{"MX":[0,"e1.example.com"]}],"e2.example.com":[{"A":"1.1.1.1"},{"AAAA":"1234::2"},{"MX":[0,"e2.example.com"]},{"SPF":"v=spf1 mx/0 -all"}],"e2a.example.com":[{"AAAA":"1234::1"},{"MX":[0,"e2a.example.com"]},{"SPF":"v=spf1 mx//0 -all"}],"e2b.example.com":[{"A":"1.1.1.1"},{"MX":[0,"e2b.example.com"]},{"SPF":"v=spf1 mx//0 -all"}],"e3.example.com":[{"SPF":"v=spf1 mx:foo.example.com\u0000"}],"e4.example.com":[{"SPF":"v=spf1 mx"},{"A":"1.2.3.4"}],"e5.example.com":[{"SPF":"v=spf1 mx:abc.123"}],"e6.example.com":[{"SPF":"v=spf1 mx//33 -all"}],"e6a.example.com":[{"SPF":"v=spf1 mx/33 -all"}],"e7.example.com":[{"SPF":"v=spf1 mx//129 -all"}],"e9.example.com":[{"SPF":"v=spf1 mx:example.com:8080"}],"e10.example.com":[{"SPF":"v=spf1 mx:foo.example.com/24"}],"foo.example.com":[{"MX":[0,"foo1.example.com"]}],"foo1.example.com":[{"A":"1.1.1.1"},{"A":"1.2.3.5"}],"e11.example.com":[{"SPF":"v=spf1 mx:foo:bar/baz.example.com"}],"foo:bar/baz.example.com":[{"MX":[0,"foo:bar/baz.example.com"]},{"A":"1.2.3.4"}],"e12.example.com":[{"SPF":"v=spf1 mx:example.-com"}],"e13.example.com":[{"SPF":"v=spf1 mx: -all"}]}, failOnNoFake: true, helo: "mail.example.com"}
        let promise = spf.check_host('1.2.3.4', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'PASS');
        });
      });
      it('mx-multi-ip2', function(){
        let email = 'foo@e10.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"},{"MX":[0,""]},{"SPF":"v=spf1 mx"}],"e1.example.com":[{"SPF":"v=spf1 mx/0 -all"},{"MX":[0,"e1.example.com"]}],"e2.example.com":[{"A":"1.1.1.1"},{"AAAA":"1234::2"},{"MX":[0,"e2.example.com"]},{"SPF":"v=spf1 mx/0 -all"}],"e2a.example.com":[{"AAAA":"1234::1"},{"MX":[0,"e2a.example.com"]},{"SPF":"v=spf1 mx//0 -all"}],"e2b.example.com":[{"A":"1.1.1.1"},{"MX":[0,"e2b.example.com"]},{"SPF":"v=spf1 mx//0 -all"}],"e3.example.com":[{"SPF":"v=spf1 mx:foo.example.com\u0000"}],"e4.example.com":[{"SPF":"v=spf1 mx"},{"A":"1.2.3.4"}],"e5.example.com":[{"SPF":"v=spf1 mx:abc.123"}],"e6.example.com":[{"SPF":"v=spf1 mx//33 -all"}],"e6a.example.com":[{"SPF":"v=spf1 mx/33 -all"}],"e7.example.com":[{"SPF":"v=spf1 mx//129 -all"}],"e9.example.com":[{"SPF":"v=spf1 mx:example.com:8080"}],"e10.example.com":[{"SPF":"v=spf1 mx:foo.example.com/24"}],"foo.example.com":[{"MX":[0,"foo1.example.com"]}],"foo1.example.com":[{"A":"1.1.1.1"},{"A":"1.2.3.5"}],"e11.example.com":[{"SPF":"v=spf1 mx:foo:bar/baz.example.com"}],"foo:bar/baz.example.com":[{"MX":[0,"foo:bar/baz.example.com"]},{"A":"1.2.3.4"}],"e12.example.com":[{"SPF":"v=spf1 mx:example.-com"}],"e13.example.com":[{"SPF":"v=spf1 mx: -all"}]}, failOnNoFake: true, helo: "mail.example.com"}
        let promise = spf.check_host('1.2.3.4', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'PASS');
        });
      });
      it('mx-bad-domain', function(){
        let email = 'foo@e9.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"},{"MX":[0,""]},{"SPF":"v=spf1 mx"}],"e1.example.com":[{"SPF":"v=spf1 mx/0 -all"},{"MX":[0,"e1.example.com"]}],"e2.example.com":[{"A":"1.1.1.1"},{"AAAA":"1234::2"},{"MX":[0,"e2.example.com"]},{"SPF":"v=spf1 mx/0 -all"}],"e2a.example.com":[{"AAAA":"1234::1"},{"MX":[0,"e2a.example.com"]},{"SPF":"v=spf1 mx//0 -all"}],"e2b.example.com":[{"A":"1.1.1.1"},{"MX":[0,"e2b.example.com"]},{"SPF":"v=spf1 mx//0 -all"}],"e3.example.com":[{"SPF":"v=spf1 mx:foo.example.com\u0000"}],"e4.example.com":[{"SPF":"v=spf1 mx"},{"A":"1.2.3.4"}],"e5.example.com":[{"SPF":"v=spf1 mx:abc.123"}],"e6.example.com":[{"SPF":"v=spf1 mx//33 -all"}],"e6a.example.com":[{"SPF":"v=spf1 mx/33 -all"}],"e7.example.com":[{"SPF":"v=spf1 mx//129 -all"}],"e9.example.com":[{"SPF":"v=spf1 mx:example.com:8080"}],"e10.example.com":[{"SPF":"v=spf1 mx:foo.example.com/24"}],"foo.example.com":[{"MX":[0,"foo1.example.com"]}],"foo1.example.com":[{"A":"1.1.1.1"},{"A":"1.2.3.5"}],"e11.example.com":[{"SPF":"v=spf1 mx:foo:bar/baz.example.com"}],"foo:bar/baz.example.com":[{"MX":[0,"foo:bar/baz.example.com"]},{"A":"1.2.3.4"}],"e12.example.com":[{"SPF":"v=spf1 mx:example.-com"}],"e13.example.com":[{"SPF":"v=spf1 mx: -all"}]}, failOnNoFake: true, helo: "mail.example.com"}
        let promise = spf.check_host('1.2.3.4', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'PERMERROR');
        });
      });
      it('mx-nxdomain', function(){
        let email = 'foo@e1.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"},{"MX":[0,""]},{"SPF":"v=spf1 mx"}],"e1.example.com":[{"SPF":"v=spf1 mx/0 -all"},{"MX":[0,"e1.example.com"]}],"e2.example.com":[{"A":"1.1.1.1"},{"AAAA":"1234::2"},{"MX":[0,"e2.example.com"]},{"SPF":"v=spf1 mx/0 -all"}],"e2a.example.com":[{"AAAA":"1234::1"},{"MX":[0,"e2a.example.com"]},{"SPF":"v=spf1 mx//0 -all"}],"e2b.example.com":[{"A":"1.1.1.1"},{"MX":[0,"e2b.example.com"]},{"SPF":"v=spf1 mx//0 -all"}],"e3.example.com":[{"SPF":"v=spf1 mx:foo.example.com\u0000"}],"e4.example.com":[{"SPF":"v=spf1 mx"},{"A":"1.2.3.4"}],"e5.example.com":[{"SPF":"v=spf1 mx:abc.123"}],"e6.example.com":[{"SPF":"v=spf1 mx//33 -all"}],"e6a.example.com":[{"SPF":"v=spf1 mx/33 -all"}],"e7.example.com":[{"SPF":"v=spf1 mx//129 -all"}],"e9.example.com":[{"SPF":"v=spf1 mx:example.com:8080"}],"e10.example.com":[{"SPF":"v=spf1 mx:foo.example.com/24"}],"foo.example.com":[{"MX":[0,"foo1.example.com"]}],"foo1.example.com":[{"A":"1.1.1.1"},{"A":"1.2.3.5"}],"e11.example.com":[{"SPF":"v=spf1 mx:foo:bar/baz.example.com"}],"foo:bar/baz.example.com":[{"MX":[0,"foo:bar/baz.example.com"]},{"A":"1.2.3.4"}],"e12.example.com":[{"SPF":"v=spf1 mx:example.-com"}],"e13.example.com":[{"SPF":"v=spf1 mx: -all"}]}, failOnNoFake: true, helo: "mail.example.com"}
        let promise = spf.check_host('1.2.3.4', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'FAIL');
        });
      });
      it('mx-cidr4-0', function(){
        let email = 'foo@e2.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"},{"MX":[0,""]},{"SPF":"v=spf1 mx"}],"e1.example.com":[{"SPF":"v=spf1 mx/0 -all"},{"MX":[0,"e1.example.com"]}],"e2.example.com":[{"A":"1.1.1.1"},{"AAAA":"1234::2"},{"MX":[0,"e2.example.com"]},{"SPF":"v=spf1 mx/0 -all"}],"e2a.example.com":[{"AAAA":"1234::1"},{"MX":[0,"e2a.example.com"]},{"SPF":"v=spf1 mx//0 -all"}],"e2b.example.com":[{"A":"1.1.1.1"},{"MX":[0,"e2b.example.com"]},{"SPF":"v=spf1 mx//0 -all"}],"e3.example.com":[{"SPF":"v=spf1 mx:foo.example.com\u0000"}],"e4.example.com":[{"SPF":"v=spf1 mx"},{"A":"1.2.3.4"}],"e5.example.com":[{"SPF":"v=spf1 mx:abc.123"}],"e6.example.com":[{"SPF":"v=spf1 mx//33 -all"}],"e6a.example.com":[{"SPF":"v=spf1 mx/33 -all"}],"e7.example.com":[{"SPF":"v=spf1 mx//129 -all"}],"e9.example.com":[{"SPF":"v=spf1 mx:example.com:8080"}],"e10.example.com":[{"SPF":"v=spf1 mx:foo.example.com/24"}],"foo.example.com":[{"MX":[0,"foo1.example.com"]}],"foo1.example.com":[{"A":"1.1.1.1"},{"A":"1.2.3.5"}],"e11.example.com":[{"SPF":"v=spf1 mx:foo:bar/baz.example.com"}],"foo:bar/baz.example.com":[{"MX":[0,"foo:bar/baz.example.com"]},{"A":"1.2.3.4"}],"e12.example.com":[{"SPF":"v=spf1 mx:example.-com"}],"e13.example.com":[{"SPF":"v=spf1 mx: -all"}]}, failOnNoFake: true, helo: "mail.example.com"}
        let promise = spf.check_host('1.2.3.4', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'PASS');
        });
      });
      it('mx-cidr4-0-ip6', function(){
        let email = 'foo@e2.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"},{"MX":[0,""]},{"SPF":"v=spf1 mx"}],"e1.example.com":[{"SPF":"v=spf1 mx/0 -all"},{"MX":[0,"e1.example.com"]}],"e2.example.com":[{"A":"1.1.1.1"},{"AAAA":"1234::2"},{"MX":[0,"e2.example.com"]},{"SPF":"v=spf1 mx/0 -all"}],"e2a.example.com":[{"AAAA":"1234::1"},{"MX":[0,"e2a.example.com"]},{"SPF":"v=spf1 mx//0 -all"}],"e2b.example.com":[{"A":"1.1.1.1"},{"MX":[0,"e2b.example.com"]},{"SPF":"v=spf1 mx//0 -all"}],"e3.example.com":[{"SPF":"v=spf1 mx:foo.example.com\u0000"}],"e4.example.com":[{"SPF":"v=spf1 mx"},{"A":"1.2.3.4"}],"e5.example.com":[{"SPF":"v=spf1 mx:abc.123"}],"e6.example.com":[{"SPF":"v=spf1 mx//33 -all"}],"e6a.example.com":[{"SPF":"v=spf1 mx/33 -all"}],"e7.example.com":[{"SPF":"v=spf1 mx//129 -all"}],"e9.example.com":[{"SPF":"v=spf1 mx:example.com:8080"}],"e10.example.com":[{"SPF":"v=spf1 mx:foo.example.com/24"}],"foo.example.com":[{"MX":[0,"foo1.example.com"]}],"foo1.example.com":[{"A":"1.1.1.1"},{"A":"1.2.3.5"}],"e11.example.com":[{"SPF":"v=spf1 mx:foo:bar/baz.example.com"}],"foo:bar/baz.example.com":[{"MX":[0,"foo:bar/baz.example.com"]},{"A":"1.2.3.4"}],"e12.example.com":[{"SPF":"v=spf1 mx:example.-com"}],"e13.example.com":[{"SPF":"v=spf1 mx: -all"}]}, failOnNoFake: true, helo: "mail.example.com"}
        let promise = spf.check_host('1234::1', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'FAIL');
        });
      });
      it('mx-cidr6-0-ip4', function(){
        let email = 'foo@e2a.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"},{"MX":[0,""]},{"SPF":"v=spf1 mx"}],"e1.example.com":[{"SPF":"v=spf1 mx/0 -all"},{"MX":[0,"e1.example.com"]}],"e2.example.com":[{"A":"1.1.1.1"},{"AAAA":"1234::2"},{"MX":[0,"e2.example.com"]},{"SPF":"v=spf1 mx/0 -all"}],"e2a.example.com":[{"AAAA":"1234::1"},{"MX":[0,"e2a.example.com"]},{"SPF":"v=spf1 mx//0 -all"}],"e2b.example.com":[{"A":"1.1.1.1"},{"MX":[0,"e2b.example.com"]},{"SPF":"v=spf1 mx//0 -all"}],"e3.example.com":[{"SPF":"v=spf1 mx:foo.example.com\u0000"}],"e4.example.com":[{"SPF":"v=spf1 mx"},{"A":"1.2.3.4"}],"e5.example.com":[{"SPF":"v=spf1 mx:abc.123"}],"e6.example.com":[{"SPF":"v=spf1 mx//33 -all"}],"e6a.example.com":[{"SPF":"v=spf1 mx/33 -all"}],"e7.example.com":[{"SPF":"v=spf1 mx//129 -all"}],"e9.example.com":[{"SPF":"v=spf1 mx:example.com:8080"}],"e10.example.com":[{"SPF":"v=spf1 mx:foo.example.com/24"}],"foo.example.com":[{"MX":[0,"foo1.example.com"]}],"foo1.example.com":[{"A":"1.1.1.1"},{"A":"1.2.3.5"}],"e11.example.com":[{"SPF":"v=spf1 mx:foo:bar/baz.example.com"}],"foo:bar/baz.example.com":[{"MX":[0,"foo:bar/baz.example.com"]},{"A":"1.2.3.4"}],"e12.example.com":[{"SPF":"v=spf1 mx:example.-com"}],"e13.example.com":[{"SPF":"v=spf1 mx: -all"}]}, failOnNoFake: true, helo: "mail.example.com"}
        let promise = spf.check_host('1.2.3.4', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'FAIL');
        });
      });
      it('mx-cidr6-0-ip4mapped', function(){
        let email = 'foo@e2a.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"},{"MX":[0,""]},{"SPF":"v=spf1 mx"}],"e1.example.com":[{"SPF":"v=spf1 mx/0 -all"},{"MX":[0,"e1.example.com"]}],"e2.example.com":[{"A":"1.1.1.1"},{"AAAA":"1234::2"},{"MX":[0,"e2.example.com"]},{"SPF":"v=spf1 mx/0 -all"}],"e2a.example.com":[{"AAAA":"1234::1"},{"MX":[0,"e2a.example.com"]},{"SPF":"v=spf1 mx//0 -all"}],"e2b.example.com":[{"A":"1.1.1.1"},{"MX":[0,"e2b.example.com"]},{"SPF":"v=spf1 mx//0 -all"}],"e3.example.com":[{"SPF":"v=spf1 mx:foo.example.com\u0000"}],"e4.example.com":[{"SPF":"v=spf1 mx"},{"A":"1.2.3.4"}],"e5.example.com":[{"SPF":"v=spf1 mx:abc.123"}],"e6.example.com":[{"SPF":"v=spf1 mx//33 -all"}],"e6a.example.com":[{"SPF":"v=spf1 mx/33 -all"}],"e7.example.com":[{"SPF":"v=spf1 mx//129 -all"}],"e9.example.com":[{"SPF":"v=spf1 mx:example.com:8080"}],"e10.example.com":[{"SPF":"v=spf1 mx:foo.example.com/24"}],"foo.example.com":[{"MX":[0,"foo1.example.com"]}],"foo1.example.com":[{"A":"1.1.1.1"},{"A":"1.2.3.5"}],"e11.example.com":[{"SPF":"v=spf1 mx:foo:bar/baz.example.com"}],"foo:bar/baz.example.com":[{"MX":[0,"foo:bar/baz.example.com"]},{"A":"1.2.3.4"}],"e12.example.com":[{"SPF":"v=spf1 mx:example.-com"}],"e13.example.com":[{"SPF":"v=spf1 mx: -all"}]}, failOnNoFake: true, helo: "mail.example.com"}
        let promise = spf.check_host('::FFFF:1.2.3.4', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'FAIL');
        });
      });
      it('mx-cidr6-0-ip6', function(){
        let email = 'foo@e2a.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"},{"MX":[0,""]},{"SPF":"v=spf1 mx"}],"e1.example.com":[{"SPF":"v=spf1 mx/0 -all"},{"MX":[0,"e1.example.com"]}],"e2.example.com":[{"A":"1.1.1.1"},{"AAAA":"1234::2"},{"MX":[0,"e2.example.com"]},{"SPF":"v=spf1 mx/0 -all"}],"e2a.example.com":[{"AAAA":"1234::1"},{"MX":[0,"e2a.example.com"]},{"SPF":"v=spf1 mx//0 -all"}],"e2b.example.com":[{"A":"1.1.1.1"},{"MX":[0,"e2b.example.com"]},{"SPF":"v=spf1 mx//0 -all"}],"e3.example.com":[{"SPF":"v=spf1 mx:foo.example.com\u0000"}],"e4.example.com":[{"SPF":"v=spf1 mx"},{"A":"1.2.3.4"}],"e5.example.com":[{"SPF":"v=spf1 mx:abc.123"}],"e6.example.com":[{"SPF":"v=spf1 mx//33 -all"}],"e6a.example.com":[{"SPF":"v=spf1 mx/33 -all"}],"e7.example.com":[{"SPF":"v=spf1 mx//129 -all"}],"e9.example.com":[{"SPF":"v=spf1 mx:example.com:8080"}],"e10.example.com":[{"SPF":"v=spf1 mx:foo.example.com/24"}],"foo.example.com":[{"MX":[0,"foo1.example.com"]}],"foo1.example.com":[{"A":"1.1.1.1"},{"A":"1.2.3.5"}],"e11.example.com":[{"SPF":"v=spf1 mx:foo:bar/baz.example.com"}],"foo:bar/baz.example.com":[{"MX":[0,"foo:bar/baz.example.com"]},{"A":"1.2.3.4"}],"e12.example.com":[{"SPF":"v=spf1 mx:example.-com"}],"e13.example.com":[{"SPF":"v=spf1 mx: -all"}]}, failOnNoFake: true, helo: "mail.example.com"}
        let promise = spf.check_host('1234::1', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'PASS');
        });
      });
      it('mx-cidr6-0-nxdomain', function(){
        let email = 'foo@e2b.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"},{"MX":[0,""]},{"SPF":"v=spf1 mx"}],"e1.example.com":[{"SPF":"v=spf1 mx/0 -all"},{"MX":[0,"e1.example.com"]}],"e2.example.com":[{"A":"1.1.1.1"},{"AAAA":"1234::2"},{"MX":[0,"e2.example.com"]},{"SPF":"v=spf1 mx/0 -all"}],"e2a.example.com":[{"AAAA":"1234::1"},{"MX":[0,"e2a.example.com"]},{"SPF":"v=spf1 mx//0 -all"}],"e2b.example.com":[{"A":"1.1.1.1"},{"MX":[0,"e2b.example.com"]},{"SPF":"v=spf1 mx//0 -all"}],"e3.example.com":[{"SPF":"v=spf1 mx:foo.example.com\u0000"}],"e4.example.com":[{"SPF":"v=spf1 mx"},{"A":"1.2.3.4"}],"e5.example.com":[{"SPF":"v=spf1 mx:abc.123"}],"e6.example.com":[{"SPF":"v=spf1 mx//33 -all"}],"e6a.example.com":[{"SPF":"v=spf1 mx/33 -all"}],"e7.example.com":[{"SPF":"v=spf1 mx//129 -all"}],"e9.example.com":[{"SPF":"v=spf1 mx:example.com:8080"}],"e10.example.com":[{"SPF":"v=spf1 mx:foo.example.com/24"}],"foo.example.com":[{"MX":[0,"foo1.example.com"]}],"foo1.example.com":[{"A":"1.1.1.1"},{"A":"1.2.3.5"}],"e11.example.com":[{"SPF":"v=spf1 mx:foo:bar/baz.example.com"}],"foo:bar/baz.example.com":[{"MX":[0,"foo:bar/baz.example.com"]},{"A":"1.2.3.4"}],"e12.example.com":[{"SPF":"v=spf1 mx:example.-com"}],"e13.example.com":[{"SPF":"v=spf1 mx: -all"}]}, failOnNoFake: true, helo: "mail.example.com"}
        let promise = spf.check_host('1234::1', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'FAIL');
        });
      });
      it('mx-null', function(){
        let email = 'foo@e3.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"},{"MX":[0,""]},{"SPF":"v=spf1 mx"}],"e1.example.com":[{"SPF":"v=spf1 mx/0 -all"},{"MX":[0,"e1.example.com"]}],"e2.example.com":[{"A":"1.1.1.1"},{"AAAA":"1234::2"},{"MX":[0,"e2.example.com"]},{"SPF":"v=spf1 mx/0 -all"}],"e2a.example.com":[{"AAAA":"1234::1"},{"MX":[0,"e2a.example.com"]},{"SPF":"v=spf1 mx//0 -all"}],"e2b.example.com":[{"A":"1.1.1.1"},{"MX":[0,"e2b.example.com"]},{"SPF":"v=spf1 mx//0 -all"}],"e3.example.com":[{"SPF":"v=spf1 mx:foo.example.com\u0000"}],"e4.example.com":[{"SPF":"v=spf1 mx"},{"A":"1.2.3.4"}],"e5.example.com":[{"SPF":"v=spf1 mx:abc.123"}],"e6.example.com":[{"SPF":"v=spf1 mx//33 -all"}],"e6a.example.com":[{"SPF":"v=spf1 mx/33 -all"}],"e7.example.com":[{"SPF":"v=spf1 mx//129 -all"}],"e9.example.com":[{"SPF":"v=spf1 mx:example.com:8080"}],"e10.example.com":[{"SPF":"v=spf1 mx:foo.example.com/24"}],"foo.example.com":[{"MX":[0,"foo1.example.com"]}],"foo1.example.com":[{"A":"1.1.1.1"},{"A":"1.2.3.5"}],"e11.example.com":[{"SPF":"v=spf1 mx:foo:bar/baz.example.com"}],"foo:bar/baz.example.com":[{"MX":[0,"foo:bar/baz.example.com"]},{"A":"1.2.3.4"}],"e12.example.com":[{"SPF":"v=spf1 mx:example.-com"}],"e13.example.com":[{"SPF":"v=spf1 mx: -all"}]}, failOnNoFake: true, helo: "mail.example.com"}
        let promise = spf.check_host('1.2.3.5', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'PERMERROR');
        });
      });
      it('mx-numeric-top-label', function(){
        let email = 'foo@e5.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"},{"MX":[0,""]},{"SPF":"v=spf1 mx"}],"e1.example.com":[{"SPF":"v=spf1 mx/0 -all"},{"MX":[0,"e1.example.com"]}],"e2.example.com":[{"A":"1.1.1.1"},{"AAAA":"1234::2"},{"MX":[0,"e2.example.com"]},{"SPF":"v=spf1 mx/0 -all"}],"e2a.example.com":[{"AAAA":"1234::1"},{"MX":[0,"e2a.example.com"]},{"SPF":"v=spf1 mx//0 -all"}],"e2b.example.com":[{"A":"1.1.1.1"},{"MX":[0,"e2b.example.com"]},{"SPF":"v=spf1 mx//0 -all"}],"e3.example.com":[{"SPF":"v=spf1 mx:foo.example.com\u0000"}],"e4.example.com":[{"SPF":"v=spf1 mx"},{"A":"1.2.3.4"}],"e5.example.com":[{"SPF":"v=spf1 mx:abc.123"}],"e6.example.com":[{"SPF":"v=spf1 mx//33 -all"}],"e6a.example.com":[{"SPF":"v=spf1 mx/33 -all"}],"e7.example.com":[{"SPF":"v=spf1 mx//129 -all"}],"e9.example.com":[{"SPF":"v=spf1 mx:example.com:8080"}],"e10.example.com":[{"SPF":"v=spf1 mx:foo.example.com/24"}],"foo.example.com":[{"MX":[0,"foo1.example.com"]}],"foo1.example.com":[{"A":"1.1.1.1"},{"A":"1.2.3.5"}],"e11.example.com":[{"SPF":"v=spf1 mx:foo:bar/baz.example.com"}],"foo:bar/baz.example.com":[{"MX":[0,"foo:bar/baz.example.com"]},{"A":"1.2.3.4"}],"e12.example.com":[{"SPF":"v=spf1 mx:example.-com"}],"e13.example.com":[{"SPF":"v=spf1 mx: -all"}]}, failOnNoFake: true, helo: "mail.example.com"}
        let promise = spf.check_host('1.2.3.4', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'PERMERROR');
        });
      });
      it('mx-colon-domain', function(){
        let email = 'foo@e11.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"},{"MX":[0,""]},{"SPF":"v=spf1 mx"}],"e1.example.com":[{"SPF":"v=spf1 mx/0 -all"},{"MX":[0,"e1.example.com"]}],"e2.example.com":[{"A":"1.1.1.1"},{"AAAA":"1234::2"},{"MX":[0,"e2.example.com"]},{"SPF":"v=spf1 mx/0 -all"}],"e2a.example.com":[{"AAAA":"1234::1"},{"MX":[0,"e2a.example.com"]},{"SPF":"v=spf1 mx//0 -all"}],"e2b.example.com":[{"A":"1.1.1.1"},{"MX":[0,"e2b.example.com"]},{"SPF":"v=spf1 mx//0 -all"}],"e3.example.com":[{"SPF":"v=spf1 mx:foo.example.com\u0000"}],"e4.example.com":[{"SPF":"v=spf1 mx"},{"A":"1.2.3.4"}],"e5.example.com":[{"SPF":"v=spf1 mx:abc.123"}],"e6.example.com":[{"SPF":"v=spf1 mx//33 -all"}],"e6a.example.com":[{"SPF":"v=spf1 mx/33 -all"}],"e7.example.com":[{"SPF":"v=spf1 mx//129 -all"}],"e9.example.com":[{"SPF":"v=spf1 mx:example.com:8080"}],"e10.example.com":[{"SPF":"v=spf1 mx:foo.example.com/24"}],"foo.example.com":[{"MX":[0,"foo1.example.com"]}],"foo1.example.com":[{"A":"1.1.1.1"},{"A":"1.2.3.5"}],"e11.example.com":[{"SPF":"v=spf1 mx:foo:bar/baz.example.com"}],"foo:bar/baz.example.com":[{"MX":[0,"foo:bar/baz.example.com"]},{"A":"1.2.3.4"}],"e12.example.com":[{"SPF":"v=spf1 mx:example.-com"}],"e13.example.com":[{"SPF":"v=spf1 mx: -all"}]}, failOnNoFake: true, helo: "mail.example.com"}
        let promise = spf.check_host('1.2.3.4', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'PASS');
        });
      });
      it('mx-colon-domain-ip4mapped', function(){
        let email = 'foo@e11.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"},{"MX":[0,""]},{"SPF":"v=spf1 mx"}],"e1.example.com":[{"SPF":"v=spf1 mx/0 -all"},{"MX":[0,"e1.example.com"]}],"e2.example.com":[{"A":"1.1.1.1"},{"AAAA":"1234::2"},{"MX":[0,"e2.example.com"]},{"SPF":"v=spf1 mx/0 -all"}],"e2a.example.com":[{"AAAA":"1234::1"},{"MX":[0,"e2a.example.com"]},{"SPF":"v=spf1 mx//0 -all"}],"e2b.example.com":[{"A":"1.1.1.1"},{"MX":[0,"e2b.example.com"]},{"SPF":"v=spf1 mx//0 -all"}],"e3.example.com":[{"SPF":"v=spf1 mx:foo.example.com\u0000"}],"e4.example.com":[{"SPF":"v=spf1 mx"},{"A":"1.2.3.4"}],"e5.example.com":[{"SPF":"v=spf1 mx:abc.123"}],"e6.example.com":[{"SPF":"v=spf1 mx//33 -all"}],"e6a.example.com":[{"SPF":"v=spf1 mx/33 -all"}],"e7.example.com":[{"SPF":"v=spf1 mx//129 -all"}],"e9.example.com":[{"SPF":"v=spf1 mx:example.com:8080"}],"e10.example.com":[{"SPF":"v=spf1 mx:foo.example.com/24"}],"foo.example.com":[{"MX":[0,"foo1.example.com"]}],"foo1.example.com":[{"A":"1.1.1.1"},{"A":"1.2.3.5"}],"e11.example.com":[{"SPF":"v=spf1 mx:foo:bar/baz.example.com"}],"foo:bar/baz.example.com":[{"MX":[0,"foo:bar/baz.example.com"]},{"A":"1.2.3.4"}],"e12.example.com":[{"SPF":"v=spf1 mx:example.-com"}],"e13.example.com":[{"SPF":"v=spf1 mx: -all"}]}, failOnNoFake: true, helo: "mail.example.com"}
        let promise = spf.check_host('::FFFF:1.2.3.4', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'PASS');
        });
      });
      it('mx-bad-toplab', function(){
        let email = 'foo@e12.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"},{"MX":[0,""]},{"SPF":"v=spf1 mx"}],"e1.example.com":[{"SPF":"v=spf1 mx/0 -all"},{"MX":[0,"e1.example.com"]}],"e2.example.com":[{"A":"1.1.1.1"},{"AAAA":"1234::2"},{"MX":[0,"e2.example.com"]},{"SPF":"v=spf1 mx/0 -all"}],"e2a.example.com":[{"AAAA":"1234::1"},{"MX":[0,"e2a.example.com"]},{"SPF":"v=spf1 mx//0 -all"}],"e2b.example.com":[{"A":"1.1.1.1"},{"MX":[0,"e2b.example.com"]},{"SPF":"v=spf1 mx//0 -all"}],"e3.example.com":[{"SPF":"v=spf1 mx:foo.example.com\u0000"}],"e4.example.com":[{"SPF":"v=spf1 mx"},{"A":"1.2.3.4"}],"e5.example.com":[{"SPF":"v=spf1 mx:abc.123"}],"e6.example.com":[{"SPF":"v=spf1 mx//33 -all"}],"e6a.example.com":[{"SPF":"v=spf1 mx/33 -all"}],"e7.example.com":[{"SPF":"v=spf1 mx//129 -all"}],"e9.example.com":[{"SPF":"v=spf1 mx:example.com:8080"}],"e10.example.com":[{"SPF":"v=spf1 mx:foo.example.com/24"}],"foo.example.com":[{"MX":[0,"foo1.example.com"]}],"foo1.example.com":[{"A":"1.1.1.1"},{"A":"1.2.3.5"}],"e11.example.com":[{"SPF":"v=spf1 mx:foo:bar/baz.example.com"}],"foo:bar/baz.example.com":[{"MX":[0,"foo:bar/baz.example.com"]},{"A":"1.2.3.4"}],"e12.example.com":[{"SPF":"v=spf1 mx:example.-com"}],"e13.example.com":[{"SPF":"v=spf1 mx: -all"}]}, failOnNoFake: true, helo: "mail.example.com"}
        let promise = spf.check_host('1.2.3.4', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'PERMERROR');
        });
      });
      it('mx-empty', function(){
        let email = '';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"},{"MX":[0,""]},{"SPF":"v=spf1 mx"}],"e1.example.com":[{"SPF":"v=spf1 mx/0 -all"},{"MX":[0,"e1.example.com"]}],"e2.example.com":[{"A":"1.1.1.1"},{"AAAA":"1234::2"},{"MX":[0,"e2.example.com"]},{"SPF":"v=spf1 mx/0 -all"}],"e2a.example.com":[{"AAAA":"1234::1"},{"MX":[0,"e2a.example.com"]},{"SPF":"v=spf1 mx//0 -all"}],"e2b.example.com":[{"A":"1.1.1.1"},{"MX":[0,"e2b.example.com"]},{"SPF":"v=spf1 mx//0 -all"}],"e3.example.com":[{"SPF":"v=spf1 mx:foo.example.com\u0000"}],"e4.example.com":[{"SPF":"v=spf1 mx"},{"A":"1.2.3.4"}],"e5.example.com":[{"SPF":"v=spf1 mx:abc.123"}],"e6.example.com":[{"SPF":"v=spf1 mx//33 -all"}],"e6a.example.com":[{"SPF":"v=spf1 mx/33 -all"}],"e7.example.com":[{"SPF":"v=spf1 mx//129 -all"}],"e9.example.com":[{"SPF":"v=spf1 mx:example.com:8080"}],"e10.example.com":[{"SPF":"v=spf1 mx:foo.example.com/24"}],"foo.example.com":[{"MX":[0,"foo1.example.com"]}],"foo1.example.com":[{"A":"1.1.1.1"},{"A":"1.2.3.5"}],"e11.example.com":[{"SPF":"v=spf1 mx:foo:bar/baz.example.com"}],"foo:bar/baz.example.com":[{"MX":[0,"foo:bar/baz.example.com"]},{"A":"1.2.3.4"}],"e12.example.com":[{"SPF":"v=spf1 mx:example.-com"}],"e13.example.com":[{"SPF":"v=spf1 mx: -all"}]}, failOnNoFake: true, helo: "mail.example.com"}
        let promise = spf.check_host('1.2.3.4', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'NEUTRAL');
        });
      });
      it('mx-implicit', function(){
        let email = 'foo@e4.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"},{"MX":[0,""]},{"SPF":"v=spf1 mx"}],"e1.example.com":[{"SPF":"v=spf1 mx/0 -all"},{"MX":[0,"e1.example.com"]}],"e2.example.com":[{"A":"1.1.1.1"},{"AAAA":"1234::2"},{"MX":[0,"e2.example.com"]},{"SPF":"v=spf1 mx/0 -all"}],"e2a.example.com":[{"AAAA":"1234::1"},{"MX":[0,"e2a.example.com"]},{"SPF":"v=spf1 mx//0 -all"}],"e2b.example.com":[{"A":"1.1.1.1"},{"MX":[0,"e2b.example.com"]},{"SPF":"v=spf1 mx//0 -all"}],"e3.example.com":[{"SPF":"v=spf1 mx:foo.example.com\u0000"}],"e4.example.com":[{"SPF":"v=spf1 mx"},{"A":"1.2.3.4"}],"e5.example.com":[{"SPF":"v=spf1 mx:abc.123"}],"e6.example.com":[{"SPF":"v=spf1 mx//33 -all"}],"e6a.example.com":[{"SPF":"v=spf1 mx/33 -all"}],"e7.example.com":[{"SPF":"v=spf1 mx//129 -all"}],"e9.example.com":[{"SPF":"v=spf1 mx:example.com:8080"}],"e10.example.com":[{"SPF":"v=spf1 mx:foo.example.com/24"}],"foo.example.com":[{"MX":[0,"foo1.example.com"]}],"foo1.example.com":[{"A":"1.1.1.1"},{"A":"1.2.3.5"}],"e11.example.com":[{"SPF":"v=spf1 mx:foo:bar/baz.example.com"}],"foo:bar/baz.example.com":[{"MX":[0,"foo:bar/baz.example.com"]},{"A":"1.2.3.4"}],"e12.example.com":[{"SPF":"v=spf1 mx:example.-com"}],"e13.example.com":[{"SPF":"v=spf1 mx: -all"}]}, failOnNoFake: true, helo: "mail.example.com"}
        let promise = spf.check_host('1.2.3.4', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'NEUTRAL');
        });
      });
      it('mx-empty-domain', function(){
        let email = 'foo@e13.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"},{"MX":[0,""]},{"SPF":"v=spf1 mx"}],"e1.example.com":[{"SPF":"v=spf1 mx/0 -all"},{"MX":[0,"e1.example.com"]}],"e2.example.com":[{"A":"1.1.1.1"},{"AAAA":"1234::2"},{"MX":[0,"e2.example.com"]},{"SPF":"v=spf1 mx/0 -all"}],"e2a.example.com":[{"AAAA":"1234::1"},{"MX":[0,"e2a.example.com"]},{"SPF":"v=spf1 mx//0 -all"}],"e2b.example.com":[{"A":"1.1.1.1"},{"MX":[0,"e2b.example.com"]},{"SPF":"v=spf1 mx//0 -all"}],"e3.example.com":[{"SPF":"v=spf1 mx:foo.example.com\u0000"}],"e4.example.com":[{"SPF":"v=spf1 mx"},{"A":"1.2.3.4"}],"e5.example.com":[{"SPF":"v=spf1 mx:abc.123"}],"e6.example.com":[{"SPF":"v=spf1 mx//33 -all"}],"e6a.example.com":[{"SPF":"v=spf1 mx/33 -all"}],"e7.example.com":[{"SPF":"v=spf1 mx//129 -all"}],"e9.example.com":[{"SPF":"v=spf1 mx:example.com:8080"}],"e10.example.com":[{"SPF":"v=spf1 mx:foo.example.com/24"}],"foo.example.com":[{"MX":[0,"foo1.example.com"]}],"foo1.example.com":[{"A":"1.1.1.1"},{"A":"1.2.3.5"}],"e11.example.com":[{"SPF":"v=spf1 mx:foo:bar/baz.example.com"}],"foo:bar/baz.example.com":[{"MX":[0,"foo:bar/baz.example.com"]},{"A":"1.2.3.4"}],"e12.example.com":[{"SPF":"v=spf1 mx:example.-com"}],"e13.example.com":[{"SPF":"v=spf1 mx: -all"}]}, failOnNoFake: true, helo: "mail.example.com"}
        let promise = spf.check_host('1.2.3.4', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'PERMERROR');
        });
      });
    });
    describe('EXISTS mechanism syntax', function(){
      it('exists-empty-domain', function(){
        let email = 'foo@e1.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"mail6.example.com":[{"AAAA":"CAFE:BABE::4"}],"err.example.com":["TIMEOUT"],"e1.example.com":[{"SPF":"v=spf1 exists:"}],"e2.example.com":[{"SPF":"v=spf1 exists"}],"e3.example.com":[{"SPF":"v=spf1 exists:mail.example.com/24"}],"e4.example.com":[{"SPF":"v=spf1 exists:mail.example.com"}],"e5.example.com":[{"SPF":"v=spf1 exists:mail6.example.com -all"}],"e6.example.com":[{"SPF":"v=spf1 exists:err.example.com -all"}]}, failOnNoFake: true, helo: "mail.example.com"}
        let promise = spf.check_host('1.2.3.4', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'PERMERROR');
        });
      });
      it('exists-implicit', function(){
        let email = 'foo@e2.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"mail6.example.com":[{"AAAA":"CAFE:BABE::4"}],"err.example.com":["TIMEOUT"],"e1.example.com":[{"SPF":"v=spf1 exists:"}],"e2.example.com":[{"SPF":"v=spf1 exists"}],"e3.example.com":[{"SPF":"v=spf1 exists:mail.example.com/24"}],"e4.example.com":[{"SPF":"v=spf1 exists:mail.example.com"}],"e5.example.com":[{"SPF":"v=spf1 exists:mail6.example.com -all"}],"e6.example.com":[{"SPF":"v=spf1 exists:err.example.com -all"}]}, failOnNoFake: true, helo: "mail.example.com"}
        let promise = spf.check_host('1.2.3.4', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'PERMERROR');
        });
      });
      it('exists-cidr', function(){
        let email = 'foo@e3.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"mail6.example.com":[{"AAAA":"CAFE:BABE::4"}],"err.example.com":["TIMEOUT"],"e1.example.com":[{"SPF":"v=spf1 exists:"}],"e2.example.com":[{"SPF":"v=spf1 exists"}],"e3.example.com":[{"SPF":"v=spf1 exists:mail.example.com/24"}],"e4.example.com":[{"SPF":"v=spf1 exists:mail.example.com"}],"e5.example.com":[{"SPF":"v=spf1 exists:mail6.example.com -all"}],"e6.example.com":[{"SPF":"v=spf1 exists:err.example.com -all"}]}, failOnNoFake: true, helo: "mail.example.com"}
        let promise = spf.check_host('1.2.3.4', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'PERMERROR');
        });
      });
      it('exists-ip4', function(){
        let email = 'foo@e4.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"mail6.example.com":[{"AAAA":"CAFE:BABE::4"}],"err.example.com":["TIMEOUT"],"e1.example.com":[{"SPF":"v=spf1 exists:"}],"e2.example.com":[{"SPF":"v=spf1 exists"}],"e3.example.com":[{"SPF":"v=spf1 exists:mail.example.com/24"}],"e4.example.com":[{"SPF":"v=spf1 exists:mail.example.com"}],"e5.example.com":[{"SPF":"v=spf1 exists:mail6.example.com -all"}],"e6.example.com":[{"SPF":"v=spf1 exists:err.example.com -all"}]}, failOnNoFake: true, helo: "mail.example.com"}
        let promise = spf.check_host('1.2.3.4', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'PASS');
        });
      });
      it('exists-ip6', function(){
        let email = 'foo@e4.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"mail6.example.com":[{"AAAA":"CAFE:BABE::4"}],"err.example.com":["TIMEOUT"],"e1.example.com":[{"SPF":"v=spf1 exists:"}],"e2.example.com":[{"SPF":"v=spf1 exists"}],"e3.example.com":[{"SPF":"v=spf1 exists:mail.example.com/24"}],"e4.example.com":[{"SPF":"v=spf1 exists:mail.example.com"}],"e5.example.com":[{"SPF":"v=spf1 exists:mail6.example.com -all"}],"e6.example.com":[{"SPF":"v=spf1 exists:err.example.com -all"}]}, failOnNoFake: true, helo: "mail.example.com"}
        let promise = spf.check_host('CAFE:BABE::3', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'PASS');
        });
      });
      it('exists-ip6only', function(){
        let email = 'foo@e5.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"mail6.example.com":[{"AAAA":"CAFE:BABE::4"}],"err.example.com":["TIMEOUT"],"e1.example.com":[{"SPF":"v=spf1 exists:"}],"e2.example.com":[{"SPF":"v=spf1 exists"}],"e3.example.com":[{"SPF":"v=spf1 exists:mail.example.com/24"}],"e4.example.com":[{"SPF":"v=spf1 exists:mail.example.com"}],"e5.example.com":[{"SPF":"v=spf1 exists:mail6.example.com -all"}],"e6.example.com":[{"SPF":"v=spf1 exists:err.example.com -all"}]}, failOnNoFake: true, helo: "mail.example.com"}
        let promise = spf.check_host('CAFE:BABE::3', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'FAIL');
        });
      });
      it('exists-dnserr', function(){
        let email = 'foo@e6.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"mail6.example.com":[{"AAAA":"CAFE:BABE::4"}],"err.example.com":["TIMEOUT"],"e1.example.com":[{"SPF":"v=spf1 exists:"}],"e2.example.com":[{"SPF":"v=spf1 exists"}],"e3.example.com":[{"SPF":"v=spf1 exists:mail.example.com/24"}],"e4.example.com":[{"SPF":"v=spf1 exists:mail.example.com"}],"e5.example.com":[{"SPF":"v=spf1 exists:mail6.example.com -all"}],"e6.example.com":[{"SPF":"v=spf1 exists:err.example.com -all"}]}, failOnNoFake: true, helo: "mail.example.com"}
        let promise = spf.check_host('CAFE:BABE::3', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.include(["fail","temperror"], result.toLowerCase());
        });
      });
    });
    describe('IP4 mechanism syntax', function(){
      it('cidr4-0', function(){
        let email = 'foo@e1.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 ip4:1.1.1.1/0 -all"}],"e2.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4/32 -all"}],"e3.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4/33 -all"}],"e4.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4/032 -all"}],"e5.example.com":[{"SPF":"v=spf1 ip4"}],"e6.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4//32"}],"e7.example.com":[{"SPF":"v=spf1 -ip4:1.2.3.4 ip6:::FFFF:1.2.3.4"}],"e8.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4:8080"}],"e9.example.com":[{"SPF":"v=spf1 ip4:1.2.3"}]}, failOnNoFake: true, helo: "mail.example.com"}
        let promise = spf.check_host('1.2.3.4', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'PASS');
        });
      });
      it('cidr4-32', function(){
        let email = 'foo@e2.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 ip4:1.1.1.1/0 -all"}],"e2.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4/32 -all"}],"e3.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4/33 -all"}],"e4.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4/032 -all"}],"e5.example.com":[{"SPF":"v=spf1 ip4"}],"e6.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4//32"}],"e7.example.com":[{"SPF":"v=spf1 -ip4:1.2.3.4 ip6:::FFFF:1.2.3.4"}],"e8.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4:8080"}],"e9.example.com":[{"SPF":"v=spf1 ip4:1.2.3"}]}, failOnNoFake: true, helo: "mail.example.com"}
        let promise = spf.check_host('1.2.3.4', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'PASS');
        });
      });
      it('cidr4-33', function(){
        let email = 'foo@e3.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 ip4:1.1.1.1/0 -all"}],"e2.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4/32 -all"}],"e3.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4/33 -all"}],"e4.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4/032 -all"}],"e5.example.com":[{"SPF":"v=spf1 ip4"}],"e6.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4//32"}],"e7.example.com":[{"SPF":"v=spf1 -ip4:1.2.3.4 ip6:::FFFF:1.2.3.4"}],"e8.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4:8080"}],"e9.example.com":[{"SPF":"v=spf1 ip4:1.2.3"}]}, failOnNoFake: true, helo: "mail.example.com"}
        let promise = spf.check_host('1.2.3.4', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'PERMERROR');
        });
      });
      it('cidr4-032', function(){
        let email = 'foo@e4.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 ip4:1.1.1.1/0 -all"}],"e2.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4/32 -all"}],"e3.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4/33 -all"}],"e4.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4/032 -all"}],"e5.example.com":[{"SPF":"v=spf1 ip4"}],"e6.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4//32"}],"e7.example.com":[{"SPF":"v=spf1 -ip4:1.2.3.4 ip6:::FFFF:1.2.3.4"}],"e8.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4:8080"}],"e9.example.com":[{"SPF":"v=spf1 ip4:1.2.3"}]}, failOnNoFake: true, helo: "mail.example.com"}
        let promise = spf.check_host('1.2.3.4', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'PERMERROR');
        });
      });
      it('bare-ip4', function(){
        let email = 'foo@e5.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 ip4:1.1.1.1/0 -all"}],"e2.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4/32 -all"}],"e3.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4/33 -all"}],"e4.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4/032 -all"}],"e5.example.com":[{"SPF":"v=spf1 ip4"}],"e6.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4//32"}],"e7.example.com":[{"SPF":"v=spf1 -ip4:1.2.3.4 ip6:::FFFF:1.2.3.4"}],"e8.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4:8080"}],"e9.example.com":[{"SPF":"v=spf1 ip4:1.2.3"}]}, failOnNoFake: true, helo: "mail.example.com"}
        let promise = spf.check_host('1.2.3.4', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'PERMERROR');
        });
      });
      it('bad-ip4-port', function(){
        let email = 'foo@e8.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 ip4:1.1.1.1/0 -all"}],"e2.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4/32 -all"}],"e3.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4/33 -all"}],"e4.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4/032 -all"}],"e5.example.com":[{"SPF":"v=spf1 ip4"}],"e6.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4//32"}],"e7.example.com":[{"SPF":"v=spf1 -ip4:1.2.3.4 ip6:::FFFF:1.2.3.4"}],"e8.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4:8080"}],"e9.example.com":[{"SPF":"v=spf1 ip4:1.2.3"}]}, failOnNoFake: true, helo: "mail.example.com"}
        let promise = spf.check_host('1.2.3.4', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'PERMERROR');
        });
      });
      it('bad-ip4-short', function(){
        let email = 'foo@e9.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 ip4:1.1.1.1/0 -all"}],"e2.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4/32 -all"}],"e3.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4/33 -all"}],"e4.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4/032 -all"}],"e5.example.com":[{"SPF":"v=spf1 ip4"}],"e6.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4//32"}],"e7.example.com":[{"SPF":"v=spf1 -ip4:1.2.3.4 ip6:::FFFF:1.2.3.4"}],"e8.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4:8080"}],"e9.example.com":[{"SPF":"v=spf1 ip4:1.2.3"}]}, failOnNoFake: true, helo: "mail.example.com"}
        let promise = spf.check_host('1.2.3.4', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'PERMERROR');
        });
      });
      it('ip4-dual-cidr', function(){
        let email = 'foo@e6.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 ip4:1.1.1.1/0 -all"}],"e2.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4/32 -all"}],"e3.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4/33 -all"}],"e4.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4/032 -all"}],"e5.example.com":[{"SPF":"v=spf1 ip4"}],"e6.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4//32"}],"e7.example.com":[{"SPF":"v=spf1 -ip4:1.2.3.4 ip6:::FFFF:1.2.3.4"}],"e8.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4:8080"}],"e9.example.com":[{"SPF":"v=spf1 ip4:1.2.3"}]}, failOnNoFake: true, helo: "mail.example.com"}
        let promise = spf.check_host('1.2.3.4', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'PERMERROR');
        });
      });
      it('ip4-mapped-ip6', function(){
        let email = 'foo@e7.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 ip4:1.1.1.1/0 -all"}],"e2.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4/32 -all"}],"e3.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4/33 -all"}],"e4.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4/032 -all"}],"e5.example.com":[{"SPF":"v=spf1 ip4"}],"e6.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4//32"}],"e7.example.com":[{"SPF":"v=spf1 -ip4:1.2.3.4 ip6:::FFFF:1.2.3.4"}],"e8.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4:8080"}],"e9.example.com":[{"SPF":"v=spf1 ip4:1.2.3"}]}, failOnNoFake: true, helo: "mail.example.com"}
        let promise = spf.check_host('::FFFF:1.2.3.4', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'FAIL');
        });
      });
    });
    describe('IP6 mechanism syntax', function(){
      it('bare-ip6', function(){
        let email = 'foo@e1.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 -all ip6"}],"e2.example.com":[{"SPF":"v=spf1 ip6:::1.1.1.1/0"}],"e3.example.com":[{"SPF":"v=spf1 ip6:::1.1.1.1/129"}],"e4.example.com":[{"SPF":"v=spf1 ip6:::1.1.1.1//33"}],"e5.example.com":[{"SPF":"v=spf1 ip6:CAFE:BABE:8000::/33"}],"e6.example.com":[{"SPF":"v=spf1 ip6::CAFE::BABE"}]}, failOnNoFake: true, helo: "mail.example.com"}
        let promise = spf.check_host('1.2.3.4', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'PERMERROR');
        });
      });
      it('cidr6-0-ip4', function(){
        let email = 'foo@e2.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 -all ip6"}],"e2.example.com":[{"SPF":"v=spf1 ip6:::1.1.1.1/0"}],"e3.example.com":[{"SPF":"v=spf1 ip6:::1.1.1.1/129"}],"e4.example.com":[{"SPF":"v=spf1 ip6:::1.1.1.1//33"}],"e5.example.com":[{"SPF":"v=spf1 ip6:CAFE:BABE:8000::/33"}],"e6.example.com":[{"SPF":"v=spf1 ip6::CAFE::BABE"}]}, failOnNoFake: true, helo: "mail.example.com"}
        let promise = spf.check_host('1.2.3.4', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.include(["neutral","pass"], result.toLowerCase());
        });
      });
      it('cidr6-ip4', function(){
        let email = 'foo@e2.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 -all ip6"}],"e2.example.com":[{"SPF":"v=spf1 ip6:::1.1.1.1/0"}],"e3.example.com":[{"SPF":"v=spf1 ip6:::1.1.1.1/129"}],"e4.example.com":[{"SPF":"v=spf1 ip6:::1.1.1.1//33"}],"e5.example.com":[{"SPF":"v=spf1 ip6:CAFE:BABE:8000::/33"}],"e6.example.com":[{"SPF":"v=spf1 ip6::CAFE::BABE"}]}, failOnNoFake: true, helo: "mail.example.com"}
        let promise = spf.check_host('::FFFF:1.2.3.4', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.include(["neutral","pass"], result.toLowerCase());
        });
      });
      it('cidr6-0', function(){
        let email = 'foo@e2.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 -all ip6"}],"e2.example.com":[{"SPF":"v=spf1 ip6:::1.1.1.1/0"}],"e3.example.com":[{"SPF":"v=spf1 ip6:::1.1.1.1/129"}],"e4.example.com":[{"SPF":"v=spf1 ip6:::1.1.1.1//33"}],"e5.example.com":[{"SPF":"v=spf1 ip6:CAFE:BABE:8000::/33"}],"e6.example.com":[{"SPF":"v=spf1 ip6::CAFE::BABE"}]}, failOnNoFake: true, helo: "mail.example.com"}
        let promise = spf.check_host('DEAF:BABE::CAB:FEE', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'PASS');
        });
      });
      it('cidr6-129', function(){
        let email = 'foo@e3.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 -all ip6"}],"e2.example.com":[{"SPF":"v=spf1 ip6:::1.1.1.1/0"}],"e3.example.com":[{"SPF":"v=spf1 ip6:::1.1.1.1/129"}],"e4.example.com":[{"SPF":"v=spf1 ip6:::1.1.1.1//33"}],"e5.example.com":[{"SPF":"v=spf1 ip6:CAFE:BABE:8000::/33"}],"e6.example.com":[{"SPF":"v=spf1 ip6::CAFE::BABE"}]}, failOnNoFake: true, helo: "mail.example.com"}
        let promise = spf.check_host('1.2.3.4', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'PERMERROR');
        });
      });
      it('cidr6-bad', function(){
        let email = 'foo@e4.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 -all ip6"}],"e2.example.com":[{"SPF":"v=spf1 ip6:::1.1.1.1/0"}],"e3.example.com":[{"SPF":"v=spf1 ip6:::1.1.1.1/129"}],"e4.example.com":[{"SPF":"v=spf1 ip6:::1.1.1.1//33"}],"e5.example.com":[{"SPF":"v=spf1 ip6:CAFE:BABE:8000::/33"}],"e6.example.com":[{"SPF":"v=spf1 ip6::CAFE::BABE"}]}, failOnNoFake: true, helo: "mail.example.com"}
        let promise = spf.check_host('1.2.3.4', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'PERMERROR');
        });
      });
      it('cidr6-33', function(){
        let email = 'foo@e5.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 -all ip6"}],"e2.example.com":[{"SPF":"v=spf1 ip6:::1.1.1.1/0"}],"e3.example.com":[{"SPF":"v=spf1 ip6:::1.1.1.1/129"}],"e4.example.com":[{"SPF":"v=spf1 ip6:::1.1.1.1//33"}],"e5.example.com":[{"SPF":"v=spf1 ip6:CAFE:BABE:8000::/33"}],"e6.example.com":[{"SPF":"v=spf1 ip6::CAFE::BABE"}]}, failOnNoFake: true, helo: "mail.example.com"}
        let promise = spf.check_host('CAFE:BABE:8000::', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'PASS');
        });
      });
      it('cidr6-33-ip4', function(){
        let email = 'foo@e5.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 -all ip6"}],"e2.example.com":[{"SPF":"v=spf1 ip6:::1.1.1.1/0"}],"e3.example.com":[{"SPF":"v=spf1 ip6:::1.1.1.1/129"}],"e4.example.com":[{"SPF":"v=spf1 ip6:::1.1.1.1//33"}],"e5.example.com":[{"SPF":"v=spf1 ip6:CAFE:BABE:8000::/33"}],"e6.example.com":[{"SPF":"v=spf1 ip6::CAFE::BABE"}]}, failOnNoFake: true, helo: "mail.example.com"}
        let promise = spf.check_host('1.2.3.4', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'NEUTRAL');
        });
      });
      it('ip6-bad1', function(){
        let email = 'foo@e6.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 -all ip6"}],"e2.example.com":[{"SPF":"v=spf1 ip6:::1.1.1.1/0"}],"e3.example.com":[{"SPF":"v=spf1 ip6:::1.1.1.1/129"}],"e4.example.com":[{"SPF":"v=spf1 ip6:::1.1.1.1//33"}],"e5.example.com":[{"SPF":"v=spf1 ip6:CAFE:BABE:8000::/33"}],"e6.example.com":[{"SPF":"v=spf1 ip6::CAFE::BABE"}]}, failOnNoFake: true, helo: "mail.example.com"}
        let promise = spf.check_host('1.2.3.4', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'PERMERROR');
        });
      });
    });
    describe('Semantics of exp and other modifiers', function(){
      it('redirect-none', function(){
        let email = 'foo@e10.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 exp=exp1.example.com redirect=e2.example.com"}],"e2.example.com":[{"SPF":"v=spf1 -all"}],"e3.example.com":[{"SPF":"v=spf1 exp=exp1.example.com redirect=e4.example.com"}],"e4.example.com":[{"SPF":"v=spf1 -all exp=exp2.example.com"}],"exp1.example.com":[{"TXT":"No-see-um"}],"exp2.example.com":[{"TXT":"See me."}],"exp3.example.com":[{"TXT":"Correct!"}],"exp4.example.com":[{"TXT":"%{l} in implementation"}],"e5.example.com":[{"SPF":"v=spf1 1up=foo"}],"e6.example.com":[{"SPF":"v=spf1 =all"}],"e7.example.com":[{"SPF":"v=spf1 include:e3.example.com -all exp=exp3.example.com"}],"e8.example.com":[{"SPF":"v=spf1 -all exp=exp4.example.com"}],"e9.example.com":[{"SPF":"v=spf1 -all foo=%abc"}],"e10.example.com":[{"SPF":"v=spf1 redirect=erehwon.example.com"}],"e11.example.com":[{"SPF":"v=spf1 -all exp=e11msg.example.com"}],"e11msg.example.com":[{"TXT":"Answer a fool according to his folly."},{"TXT":"Do not answer a fool according to his folly."}],"e12.example.com":[{"SPF":"v=spf1 exp= -all"}],"e13.example.com":[{"SPF":"v=spf1 exp=e13msg.example.com -all"}],"e13msg.example.com":[{"TXT":"The %{x}-files."}],"e14.example.com":[{"SPF":"v=spf1 exp=e13msg.example.com -all exp=e11msg.example.com"}],"e15.example.com":[{"SPF":"v=spf1 redirect=e12.example.com -all redirect=e12.example.com"}],"e16.example.com":[{"SPF":"v=spf1 exp=-all"}],"e17.example.com":[{"SPF":"v=spf1 redirect=-all ?all"}],"e18.example.com":[{"SPF":"v=spf1 ?all redirect="}],"e19.example.com":[{"SPF":"v=spf1 default=pass"}],"e20.example.com":[{"SPF":"v=spf1 default=+"}],"e21.example.com":[{"SPF":"v=spf1 exp=e21msg.example.com -all"}],"e21msg.example.com":["TIMEOUT"],"e22.example.com":[{"SPF":"v=spf1 exp=mail.example.com -all"}],"nonascii.example.com":[{"SPF":"v=spf1 exp=badexp.example.com -all"}],"badexp.example.com":[{"TXT":"ï»¿Explanation"}],"tworecs.example.com":[{"SPF":"v=spf1 exp=twoexp.example.com -all"}],"twoexp.example.com":[{"TXT":"one"},{"TXT":"two"}]}, failOnNoFake: true, helo: "mail.example.com"}
        let promise = spf.check_host('1.2.3.4', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'PERMERROR');
        });
      });
      it('redirect-cancels-exp', function(){
        let email = 'foo@e1.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 exp=exp1.example.com redirect=e2.example.com"}],"e2.example.com":[{"SPF":"v=spf1 -all"}],"e3.example.com":[{"SPF":"v=spf1 exp=exp1.example.com redirect=e4.example.com"}],"e4.example.com":[{"SPF":"v=spf1 -all exp=exp2.example.com"}],"exp1.example.com":[{"TXT":"No-see-um"}],"exp2.example.com":[{"TXT":"See me."}],"exp3.example.com":[{"TXT":"Correct!"}],"exp4.example.com":[{"TXT":"%{l} in implementation"}],"e5.example.com":[{"SPF":"v=spf1 1up=foo"}],"e6.example.com":[{"SPF":"v=spf1 =all"}],"e7.example.com":[{"SPF":"v=spf1 include:e3.example.com -all exp=exp3.example.com"}],"e8.example.com":[{"SPF":"v=spf1 -all exp=exp4.example.com"}],"e9.example.com":[{"SPF":"v=spf1 -all foo=%abc"}],"e10.example.com":[{"SPF":"v=spf1 redirect=erehwon.example.com"}],"e11.example.com":[{"SPF":"v=spf1 -all exp=e11msg.example.com"}],"e11msg.example.com":[{"TXT":"Answer a fool according to his folly."},{"TXT":"Do not answer a fool according to his folly."}],"e12.example.com":[{"SPF":"v=spf1 exp= -all"}],"e13.example.com":[{"SPF":"v=spf1 exp=e13msg.example.com -all"}],"e13msg.example.com":[{"TXT":"The %{x}-files."}],"e14.example.com":[{"SPF":"v=spf1 exp=e13msg.example.com -all exp=e11msg.example.com"}],"e15.example.com":[{"SPF":"v=spf1 redirect=e12.example.com -all redirect=e12.example.com"}],"e16.example.com":[{"SPF":"v=spf1 exp=-all"}],"e17.example.com":[{"SPF":"v=spf1 redirect=-all ?all"}],"e18.example.com":[{"SPF":"v=spf1 ?all redirect="}],"e19.example.com":[{"SPF":"v=spf1 default=pass"}],"e20.example.com":[{"SPF":"v=spf1 default=+"}],"e21.example.com":[{"SPF":"v=spf1 exp=e21msg.example.com -all"}],"e21msg.example.com":["TIMEOUT"],"e22.example.com":[{"SPF":"v=spf1 exp=mail.example.com -all"}],"nonascii.example.com":[{"SPF":"v=spf1 exp=badexp.example.com -all"}],"badexp.example.com":[{"TXT":"ï»¿Explanation"}],"tworecs.example.com":[{"SPF":"v=spf1 exp=twoexp.example.com -all"}],"twoexp.example.com":[{"TXT":"one"},{"TXT":"two"}]}, failOnNoFake: true, helo: "mail.example.com"}
        let promise = spf.check_host('1.2.3.4', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'FAIL');
        });
      });
      it('redirect-syntax-error', function(){
        let email = 'foo@e17.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 exp=exp1.example.com redirect=e2.example.com"}],"e2.example.com":[{"SPF":"v=spf1 -all"}],"e3.example.com":[{"SPF":"v=spf1 exp=exp1.example.com redirect=e4.example.com"}],"e4.example.com":[{"SPF":"v=spf1 -all exp=exp2.example.com"}],"exp1.example.com":[{"TXT":"No-see-um"}],"exp2.example.com":[{"TXT":"See me."}],"exp3.example.com":[{"TXT":"Correct!"}],"exp4.example.com":[{"TXT":"%{l} in implementation"}],"e5.example.com":[{"SPF":"v=spf1 1up=foo"}],"e6.example.com":[{"SPF":"v=spf1 =all"}],"e7.example.com":[{"SPF":"v=spf1 include:e3.example.com -all exp=exp3.example.com"}],"e8.example.com":[{"SPF":"v=spf1 -all exp=exp4.example.com"}],"e9.example.com":[{"SPF":"v=spf1 -all foo=%abc"}],"e10.example.com":[{"SPF":"v=spf1 redirect=erehwon.example.com"}],"e11.example.com":[{"SPF":"v=spf1 -all exp=e11msg.example.com"}],"e11msg.example.com":[{"TXT":"Answer a fool according to his folly."},{"TXT":"Do not answer a fool according to his folly."}],"e12.example.com":[{"SPF":"v=spf1 exp= -all"}],"e13.example.com":[{"SPF":"v=spf1 exp=e13msg.example.com -all"}],"e13msg.example.com":[{"TXT":"The %{x}-files."}],"e14.example.com":[{"SPF":"v=spf1 exp=e13msg.example.com -all exp=e11msg.example.com"}],"e15.example.com":[{"SPF":"v=spf1 redirect=e12.example.com -all redirect=e12.example.com"}],"e16.example.com":[{"SPF":"v=spf1 exp=-all"}],"e17.example.com":[{"SPF":"v=spf1 redirect=-all ?all"}],"e18.example.com":[{"SPF":"v=spf1 ?all redirect="}],"e19.example.com":[{"SPF":"v=spf1 default=pass"}],"e20.example.com":[{"SPF":"v=spf1 default=+"}],"e21.example.com":[{"SPF":"v=spf1 exp=e21msg.example.com -all"}],"e21msg.example.com":["TIMEOUT"],"e22.example.com":[{"SPF":"v=spf1 exp=mail.example.com -all"}],"nonascii.example.com":[{"SPF":"v=spf1 exp=badexp.example.com -all"}],"badexp.example.com":[{"TXT":"ï»¿Explanation"}],"tworecs.example.com":[{"SPF":"v=spf1 exp=twoexp.example.com -all"}],"twoexp.example.com":[{"TXT":"one"},{"TXT":"two"}]}, failOnNoFake: true, helo: "mail.example.com"}
        let promise = spf.check_host('1.2.3.4', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'PERMERROR');
        });
      });
      it('include-ignores-exp', function(){
        let email = 'foo@e7.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 exp=exp1.example.com redirect=e2.example.com"}],"e2.example.com":[{"SPF":"v=spf1 -all"}],"e3.example.com":[{"SPF":"v=spf1 exp=exp1.example.com redirect=e4.example.com"}],"e4.example.com":[{"SPF":"v=spf1 -all exp=exp2.example.com"}],"exp1.example.com":[{"TXT":"No-see-um"}],"exp2.example.com":[{"TXT":"See me."}],"exp3.example.com":[{"TXT":"Correct!"}],"exp4.example.com":[{"TXT":"%{l} in implementation"}],"e5.example.com":[{"SPF":"v=spf1 1up=foo"}],"e6.example.com":[{"SPF":"v=spf1 =all"}],"e7.example.com":[{"SPF":"v=spf1 include:e3.example.com -all exp=exp3.example.com"}],"e8.example.com":[{"SPF":"v=spf1 -all exp=exp4.example.com"}],"e9.example.com":[{"SPF":"v=spf1 -all foo=%abc"}],"e10.example.com":[{"SPF":"v=spf1 redirect=erehwon.example.com"}],"e11.example.com":[{"SPF":"v=spf1 -all exp=e11msg.example.com"}],"e11msg.example.com":[{"TXT":"Answer a fool according to his folly."},{"TXT":"Do not answer a fool according to his folly."}],"e12.example.com":[{"SPF":"v=spf1 exp= -all"}],"e13.example.com":[{"SPF":"v=spf1 exp=e13msg.example.com -all"}],"e13msg.example.com":[{"TXT":"The %{x}-files."}],"e14.example.com":[{"SPF":"v=spf1 exp=e13msg.example.com -all exp=e11msg.example.com"}],"e15.example.com":[{"SPF":"v=spf1 redirect=e12.example.com -all redirect=e12.example.com"}],"e16.example.com":[{"SPF":"v=spf1 exp=-all"}],"e17.example.com":[{"SPF":"v=spf1 redirect=-all ?all"}],"e18.example.com":[{"SPF":"v=spf1 ?all redirect="}],"e19.example.com":[{"SPF":"v=spf1 default=pass"}],"e20.example.com":[{"SPF":"v=spf1 default=+"}],"e21.example.com":[{"SPF":"v=spf1 exp=e21msg.example.com -all"}],"e21msg.example.com":["TIMEOUT"],"e22.example.com":[{"SPF":"v=spf1 exp=mail.example.com -all"}],"nonascii.example.com":[{"SPF":"v=spf1 exp=badexp.example.com -all"}],"badexp.example.com":[{"TXT":"ï»¿Explanation"}],"tworecs.example.com":[{"SPF":"v=spf1 exp=twoexp.example.com -all"}],"twoexp.example.com":[{"TXT":"one"},{"TXT":"two"}]}, failOnNoFake: true, helo: "mail.example.com"}
        let promise = spf.check_host('1.2.3.4', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'FAIL');
        });
      });
      it('redirect-cancels-prior-exp', function(){
        let email = 'foo@e3.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 exp=exp1.example.com redirect=e2.example.com"}],"e2.example.com":[{"SPF":"v=spf1 -all"}],"e3.example.com":[{"SPF":"v=spf1 exp=exp1.example.com redirect=e4.example.com"}],"e4.example.com":[{"SPF":"v=spf1 -all exp=exp2.example.com"}],"exp1.example.com":[{"TXT":"No-see-um"}],"exp2.example.com":[{"TXT":"See me."}],"exp3.example.com":[{"TXT":"Correct!"}],"exp4.example.com":[{"TXT":"%{l} in implementation"}],"e5.example.com":[{"SPF":"v=spf1 1up=foo"}],"e6.example.com":[{"SPF":"v=spf1 =all"}],"e7.example.com":[{"SPF":"v=spf1 include:e3.example.com -all exp=exp3.example.com"}],"e8.example.com":[{"SPF":"v=spf1 -all exp=exp4.example.com"}],"e9.example.com":[{"SPF":"v=spf1 -all foo=%abc"}],"e10.example.com":[{"SPF":"v=spf1 redirect=erehwon.example.com"}],"e11.example.com":[{"SPF":"v=spf1 -all exp=e11msg.example.com"}],"e11msg.example.com":[{"TXT":"Answer a fool according to his folly."},{"TXT":"Do not answer a fool according to his folly."}],"e12.example.com":[{"SPF":"v=spf1 exp= -all"}],"e13.example.com":[{"SPF":"v=spf1 exp=e13msg.example.com -all"}],"e13msg.example.com":[{"TXT":"The %{x}-files."}],"e14.example.com":[{"SPF":"v=spf1 exp=e13msg.example.com -all exp=e11msg.example.com"}],"e15.example.com":[{"SPF":"v=spf1 redirect=e12.example.com -all redirect=e12.example.com"}],"e16.example.com":[{"SPF":"v=spf1 exp=-all"}],"e17.example.com":[{"SPF":"v=spf1 redirect=-all ?all"}],"e18.example.com":[{"SPF":"v=spf1 ?all redirect="}],"e19.example.com":[{"SPF":"v=spf1 default=pass"}],"e20.example.com":[{"SPF":"v=spf1 default=+"}],"e21.example.com":[{"SPF":"v=spf1 exp=e21msg.example.com -all"}],"e21msg.example.com":["TIMEOUT"],"e22.example.com":[{"SPF":"v=spf1 exp=mail.example.com -all"}],"nonascii.example.com":[{"SPF":"v=spf1 exp=badexp.example.com -all"}],"badexp.example.com":[{"TXT":"ï»¿Explanation"}],"tworecs.example.com":[{"SPF":"v=spf1 exp=twoexp.example.com -all"}],"twoexp.example.com":[{"TXT":"one"},{"TXT":"two"}]}, failOnNoFake: true, helo: "mail.example.com"}
        let promise = spf.check_host('1.2.3.4', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'FAIL');
        });
      });
      it('invalid-modifier', function(){
        let email = 'foo@e5.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 exp=exp1.example.com redirect=e2.example.com"}],"e2.example.com":[{"SPF":"v=spf1 -all"}],"e3.example.com":[{"SPF":"v=spf1 exp=exp1.example.com redirect=e4.example.com"}],"e4.example.com":[{"SPF":"v=spf1 -all exp=exp2.example.com"}],"exp1.example.com":[{"TXT":"No-see-um"}],"exp2.example.com":[{"TXT":"See me."}],"exp3.example.com":[{"TXT":"Correct!"}],"exp4.example.com":[{"TXT":"%{l} in implementation"}],"e5.example.com":[{"SPF":"v=spf1 1up=foo"}],"e6.example.com":[{"SPF":"v=spf1 =all"}],"e7.example.com":[{"SPF":"v=spf1 include:e3.example.com -all exp=exp3.example.com"}],"e8.example.com":[{"SPF":"v=spf1 -all exp=exp4.example.com"}],"e9.example.com":[{"SPF":"v=spf1 -all foo=%abc"}],"e10.example.com":[{"SPF":"v=spf1 redirect=erehwon.example.com"}],"e11.example.com":[{"SPF":"v=spf1 -all exp=e11msg.example.com"}],"e11msg.example.com":[{"TXT":"Answer a fool according to his folly."},{"TXT":"Do not answer a fool according to his folly."}],"e12.example.com":[{"SPF":"v=spf1 exp= -all"}],"e13.example.com":[{"SPF":"v=spf1 exp=e13msg.example.com -all"}],"e13msg.example.com":[{"TXT":"The %{x}-files."}],"e14.example.com":[{"SPF":"v=spf1 exp=e13msg.example.com -all exp=e11msg.example.com"}],"e15.example.com":[{"SPF":"v=spf1 redirect=e12.example.com -all redirect=e12.example.com"}],"e16.example.com":[{"SPF":"v=spf1 exp=-all"}],"e17.example.com":[{"SPF":"v=spf1 redirect=-all ?all"}],"e18.example.com":[{"SPF":"v=spf1 ?all redirect="}],"e19.example.com":[{"SPF":"v=spf1 default=pass"}],"e20.example.com":[{"SPF":"v=spf1 default=+"}],"e21.example.com":[{"SPF":"v=spf1 exp=e21msg.example.com -all"}],"e21msg.example.com":["TIMEOUT"],"e22.example.com":[{"SPF":"v=spf1 exp=mail.example.com -all"}],"nonascii.example.com":[{"SPF":"v=spf1 exp=badexp.example.com -all"}],"badexp.example.com":[{"TXT":"ï»¿Explanation"}],"tworecs.example.com":[{"SPF":"v=spf1 exp=twoexp.example.com -all"}],"twoexp.example.com":[{"TXT":"one"},{"TXT":"two"}]}, failOnNoFake: true, helo: "mail.example.com"}
        let promise = spf.check_host('1.2.3.4', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'PERMERROR');
        });
      });
      it('empty-modifier-name', function(){
        let email = 'foo@e6.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 exp=exp1.example.com redirect=e2.example.com"}],"e2.example.com":[{"SPF":"v=spf1 -all"}],"e3.example.com":[{"SPF":"v=spf1 exp=exp1.example.com redirect=e4.example.com"}],"e4.example.com":[{"SPF":"v=spf1 -all exp=exp2.example.com"}],"exp1.example.com":[{"TXT":"No-see-um"}],"exp2.example.com":[{"TXT":"See me."}],"exp3.example.com":[{"TXT":"Correct!"}],"exp4.example.com":[{"TXT":"%{l} in implementation"}],"e5.example.com":[{"SPF":"v=spf1 1up=foo"}],"e6.example.com":[{"SPF":"v=spf1 =all"}],"e7.example.com":[{"SPF":"v=spf1 include:e3.example.com -all exp=exp3.example.com"}],"e8.example.com":[{"SPF":"v=spf1 -all exp=exp4.example.com"}],"e9.example.com":[{"SPF":"v=spf1 -all foo=%abc"}],"e10.example.com":[{"SPF":"v=spf1 redirect=erehwon.example.com"}],"e11.example.com":[{"SPF":"v=spf1 -all exp=e11msg.example.com"}],"e11msg.example.com":[{"TXT":"Answer a fool according to his folly."},{"TXT":"Do not answer a fool according to his folly."}],"e12.example.com":[{"SPF":"v=spf1 exp= -all"}],"e13.example.com":[{"SPF":"v=spf1 exp=e13msg.example.com -all"}],"e13msg.example.com":[{"TXT":"The %{x}-files."}],"e14.example.com":[{"SPF":"v=spf1 exp=e13msg.example.com -all exp=e11msg.example.com"}],"e15.example.com":[{"SPF":"v=spf1 redirect=e12.example.com -all redirect=e12.example.com"}],"e16.example.com":[{"SPF":"v=spf1 exp=-all"}],"e17.example.com":[{"SPF":"v=spf1 redirect=-all ?all"}],"e18.example.com":[{"SPF":"v=spf1 ?all redirect="}],"e19.example.com":[{"SPF":"v=spf1 default=pass"}],"e20.example.com":[{"SPF":"v=spf1 default=+"}],"e21.example.com":[{"SPF":"v=spf1 exp=e21msg.example.com -all"}],"e21msg.example.com":["TIMEOUT"],"e22.example.com":[{"SPF":"v=spf1 exp=mail.example.com -all"}],"nonascii.example.com":[{"SPF":"v=spf1 exp=badexp.example.com -all"}],"badexp.example.com":[{"TXT":"ï»¿Explanation"}],"tworecs.example.com":[{"SPF":"v=spf1 exp=twoexp.example.com -all"}],"twoexp.example.com":[{"TXT":"one"},{"TXT":"two"}]}, failOnNoFake: true, helo: "mail.example.com"}
        let promise = spf.check_host('1.2.3.4', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'PERMERROR');
        });
      });
      it('dorky-sentinel', function(){
        let email = 'Macro Error@e8.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 exp=exp1.example.com redirect=e2.example.com"}],"e2.example.com":[{"SPF":"v=spf1 -all"}],"e3.example.com":[{"SPF":"v=spf1 exp=exp1.example.com redirect=e4.example.com"}],"e4.example.com":[{"SPF":"v=spf1 -all exp=exp2.example.com"}],"exp1.example.com":[{"TXT":"No-see-um"}],"exp2.example.com":[{"TXT":"See me."}],"exp3.example.com":[{"TXT":"Correct!"}],"exp4.example.com":[{"TXT":"%{l} in implementation"}],"e5.example.com":[{"SPF":"v=spf1 1up=foo"}],"e6.example.com":[{"SPF":"v=spf1 =all"}],"e7.example.com":[{"SPF":"v=spf1 include:e3.example.com -all exp=exp3.example.com"}],"e8.example.com":[{"SPF":"v=spf1 -all exp=exp4.example.com"}],"e9.example.com":[{"SPF":"v=spf1 -all foo=%abc"}],"e10.example.com":[{"SPF":"v=spf1 redirect=erehwon.example.com"}],"e11.example.com":[{"SPF":"v=spf1 -all exp=e11msg.example.com"}],"e11msg.example.com":[{"TXT":"Answer a fool according to his folly."},{"TXT":"Do not answer a fool according to his folly."}],"e12.example.com":[{"SPF":"v=spf1 exp= -all"}],"e13.example.com":[{"SPF":"v=spf1 exp=e13msg.example.com -all"}],"e13msg.example.com":[{"TXT":"The %{x}-files."}],"e14.example.com":[{"SPF":"v=spf1 exp=e13msg.example.com -all exp=e11msg.example.com"}],"e15.example.com":[{"SPF":"v=spf1 redirect=e12.example.com -all redirect=e12.example.com"}],"e16.example.com":[{"SPF":"v=spf1 exp=-all"}],"e17.example.com":[{"SPF":"v=spf1 redirect=-all ?all"}],"e18.example.com":[{"SPF":"v=spf1 ?all redirect="}],"e19.example.com":[{"SPF":"v=spf1 default=pass"}],"e20.example.com":[{"SPF":"v=spf1 default=+"}],"e21.example.com":[{"SPF":"v=spf1 exp=e21msg.example.com -all"}],"e21msg.example.com":["TIMEOUT"],"e22.example.com":[{"SPF":"v=spf1 exp=mail.example.com -all"}],"nonascii.example.com":[{"SPF":"v=spf1 exp=badexp.example.com -all"}],"badexp.example.com":[{"TXT":"ï»¿Explanation"}],"tworecs.example.com":[{"SPF":"v=spf1 exp=twoexp.example.com -all"}],"twoexp.example.com":[{"TXT":"one"},{"TXT":"two"}]}, failOnNoFake: true, helo: "mail.example.com"}
        let promise = spf.check_host('1.2.3.4', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'FAIL');
        });
      });
      it('exp-multiple-txt', function(){
        let email = 'foo@e11.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 exp=exp1.example.com redirect=e2.example.com"}],"e2.example.com":[{"SPF":"v=spf1 -all"}],"e3.example.com":[{"SPF":"v=spf1 exp=exp1.example.com redirect=e4.example.com"}],"e4.example.com":[{"SPF":"v=spf1 -all exp=exp2.example.com"}],"exp1.example.com":[{"TXT":"No-see-um"}],"exp2.example.com":[{"TXT":"See me."}],"exp3.example.com":[{"TXT":"Correct!"}],"exp4.example.com":[{"TXT":"%{l} in implementation"}],"e5.example.com":[{"SPF":"v=spf1 1up=foo"}],"e6.example.com":[{"SPF":"v=spf1 =all"}],"e7.example.com":[{"SPF":"v=spf1 include:e3.example.com -all exp=exp3.example.com"}],"e8.example.com":[{"SPF":"v=spf1 -all exp=exp4.example.com"}],"e9.example.com":[{"SPF":"v=spf1 -all foo=%abc"}],"e10.example.com":[{"SPF":"v=spf1 redirect=erehwon.example.com"}],"e11.example.com":[{"SPF":"v=spf1 -all exp=e11msg.example.com"}],"e11msg.example.com":[{"TXT":"Answer a fool according to his folly."},{"TXT":"Do not answer a fool according to his folly."}],"e12.example.com":[{"SPF":"v=spf1 exp= -all"}],"e13.example.com":[{"SPF":"v=spf1 exp=e13msg.example.com -all"}],"e13msg.example.com":[{"TXT":"The %{x}-files."}],"e14.example.com":[{"SPF":"v=spf1 exp=e13msg.example.com -all exp=e11msg.example.com"}],"e15.example.com":[{"SPF":"v=spf1 redirect=e12.example.com -all redirect=e12.example.com"}],"e16.example.com":[{"SPF":"v=spf1 exp=-all"}],"e17.example.com":[{"SPF":"v=spf1 redirect=-all ?all"}],"e18.example.com":[{"SPF":"v=spf1 ?all redirect="}],"e19.example.com":[{"SPF":"v=spf1 default=pass"}],"e20.example.com":[{"SPF":"v=spf1 default=+"}],"e21.example.com":[{"SPF":"v=spf1 exp=e21msg.example.com -all"}],"e21msg.example.com":["TIMEOUT"],"e22.example.com":[{"SPF":"v=spf1 exp=mail.example.com -all"}],"nonascii.example.com":[{"SPF":"v=spf1 exp=badexp.example.com -all"}],"badexp.example.com":[{"TXT":"ï»¿Explanation"}],"tworecs.example.com":[{"SPF":"v=spf1 exp=twoexp.example.com -all"}],"twoexp.example.com":[{"TXT":"one"},{"TXT":"two"}]}, failOnNoFake: true, helo: "mail.example.com"}
        let promise = spf.check_host('1.2.3.4', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'FAIL');
        });
      });
      it('exp-no-txt', function(){
        let email = 'foo@e22.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 exp=exp1.example.com redirect=e2.example.com"}],"e2.example.com":[{"SPF":"v=spf1 -all"}],"e3.example.com":[{"SPF":"v=spf1 exp=exp1.example.com redirect=e4.example.com"}],"e4.example.com":[{"SPF":"v=spf1 -all exp=exp2.example.com"}],"exp1.example.com":[{"TXT":"No-see-um"}],"exp2.example.com":[{"TXT":"See me."}],"exp3.example.com":[{"TXT":"Correct!"}],"exp4.example.com":[{"TXT":"%{l} in implementation"}],"e5.example.com":[{"SPF":"v=spf1 1up=foo"}],"e6.example.com":[{"SPF":"v=spf1 =all"}],"e7.example.com":[{"SPF":"v=spf1 include:e3.example.com -all exp=exp3.example.com"}],"e8.example.com":[{"SPF":"v=spf1 -all exp=exp4.example.com"}],"e9.example.com":[{"SPF":"v=spf1 -all foo=%abc"}],"e10.example.com":[{"SPF":"v=spf1 redirect=erehwon.example.com"}],"e11.example.com":[{"SPF":"v=spf1 -all exp=e11msg.example.com"}],"e11msg.example.com":[{"TXT":"Answer a fool according to his folly."},{"TXT":"Do not answer a fool according to his folly."}],"e12.example.com":[{"SPF":"v=spf1 exp= -all"}],"e13.example.com":[{"SPF":"v=spf1 exp=e13msg.example.com -all"}],"e13msg.example.com":[{"TXT":"The %{x}-files."}],"e14.example.com":[{"SPF":"v=spf1 exp=e13msg.example.com -all exp=e11msg.example.com"}],"e15.example.com":[{"SPF":"v=spf1 redirect=e12.example.com -all redirect=e12.example.com"}],"e16.example.com":[{"SPF":"v=spf1 exp=-all"}],"e17.example.com":[{"SPF":"v=spf1 redirect=-all ?all"}],"e18.example.com":[{"SPF":"v=spf1 ?all redirect="}],"e19.example.com":[{"SPF":"v=spf1 default=pass"}],"e20.example.com":[{"SPF":"v=spf1 default=+"}],"e21.example.com":[{"SPF":"v=spf1 exp=e21msg.example.com -all"}],"e21msg.example.com":["TIMEOUT"],"e22.example.com":[{"SPF":"v=spf1 exp=mail.example.com -all"}],"nonascii.example.com":[{"SPF":"v=spf1 exp=badexp.example.com -all"}],"badexp.example.com":[{"TXT":"ï»¿Explanation"}],"tworecs.example.com":[{"SPF":"v=spf1 exp=twoexp.example.com -all"}],"twoexp.example.com":[{"TXT":"one"},{"TXT":"two"}]}, failOnNoFake: true, helo: "mail.example.com"}
        let promise = spf.check_host('1.2.3.4', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'FAIL');
        });
      });
      it('exp-dns-error', function(){
        let email = 'foo@e21.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 exp=exp1.example.com redirect=e2.example.com"}],"e2.example.com":[{"SPF":"v=spf1 -all"}],"e3.example.com":[{"SPF":"v=spf1 exp=exp1.example.com redirect=e4.example.com"}],"e4.example.com":[{"SPF":"v=spf1 -all exp=exp2.example.com"}],"exp1.example.com":[{"TXT":"No-see-um"}],"exp2.example.com":[{"TXT":"See me."}],"exp3.example.com":[{"TXT":"Correct!"}],"exp4.example.com":[{"TXT":"%{l} in implementation"}],"e5.example.com":[{"SPF":"v=spf1 1up=foo"}],"e6.example.com":[{"SPF":"v=spf1 =all"}],"e7.example.com":[{"SPF":"v=spf1 include:e3.example.com -all exp=exp3.example.com"}],"e8.example.com":[{"SPF":"v=spf1 -all exp=exp4.example.com"}],"e9.example.com":[{"SPF":"v=spf1 -all foo=%abc"}],"e10.example.com":[{"SPF":"v=spf1 redirect=erehwon.example.com"}],"e11.example.com":[{"SPF":"v=spf1 -all exp=e11msg.example.com"}],"e11msg.example.com":[{"TXT":"Answer a fool according to his folly."},{"TXT":"Do not answer a fool according to his folly."}],"e12.example.com":[{"SPF":"v=spf1 exp= -all"}],"e13.example.com":[{"SPF":"v=spf1 exp=e13msg.example.com -all"}],"e13msg.example.com":[{"TXT":"The %{x}-files."}],"e14.example.com":[{"SPF":"v=spf1 exp=e13msg.example.com -all exp=e11msg.example.com"}],"e15.example.com":[{"SPF":"v=spf1 redirect=e12.example.com -all redirect=e12.example.com"}],"e16.example.com":[{"SPF":"v=spf1 exp=-all"}],"e17.example.com":[{"SPF":"v=spf1 redirect=-all ?all"}],"e18.example.com":[{"SPF":"v=spf1 ?all redirect="}],"e19.example.com":[{"SPF":"v=spf1 default=pass"}],"e20.example.com":[{"SPF":"v=spf1 default=+"}],"e21.example.com":[{"SPF":"v=spf1 exp=e21msg.example.com -all"}],"e21msg.example.com":["TIMEOUT"],"e22.example.com":[{"SPF":"v=spf1 exp=mail.example.com -all"}],"nonascii.example.com":[{"SPF":"v=spf1 exp=badexp.example.com -all"}],"badexp.example.com":[{"TXT":"ï»¿Explanation"}],"tworecs.example.com":[{"SPF":"v=spf1 exp=twoexp.example.com -all"}],"twoexp.example.com":[{"TXT":"one"},{"TXT":"two"}]}, failOnNoFake: true, helo: "mail.example.com"}
        let promise = spf.check_host('1.2.3.4', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'FAIL');
        });
      });
      it('exp-empty-domain', function(){
        let email = 'foo@e12.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 exp=exp1.example.com redirect=e2.example.com"}],"e2.example.com":[{"SPF":"v=spf1 -all"}],"e3.example.com":[{"SPF":"v=spf1 exp=exp1.example.com redirect=e4.example.com"}],"e4.example.com":[{"SPF":"v=spf1 -all exp=exp2.example.com"}],"exp1.example.com":[{"TXT":"No-see-um"}],"exp2.example.com":[{"TXT":"See me."}],"exp3.example.com":[{"TXT":"Correct!"}],"exp4.example.com":[{"TXT":"%{l} in implementation"}],"e5.example.com":[{"SPF":"v=spf1 1up=foo"}],"e6.example.com":[{"SPF":"v=spf1 =all"}],"e7.example.com":[{"SPF":"v=spf1 include:e3.example.com -all exp=exp3.example.com"}],"e8.example.com":[{"SPF":"v=spf1 -all exp=exp4.example.com"}],"e9.example.com":[{"SPF":"v=spf1 -all foo=%abc"}],"e10.example.com":[{"SPF":"v=spf1 redirect=erehwon.example.com"}],"e11.example.com":[{"SPF":"v=spf1 -all exp=e11msg.example.com"}],"e11msg.example.com":[{"TXT":"Answer a fool according to his folly."},{"TXT":"Do not answer a fool according to his folly."}],"e12.example.com":[{"SPF":"v=spf1 exp= -all"}],"e13.example.com":[{"SPF":"v=spf1 exp=e13msg.example.com -all"}],"e13msg.example.com":[{"TXT":"The %{x}-files."}],"e14.example.com":[{"SPF":"v=spf1 exp=e13msg.example.com -all exp=e11msg.example.com"}],"e15.example.com":[{"SPF":"v=spf1 redirect=e12.example.com -all redirect=e12.example.com"}],"e16.example.com":[{"SPF":"v=spf1 exp=-all"}],"e17.example.com":[{"SPF":"v=spf1 redirect=-all ?all"}],"e18.example.com":[{"SPF":"v=spf1 ?all redirect="}],"e19.example.com":[{"SPF":"v=spf1 default=pass"}],"e20.example.com":[{"SPF":"v=spf1 default=+"}],"e21.example.com":[{"SPF":"v=spf1 exp=e21msg.example.com -all"}],"e21msg.example.com":["TIMEOUT"],"e22.example.com":[{"SPF":"v=spf1 exp=mail.example.com -all"}],"nonascii.example.com":[{"SPF":"v=spf1 exp=badexp.example.com -all"}],"badexp.example.com":[{"TXT":"ï»¿Explanation"}],"tworecs.example.com":[{"SPF":"v=spf1 exp=twoexp.example.com -all"}],"twoexp.example.com":[{"TXT":"one"},{"TXT":"two"}]}, failOnNoFake: true, helo: "mail.example.com"}
        let promise = spf.check_host('1.2.3.4', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'PERMERROR');
        });
      });
      it('explanation-syntax-error', function(){
        let email = 'foo@e13.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 exp=exp1.example.com redirect=e2.example.com"}],"e2.example.com":[{"SPF":"v=spf1 -all"}],"e3.example.com":[{"SPF":"v=spf1 exp=exp1.example.com redirect=e4.example.com"}],"e4.example.com":[{"SPF":"v=spf1 -all exp=exp2.example.com"}],"exp1.example.com":[{"TXT":"No-see-um"}],"exp2.example.com":[{"TXT":"See me."}],"exp3.example.com":[{"TXT":"Correct!"}],"exp4.example.com":[{"TXT":"%{l} in implementation"}],"e5.example.com":[{"SPF":"v=spf1 1up=foo"}],"e6.example.com":[{"SPF":"v=spf1 =all"}],"e7.example.com":[{"SPF":"v=spf1 include:e3.example.com -all exp=exp3.example.com"}],"e8.example.com":[{"SPF":"v=spf1 -all exp=exp4.example.com"}],"e9.example.com":[{"SPF":"v=spf1 -all foo=%abc"}],"e10.example.com":[{"SPF":"v=spf1 redirect=erehwon.example.com"}],"e11.example.com":[{"SPF":"v=spf1 -all exp=e11msg.example.com"}],"e11msg.example.com":[{"TXT":"Answer a fool according to his folly."},{"TXT":"Do not answer a fool according to his folly."}],"e12.example.com":[{"SPF":"v=spf1 exp= -all"}],"e13.example.com":[{"SPF":"v=spf1 exp=e13msg.example.com -all"}],"e13msg.example.com":[{"TXT":"The %{x}-files."}],"e14.example.com":[{"SPF":"v=spf1 exp=e13msg.example.com -all exp=e11msg.example.com"}],"e15.example.com":[{"SPF":"v=spf1 redirect=e12.example.com -all redirect=e12.example.com"}],"e16.example.com":[{"SPF":"v=spf1 exp=-all"}],"e17.example.com":[{"SPF":"v=spf1 redirect=-all ?all"}],"e18.example.com":[{"SPF":"v=spf1 ?all redirect="}],"e19.example.com":[{"SPF":"v=spf1 default=pass"}],"e20.example.com":[{"SPF":"v=spf1 default=+"}],"e21.example.com":[{"SPF":"v=spf1 exp=e21msg.example.com -all"}],"e21msg.example.com":["TIMEOUT"],"e22.example.com":[{"SPF":"v=spf1 exp=mail.example.com -all"}],"nonascii.example.com":[{"SPF":"v=spf1 exp=badexp.example.com -all"}],"badexp.example.com":[{"TXT":"ï»¿Explanation"}],"tworecs.example.com":[{"SPF":"v=spf1 exp=twoexp.example.com -all"}],"twoexp.example.com":[{"TXT":"one"},{"TXT":"two"}]}, failOnNoFake: true, helo: "mail.example.com"}
        let promise = spf.check_host('1.2.3.4', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'FAIL');
        });
      });
      it('exp-syntax-error', function(){
        let email = 'foo@e16.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 exp=exp1.example.com redirect=e2.example.com"}],"e2.example.com":[{"SPF":"v=spf1 -all"}],"e3.example.com":[{"SPF":"v=spf1 exp=exp1.example.com redirect=e4.example.com"}],"e4.example.com":[{"SPF":"v=spf1 -all exp=exp2.example.com"}],"exp1.example.com":[{"TXT":"No-see-um"}],"exp2.example.com":[{"TXT":"See me."}],"exp3.example.com":[{"TXT":"Correct!"}],"exp4.example.com":[{"TXT":"%{l} in implementation"}],"e5.example.com":[{"SPF":"v=spf1 1up=foo"}],"e6.example.com":[{"SPF":"v=spf1 =all"}],"e7.example.com":[{"SPF":"v=spf1 include:e3.example.com -all exp=exp3.example.com"}],"e8.example.com":[{"SPF":"v=spf1 -all exp=exp4.example.com"}],"e9.example.com":[{"SPF":"v=spf1 -all foo=%abc"}],"e10.example.com":[{"SPF":"v=spf1 redirect=erehwon.example.com"}],"e11.example.com":[{"SPF":"v=spf1 -all exp=e11msg.example.com"}],"e11msg.example.com":[{"TXT":"Answer a fool according to his folly."},{"TXT":"Do not answer a fool according to his folly."}],"e12.example.com":[{"SPF":"v=spf1 exp= -all"}],"e13.example.com":[{"SPF":"v=spf1 exp=e13msg.example.com -all"}],"e13msg.example.com":[{"TXT":"The %{x}-files."}],"e14.example.com":[{"SPF":"v=spf1 exp=e13msg.example.com -all exp=e11msg.example.com"}],"e15.example.com":[{"SPF":"v=spf1 redirect=e12.example.com -all redirect=e12.example.com"}],"e16.example.com":[{"SPF":"v=spf1 exp=-all"}],"e17.example.com":[{"SPF":"v=spf1 redirect=-all ?all"}],"e18.example.com":[{"SPF":"v=spf1 ?all redirect="}],"e19.example.com":[{"SPF":"v=spf1 default=pass"}],"e20.example.com":[{"SPF":"v=spf1 default=+"}],"e21.example.com":[{"SPF":"v=spf1 exp=e21msg.example.com -all"}],"e21msg.example.com":["TIMEOUT"],"e22.example.com":[{"SPF":"v=spf1 exp=mail.example.com -all"}],"nonascii.example.com":[{"SPF":"v=spf1 exp=badexp.example.com -all"}],"badexp.example.com":[{"TXT":"ï»¿Explanation"}],"tworecs.example.com":[{"SPF":"v=spf1 exp=twoexp.example.com -all"}],"twoexp.example.com":[{"TXT":"one"},{"TXT":"two"}]}, failOnNoFake: true, helo: "mail.example.com"}
        let promise = spf.check_host('1.2.3.4', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'PERMERROR');
        });
      });
      it('exp-twice', function(){
        let email = 'foo@e14.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 exp=exp1.example.com redirect=e2.example.com"}],"e2.example.com":[{"SPF":"v=spf1 -all"}],"e3.example.com":[{"SPF":"v=spf1 exp=exp1.example.com redirect=e4.example.com"}],"e4.example.com":[{"SPF":"v=spf1 -all exp=exp2.example.com"}],"exp1.example.com":[{"TXT":"No-see-um"}],"exp2.example.com":[{"TXT":"See me."}],"exp3.example.com":[{"TXT":"Correct!"}],"exp4.example.com":[{"TXT":"%{l} in implementation"}],"e5.example.com":[{"SPF":"v=spf1 1up=foo"}],"e6.example.com":[{"SPF":"v=spf1 =all"}],"e7.example.com":[{"SPF":"v=spf1 include:e3.example.com -all exp=exp3.example.com"}],"e8.example.com":[{"SPF":"v=spf1 -all exp=exp4.example.com"}],"e9.example.com":[{"SPF":"v=spf1 -all foo=%abc"}],"e10.example.com":[{"SPF":"v=spf1 redirect=erehwon.example.com"}],"e11.example.com":[{"SPF":"v=spf1 -all exp=e11msg.example.com"}],"e11msg.example.com":[{"TXT":"Answer a fool according to his folly."},{"TXT":"Do not answer a fool according to his folly."}],"e12.example.com":[{"SPF":"v=spf1 exp= -all"}],"e13.example.com":[{"SPF":"v=spf1 exp=e13msg.example.com -all"}],"e13msg.example.com":[{"TXT":"The %{x}-files."}],"e14.example.com":[{"SPF":"v=spf1 exp=e13msg.example.com -all exp=e11msg.example.com"}],"e15.example.com":[{"SPF":"v=spf1 redirect=e12.example.com -all redirect=e12.example.com"}],"e16.example.com":[{"SPF":"v=spf1 exp=-all"}],"e17.example.com":[{"SPF":"v=spf1 redirect=-all ?all"}],"e18.example.com":[{"SPF":"v=spf1 ?all redirect="}],"e19.example.com":[{"SPF":"v=spf1 default=pass"}],"e20.example.com":[{"SPF":"v=spf1 default=+"}],"e21.example.com":[{"SPF":"v=spf1 exp=e21msg.example.com -all"}],"e21msg.example.com":["TIMEOUT"],"e22.example.com":[{"SPF":"v=spf1 exp=mail.example.com -all"}],"nonascii.example.com":[{"SPF":"v=spf1 exp=badexp.example.com -all"}],"badexp.example.com":[{"TXT":"ï»¿Explanation"}],"tworecs.example.com":[{"SPF":"v=spf1 exp=twoexp.example.com -all"}],"twoexp.example.com":[{"TXT":"one"},{"TXT":"two"}]}, failOnNoFake: true, helo: "mail.example.com"}
        let promise = spf.check_host('1.2.3.4', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'PERMERROR');
        });
      });
      it('redirect-empty-domain', function(){
        let email = 'foo@e18.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 exp=exp1.example.com redirect=e2.example.com"}],"e2.example.com":[{"SPF":"v=spf1 -all"}],"e3.example.com":[{"SPF":"v=spf1 exp=exp1.example.com redirect=e4.example.com"}],"e4.example.com":[{"SPF":"v=spf1 -all exp=exp2.example.com"}],"exp1.example.com":[{"TXT":"No-see-um"}],"exp2.example.com":[{"TXT":"See me."}],"exp3.example.com":[{"TXT":"Correct!"}],"exp4.example.com":[{"TXT":"%{l} in implementation"}],"e5.example.com":[{"SPF":"v=spf1 1up=foo"}],"e6.example.com":[{"SPF":"v=spf1 =all"}],"e7.example.com":[{"SPF":"v=spf1 include:e3.example.com -all exp=exp3.example.com"}],"e8.example.com":[{"SPF":"v=spf1 -all exp=exp4.example.com"}],"e9.example.com":[{"SPF":"v=spf1 -all foo=%abc"}],"e10.example.com":[{"SPF":"v=spf1 redirect=erehwon.example.com"}],"e11.example.com":[{"SPF":"v=spf1 -all exp=e11msg.example.com"}],"e11msg.example.com":[{"TXT":"Answer a fool according to his folly."},{"TXT":"Do not answer a fool according to his folly."}],"e12.example.com":[{"SPF":"v=spf1 exp= -all"}],"e13.example.com":[{"SPF":"v=spf1 exp=e13msg.example.com -all"}],"e13msg.example.com":[{"TXT":"The %{x}-files."}],"e14.example.com":[{"SPF":"v=spf1 exp=e13msg.example.com -all exp=e11msg.example.com"}],"e15.example.com":[{"SPF":"v=spf1 redirect=e12.example.com -all redirect=e12.example.com"}],"e16.example.com":[{"SPF":"v=spf1 exp=-all"}],"e17.example.com":[{"SPF":"v=spf1 redirect=-all ?all"}],"e18.example.com":[{"SPF":"v=spf1 ?all redirect="}],"e19.example.com":[{"SPF":"v=spf1 default=pass"}],"e20.example.com":[{"SPF":"v=spf1 default=+"}],"e21.example.com":[{"SPF":"v=spf1 exp=e21msg.example.com -all"}],"e21msg.example.com":["TIMEOUT"],"e22.example.com":[{"SPF":"v=spf1 exp=mail.example.com -all"}],"nonascii.example.com":[{"SPF":"v=spf1 exp=badexp.example.com -all"}],"badexp.example.com":[{"TXT":"ï»¿Explanation"}],"tworecs.example.com":[{"SPF":"v=spf1 exp=twoexp.example.com -all"}],"twoexp.example.com":[{"TXT":"one"},{"TXT":"two"}]}, failOnNoFake: true, helo: "mail.example.com"}
        let promise = spf.check_host('1.2.3.4', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'PERMERROR');
        });
      });
      it('redirect-twice', function(){
        let email = 'foo@e15.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 exp=exp1.example.com redirect=e2.example.com"}],"e2.example.com":[{"SPF":"v=spf1 -all"}],"e3.example.com":[{"SPF":"v=spf1 exp=exp1.example.com redirect=e4.example.com"}],"e4.example.com":[{"SPF":"v=spf1 -all exp=exp2.example.com"}],"exp1.example.com":[{"TXT":"No-see-um"}],"exp2.example.com":[{"TXT":"See me."}],"exp3.example.com":[{"TXT":"Correct!"}],"exp4.example.com":[{"TXT":"%{l} in implementation"}],"e5.example.com":[{"SPF":"v=spf1 1up=foo"}],"e6.example.com":[{"SPF":"v=spf1 =all"}],"e7.example.com":[{"SPF":"v=spf1 include:e3.example.com -all exp=exp3.example.com"}],"e8.example.com":[{"SPF":"v=spf1 -all exp=exp4.example.com"}],"e9.example.com":[{"SPF":"v=spf1 -all foo=%abc"}],"e10.example.com":[{"SPF":"v=spf1 redirect=erehwon.example.com"}],"e11.example.com":[{"SPF":"v=spf1 -all exp=e11msg.example.com"}],"e11msg.example.com":[{"TXT":"Answer a fool according to his folly."},{"TXT":"Do not answer a fool according to his folly."}],"e12.example.com":[{"SPF":"v=spf1 exp= -all"}],"e13.example.com":[{"SPF":"v=spf1 exp=e13msg.example.com -all"}],"e13msg.example.com":[{"TXT":"The %{x}-files."}],"e14.example.com":[{"SPF":"v=spf1 exp=e13msg.example.com -all exp=e11msg.example.com"}],"e15.example.com":[{"SPF":"v=spf1 redirect=e12.example.com -all redirect=e12.example.com"}],"e16.example.com":[{"SPF":"v=spf1 exp=-all"}],"e17.example.com":[{"SPF":"v=spf1 redirect=-all ?all"}],"e18.example.com":[{"SPF":"v=spf1 ?all redirect="}],"e19.example.com":[{"SPF":"v=spf1 default=pass"}],"e20.example.com":[{"SPF":"v=spf1 default=+"}],"e21.example.com":[{"SPF":"v=spf1 exp=e21msg.example.com -all"}],"e21msg.example.com":["TIMEOUT"],"e22.example.com":[{"SPF":"v=spf1 exp=mail.example.com -all"}],"nonascii.example.com":[{"SPF":"v=spf1 exp=badexp.example.com -all"}],"badexp.example.com":[{"TXT":"ï»¿Explanation"}],"tworecs.example.com":[{"SPF":"v=spf1 exp=twoexp.example.com -all"}],"twoexp.example.com":[{"TXT":"one"},{"TXT":"two"}]}, failOnNoFake: true, helo: "mail.example.com"}
        let promise = spf.check_host('1.2.3.4', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'PERMERROR');
        });
      });
      it('unknown-modifier-syntax', function(){
        let email = 'foo@e9.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 exp=exp1.example.com redirect=e2.example.com"}],"e2.example.com":[{"SPF":"v=spf1 -all"}],"e3.example.com":[{"SPF":"v=spf1 exp=exp1.example.com redirect=e4.example.com"}],"e4.example.com":[{"SPF":"v=spf1 -all exp=exp2.example.com"}],"exp1.example.com":[{"TXT":"No-see-um"}],"exp2.example.com":[{"TXT":"See me."}],"exp3.example.com":[{"TXT":"Correct!"}],"exp4.example.com":[{"TXT":"%{l} in implementation"}],"e5.example.com":[{"SPF":"v=spf1 1up=foo"}],"e6.example.com":[{"SPF":"v=spf1 =all"}],"e7.example.com":[{"SPF":"v=spf1 include:e3.example.com -all exp=exp3.example.com"}],"e8.example.com":[{"SPF":"v=spf1 -all exp=exp4.example.com"}],"e9.example.com":[{"SPF":"v=spf1 -all foo=%abc"}],"e10.example.com":[{"SPF":"v=spf1 redirect=erehwon.example.com"}],"e11.example.com":[{"SPF":"v=spf1 -all exp=e11msg.example.com"}],"e11msg.example.com":[{"TXT":"Answer a fool according to his folly."},{"TXT":"Do not answer a fool according to his folly."}],"e12.example.com":[{"SPF":"v=spf1 exp= -all"}],"e13.example.com":[{"SPF":"v=spf1 exp=e13msg.example.com -all"}],"e13msg.example.com":[{"TXT":"The %{x}-files."}],"e14.example.com":[{"SPF":"v=spf1 exp=e13msg.example.com -all exp=e11msg.example.com"}],"e15.example.com":[{"SPF":"v=spf1 redirect=e12.example.com -all redirect=e12.example.com"}],"e16.example.com":[{"SPF":"v=spf1 exp=-all"}],"e17.example.com":[{"SPF":"v=spf1 redirect=-all ?all"}],"e18.example.com":[{"SPF":"v=spf1 ?all redirect="}],"e19.example.com":[{"SPF":"v=spf1 default=pass"}],"e20.example.com":[{"SPF":"v=spf1 default=+"}],"e21.example.com":[{"SPF":"v=spf1 exp=e21msg.example.com -all"}],"e21msg.example.com":["TIMEOUT"],"e22.example.com":[{"SPF":"v=spf1 exp=mail.example.com -all"}],"nonascii.example.com":[{"SPF":"v=spf1 exp=badexp.example.com -all"}],"badexp.example.com":[{"TXT":"ï»¿Explanation"}],"tworecs.example.com":[{"SPF":"v=spf1 exp=twoexp.example.com -all"}],"twoexp.example.com":[{"TXT":"one"},{"TXT":"two"}]}, failOnNoFake: true, helo: "mail.example.com"}
        let promise = spf.check_host('1.2.3.4', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'PERMERROR');
        });
      });
      it('default-modifier-obsolete', function(){
        let email = 'foo@e19.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 exp=exp1.example.com redirect=e2.example.com"}],"e2.example.com":[{"SPF":"v=spf1 -all"}],"e3.example.com":[{"SPF":"v=spf1 exp=exp1.example.com redirect=e4.example.com"}],"e4.example.com":[{"SPF":"v=spf1 -all exp=exp2.example.com"}],"exp1.example.com":[{"TXT":"No-see-um"}],"exp2.example.com":[{"TXT":"See me."}],"exp3.example.com":[{"TXT":"Correct!"}],"exp4.example.com":[{"TXT":"%{l} in implementation"}],"e5.example.com":[{"SPF":"v=spf1 1up=foo"}],"e6.example.com":[{"SPF":"v=spf1 =all"}],"e7.example.com":[{"SPF":"v=spf1 include:e3.example.com -all exp=exp3.example.com"}],"e8.example.com":[{"SPF":"v=spf1 -all exp=exp4.example.com"}],"e9.example.com":[{"SPF":"v=spf1 -all foo=%abc"}],"e10.example.com":[{"SPF":"v=spf1 redirect=erehwon.example.com"}],"e11.example.com":[{"SPF":"v=spf1 -all exp=e11msg.example.com"}],"e11msg.example.com":[{"TXT":"Answer a fool according to his folly."},{"TXT":"Do not answer a fool according to his folly."}],"e12.example.com":[{"SPF":"v=spf1 exp= -all"}],"e13.example.com":[{"SPF":"v=spf1 exp=e13msg.example.com -all"}],"e13msg.example.com":[{"TXT":"The %{x}-files."}],"e14.example.com":[{"SPF":"v=spf1 exp=e13msg.example.com -all exp=e11msg.example.com"}],"e15.example.com":[{"SPF":"v=spf1 redirect=e12.example.com -all redirect=e12.example.com"}],"e16.example.com":[{"SPF":"v=spf1 exp=-all"}],"e17.example.com":[{"SPF":"v=spf1 redirect=-all ?all"}],"e18.example.com":[{"SPF":"v=spf1 ?all redirect="}],"e19.example.com":[{"SPF":"v=spf1 default=pass"}],"e20.example.com":[{"SPF":"v=spf1 default=+"}],"e21.example.com":[{"SPF":"v=spf1 exp=e21msg.example.com -all"}],"e21msg.example.com":["TIMEOUT"],"e22.example.com":[{"SPF":"v=spf1 exp=mail.example.com -all"}],"nonascii.example.com":[{"SPF":"v=spf1 exp=badexp.example.com -all"}],"badexp.example.com":[{"TXT":"ï»¿Explanation"}],"tworecs.example.com":[{"SPF":"v=spf1 exp=twoexp.example.com -all"}],"twoexp.example.com":[{"TXT":"one"},{"TXT":"two"}]}, failOnNoFake: true, helo: "mail.example.com"}
        let promise = spf.check_host('1.2.3.4', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'NEUTRAL');
        });
      });
      it('default-modifier-obsolete2', function(){
        let email = 'foo@e20.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 exp=exp1.example.com redirect=e2.example.com"}],"e2.example.com":[{"SPF":"v=spf1 -all"}],"e3.example.com":[{"SPF":"v=spf1 exp=exp1.example.com redirect=e4.example.com"}],"e4.example.com":[{"SPF":"v=spf1 -all exp=exp2.example.com"}],"exp1.example.com":[{"TXT":"No-see-um"}],"exp2.example.com":[{"TXT":"See me."}],"exp3.example.com":[{"TXT":"Correct!"}],"exp4.example.com":[{"TXT":"%{l} in implementation"}],"e5.example.com":[{"SPF":"v=spf1 1up=foo"}],"e6.example.com":[{"SPF":"v=spf1 =all"}],"e7.example.com":[{"SPF":"v=spf1 include:e3.example.com -all exp=exp3.example.com"}],"e8.example.com":[{"SPF":"v=spf1 -all exp=exp4.example.com"}],"e9.example.com":[{"SPF":"v=spf1 -all foo=%abc"}],"e10.example.com":[{"SPF":"v=spf1 redirect=erehwon.example.com"}],"e11.example.com":[{"SPF":"v=spf1 -all exp=e11msg.example.com"}],"e11msg.example.com":[{"TXT":"Answer a fool according to his folly."},{"TXT":"Do not answer a fool according to his folly."}],"e12.example.com":[{"SPF":"v=spf1 exp= -all"}],"e13.example.com":[{"SPF":"v=spf1 exp=e13msg.example.com -all"}],"e13msg.example.com":[{"TXT":"The %{x}-files."}],"e14.example.com":[{"SPF":"v=spf1 exp=e13msg.example.com -all exp=e11msg.example.com"}],"e15.example.com":[{"SPF":"v=spf1 redirect=e12.example.com -all redirect=e12.example.com"}],"e16.example.com":[{"SPF":"v=spf1 exp=-all"}],"e17.example.com":[{"SPF":"v=spf1 redirect=-all ?all"}],"e18.example.com":[{"SPF":"v=spf1 ?all redirect="}],"e19.example.com":[{"SPF":"v=spf1 default=pass"}],"e20.example.com":[{"SPF":"v=spf1 default=+"}],"e21.example.com":[{"SPF":"v=spf1 exp=e21msg.example.com -all"}],"e21msg.example.com":["TIMEOUT"],"e22.example.com":[{"SPF":"v=spf1 exp=mail.example.com -all"}],"nonascii.example.com":[{"SPF":"v=spf1 exp=badexp.example.com -all"}],"badexp.example.com":[{"TXT":"ï»¿Explanation"}],"tworecs.example.com":[{"SPF":"v=spf1 exp=twoexp.example.com -all"}],"twoexp.example.com":[{"TXT":"one"},{"TXT":"two"}]}, failOnNoFake: true, helo: "mail.example.com"}
        let promise = spf.check_host('1.2.3.4', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'NEUTRAL');
        });
      });
      it('non-ascii-exp', function(){
        let email = 'foobar@nonascii.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 exp=exp1.example.com redirect=e2.example.com"}],"e2.example.com":[{"SPF":"v=spf1 -all"}],"e3.example.com":[{"SPF":"v=spf1 exp=exp1.example.com redirect=e4.example.com"}],"e4.example.com":[{"SPF":"v=spf1 -all exp=exp2.example.com"}],"exp1.example.com":[{"TXT":"No-see-um"}],"exp2.example.com":[{"TXT":"See me."}],"exp3.example.com":[{"TXT":"Correct!"}],"exp4.example.com":[{"TXT":"%{l} in implementation"}],"e5.example.com":[{"SPF":"v=spf1 1up=foo"}],"e6.example.com":[{"SPF":"v=spf1 =all"}],"e7.example.com":[{"SPF":"v=spf1 include:e3.example.com -all exp=exp3.example.com"}],"e8.example.com":[{"SPF":"v=spf1 -all exp=exp4.example.com"}],"e9.example.com":[{"SPF":"v=spf1 -all foo=%abc"}],"e10.example.com":[{"SPF":"v=spf1 redirect=erehwon.example.com"}],"e11.example.com":[{"SPF":"v=spf1 -all exp=e11msg.example.com"}],"e11msg.example.com":[{"TXT":"Answer a fool according to his folly."},{"TXT":"Do not answer a fool according to his folly."}],"e12.example.com":[{"SPF":"v=spf1 exp= -all"}],"e13.example.com":[{"SPF":"v=spf1 exp=e13msg.example.com -all"}],"e13msg.example.com":[{"TXT":"The %{x}-files."}],"e14.example.com":[{"SPF":"v=spf1 exp=e13msg.example.com -all exp=e11msg.example.com"}],"e15.example.com":[{"SPF":"v=spf1 redirect=e12.example.com -all redirect=e12.example.com"}],"e16.example.com":[{"SPF":"v=spf1 exp=-all"}],"e17.example.com":[{"SPF":"v=spf1 redirect=-all ?all"}],"e18.example.com":[{"SPF":"v=spf1 ?all redirect="}],"e19.example.com":[{"SPF":"v=spf1 default=pass"}],"e20.example.com":[{"SPF":"v=spf1 default=+"}],"e21.example.com":[{"SPF":"v=spf1 exp=e21msg.example.com -all"}],"e21msg.example.com":["TIMEOUT"],"e22.example.com":[{"SPF":"v=spf1 exp=mail.example.com -all"}],"nonascii.example.com":[{"SPF":"v=spf1 exp=badexp.example.com -all"}],"badexp.example.com":[{"TXT":"ï»¿Explanation"}],"tworecs.example.com":[{"SPF":"v=spf1 exp=twoexp.example.com -all"}],"twoexp.example.com":[{"TXT":"one"},{"TXT":"two"}]}, failOnNoFake: true, helo: "hosed"}
        let promise = spf.check_host('1.2.3.4', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'FAIL');
        });
      });
      it('two-exp-records', function(){
        let email = 'foobar@tworecs.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 exp=exp1.example.com redirect=e2.example.com"}],"e2.example.com":[{"SPF":"v=spf1 -all"}],"e3.example.com":[{"SPF":"v=spf1 exp=exp1.example.com redirect=e4.example.com"}],"e4.example.com":[{"SPF":"v=spf1 -all exp=exp2.example.com"}],"exp1.example.com":[{"TXT":"No-see-um"}],"exp2.example.com":[{"TXT":"See me."}],"exp3.example.com":[{"TXT":"Correct!"}],"exp4.example.com":[{"TXT":"%{l} in implementation"}],"e5.example.com":[{"SPF":"v=spf1 1up=foo"}],"e6.example.com":[{"SPF":"v=spf1 =all"}],"e7.example.com":[{"SPF":"v=spf1 include:e3.example.com -all exp=exp3.example.com"}],"e8.example.com":[{"SPF":"v=spf1 -all exp=exp4.example.com"}],"e9.example.com":[{"SPF":"v=spf1 -all foo=%abc"}],"e10.example.com":[{"SPF":"v=spf1 redirect=erehwon.example.com"}],"e11.example.com":[{"SPF":"v=spf1 -all exp=e11msg.example.com"}],"e11msg.example.com":[{"TXT":"Answer a fool according to his folly."},{"TXT":"Do not answer a fool according to his folly."}],"e12.example.com":[{"SPF":"v=spf1 exp= -all"}],"e13.example.com":[{"SPF":"v=spf1 exp=e13msg.example.com -all"}],"e13msg.example.com":[{"TXT":"The %{x}-files."}],"e14.example.com":[{"SPF":"v=spf1 exp=e13msg.example.com -all exp=e11msg.example.com"}],"e15.example.com":[{"SPF":"v=spf1 redirect=e12.example.com -all redirect=e12.example.com"}],"e16.example.com":[{"SPF":"v=spf1 exp=-all"}],"e17.example.com":[{"SPF":"v=spf1 redirect=-all ?all"}],"e18.example.com":[{"SPF":"v=spf1 ?all redirect="}],"e19.example.com":[{"SPF":"v=spf1 default=pass"}],"e20.example.com":[{"SPF":"v=spf1 default=+"}],"e21.example.com":[{"SPF":"v=spf1 exp=e21msg.example.com -all"}],"e21msg.example.com":["TIMEOUT"],"e22.example.com":[{"SPF":"v=spf1 exp=mail.example.com -all"}],"nonascii.example.com":[{"SPF":"v=spf1 exp=badexp.example.com -all"}],"badexp.example.com":[{"TXT":"ï»¿Explanation"}],"tworecs.example.com":[{"SPF":"v=spf1 exp=twoexp.example.com -all"}],"twoexp.example.com":[{"TXT":"one"},{"TXT":"two"}]}, failOnNoFake: true, helo: "hosed"}
        let promise = spf.check_host('1.2.3.4', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'FAIL');
        });
      });
    });
    describe('Macro expansion rules', function(){
      it('trailing-dot-domain', function(){
        let email = 'test@example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"example.com.d.spf.example.com":[{"SPF":"v=spf1 redirect=a.spf.example.com"}],"a.spf.example.com":[{"SPF":"v=spf1 include:o.spf.example.com. ~all"}],"o.spf.example.com":[{"SPF":"v=spf1 ip4:192.168.218.40"}],"msgbas2x.cos.example.com":[{"A":"192.168.218.40"}],"example.com":[{"A":"192.168.90.76"},{"SPF":"v=spf1 redirect=%{d}.d.spf.example.com."}],"exp.example.com":[{"SPF":"v=spf1 exp=msg.example.com. -all"}],"msg.example.com":[{"TXT":"This is a test."}],"e1.example.com":[{"SPF":"v=spf1 -exists:%(ir).sbl.example.com ?all"}],"e1e.example.com":[{"SPF":"v=spf1 exists:foo%(ir).sbl.example.com ?all"}],"e1t.example.com":[{"SPF":"v=spf1 exists:foo%.sbl.example.com ?all"}],"e1a.example.com":[{"SPF":"v=spf1 a:macro%%percent%_%_space%-url-space.example.com -all"}],"macro%percent  space%20url-space.example.com":[{"A":"1.2.3.4"}],"e2.example.com":[{"SPF":"v=spf1 -all exp=%{r}.example.com"}],"e3.example.com":[{"SPF":"v=spf1 -all exp=%{ir}.example.com"}],"40.218.168.192.example.com":[{"TXT":"Connections from %{c} not authorized."}],"somewhat.long.exp.example.com":[{"SPF":"v=spf1 -all exp=foobar.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.example.com"}],"somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.example.com":[{"TXT":"Congratulations!  That was tricky."}],"e4.example.com":[{"SPF":"v=spf1 -all exp=e4msg.example.com"}],"e4msg.example.com":[{"TXT":"%{c} is queried as %{ir}.%{v}.arpa"}],"e5.example.com":[{"SPF":"v=spf1 a:%{a}.example.com -all"}],"e6.example.com":[{"SPF":"v=spf1 -all exp=e6msg.example.com"}],"e6msg.example.com":[{"TXT":"connect from %{p}"}],"mx.example.com":[{"A":"192.168.218.41"},{"A":"192.168.218.42"},{"AAAA":"CAFE:BABE::2"},{"AAAA":"CAFE:BABE::3"}],"40.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"}],"41.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"}],"42.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"},{"PTR":"mx.e7.example.com"}],"1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.E.B.A.B.E.F.A.C.ip6.arpa":[{"PTR":"mx.example.com"}],"3.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.E.B.A.B.E.F.A.C.ip6.arpa":[{"PTR":"mx.example.com"}],"mx.e7.example.com":[{"A":"192.168.218.42"}],"mx.e7.example.com.should.example.com":[{"A":"127.0.0.2"}],"mx.example.com.ok.example.com":[{"A":"127.0.0.2"}],"e7.example.com":[{"SPF":"v=spf1 exists:%{p}.should.example.com ~exists:%{p}.ok.example.com"}],"e8.example.com":[{"SPF":"v=spf1 -all exp=msg8.%{D2}"}],"msg8.example.com":[{"TXT":"http://example.com/why.html?l=%{L}"}],"e9.example.com":[{"SPF":"v=spf1 a:%{H} -all"}],"e10.example.com":[{"SPF":"v=spf1 -include:_spfh.%{d2} ip4:1.2.3.0/24 -all"}],"_spfh.example.com":[{"SPF":"v=spf1 -a:%{h} +all"}],"e11.example.com":[{"SPF":"v=spf1 exists:%{i}.%{l2r-}.user.%{d2}"}],"1.2.3.4.gladstone.philip.user.example.com":[{"A":"127.0.0.2"}],"e12.example.com":[{"SPF":"v=spf1 exists:%{l2r+-}.user.%{d2}"}],"bar.foo.user.example.com":[{"A":"127.0.0.2"}]}, failOnNoFake: true, helo: "msgbas2x.cos.example.com"}
        let promise = spf.check_host('192.168.218.40', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'PASS');
        });
      });
      it('trailing-dot-exp', function(){
        let email = 'test@exp.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"example.com.d.spf.example.com":[{"SPF":"v=spf1 redirect=a.spf.example.com"}],"a.spf.example.com":[{"SPF":"v=spf1 include:o.spf.example.com. ~all"}],"o.spf.example.com":[{"SPF":"v=spf1 ip4:192.168.218.40"}],"msgbas2x.cos.example.com":[{"A":"192.168.218.40"}],"example.com":[{"A":"192.168.90.76"},{"SPF":"v=spf1 redirect=%{d}.d.spf.example.com."}],"exp.example.com":[{"SPF":"v=spf1 exp=msg.example.com. -all"}],"msg.example.com":[{"TXT":"This is a test."}],"e1.example.com":[{"SPF":"v=spf1 -exists:%(ir).sbl.example.com ?all"}],"e1e.example.com":[{"SPF":"v=spf1 exists:foo%(ir).sbl.example.com ?all"}],"e1t.example.com":[{"SPF":"v=spf1 exists:foo%.sbl.example.com ?all"}],"e1a.example.com":[{"SPF":"v=spf1 a:macro%%percent%_%_space%-url-space.example.com -all"}],"macro%percent  space%20url-space.example.com":[{"A":"1.2.3.4"}],"e2.example.com":[{"SPF":"v=spf1 -all exp=%{r}.example.com"}],"e3.example.com":[{"SPF":"v=spf1 -all exp=%{ir}.example.com"}],"40.218.168.192.example.com":[{"TXT":"Connections from %{c} not authorized."}],"somewhat.long.exp.example.com":[{"SPF":"v=spf1 -all exp=foobar.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.example.com"}],"somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.example.com":[{"TXT":"Congratulations!  That was tricky."}],"e4.example.com":[{"SPF":"v=spf1 -all exp=e4msg.example.com"}],"e4msg.example.com":[{"TXT":"%{c} is queried as %{ir}.%{v}.arpa"}],"e5.example.com":[{"SPF":"v=spf1 a:%{a}.example.com -all"}],"e6.example.com":[{"SPF":"v=spf1 -all exp=e6msg.example.com"}],"e6msg.example.com":[{"TXT":"connect from %{p}"}],"mx.example.com":[{"A":"192.168.218.41"},{"A":"192.168.218.42"},{"AAAA":"CAFE:BABE::2"},{"AAAA":"CAFE:BABE::3"}],"40.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"}],"41.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"}],"42.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"},{"PTR":"mx.e7.example.com"}],"1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.E.B.A.B.E.F.A.C.ip6.arpa":[{"PTR":"mx.example.com"}],"3.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.E.B.A.B.E.F.A.C.ip6.arpa":[{"PTR":"mx.example.com"}],"mx.e7.example.com":[{"A":"192.168.218.42"}],"mx.e7.example.com.should.example.com":[{"A":"127.0.0.2"}],"mx.example.com.ok.example.com":[{"A":"127.0.0.2"}],"e7.example.com":[{"SPF":"v=spf1 exists:%{p}.should.example.com ~exists:%{p}.ok.example.com"}],"e8.example.com":[{"SPF":"v=spf1 -all exp=msg8.%{D2}"}],"msg8.example.com":[{"TXT":"http://example.com/why.html?l=%{L}"}],"e9.example.com":[{"SPF":"v=spf1 a:%{H} -all"}],"e10.example.com":[{"SPF":"v=spf1 -include:_spfh.%{d2} ip4:1.2.3.0/24 -all"}],"_spfh.example.com":[{"SPF":"v=spf1 -a:%{h} +all"}],"e11.example.com":[{"SPF":"v=spf1 exists:%{i}.%{l2r-}.user.%{d2}"}],"1.2.3.4.gladstone.philip.user.example.com":[{"A":"127.0.0.2"}],"e12.example.com":[{"SPF":"v=spf1 exists:%{l2r+-}.user.%{d2}"}],"bar.foo.user.example.com":[{"A":"127.0.0.2"}]}, failOnNoFake: true, helo: "msgbas2x.cos.example.com"}
        let promise = spf.check_host('192.168.218.40', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'FAIL');
        });
      });
      it('exp-only-macro-char', function(){
        let email = 'test@e2.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"example.com.d.spf.example.com":[{"SPF":"v=spf1 redirect=a.spf.example.com"}],"a.spf.example.com":[{"SPF":"v=spf1 include:o.spf.example.com. ~all"}],"o.spf.example.com":[{"SPF":"v=spf1 ip4:192.168.218.40"}],"msgbas2x.cos.example.com":[{"A":"192.168.218.40"}],"example.com":[{"A":"192.168.90.76"},{"SPF":"v=spf1 redirect=%{d}.d.spf.example.com."}],"exp.example.com":[{"SPF":"v=spf1 exp=msg.example.com. -all"}],"msg.example.com":[{"TXT":"This is a test."}],"e1.example.com":[{"SPF":"v=spf1 -exists:%(ir).sbl.example.com ?all"}],"e1e.example.com":[{"SPF":"v=spf1 exists:foo%(ir).sbl.example.com ?all"}],"e1t.example.com":[{"SPF":"v=spf1 exists:foo%.sbl.example.com ?all"}],"e1a.example.com":[{"SPF":"v=spf1 a:macro%%percent%_%_space%-url-space.example.com -all"}],"macro%percent  space%20url-space.example.com":[{"A":"1.2.3.4"}],"e2.example.com":[{"SPF":"v=spf1 -all exp=%{r}.example.com"}],"e3.example.com":[{"SPF":"v=spf1 -all exp=%{ir}.example.com"}],"40.218.168.192.example.com":[{"TXT":"Connections from %{c} not authorized."}],"somewhat.long.exp.example.com":[{"SPF":"v=spf1 -all exp=foobar.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.example.com"}],"somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.example.com":[{"TXT":"Congratulations!  That was tricky."}],"e4.example.com":[{"SPF":"v=spf1 -all exp=e4msg.example.com"}],"e4msg.example.com":[{"TXT":"%{c} is queried as %{ir}.%{v}.arpa"}],"e5.example.com":[{"SPF":"v=spf1 a:%{a}.example.com -all"}],"e6.example.com":[{"SPF":"v=spf1 -all exp=e6msg.example.com"}],"e6msg.example.com":[{"TXT":"connect from %{p}"}],"mx.example.com":[{"A":"192.168.218.41"},{"A":"192.168.218.42"},{"AAAA":"CAFE:BABE::2"},{"AAAA":"CAFE:BABE::3"}],"40.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"}],"41.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"}],"42.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"},{"PTR":"mx.e7.example.com"}],"1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.E.B.A.B.E.F.A.C.ip6.arpa":[{"PTR":"mx.example.com"}],"3.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.E.B.A.B.E.F.A.C.ip6.arpa":[{"PTR":"mx.example.com"}],"mx.e7.example.com":[{"A":"192.168.218.42"}],"mx.e7.example.com.should.example.com":[{"A":"127.0.0.2"}],"mx.example.com.ok.example.com":[{"A":"127.0.0.2"}],"e7.example.com":[{"SPF":"v=spf1 exists:%{p}.should.example.com ~exists:%{p}.ok.example.com"}],"e8.example.com":[{"SPF":"v=spf1 -all exp=msg8.%{D2}"}],"msg8.example.com":[{"TXT":"http://example.com/why.html?l=%{L}"}],"e9.example.com":[{"SPF":"v=spf1 a:%{H} -all"}],"e10.example.com":[{"SPF":"v=spf1 -include:_spfh.%{d2} ip4:1.2.3.0/24 -all"}],"_spfh.example.com":[{"SPF":"v=spf1 -a:%{h} +all"}],"e11.example.com":[{"SPF":"v=spf1 exists:%{i}.%{l2r-}.user.%{d2}"}],"1.2.3.4.gladstone.philip.user.example.com":[{"A":"127.0.0.2"}],"e12.example.com":[{"SPF":"v=spf1 exists:%{l2r+-}.user.%{d2}"}],"bar.foo.user.example.com":[{"A":"127.0.0.2"}]}, failOnNoFake: true, helo: "msgbas2x.cos.example.com"}
        let promise = spf.check_host('192.168.218.40', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'PERMERROR');
        });
      });
      it('invalid-macro-char', function(){
        let email = 'test@e1.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"example.com.d.spf.example.com":[{"SPF":"v=spf1 redirect=a.spf.example.com"}],"a.spf.example.com":[{"SPF":"v=spf1 include:o.spf.example.com. ~all"}],"o.spf.example.com":[{"SPF":"v=spf1 ip4:192.168.218.40"}],"msgbas2x.cos.example.com":[{"A":"192.168.218.40"}],"example.com":[{"A":"192.168.90.76"},{"SPF":"v=spf1 redirect=%{d}.d.spf.example.com."}],"exp.example.com":[{"SPF":"v=spf1 exp=msg.example.com. -all"}],"msg.example.com":[{"TXT":"This is a test."}],"e1.example.com":[{"SPF":"v=spf1 -exists:%(ir).sbl.example.com ?all"}],"e1e.example.com":[{"SPF":"v=spf1 exists:foo%(ir).sbl.example.com ?all"}],"e1t.example.com":[{"SPF":"v=spf1 exists:foo%.sbl.example.com ?all"}],"e1a.example.com":[{"SPF":"v=spf1 a:macro%%percent%_%_space%-url-space.example.com -all"}],"macro%percent  space%20url-space.example.com":[{"A":"1.2.3.4"}],"e2.example.com":[{"SPF":"v=spf1 -all exp=%{r}.example.com"}],"e3.example.com":[{"SPF":"v=spf1 -all exp=%{ir}.example.com"}],"40.218.168.192.example.com":[{"TXT":"Connections from %{c} not authorized."}],"somewhat.long.exp.example.com":[{"SPF":"v=spf1 -all exp=foobar.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.example.com"}],"somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.example.com":[{"TXT":"Congratulations!  That was tricky."}],"e4.example.com":[{"SPF":"v=spf1 -all exp=e4msg.example.com"}],"e4msg.example.com":[{"TXT":"%{c} is queried as %{ir}.%{v}.arpa"}],"e5.example.com":[{"SPF":"v=spf1 a:%{a}.example.com -all"}],"e6.example.com":[{"SPF":"v=spf1 -all exp=e6msg.example.com"}],"e6msg.example.com":[{"TXT":"connect from %{p}"}],"mx.example.com":[{"A":"192.168.218.41"},{"A":"192.168.218.42"},{"AAAA":"CAFE:BABE::2"},{"AAAA":"CAFE:BABE::3"}],"40.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"}],"41.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"}],"42.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"},{"PTR":"mx.e7.example.com"}],"1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.E.B.A.B.E.F.A.C.ip6.arpa":[{"PTR":"mx.example.com"}],"3.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.E.B.A.B.E.F.A.C.ip6.arpa":[{"PTR":"mx.example.com"}],"mx.e7.example.com":[{"A":"192.168.218.42"}],"mx.e7.example.com.should.example.com":[{"A":"127.0.0.2"}],"mx.example.com.ok.example.com":[{"A":"127.0.0.2"}],"e7.example.com":[{"SPF":"v=spf1 exists:%{p}.should.example.com ~exists:%{p}.ok.example.com"}],"e8.example.com":[{"SPF":"v=spf1 -all exp=msg8.%{D2}"}],"msg8.example.com":[{"TXT":"http://example.com/why.html?l=%{L}"}],"e9.example.com":[{"SPF":"v=spf1 a:%{H} -all"}],"e10.example.com":[{"SPF":"v=spf1 -include:_spfh.%{d2} ip4:1.2.3.0/24 -all"}],"_spfh.example.com":[{"SPF":"v=spf1 -a:%{h} +all"}],"e11.example.com":[{"SPF":"v=spf1 exists:%{i}.%{l2r-}.user.%{d2}"}],"1.2.3.4.gladstone.philip.user.example.com":[{"A":"127.0.0.2"}],"e12.example.com":[{"SPF":"v=spf1 exists:%{l2r+-}.user.%{d2}"}],"bar.foo.user.example.com":[{"A":"127.0.0.2"}]}, failOnNoFake: true, helo: "msgbas2x.cos.example.com"}
        let promise = spf.check_host('192.168.218.40', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'PERMERROR');
        });
      });
      it('invalid-embedded-macro-char', function(){
        let email = 'test@e1e.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"example.com.d.spf.example.com":[{"SPF":"v=spf1 redirect=a.spf.example.com"}],"a.spf.example.com":[{"SPF":"v=spf1 include:o.spf.example.com. ~all"}],"o.spf.example.com":[{"SPF":"v=spf1 ip4:192.168.218.40"}],"msgbas2x.cos.example.com":[{"A":"192.168.218.40"}],"example.com":[{"A":"192.168.90.76"},{"SPF":"v=spf1 redirect=%{d}.d.spf.example.com."}],"exp.example.com":[{"SPF":"v=spf1 exp=msg.example.com. -all"}],"msg.example.com":[{"TXT":"This is a test."}],"e1.example.com":[{"SPF":"v=spf1 -exists:%(ir).sbl.example.com ?all"}],"e1e.example.com":[{"SPF":"v=spf1 exists:foo%(ir).sbl.example.com ?all"}],"e1t.example.com":[{"SPF":"v=spf1 exists:foo%.sbl.example.com ?all"}],"e1a.example.com":[{"SPF":"v=spf1 a:macro%%percent%_%_space%-url-space.example.com -all"}],"macro%percent  space%20url-space.example.com":[{"A":"1.2.3.4"}],"e2.example.com":[{"SPF":"v=spf1 -all exp=%{r}.example.com"}],"e3.example.com":[{"SPF":"v=spf1 -all exp=%{ir}.example.com"}],"40.218.168.192.example.com":[{"TXT":"Connections from %{c} not authorized."}],"somewhat.long.exp.example.com":[{"SPF":"v=spf1 -all exp=foobar.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.example.com"}],"somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.example.com":[{"TXT":"Congratulations!  That was tricky."}],"e4.example.com":[{"SPF":"v=spf1 -all exp=e4msg.example.com"}],"e4msg.example.com":[{"TXT":"%{c} is queried as %{ir}.%{v}.arpa"}],"e5.example.com":[{"SPF":"v=spf1 a:%{a}.example.com -all"}],"e6.example.com":[{"SPF":"v=spf1 -all exp=e6msg.example.com"}],"e6msg.example.com":[{"TXT":"connect from %{p}"}],"mx.example.com":[{"A":"192.168.218.41"},{"A":"192.168.218.42"},{"AAAA":"CAFE:BABE::2"},{"AAAA":"CAFE:BABE::3"}],"40.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"}],"41.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"}],"42.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"},{"PTR":"mx.e7.example.com"}],"1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.E.B.A.B.E.F.A.C.ip6.arpa":[{"PTR":"mx.example.com"}],"3.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.E.B.A.B.E.F.A.C.ip6.arpa":[{"PTR":"mx.example.com"}],"mx.e7.example.com":[{"A":"192.168.218.42"}],"mx.e7.example.com.should.example.com":[{"A":"127.0.0.2"}],"mx.example.com.ok.example.com":[{"A":"127.0.0.2"}],"e7.example.com":[{"SPF":"v=spf1 exists:%{p}.should.example.com ~exists:%{p}.ok.example.com"}],"e8.example.com":[{"SPF":"v=spf1 -all exp=msg8.%{D2}"}],"msg8.example.com":[{"TXT":"http://example.com/why.html?l=%{L}"}],"e9.example.com":[{"SPF":"v=spf1 a:%{H} -all"}],"e10.example.com":[{"SPF":"v=spf1 -include:_spfh.%{d2} ip4:1.2.3.0/24 -all"}],"_spfh.example.com":[{"SPF":"v=spf1 -a:%{h} +all"}],"e11.example.com":[{"SPF":"v=spf1 exists:%{i}.%{l2r-}.user.%{d2}"}],"1.2.3.4.gladstone.philip.user.example.com":[{"A":"127.0.0.2"}],"e12.example.com":[{"SPF":"v=spf1 exists:%{l2r+-}.user.%{d2}"}],"bar.foo.user.example.com":[{"A":"127.0.0.2"}]}, failOnNoFake: true, helo: "msgbas2x.cos.example.com"}
        let promise = spf.check_host('192.168.218.40', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'PERMERROR');
        });
      });
      it('invalid-trailing-macro-char', function(){
        let email = 'test@e1t.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"example.com.d.spf.example.com":[{"SPF":"v=spf1 redirect=a.spf.example.com"}],"a.spf.example.com":[{"SPF":"v=spf1 include:o.spf.example.com. ~all"}],"o.spf.example.com":[{"SPF":"v=spf1 ip4:192.168.218.40"}],"msgbas2x.cos.example.com":[{"A":"192.168.218.40"}],"example.com":[{"A":"192.168.90.76"},{"SPF":"v=spf1 redirect=%{d}.d.spf.example.com."}],"exp.example.com":[{"SPF":"v=spf1 exp=msg.example.com. -all"}],"msg.example.com":[{"TXT":"This is a test."}],"e1.example.com":[{"SPF":"v=spf1 -exists:%(ir).sbl.example.com ?all"}],"e1e.example.com":[{"SPF":"v=spf1 exists:foo%(ir).sbl.example.com ?all"}],"e1t.example.com":[{"SPF":"v=spf1 exists:foo%.sbl.example.com ?all"}],"e1a.example.com":[{"SPF":"v=spf1 a:macro%%percent%_%_space%-url-space.example.com -all"}],"macro%percent  space%20url-space.example.com":[{"A":"1.2.3.4"}],"e2.example.com":[{"SPF":"v=spf1 -all exp=%{r}.example.com"}],"e3.example.com":[{"SPF":"v=spf1 -all exp=%{ir}.example.com"}],"40.218.168.192.example.com":[{"TXT":"Connections from %{c} not authorized."}],"somewhat.long.exp.example.com":[{"SPF":"v=spf1 -all exp=foobar.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.example.com"}],"somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.example.com":[{"TXT":"Congratulations!  That was tricky."}],"e4.example.com":[{"SPF":"v=spf1 -all exp=e4msg.example.com"}],"e4msg.example.com":[{"TXT":"%{c} is queried as %{ir}.%{v}.arpa"}],"e5.example.com":[{"SPF":"v=spf1 a:%{a}.example.com -all"}],"e6.example.com":[{"SPF":"v=spf1 -all exp=e6msg.example.com"}],"e6msg.example.com":[{"TXT":"connect from %{p}"}],"mx.example.com":[{"A":"192.168.218.41"},{"A":"192.168.218.42"},{"AAAA":"CAFE:BABE::2"},{"AAAA":"CAFE:BABE::3"}],"40.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"}],"41.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"}],"42.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"},{"PTR":"mx.e7.example.com"}],"1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.E.B.A.B.E.F.A.C.ip6.arpa":[{"PTR":"mx.example.com"}],"3.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.E.B.A.B.E.F.A.C.ip6.arpa":[{"PTR":"mx.example.com"}],"mx.e7.example.com":[{"A":"192.168.218.42"}],"mx.e7.example.com.should.example.com":[{"A":"127.0.0.2"}],"mx.example.com.ok.example.com":[{"A":"127.0.0.2"}],"e7.example.com":[{"SPF":"v=spf1 exists:%{p}.should.example.com ~exists:%{p}.ok.example.com"}],"e8.example.com":[{"SPF":"v=spf1 -all exp=msg8.%{D2}"}],"msg8.example.com":[{"TXT":"http://example.com/why.html?l=%{L}"}],"e9.example.com":[{"SPF":"v=spf1 a:%{H} -all"}],"e10.example.com":[{"SPF":"v=spf1 -include:_spfh.%{d2} ip4:1.2.3.0/24 -all"}],"_spfh.example.com":[{"SPF":"v=spf1 -a:%{h} +all"}],"e11.example.com":[{"SPF":"v=spf1 exists:%{i}.%{l2r-}.user.%{d2}"}],"1.2.3.4.gladstone.philip.user.example.com":[{"A":"127.0.0.2"}],"e12.example.com":[{"SPF":"v=spf1 exists:%{l2r+-}.user.%{d2}"}],"bar.foo.user.example.com":[{"A":"127.0.0.2"}]}, failOnNoFake: true, helo: "msgbas2x.cos.example.com"}
        let promise = spf.check_host('192.168.218.40', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'PERMERROR');
        });
      });
      it('macro-mania-in-domain', function(){
        let email = 'test@e1a.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"example.com.d.spf.example.com":[{"SPF":"v=spf1 redirect=a.spf.example.com"}],"a.spf.example.com":[{"SPF":"v=spf1 include:o.spf.example.com. ~all"}],"o.spf.example.com":[{"SPF":"v=spf1 ip4:192.168.218.40"}],"msgbas2x.cos.example.com":[{"A":"192.168.218.40"}],"example.com":[{"A":"192.168.90.76"},{"SPF":"v=spf1 redirect=%{d}.d.spf.example.com."}],"exp.example.com":[{"SPF":"v=spf1 exp=msg.example.com. -all"}],"msg.example.com":[{"TXT":"This is a test."}],"e1.example.com":[{"SPF":"v=spf1 -exists:%(ir).sbl.example.com ?all"}],"e1e.example.com":[{"SPF":"v=spf1 exists:foo%(ir).sbl.example.com ?all"}],"e1t.example.com":[{"SPF":"v=spf1 exists:foo%.sbl.example.com ?all"}],"e1a.example.com":[{"SPF":"v=spf1 a:macro%%percent%_%_space%-url-space.example.com -all"}],"macro%percent  space%20url-space.example.com":[{"A":"1.2.3.4"}],"e2.example.com":[{"SPF":"v=spf1 -all exp=%{r}.example.com"}],"e3.example.com":[{"SPF":"v=spf1 -all exp=%{ir}.example.com"}],"40.218.168.192.example.com":[{"TXT":"Connections from %{c} not authorized."}],"somewhat.long.exp.example.com":[{"SPF":"v=spf1 -all exp=foobar.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.example.com"}],"somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.example.com":[{"TXT":"Congratulations!  That was tricky."}],"e4.example.com":[{"SPF":"v=spf1 -all exp=e4msg.example.com"}],"e4msg.example.com":[{"TXT":"%{c} is queried as %{ir}.%{v}.arpa"}],"e5.example.com":[{"SPF":"v=spf1 a:%{a}.example.com -all"}],"e6.example.com":[{"SPF":"v=spf1 -all exp=e6msg.example.com"}],"e6msg.example.com":[{"TXT":"connect from %{p}"}],"mx.example.com":[{"A":"192.168.218.41"},{"A":"192.168.218.42"},{"AAAA":"CAFE:BABE::2"},{"AAAA":"CAFE:BABE::3"}],"40.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"}],"41.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"}],"42.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"},{"PTR":"mx.e7.example.com"}],"1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.E.B.A.B.E.F.A.C.ip6.arpa":[{"PTR":"mx.example.com"}],"3.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.E.B.A.B.E.F.A.C.ip6.arpa":[{"PTR":"mx.example.com"}],"mx.e7.example.com":[{"A":"192.168.218.42"}],"mx.e7.example.com.should.example.com":[{"A":"127.0.0.2"}],"mx.example.com.ok.example.com":[{"A":"127.0.0.2"}],"e7.example.com":[{"SPF":"v=spf1 exists:%{p}.should.example.com ~exists:%{p}.ok.example.com"}],"e8.example.com":[{"SPF":"v=spf1 -all exp=msg8.%{D2}"}],"msg8.example.com":[{"TXT":"http://example.com/why.html?l=%{L}"}],"e9.example.com":[{"SPF":"v=spf1 a:%{H} -all"}],"e10.example.com":[{"SPF":"v=spf1 -include:_spfh.%{d2} ip4:1.2.3.0/24 -all"}],"_spfh.example.com":[{"SPF":"v=spf1 -a:%{h} +all"}],"e11.example.com":[{"SPF":"v=spf1 exists:%{i}.%{l2r-}.user.%{d2}"}],"1.2.3.4.gladstone.philip.user.example.com":[{"A":"127.0.0.2"}],"e12.example.com":[{"SPF":"v=spf1 exists:%{l2r+-}.user.%{d2}"}],"bar.foo.user.example.com":[{"A":"127.0.0.2"}]}, failOnNoFake: true, helo: "mail.example.com"}
        let promise = spf.check_host('1.2.3.4', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'PASS');
        });
      });
      it('exp-txt-macro-char', function(){
        let email = 'test@e3.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"example.com.d.spf.example.com":[{"SPF":"v=spf1 redirect=a.spf.example.com"}],"a.spf.example.com":[{"SPF":"v=spf1 include:o.spf.example.com. ~all"}],"o.spf.example.com":[{"SPF":"v=spf1 ip4:192.168.218.40"}],"msgbas2x.cos.example.com":[{"A":"192.168.218.40"}],"example.com":[{"A":"192.168.90.76"},{"SPF":"v=spf1 redirect=%{d}.d.spf.example.com."}],"exp.example.com":[{"SPF":"v=spf1 exp=msg.example.com. -all"}],"msg.example.com":[{"TXT":"This is a test."}],"e1.example.com":[{"SPF":"v=spf1 -exists:%(ir).sbl.example.com ?all"}],"e1e.example.com":[{"SPF":"v=spf1 exists:foo%(ir).sbl.example.com ?all"}],"e1t.example.com":[{"SPF":"v=spf1 exists:foo%.sbl.example.com ?all"}],"e1a.example.com":[{"SPF":"v=spf1 a:macro%%percent%_%_space%-url-space.example.com -all"}],"macro%percent  space%20url-space.example.com":[{"A":"1.2.3.4"}],"e2.example.com":[{"SPF":"v=spf1 -all exp=%{r}.example.com"}],"e3.example.com":[{"SPF":"v=spf1 -all exp=%{ir}.example.com"}],"40.218.168.192.example.com":[{"TXT":"Connections from %{c} not authorized."}],"somewhat.long.exp.example.com":[{"SPF":"v=spf1 -all exp=foobar.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.example.com"}],"somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.example.com":[{"TXT":"Congratulations!  That was tricky."}],"e4.example.com":[{"SPF":"v=spf1 -all exp=e4msg.example.com"}],"e4msg.example.com":[{"TXT":"%{c} is queried as %{ir}.%{v}.arpa"}],"e5.example.com":[{"SPF":"v=spf1 a:%{a}.example.com -all"}],"e6.example.com":[{"SPF":"v=spf1 -all exp=e6msg.example.com"}],"e6msg.example.com":[{"TXT":"connect from %{p}"}],"mx.example.com":[{"A":"192.168.218.41"},{"A":"192.168.218.42"},{"AAAA":"CAFE:BABE::2"},{"AAAA":"CAFE:BABE::3"}],"40.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"}],"41.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"}],"42.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"},{"PTR":"mx.e7.example.com"}],"1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.E.B.A.B.E.F.A.C.ip6.arpa":[{"PTR":"mx.example.com"}],"3.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.E.B.A.B.E.F.A.C.ip6.arpa":[{"PTR":"mx.example.com"}],"mx.e7.example.com":[{"A":"192.168.218.42"}],"mx.e7.example.com.should.example.com":[{"A":"127.0.0.2"}],"mx.example.com.ok.example.com":[{"A":"127.0.0.2"}],"e7.example.com":[{"SPF":"v=spf1 exists:%{p}.should.example.com ~exists:%{p}.ok.example.com"}],"e8.example.com":[{"SPF":"v=spf1 -all exp=msg8.%{D2}"}],"msg8.example.com":[{"TXT":"http://example.com/why.html?l=%{L}"}],"e9.example.com":[{"SPF":"v=spf1 a:%{H} -all"}],"e10.example.com":[{"SPF":"v=spf1 -include:_spfh.%{d2} ip4:1.2.3.0/24 -all"}],"_spfh.example.com":[{"SPF":"v=spf1 -a:%{h} +all"}],"e11.example.com":[{"SPF":"v=spf1 exists:%{i}.%{l2r-}.user.%{d2}"}],"1.2.3.4.gladstone.philip.user.example.com":[{"A":"127.0.0.2"}],"e12.example.com":[{"SPF":"v=spf1 exists:%{l2r+-}.user.%{d2}"}],"bar.foo.user.example.com":[{"A":"127.0.0.2"}]}, failOnNoFake: true, helo: "msgbas2x.cos.example.com"}
        let promise = spf.check_host('192.168.218.40', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'FAIL');
        });
      });
      it('domain-name-truncation', function(){
        let email = 'test@somewhat.long.exp.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"example.com.d.spf.example.com":[{"SPF":"v=spf1 redirect=a.spf.example.com"}],"a.spf.example.com":[{"SPF":"v=spf1 include:o.spf.example.com. ~all"}],"o.spf.example.com":[{"SPF":"v=spf1 ip4:192.168.218.40"}],"msgbas2x.cos.example.com":[{"A":"192.168.218.40"}],"example.com":[{"A":"192.168.90.76"},{"SPF":"v=spf1 redirect=%{d}.d.spf.example.com."}],"exp.example.com":[{"SPF":"v=spf1 exp=msg.example.com. -all"}],"msg.example.com":[{"TXT":"This is a test."}],"e1.example.com":[{"SPF":"v=spf1 -exists:%(ir).sbl.example.com ?all"}],"e1e.example.com":[{"SPF":"v=spf1 exists:foo%(ir).sbl.example.com ?all"}],"e1t.example.com":[{"SPF":"v=spf1 exists:foo%.sbl.example.com ?all"}],"e1a.example.com":[{"SPF":"v=spf1 a:macro%%percent%_%_space%-url-space.example.com -all"}],"macro%percent  space%20url-space.example.com":[{"A":"1.2.3.4"}],"e2.example.com":[{"SPF":"v=spf1 -all exp=%{r}.example.com"}],"e3.example.com":[{"SPF":"v=spf1 -all exp=%{ir}.example.com"}],"40.218.168.192.example.com":[{"TXT":"Connections from %{c} not authorized."}],"somewhat.long.exp.example.com":[{"SPF":"v=spf1 -all exp=foobar.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.example.com"}],"somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.example.com":[{"TXT":"Congratulations!  That was tricky."}],"e4.example.com":[{"SPF":"v=spf1 -all exp=e4msg.example.com"}],"e4msg.example.com":[{"TXT":"%{c} is queried as %{ir}.%{v}.arpa"}],"e5.example.com":[{"SPF":"v=spf1 a:%{a}.example.com -all"}],"e6.example.com":[{"SPF":"v=spf1 -all exp=e6msg.example.com"}],"e6msg.example.com":[{"TXT":"connect from %{p}"}],"mx.example.com":[{"A":"192.168.218.41"},{"A":"192.168.218.42"},{"AAAA":"CAFE:BABE::2"},{"AAAA":"CAFE:BABE::3"}],"40.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"}],"41.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"}],"42.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"},{"PTR":"mx.e7.example.com"}],"1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.E.B.A.B.E.F.A.C.ip6.arpa":[{"PTR":"mx.example.com"}],"3.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.E.B.A.B.E.F.A.C.ip6.arpa":[{"PTR":"mx.example.com"}],"mx.e7.example.com":[{"A":"192.168.218.42"}],"mx.e7.example.com.should.example.com":[{"A":"127.0.0.2"}],"mx.example.com.ok.example.com":[{"A":"127.0.0.2"}],"e7.example.com":[{"SPF":"v=spf1 exists:%{p}.should.example.com ~exists:%{p}.ok.example.com"}],"e8.example.com":[{"SPF":"v=spf1 -all exp=msg8.%{D2}"}],"msg8.example.com":[{"TXT":"http://example.com/why.html?l=%{L}"}],"e9.example.com":[{"SPF":"v=spf1 a:%{H} -all"}],"e10.example.com":[{"SPF":"v=spf1 -include:_spfh.%{d2} ip4:1.2.3.0/24 -all"}],"_spfh.example.com":[{"SPF":"v=spf1 -a:%{h} +all"}],"e11.example.com":[{"SPF":"v=spf1 exists:%{i}.%{l2r-}.user.%{d2}"}],"1.2.3.4.gladstone.philip.user.example.com":[{"A":"127.0.0.2"}],"e12.example.com":[{"SPF":"v=spf1 exists:%{l2r+-}.user.%{d2}"}],"bar.foo.user.example.com":[{"A":"127.0.0.2"}]}, failOnNoFake: true, helo: "msgbas2x.cos.example.com"}
        let promise = spf.check_host('192.168.218.40', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'FAIL');
        });
      });
      it('v-macro-ip4', function(){
        let email = 'test@e4.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"example.com.d.spf.example.com":[{"SPF":"v=spf1 redirect=a.spf.example.com"}],"a.spf.example.com":[{"SPF":"v=spf1 include:o.spf.example.com. ~all"}],"o.spf.example.com":[{"SPF":"v=spf1 ip4:192.168.218.40"}],"msgbas2x.cos.example.com":[{"A":"192.168.218.40"}],"example.com":[{"A":"192.168.90.76"},{"SPF":"v=spf1 redirect=%{d}.d.spf.example.com."}],"exp.example.com":[{"SPF":"v=spf1 exp=msg.example.com. -all"}],"msg.example.com":[{"TXT":"This is a test."}],"e1.example.com":[{"SPF":"v=spf1 -exists:%(ir).sbl.example.com ?all"}],"e1e.example.com":[{"SPF":"v=spf1 exists:foo%(ir).sbl.example.com ?all"}],"e1t.example.com":[{"SPF":"v=spf1 exists:foo%.sbl.example.com ?all"}],"e1a.example.com":[{"SPF":"v=spf1 a:macro%%percent%_%_space%-url-space.example.com -all"}],"macro%percent  space%20url-space.example.com":[{"A":"1.2.3.4"}],"e2.example.com":[{"SPF":"v=spf1 -all exp=%{r}.example.com"}],"e3.example.com":[{"SPF":"v=spf1 -all exp=%{ir}.example.com"}],"40.218.168.192.example.com":[{"TXT":"Connections from %{c} not authorized."}],"somewhat.long.exp.example.com":[{"SPF":"v=spf1 -all exp=foobar.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.example.com"}],"somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.example.com":[{"TXT":"Congratulations!  That was tricky."}],"e4.example.com":[{"SPF":"v=spf1 -all exp=e4msg.example.com"}],"e4msg.example.com":[{"TXT":"%{c} is queried as %{ir}.%{v}.arpa"}],"e5.example.com":[{"SPF":"v=spf1 a:%{a}.example.com -all"}],"e6.example.com":[{"SPF":"v=spf1 -all exp=e6msg.example.com"}],"e6msg.example.com":[{"TXT":"connect from %{p}"}],"mx.example.com":[{"A":"192.168.218.41"},{"A":"192.168.218.42"},{"AAAA":"CAFE:BABE::2"},{"AAAA":"CAFE:BABE::3"}],"40.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"}],"41.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"}],"42.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"},{"PTR":"mx.e7.example.com"}],"1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.E.B.A.B.E.F.A.C.ip6.arpa":[{"PTR":"mx.example.com"}],"3.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.E.B.A.B.E.F.A.C.ip6.arpa":[{"PTR":"mx.example.com"}],"mx.e7.example.com":[{"A":"192.168.218.42"}],"mx.e7.example.com.should.example.com":[{"A":"127.0.0.2"}],"mx.example.com.ok.example.com":[{"A":"127.0.0.2"}],"e7.example.com":[{"SPF":"v=spf1 exists:%{p}.should.example.com ~exists:%{p}.ok.example.com"}],"e8.example.com":[{"SPF":"v=spf1 -all exp=msg8.%{D2}"}],"msg8.example.com":[{"TXT":"http://example.com/why.html?l=%{L}"}],"e9.example.com":[{"SPF":"v=spf1 a:%{H} -all"}],"e10.example.com":[{"SPF":"v=spf1 -include:_spfh.%{d2} ip4:1.2.3.0/24 -all"}],"_spfh.example.com":[{"SPF":"v=spf1 -a:%{h} +all"}],"e11.example.com":[{"SPF":"v=spf1 exists:%{i}.%{l2r-}.user.%{d2}"}],"1.2.3.4.gladstone.philip.user.example.com":[{"A":"127.0.0.2"}],"e12.example.com":[{"SPF":"v=spf1 exists:%{l2r+-}.user.%{d2}"}],"bar.foo.user.example.com":[{"A":"127.0.0.2"}]}, failOnNoFake: true, helo: "msgbas2x.cos.example.com"}
        let promise = spf.check_host('192.168.218.40', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'FAIL');
        });
      });
      it('v-macro-ip6', function(){
        let email = 'test@e4.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"example.com.d.spf.example.com":[{"SPF":"v=spf1 redirect=a.spf.example.com"}],"a.spf.example.com":[{"SPF":"v=spf1 include:o.spf.example.com. ~all"}],"o.spf.example.com":[{"SPF":"v=spf1 ip4:192.168.218.40"}],"msgbas2x.cos.example.com":[{"A":"192.168.218.40"}],"example.com":[{"A":"192.168.90.76"},{"SPF":"v=spf1 redirect=%{d}.d.spf.example.com."}],"exp.example.com":[{"SPF":"v=spf1 exp=msg.example.com. -all"}],"msg.example.com":[{"TXT":"This is a test."}],"e1.example.com":[{"SPF":"v=spf1 -exists:%(ir).sbl.example.com ?all"}],"e1e.example.com":[{"SPF":"v=spf1 exists:foo%(ir).sbl.example.com ?all"}],"e1t.example.com":[{"SPF":"v=spf1 exists:foo%.sbl.example.com ?all"}],"e1a.example.com":[{"SPF":"v=spf1 a:macro%%percent%_%_space%-url-space.example.com -all"}],"macro%percent  space%20url-space.example.com":[{"A":"1.2.3.4"}],"e2.example.com":[{"SPF":"v=spf1 -all exp=%{r}.example.com"}],"e3.example.com":[{"SPF":"v=spf1 -all exp=%{ir}.example.com"}],"40.218.168.192.example.com":[{"TXT":"Connections from %{c} not authorized."}],"somewhat.long.exp.example.com":[{"SPF":"v=spf1 -all exp=foobar.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.example.com"}],"somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.example.com":[{"TXT":"Congratulations!  That was tricky."}],"e4.example.com":[{"SPF":"v=spf1 -all exp=e4msg.example.com"}],"e4msg.example.com":[{"TXT":"%{c} is queried as %{ir}.%{v}.arpa"}],"e5.example.com":[{"SPF":"v=spf1 a:%{a}.example.com -all"}],"e6.example.com":[{"SPF":"v=spf1 -all exp=e6msg.example.com"}],"e6msg.example.com":[{"TXT":"connect from %{p}"}],"mx.example.com":[{"A":"192.168.218.41"},{"A":"192.168.218.42"},{"AAAA":"CAFE:BABE::2"},{"AAAA":"CAFE:BABE::3"}],"40.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"}],"41.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"}],"42.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"},{"PTR":"mx.e7.example.com"}],"1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.E.B.A.B.E.F.A.C.ip6.arpa":[{"PTR":"mx.example.com"}],"3.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.E.B.A.B.E.F.A.C.ip6.arpa":[{"PTR":"mx.example.com"}],"mx.e7.example.com":[{"A":"192.168.218.42"}],"mx.e7.example.com.should.example.com":[{"A":"127.0.0.2"}],"mx.example.com.ok.example.com":[{"A":"127.0.0.2"}],"e7.example.com":[{"SPF":"v=spf1 exists:%{p}.should.example.com ~exists:%{p}.ok.example.com"}],"e8.example.com":[{"SPF":"v=spf1 -all exp=msg8.%{D2}"}],"msg8.example.com":[{"TXT":"http://example.com/why.html?l=%{L}"}],"e9.example.com":[{"SPF":"v=spf1 a:%{H} -all"}],"e10.example.com":[{"SPF":"v=spf1 -include:_spfh.%{d2} ip4:1.2.3.0/24 -all"}],"_spfh.example.com":[{"SPF":"v=spf1 -a:%{h} +all"}],"e11.example.com":[{"SPF":"v=spf1 exists:%{i}.%{l2r-}.user.%{d2}"}],"1.2.3.4.gladstone.philip.user.example.com":[{"A":"127.0.0.2"}],"e12.example.com":[{"SPF":"v=spf1 exists:%{l2r+-}.user.%{d2}"}],"bar.foo.user.example.com":[{"A":"127.0.0.2"}]}, failOnNoFake: true, helo: "msgbas2x.cos.example.com"}
        let promise = spf.check_host('CAFE:BABE::1', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'FAIL');
        });
      });
      it('undef-macro', function(){
        let email = 'test@e5.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"example.com.d.spf.example.com":[{"SPF":"v=spf1 redirect=a.spf.example.com"}],"a.spf.example.com":[{"SPF":"v=spf1 include:o.spf.example.com. ~all"}],"o.spf.example.com":[{"SPF":"v=spf1 ip4:192.168.218.40"}],"msgbas2x.cos.example.com":[{"A":"192.168.218.40"}],"example.com":[{"A":"192.168.90.76"},{"SPF":"v=spf1 redirect=%{d}.d.spf.example.com."}],"exp.example.com":[{"SPF":"v=spf1 exp=msg.example.com. -all"}],"msg.example.com":[{"TXT":"This is a test."}],"e1.example.com":[{"SPF":"v=spf1 -exists:%(ir).sbl.example.com ?all"}],"e1e.example.com":[{"SPF":"v=spf1 exists:foo%(ir).sbl.example.com ?all"}],"e1t.example.com":[{"SPF":"v=spf1 exists:foo%.sbl.example.com ?all"}],"e1a.example.com":[{"SPF":"v=spf1 a:macro%%percent%_%_space%-url-space.example.com -all"}],"macro%percent  space%20url-space.example.com":[{"A":"1.2.3.4"}],"e2.example.com":[{"SPF":"v=spf1 -all exp=%{r}.example.com"}],"e3.example.com":[{"SPF":"v=spf1 -all exp=%{ir}.example.com"}],"40.218.168.192.example.com":[{"TXT":"Connections from %{c} not authorized."}],"somewhat.long.exp.example.com":[{"SPF":"v=spf1 -all exp=foobar.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.example.com"}],"somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.example.com":[{"TXT":"Congratulations!  That was tricky."}],"e4.example.com":[{"SPF":"v=spf1 -all exp=e4msg.example.com"}],"e4msg.example.com":[{"TXT":"%{c} is queried as %{ir}.%{v}.arpa"}],"e5.example.com":[{"SPF":"v=spf1 a:%{a}.example.com -all"}],"e6.example.com":[{"SPF":"v=spf1 -all exp=e6msg.example.com"}],"e6msg.example.com":[{"TXT":"connect from %{p}"}],"mx.example.com":[{"A":"192.168.218.41"},{"A":"192.168.218.42"},{"AAAA":"CAFE:BABE::2"},{"AAAA":"CAFE:BABE::3"}],"40.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"}],"41.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"}],"42.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"},{"PTR":"mx.e7.example.com"}],"1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.E.B.A.B.E.F.A.C.ip6.arpa":[{"PTR":"mx.example.com"}],"3.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.E.B.A.B.E.F.A.C.ip6.arpa":[{"PTR":"mx.example.com"}],"mx.e7.example.com":[{"A":"192.168.218.42"}],"mx.e7.example.com.should.example.com":[{"A":"127.0.0.2"}],"mx.example.com.ok.example.com":[{"A":"127.0.0.2"}],"e7.example.com":[{"SPF":"v=spf1 exists:%{p}.should.example.com ~exists:%{p}.ok.example.com"}],"e8.example.com":[{"SPF":"v=spf1 -all exp=msg8.%{D2}"}],"msg8.example.com":[{"TXT":"http://example.com/why.html?l=%{L}"}],"e9.example.com":[{"SPF":"v=spf1 a:%{H} -all"}],"e10.example.com":[{"SPF":"v=spf1 -include:_spfh.%{d2} ip4:1.2.3.0/24 -all"}],"_spfh.example.com":[{"SPF":"v=spf1 -a:%{h} +all"}],"e11.example.com":[{"SPF":"v=spf1 exists:%{i}.%{l2r-}.user.%{d2}"}],"1.2.3.4.gladstone.philip.user.example.com":[{"A":"127.0.0.2"}],"e12.example.com":[{"SPF":"v=spf1 exists:%{l2r+-}.user.%{d2}"}],"bar.foo.user.example.com":[{"A":"127.0.0.2"}]}, failOnNoFake: true, helo: "msgbas2x.cos.example.com"}
        let promise = spf.check_host('CAFE:BABE::192.168.218.40', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'PERMERROR');
        });
      });
      it('p-macro-ip4-novalid', function(){
        let email = 'test@e6.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"example.com.d.spf.example.com":[{"SPF":"v=spf1 redirect=a.spf.example.com"}],"a.spf.example.com":[{"SPF":"v=spf1 include:o.spf.example.com. ~all"}],"o.spf.example.com":[{"SPF":"v=spf1 ip4:192.168.218.40"}],"msgbas2x.cos.example.com":[{"A":"192.168.218.40"}],"example.com":[{"A":"192.168.90.76"},{"SPF":"v=spf1 redirect=%{d}.d.spf.example.com."}],"exp.example.com":[{"SPF":"v=spf1 exp=msg.example.com. -all"}],"msg.example.com":[{"TXT":"This is a test."}],"e1.example.com":[{"SPF":"v=spf1 -exists:%(ir).sbl.example.com ?all"}],"e1e.example.com":[{"SPF":"v=spf1 exists:foo%(ir).sbl.example.com ?all"}],"e1t.example.com":[{"SPF":"v=spf1 exists:foo%.sbl.example.com ?all"}],"e1a.example.com":[{"SPF":"v=spf1 a:macro%%percent%_%_space%-url-space.example.com -all"}],"macro%percent  space%20url-space.example.com":[{"A":"1.2.3.4"}],"e2.example.com":[{"SPF":"v=spf1 -all exp=%{r}.example.com"}],"e3.example.com":[{"SPF":"v=spf1 -all exp=%{ir}.example.com"}],"40.218.168.192.example.com":[{"TXT":"Connections from %{c} not authorized."}],"somewhat.long.exp.example.com":[{"SPF":"v=spf1 -all exp=foobar.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.example.com"}],"somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.example.com":[{"TXT":"Congratulations!  That was tricky."}],"e4.example.com":[{"SPF":"v=spf1 -all exp=e4msg.example.com"}],"e4msg.example.com":[{"TXT":"%{c} is queried as %{ir}.%{v}.arpa"}],"e5.example.com":[{"SPF":"v=spf1 a:%{a}.example.com -all"}],"e6.example.com":[{"SPF":"v=spf1 -all exp=e6msg.example.com"}],"e6msg.example.com":[{"TXT":"connect from %{p}"}],"mx.example.com":[{"A":"192.168.218.41"},{"A":"192.168.218.42"},{"AAAA":"CAFE:BABE::2"},{"AAAA":"CAFE:BABE::3"}],"40.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"}],"41.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"}],"42.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"},{"PTR":"mx.e7.example.com"}],"1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.E.B.A.B.E.F.A.C.ip6.arpa":[{"PTR":"mx.example.com"}],"3.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.E.B.A.B.E.F.A.C.ip6.arpa":[{"PTR":"mx.example.com"}],"mx.e7.example.com":[{"A":"192.168.218.42"}],"mx.e7.example.com.should.example.com":[{"A":"127.0.0.2"}],"mx.example.com.ok.example.com":[{"A":"127.0.0.2"}],"e7.example.com":[{"SPF":"v=spf1 exists:%{p}.should.example.com ~exists:%{p}.ok.example.com"}],"e8.example.com":[{"SPF":"v=spf1 -all exp=msg8.%{D2}"}],"msg8.example.com":[{"TXT":"http://example.com/why.html?l=%{L}"}],"e9.example.com":[{"SPF":"v=spf1 a:%{H} -all"}],"e10.example.com":[{"SPF":"v=spf1 -include:_spfh.%{d2} ip4:1.2.3.0/24 -all"}],"_spfh.example.com":[{"SPF":"v=spf1 -a:%{h} +all"}],"e11.example.com":[{"SPF":"v=spf1 exists:%{i}.%{l2r-}.user.%{d2}"}],"1.2.3.4.gladstone.philip.user.example.com":[{"A":"127.0.0.2"}],"e12.example.com":[{"SPF":"v=spf1 exists:%{l2r+-}.user.%{d2}"}],"bar.foo.user.example.com":[{"A":"127.0.0.2"}]}, failOnNoFake: true, helo: "msgbas2x.cos.example.com"}
        let promise = spf.check_host('192.168.218.40', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'FAIL');
        });
      });
      it('p-macro-ip4-valid', function(){
        let email = 'test@e6.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"example.com.d.spf.example.com":[{"SPF":"v=spf1 redirect=a.spf.example.com"}],"a.spf.example.com":[{"SPF":"v=spf1 include:o.spf.example.com. ~all"}],"o.spf.example.com":[{"SPF":"v=spf1 ip4:192.168.218.40"}],"msgbas2x.cos.example.com":[{"A":"192.168.218.40"}],"example.com":[{"A":"192.168.90.76"},{"SPF":"v=spf1 redirect=%{d}.d.spf.example.com."}],"exp.example.com":[{"SPF":"v=spf1 exp=msg.example.com. -all"}],"msg.example.com":[{"TXT":"This is a test."}],"e1.example.com":[{"SPF":"v=spf1 -exists:%(ir).sbl.example.com ?all"}],"e1e.example.com":[{"SPF":"v=spf1 exists:foo%(ir).sbl.example.com ?all"}],"e1t.example.com":[{"SPF":"v=spf1 exists:foo%.sbl.example.com ?all"}],"e1a.example.com":[{"SPF":"v=spf1 a:macro%%percent%_%_space%-url-space.example.com -all"}],"macro%percent  space%20url-space.example.com":[{"A":"1.2.3.4"}],"e2.example.com":[{"SPF":"v=spf1 -all exp=%{r}.example.com"}],"e3.example.com":[{"SPF":"v=spf1 -all exp=%{ir}.example.com"}],"40.218.168.192.example.com":[{"TXT":"Connections from %{c} not authorized."}],"somewhat.long.exp.example.com":[{"SPF":"v=spf1 -all exp=foobar.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.example.com"}],"somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.example.com":[{"TXT":"Congratulations!  That was tricky."}],"e4.example.com":[{"SPF":"v=spf1 -all exp=e4msg.example.com"}],"e4msg.example.com":[{"TXT":"%{c} is queried as %{ir}.%{v}.arpa"}],"e5.example.com":[{"SPF":"v=spf1 a:%{a}.example.com -all"}],"e6.example.com":[{"SPF":"v=spf1 -all exp=e6msg.example.com"}],"e6msg.example.com":[{"TXT":"connect from %{p}"}],"mx.example.com":[{"A":"192.168.218.41"},{"A":"192.168.218.42"},{"AAAA":"CAFE:BABE::2"},{"AAAA":"CAFE:BABE::3"}],"40.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"}],"41.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"}],"42.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"},{"PTR":"mx.e7.example.com"}],"1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.E.B.A.B.E.F.A.C.ip6.arpa":[{"PTR":"mx.example.com"}],"3.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.E.B.A.B.E.F.A.C.ip6.arpa":[{"PTR":"mx.example.com"}],"mx.e7.example.com":[{"A":"192.168.218.42"}],"mx.e7.example.com.should.example.com":[{"A":"127.0.0.2"}],"mx.example.com.ok.example.com":[{"A":"127.0.0.2"}],"e7.example.com":[{"SPF":"v=spf1 exists:%{p}.should.example.com ~exists:%{p}.ok.example.com"}],"e8.example.com":[{"SPF":"v=spf1 -all exp=msg8.%{D2}"}],"msg8.example.com":[{"TXT":"http://example.com/why.html?l=%{L}"}],"e9.example.com":[{"SPF":"v=spf1 a:%{H} -all"}],"e10.example.com":[{"SPF":"v=spf1 -include:_spfh.%{d2} ip4:1.2.3.0/24 -all"}],"_spfh.example.com":[{"SPF":"v=spf1 -a:%{h} +all"}],"e11.example.com":[{"SPF":"v=spf1 exists:%{i}.%{l2r-}.user.%{d2}"}],"1.2.3.4.gladstone.philip.user.example.com":[{"A":"127.0.0.2"}],"e12.example.com":[{"SPF":"v=spf1 exists:%{l2r+-}.user.%{d2}"}],"bar.foo.user.example.com":[{"A":"127.0.0.2"}]}, failOnNoFake: true, helo: "msgbas2x.cos.example.com"}
        let promise = spf.check_host('192.168.218.41', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'FAIL');
        });
      });
      it('p-macro-ip6-novalid', function(){
        let email = 'test@e6.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"example.com.d.spf.example.com":[{"SPF":"v=spf1 redirect=a.spf.example.com"}],"a.spf.example.com":[{"SPF":"v=spf1 include:o.spf.example.com. ~all"}],"o.spf.example.com":[{"SPF":"v=spf1 ip4:192.168.218.40"}],"msgbas2x.cos.example.com":[{"A":"192.168.218.40"}],"example.com":[{"A":"192.168.90.76"},{"SPF":"v=spf1 redirect=%{d}.d.spf.example.com."}],"exp.example.com":[{"SPF":"v=spf1 exp=msg.example.com. -all"}],"msg.example.com":[{"TXT":"This is a test."}],"e1.example.com":[{"SPF":"v=spf1 -exists:%(ir).sbl.example.com ?all"}],"e1e.example.com":[{"SPF":"v=spf1 exists:foo%(ir).sbl.example.com ?all"}],"e1t.example.com":[{"SPF":"v=spf1 exists:foo%.sbl.example.com ?all"}],"e1a.example.com":[{"SPF":"v=spf1 a:macro%%percent%_%_space%-url-space.example.com -all"}],"macro%percent  space%20url-space.example.com":[{"A":"1.2.3.4"}],"e2.example.com":[{"SPF":"v=spf1 -all exp=%{r}.example.com"}],"e3.example.com":[{"SPF":"v=spf1 -all exp=%{ir}.example.com"}],"40.218.168.192.example.com":[{"TXT":"Connections from %{c} not authorized."}],"somewhat.long.exp.example.com":[{"SPF":"v=spf1 -all exp=foobar.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.example.com"}],"somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.example.com":[{"TXT":"Congratulations!  That was tricky."}],"e4.example.com":[{"SPF":"v=spf1 -all exp=e4msg.example.com"}],"e4msg.example.com":[{"TXT":"%{c} is queried as %{ir}.%{v}.arpa"}],"e5.example.com":[{"SPF":"v=spf1 a:%{a}.example.com -all"}],"e6.example.com":[{"SPF":"v=spf1 -all exp=e6msg.example.com"}],"e6msg.example.com":[{"TXT":"connect from %{p}"}],"mx.example.com":[{"A":"192.168.218.41"},{"A":"192.168.218.42"},{"AAAA":"CAFE:BABE::2"},{"AAAA":"CAFE:BABE::3"}],"40.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"}],"41.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"}],"42.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"},{"PTR":"mx.e7.example.com"}],"1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.E.B.A.B.E.F.A.C.ip6.arpa":[{"PTR":"mx.example.com"}],"3.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.E.B.A.B.E.F.A.C.ip6.arpa":[{"PTR":"mx.example.com"}],"mx.e7.example.com":[{"A":"192.168.218.42"}],"mx.e7.example.com.should.example.com":[{"A":"127.0.0.2"}],"mx.example.com.ok.example.com":[{"A":"127.0.0.2"}],"e7.example.com":[{"SPF":"v=spf1 exists:%{p}.should.example.com ~exists:%{p}.ok.example.com"}],"e8.example.com":[{"SPF":"v=spf1 -all exp=msg8.%{D2}"}],"msg8.example.com":[{"TXT":"http://example.com/why.html?l=%{L}"}],"e9.example.com":[{"SPF":"v=spf1 a:%{H} -all"}],"e10.example.com":[{"SPF":"v=spf1 -include:_spfh.%{d2} ip4:1.2.3.0/24 -all"}],"_spfh.example.com":[{"SPF":"v=spf1 -a:%{h} +all"}],"e11.example.com":[{"SPF":"v=spf1 exists:%{i}.%{l2r-}.user.%{d2}"}],"1.2.3.4.gladstone.philip.user.example.com":[{"A":"127.0.0.2"}],"e12.example.com":[{"SPF":"v=spf1 exists:%{l2r+-}.user.%{d2}"}],"bar.foo.user.example.com":[{"A":"127.0.0.2"}]}, failOnNoFake: true, helo: "msgbas2x.cos.example.com"}
        let promise = spf.check_host('CAFE:BABE::1', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'FAIL');
        });
      });
      it('p-macro-ip6-valid', function(){
        let email = 'test@e6.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"example.com.d.spf.example.com":[{"SPF":"v=spf1 redirect=a.spf.example.com"}],"a.spf.example.com":[{"SPF":"v=spf1 include:o.spf.example.com. ~all"}],"o.spf.example.com":[{"SPF":"v=spf1 ip4:192.168.218.40"}],"msgbas2x.cos.example.com":[{"A":"192.168.218.40"}],"example.com":[{"A":"192.168.90.76"},{"SPF":"v=spf1 redirect=%{d}.d.spf.example.com."}],"exp.example.com":[{"SPF":"v=spf1 exp=msg.example.com. -all"}],"msg.example.com":[{"TXT":"This is a test."}],"e1.example.com":[{"SPF":"v=spf1 -exists:%(ir).sbl.example.com ?all"}],"e1e.example.com":[{"SPF":"v=spf1 exists:foo%(ir).sbl.example.com ?all"}],"e1t.example.com":[{"SPF":"v=spf1 exists:foo%.sbl.example.com ?all"}],"e1a.example.com":[{"SPF":"v=spf1 a:macro%%percent%_%_space%-url-space.example.com -all"}],"macro%percent  space%20url-space.example.com":[{"A":"1.2.3.4"}],"e2.example.com":[{"SPF":"v=spf1 -all exp=%{r}.example.com"}],"e3.example.com":[{"SPF":"v=spf1 -all exp=%{ir}.example.com"}],"40.218.168.192.example.com":[{"TXT":"Connections from %{c} not authorized."}],"somewhat.long.exp.example.com":[{"SPF":"v=spf1 -all exp=foobar.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.example.com"}],"somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.example.com":[{"TXT":"Congratulations!  That was tricky."}],"e4.example.com":[{"SPF":"v=spf1 -all exp=e4msg.example.com"}],"e4msg.example.com":[{"TXT":"%{c} is queried as %{ir}.%{v}.arpa"}],"e5.example.com":[{"SPF":"v=spf1 a:%{a}.example.com -all"}],"e6.example.com":[{"SPF":"v=spf1 -all exp=e6msg.example.com"}],"e6msg.example.com":[{"TXT":"connect from %{p}"}],"mx.example.com":[{"A":"192.168.218.41"},{"A":"192.168.218.42"},{"AAAA":"CAFE:BABE::2"},{"AAAA":"CAFE:BABE::3"}],"40.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"}],"41.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"}],"42.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"},{"PTR":"mx.e7.example.com"}],"1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.E.B.A.B.E.F.A.C.ip6.arpa":[{"PTR":"mx.example.com"}],"3.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.E.B.A.B.E.F.A.C.ip6.arpa":[{"PTR":"mx.example.com"}],"mx.e7.example.com":[{"A":"192.168.218.42"}],"mx.e7.example.com.should.example.com":[{"A":"127.0.0.2"}],"mx.example.com.ok.example.com":[{"A":"127.0.0.2"}],"e7.example.com":[{"SPF":"v=spf1 exists:%{p}.should.example.com ~exists:%{p}.ok.example.com"}],"e8.example.com":[{"SPF":"v=spf1 -all exp=msg8.%{D2}"}],"msg8.example.com":[{"TXT":"http://example.com/why.html?l=%{L}"}],"e9.example.com":[{"SPF":"v=spf1 a:%{H} -all"}],"e10.example.com":[{"SPF":"v=spf1 -include:_spfh.%{d2} ip4:1.2.3.0/24 -all"}],"_spfh.example.com":[{"SPF":"v=spf1 -a:%{h} +all"}],"e11.example.com":[{"SPF":"v=spf1 exists:%{i}.%{l2r-}.user.%{d2}"}],"1.2.3.4.gladstone.philip.user.example.com":[{"A":"127.0.0.2"}],"e12.example.com":[{"SPF":"v=spf1 exists:%{l2r+-}.user.%{d2}"}],"bar.foo.user.example.com":[{"A":"127.0.0.2"}]}, failOnNoFake: true, helo: "msgbas2x.cos.example.com"}
        let promise = spf.check_host('CAFE:BABE::3', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'FAIL');
        });
      });
      it('p-macro-multiple', function(){
        let email = 'test@e7.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"example.com.d.spf.example.com":[{"SPF":"v=spf1 redirect=a.spf.example.com"}],"a.spf.example.com":[{"SPF":"v=spf1 include:o.spf.example.com. ~all"}],"o.spf.example.com":[{"SPF":"v=spf1 ip4:192.168.218.40"}],"msgbas2x.cos.example.com":[{"A":"192.168.218.40"}],"example.com":[{"A":"192.168.90.76"},{"SPF":"v=spf1 redirect=%{d}.d.spf.example.com."}],"exp.example.com":[{"SPF":"v=spf1 exp=msg.example.com. -all"}],"msg.example.com":[{"TXT":"This is a test."}],"e1.example.com":[{"SPF":"v=spf1 -exists:%(ir).sbl.example.com ?all"}],"e1e.example.com":[{"SPF":"v=spf1 exists:foo%(ir).sbl.example.com ?all"}],"e1t.example.com":[{"SPF":"v=spf1 exists:foo%.sbl.example.com ?all"}],"e1a.example.com":[{"SPF":"v=spf1 a:macro%%percent%_%_space%-url-space.example.com -all"}],"macro%percent  space%20url-space.example.com":[{"A":"1.2.3.4"}],"e2.example.com":[{"SPF":"v=spf1 -all exp=%{r}.example.com"}],"e3.example.com":[{"SPF":"v=spf1 -all exp=%{ir}.example.com"}],"40.218.168.192.example.com":[{"TXT":"Connections from %{c} not authorized."}],"somewhat.long.exp.example.com":[{"SPF":"v=spf1 -all exp=foobar.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.example.com"}],"somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.example.com":[{"TXT":"Congratulations!  That was tricky."}],"e4.example.com":[{"SPF":"v=spf1 -all exp=e4msg.example.com"}],"e4msg.example.com":[{"TXT":"%{c} is queried as %{ir}.%{v}.arpa"}],"e5.example.com":[{"SPF":"v=spf1 a:%{a}.example.com -all"}],"e6.example.com":[{"SPF":"v=spf1 -all exp=e6msg.example.com"}],"e6msg.example.com":[{"TXT":"connect from %{p}"}],"mx.example.com":[{"A":"192.168.218.41"},{"A":"192.168.218.42"},{"AAAA":"CAFE:BABE::2"},{"AAAA":"CAFE:BABE::3"}],"40.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"}],"41.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"}],"42.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"},{"PTR":"mx.e7.example.com"}],"1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.E.B.A.B.E.F.A.C.ip6.arpa":[{"PTR":"mx.example.com"}],"3.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.E.B.A.B.E.F.A.C.ip6.arpa":[{"PTR":"mx.example.com"}],"mx.e7.example.com":[{"A":"192.168.218.42"}],"mx.e7.example.com.should.example.com":[{"A":"127.0.0.2"}],"mx.example.com.ok.example.com":[{"A":"127.0.0.2"}],"e7.example.com":[{"SPF":"v=spf1 exists:%{p}.should.example.com ~exists:%{p}.ok.example.com"}],"e8.example.com":[{"SPF":"v=spf1 -all exp=msg8.%{D2}"}],"msg8.example.com":[{"TXT":"http://example.com/why.html?l=%{L}"}],"e9.example.com":[{"SPF":"v=spf1 a:%{H} -all"}],"e10.example.com":[{"SPF":"v=spf1 -include:_spfh.%{d2} ip4:1.2.3.0/24 -all"}],"_spfh.example.com":[{"SPF":"v=spf1 -a:%{h} +all"}],"e11.example.com":[{"SPF":"v=spf1 exists:%{i}.%{l2r-}.user.%{d2}"}],"1.2.3.4.gladstone.philip.user.example.com":[{"A":"127.0.0.2"}],"e12.example.com":[{"SPF":"v=spf1 exists:%{l2r+-}.user.%{d2}"}],"bar.foo.user.example.com":[{"A":"127.0.0.2"}]}, failOnNoFake: true, helo: "msgbas2x.cos.example.com"}
        let promise = spf.check_host('192.168.218.42', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.include(["pass","softfail"], result.toLowerCase());
        });
      });
      it('upper-macro', function(){
        let email = 'jack&jill=up@e8.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"example.com.d.spf.example.com":[{"SPF":"v=spf1 redirect=a.spf.example.com"}],"a.spf.example.com":[{"SPF":"v=spf1 include:o.spf.example.com. ~all"}],"o.spf.example.com":[{"SPF":"v=spf1 ip4:192.168.218.40"}],"msgbas2x.cos.example.com":[{"A":"192.168.218.40"}],"example.com":[{"A":"192.168.90.76"},{"SPF":"v=spf1 redirect=%{d}.d.spf.example.com."}],"exp.example.com":[{"SPF":"v=spf1 exp=msg.example.com. -all"}],"msg.example.com":[{"TXT":"This is a test."}],"e1.example.com":[{"SPF":"v=spf1 -exists:%(ir).sbl.example.com ?all"}],"e1e.example.com":[{"SPF":"v=spf1 exists:foo%(ir).sbl.example.com ?all"}],"e1t.example.com":[{"SPF":"v=spf1 exists:foo%.sbl.example.com ?all"}],"e1a.example.com":[{"SPF":"v=spf1 a:macro%%percent%_%_space%-url-space.example.com -all"}],"macro%percent  space%20url-space.example.com":[{"A":"1.2.3.4"}],"e2.example.com":[{"SPF":"v=spf1 -all exp=%{r}.example.com"}],"e3.example.com":[{"SPF":"v=spf1 -all exp=%{ir}.example.com"}],"40.218.168.192.example.com":[{"TXT":"Connections from %{c} not authorized."}],"somewhat.long.exp.example.com":[{"SPF":"v=spf1 -all exp=foobar.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.example.com"}],"somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.example.com":[{"TXT":"Congratulations!  That was tricky."}],"e4.example.com":[{"SPF":"v=spf1 -all exp=e4msg.example.com"}],"e4msg.example.com":[{"TXT":"%{c} is queried as %{ir}.%{v}.arpa"}],"e5.example.com":[{"SPF":"v=spf1 a:%{a}.example.com -all"}],"e6.example.com":[{"SPF":"v=spf1 -all exp=e6msg.example.com"}],"e6msg.example.com":[{"TXT":"connect from %{p}"}],"mx.example.com":[{"A":"192.168.218.41"},{"A":"192.168.218.42"},{"AAAA":"CAFE:BABE::2"},{"AAAA":"CAFE:BABE::3"}],"40.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"}],"41.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"}],"42.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"},{"PTR":"mx.e7.example.com"}],"1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.E.B.A.B.E.F.A.C.ip6.arpa":[{"PTR":"mx.example.com"}],"3.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.E.B.A.B.E.F.A.C.ip6.arpa":[{"PTR":"mx.example.com"}],"mx.e7.example.com":[{"A":"192.168.218.42"}],"mx.e7.example.com.should.example.com":[{"A":"127.0.0.2"}],"mx.example.com.ok.example.com":[{"A":"127.0.0.2"}],"e7.example.com":[{"SPF":"v=spf1 exists:%{p}.should.example.com ~exists:%{p}.ok.example.com"}],"e8.example.com":[{"SPF":"v=spf1 -all exp=msg8.%{D2}"}],"msg8.example.com":[{"TXT":"http://example.com/why.html?l=%{L}"}],"e9.example.com":[{"SPF":"v=spf1 a:%{H} -all"}],"e10.example.com":[{"SPF":"v=spf1 -include:_spfh.%{d2} ip4:1.2.3.0/24 -all"}],"_spfh.example.com":[{"SPF":"v=spf1 -a:%{h} +all"}],"e11.example.com":[{"SPF":"v=spf1 exists:%{i}.%{l2r-}.user.%{d2}"}],"1.2.3.4.gladstone.philip.user.example.com":[{"A":"127.0.0.2"}],"e12.example.com":[{"SPF":"v=spf1 exists:%{l2r+-}.user.%{d2}"}],"bar.foo.user.example.com":[{"A":"127.0.0.2"}]}, failOnNoFake: true, helo: "msgbas2x.cos.example.com"}
        let promise = spf.check_host('192.168.218.42', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'FAIL');
        });
      });
      it('hello-macro', function(){
        let email = 'test@e9.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"example.com.d.spf.example.com":[{"SPF":"v=spf1 redirect=a.spf.example.com"}],"a.spf.example.com":[{"SPF":"v=spf1 include:o.spf.example.com. ~all"}],"o.spf.example.com":[{"SPF":"v=spf1 ip4:192.168.218.40"}],"msgbas2x.cos.example.com":[{"A":"192.168.218.40"}],"example.com":[{"A":"192.168.90.76"},{"SPF":"v=spf1 redirect=%{d}.d.spf.example.com."}],"exp.example.com":[{"SPF":"v=spf1 exp=msg.example.com. -all"}],"msg.example.com":[{"TXT":"This is a test."}],"e1.example.com":[{"SPF":"v=spf1 -exists:%(ir).sbl.example.com ?all"}],"e1e.example.com":[{"SPF":"v=spf1 exists:foo%(ir).sbl.example.com ?all"}],"e1t.example.com":[{"SPF":"v=spf1 exists:foo%.sbl.example.com ?all"}],"e1a.example.com":[{"SPF":"v=spf1 a:macro%%percent%_%_space%-url-space.example.com -all"}],"macro%percent  space%20url-space.example.com":[{"A":"1.2.3.4"}],"e2.example.com":[{"SPF":"v=spf1 -all exp=%{r}.example.com"}],"e3.example.com":[{"SPF":"v=spf1 -all exp=%{ir}.example.com"}],"40.218.168.192.example.com":[{"TXT":"Connections from %{c} not authorized."}],"somewhat.long.exp.example.com":[{"SPF":"v=spf1 -all exp=foobar.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.example.com"}],"somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.example.com":[{"TXT":"Congratulations!  That was tricky."}],"e4.example.com":[{"SPF":"v=spf1 -all exp=e4msg.example.com"}],"e4msg.example.com":[{"TXT":"%{c} is queried as %{ir}.%{v}.arpa"}],"e5.example.com":[{"SPF":"v=spf1 a:%{a}.example.com -all"}],"e6.example.com":[{"SPF":"v=spf1 -all exp=e6msg.example.com"}],"e6msg.example.com":[{"TXT":"connect from %{p}"}],"mx.example.com":[{"A":"192.168.218.41"},{"A":"192.168.218.42"},{"AAAA":"CAFE:BABE::2"},{"AAAA":"CAFE:BABE::3"}],"40.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"}],"41.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"}],"42.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"},{"PTR":"mx.e7.example.com"}],"1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.E.B.A.B.E.F.A.C.ip6.arpa":[{"PTR":"mx.example.com"}],"3.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.E.B.A.B.E.F.A.C.ip6.arpa":[{"PTR":"mx.example.com"}],"mx.e7.example.com":[{"A":"192.168.218.42"}],"mx.e7.example.com.should.example.com":[{"A":"127.0.0.2"}],"mx.example.com.ok.example.com":[{"A":"127.0.0.2"}],"e7.example.com":[{"SPF":"v=spf1 exists:%{p}.should.example.com ~exists:%{p}.ok.example.com"}],"e8.example.com":[{"SPF":"v=spf1 -all exp=msg8.%{D2}"}],"msg8.example.com":[{"TXT":"http://example.com/why.html?l=%{L}"}],"e9.example.com":[{"SPF":"v=spf1 a:%{H} -all"}],"e10.example.com":[{"SPF":"v=spf1 -include:_spfh.%{d2} ip4:1.2.3.0/24 -all"}],"_spfh.example.com":[{"SPF":"v=spf1 -a:%{h} +all"}],"e11.example.com":[{"SPF":"v=spf1 exists:%{i}.%{l2r-}.user.%{d2}"}],"1.2.3.4.gladstone.philip.user.example.com":[{"A":"127.0.0.2"}],"e12.example.com":[{"SPF":"v=spf1 exists:%{l2r+-}.user.%{d2}"}],"bar.foo.user.example.com":[{"A":"127.0.0.2"}]}, failOnNoFake: true, helo: "msgbas2x.cos.example.com"}
        let promise = spf.check_host('192.168.218.40', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'PASS');
        });
      });
      it('invalid-hello-macro', function(){
        let email = 'test@e9.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"example.com.d.spf.example.com":[{"SPF":"v=spf1 redirect=a.spf.example.com"}],"a.spf.example.com":[{"SPF":"v=spf1 include:o.spf.example.com. ~all"}],"o.spf.example.com":[{"SPF":"v=spf1 ip4:192.168.218.40"}],"msgbas2x.cos.example.com":[{"A":"192.168.218.40"}],"example.com":[{"A":"192.168.90.76"},{"SPF":"v=spf1 redirect=%{d}.d.spf.example.com."}],"exp.example.com":[{"SPF":"v=spf1 exp=msg.example.com. -all"}],"msg.example.com":[{"TXT":"This is a test."}],"e1.example.com":[{"SPF":"v=spf1 -exists:%(ir).sbl.example.com ?all"}],"e1e.example.com":[{"SPF":"v=spf1 exists:foo%(ir).sbl.example.com ?all"}],"e1t.example.com":[{"SPF":"v=spf1 exists:foo%.sbl.example.com ?all"}],"e1a.example.com":[{"SPF":"v=spf1 a:macro%%percent%_%_space%-url-space.example.com -all"}],"macro%percent  space%20url-space.example.com":[{"A":"1.2.3.4"}],"e2.example.com":[{"SPF":"v=spf1 -all exp=%{r}.example.com"}],"e3.example.com":[{"SPF":"v=spf1 -all exp=%{ir}.example.com"}],"40.218.168.192.example.com":[{"TXT":"Connections from %{c} not authorized."}],"somewhat.long.exp.example.com":[{"SPF":"v=spf1 -all exp=foobar.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.example.com"}],"somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.example.com":[{"TXT":"Congratulations!  That was tricky."}],"e4.example.com":[{"SPF":"v=spf1 -all exp=e4msg.example.com"}],"e4msg.example.com":[{"TXT":"%{c} is queried as %{ir}.%{v}.arpa"}],"e5.example.com":[{"SPF":"v=spf1 a:%{a}.example.com -all"}],"e6.example.com":[{"SPF":"v=spf1 -all exp=e6msg.example.com"}],"e6msg.example.com":[{"TXT":"connect from %{p}"}],"mx.example.com":[{"A":"192.168.218.41"},{"A":"192.168.218.42"},{"AAAA":"CAFE:BABE::2"},{"AAAA":"CAFE:BABE::3"}],"40.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"}],"41.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"}],"42.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"},{"PTR":"mx.e7.example.com"}],"1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.E.B.A.B.E.F.A.C.ip6.arpa":[{"PTR":"mx.example.com"}],"3.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.E.B.A.B.E.F.A.C.ip6.arpa":[{"PTR":"mx.example.com"}],"mx.e7.example.com":[{"A":"192.168.218.42"}],"mx.e7.example.com.should.example.com":[{"A":"127.0.0.2"}],"mx.example.com.ok.example.com":[{"A":"127.0.0.2"}],"e7.example.com":[{"SPF":"v=spf1 exists:%{p}.should.example.com ~exists:%{p}.ok.example.com"}],"e8.example.com":[{"SPF":"v=spf1 -all exp=msg8.%{D2}"}],"msg8.example.com":[{"TXT":"http://example.com/why.html?l=%{L}"}],"e9.example.com":[{"SPF":"v=spf1 a:%{H} -all"}],"e10.example.com":[{"SPF":"v=spf1 -include:_spfh.%{d2} ip4:1.2.3.0/24 -all"}],"_spfh.example.com":[{"SPF":"v=spf1 -a:%{h} +all"}],"e11.example.com":[{"SPF":"v=spf1 exists:%{i}.%{l2r-}.user.%{d2}"}],"1.2.3.4.gladstone.philip.user.example.com":[{"A":"127.0.0.2"}],"e12.example.com":[{"SPF":"v=spf1 exists:%{l2r+-}.user.%{d2}"}],"bar.foo.user.example.com":[{"A":"127.0.0.2"}]}, failOnNoFake: true, helo: "JUMPIN' JUPITER"}
        let promise = spf.check_host('192.168.218.40', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'FAIL');
        });
      });
      it('hello-domain-literal', function(){
        let email = 'test@e9.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"example.com.d.spf.example.com":[{"SPF":"v=spf1 redirect=a.spf.example.com"}],"a.spf.example.com":[{"SPF":"v=spf1 include:o.spf.example.com. ~all"}],"o.spf.example.com":[{"SPF":"v=spf1 ip4:192.168.218.40"}],"msgbas2x.cos.example.com":[{"A":"192.168.218.40"}],"example.com":[{"A":"192.168.90.76"},{"SPF":"v=spf1 redirect=%{d}.d.spf.example.com."}],"exp.example.com":[{"SPF":"v=spf1 exp=msg.example.com. -all"}],"msg.example.com":[{"TXT":"This is a test."}],"e1.example.com":[{"SPF":"v=spf1 -exists:%(ir).sbl.example.com ?all"}],"e1e.example.com":[{"SPF":"v=spf1 exists:foo%(ir).sbl.example.com ?all"}],"e1t.example.com":[{"SPF":"v=spf1 exists:foo%.sbl.example.com ?all"}],"e1a.example.com":[{"SPF":"v=spf1 a:macro%%percent%_%_space%-url-space.example.com -all"}],"macro%percent  space%20url-space.example.com":[{"A":"1.2.3.4"}],"e2.example.com":[{"SPF":"v=spf1 -all exp=%{r}.example.com"}],"e3.example.com":[{"SPF":"v=spf1 -all exp=%{ir}.example.com"}],"40.218.168.192.example.com":[{"TXT":"Connections from %{c} not authorized."}],"somewhat.long.exp.example.com":[{"SPF":"v=spf1 -all exp=foobar.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.example.com"}],"somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.example.com":[{"TXT":"Congratulations!  That was tricky."}],"e4.example.com":[{"SPF":"v=spf1 -all exp=e4msg.example.com"}],"e4msg.example.com":[{"TXT":"%{c} is queried as %{ir}.%{v}.arpa"}],"e5.example.com":[{"SPF":"v=spf1 a:%{a}.example.com -all"}],"e6.example.com":[{"SPF":"v=spf1 -all exp=e6msg.example.com"}],"e6msg.example.com":[{"TXT":"connect from %{p}"}],"mx.example.com":[{"A":"192.168.218.41"},{"A":"192.168.218.42"},{"AAAA":"CAFE:BABE::2"},{"AAAA":"CAFE:BABE::3"}],"40.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"}],"41.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"}],"42.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"},{"PTR":"mx.e7.example.com"}],"1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.E.B.A.B.E.F.A.C.ip6.arpa":[{"PTR":"mx.example.com"}],"3.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.E.B.A.B.E.F.A.C.ip6.arpa":[{"PTR":"mx.example.com"}],"mx.e7.example.com":[{"A":"192.168.218.42"}],"mx.e7.example.com.should.example.com":[{"A":"127.0.0.2"}],"mx.example.com.ok.example.com":[{"A":"127.0.0.2"}],"e7.example.com":[{"SPF":"v=spf1 exists:%{p}.should.example.com ~exists:%{p}.ok.example.com"}],"e8.example.com":[{"SPF":"v=spf1 -all exp=msg8.%{D2}"}],"msg8.example.com":[{"TXT":"http://example.com/why.html?l=%{L}"}],"e9.example.com":[{"SPF":"v=spf1 a:%{H} -all"}],"e10.example.com":[{"SPF":"v=spf1 -include:_spfh.%{d2} ip4:1.2.3.0/24 -all"}],"_spfh.example.com":[{"SPF":"v=spf1 -a:%{h} +all"}],"e11.example.com":[{"SPF":"v=spf1 exists:%{i}.%{l2r-}.user.%{d2}"}],"1.2.3.4.gladstone.philip.user.example.com":[{"A":"127.0.0.2"}],"e12.example.com":[{"SPF":"v=spf1 exists:%{l2r+-}.user.%{d2}"}],"bar.foo.user.example.com":[{"A":"127.0.0.2"}]}, failOnNoFake: true, helo: "[192.168.218.40]"}
        let promise = spf.check_host('192.168.218.40', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'FAIL');
        });
      });
      it('require-valid-helo', function(){
        let email = 'test@e10.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"example.com.d.spf.example.com":[{"SPF":"v=spf1 redirect=a.spf.example.com"}],"a.spf.example.com":[{"SPF":"v=spf1 include:o.spf.example.com. ~all"}],"o.spf.example.com":[{"SPF":"v=spf1 ip4:192.168.218.40"}],"msgbas2x.cos.example.com":[{"A":"192.168.218.40"}],"example.com":[{"A":"192.168.90.76"},{"SPF":"v=spf1 redirect=%{d}.d.spf.example.com."}],"exp.example.com":[{"SPF":"v=spf1 exp=msg.example.com. -all"}],"msg.example.com":[{"TXT":"This is a test."}],"e1.example.com":[{"SPF":"v=spf1 -exists:%(ir).sbl.example.com ?all"}],"e1e.example.com":[{"SPF":"v=spf1 exists:foo%(ir).sbl.example.com ?all"}],"e1t.example.com":[{"SPF":"v=spf1 exists:foo%.sbl.example.com ?all"}],"e1a.example.com":[{"SPF":"v=spf1 a:macro%%percent%_%_space%-url-space.example.com -all"}],"macro%percent  space%20url-space.example.com":[{"A":"1.2.3.4"}],"e2.example.com":[{"SPF":"v=spf1 -all exp=%{r}.example.com"}],"e3.example.com":[{"SPF":"v=spf1 -all exp=%{ir}.example.com"}],"40.218.168.192.example.com":[{"TXT":"Connections from %{c} not authorized."}],"somewhat.long.exp.example.com":[{"SPF":"v=spf1 -all exp=foobar.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.example.com"}],"somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.example.com":[{"TXT":"Congratulations!  That was tricky."}],"e4.example.com":[{"SPF":"v=spf1 -all exp=e4msg.example.com"}],"e4msg.example.com":[{"TXT":"%{c} is queried as %{ir}.%{v}.arpa"}],"e5.example.com":[{"SPF":"v=spf1 a:%{a}.example.com -all"}],"e6.example.com":[{"SPF":"v=spf1 -all exp=e6msg.example.com"}],"e6msg.example.com":[{"TXT":"connect from %{p}"}],"mx.example.com":[{"A":"192.168.218.41"},{"A":"192.168.218.42"},{"AAAA":"CAFE:BABE::2"},{"AAAA":"CAFE:BABE::3"}],"40.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"}],"41.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"}],"42.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"},{"PTR":"mx.e7.example.com"}],"1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.E.B.A.B.E.F.A.C.ip6.arpa":[{"PTR":"mx.example.com"}],"3.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.E.B.A.B.E.F.A.C.ip6.arpa":[{"PTR":"mx.example.com"}],"mx.e7.example.com":[{"A":"192.168.218.42"}],"mx.e7.example.com.should.example.com":[{"A":"127.0.0.2"}],"mx.example.com.ok.example.com":[{"A":"127.0.0.2"}],"e7.example.com":[{"SPF":"v=spf1 exists:%{p}.should.example.com ~exists:%{p}.ok.example.com"}],"e8.example.com":[{"SPF":"v=spf1 -all exp=msg8.%{D2}"}],"msg8.example.com":[{"TXT":"http://example.com/why.html?l=%{L}"}],"e9.example.com":[{"SPF":"v=spf1 a:%{H} -all"}],"e10.example.com":[{"SPF":"v=spf1 -include:_spfh.%{d2} ip4:1.2.3.0/24 -all"}],"_spfh.example.com":[{"SPF":"v=spf1 -a:%{h} +all"}],"e11.example.com":[{"SPF":"v=spf1 exists:%{i}.%{l2r-}.user.%{d2}"}],"1.2.3.4.gladstone.philip.user.example.com":[{"A":"127.0.0.2"}],"e12.example.com":[{"SPF":"v=spf1 exists:%{l2r+-}.user.%{d2}"}],"bar.foo.user.example.com":[{"A":"127.0.0.2"}]}, failOnNoFake: true, helo: "OEMCOMPUTER"}
        let promise = spf.check_host('1.2.3.4', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'FAIL');
        });
      });
      it('macro-reverse-split-on-dash', function(){
        let email = 'philip-gladstone-test@e11.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"example.com.d.spf.example.com":[{"SPF":"v=spf1 redirect=a.spf.example.com"}],"a.spf.example.com":[{"SPF":"v=spf1 include:o.spf.example.com. ~all"}],"o.spf.example.com":[{"SPF":"v=spf1 ip4:192.168.218.40"}],"msgbas2x.cos.example.com":[{"A":"192.168.218.40"}],"example.com":[{"A":"192.168.90.76"},{"SPF":"v=spf1 redirect=%{d}.d.spf.example.com."}],"exp.example.com":[{"SPF":"v=spf1 exp=msg.example.com. -all"}],"msg.example.com":[{"TXT":"This is a test."}],"e1.example.com":[{"SPF":"v=spf1 -exists:%(ir).sbl.example.com ?all"}],"e1e.example.com":[{"SPF":"v=spf1 exists:foo%(ir).sbl.example.com ?all"}],"e1t.example.com":[{"SPF":"v=spf1 exists:foo%.sbl.example.com ?all"}],"e1a.example.com":[{"SPF":"v=spf1 a:macro%%percent%_%_space%-url-space.example.com -all"}],"macro%percent  space%20url-space.example.com":[{"A":"1.2.3.4"}],"e2.example.com":[{"SPF":"v=spf1 -all exp=%{r}.example.com"}],"e3.example.com":[{"SPF":"v=spf1 -all exp=%{ir}.example.com"}],"40.218.168.192.example.com":[{"TXT":"Connections from %{c} not authorized."}],"somewhat.long.exp.example.com":[{"SPF":"v=spf1 -all exp=foobar.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.example.com"}],"somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.example.com":[{"TXT":"Congratulations!  That was tricky."}],"e4.example.com":[{"SPF":"v=spf1 -all exp=e4msg.example.com"}],"e4msg.example.com":[{"TXT":"%{c} is queried as %{ir}.%{v}.arpa"}],"e5.example.com":[{"SPF":"v=spf1 a:%{a}.example.com -all"}],"e6.example.com":[{"SPF":"v=spf1 -all exp=e6msg.example.com"}],"e6msg.example.com":[{"TXT":"connect from %{p}"}],"mx.example.com":[{"A":"192.168.218.41"},{"A":"192.168.218.42"},{"AAAA":"CAFE:BABE::2"},{"AAAA":"CAFE:BABE::3"}],"40.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"}],"41.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"}],"42.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"},{"PTR":"mx.e7.example.com"}],"1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.E.B.A.B.E.F.A.C.ip6.arpa":[{"PTR":"mx.example.com"}],"3.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.E.B.A.B.E.F.A.C.ip6.arpa":[{"PTR":"mx.example.com"}],"mx.e7.example.com":[{"A":"192.168.218.42"}],"mx.e7.example.com.should.example.com":[{"A":"127.0.0.2"}],"mx.example.com.ok.example.com":[{"A":"127.0.0.2"}],"e7.example.com":[{"SPF":"v=spf1 exists:%{p}.should.example.com ~exists:%{p}.ok.example.com"}],"e8.example.com":[{"SPF":"v=spf1 -all exp=msg8.%{D2}"}],"msg8.example.com":[{"TXT":"http://example.com/why.html?l=%{L}"}],"e9.example.com":[{"SPF":"v=spf1 a:%{H} -all"}],"e10.example.com":[{"SPF":"v=spf1 -include:_spfh.%{d2} ip4:1.2.3.0/24 -all"}],"_spfh.example.com":[{"SPF":"v=spf1 -a:%{h} +all"}],"e11.example.com":[{"SPF":"v=spf1 exists:%{i}.%{l2r-}.user.%{d2}"}],"1.2.3.4.gladstone.philip.user.example.com":[{"A":"127.0.0.2"}],"e12.example.com":[{"SPF":"v=spf1 exists:%{l2r+-}.user.%{d2}"}],"bar.foo.user.example.com":[{"A":"127.0.0.2"}]}, failOnNoFake: true, helo: "mail.example.com"}
        let promise = spf.check_host('1.2.3.4', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'PASS');
        });
      });
      it('macro-multiple-delimiters', function(){
        let email = 'foo-bar+zip+quux@e12.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"example.com.d.spf.example.com":[{"SPF":"v=spf1 redirect=a.spf.example.com"}],"a.spf.example.com":[{"SPF":"v=spf1 include:o.spf.example.com. ~all"}],"o.spf.example.com":[{"SPF":"v=spf1 ip4:192.168.218.40"}],"msgbas2x.cos.example.com":[{"A":"192.168.218.40"}],"example.com":[{"A":"192.168.90.76"},{"SPF":"v=spf1 redirect=%{d}.d.spf.example.com."}],"exp.example.com":[{"SPF":"v=spf1 exp=msg.example.com. -all"}],"msg.example.com":[{"TXT":"This is a test."}],"e1.example.com":[{"SPF":"v=spf1 -exists:%(ir).sbl.example.com ?all"}],"e1e.example.com":[{"SPF":"v=spf1 exists:foo%(ir).sbl.example.com ?all"}],"e1t.example.com":[{"SPF":"v=spf1 exists:foo%.sbl.example.com ?all"}],"e1a.example.com":[{"SPF":"v=spf1 a:macro%%percent%_%_space%-url-space.example.com -all"}],"macro%percent  space%20url-space.example.com":[{"A":"1.2.3.4"}],"e2.example.com":[{"SPF":"v=spf1 -all exp=%{r}.example.com"}],"e3.example.com":[{"SPF":"v=spf1 -all exp=%{ir}.example.com"}],"40.218.168.192.example.com":[{"TXT":"Connections from %{c} not authorized."}],"somewhat.long.exp.example.com":[{"SPF":"v=spf1 -all exp=foobar.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.example.com"}],"somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.example.com":[{"TXT":"Congratulations!  That was tricky."}],"e4.example.com":[{"SPF":"v=spf1 -all exp=e4msg.example.com"}],"e4msg.example.com":[{"TXT":"%{c} is queried as %{ir}.%{v}.arpa"}],"e5.example.com":[{"SPF":"v=spf1 a:%{a}.example.com -all"}],"e6.example.com":[{"SPF":"v=spf1 -all exp=e6msg.example.com"}],"e6msg.example.com":[{"TXT":"connect from %{p}"}],"mx.example.com":[{"A":"192.168.218.41"},{"A":"192.168.218.42"},{"AAAA":"CAFE:BABE::2"},{"AAAA":"CAFE:BABE::3"}],"40.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"}],"41.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"}],"42.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"},{"PTR":"mx.e7.example.com"}],"1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.E.B.A.B.E.F.A.C.ip6.arpa":[{"PTR":"mx.example.com"}],"3.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.E.B.A.B.E.F.A.C.ip6.arpa":[{"PTR":"mx.example.com"}],"mx.e7.example.com":[{"A":"192.168.218.42"}],"mx.e7.example.com.should.example.com":[{"A":"127.0.0.2"}],"mx.example.com.ok.example.com":[{"A":"127.0.0.2"}],"e7.example.com":[{"SPF":"v=spf1 exists:%{p}.should.example.com ~exists:%{p}.ok.example.com"}],"e8.example.com":[{"SPF":"v=spf1 -all exp=msg8.%{D2}"}],"msg8.example.com":[{"TXT":"http://example.com/why.html?l=%{L}"}],"e9.example.com":[{"SPF":"v=spf1 a:%{H} -all"}],"e10.example.com":[{"SPF":"v=spf1 -include:_spfh.%{d2} ip4:1.2.3.0/24 -all"}],"_spfh.example.com":[{"SPF":"v=spf1 -a:%{h} +all"}],"e11.example.com":[{"SPF":"v=spf1 exists:%{i}.%{l2r-}.user.%{d2}"}],"1.2.3.4.gladstone.philip.user.example.com":[{"A":"127.0.0.2"}],"e12.example.com":[{"SPF":"v=spf1 exists:%{l2r+-}.user.%{d2}"}],"bar.foo.user.example.com":[{"A":"127.0.0.2"}]}, failOnNoFake: true, helo: "mail.example.com"}
        let promise = spf.check_host('1.2.3.4', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'PASS');
        });
      });
    });
    describe('Processing limits', function(){
      it('redirect-loop', function(){
        let email = 'foo@e1.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 ip4:1.1.1.1 redirect=e1.example.com"},{"A":"1.2.3.6"}],"e2.example.com":[{"SPF":"v=spf1 include:e3.example.com"},{"A":"1.2.3.7"}],"e3.example.com":[{"SPF":"v=spf1 include:e2.example.com"},{"A":"1.2.3.8"}],"e4.example.com":[{"SPF":"v=spf1 mx"},{"MX":[0,"mail.example.com"]},{"MX":[1,"mail.example.com"]},{"MX":[2,"mail.example.com"]},{"MX":[3,"mail.example.com"]},{"MX":[4,"mail.example.com"]},{"MX":[5,"mail.example.com"]},{"MX":[6,"mail.example.com"]},{"MX":[7,"mail.example.com"]},{"MX":[8,"mail.example.com"]},{"MX":[9,"mail.example.com"]},{"MX":[10,"e4.example.com"]},{"A":"1.2.3.5"}],"e5.example.com":[{"SPF":"v=spf1 ptr"},{"A":"1.2.3.5"}],"5.3.2.1.in-addr.arpa":[{"PTR":"e1.example.com."},{"PTR":"e2.example.com."},{"PTR":"e3.example.com."},{"PTR":"e4.example.com."},{"PTR":"example.com."},{"PTR":"e6.example.com."},{"PTR":"e7.example.com."},{"PTR":"e8.example.com."},{"PTR":"e9.example.com."},{"PTR":"e10.example.com."},{"PTR":"e5.example.com."}],"e6.example.com":[{"SPF":"v=spf1 a mx a mx a mx a mx a ptr ip4:1.2.3.4 -all"},{"A":"1.2.3.8"},{"MX":[10,"e6.example.com"]}],"e7.example.com":[{"SPF":"v=spf1 a mx a mx a mx a mx a ptr a ip4:1.2.3.4 -all"},{"A":"1.2.3.20"}],"e8.example.com":[{"SPF":"v=spf1 a include:inc.example.com ip4:1.2.3.4 mx -all"},{"A":"1.2.3.4"}],"inc.example.com":[{"SPF":"v=spf1 a a a a a a a a"},{"A":"1.2.3.10"}],"e9.example.com":[{"SPF":"v=spf1 a include:inc.example.com a ip4:1.2.3.4 -all"},{"A":"1.2.3.21"}],"e10.example.com":[{"SPF":"v=spf1 a -all"},{"A":"1.2.3.1"},{"A":"1.2.3.2"},{"A":"1.2.3.3"},{"A":"1.2.3.4"},{"A":"1.2.3.5"},{"A":"1.2.3.6"},{"A":"1.2.3.7"},{"A":"1.2.3.8"},{"A":"1.2.3.9"},{"A":"1.2.3.10"},{"A":"1.2.3.11"},{"A":"1.2.3.12"}]}, failOnNoFake: true, helo: "mail.example.com"}
        let promise = spf.check_host('1.2.3.4', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'PERMERROR');
        });
      });
      it('include-loop', function(){
        let email = 'foo@e2.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 ip4:1.1.1.1 redirect=e1.example.com"},{"A":"1.2.3.6"}],"e2.example.com":[{"SPF":"v=spf1 include:e3.example.com"},{"A":"1.2.3.7"}],"e3.example.com":[{"SPF":"v=spf1 include:e2.example.com"},{"A":"1.2.3.8"}],"e4.example.com":[{"SPF":"v=spf1 mx"},{"MX":[0,"mail.example.com"]},{"MX":[1,"mail.example.com"]},{"MX":[2,"mail.example.com"]},{"MX":[3,"mail.example.com"]},{"MX":[4,"mail.example.com"]},{"MX":[5,"mail.example.com"]},{"MX":[6,"mail.example.com"]},{"MX":[7,"mail.example.com"]},{"MX":[8,"mail.example.com"]},{"MX":[9,"mail.example.com"]},{"MX":[10,"e4.example.com"]},{"A":"1.2.3.5"}],"e5.example.com":[{"SPF":"v=spf1 ptr"},{"A":"1.2.3.5"}],"5.3.2.1.in-addr.arpa":[{"PTR":"e1.example.com."},{"PTR":"e2.example.com."},{"PTR":"e3.example.com."},{"PTR":"e4.example.com."},{"PTR":"example.com."},{"PTR":"e6.example.com."},{"PTR":"e7.example.com."},{"PTR":"e8.example.com."},{"PTR":"e9.example.com."},{"PTR":"e10.example.com."},{"PTR":"e5.example.com."}],"e6.example.com":[{"SPF":"v=spf1 a mx a mx a mx a mx a ptr ip4:1.2.3.4 -all"},{"A":"1.2.3.8"},{"MX":[10,"e6.example.com"]}],"e7.example.com":[{"SPF":"v=spf1 a mx a mx a mx a mx a ptr a ip4:1.2.3.4 -all"},{"A":"1.2.3.20"}],"e8.example.com":[{"SPF":"v=spf1 a include:inc.example.com ip4:1.2.3.4 mx -all"},{"A":"1.2.3.4"}],"inc.example.com":[{"SPF":"v=spf1 a a a a a a a a"},{"A":"1.2.3.10"}],"e9.example.com":[{"SPF":"v=spf1 a include:inc.example.com a ip4:1.2.3.4 -all"},{"A":"1.2.3.21"}],"e10.example.com":[{"SPF":"v=spf1 a -all"},{"A":"1.2.3.1"},{"A":"1.2.3.2"},{"A":"1.2.3.3"},{"A":"1.2.3.4"},{"A":"1.2.3.5"},{"A":"1.2.3.6"},{"A":"1.2.3.7"},{"A":"1.2.3.8"},{"A":"1.2.3.9"},{"A":"1.2.3.10"},{"A":"1.2.3.11"},{"A":"1.2.3.12"}]}, failOnNoFake: true, helo: "mail.example.com"}
        let promise = spf.check_host('1.2.3.4', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'PERMERROR');
        });
      });
      it('mx-limit', function(){
        let email = 'foo@e4.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 ip4:1.1.1.1 redirect=e1.example.com"},{"A":"1.2.3.6"}],"e2.example.com":[{"SPF":"v=spf1 include:e3.example.com"},{"A":"1.2.3.7"}],"e3.example.com":[{"SPF":"v=spf1 include:e2.example.com"},{"A":"1.2.3.8"}],"e4.example.com":[{"SPF":"v=spf1 mx"},{"MX":[0,"mail.example.com"]},{"MX":[1,"mail.example.com"]},{"MX":[2,"mail.example.com"]},{"MX":[3,"mail.example.com"]},{"MX":[4,"mail.example.com"]},{"MX":[5,"mail.example.com"]},{"MX":[6,"mail.example.com"]},{"MX":[7,"mail.example.com"]},{"MX":[8,"mail.example.com"]},{"MX":[9,"mail.example.com"]},{"MX":[10,"e4.example.com"]},{"A":"1.2.3.5"}],"e5.example.com":[{"SPF":"v=spf1 ptr"},{"A":"1.2.3.5"}],"5.3.2.1.in-addr.arpa":[{"PTR":"e1.example.com."},{"PTR":"e2.example.com."},{"PTR":"e3.example.com."},{"PTR":"e4.example.com."},{"PTR":"example.com."},{"PTR":"e6.example.com."},{"PTR":"e7.example.com."},{"PTR":"e8.example.com."},{"PTR":"e9.example.com."},{"PTR":"e10.example.com."},{"PTR":"e5.example.com."}],"e6.example.com":[{"SPF":"v=spf1 a mx a mx a mx a mx a ptr ip4:1.2.3.4 -all"},{"A":"1.2.3.8"},{"MX":[10,"e6.example.com"]}],"e7.example.com":[{"SPF":"v=spf1 a mx a mx a mx a mx a ptr a ip4:1.2.3.4 -all"},{"A":"1.2.3.20"}],"e8.example.com":[{"SPF":"v=spf1 a include:inc.example.com ip4:1.2.3.4 mx -all"},{"A":"1.2.3.4"}],"inc.example.com":[{"SPF":"v=spf1 a a a a a a a a"},{"A":"1.2.3.10"}],"e9.example.com":[{"SPF":"v=spf1 a include:inc.example.com a ip4:1.2.3.4 -all"},{"A":"1.2.3.21"}],"e10.example.com":[{"SPF":"v=spf1 a -all"},{"A":"1.2.3.1"},{"A":"1.2.3.2"},{"A":"1.2.3.3"},{"A":"1.2.3.4"},{"A":"1.2.3.5"},{"A":"1.2.3.6"},{"A":"1.2.3.7"},{"A":"1.2.3.8"},{"A":"1.2.3.9"},{"A":"1.2.3.10"},{"A":"1.2.3.11"},{"A":"1.2.3.12"}]}, failOnNoFake: true, helo: "mail.example.com"}
        let promise = spf.check_host('1.2.3.5', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.include(["neutral","pass","permerror"], result.toLowerCase());
        });
      });
      it('ptr-limit', function(){
        let email = 'foo@e5.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 ip4:1.1.1.1 redirect=e1.example.com"},{"A":"1.2.3.6"}],"e2.example.com":[{"SPF":"v=spf1 include:e3.example.com"},{"A":"1.2.3.7"}],"e3.example.com":[{"SPF":"v=spf1 include:e2.example.com"},{"A":"1.2.3.8"}],"e4.example.com":[{"SPF":"v=spf1 mx"},{"MX":[0,"mail.example.com"]},{"MX":[1,"mail.example.com"]},{"MX":[2,"mail.example.com"]},{"MX":[3,"mail.example.com"]},{"MX":[4,"mail.example.com"]},{"MX":[5,"mail.example.com"]},{"MX":[6,"mail.example.com"]},{"MX":[7,"mail.example.com"]},{"MX":[8,"mail.example.com"]},{"MX":[9,"mail.example.com"]},{"MX":[10,"e4.example.com"]},{"A":"1.2.3.5"}],"e5.example.com":[{"SPF":"v=spf1 ptr"},{"A":"1.2.3.5"}],"5.3.2.1.in-addr.arpa":[{"PTR":"e1.example.com."},{"PTR":"e2.example.com."},{"PTR":"e3.example.com."},{"PTR":"e4.example.com."},{"PTR":"example.com."},{"PTR":"e6.example.com."},{"PTR":"e7.example.com."},{"PTR":"e8.example.com."},{"PTR":"e9.example.com."},{"PTR":"e10.example.com."},{"PTR":"e5.example.com."}],"e6.example.com":[{"SPF":"v=spf1 a mx a mx a mx a mx a ptr ip4:1.2.3.4 -all"},{"A":"1.2.3.8"},{"MX":[10,"e6.example.com"]}],"e7.example.com":[{"SPF":"v=spf1 a mx a mx a mx a mx a ptr a ip4:1.2.3.4 -all"},{"A":"1.2.3.20"}],"e8.example.com":[{"SPF":"v=spf1 a include:inc.example.com ip4:1.2.3.4 mx -all"},{"A":"1.2.3.4"}],"inc.example.com":[{"SPF":"v=spf1 a a a a a a a a"},{"A":"1.2.3.10"}],"e9.example.com":[{"SPF":"v=spf1 a include:inc.example.com a ip4:1.2.3.4 -all"},{"A":"1.2.3.21"}],"e10.example.com":[{"SPF":"v=spf1 a -all"},{"A":"1.2.3.1"},{"A":"1.2.3.2"},{"A":"1.2.3.3"},{"A":"1.2.3.4"},{"A":"1.2.3.5"},{"A":"1.2.3.6"},{"A":"1.2.3.7"},{"A":"1.2.3.8"},{"A":"1.2.3.9"},{"A":"1.2.3.10"},{"A":"1.2.3.11"},{"A":"1.2.3.12"}]}, failOnNoFake: true, helo: "mail.example.com"}
        let promise = spf.check_host('1.2.3.5', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.include(["neutral","pass"], result.toLowerCase());
        });
      });
      it('false-a-limit', function(){
        let email = 'foo@e10.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 ip4:1.1.1.1 redirect=e1.example.com"},{"A":"1.2.3.6"}],"e2.example.com":[{"SPF":"v=spf1 include:e3.example.com"},{"A":"1.2.3.7"}],"e3.example.com":[{"SPF":"v=spf1 include:e2.example.com"},{"A":"1.2.3.8"}],"e4.example.com":[{"SPF":"v=spf1 mx"},{"MX":[0,"mail.example.com"]},{"MX":[1,"mail.example.com"]},{"MX":[2,"mail.example.com"]},{"MX":[3,"mail.example.com"]},{"MX":[4,"mail.example.com"]},{"MX":[5,"mail.example.com"]},{"MX":[6,"mail.example.com"]},{"MX":[7,"mail.example.com"]},{"MX":[8,"mail.example.com"]},{"MX":[9,"mail.example.com"]},{"MX":[10,"e4.example.com"]},{"A":"1.2.3.5"}],"e5.example.com":[{"SPF":"v=spf1 ptr"},{"A":"1.2.3.5"}],"5.3.2.1.in-addr.arpa":[{"PTR":"e1.example.com."},{"PTR":"e2.example.com."},{"PTR":"e3.example.com."},{"PTR":"e4.example.com."},{"PTR":"example.com."},{"PTR":"e6.example.com."},{"PTR":"e7.example.com."},{"PTR":"e8.example.com."},{"PTR":"e9.example.com."},{"PTR":"e10.example.com."},{"PTR":"e5.example.com."}],"e6.example.com":[{"SPF":"v=spf1 a mx a mx a mx a mx a ptr ip4:1.2.3.4 -all"},{"A":"1.2.3.8"},{"MX":[10,"e6.example.com"]}],"e7.example.com":[{"SPF":"v=spf1 a mx a mx a mx a mx a ptr a ip4:1.2.3.4 -all"},{"A":"1.2.3.20"}],"e8.example.com":[{"SPF":"v=spf1 a include:inc.example.com ip4:1.2.3.4 mx -all"},{"A":"1.2.3.4"}],"inc.example.com":[{"SPF":"v=spf1 a a a a a a a a"},{"A":"1.2.3.10"}],"e9.example.com":[{"SPF":"v=spf1 a include:inc.example.com a ip4:1.2.3.4 -all"},{"A":"1.2.3.21"}],"e10.example.com":[{"SPF":"v=spf1 a -all"},{"A":"1.2.3.1"},{"A":"1.2.3.2"},{"A":"1.2.3.3"},{"A":"1.2.3.4"},{"A":"1.2.3.5"},{"A":"1.2.3.6"},{"A":"1.2.3.7"},{"A":"1.2.3.8"},{"A":"1.2.3.9"},{"A":"1.2.3.10"},{"A":"1.2.3.11"},{"A":"1.2.3.12"}]}, failOnNoFake: true, helo: "mail.example.com"}
        let promise = spf.check_host('1.2.3.12', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'PASS');
        });
      });
      it('mech-at-limit', function(){
        let email = 'foo@e6.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 ip4:1.1.1.1 redirect=e1.example.com"},{"A":"1.2.3.6"}],"e2.example.com":[{"SPF":"v=spf1 include:e3.example.com"},{"A":"1.2.3.7"}],"e3.example.com":[{"SPF":"v=spf1 include:e2.example.com"},{"A":"1.2.3.8"}],"e4.example.com":[{"SPF":"v=spf1 mx"},{"MX":[0,"mail.example.com"]},{"MX":[1,"mail.example.com"]},{"MX":[2,"mail.example.com"]},{"MX":[3,"mail.example.com"]},{"MX":[4,"mail.example.com"]},{"MX":[5,"mail.example.com"]},{"MX":[6,"mail.example.com"]},{"MX":[7,"mail.example.com"]},{"MX":[8,"mail.example.com"]},{"MX":[9,"mail.example.com"]},{"MX":[10,"e4.example.com"]},{"A":"1.2.3.5"}],"e5.example.com":[{"SPF":"v=spf1 ptr"},{"A":"1.2.3.5"}],"5.3.2.1.in-addr.arpa":[{"PTR":"e1.example.com."},{"PTR":"e2.example.com."},{"PTR":"e3.example.com."},{"PTR":"e4.example.com."},{"PTR":"example.com."},{"PTR":"e6.example.com."},{"PTR":"e7.example.com."},{"PTR":"e8.example.com."},{"PTR":"e9.example.com."},{"PTR":"e10.example.com."},{"PTR":"e5.example.com."}],"e6.example.com":[{"SPF":"v=spf1 a mx a mx a mx a mx a ptr ip4:1.2.3.4 -all"},{"A":"1.2.3.8"},{"MX":[10,"e6.example.com"]}],"e7.example.com":[{"SPF":"v=spf1 a mx a mx a mx a mx a ptr a ip4:1.2.3.4 -all"},{"A":"1.2.3.20"}],"e8.example.com":[{"SPF":"v=spf1 a include:inc.example.com ip4:1.2.3.4 mx -all"},{"A":"1.2.3.4"}],"inc.example.com":[{"SPF":"v=spf1 a a a a a a a a"},{"A":"1.2.3.10"}],"e9.example.com":[{"SPF":"v=spf1 a include:inc.example.com a ip4:1.2.3.4 -all"},{"A":"1.2.3.21"}],"e10.example.com":[{"SPF":"v=spf1 a -all"},{"A":"1.2.3.1"},{"A":"1.2.3.2"},{"A":"1.2.3.3"},{"A":"1.2.3.4"},{"A":"1.2.3.5"},{"A":"1.2.3.6"},{"A":"1.2.3.7"},{"A":"1.2.3.8"},{"A":"1.2.3.9"},{"A":"1.2.3.10"},{"A":"1.2.3.11"},{"A":"1.2.3.12"}]}, failOnNoFake: true, helo: "mail.example.com"}
        let promise = spf.check_host('1.2.3.4', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'PASS');
        });
      });
      it('mech-over-limit', function(){
        let email = 'foo@e7.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 ip4:1.1.1.1 redirect=e1.example.com"},{"A":"1.2.3.6"}],"e2.example.com":[{"SPF":"v=spf1 include:e3.example.com"},{"A":"1.2.3.7"}],"e3.example.com":[{"SPF":"v=spf1 include:e2.example.com"},{"A":"1.2.3.8"}],"e4.example.com":[{"SPF":"v=spf1 mx"},{"MX":[0,"mail.example.com"]},{"MX":[1,"mail.example.com"]},{"MX":[2,"mail.example.com"]},{"MX":[3,"mail.example.com"]},{"MX":[4,"mail.example.com"]},{"MX":[5,"mail.example.com"]},{"MX":[6,"mail.example.com"]},{"MX":[7,"mail.example.com"]},{"MX":[8,"mail.example.com"]},{"MX":[9,"mail.example.com"]},{"MX":[10,"e4.example.com"]},{"A":"1.2.3.5"}],"e5.example.com":[{"SPF":"v=spf1 ptr"},{"A":"1.2.3.5"}],"5.3.2.1.in-addr.arpa":[{"PTR":"e1.example.com."},{"PTR":"e2.example.com."},{"PTR":"e3.example.com."},{"PTR":"e4.example.com."},{"PTR":"example.com."},{"PTR":"e6.example.com."},{"PTR":"e7.example.com."},{"PTR":"e8.example.com."},{"PTR":"e9.example.com."},{"PTR":"e10.example.com."},{"PTR":"e5.example.com."}],"e6.example.com":[{"SPF":"v=spf1 a mx a mx a mx a mx a ptr ip4:1.2.3.4 -all"},{"A":"1.2.3.8"},{"MX":[10,"e6.example.com"]}],"e7.example.com":[{"SPF":"v=spf1 a mx a mx a mx a mx a ptr a ip4:1.2.3.4 -all"},{"A":"1.2.3.20"}],"e8.example.com":[{"SPF":"v=spf1 a include:inc.example.com ip4:1.2.3.4 mx -all"},{"A":"1.2.3.4"}],"inc.example.com":[{"SPF":"v=spf1 a a a a a a a a"},{"A":"1.2.3.10"}],"e9.example.com":[{"SPF":"v=spf1 a include:inc.example.com a ip4:1.2.3.4 -all"},{"A":"1.2.3.21"}],"e10.example.com":[{"SPF":"v=spf1 a -all"},{"A":"1.2.3.1"},{"A":"1.2.3.2"},{"A":"1.2.3.3"},{"A":"1.2.3.4"},{"A":"1.2.3.5"},{"A":"1.2.3.6"},{"A":"1.2.3.7"},{"A":"1.2.3.8"},{"A":"1.2.3.9"},{"A":"1.2.3.10"},{"A":"1.2.3.11"},{"A":"1.2.3.12"}]}, failOnNoFake: true, helo: "mail.example.com"}
        let promise = spf.check_host('1.2.3.4', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'PERMERROR');
        });
      });
      it('include-at-limit', function(){
        let email = 'foo@e8.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 ip4:1.1.1.1 redirect=e1.example.com"},{"A":"1.2.3.6"}],"e2.example.com":[{"SPF":"v=spf1 include:e3.example.com"},{"A":"1.2.3.7"}],"e3.example.com":[{"SPF":"v=spf1 include:e2.example.com"},{"A":"1.2.3.8"}],"e4.example.com":[{"SPF":"v=spf1 mx"},{"MX":[0,"mail.example.com"]},{"MX":[1,"mail.example.com"]},{"MX":[2,"mail.example.com"]},{"MX":[3,"mail.example.com"]},{"MX":[4,"mail.example.com"]},{"MX":[5,"mail.example.com"]},{"MX":[6,"mail.example.com"]},{"MX":[7,"mail.example.com"]},{"MX":[8,"mail.example.com"]},{"MX":[9,"mail.example.com"]},{"MX":[10,"e4.example.com"]},{"A":"1.2.3.5"}],"e5.example.com":[{"SPF":"v=spf1 ptr"},{"A":"1.2.3.5"}],"5.3.2.1.in-addr.arpa":[{"PTR":"e1.example.com."},{"PTR":"e2.example.com."},{"PTR":"e3.example.com."},{"PTR":"e4.example.com."},{"PTR":"example.com."},{"PTR":"e6.example.com."},{"PTR":"e7.example.com."},{"PTR":"e8.example.com."},{"PTR":"e9.example.com."},{"PTR":"e10.example.com."},{"PTR":"e5.example.com."}],"e6.example.com":[{"SPF":"v=spf1 a mx a mx a mx a mx a ptr ip4:1.2.3.4 -all"},{"A":"1.2.3.8"},{"MX":[10,"e6.example.com"]}],"e7.example.com":[{"SPF":"v=spf1 a mx a mx a mx a mx a ptr a ip4:1.2.3.4 -all"},{"A":"1.2.3.20"}],"e8.example.com":[{"SPF":"v=spf1 a include:inc.example.com ip4:1.2.3.4 mx -all"},{"A":"1.2.3.4"}],"inc.example.com":[{"SPF":"v=spf1 a a a a a a a a"},{"A":"1.2.3.10"}],"e9.example.com":[{"SPF":"v=spf1 a include:inc.example.com a ip4:1.2.3.4 -all"},{"A":"1.2.3.21"}],"e10.example.com":[{"SPF":"v=spf1 a -all"},{"A":"1.2.3.1"},{"A":"1.2.3.2"},{"A":"1.2.3.3"},{"A":"1.2.3.4"},{"A":"1.2.3.5"},{"A":"1.2.3.6"},{"A":"1.2.3.7"},{"A":"1.2.3.8"},{"A":"1.2.3.9"},{"A":"1.2.3.10"},{"A":"1.2.3.11"},{"A":"1.2.3.12"}]}, failOnNoFake: true, helo: "mail.example.com"}
        let promise = spf.check_host('1.2.3.4', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'PASS');
        });
      });
      it('include-over-limit', function(){
        let email = 'foo@e9.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 ip4:1.1.1.1 redirect=e1.example.com"},{"A":"1.2.3.6"}],"e2.example.com":[{"SPF":"v=spf1 include:e3.example.com"},{"A":"1.2.3.7"}],"e3.example.com":[{"SPF":"v=spf1 include:e2.example.com"},{"A":"1.2.3.8"}],"e4.example.com":[{"SPF":"v=spf1 mx"},{"MX":[0,"mail.example.com"]},{"MX":[1,"mail.example.com"]},{"MX":[2,"mail.example.com"]},{"MX":[3,"mail.example.com"]},{"MX":[4,"mail.example.com"]},{"MX":[5,"mail.example.com"]},{"MX":[6,"mail.example.com"]},{"MX":[7,"mail.example.com"]},{"MX":[8,"mail.example.com"]},{"MX":[9,"mail.example.com"]},{"MX":[10,"e4.example.com"]},{"A":"1.2.3.5"}],"e5.example.com":[{"SPF":"v=spf1 ptr"},{"A":"1.2.3.5"}],"5.3.2.1.in-addr.arpa":[{"PTR":"e1.example.com."},{"PTR":"e2.example.com."},{"PTR":"e3.example.com."},{"PTR":"e4.example.com."},{"PTR":"example.com."},{"PTR":"e6.example.com."},{"PTR":"e7.example.com."},{"PTR":"e8.example.com."},{"PTR":"e9.example.com."},{"PTR":"e10.example.com."},{"PTR":"e5.example.com."}],"e6.example.com":[{"SPF":"v=spf1 a mx a mx a mx a mx a ptr ip4:1.2.3.4 -all"},{"A":"1.2.3.8"},{"MX":[10,"e6.example.com"]}],"e7.example.com":[{"SPF":"v=spf1 a mx a mx a mx a mx a ptr a ip4:1.2.3.4 -all"},{"A":"1.2.3.20"}],"e8.example.com":[{"SPF":"v=spf1 a include:inc.example.com ip4:1.2.3.4 mx -all"},{"A":"1.2.3.4"}],"inc.example.com":[{"SPF":"v=spf1 a a a a a a a a"},{"A":"1.2.3.10"}],"e9.example.com":[{"SPF":"v=spf1 a include:inc.example.com a ip4:1.2.3.4 -all"},{"A":"1.2.3.21"}],"e10.example.com":[{"SPF":"v=spf1 a -all"},{"A":"1.2.3.1"},{"A":"1.2.3.2"},{"A":"1.2.3.3"},{"A":"1.2.3.4"},{"A":"1.2.3.5"},{"A":"1.2.3.6"},{"A":"1.2.3.7"},{"A":"1.2.3.8"},{"A":"1.2.3.9"},{"A":"1.2.3.10"},{"A":"1.2.3.11"},{"A":"1.2.3.12"}]}, failOnNoFake: true, helo: "mail.example.com"}
        let promise = spf.check_host('1.2.3.4', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'PERMERROR');
        });
      });
    });
  });
  describe('RFC7208', function(){
    describe('Initial processing', function(){
      it('toolonglabel', function(){
        let email = 'lyme.eater@A123456789012345678901234567890123456789012345678901234567890123.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"example.com":["TIMEOUT"],"example.net":[{"SPF":"v=spf1 -all exp=exp.example.net"}],"a.example.net":[{"SPF":"v=spf1 -all exp=exp.example.net"}],"exp.example.net":[{"TXT":"%{l}"}],"a12345678901234567890123456789012345678901234567890123456789012.example.com":[{"SPF":"v=spf1 -all"}],"hosed.example.com":[{"SPF":"v=spf1 a:ï»¿garbage.example.net -all"}],"hosed2.example.com":[{"SPF":"v=spf1 a:example.net -all"}],"hosed3.example.com":[{"SPF":"v=spf1 a:example.net all"}],"nothosed.example.com":[{"SPF":"v=spf1 a:example.net -all"},{"SPF":""}],"ctrl.example.com":[{"SPF":"v=spf1 a:ctrl.example.com\rptr -all"},{"A":"192.0.2.3"}],"fine.example.com":[{"SPF":"v=spf1 a  -all"}],"trail.example.com":[{"SPF":"v=spf1 a -all "}]}, failOnNoFake: true, helo: "mail.example.net"}
        let promise = spf.check_host('1.2.3.5', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'NONE');
        });
      });
      it('longlabel', function(){
        let email = 'lyme.eater@A12345678901234567890123456789012345678901234567890123456789012.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"example.com":["TIMEOUT"],"example.net":[{"SPF":"v=spf1 -all exp=exp.example.net"}],"a.example.net":[{"SPF":"v=spf1 -all exp=exp.example.net"}],"exp.example.net":[{"TXT":"%{l}"}],"a12345678901234567890123456789012345678901234567890123456789012.example.com":[{"SPF":"v=spf1 -all"}],"hosed.example.com":[{"SPF":"v=spf1 a:ï»¿garbage.example.net -all"}],"hosed2.example.com":[{"SPF":"v=spf1 a:example.net -all"}],"hosed3.example.com":[{"SPF":"v=spf1 a:example.net all"}],"nothosed.example.com":[{"SPF":"v=spf1 a:example.net -all"},{"SPF":""}],"ctrl.example.com":[{"SPF":"v=spf1 a:ctrl.example.com\rptr -all"},{"A":"192.0.2.3"}],"fine.example.com":[{"SPF":"v=spf1 a  -all"}],"trail.example.com":[{"SPF":"v=spf1 a -all "}]}, failOnNoFake: true, helo: "mail.example.net"}
        let promise = spf.check_host('1.2.3.5', emailSplit[1], email, opts);
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
        let opts = {fakeDNSData: {"example.com":["TIMEOUT"],"example.net":[{"SPF":"v=spf1 -all exp=exp.example.net"}],"a.example.net":[{"SPF":"v=spf1 -all exp=exp.example.net"}],"exp.example.net":[{"TXT":"%{l}"}],"a12345678901234567890123456789012345678901234567890123456789012.example.com":[{"SPF":"v=spf1 -all"}],"hosed.example.com":[{"SPF":"v=spf1 a:ï»¿garbage.example.net -all"}],"hosed2.example.com":[{"SPF":"v=spf1 a:example.net -all"}],"hosed3.example.com":[{"SPF":"v=spf1 a:example.net all"}],"nothosed.example.com":[{"SPF":"v=spf1 a:example.net -all"},{"SPF":""}],"ctrl.example.com":[{"SPF":"v=spf1 a:ctrl.example.com\rptr -all"},{"A":"192.0.2.3"}],"fine.example.com":[{"SPF":"v=spf1 a  -all"}],"trail.example.com":[{"SPF":"v=spf1 a -all "}]}, failOnNoFake: true, helo: "mail.example.net"}
        let promise = spf.check_host('1.2.3.5', emailSplit[1], email, opts);
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
        let opts = {fakeDNSData: {"example.com":["TIMEOUT"],"example.net":[{"SPF":"v=spf1 -all exp=exp.example.net"}],"a.example.net":[{"SPF":"v=spf1 -all exp=exp.example.net"}],"exp.example.net":[{"TXT":"%{l}"}],"a12345678901234567890123456789012345678901234567890123456789012.example.com":[{"SPF":"v=spf1 -all"}],"hosed.example.com":[{"SPF":"v=spf1 a:ï»¿garbage.example.net -all"}],"hosed2.example.com":[{"SPF":"v=spf1 a:example.net -all"}],"hosed3.example.com":[{"SPF":"v=spf1 a:example.net all"}],"nothosed.example.com":[{"SPF":"v=spf1 a:example.net -all"},{"SPF":""}],"ctrl.example.com":[{"SPF":"v=spf1 a:ctrl.example.com\rptr -all"},{"A":"192.0.2.3"}],"fine.example.com":[{"SPF":"v=spf1 a  -all"}],"trail.example.com":[{"SPF":"v=spf1 a -all "}]}, failOnNoFake: true, helo: "A2345678"}
        let promise = spf.check_host('1.2.3.5', emailSplit[1], email, opts);
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
        let opts = {fakeDNSData: {"example.com":["TIMEOUT"],"example.net":[{"SPF":"v=spf1 -all exp=exp.example.net"}],"a.example.net":[{"SPF":"v=spf1 -all exp=exp.example.net"}],"exp.example.net":[{"TXT":"%{l}"}],"a12345678901234567890123456789012345678901234567890123456789012.example.com":[{"SPF":"v=spf1 -all"}],"hosed.example.com":[{"SPF":"v=spf1 a:ï»¿garbage.example.net -all"}],"hosed2.example.com":[{"SPF":"v=spf1 a:example.net -all"}],"hosed3.example.com":[{"SPF":"v=spf1 a:example.net all"}],"nothosed.example.com":[{"SPF":"v=spf1 a:example.net -all"},{"SPF":""}],"ctrl.example.com":[{"SPF":"v=spf1 a:ctrl.example.com\rptr -all"},{"A":"192.0.2.3"}],"fine.example.com":[{"SPF":"v=spf1 a  -all"}],"trail.example.com":[{"SPF":"v=spf1 a -all "}]}, failOnNoFake: true, helo: "[1.2.3.5]"}
        let promise = spf.check_host('1.2.3.5', emailSplit[1], email, opts);
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
        let opts = {fakeDNSData: {"example.com":["TIMEOUT"],"example.net":[{"SPF":"v=spf1 -all exp=exp.example.net"}],"a.example.net":[{"SPF":"v=spf1 -all exp=exp.example.net"}],"exp.example.net":[{"TXT":"%{l}"}],"a12345678901234567890123456789012345678901234567890123456789012.example.com":[{"SPF":"v=spf1 -all"}],"hosed.example.com":[{"SPF":"v=spf1 a:ï»¿garbage.example.net -all"}],"hosed2.example.com":[{"SPF":"v=spf1 a:example.net -all"}],"hosed3.example.com":[{"SPF":"v=spf1 a:example.net all"}],"nothosed.example.com":[{"SPF":"v=spf1 a:example.net -all"},{"SPF":""}],"ctrl.example.com":[{"SPF":"v=spf1 a:ctrl.example.com\rptr -all"},{"A":"192.0.2.3"}],"fine.example.com":[{"SPF":"v=spf1 a  -all"}],"trail.example.com":[{"SPF":"v=spf1 a -all "}]}, failOnNoFake: true, helo: "mail.example.net"}
        let promise = spf.check_host('1.2.3.4', emailSplit[1], email, opts);
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
        let opts = {fakeDNSData: {"example.com":["TIMEOUT"],"example.net":[{"SPF":"v=spf1 -all exp=exp.example.net"}],"a.example.net":[{"SPF":"v=spf1 -all exp=exp.example.net"}],"exp.example.net":[{"TXT":"%{l}"}],"a12345678901234567890123456789012345678901234567890123456789012.example.com":[{"SPF":"v=spf1 -all"}],"hosed.example.com":[{"SPF":"v=spf1 a:ï»¿garbage.example.net -all"}],"hosed2.example.com":[{"SPF":"v=spf1 a:example.net -all"}],"hosed3.example.com":[{"SPF":"v=spf1 a:example.net all"}],"nothosed.example.com":[{"SPF":"v=spf1 a:example.net -all"},{"SPF":""}],"ctrl.example.com":[{"SPF":"v=spf1 a:ctrl.example.com\rptr -all"},{"A":"192.0.2.3"}],"fine.example.com":[{"SPF":"v=spf1 a  -all"}],"trail.example.com":[{"SPF":"v=spf1 a -all "}]}, failOnNoFake: true, helo: "OEMCOMPUTER"}
        let promise = spf.check_host('1.2.3.5', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'NONE');
        });
      });
      it('non-ascii-policy', function(){
        let email = 'foobar@hosed.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"example.com":["TIMEOUT"],"example.net":[{"SPF":"v=spf1 -all exp=exp.example.net"}],"a.example.net":[{"SPF":"v=spf1 -all exp=exp.example.net"}],"exp.example.net":[{"TXT":"%{l}"}],"a12345678901234567890123456789012345678901234567890123456789012.example.com":[{"SPF":"v=spf1 -all"}],"hosed.example.com":[{"SPF":"v=spf1 a:ï»¿garbage.example.net -all"}],"hosed2.example.com":[{"SPF":"v=spf1 a:example.net -all"}],"hosed3.example.com":[{"SPF":"v=spf1 a:example.net all"}],"nothosed.example.com":[{"SPF":"v=spf1 a:example.net -all"},{"SPF":""}],"ctrl.example.com":[{"SPF":"v=spf1 a:ctrl.example.com\rptr -all"},{"A":"192.0.2.3"}],"fine.example.com":[{"SPF":"v=spf1 a  -all"}],"trail.example.com":[{"SPF":"v=spf1 a -all "}]}, failOnNoFake: true, helo: "hosed"}
        let promise = spf.check_host('1.2.3.4', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'PERMERROR');
        });
      });
      it('non-ascii-mech', function(){
        let email = 'foobar@hosed2.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"example.com":["TIMEOUT"],"example.net":[{"SPF":"v=spf1 -all exp=exp.example.net"}],"a.example.net":[{"SPF":"v=spf1 -all exp=exp.example.net"}],"exp.example.net":[{"TXT":"%{l}"}],"a12345678901234567890123456789012345678901234567890123456789012.example.com":[{"SPF":"v=spf1 -all"}],"hosed.example.com":[{"SPF":"v=spf1 a:ï»¿garbage.example.net -all"}],"hosed2.example.com":[{"SPF":"v=spf1 a:example.net -all"}],"hosed3.example.com":[{"SPF":"v=spf1 a:example.net all"}],"nothosed.example.com":[{"SPF":"v=spf1 a:example.net -all"},{"SPF":""}],"ctrl.example.com":[{"SPF":"v=spf1 a:ctrl.example.com\rptr -all"},{"A":"192.0.2.3"}],"fine.example.com":[{"SPF":"v=spf1 a  -all"}],"trail.example.com":[{"SPF":"v=spf1 a -all "}]}, failOnNoFake: true, helo: "hosed"}
        let promise = spf.check_host('1.2.3.4', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'PERMERROR');
        });
      });
      it('non-ascii-result', function(){
        let email = 'foobar@hosed3.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"example.com":["TIMEOUT"],"example.net":[{"SPF":"v=spf1 -all exp=exp.example.net"}],"a.example.net":[{"SPF":"v=spf1 -all exp=exp.example.net"}],"exp.example.net":[{"TXT":"%{l}"}],"a12345678901234567890123456789012345678901234567890123456789012.example.com":[{"SPF":"v=spf1 -all"}],"hosed.example.com":[{"SPF":"v=spf1 a:ï»¿garbage.example.net -all"}],"hosed2.example.com":[{"SPF":"v=spf1 a:example.net -all"}],"hosed3.example.com":[{"SPF":"v=spf1 a:example.net all"}],"nothosed.example.com":[{"SPF":"v=spf1 a:example.net -all"},{"SPF":""}],"ctrl.example.com":[{"SPF":"v=spf1 a:ctrl.example.com\rptr -all"},{"A":"192.0.2.3"}],"fine.example.com":[{"SPF":"v=spf1 a  -all"}],"trail.example.com":[{"SPF":"v=spf1 a -all "}]}, failOnNoFake: true, helo: "hosed"}
        let promise = spf.check_host('1.2.3.4', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'PERMERROR');
        });
      });
      it('non-ascii-non-spf', function(){
        let email = 'foobar@nothosed.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"example.com":["TIMEOUT"],"example.net":[{"SPF":"v=spf1 -all exp=exp.example.net"}],"a.example.net":[{"SPF":"v=spf1 -all exp=exp.example.net"}],"exp.example.net":[{"TXT":"%{l}"}],"a12345678901234567890123456789012345678901234567890123456789012.example.com":[{"SPF":"v=spf1 -all"}],"hosed.example.com":[{"SPF":"v=spf1 a:ï»¿garbage.example.net -all"}],"hosed2.example.com":[{"SPF":"v=spf1 a:example.net -all"}],"hosed3.example.com":[{"SPF":"v=spf1 a:example.net all"}],"nothosed.example.com":[{"SPF":"v=spf1 a:example.net -all"},{"SPF":""}],"ctrl.example.com":[{"SPF":"v=spf1 a:ctrl.example.com\rptr -all"},{"A":"192.0.2.3"}],"fine.example.com":[{"SPF":"v=spf1 a  -all"}],"trail.example.com":[{"SPF":"v=spf1 a -all "}]}, failOnNoFake: true, helo: "hosed"}
        let promise = spf.check_host('1.2.3.4', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'FAIL');
        });
      });
      it('control-char-policy', function(){
        let email = 'foobar@ctrl.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"example.com":["TIMEOUT"],"example.net":[{"SPF":"v=spf1 -all exp=exp.example.net"}],"a.example.net":[{"SPF":"v=spf1 -all exp=exp.example.net"}],"exp.example.net":[{"TXT":"%{l}"}],"a12345678901234567890123456789012345678901234567890123456789012.example.com":[{"SPF":"v=spf1 -all"}],"hosed.example.com":[{"SPF":"v=spf1 a:ï»¿garbage.example.net -all"}],"hosed2.example.com":[{"SPF":"v=spf1 a:example.net -all"}],"hosed3.example.com":[{"SPF":"v=spf1 a:example.net all"}],"nothosed.example.com":[{"SPF":"v=spf1 a:example.net -all"},{"SPF":""}],"ctrl.example.com":[{"SPF":"v=spf1 a:ctrl.example.com\rptr -all"},{"A":"192.0.2.3"}],"fine.example.com":[{"SPF":"v=spf1 a  -all"}],"trail.example.com":[{"SPF":"v=spf1 a -all "}]}, failOnNoFake: true, helo: "hosed"}
        let promise = spf.check_host('192.0.2.3', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'PERMERROR');
        });
      });
      it('two-spaces', function(){
        let email = 'actually@fine.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"example.com":["TIMEOUT"],"example.net":[{"SPF":"v=spf1 -all exp=exp.example.net"}],"a.example.net":[{"SPF":"v=spf1 -all exp=exp.example.net"}],"exp.example.net":[{"TXT":"%{l}"}],"a12345678901234567890123456789012345678901234567890123456789012.example.com":[{"SPF":"v=spf1 -all"}],"hosed.example.com":[{"SPF":"v=spf1 a:ï»¿garbage.example.net -all"}],"hosed2.example.com":[{"SPF":"v=spf1 a:example.net -all"}],"hosed3.example.com":[{"SPF":"v=spf1 a:example.net all"}],"nothosed.example.com":[{"SPF":"v=spf1 a:example.net -all"},{"SPF":""}],"ctrl.example.com":[{"SPF":"v=spf1 a:ctrl.example.com\rptr -all"},{"A":"192.0.2.3"}],"fine.example.com":[{"SPF":"v=spf1 a  -all"}],"trail.example.com":[{"SPF":"v=spf1 a -all "}]}, failOnNoFake: true, helo: "hosed"}
        let promise = spf.check_host('1.2.3.4', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'FAIL');
        });
      });
      it('trailing-space', function(){
        let email = 'silly@trail.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"example.com":["TIMEOUT"],"example.net":[{"SPF":"v=spf1 -all exp=exp.example.net"}],"a.example.net":[{"SPF":"v=spf1 -all exp=exp.example.net"}],"exp.example.net":[{"TXT":"%{l}"}],"a12345678901234567890123456789012345678901234567890123456789012.example.com":[{"SPF":"v=spf1 -all"}],"hosed.example.com":[{"SPF":"v=spf1 a:ï»¿garbage.example.net -all"}],"hosed2.example.com":[{"SPF":"v=spf1 a:example.net -all"}],"hosed3.example.com":[{"SPF":"v=spf1 a:example.net all"}],"nothosed.example.com":[{"SPF":"v=spf1 a:example.net -all"},{"SPF":""}],"ctrl.example.com":[{"SPF":"v=spf1 a:ctrl.example.com\rptr -all"},{"A":"192.0.2.3"}],"fine.example.com":[{"SPF":"v=spf1 a  -all"}],"trail.example.com":[{"SPF":"v=spf1 a -all "}]}, failOnNoFake: true, helo: "hosed"}
        let promise = spf.check_host('192.0.2.5', emailSplit[1], email, opts);
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
        let opts = {fakeDNSData: {"both.example.net":[{"TXT":"v=spf1 -all"},{"SPF":"v=spf1 -all"}],"txtonly.example.net":[{"TXT":"v=spf1 -all"}],"spfonly.example.net":[{"SPF":"v=spf1 -all"},{"TXT":"NONE"}],"spftimeout.example.net":[{"TXT":"v=spf1 -all"},"TIMEOUT"],"txttimeout.example.net":[{"SPF":"v=spf1 -all"},{"TXT":"NONE"},"TIMEOUT"],"nospftxttimeout.example.net":[{"SPF":"v=spf3 !a:yahoo.com -all"},{"TXT":"NONE"},"TIMEOUT"],"alltimeout.example.net":["TIMEOUT"]}, failOnNoFake: true, helo: "mail.example.net"}
        let promise = spf.check_host('1.2.3.4', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'FAIL');
        });
      });
      it('txtonly', function(){
        let email = 'foo@txtonly.example.net';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"both.example.net":[{"TXT":"v=spf1 -all"},{"SPF":"v=spf1 -all"}],"txtonly.example.net":[{"TXT":"v=spf1 -all"}],"spfonly.example.net":[{"SPF":"v=spf1 -all"},{"TXT":"NONE"}],"spftimeout.example.net":[{"TXT":"v=spf1 -all"},"TIMEOUT"],"txttimeout.example.net":[{"SPF":"v=spf1 -all"},{"TXT":"NONE"},"TIMEOUT"],"nospftxttimeout.example.net":[{"SPF":"v=spf3 !a:yahoo.com -all"},{"TXT":"NONE"},"TIMEOUT"],"alltimeout.example.net":["TIMEOUT"]}, failOnNoFake: true, helo: "mail.example.net"}
        let promise = spf.check_host('1.2.3.4', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'FAIL');
        });
      });
      it('spfonly', function(){
        let email = 'foo@spfonly.example.net';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"both.example.net":[{"TXT":"v=spf1 -all"},{"SPF":"v=spf1 -all"}],"txtonly.example.net":[{"TXT":"v=spf1 -all"}],"spfonly.example.net":[{"SPF":"v=spf1 -all"},{"TXT":"NONE"}],"spftimeout.example.net":[{"TXT":"v=spf1 -all"},"TIMEOUT"],"txttimeout.example.net":[{"SPF":"v=spf1 -all"},{"TXT":"NONE"},"TIMEOUT"],"nospftxttimeout.example.net":[{"SPF":"v=spf3 !a:yahoo.com -all"},{"TXT":"NONE"},"TIMEOUT"],"alltimeout.example.net":["TIMEOUT"]}, failOnNoFake: true, helo: "mail.example.net"}
        let promise = spf.check_host('1.2.3.4', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'NONE');
        });
      });
      it('spftimeout', function(){
        let email = 'foo@spftimeout.example.net';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"both.example.net":[{"TXT":"v=spf1 -all"},{"SPF":"v=spf1 -all"}],"txtonly.example.net":[{"TXT":"v=spf1 -all"}],"spfonly.example.net":[{"SPF":"v=spf1 -all"},{"TXT":"NONE"}],"spftimeout.example.net":[{"TXT":"v=spf1 -all"},"TIMEOUT"],"txttimeout.example.net":[{"SPF":"v=spf1 -all"},{"TXT":"NONE"},"TIMEOUT"],"nospftxttimeout.example.net":[{"SPF":"v=spf3 !a:yahoo.com -all"},{"TXT":"NONE"},"TIMEOUT"],"alltimeout.example.net":["TIMEOUT"]}, failOnNoFake: true, helo: "mail.example.net"}
        let promise = spf.check_host('1.2.3.4', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'FAIL');
        });
      });
      it('txttimeout', function(){
        let email = 'foo@txttimeout.example.net';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"both.example.net":[{"TXT":"v=spf1 -all"},{"SPF":"v=spf1 -all"}],"txtonly.example.net":[{"TXT":"v=spf1 -all"}],"spfonly.example.net":[{"SPF":"v=spf1 -all"},{"TXT":"NONE"}],"spftimeout.example.net":[{"TXT":"v=spf1 -all"},"TIMEOUT"],"txttimeout.example.net":[{"SPF":"v=spf1 -all"},{"TXT":"NONE"},"TIMEOUT"],"nospftxttimeout.example.net":[{"SPF":"v=spf3 !a:yahoo.com -all"},{"TXT":"NONE"},"TIMEOUT"],"alltimeout.example.net":["TIMEOUT"]}, failOnNoFake: true, helo: "mail.example.net"}
        let promise = spf.check_host('1.2.3.4', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'TEMPERROR');
        });
      });
      it('nospftxttimeout', function(){
        let email = 'foo@nospftxttimeout.example.net';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"both.example.net":[{"TXT":"v=spf1 -all"},{"SPF":"v=spf1 -all"}],"txtonly.example.net":[{"TXT":"v=spf1 -all"}],"spfonly.example.net":[{"SPF":"v=spf1 -all"},{"TXT":"NONE"}],"spftimeout.example.net":[{"TXT":"v=spf1 -all"},"TIMEOUT"],"txttimeout.example.net":[{"SPF":"v=spf1 -all"},{"TXT":"NONE"},"TIMEOUT"],"nospftxttimeout.example.net":[{"SPF":"v=spf3 !a:yahoo.com -all"},{"TXT":"NONE"},"TIMEOUT"],"alltimeout.example.net":["TIMEOUT"]}, failOnNoFake: true, helo: "mail.example.net"}
        let promise = spf.check_host('1.2.3.4', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'TEMPERROR');
        });
      });
      it('alltimeout', function(){
        let email = 'foo@alltimeout.example.net';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"both.example.net":[{"TXT":"v=spf1 -all"},{"SPF":"v=spf1 -all"}],"txtonly.example.net":[{"TXT":"v=spf1 -all"}],"spfonly.example.net":[{"SPF":"v=spf1 -all"},{"TXT":"NONE"}],"spftimeout.example.net":[{"TXT":"v=spf1 -all"},"TIMEOUT"],"txttimeout.example.net":[{"SPF":"v=spf1 -all"},{"TXT":"NONE"},"TIMEOUT"],"nospftxttimeout.example.net":[{"SPF":"v=spf3 !a:yahoo.com -all"},{"TXT":"NONE"},"TIMEOUT"],"alltimeout.example.net":["TIMEOUT"]}, failOnNoFake: true, helo: "mail.example.net"}
        let promise = spf.check_host('1.2.3.4', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'TEMPERROR');
        });
      });
    });
    describe('Selecting records', function(){
      it('nospace1', function(){
        let email = 'foo@example2.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"example3.com":[{"SPF":"v=spf10"},{"SPF":"v=spf1 mx"},{"MX":[0,"mail.example1.com"]}],"example1.com":[{"SPF":"v=spf1"}],"example2.com":[{"SPF":["v=spf1","mx"]}],"mail.example1.com":[{"A":"1.2.3.4"}],"example4.com":[{"SPF":"v=spf1 +all"},{"TXT":"v=spf1 -all"}],"example5.com":[{"SPF":"v=spf1 +all"},{"TXT":"v=spf1 -all"},{"TXT":"v=spf1 +all"}],"example6.com":[{"SPF":"v=spf1 -all"},{"SPF":"V=sPf1 +all"}],"example7.com":[{"SPF":"v=spf1 -all"},{"SPF":"v=spf1 -all"}],"example8.com":[{"SPF":"V=spf1 -all"},{"SPF":"v=spf1 -all"},{"TXT":"v=spf1 +all"}],"example9.com":[{"SPF":"v=SpF1 ~all"}]}, failOnNoFake: true, helo: "mail.example1.com"}
        let promise = spf.check_host('1.2.3.4', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'NONE');
        });
      });
      it('empty', function(){
        let email = 'foo@example1.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"example3.com":[{"SPF":"v=spf10"},{"SPF":"v=spf1 mx"},{"MX":[0,"mail.example1.com"]}],"example1.com":[{"SPF":"v=spf1"}],"example2.com":[{"SPF":["v=spf1","mx"]}],"mail.example1.com":[{"A":"1.2.3.4"}],"example4.com":[{"SPF":"v=spf1 +all"},{"TXT":"v=spf1 -all"}],"example5.com":[{"SPF":"v=spf1 +all"},{"TXT":"v=spf1 -all"},{"TXT":"v=spf1 +all"}],"example6.com":[{"SPF":"v=spf1 -all"},{"SPF":"V=sPf1 +all"}],"example7.com":[{"SPF":"v=spf1 -all"},{"SPF":"v=spf1 -all"}],"example8.com":[{"SPF":"V=spf1 -all"},{"SPF":"v=spf1 -all"},{"TXT":"v=spf1 +all"}],"example9.com":[{"SPF":"v=SpF1 ~all"}]}, failOnNoFake: true, helo: "mail1.example1.com"}
        let promise = spf.check_host('1.2.3.4', emailSplit[1], email, opts);
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
        let opts = {fakeDNSData: {"example3.com":[{"SPF":"v=spf10"},{"SPF":"v=spf1 mx"},{"MX":[0,"mail.example1.com"]}],"example1.com":[{"SPF":"v=spf1"}],"example2.com":[{"SPF":["v=spf1","mx"]}],"mail.example1.com":[{"A":"1.2.3.4"}],"example4.com":[{"SPF":"v=spf1 +all"},{"TXT":"v=spf1 -all"}],"example5.com":[{"SPF":"v=spf1 +all"},{"TXT":"v=spf1 -all"},{"TXT":"v=spf1 +all"}],"example6.com":[{"SPF":"v=spf1 -all"},{"SPF":"V=sPf1 +all"}],"example7.com":[{"SPF":"v=spf1 -all"},{"SPF":"v=spf1 -all"}],"example8.com":[{"SPF":"V=spf1 -all"},{"SPF":"v=spf1 -all"},{"TXT":"v=spf1 +all"}],"example9.com":[{"SPF":"v=SpF1 ~all"}]}, failOnNoFake: true, helo: "mail.example1.com"}
        let promise = spf.check_host('1.2.3.4', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'PASS');
        });
      });
      it('spfoverride', function(){
        let email = 'foo@example4.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"example3.com":[{"SPF":"v=spf10"},{"SPF":"v=spf1 mx"},{"MX":[0,"mail.example1.com"]}],"example1.com":[{"SPF":"v=spf1"}],"example2.com":[{"SPF":["v=spf1","mx"]}],"mail.example1.com":[{"A":"1.2.3.4"}],"example4.com":[{"SPF":"v=spf1 +all"},{"TXT":"v=spf1 -all"}],"example5.com":[{"SPF":"v=spf1 +all"},{"TXT":"v=spf1 -all"},{"TXT":"v=spf1 +all"}],"example6.com":[{"SPF":"v=spf1 -all"},{"SPF":"V=sPf1 +all"}],"example7.com":[{"SPF":"v=spf1 -all"},{"SPF":"v=spf1 -all"}],"example8.com":[{"SPF":"V=spf1 -all"},{"SPF":"v=spf1 -all"},{"TXT":"v=spf1 +all"}],"example9.com":[{"SPF":"v=SpF1 ~all"}]}, failOnNoFake: true, helo: "mail.example1.com"}
        let promise = spf.check_host('1.2.3.4', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'FAIL');
        });
      });
      it('multitxt1', function(){
        let email = 'foo@example5.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"example3.com":[{"SPF":"v=spf10"},{"SPF":"v=spf1 mx"},{"MX":[0,"mail.example1.com"]}],"example1.com":[{"SPF":"v=spf1"}],"example2.com":[{"SPF":["v=spf1","mx"]}],"mail.example1.com":[{"A":"1.2.3.4"}],"example4.com":[{"SPF":"v=spf1 +all"},{"TXT":"v=spf1 -all"}],"example5.com":[{"SPF":"v=spf1 +all"},{"TXT":"v=spf1 -all"},{"TXT":"v=spf1 +all"}],"example6.com":[{"SPF":"v=spf1 -all"},{"SPF":"V=sPf1 +all"}],"example7.com":[{"SPF":"v=spf1 -all"},{"SPF":"v=spf1 -all"}],"example8.com":[{"SPF":"V=spf1 -all"},{"SPF":"v=spf1 -all"},{"TXT":"v=spf1 +all"}],"example9.com":[{"SPF":"v=SpF1 ~all"}]}, failOnNoFake: true, helo: "mail.example1.com"}
        let promise = spf.check_host('1.2.3.4', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'PERMERROR');
        });
      });
      it('multitxt2', function(){
        let email = 'foo@example6.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"example3.com":[{"SPF":"v=spf10"},{"SPF":"v=spf1 mx"},{"MX":[0,"mail.example1.com"]}],"example1.com":[{"SPF":"v=spf1"}],"example2.com":[{"SPF":["v=spf1","mx"]}],"mail.example1.com":[{"A":"1.2.3.4"}],"example4.com":[{"SPF":"v=spf1 +all"},{"TXT":"v=spf1 -all"}],"example5.com":[{"SPF":"v=spf1 +all"},{"TXT":"v=spf1 -all"},{"TXT":"v=spf1 +all"}],"example6.com":[{"SPF":"v=spf1 -all"},{"SPF":"V=sPf1 +all"}],"example7.com":[{"SPF":"v=spf1 -all"},{"SPF":"v=spf1 -all"}],"example8.com":[{"SPF":"V=spf1 -all"},{"SPF":"v=spf1 -all"},{"TXT":"v=spf1 +all"}],"example9.com":[{"SPF":"v=SpF1 ~all"}]}, failOnNoFake: true, helo: "mail.example1.com"}
        let promise = spf.check_host('1.2.3.4', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'PERMERROR');
        });
      });
      it('multispf1', function(){
        let email = 'foo@example7.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"example3.com":[{"SPF":"v=spf10"},{"SPF":"v=spf1 mx"},{"MX":[0,"mail.example1.com"]}],"example1.com":[{"SPF":"v=spf1"}],"example2.com":[{"SPF":["v=spf1","mx"]}],"mail.example1.com":[{"A":"1.2.3.4"}],"example4.com":[{"SPF":"v=spf1 +all"},{"TXT":"v=spf1 -all"}],"example5.com":[{"SPF":"v=spf1 +all"},{"TXT":"v=spf1 -all"},{"TXT":"v=spf1 +all"}],"example6.com":[{"SPF":"v=spf1 -all"},{"SPF":"V=sPf1 +all"}],"example7.com":[{"SPF":"v=spf1 -all"},{"SPF":"v=spf1 -all"}],"example8.com":[{"SPF":"V=spf1 -all"},{"SPF":"v=spf1 -all"},{"TXT":"v=spf1 +all"}],"example9.com":[{"SPF":"v=SpF1 ~all"}]}, failOnNoFake: true, helo: "mail.example1.com"}
        let promise = spf.check_host('1.2.3.4', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.include(["permerror","fail"], result.toLowerCase());
        });
      });
      it('multispf2', function(){
        let email = 'foo@example8.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"example3.com":[{"SPF":"v=spf10"},{"SPF":"v=spf1 mx"},{"MX":[0,"mail.example1.com"]}],"example1.com":[{"SPF":"v=spf1"}],"example2.com":[{"SPF":["v=spf1","mx"]}],"mail.example1.com":[{"A":"1.2.3.4"}],"example4.com":[{"SPF":"v=spf1 +all"},{"TXT":"v=spf1 -all"}],"example5.com":[{"SPF":"v=spf1 +all"},{"TXT":"v=spf1 -all"},{"TXT":"v=spf1 +all"}],"example6.com":[{"SPF":"v=spf1 -all"},{"SPF":"V=sPf1 +all"}],"example7.com":[{"SPF":"v=spf1 -all"},{"SPF":"v=spf1 -all"}],"example8.com":[{"SPF":"V=spf1 -all"},{"SPF":"v=spf1 -all"},{"TXT":"v=spf1 +all"}],"example9.com":[{"SPF":"v=SpF1 ~all"}]}, failOnNoFake: true, helo: "mail.example1.com"}
        let promise = spf.check_host('1.2.3.4', emailSplit[1], email, opts);
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
        let opts = {fakeDNSData: {"example3.com":[{"SPF":"v=spf10"},{"SPF":"v=spf1 mx"},{"MX":[0,"mail.example1.com"]}],"example1.com":[{"SPF":"v=spf1"}],"example2.com":[{"SPF":["v=spf1","mx"]}],"mail.example1.com":[{"A":"1.2.3.4"}],"example4.com":[{"SPF":"v=spf1 +all"},{"TXT":"v=spf1 -all"}],"example5.com":[{"SPF":"v=spf1 +all"},{"TXT":"v=spf1 -all"},{"TXT":"v=spf1 +all"}],"example6.com":[{"SPF":"v=spf1 -all"},{"SPF":"V=sPf1 +all"}],"example7.com":[{"SPF":"v=spf1 -all"},{"SPF":"v=spf1 -all"}],"example8.com":[{"SPF":"V=spf1 -all"},{"SPF":"v=spf1 -all"},{"TXT":"v=spf1 +all"}],"example9.com":[{"SPF":"v=SpF1 ~all"}]}, failOnNoFake: true, helo: "mail.example1.com"}
        let promise = spf.check_host('1.2.3.4', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'NONE');
        });
      });
      it('case-insensitive', function(){
        let email = 'foo@example9.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"example3.com":[{"SPF":"v=spf10"},{"SPF":"v=spf1 mx"},{"MX":[0,"mail.example1.com"]}],"example1.com":[{"SPF":"v=spf1"}],"example2.com":[{"SPF":["v=spf1","mx"]}],"mail.example1.com":[{"A":"1.2.3.4"}],"example4.com":[{"SPF":"v=spf1 +all"},{"TXT":"v=spf1 -all"}],"example5.com":[{"SPF":"v=spf1 +all"},{"TXT":"v=spf1 -all"},{"TXT":"v=spf1 +all"}],"example6.com":[{"SPF":"v=spf1 -all"},{"SPF":"V=sPf1 +all"}],"example7.com":[{"SPF":"v=spf1 -all"},{"SPF":"v=spf1 -all"}],"example8.com":[{"SPF":"V=spf1 -all"},{"SPF":"v=spf1 -all"},{"TXT":"v=spf1 +all"}],"example9.com":[{"SPF":"v=SpF1 ~all"}]}, failOnNoFake: true, helo: "mail.example1.com"}
        let promise = spf.check_host('1.2.3.4', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'SOFTFAIL');
        });
      });
    });
    describe('Record evaluation', function(){
      it('detect-errors-anywhere', function(){
        let email = 'foo@t1.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"t1.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4 -all moo"}],"t2.example.com":[{"SPF":"v=spf1 moo.cow-far_out=man:dog/cat ip4:1.2.3.4 -all"}],"t3.example.com":[{"SPF":"v=spf1 moo.cow/far_out=man:dog/cat ip4:1.2.3.4 -all"}],"t4.example.com":[{"SPF":"v=spf1 moo.cow:far_out=man:dog/cat ip4:1.2.3.4 -all"}],"t5.example.com":[{"SPF":"v=spf1 redirect=t5.example.com ~all"}],"t6.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4 redirect=t2.example.com"}],"t7.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4"}],"t8.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4 redirect:t2.example.com"}],"t9.example.com":[{"SPF":"v=spf1 a:foo-bar -all"}],"t10.example.com":[{"SPF":"v=spf1 a:mail.example...com -all"}],"t11.example.com":[{"SPF":"v=spf1 a:a123456789012345678901234567890123456789012345678901234567890123.example.com -all"}],"t12.example.com":[{"SPF":"v=spf1 a:%{H}.bar -all"}]}, failOnNoFake: true, helo: "mail.example.com"}
        let promise = spf.check_host('1.2.3.4', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'PERMERROR');
        });
      });
      it('modifier-charset-good', function(){
        let email = 'foo@t2.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"t1.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4 -all moo"}],"t2.example.com":[{"SPF":"v=spf1 moo.cow-far_out=man:dog/cat ip4:1.2.3.4 -all"}],"t3.example.com":[{"SPF":"v=spf1 moo.cow/far_out=man:dog/cat ip4:1.2.3.4 -all"}],"t4.example.com":[{"SPF":"v=spf1 moo.cow:far_out=man:dog/cat ip4:1.2.3.4 -all"}],"t5.example.com":[{"SPF":"v=spf1 redirect=t5.example.com ~all"}],"t6.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4 redirect=t2.example.com"}],"t7.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4"}],"t8.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4 redirect:t2.example.com"}],"t9.example.com":[{"SPF":"v=spf1 a:foo-bar -all"}],"t10.example.com":[{"SPF":"v=spf1 a:mail.example...com -all"}],"t11.example.com":[{"SPF":"v=spf1 a:a123456789012345678901234567890123456789012345678901234567890123.example.com -all"}],"t12.example.com":[{"SPF":"v=spf1 a:%{H}.bar -all"}]}, failOnNoFake: true, helo: "mail.example.com"}
        let promise = spf.check_host('1.2.3.4', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'PASS');
        });
      });
      it('modifier-charset-bad1', function(){
        let email = 'foo@t3.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"t1.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4 -all moo"}],"t2.example.com":[{"SPF":"v=spf1 moo.cow-far_out=man:dog/cat ip4:1.2.3.4 -all"}],"t3.example.com":[{"SPF":"v=spf1 moo.cow/far_out=man:dog/cat ip4:1.2.3.4 -all"}],"t4.example.com":[{"SPF":"v=spf1 moo.cow:far_out=man:dog/cat ip4:1.2.3.4 -all"}],"t5.example.com":[{"SPF":"v=spf1 redirect=t5.example.com ~all"}],"t6.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4 redirect=t2.example.com"}],"t7.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4"}],"t8.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4 redirect:t2.example.com"}],"t9.example.com":[{"SPF":"v=spf1 a:foo-bar -all"}],"t10.example.com":[{"SPF":"v=spf1 a:mail.example...com -all"}],"t11.example.com":[{"SPF":"v=spf1 a:a123456789012345678901234567890123456789012345678901234567890123.example.com -all"}],"t12.example.com":[{"SPF":"v=spf1 a:%{H}.bar -all"}]}, failOnNoFake: true, helo: "mail.example.com"}
        let promise = spf.check_host('1.2.3.4', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'PERMERROR');
        });
      });
      it('modifier-charset-bad2', function(){
        let email = 'foo@t4.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"t1.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4 -all moo"}],"t2.example.com":[{"SPF":"v=spf1 moo.cow-far_out=man:dog/cat ip4:1.2.3.4 -all"}],"t3.example.com":[{"SPF":"v=spf1 moo.cow/far_out=man:dog/cat ip4:1.2.3.4 -all"}],"t4.example.com":[{"SPF":"v=spf1 moo.cow:far_out=man:dog/cat ip4:1.2.3.4 -all"}],"t5.example.com":[{"SPF":"v=spf1 redirect=t5.example.com ~all"}],"t6.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4 redirect=t2.example.com"}],"t7.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4"}],"t8.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4 redirect:t2.example.com"}],"t9.example.com":[{"SPF":"v=spf1 a:foo-bar -all"}],"t10.example.com":[{"SPF":"v=spf1 a:mail.example...com -all"}],"t11.example.com":[{"SPF":"v=spf1 a:a123456789012345678901234567890123456789012345678901234567890123.example.com -all"}],"t12.example.com":[{"SPF":"v=spf1 a:%{H}.bar -all"}]}, failOnNoFake: true, helo: "mail.example.com"}
        let promise = spf.check_host('1.2.3.4', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'PERMERROR');
        });
      });
      it('redirect-after-mechanisms1', function(){
        let email = 'foo@t5.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"t1.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4 -all moo"}],"t2.example.com":[{"SPF":"v=spf1 moo.cow-far_out=man:dog/cat ip4:1.2.3.4 -all"}],"t3.example.com":[{"SPF":"v=spf1 moo.cow/far_out=man:dog/cat ip4:1.2.3.4 -all"}],"t4.example.com":[{"SPF":"v=spf1 moo.cow:far_out=man:dog/cat ip4:1.2.3.4 -all"}],"t5.example.com":[{"SPF":"v=spf1 redirect=t5.example.com ~all"}],"t6.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4 redirect=t2.example.com"}],"t7.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4"}],"t8.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4 redirect:t2.example.com"}],"t9.example.com":[{"SPF":"v=spf1 a:foo-bar -all"}],"t10.example.com":[{"SPF":"v=spf1 a:mail.example...com -all"}],"t11.example.com":[{"SPF":"v=spf1 a:a123456789012345678901234567890123456789012345678901234567890123.example.com -all"}],"t12.example.com":[{"SPF":"v=spf1 a:%{H}.bar -all"}]}, failOnNoFake: true, helo: "mail.example.com"}
        let promise = spf.check_host('1.2.3.4', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'SOFTFAIL');
        });
      });
      it('redirect-after-mechanisms2', function(){
        let email = 'foo@t6.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"t1.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4 -all moo"}],"t2.example.com":[{"SPF":"v=spf1 moo.cow-far_out=man:dog/cat ip4:1.2.3.4 -all"}],"t3.example.com":[{"SPF":"v=spf1 moo.cow/far_out=man:dog/cat ip4:1.2.3.4 -all"}],"t4.example.com":[{"SPF":"v=spf1 moo.cow:far_out=man:dog/cat ip4:1.2.3.4 -all"}],"t5.example.com":[{"SPF":"v=spf1 redirect=t5.example.com ~all"}],"t6.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4 redirect=t2.example.com"}],"t7.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4"}],"t8.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4 redirect:t2.example.com"}],"t9.example.com":[{"SPF":"v=spf1 a:foo-bar -all"}],"t10.example.com":[{"SPF":"v=spf1 a:mail.example...com -all"}],"t11.example.com":[{"SPF":"v=spf1 a:a123456789012345678901234567890123456789012345678901234567890123.example.com -all"}],"t12.example.com":[{"SPF":"v=spf1 a:%{H}.bar -all"}]}, failOnNoFake: true, helo: "mail.example.com"}
        let promise = spf.check_host('1.2.3.5', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'FAIL');
        });
      });
      it('default-result', function(){
        let email = 'foo@t7.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"t1.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4 -all moo"}],"t2.example.com":[{"SPF":"v=spf1 moo.cow-far_out=man:dog/cat ip4:1.2.3.4 -all"}],"t3.example.com":[{"SPF":"v=spf1 moo.cow/far_out=man:dog/cat ip4:1.2.3.4 -all"}],"t4.example.com":[{"SPF":"v=spf1 moo.cow:far_out=man:dog/cat ip4:1.2.3.4 -all"}],"t5.example.com":[{"SPF":"v=spf1 redirect=t5.example.com ~all"}],"t6.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4 redirect=t2.example.com"}],"t7.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4"}],"t8.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4 redirect:t2.example.com"}],"t9.example.com":[{"SPF":"v=spf1 a:foo-bar -all"}],"t10.example.com":[{"SPF":"v=spf1 a:mail.example...com -all"}],"t11.example.com":[{"SPF":"v=spf1 a:a123456789012345678901234567890123456789012345678901234567890123.example.com -all"}],"t12.example.com":[{"SPF":"v=spf1 a:%{H}.bar -all"}]}, failOnNoFake: true, helo: "mail.example.com"}
        let promise = spf.check_host('1.2.3.5', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'NEUTRAL');
        });
      });
      it('redirect-is-modifier', function(){
        let email = 'foo@t8.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"t1.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4 -all moo"}],"t2.example.com":[{"SPF":"v=spf1 moo.cow-far_out=man:dog/cat ip4:1.2.3.4 -all"}],"t3.example.com":[{"SPF":"v=spf1 moo.cow/far_out=man:dog/cat ip4:1.2.3.4 -all"}],"t4.example.com":[{"SPF":"v=spf1 moo.cow:far_out=man:dog/cat ip4:1.2.3.4 -all"}],"t5.example.com":[{"SPF":"v=spf1 redirect=t5.example.com ~all"}],"t6.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4 redirect=t2.example.com"}],"t7.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4"}],"t8.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4 redirect:t2.example.com"}],"t9.example.com":[{"SPF":"v=spf1 a:foo-bar -all"}],"t10.example.com":[{"SPF":"v=spf1 a:mail.example...com -all"}],"t11.example.com":[{"SPF":"v=spf1 a:a123456789012345678901234567890123456789012345678901234567890123.example.com -all"}],"t12.example.com":[{"SPF":"v=spf1 a:%{H}.bar -all"}]}, failOnNoFake: true, helo: "mail.example.com"}
        let promise = spf.check_host('1.2.3.4', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'PERMERROR');
        });
      });
      it('invalid-domain', function(){
        let email = 'foo@t9.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"t1.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4 -all moo"}],"t2.example.com":[{"SPF":"v=spf1 moo.cow-far_out=man:dog/cat ip4:1.2.3.4 -all"}],"t3.example.com":[{"SPF":"v=spf1 moo.cow/far_out=man:dog/cat ip4:1.2.3.4 -all"}],"t4.example.com":[{"SPF":"v=spf1 moo.cow:far_out=man:dog/cat ip4:1.2.3.4 -all"}],"t5.example.com":[{"SPF":"v=spf1 redirect=t5.example.com ~all"}],"t6.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4 redirect=t2.example.com"}],"t7.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4"}],"t8.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4 redirect:t2.example.com"}],"t9.example.com":[{"SPF":"v=spf1 a:foo-bar -all"}],"t10.example.com":[{"SPF":"v=spf1 a:mail.example...com -all"}],"t11.example.com":[{"SPF":"v=spf1 a:a123456789012345678901234567890123456789012345678901234567890123.example.com -all"}],"t12.example.com":[{"SPF":"v=spf1 a:%{H}.bar -all"}]}, failOnNoFake: true, helo: "mail.example.com"}
        let promise = spf.check_host('1.2.3.4', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'PERMERROR');
        });
      });
      it('invalid-domain-empty-label', function(){
        let email = 'foo@t10.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"t1.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4 -all moo"}],"t2.example.com":[{"SPF":"v=spf1 moo.cow-far_out=man:dog/cat ip4:1.2.3.4 -all"}],"t3.example.com":[{"SPF":"v=spf1 moo.cow/far_out=man:dog/cat ip4:1.2.3.4 -all"}],"t4.example.com":[{"SPF":"v=spf1 moo.cow:far_out=man:dog/cat ip4:1.2.3.4 -all"}],"t5.example.com":[{"SPF":"v=spf1 redirect=t5.example.com ~all"}],"t6.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4 redirect=t2.example.com"}],"t7.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4"}],"t8.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4 redirect:t2.example.com"}],"t9.example.com":[{"SPF":"v=spf1 a:foo-bar -all"}],"t10.example.com":[{"SPF":"v=spf1 a:mail.example...com -all"}],"t11.example.com":[{"SPF":"v=spf1 a:a123456789012345678901234567890123456789012345678901234567890123.example.com -all"}],"t12.example.com":[{"SPF":"v=spf1 a:%{H}.bar -all"}]}, failOnNoFake: true, helo: "mail.example.com"}
        let promise = spf.check_host('1.2.3.4', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.include(["fail","permerror"], result.toLowerCase());
        });
      });
      it('invalid-domain-long', function(){
        let email = 'foo@t11.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"t1.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4 -all moo"}],"t2.example.com":[{"SPF":"v=spf1 moo.cow-far_out=man:dog/cat ip4:1.2.3.4 -all"}],"t3.example.com":[{"SPF":"v=spf1 moo.cow/far_out=man:dog/cat ip4:1.2.3.4 -all"}],"t4.example.com":[{"SPF":"v=spf1 moo.cow:far_out=man:dog/cat ip4:1.2.3.4 -all"}],"t5.example.com":[{"SPF":"v=spf1 redirect=t5.example.com ~all"}],"t6.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4 redirect=t2.example.com"}],"t7.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4"}],"t8.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4 redirect:t2.example.com"}],"t9.example.com":[{"SPF":"v=spf1 a:foo-bar -all"}],"t10.example.com":[{"SPF":"v=spf1 a:mail.example...com -all"}],"t11.example.com":[{"SPF":"v=spf1 a:a123456789012345678901234567890123456789012345678901234567890123.example.com -all"}],"t12.example.com":[{"SPF":"v=spf1 a:%{H}.bar -all"}]}, failOnNoFake: true, helo: "mail.example.com"}
        let promise = spf.check_host('1.2.3.4', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.include(["fail","permerror"], result.toLowerCase());
        });
      });
      it('invalid-domain-long-via-macro', function(){
        let email = 'foo@t12.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"t1.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4 -all moo"}],"t2.example.com":[{"SPF":"v=spf1 moo.cow-far_out=man:dog/cat ip4:1.2.3.4 -all"}],"t3.example.com":[{"SPF":"v=spf1 moo.cow/far_out=man:dog/cat ip4:1.2.3.4 -all"}],"t4.example.com":[{"SPF":"v=spf1 moo.cow:far_out=man:dog/cat ip4:1.2.3.4 -all"}],"t5.example.com":[{"SPF":"v=spf1 redirect=t5.example.com ~all"}],"t6.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4 redirect=t2.example.com"}],"t7.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4"}],"t8.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4 redirect:t2.example.com"}],"t9.example.com":[{"SPF":"v=spf1 a:foo-bar -all"}],"t10.example.com":[{"SPF":"v=spf1 a:mail.example...com -all"}],"t11.example.com":[{"SPF":"v=spf1 a:a123456789012345678901234567890123456789012345678901234567890123.example.com -all"}],"t12.example.com":[{"SPF":"v=spf1 a:%{H}.bar -all"}]}, failOnNoFake: true, helo: "%%%%%%%%%%%%%%%%%%%%%%"}
        let promise = spf.check_host('1.2.3.4', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.include(["fail","permerror"], result.toLowerCase());
        });
      });
    });
    describe('ALL mechanism syntax', function(){
      it('all-dot', function(){
        let email = 'foo@e1.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 -all."}],"e2.example.com":[{"SPF":"v=spf1 -all:foobar"}],"e3.example.com":[{"SPF":"v=spf1 -all/8"}],"e4.example.com":[{"SPF":"v=spf1 ?all"}],"e5.example.com":[{"SPF":"v=spf1 all -all"}]}, failOnNoFake: true, helo: "mail.example.com"}
        let promise = spf.check_host('1.2.3.4', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'PERMERROR');
        });
      });
      it('all-arg', function(){
        let email = 'foo@e2.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 -all."}],"e2.example.com":[{"SPF":"v=spf1 -all:foobar"}],"e3.example.com":[{"SPF":"v=spf1 -all/8"}],"e4.example.com":[{"SPF":"v=spf1 ?all"}],"e5.example.com":[{"SPF":"v=spf1 all -all"}]}, failOnNoFake: true, helo: "mail.example.com"}
        let promise = spf.check_host('1.2.3.4', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'PERMERROR');
        });
      });
      it('all-cidr', function(){
        let email = 'foo@e3.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 -all."}],"e2.example.com":[{"SPF":"v=spf1 -all:foobar"}],"e3.example.com":[{"SPF":"v=spf1 -all/8"}],"e4.example.com":[{"SPF":"v=spf1 ?all"}],"e5.example.com":[{"SPF":"v=spf1 all -all"}]}, failOnNoFake: true, helo: "mail.example.com"}
        let promise = spf.check_host('1.2.3.4', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'PERMERROR');
        });
      });
      it('all-neutral', function(){
        let email = 'foo@e4.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 -all."}],"e2.example.com":[{"SPF":"v=spf1 -all:foobar"}],"e3.example.com":[{"SPF":"v=spf1 -all/8"}],"e4.example.com":[{"SPF":"v=spf1 ?all"}],"e5.example.com":[{"SPF":"v=spf1 all -all"}]}, failOnNoFake: true, helo: "mail.example.com"}
        let promise = spf.check_host('1.2.3.4', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'NEUTRAL');
        });
      });
      it('all-double', function(){
        let email = 'foo@e5.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 -all."}],"e2.example.com":[{"SPF":"v=spf1 -all:foobar"}],"e3.example.com":[{"SPF":"v=spf1 -all/8"}],"e4.example.com":[{"SPF":"v=spf1 ?all"}],"e5.example.com":[{"SPF":"v=spf1 all -all"}]}, failOnNoFake: true, helo: "mail.example.com"}
        let promise = spf.check_host('1.2.3.4', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'PASS');
        });
      });
    });
    describe('PTR mechanism syntax', function(){
      it('ptr-cidr', function(){
        let email = 'foo@e1.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"},{"AAAA":"2001:db8::1"}],"e1.example.com":[{"SPF":"v=spf1 ptr/0 -all"}],"e2.example.com":[{"SPF":"v=spf1 ptr:example.com -all"}],"4.3.2.1.in-addr.arpa":[{"PTR":"e3.example.com"},{"PTR":"e4.example.com"},{"PTR":"mail.example.com"}],"1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.E.B.A.B.E.F.A.C.ip6.arpa":[{"PTR":"e3.example.com"}],"1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.D.0.1.0.0.2.ip6.arpa":[{"PTR":"mail.Example.com"}],"e3.example.com":[{"SPF":"v=spf1 ptr -all"},{"A":"1.2.3.4"},{"AAAA":"CAFE:BABE::1"}],"e4.example.com":[{"SPF":"v=spf1 ptr -all"}],"e5.example.com":[{"SPF":"v=spf1 ptr:"}],"e6.example.com":[{"SPF":"v=spf1 ptr:example.Com -all"}],"loop.example.com":[{"SPF":"v=spf1 ptr"}],"4.2.0.192.in-addr.arpa":[{"PTR":"loop4.example.com."}],"loop4.example.com":[{"CNAME":"CNAME.example.com."}],"cname.example.com":[{"CNAME":"CNAME.example.com."}]}, failOnNoFake: true, helo: "mail.example.com"}
        let promise = spf.check_host('1.2.3.4', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'PERMERROR');
        });
      });
      it('ptr-match-target', function(){
        let email = 'foo@e2.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"},{"AAAA":"2001:db8::1"}],"e1.example.com":[{"SPF":"v=spf1 ptr/0 -all"}],"e2.example.com":[{"SPF":"v=spf1 ptr:example.com -all"}],"4.3.2.1.in-addr.arpa":[{"PTR":"e3.example.com"},{"PTR":"e4.example.com"},{"PTR":"mail.example.com"}],"1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.E.B.A.B.E.F.A.C.ip6.arpa":[{"PTR":"e3.example.com"}],"1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.D.0.1.0.0.2.ip6.arpa":[{"PTR":"mail.Example.com"}],"e3.example.com":[{"SPF":"v=spf1 ptr -all"},{"A":"1.2.3.4"},{"AAAA":"CAFE:BABE::1"}],"e4.example.com":[{"SPF":"v=spf1 ptr -all"}],"e5.example.com":[{"SPF":"v=spf1 ptr:"}],"e6.example.com":[{"SPF":"v=spf1 ptr:example.Com -all"}],"loop.example.com":[{"SPF":"v=spf1 ptr"}],"4.2.0.192.in-addr.arpa":[{"PTR":"loop4.example.com."}],"loop4.example.com":[{"CNAME":"CNAME.example.com."}],"cname.example.com":[{"CNAME":"CNAME.example.com."}]}, failOnNoFake: true, helo: "mail.example.com"}
        let promise = spf.check_host('1.2.3.4', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'PASS');
        });
      });
      it('ptr-match-implicit', function(){
        let email = 'foo@e3.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"},{"AAAA":"2001:db8::1"}],"e1.example.com":[{"SPF":"v=spf1 ptr/0 -all"}],"e2.example.com":[{"SPF":"v=spf1 ptr:example.com -all"}],"4.3.2.1.in-addr.arpa":[{"PTR":"e3.example.com"},{"PTR":"e4.example.com"},{"PTR":"mail.example.com"}],"1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.E.B.A.B.E.F.A.C.ip6.arpa":[{"PTR":"e3.example.com"}],"1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.D.0.1.0.0.2.ip6.arpa":[{"PTR":"mail.Example.com"}],"e3.example.com":[{"SPF":"v=spf1 ptr -all"},{"A":"1.2.3.4"},{"AAAA":"CAFE:BABE::1"}],"e4.example.com":[{"SPF":"v=spf1 ptr -all"}],"e5.example.com":[{"SPF":"v=spf1 ptr:"}],"e6.example.com":[{"SPF":"v=spf1 ptr:example.Com -all"}],"loop.example.com":[{"SPF":"v=spf1 ptr"}],"4.2.0.192.in-addr.arpa":[{"PTR":"loop4.example.com."}],"loop4.example.com":[{"CNAME":"CNAME.example.com."}],"cname.example.com":[{"CNAME":"CNAME.example.com."}]}, failOnNoFake: true, helo: "mail.example.com"}
        let promise = spf.check_host('1.2.3.4', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'PASS');
        });
      });
      it('ptr-nomatch-invalid', function(){
        let email = 'foo@e4.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"},{"AAAA":"2001:db8::1"}],"e1.example.com":[{"SPF":"v=spf1 ptr/0 -all"}],"e2.example.com":[{"SPF":"v=spf1 ptr:example.com -all"}],"4.3.2.1.in-addr.arpa":[{"PTR":"e3.example.com"},{"PTR":"e4.example.com"},{"PTR":"mail.example.com"}],"1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.E.B.A.B.E.F.A.C.ip6.arpa":[{"PTR":"e3.example.com"}],"1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.D.0.1.0.0.2.ip6.arpa":[{"PTR":"mail.Example.com"}],"e3.example.com":[{"SPF":"v=spf1 ptr -all"},{"A":"1.2.3.4"},{"AAAA":"CAFE:BABE::1"}],"e4.example.com":[{"SPF":"v=spf1 ptr -all"}],"e5.example.com":[{"SPF":"v=spf1 ptr:"}],"e6.example.com":[{"SPF":"v=spf1 ptr:example.Com -all"}],"loop.example.com":[{"SPF":"v=spf1 ptr"}],"4.2.0.192.in-addr.arpa":[{"PTR":"loop4.example.com."}],"loop4.example.com":[{"CNAME":"CNAME.example.com."}],"cname.example.com":[{"CNAME":"CNAME.example.com."}]}, failOnNoFake: true, helo: "mail.example.com"}
        let promise = spf.check_host('1.2.3.4', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'FAIL');
        });
      });
      it('ptr-match-ip6', function(){
        let email = 'foo@e3.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"},{"AAAA":"2001:db8::1"}],"e1.example.com":[{"SPF":"v=spf1 ptr/0 -all"}],"e2.example.com":[{"SPF":"v=spf1 ptr:example.com -all"}],"4.3.2.1.in-addr.arpa":[{"PTR":"e3.example.com"},{"PTR":"e4.example.com"},{"PTR":"mail.example.com"}],"1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.E.B.A.B.E.F.A.C.ip6.arpa":[{"PTR":"e3.example.com"}],"1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.D.0.1.0.0.2.ip6.arpa":[{"PTR":"mail.Example.com"}],"e3.example.com":[{"SPF":"v=spf1 ptr -all"},{"A":"1.2.3.4"},{"AAAA":"CAFE:BABE::1"}],"e4.example.com":[{"SPF":"v=spf1 ptr -all"}],"e5.example.com":[{"SPF":"v=spf1 ptr:"}],"e6.example.com":[{"SPF":"v=spf1 ptr:example.Com -all"}],"loop.example.com":[{"SPF":"v=spf1 ptr"}],"4.2.0.192.in-addr.arpa":[{"PTR":"loop4.example.com."}],"loop4.example.com":[{"CNAME":"CNAME.example.com."}],"cname.example.com":[{"CNAME":"CNAME.example.com."}]}, failOnNoFake: true, helo: "mail.example.com"}
        let promise = spf.check_host('CAFE:BABE::1', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'PASS');
        });
      });
      it('ptr-empty-domain', function(){
        let email = 'foo@e5.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"},{"AAAA":"2001:db8::1"}],"e1.example.com":[{"SPF":"v=spf1 ptr/0 -all"}],"e2.example.com":[{"SPF":"v=spf1 ptr:example.com -all"}],"4.3.2.1.in-addr.arpa":[{"PTR":"e3.example.com"},{"PTR":"e4.example.com"},{"PTR":"mail.example.com"}],"1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.E.B.A.B.E.F.A.C.ip6.arpa":[{"PTR":"e3.example.com"}],"1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.D.0.1.0.0.2.ip6.arpa":[{"PTR":"mail.Example.com"}],"e3.example.com":[{"SPF":"v=spf1 ptr -all"},{"A":"1.2.3.4"},{"AAAA":"CAFE:BABE::1"}],"e4.example.com":[{"SPF":"v=spf1 ptr -all"}],"e5.example.com":[{"SPF":"v=spf1 ptr:"}],"e6.example.com":[{"SPF":"v=spf1 ptr:example.Com -all"}],"loop.example.com":[{"SPF":"v=spf1 ptr"}],"4.2.0.192.in-addr.arpa":[{"PTR":"loop4.example.com."}],"loop4.example.com":[{"CNAME":"CNAME.example.com."}],"cname.example.com":[{"CNAME":"CNAME.example.com."}]}, failOnNoFake: true, helo: "mail.example.com"}
        let promise = spf.check_host('1.2.3.4', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'PERMERROR');
        });
      });
      it('ptr-case-change', function(){
        let email = 'bar@e6.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"},{"AAAA":"2001:db8::1"}],"e1.example.com":[{"SPF":"v=spf1 ptr/0 -all"}],"e2.example.com":[{"SPF":"v=spf1 ptr:example.com -all"}],"4.3.2.1.in-addr.arpa":[{"PTR":"e3.example.com"},{"PTR":"e4.example.com"},{"PTR":"mail.example.com"}],"1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.E.B.A.B.E.F.A.C.ip6.arpa":[{"PTR":"e3.example.com"}],"1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.D.0.1.0.0.2.ip6.arpa":[{"PTR":"mail.Example.com"}],"e3.example.com":[{"SPF":"v=spf1 ptr -all"},{"A":"1.2.3.4"},{"AAAA":"CAFE:BABE::1"}],"e4.example.com":[{"SPF":"v=spf1 ptr -all"}],"e5.example.com":[{"SPF":"v=spf1 ptr:"}],"e6.example.com":[{"SPF":"v=spf1 ptr:example.Com -all"}],"loop.example.com":[{"SPF":"v=spf1 ptr"}],"4.2.0.192.in-addr.arpa":[{"PTR":"loop4.example.com."}],"loop4.example.com":[{"CNAME":"CNAME.example.com."}],"cname.example.com":[{"CNAME":"CNAME.example.com."}]}, failOnNoFake: true, helo: "mail.example.com"}
        let promise = spf.check_host('2001:db8::1', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'PASS');
        });
      });
      it('ptr-cname-loop', function(){
        let email = 'postmaster@loop.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"},{"AAAA":"2001:db8::1"}],"e1.example.com":[{"SPF":"v=spf1 ptr/0 -all"}],"e2.example.com":[{"SPF":"v=spf1 ptr:example.com -all"}],"4.3.2.1.in-addr.arpa":[{"PTR":"e3.example.com"},{"PTR":"e4.example.com"},{"PTR":"mail.example.com"}],"1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.E.B.A.B.E.F.A.C.ip6.arpa":[{"PTR":"e3.example.com"}],"1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.D.0.1.0.0.2.ip6.arpa":[{"PTR":"mail.Example.com"}],"e3.example.com":[{"SPF":"v=spf1 ptr -all"},{"A":"1.2.3.4"},{"AAAA":"CAFE:BABE::1"}],"e4.example.com":[{"SPF":"v=spf1 ptr -all"}],"e5.example.com":[{"SPF":"v=spf1 ptr:"}],"e6.example.com":[{"SPF":"v=spf1 ptr:example.Com -all"}],"loop.example.com":[{"SPF":"v=spf1 ptr"}],"4.2.0.192.in-addr.arpa":[{"PTR":"loop4.example.com."}],"loop4.example.com":[{"CNAME":"CNAME.example.com."}],"cname.example.com":[{"CNAME":"CNAME.example.com."}]}, failOnNoFake: true, helo: "loop.example.com"}
        let promise = spf.check_host('192.0.2.4', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'NEUTRAL');
        });
      });
    });
    describe('A mechanism syntax', function(){
      it('a-cidr6', function(){
        let email = 'foo@e6.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 a/0 -all"}],"e2.example.com":[{"A":"1.1.1.1"},{"AAAA":"1234::2"},{"SPF":"v=spf1 a/0 -all"}],"e2a.example.com":[{"AAAA":"1234::1"},{"SPF":"v=spf1 a//0 -all"}],"e2b.example.com":[{"A":"1.1.1.1"},{"SPF":"v=spf1 a//0 -all"}],"ipv6.example.com":[{"AAAA":"1234::1"},{"A":"1.1.1.1"},{"SPF":"v=spf1 a -all"}],"e3.example.com":[{"SPF":"v=spf1 a:foo.example.com\u0000"}],"e4.example.com":[{"SPF":"v=spf1 a:111.222.33.44"}],"e5.example.com":[{"SPF":"v=spf1 a:abc.123"}],"e5a.example.com":[{"SPF":"v=spf1 a:museum"}],"e5b.example.com":[{"SPF":"v=spf1 a:museum."}],"e6.example.com":[{"SPF":"v=spf1 a//33 -all"}],"e6a.example.com":[{"SPF":"v=spf1 a/33 -all"}],"e7.example.com":[{"SPF":"v=spf1 a//129 -all"}],"e8.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24//64 -all"}],"e8e.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24/64 -all"}],"e8a.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24 -all"}],"e8b.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a//64 -all"}],"e9.example.com":[{"SPF":"v=spf1 a:example.com:8080"}],"e10.example.com":[{"SPF":"v=spf1 a:foo.example.com/24"}],"foo.example.com":[{"A":"1.1.1.1"},{"A":"1.2.3.5"}],"e11.example.com":[{"SPF":"v=spf1 a:foo:bar/baz.example.com"}],"foo:bar/baz.example.com":[{"A":"1.2.3.4"}],"e12.example.com":[{"SPF":"v=spf1 a:example.-com"}],"e13.example.com":[{"SPF":"v=spf1 a:"}],"e14.example.com":[{"SPF":"v=spf1 a:foo.example.xn--zckzah -all"}],"foo.example.xn--zckzah":[{"A":"1.2.3.4"}]}, failOnNoFake: true, helo: "mail.example.com"}
        let promise = spf.check_host('1.2.3.4', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'FAIL');
        });
      });
      it('a-bad-cidr4', function(){
        let email = 'foo@e6a.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 a/0 -all"}],"e2.example.com":[{"A":"1.1.1.1"},{"AAAA":"1234::2"},{"SPF":"v=spf1 a/0 -all"}],"e2a.example.com":[{"AAAA":"1234::1"},{"SPF":"v=spf1 a//0 -all"}],"e2b.example.com":[{"A":"1.1.1.1"},{"SPF":"v=spf1 a//0 -all"}],"ipv6.example.com":[{"AAAA":"1234::1"},{"A":"1.1.1.1"},{"SPF":"v=spf1 a -all"}],"e3.example.com":[{"SPF":"v=spf1 a:foo.example.com\u0000"}],"e4.example.com":[{"SPF":"v=spf1 a:111.222.33.44"}],"e5.example.com":[{"SPF":"v=spf1 a:abc.123"}],"e5a.example.com":[{"SPF":"v=spf1 a:museum"}],"e5b.example.com":[{"SPF":"v=spf1 a:museum."}],"e6.example.com":[{"SPF":"v=spf1 a//33 -all"}],"e6a.example.com":[{"SPF":"v=spf1 a/33 -all"}],"e7.example.com":[{"SPF":"v=spf1 a//129 -all"}],"e8.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24//64 -all"}],"e8e.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24/64 -all"}],"e8a.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24 -all"}],"e8b.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a//64 -all"}],"e9.example.com":[{"SPF":"v=spf1 a:example.com:8080"}],"e10.example.com":[{"SPF":"v=spf1 a:foo.example.com/24"}],"foo.example.com":[{"A":"1.1.1.1"},{"A":"1.2.3.5"}],"e11.example.com":[{"SPF":"v=spf1 a:foo:bar/baz.example.com"}],"foo:bar/baz.example.com":[{"A":"1.2.3.4"}],"e12.example.com":[{"SPF":"v=spf1 a:example.-com"}],"e13.example.com":[{"SPF":"v=spf1 a:"}],"e14.example.com":[{"SPF":"v=spf1 a:foo.example.xn--zckzah -all"}],"foo.example.xn--zckzah":[{"A":"1.2.3.4"}]}, failOnNoFake: true, helo: "mail.example.com"}
        let promise = spf.check_host('1.2.3.4', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'PERMERROR');
        });
      });
      it('a-bad-cidr6', function(){
        let email = 'foo@e7.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 a/0 -all"}],"e2.example.com":[{"A":"1.1.1.1"},{"AAAA":"1234::2"},{"SPF":"v=spf1 a/0 -all"}],"e2a.example.com":[{"AAAA":"1234::1"},{"SPF":"v=spf1 a//0 -all"}],"e2b.example.com":[{"A":"1.1.1.1"},{"SPF":"v=spf1 a//0 -all"}],"ipv6.example.com":[{"AAAA":"1234::1"},{"A":"1.1.1.1"},{"SPF":"v=spf1 a -all"}],"e3.example.com":[{"SPF":"v=spf1 a:foo.example.com\u0000"}],"e4.example.com":[{"SPF":"v=spf1 a:111.222.33.44"}],"e5.example.com":[{"SPF":"v=spf1 a:abc.123"}],"e5a.example.com":[{"SPF":"v=spf1 a:museum"}],"e5b.example.com":[{"SPF":"v=spf1 a:museum."}],"e6.example.com":[{"SPF":"v=spf1 a//33 -all"}],"e6a.example.com":[{"SPF":"v=spf1 a/33 -all"}],"e7.example.com":[{"SPF":"v=spf1 a//129 -all"}],"e8.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24//64 -all"}],"e8e.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24/64 -all"}],"e8a.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24 -all"}],"e8b.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a//64 -all"}],"e9.example.com":[{"SPF":"v=spf1 a:example.com:8080"}],"e10.example.com":[{"SPF":"v=spf1 a:foo.example.com/24"}],"foo.example.com":[{"A":"1.1.1.1"},{"A":"1.2.3.5"}],"e11.example.com":[{"SPF":"v=spf1 a:foo:bar/baz.example.com"}],"foo:bar/baz.example.com":[{"A":"1.2.3.4"}],"e12.example.com":[{"SPF":"v=spf1 a:example.-com"}],"e13.example.com":[{"SPF":"v=spf1 a:"}],"e14.example.com":[{"SPF":"v=spf1 a:foo.example.xn--zckzah -all"}],"foo.example.xn--zckzah":[{"A":"1.2.3.4"}]}, failOnNoFake: true, helo: "mail.example.com"}
        let promise = spf.check_host('1.2.3.4', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'PERMERROR');
        });
      });
      it('a-dual-cidr-ip4-match', function(){
        let email = 'foo@e8.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 a/0 -all"}],"e2.example.com":[{"A":"1.1.1.1"},{"AAAA":"1234::2"},{"SPF":"v=spf1 a/0 -all"}],"e2a.example.com":[{"AAAA":"1234::1"},{"SPF":"v=spf1 a//0 -all"}],"e2b.example.com":[{"A":"1.1.1.1"},{"SPF":"v=spf1 a//0 -all"}],"ipv6.example.com":[{"AAAA":"1234::1"},{"A":"1.1.1.1"},{"SPF":"v=spf1 a -all"}],"e3.example.com":[{"SPF":"v=spf1 a:foo.example.com\u0000"}],"e4.example.com":[{"SPF":"v=spf1 a:111.222.33.44"}],"e5.example.com":[{"SPF":"v=spf1 a:abc.123"}],"e5a.example.com":[{"SPF":"v=spf1 a:museum"}],"e5b.example.com":[{"SPF":"v=spf1 a:museum."}],"e6.example.com":[{"SPF":"v=spf1 a//33 -all"}],"e6a.example.com":[{"SPF":"v=spf1 a/33 -all"}],"e7.example.com":[{"SPF":"v=spf1 a//129 -all"}],"e8.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24//64 -all"}],"e8e.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24/64 -all"}],"e8a.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24 -all"}],"e8b.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a//64 -all"}],"e9.example.com":[{"SPF":"v=spf1 a:example.com:8080"}],"e10.example.com":[{"SPF":"v=spf1 a:foo.example.com/24"}],"foo.example.com":[{"A":"1.1.1.1"},{"A":"1.2.3.5"}],"e11.example.com":[{"SPF":"v=spf1 a:foo:bar/baz.example.com"}],"foo:bar/baz.example.com":[{"A":"1.2.3.4"}],"e12.example.com":[{"SPF":"v=spf1 a:example.-com"}],"e13.example.com":[{"SPF":"v=spf1 a:"}],"e14.example.com":[{"SPF":"v=spf1 a:foo.example.xn--zckzah -all"}],"foo.example.xn--zckzah":[{"A":"1.2.3.4"}]}, failOnNoFake: true, helo: "mail.example.com"}
        let promise = spf.check_host('1.2.3.4', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'PASS');
        });
      });
      it('a-dual-cidr-ip4-err', function(){
        let email = 'foo@e8e.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 a/0 -all"}],"e2.example.com":[{"A":"1.1.1.1"},{"AAAA":"1234::2"},{"SPF":"v=spf1 a/0 -all"}],"e2a.example.com":[{"AAAA":"1234::1"},{"SPF":"v=spf1 a//0 -all"}],"e2b.example.com":[{"A":"1.1.1.1"},{"SPF":"v=spf1 a//0 -all"}],"ipv6.example.com":[{"AAAA":"1234::1"},{"A":"1.1.1.1"},{"SPF":"v=spf1 a -all"}],"e3.example.com":[{"SPF":"v=spf1 a:foo.example.com\u0000"}],"e4.example.com":[{"SPF":"v=spf1 a:111.222.33.44"}],"e5.example.com":[{"SPF":"v=spf1 a:abc.123"}],"e5a.example.com":[{"SPF":"v=spf1 a:museum"}],"e5b.example.com":[{"SPF":"v=spf1 a:museum."}],"e6.example.com":[{"SPF":"v=spf1 a//33 -all"}],"e6a.example.com":[{"SPF":"v=spf1 a/33 -all"}],"e7.example.com":[{"SPF":"v=spf1 a//129 -all"}],"e8.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24//64 -all"}],"e8e.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24/64 -all"}],"e8a.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24 -all"}],"e8b.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a//64 -all"}],"e9.example.com":[{"SPF":"v=spf1 a:example.com:8080"}],"e10.example.com":[{"SPF":"v=spf1 a:foo.example.com/24"}],"foo.example.com":[{"A":"1.1.1.1"},{"A":"1.2.3.5"}],"e11.example.com":[{"SPF":"v=spf1 a:foo:bar/baz.example.com"}],"foo:bar/baz.example.com":[{"A":"1.2.3.4"}],"e12.example.com":[{"SPF":"v=spf1 a:example.-com"}],"e13.example.com":[{"SPF":"v=spf1 a:"}],"e14.example.com":[{"SPF":"v=spf1 a:foo.example.xn--zckzah -all"}],"foo.example.xn--zckzah":[{"A":"1.2.3.4"}]}, failOnNoFake: true, helo: "mail.example.com"}
        let promise = spf.check_host('1.2.3.4', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'PERMERROR');
        });
      });
      it('a-dual-cidr-ip6-match', function(){
        let email = 'foo@e8.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 a/0 -all"}],"e2.example.com":[{"A":"1.1.1.1"},{"AAAA":"1234::2"},{"SPF":"v=spf1 a/0 -all"}],"e2a.example.com":[{"AAAA":"1234::1"},{"SPF":"v=spf1 a//0 -all"}],"e2b.example.com":[{"A":"1.1.1.1"},{"SPF":"v=spf1 a//0 -all"}],"ipv6.example.com":[{"AAAA":"1234::1"},{"A":"1.1.1.1"},{"SPF":"v=spf1 a -all"}],"e3.example.com":[{"SPF":"v=spf1 a:foo.example.com\u0000"}],"e4.example.com":[{"SPF":"v=spf1 a:111.222.33.44"}],"e5.example.com":[{"SPF":"v=spf1 a:abc.123"}],"e5a.example.com":[{"SPF":"v=spf1 a:museum"}],"e5b.example.com":[{"SPF":"v=spf1 a:museum."}],"e6.example.com":[{"SPF":"v=spf1 a//33 -all"}],"e6a.example.com":[{"SPF":"v=spf1 a/33 -all"}],"e7.example.com":[{"SPF":"v=spf1 a//129 -all"}],"e8.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24//64 -all"}],"e8e.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24/64 -all"}],"e8a.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24 -all"}],"e8b.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a//64 -all"}],"e9.example.com":[{"SPF":"v=spf1 a:example.com:8080"}],"e10.example.com":[{"SPF":"v=spf1 a:foo.example.com/24"}],"foo.example.com":[{"A":"1.1.1.1"},{"A":"1.2.3.5"}],"e11.example.com":[{"SPF":"v=spf1 a:foo:bar/baz.example.com"}],"foo:bar/baz.example.com":[{"A":"1.2.3.4"}],"e12.example.com":[{"SPF":"v=spf1 a:example.-com"}],"e13.example.com":[{"SPF":"v=spf1 a:"}],"e14.example.com":[{"SPF":"v=spf1 a:foo.example.xn--zckzah -all"}],"foo.example.xn--zckzah":[{"A":"1.2.3.4"}]}, failOnNoFake: true, helo: "mail.example.com"}
        let promise = spf.check_host('2001:db8:1234::cafe:babe', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'PASS');
        });
      });
      it('a-dual-cidr-ip4-default', function(){
        let email = 'foo@e8b.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 a/0 -all"}],"e2.example.com":[{"A":"1.1.1.1"},{"AAAA":"1234::2"},{"SPF":"v=spf1 a/0 -all"}],"e2a.example.com":[{"AAAA":"1234::1"},{"SPF":"v=spf1 a//0 -all"}],"e2b.example.com":[{"A":"1.1.1.1"},{"SPF":"v=spf1 a//0 -all"}],"ipv6.example.com":[{"AAAA":"1234::1"},{"A":"1.1.1.1"},{"SPF":"v=spf1 a -all"}],"e3.example.com":[{"SPF":"v=spf1 a:foo.example.com\u0000"}],"e4.example.com":[{"SPF":"v=spf1 a:111.222.33.44"}],"e5.example.com":[{"SPF":"v=spf1 a:abc.123"}],"e5a.example.com":[{"SPF":"v=spf1 a:museum"}],"e5b.example.com":[{"SPF":"v=spf1 a:museum."}],"e6.example.com":[{"SPF":"v=spf1 a//33 -all"}],"e6a.example.com":[{"SPF":"v=spf1 a/33 -all"}],"e7.example.com":[{"SPF":"v=spf1 a//129 -all"}],"e8.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24//64 -all"}],"e8e.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24/64 -all"}],"e8a.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24 -all"}],"e8b.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a//64 -all"}],"e9.example.com":[{"SPF":"v=spf1 a:example.com:8080"}],"e10.example.com":[{"SPF":"v=spf1 a:foo.example.com/24"}],"foo.example.com":[{"A":"1.1.1.1"},{"A":"1.2.3.5"}],"e11.example.com":[{"SPF":"v=spf1 a:foo:bar/baz.example.com"}],"foo:bar/baz.example.com":[{"A":"1.2.3.4"}],"e12.example.com":[{"SPF":"v=spf1 a:example.-com"}],"e13.example.com":[{"SPF":"v=spf1 a:"}],"e14.example.com":[{"SPF":"v=spf1 a:foo.example.xn--zckzah -all"}],"foo.example.xn--zckzah":[{"A":"1.2.3.4"}]}, failOnNoFake: true, helo: "mail.example.com"}
        let promise = spf.check_host('1.2.3.4', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'FAIL');
        });
      });
      it('a-dual-cidr-ip6-default', function(){
        let email = 'foo@e8a.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 a/0 -all"}],"e2.example.com":[{"A":"1.1.1.1"},{"AAAA":"1234::2"},{"SPF":"v=spf1 a/0 -all"}],"e2a.example.com":[{"AAAA":"1234::1"},{"SPF":"v=spf1 a//0 -all"}],"e2b.example.com":[{"A":"1.1.1.1"},{"SPF":"v=spf1 a//0 -all"}],"ipv6.example.com":[{"AAAA":"1234::1"},{"A":"1.1.1.1"},{"SPF":"v=spf1 a -all"}],"e3.example.com":[{"SPF":"v=spf1 a:foo.example.com\u0000"}],"e4.example.com":[{"SPF":"v=spf1 a:111.222.33.44"}],"e5.example.com":[{"SPF":"v=spf1 a:abc.123"}],"e5a.example.com":[{"SPF":"v=spf1 a:museum"}],"e5b.example.com":[{"SPF":"v=spf1 a:museum."}],"e6.example.com":[{"SPF":"v=spf1 a//33 -all"}],"e6a.example.com":[{"SPF":"v=spf1 a/33 -all"}],"e7.example.com":[{"SPF":"v=spf1 a//129 -all"}],"e8.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24//64 -all"}],"e8e.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24/64 -all"}],"e8a.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24 -all"}],"e8b.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a//64 -all"}],"e9.example.com":[{"SPF":"v=spf1 a:example.com:8080"}],"e10.example.com":[{"SPF":"v=spf1 a:foo.example.com/24"}],"foo.example.com":[{"A":"1.1.1.1"},{"A":"1.2.3.5"}],"e11.example.com":[{"SPF":"v=spf1 a:foo:bar/baz.example.com"}],"foo:bar/baz.example.com":[{"A":"1.2.3.4"}],"e12.example.com":[{"SPF":"v=spf1 a:example.-com"}],"e13.example.com":[{"SPF":"v=spf1 a:"}],"e14.example.com":[{"SPF":"v=spf1 a:foo.example.xn--zckzah -all"}],"foo.example.xn--zckzah":[{"A":"1.2.3.4"}]}, failOnNoFake: true, helo: "mail.example.com"}
        let promise = spf.check_host('2001:db8:1234::cafe:babe', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'FAIL');
        });
      });
      it('a-multi-ip1', function(){
        let email = 'foo@e10.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 a/0 -all"}],"e2.example.com":[{"A":"1.1.1.1"},{"AAAA":"1234::2"},{"SPF":"v=spf1 a/0 -all"}],"e2a.example.com":[{"AAAA":"1234::1"},{"SPF":"v=spf1 a//0 -all"}],"e2b.example.com":[{"A":"1.1.1.1"},{"SPF":"v=spf1 a//0 -all"}],"ipv6.example.com":[{"AAAA":"1234::1"},{"A":"1.1.1.1"},{"SPF":"v=spf1 a -all"}],"e3.example.com":[{"SPF":"v=spf1 a:foo.example.com\u0000"}],"e4.example.com":[{"SPF":"v=spf1 a:111.222.33.44"}],"e5.example.com":[{"SPF":"v=spf1 a:abc.123"}],"e5a.example.com":[{"SPF":"v=spf1 a:museum"}],"e5b.example.com":[{"SPF":"v=spf1 a:museum."}],"e6.example.com":[{"SPF":"v=spf1 a//33 -all"}],"e6a.example.com":[{"SPF":"v=spf1 a/33 -all"}],"e7.example.com":[{"SPF":"v=spf1 a//129 -all"}],"e8.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24//64 -all"}],"e8e.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24/64 -all"}],"e8a.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24 -all"}],"e8b.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a//64 -all"}],"e9.example.com":[{"SPF":"v=spf1 a:example.com:8080"}],"e10.example.com":[{"SPF":"v=spf1 a:foo.example.com/24"}],"foo.example.com":[{"A":"1.1.1.1"},{"A":"1.2.3.5"}],"e11.example.com":[{"SPF":"v=spf1 a:foo:bar/baz.example.com"}],"foo:bar/baz.example.com":[{"A":"1.2.3.4"}],"e12.example.com":[{"SPF":"v=spf1 a:example.-com"}],"e13.example.com":[{"SPF":"v=spf1 a:"}],"e14.example.com":[{"SPF":"v=spf1 a:foo.example.xn--zckzah -all"}],"foo.example.xn--zckzah":[{"A":"1.2.3.4"}]}, failOnNoFake: true, helo: "mail.example.com"}
        let promise = spf.check_host('1.2.3.4', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'PASS');
        });
      });
      it('a-multi-ip2', function(){
        let email = 'foo@e10.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 a/0 -all"}],"e2.example.com":[{"A":"1.1.1.1"},{"AAAA":"1234::2"},{"SPF":"v=spf1 a/0 -all"}],"e2a.example.com":[{"AAAA":"1234::1"},{"SPF":"v=spf1 a//0 -all"}],"e2b.example.com":[{"A":"1.1.1.1"},{"SPF":"v=spf1 a//0 -all"}],"ipv6.example.com":[{"AAAA":"1234::1"},{"A":"1.1.1.1"},{"SPF":"v=spf1 a -all"}],"e3.example.com":[{"SPF":"v=spf1 a:foo.example.com\u0000"}],"e4.example.com":[{"SPF":"v=spf1 a:111.222.33.44"}],"e5.example.com":[{"SPF":"v=spf1 a:abc.123"}],"e5a.example.com":[{"SPF":"v=spf1 a:museum"}],"e5b.example.com":[{"SPF":"v=spf1 a:museum."}],"e6.example.com":[{"SPF":"v=spf1 a//33 -all"}],"e6a.example.com":[{"SPF":"v=spf1 a/33 -all"}],"e7.example.com":[{"SPF":"v=spf1 a//129 -all"}],"e8.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24//64 -all"}],"e8e.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24/64 -all"}],"e8a.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24 -all"}],"e8b.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a//64 -all"}],"e9.example.com":[{"SPF":"v=spf1 a:example.com:8080"}],"e10.example.com":[{"SPF":"v=spf1 a:foo.example.com/24"}],"foo.example.com":[{"A":"1.1.1.1"},{"A":"1.2.3.5"}],"e11.example.com":[{"SPF":"v=spf1 a:foo:bar/baz.example.com"}],"foo:bar/baz.example.com":[{"A":"1.2.3.4"}],"e12.example.com":[{"SPF":"v=spf1 a:example.-com"}],"e13.example.com":[{"SPF":"v=spf1 a:"}],"e14.example.com":[{"SPF":"v=spf1 a:foo.example.xn--zckzah -all"}],"foo.example.xn--zckzah":[{"A":"1.2.3.4"}]}, failOnNoFake: true, helo: "mail.example.com"}
        let promise = spf.check_host('1.2.3.4', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'PASS');
        });
      });
      it('a-bad-domain', function(){
        let email = 'foo@e9.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 a/0 -all"}],"e2.example.com":[{"A":"1.1.1.1"},{"AAAA":"1234::2"},{"SPF":"v=spf1 a/0 -all"}],"e2a.example.com":[{"AAAA":"1234::1"},{"SPF":"v=spf1 a//0 -all"}],"e2b.example.com":[{"A":"1.1.1.1"},{"SPF":"v=spf1 a//0 -all"}],"ipv6.example.com":[{"AAAA":"1234::1"},{"A":"1.1.1.1"},{"SPF":"v=spf1 a -all"}],"e3.example.com":[{"SPF":"v=spf1 a:foo.example.com\u0000"}],"e4.example.com":[{"SPF":"v=spf1 a:111.222.33.44"}],"e5.example.com":[{"SPF":"v=spf1 a:abc.123"}],"e5a.example.com":[{"SPF":"v=spf1 a:museum"}],"e5b.example.com":[{"SPF":"v=spf1 a:museum."}],"e6.example.com":[{"SPF":"v=spf1 a//33 -all"}],"e6a.example.com":[{"SPF":"v=spf1 a/33 -all"}],"e7.example.com":[{"SPF":"v=spf1 a//129 -all"}],"e8.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24//64 -all"}],"e8e.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24/64 -all"}],"e8a.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24 -all"}],"e8b.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a//64 -all"}],"e9.example.com":[{"SPF":"v=spf1 a:example.com:8080"}],"e10.example.com":[{"SPF":"v=spf1 a:foo.example.com/24"}],"foo.example.com":[{"A":"1.1.1.1"},{"A":"1.2.3.5"}],"e11.example.com":[{"SPF":"v=spf1 a:foo:bar/baz.example.com"}],"foo:bar/baz.example.com":[{"A":"1.2.3.4"}],"e12.example.com":[{"SPF":"v=spf1 a:example.-com"}],"e13.example.com":[{"SPF":"v=spf1 a:"}],"e14.example.com":[{"SPF":"v=spf1 a:foo.example.xn--zckzah -all"}],"foo.example.xn--zckzah":[{"A":"1.2.3.4"}]}, failOnNoFake: true, helo: "mail.example.com"}
        let promise = spf.check_host('1.2.3.4', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'PERMERROR');
        });
      });
      it('a-nxdomain', function(){
        let email = 'foo@e1.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 a/0 -all"}],"e2.example.com":[{"A":"1.1.1.1"},{"AAAA":"1234::2"},{"SPF":"v=spf1 a/0 -all"}],"e2a.example.com":[{"AAAA":"1234::1"},{"SPF":"v=spf1 a//0 -all"}],"e2b.example.com":[{"A":"1.1.1.1"},{"SPF":"v=spf1 a//0 -all"}],"ipv6.example.com":[{"AAAA":"1234::1"},{"A":"1.1.1.1"},{"SPF":"v=spf1 a -all"}],"e3.example.com":[{"SPF":"v=spf1 a:foo.example.com\u0000"}],"e4.example.com":[{"SPF":"v=spf1 a:111.222.33.44"}],"e5.example.com":[{"SPF":"v=spf1 a:abc.123"}],"e5a.example.com":[{"SPF":"v=spf1 a:museum"}],"e5b.example.com":[{"SPF":"v=spf1 a:museum."}],"e6.example.com":[{"SPF":"v=spf1 a//33 -all"}],"e6a.example.com":[{"SPF":"v=spf1 a/33 -all"}],"e7.example.com":[{"SPF":"v=spf1 a//129 -all"}],"e8.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24//64 -all"}],"e8e.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24/64 -all"}],"e8a.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24 -all"}],"e8b.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a//64 -all"}],"e9.example.com":[{"SPF":"v=spf1 a:example.com:8080"}],"e10.example.com":[{"SPF":"v=spf1 a:foo.example.com/24"}],"foo.example.com":[{"A":"1.1.1.1"},{"A":"1.2.3.5"}],"e11.example.com":[{"SPF":"v=spf1 a:foo:bar/baz.example.com"}],"foo:bar/baz.example.com":[{"A":"1.2.3.4"}],"e12.example.com":[{"SPF":"v=spf1 a:example.-com"}],"e13.example.com":[{"SPF":"v=spf1 a:"}],"e14.example.com":[{"SPF":"v=spf1 a:foo.example.xn--zckzah -all"}],"foo.example.xn--zckzah":[{"A":"1.2.3.4"}]}, failOnNoFake: true, helo: "mail.example.com"}
        let promise = spf.check_host('1.2.3.4', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'FAIL');
        });
      });
      it('a-cidr4-0', function(){
        let email = 'foo@e2.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 a/0 -all"}],"e2.example.com":[{"A":"1.1.1.1"},{"AAAA":"1234::2"},{"SPF":"v=spf1 a/0 -all"}],"e2a.example.com":[{"AAAA":"1234::1"},{"SPF":"v=spf1 a//0 -all"}],"e2b.example.com":[{"A":"1.1.1.1"},{"SPF":"v=spf1 a//0 -all"}],"ipv6.example.com":[{"AAAA":"1234::1"},{"A":"1.1.1.1"},{"SPF":"v=spf1 a -all"}],"e3.example.com":[{"SPF":"v=spf1 a:foo.example.com\u0000"}],"e4.example.com":[{"SPF":"v=spf1 a:111.222.33.44"}],"e5.example.com":[{"SPF":"v=spf1 a:abc.123"}],"e5a.example.com":[{"SPF":"v=spf1 a:museum"}],"e5b.example.com":[{"SPF":"v=spf1 a:museum."}],"e6.example.com":[{"SPF":"v=spf1 a//33 -all"}],"e6a.example.com":[{"SPF":"v=spf1 a/33 -all"}],"e7.example.com":[{"SPF":"v=spf1 a//129 -all"}],"e8.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24//64 -all"}],"e8e.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24/64 -all"}],"e8a.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24 -all"}],"e8b.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a//64 -all"}],"e9.example.com":[{"SPF":"v=spf1 a:example.com:8080"}],"e10.example.com":[{"SPF":"v=spf1 a:foo.example.com/24"}],"foo.example.com":[{"A":"1.1.1.1"},{"A":"1.2.3.5"}],"e11.example.com":[{"SPF":"v=spf1 a:foo:bar/baz.example.com"}],"foo:bar/baz.example.com":[{"A":"1.2.3.4"}],"e12.example.com":[{"SPF":"v=spf1 a:example.-com"}],"e13.example.com":[{"SPF":"v=spf1 a:"}],"e14.example.com":[{"SPF":"v=spf1 a:foo.example.xn--zckzah -all"}],"foo.example.xn--zckzah":[{"A":"1.2.3.4"}]}, failOnNoFake: true, helo: "mail.example.com"}
        let promise = spf.check_host('1.2.3.4', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'PASS');
        });
      });
      it('a-cidr4-0-ip6', function(){
        let email = 'foo@e2.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 a/0 -all"}],"e2.example.com":[{"A":"1.1.1.1"},{"AAAA":"1234::2"},{"SPF":"v=spf1 a/0 -all"}],"e2a.example.com":[{"AAAA":"1234::1"},{"SPF":"v=spf1 a//0 -all"}],"e2b.example.com":[{"A":"1.1.1.1"},{"SPF":"v=spf1 a//0 -all"}],"ipv6.example.com":[{"AAAA":"1234::1"},{"A":"1.1.1.1"},{"SPF":"v=spf1 a -all"}],"e3.example.com":[{"SPF":"v=spf1 a:foo.example.com\u0000"}],"e4.example.com":[{"SPF":"v=spf1 a:111.222.33.44"}],"e5.example.com":[{"SPF":"v=spf1 a:abc.123"}],"e5a.example.com":[{"SPF":"v=spf1 a:museum"}],"e5b.example.com":[{"SPF":"v=spf1 a:museum."}],"e6.example.com":[{"SPF":"v=spf1 a//33 -all"}],"e6a.example.com":[{"SPF":"v=spf1 a/33 -all"}],"e7.example.com":[{"SPF":"v=spf1 a//129 -all"}],"e8.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24//64 -all"}],"e8e.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24/64 -all"}],"e8a.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24 -all"}],"e8b.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a//64 -all"}],"e9.example.com":[{"SPF":"v=spf1 a:example.com:8080"}],"e10.example.com":[{"SPF":"v=spf1 a:foo.example.com/24"}],"foo.example.com":[{"A":"1.1.1.1"},{"A":"1.2.3.5"}],"e11.example.com":[{"SPF":"v=spf1 a:foo:bar/baz.example.com"}],"foo:bar/baz.example.com":[{"A":"1.2.3.4"}],"e12.example.com":[{"SPF":"v=spf1 a:example.-com"}],"e13.example.com":[{"SPF":"v=spf1 a:"}],"e14.example.com":[{"SPF":"v=spf1 a:foo.example.xn--zckzah -all"}],"foo.example.xn--zckzah":[{"A":"1.2.3.4"}]}, failOnNoFake: true, helo: "mail.example.com"}
        let promise = spf.check_host('1234::1', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'FAIL');
        });
      });
      it('a-cidr6-0-ip4', function(){
        let email = 'foo@e2a.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 a/0 -all"}],"e2.example.com":[{"A":"1.1.1.1"},{"AAAA":"1234::2"},{"SPF":"v=spf1 a/0 -all"}],"e2a.example.com":[{"AAAA":"1234::1"},{"SPF":"v=spf1 a//0 -all"}],"e2b.example.com":[{"A":"1.1.1.1"},{"SPF":"v=spf1 a//0 -all"}],"ipv6.example.com":[{"AAAA":"1234::1"},{"A":"1.1.1.1"},{"SPF":"v=spf1 a -all"}],"e3.example.com":[{"SPF":"v=spf1 a:foo.example.com\u0000"}],"e4.example.com":[{"SPF":"v=spf1 a:111.222.33.44"}],"e5.example.com":[{"SPF":"v=spf1 a:abc.123"}],"e5a.example.com":[{"SPF":"v=spf1 a:museum"}],"e5b.example.com":[{"SPF":"v=spf1 a:museum."}],"e6.example.com":[{"SPF":"v=spf1 a//33 -all"}],"e6a.example.com":[{"SPF":"v=spf1 a/33 -all"}],"e7.example.com":[{"SPF":"v=spf1 a//129 -all"}],"e8.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24//64 -all"}],"e8e.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24/64 -all"}],"e8a.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24 -all"}],"e8b.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a//64 -all"}],"e9.example.com":[{"SPF":"v=spf1 a:example.com:8080"}],"e10.example.com":[{"SPF":"v=spf1 a:foo.example.com/24"}],"foo.example.com":[{"A":"1.1.1.1"},{"A":"1.2.3.5"}],"e11.example.com":[{"SPF":"v=spf1 a:foo:bar/baz.example.com"}],"foo:bar/baz.example.com":[{"A":"1.2.3.4"}],"e12.example.com":[{"SPF":"v=spf1 a:example.-com"}],"e13.example.com":[{"SPF":"v=spf1 a:"}],"e14.example.com":[{"SPF":"v=spf1 a:foo.example.xn--zckzah -all"}],"foo.example.xn--zckzah":[{"A":"1.2.3.4"}]}, failOnNoFake: true, helo: "mail.example.com"}
        let promise = spf.check_host('1.2.3.4', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'FAIL');
        });
      });
      it('a-cidr6-0-ip4mapped', function(){
        let email = 'foo@e2a.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 a/0 -all"}],"e2.example.com":[{"A":"1.1.1.1"},{"AAAA":"1234::2"},{"SPF":"v=spf1 a/0 -all"}],"e2a.example.com":[{"AAAA":"1234::1"},{"SPF":"v=spf1 a//0 -all"}],"e2b.example.com":[{"A":"1.1.1.1"},{"SPF":"v=spf1 a//0 -all"}],"ipv6.example.com":[{"AAAA":"1234::1"},{"A":"1.1.1.1"},{"SPF":"v=spf1 a -all"}],"e3.example.com":[{"SPF":"v=spf1 a:foo.example.com\u0000"}],"e4.example.com":[{"SPF":"v=spf1 a:111.222.33.44"}],"e5.example.com":[{"SPF":"v=spf1 a:abc.123"}],"e5a.example.com":[{"SPF":"v=spf1 a:museum"}],"e5b.example.com":[{"SPF":"v=spf1 a:museum."}],"e6.example.com":[{"SPF":"v=spf1 a//33 -all"}],"e6a.example.com":[{"SPF":"v=spf1 a/33 -all"}],"e7.example.com":[{"SPF":"v=spf1 a//129 -all"}],"e8.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24//64 -all"}],"e8e.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24/64 -all"}],"e8a.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24 -all"}],"e8b.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a//64 -all"}],"e9.example.com":[{"SPF":"v=spf1 a:example.com:8080"}],"e10.example.com":[{"SPF":"v=spf1 a:foo.example.com/24"}],"foo.example.com":[{"A":"1.1.1.1"},{"A":"1.2.3.5"}],"e11.example.com":[{"SPF":"v=spf1 a:foo:bar/baz.example.com"}],"foo:bar/baz.example.com":[{"A":"1.2.3.4"}],"e12.example.com":[{"SPF":"v=spf1 a:example.-com"}],"e13.example.com":[{"SPF":"v=spf1 a:"}],"e14.example.com":[{"SPF":"v=spf1 a:foo.example.xn--zckzah -all"}],"foo.example.xn--zckzah":[{"A":"1.2.3.4"}]}, failOnNoFake: true, helo: "mail.example.com"}
        let promise = spf.check_host('::FFFF:1.2.3.4', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'FAIL');
        });
      });
      it('a-cidr6-0-ip6', function(){
        let email = 'foo@e2a.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 a/0 -all"}],"e2.example.com":[{"A":"1.1.1.1"},{"AAAA":"1234::2"},{"SPF":"v=spf1 a/0 -all"}],"e2a.example.com":[{"AAAA":"1234::1"},{"SPF":"v=spf1 a//0 -all"}],"e2b.example.com":[{"A":"1.1.1.1"},{"SPF":"v=spf1 a//0 -all"}],"ipv6.example.com":[{"AAAA":"1234::1"},{"A":"1.1.1.1"},{"SPF":"v=spf1 a -all"}],"e3.example.com":[{"SPF":"v=spf1 a:foo.example.com\u0000"}],"e4.example.com":[{"SPF":"v=spf1 a:111.222.33.44"}],"e5.example.com":[{"SPF":"v=spf1 a:abc.123"}],"e5a.example.com":[{"SPF":"v=spf1 a:museum"}],"e5b.example.com":[{"SPF":"v=spf1 a:museum."}],"e6.example.com":[{"SPF":"v=spf1 a//33 -all"}],"e6a.example.com":[{"SPF":"v=spf1 a/33 -all"}],"e7.example.com":[{"SPF":"v=spf1 a//129 -all"}],"e8.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24//64 -all"}],"e8e.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24/64 -all"}],"e8a.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24 -all"}],"e8b.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a//64 -all"}],"e9.example.com":[{"SPF":"v=spf1 a:example.com:8080"}],"e10.example.com":[{"SPF":"v=spf1 a:foo.example.com/24"}],"foo.example.com":[{"A":"1.1.1.1"},{"A":"1.2.3.5"}],"e11.example.com":[{"SPF":"v=spf1 a:foo:bar/baz.example.com"}],"foo:bar/baz.example.com":[{"A":"1.2.3.4"}],"e12.example.com":[{"SPF":"v=spf1 a:example.-com"}],"e13.example.com":[{"SPF":"v=spf1 a:"}],"e14.example.com":[{"SPF":"v=spf1 a:foo.example.xn--zckzah -all"}],"foo.example.xn--zckzah":[{"A":"1.2.3.4"}]}, failOnNoFake: true, helo: "mail.example.com"}
        let promise = spf.check_host('1234::1', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'PASS');
        });
      });
      it('a-ip6-dualstack', function(){
        let email = 'foo@ipv6.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 a/0 -all"}],"e2.example.com":[{"A":"1.1.1.1"},{"AAAA":"1234::2"},{"SPF":"v=spf1 a/0 -all"}],"e2a.example.com":[{"AAAA":"1234::1"},{"SPF":"v=spf1 a//0 -all"}],"e2b.example.com":[{"A":"1.1.1.1"},{"SPF":"v=spf1 a//0 -all"}],"ipv6.example.com":[{"AAAA":"1234::1"},{"A":"1.1.1.1"},{"SPF":"v=spf1 a -all"}],"e3.example.com":[{"SPF":"v=spf1 a:foo.example.com\u0000"}],"e4.example.com":[{"SPF":"v=spf1 a:111.222.33.44"}],"e5.example.com":[{"SPF":"v=spf1 a:abc.123"}],"e5a.example.com":[{"SPF":"v=spf1 a:museum"}],"e5b.example.com":[{"SPF":"v=spf1 a:museum."}],"e6.example.com":[{"SPF":"v=spf1 a//33 -all"}],"e6a.example.com":[{"SPF":"v=spf1 a/33 -all"}],"e7.example.com":[{"SPF":"v=spf1 a//129 -all"}],"e8.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24//64 -all"}],"e8e.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24/64 -all"}],"e8a.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24 -all"}],"e8b.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a//64 -all"}],"e9.example.com":[{"SPF":"v=spf1 a:example.com:8080"}],"e10.example.com":[{"SPF":"v=spf1 a:foo.example.com/24"}],"foo.example.com":[{"A":"1.1.1.1"},{"A":"1.2.3.5"}],"e11.example.com":[{"SPF":"v=spf1 a:foo:bar/baz.example.com"}],"foo:bar/baz.example.com":[{"A":"1.2.3.4"}],"e12.example.com":[{"SPF":"v=spf1 a:example.-com"}],"e13.example.com":[{"SPF":"v=spf1 a:"}],"e14.example.com":[{"SPF":"v=spf1 a:foo.example.xn--zckzah -all"}],"foo.example.xn--zckzah":[{"A":"1.2.3.4"}]}, failOnNoFake: true, helo: "mail.example.com"}
        let promise = spf.check_host('1234::1', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'PASS');
        });
      });
      it('a-cidr6-0-nxdomain', function(){
        let email = 'foo@e2b.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 a/0 -all"}],"e2.example.com":[{"A":"1.1.1.1"},{"AAAA":"1234::2"},{"SPF":"v=spf1 a/0 -all"}],"e2a.example.com":[{"AAAA":"1234::1"},{"SPF":"v=spf1 a//0 -all"}],"e2b.example.com":[{"A":"1.1.1.1"},{"SPF":"v=spf1 a//0 -all"}],"ipv6.example.com":[{"AAAA":"1234::1"},{"A":"1.1.1.1"},{"SPF":"v=spf1 a -all"}],"e3.example.com":[{"SPF":"v=spf1 a:foo.example.com\u0000"}],"e4.example.com":[{"SPF":"v=spf1 a:111.222.33.44"}],"e5.example.com":[{"SPF":"v=spf1 a:abc.123"}],"e5a.example.com":[{"SPF":"v=spf1 a:museum"}],"e5b.example.com":[{"SPF":"v=spf1 a:museum."}],"e6.example.com":[{"SPF":"v=spf1 a//33 -all"}],"e6a.example.com":[{"SPF":"v=spf1 a/33 -all"}],"e7.example.com":[{"SPF":"v=spf1 a//129 -all"}],"e8.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24//64 -all"}],"e8e.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24/64 -all"}],"e8a.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24 -all"}],"e8b.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a//64 -all"}],"e9.example.com":[{"SPF":"v=spf1 a:example.com:8080"}],"e10.example.com":[{"SPF":"v=spf1 a:foo.example.com/24"}],"foo.example.com":[{"A":"1.1.1.1"},{"A":"1.2.3.5"}],"e11.example.com":[{"SPF":"v=spf1 a:foo:bar/baz.example.com"}],"foo:bar/baz.example.com":[{"A":"1.2.3.4"}],"e12.example.com":[{"SPF":"v=spf1 a:example.-com"}],"e13.example.com":[{"SPF":"v=spf1 a:"}],"e14.example.com":[{"SPF":"v=spf1 a:foo.example.xn--zckzah -all"}],"foo.example.xn--zckzah":[{"A":"1.2.3.4"}]}, failOnNoFake: true, helo: "mail.example.com"}
        let promise = spf.check_host('1234::1', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'FAIL');
        });
      });
      it('a-null', function(){
        let email = 'foo@e3.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 a/0 -all"}],"e2.example.com":[{"A":"1.1.1.1"},{"AAAA":"1234::2"},{"SPF":"v=spf1 a/0 -all"}],"e2a.example.com":[{"AAAA":"1234::1"},{"SPF":"v=spf1 a//0 -all"}],"e2b.example.com":[{"A":"1.1.1.1"},{"SPF":"v=spf1 a//0 -all"}],"ipv6.example.com":[{"AAAA":"1234::1"},{"A":"1.1.1.1"},{"SPF":"v=spf1 a -all"}],"e3.example.com":[{"SPF":"v=spf1 a:foo.example.com\u0000"}],"e4.example.com":[{"SPF":"v=spf1 a:111.222.33.44"}],"e5.example.com":[{"SPF":"v=spf1 a:abc.123"}],"e5a.example.com":[{"SPF":"v=spf1 a:museum"}],"e5b.example.com":[{"SPF":"v=spf1 a:museum."}],"e6.example.com":[{"SPF":"v=spf1 a//33 -all"}],"e6a.example.com":[{"SPF":"v=spf1 a/33 -all"}],"e7.example.com":[{"SPF":"v=spf1 a//129 -all"}],"e8.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24//64 -all"}],"e8e.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24/64 -all"}],"e8a.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24 -all"}],"e8b.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a//64 -all"}],"e9.example.com":[{"SPF":"v=spf1 a:example.com:8080"}],"e10.example.com":[{"SPF":"v=spf1 a:foo.example.com/24"}],"foo.example.com":[{"A":"1.1.1.1"},{"A":"1.2.3.5"}],"e11.example.com":[{"SPF":"v=spf1 a:foo:bar/baz.example.com"}],"foo:bar/baz.example.com":[{"A":"1.2.3.4"}],"e12.example.com":[{"SPF":"v=spf1 a:example.-com"}],"e13.example.com":[{"SPF":"v=spf1 a:"}],"e14.example.com":[{"SPF":"v=spf1 a:foo.example.xn--zckzah -all"}],"foo.example.xn--zckzah":[{"A":"1.2.3.4"}]}, failOnNoFake: true, helo: "mail.example.com"}
        let promise = spf.check_host('1.2.3.5', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'PERMERROR');
        });
      });
      it('a-numeric', function(){
        let email = 'foo@e4.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 a/0 -all"}],"e2.example.com":[{"A":"1.1.1.1"},{"AAAA":"1234::2"},{"SPF":"v=spf1 a/0 -all"}],"e2a.example.com":[{"AAAA":"1234::1"},{"SPF":"v=spf1 a//0 -all"}],"e2b.example.com":[{"A":"1.1.1.1"},{"SPF":"v=spf1 a//0 -all"}],"ipv6.example.com":[{"AAAA":"1234::1"},{"A":"1.1.1.1"},{"SPF":"v=spf1 a -all"}],"e3.example.com":[{"SPF":"v=spf1 a:foo.example.com\u0000"}],"e4.example.com":[{"SPF":"v=spf1 a:111.222.33.44"}],"e5.example.com":[{"SPF":"v=spf1 a:abc.123"}],"e5a.example.com":[{"SPF":"v=spf1 a:museum"}],"e5b.example.com":[{"SPF":"v=spf1 a:museum."}],"e6.example.com":[{"SPF":"v=spf1 a//33 -all"}],"e6a.example.com":[{"SPF":"v=spf1 a/33 -all"}],"e7.example.com":[{"SPF":"v=spf1 a//129 -all"}],"e8.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24//64 -all"}],"e8e.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24/64 -all"}],"e8a.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24 -all"}],"e8b.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a//64 -all"}],"e9.example.com":[{"SPF":"v=spf1 a:example.com:8080"}],"e10.example.com":[{"SPF":"v=spf1 a:foo.example.com/24"}],"foo.example.com":[{"A":"1.1.1.1"},{"A":"1.2.3.5"}],"e11.example.com":[{"SPF":"v=spf1 a:foo:bar/baz.example.com"}],"foo:bar/baz.example.com":[{"A":"1.2.3.4"}],"e12.example.com":[{"SPF":"v=spf1 a:example.-com"}],"e13.example.com":[{"SPF":"v=spf1 a:"}],"e14.example.com":[{"SPF":"v=spf1 a:foo.example.xn--zckzah -all"}],"foo.example.xn--zckzah":[{"A":"1.2.3.4"}]}, failOnNoFake: true, helo: "mail.example.com"}
        let promise = spf.check_host('1.2.3.4', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'PERMERROR');
        });
      });
      it('a-numeric-toplabel', function(){
        let email = 'foo@e5.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 a/0 -all"}],"e2.example.com":[{"A":"1.1.1.1"},{"AAAA":"1234::2"},{"SPF":"v=spf1 a/0 -all"}],"e2a.example.com":[{"AAAA":"1234::1"},{"SPF":"v=spf1 a//0 -all"}],"e2b.example.com":[{"A":"1.1.1.1"},{"SPF":"v=spf1 a//0 -all"}],"ipv6.example.com":[{"AAAA":"1234::1"},{"A":"1.1.1.1"},{"SPF":"v=spf1 a -all"}],"e3.example.com":[{"SPF":"v=spf1 a:foo.example.com\u0000"}],"e4.example.com":[{"SPF":"v=spf1 a:111.222.33.44"}],"e5.example.com":[{"SPF":"v=spf1 a:abc.123"}],"e5a.example.com":[{"SPF":"v=spf1 a:museum"}],"e5b.example.com":[{"SPF":"v=spf1 a:museum."}],"e6.example.com":[{"SPF":"v=spf1 a//33 -all"}],"e6a.example.com":[{"SPF":"v=spf1 a/33 -all"}],"e7.example.com":[{"SPF":"v=spf1 a//129 -all"}],"e8.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24//64 -all"}],"e8e.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24/64 -all"}],"e8a.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24 -all"}],"e8b.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a//64 -all"}],"e9.example.com":[{"SPF":"v=spf1 a:example.com:8080"}],"e10.example.com":[{"SPF":"v=spf1 a:foo.example.com/24"}],"foo.example.com":[{"A":"1.1.1.1"},{"A":"1.2.3.5"}],"e11.example.com":[{"SPF":"v=spf1 a:foo:bar/baz.example.com"}],"foo:bar/baz.example.com":[{"A":"1.2.3.4"}],"e12.example.com":[{"SPF":"v=spf1 a:example.-com"}],"e13.example.com":[{"SPF":"v=spf1 a:"}],"e14.example.com":[{"SPF":"v=spf1 a:foo.example.xn--zckzah -all"}],"foo.example.xn--zckzah":[{"A":"1.2.3.4"}]}, failOnNoFake: true, helo: "mail.example.com"}
        let promise = spf.check_host('1.2.3.4', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'PERMERROR');
        });
      });
      it('a-dash-in-toplabel', function(){
        let email = 'foo@e14.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 a/0 -all"}],"e2.example.com":[{"A":"1.1.1.1"},{"AAAA":"1234::2"},{"SPF":"v=spf1 a/0 -all"}],"e2a.example.com":[{"AAAA":"1234::1"},{"SPF":"v=spf1 a//0 -all"}],"e2b.example.com":[{"A":"1.1.1.1"},{"SPF":"v=spf1 a//0 -all"}],"ipv6.example.com":[{"AAAA":"1234::1"},{"A":"1.1.1.1"},{"SPF":"v=spf1 a -all"}],"e3.example.com":[{"SPF":"v=spf1 a:foo.example.com\u0000"}],"e4.example.com":[{"SPF":"v=spf1 a:111.222.33.44"}],"e5.example.com":[{"SPF":"v=spf1 a:abc.123"}],"e5a.example.com":[{"SPF":"v=spf1 a:museum"}],"e5b.example.com":[{"SPF":"v=spf1 a:museum."}],"e6.example.com":[{"SPF":"v=spf1 a//33 -all"}],"e6a.example.com":[{"SPF":"v=spf1 a/33 -all"}],"e7.example.com":[{"SPF":"v=spf1 a//129 -all"}],"e8.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24//64 -all"}],"e8e.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24/64 -all"}],"e8a.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24 -all"}],"e8b.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a//64 -all"}],"e9.example.com":[{"SPF":"v=spf1 a:example.com:8080"}],"e10.example.com":[{"SPF":"v=spf1 a:foo.example.com/24"}],"foo.example.com":[{"A":"1.1.1.1"},{"A":"1.2.3.5"}],"e11.example.com":[{"SPF":"v=spf1 a:foo:bar/baz.example.com"}],"foo:bar/baz.example.com":[{"A":"1.2.3.4"}],"e12.example.com":[{"SPF":"v=spf1 a:example.-com"}],"e13.example.com":[{"SPF":"v=spf1 a:"}],"e14.example.com":[{"SPF":"v=spf1 a:foo.example.xn--zckzah -all"}],"foo.example.xn--zckzah":[{"A":"1.2.3.4"}]}, failOnNoFake: true, helo: "mail.example.com"}
        let promise = spf.check_host('1.2.3.4', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'PASS');
        });
      });
      it('a-bad-toplabel', function(){
        let email = 'foo@e12.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 a/0 -all"}],"e2.example.com":[{"A":"1.1.1.1"},{"AAAA":"1234::2"},{"SPF":"v=spf1 a/0 -all"}],"e2a.example.com":[{"AAAA":"1234::1"},{"SPF":"v=spf1 a//0 -all"}],"e2b.example.com":[{"A":"1.1.1.1"},{"SPF":"v=spf1 a//0 -all"}],"ipv6.example.com":[{"AAAA":"1234::1"},{"A":"1.1.1.1"},{"SPF":"v=spf1 a -all"}],"e3.example.com":[{"SPF":"v=spf1 a:foo.example.com\u0000"}],"e4.example.com":[{"SPF":"v=spf1 a:111.222.33.44"}],"e5.example.com":[{"SPF":"v=spf1 a:abc.123"}],"e5a.example.com":[{"SPF":"v=spf1 a:museum"}],"e5b.example.com":[{"SPF":"v=spf1 a:museum."}],"e6.example.com":[{"SPF":"v=spf1 a//33 -all"}],"e6a.example.com":[{"SPF":"v=spf1 a/33 -all"}],"e7.example.com":[{"SPF":"v=spf1 a//129 -all"}],"e8.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24//64 -all"}],"e8e.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24/64 -all"}],"e8a.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24 -all"}],"e8b.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a//64 -all"}],"e9.example.com":[{"SPF":"v=spf1 a:example.com:8080"}],"e10.example.com":[{"SPF":"v=spf1 a:foo.example.com/24"}],"foo.example.com":[{"A":"1.1.1.1"},{"A":"1.2.3.5"}],"e11.example.com":[{"SPF":"v=spf1 a:foo:bar/baz.example.com"}],"foo:bar/baz.example.com":[{"A":"1.2.3.4"}],"e12.example.com":[{"SPF":"v=spf1 a:example.-com"}],"e13.example.com":[{"SPF":"v=spf1 a:"}],"e14.example.com":[{"SPF":"v=spf1 a:foo.example.xn--zckzah -all"}],"foo.example.xn--zckzah":[{"A":"1.2.3.4"}]}, failOnNoFake: true, helo: "mail.example.com"}
        let promise = spf.check_host('1.2.3.4', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'PERMERROR');
        });
      });
      it('a-only-toplabel', function(){
        let email = 'foo@e5a.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 a/0 -all"}],"e2.example.com":[{"A":"1.1.1.1"},{"AAAA":"1234::2"},{"SPF":"v=spf1 a/0 -all"}],"e2a.example.com":[{"AAAA":"1234::1"},{"SPF":"v=spf1 a//0 -all"}],"e2b.example.com":[{"A":"1.1.1.1"},{"SPF":"v=spf1 a//0 -all"}],"ipv6.example.com":[{"AAAA":"1234::1"},{"A":"1.1.1.1"},{"SPF":"v=spf1 a -all"}],"e3.example.com":[{"SPF":"v=spf1 a:foo.example.com\u0000"}],"e4.example.com":[{"SPF":"v=spf1 a:111.222.33.44"}],"e5.example.com":[{"SPF":"v=spf1 a:abc.123"}],"e5a.example.com":[{"SPF":"v=spf1 a:museum"}],"e5b.example.com":[{"SPF":"v=spf1 a:museum."}],"e6.example.com":[{"SPF":"v=spf1 a//33 -all"}],"e6a.example.com":[{"SPF":"v=spf1 a/33 -all"}],"e7.example.com":[{"SPF":"v=spf1 a//129 -all"}],"e8.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24//64 -all"}],"e8e.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24/64 -all"}],"e8a.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24 -all"}],"e8b.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a//64 -all"}],"e9.example.com":[{"SPF":"v=spf1 a:example.com:8080"}],"e10.example.com":[{"SPF":"v=spf1 a:foo.example.com/24"}],"foo.example.com":[{"A":"1.1.1.1"},{"A":"1.2.3.5"}],"e11.example.com":[{"SPF":"v=spf1 a:foo:bar/baz.example.com"}],"foo:bar/baz.example.com":[{"A":"1.2.3.4"}],"e12.example.com":[{"SPF":"v=spf1 a:example.-com"}],"e13.example.com":[{"SPF":"v=spf1 a:"}],"e14.example.com":[{"SPF":"v=spf1 a:foo.example.xn--zckzah -all"}],"foo.example.xn--zckzah":[{"A":"1.2.3.4"}]}, failOnNoFake: true, helo: "mail.example.com"}
        let promise = spf.check_host('1.2.3.4', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'PERMERROR');
        });
      });
      it('a-only-toplabel-trailing-dot', function(){
        let email = 'foo@e5b.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 a/0 -all"}],"e2.example.com":[{"A":"1.1.1.1"},{"AAAA":"1234::2"},{"SPF":"v=spf1 a/0 -all"}],"e2a.example.com":[{"AAAA":"1234::1"},{"SPF":"v=spf1 a//0 -all"}],"e2b.example.com":[{"A":"1.1.1.1"},{"SPF":"v=spf1 a//0 -all"}],"ipv6.example.com":[{"AAAA":"1234::1"},{"A":"1.1.1.1"},{"SPF":"v=spf1 a -all"}],"e3.example.com":[{"SPF":"v=spf1 a:foo.example.com\u0000"}],"e4.example.com":[{"SPF":"v=spf1 a:111.222.33.44"}],"e5.example.com":[{"SPF":"v=spf1 a:abc.123"}],"e5a.example.com":[{"SPF":"v=spf1 a:museum"}],"e5b.example.com":[{"SPF":"v=spf1 a:museum."}],"e6.example.com":[{"SPF":"v=spf1 a//33 -all"}],"e6a.example.com":[{"SPF":"v=spf1 a/33 -all"}],"e7.example.com":[{"SPF":"v=spf1 a//129 -all"}],"e8.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24//64 -all"}],"e8e.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24/64 -all"}],"e8a.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24 -all"}],"e8b.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a//64 -all"}],"e9.example.com":[{"SPF":"v=spf1 a:example.com:8080"}],"e10.example.com":[{"SPF":"v=spf1 a:foo.example.com/24"}],"foo.example.com":[{"A":"1.1.1.1"},{"A":"1.2.3.5"}],"e11.example.com":[{"SPF":"v=spf1 a:foo:bar/baz.example.com"}],"foo:bar/baz.example.com":[{"A":"1.2.3.4"}],"e12.example.com":[{"SPF":"v=spf1 a:example.-com"}],"e13.example.com":[{"SPF":"v=spf1 a:"}],"e14.example.com":[{"SPF":"v=spf1 a:foo.example.xn--zckzah -all"}],"foo.example.xn--zckzah":[{"A":"1.2.3.4"}]}, failOnNoFake: true, helo: "mail.example.com"}
        let promise = spf.check_host('1.2.3.4', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'PERMERROR');
        });
      });
      it('a-colon-domain', function(){
        let email = 'foo@e11.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 a/0 -all"}],"e2.example.com":[{"A":"1.1.1.1"},{"AAAA":"1234::2"},{"SPF":"v=spf1 a/0 -all"}],"e2a.example.com":[{"AAAA":"1234::1"},{"SPF":"v=spf1 a//0 -all"}],"e2b.example.com":[{"A":"1.1.1.1"},{"SPF":"v=spf1 a//0 -all"}],"ipv6.example.com":[{"AAAA":"1234::1"},{"A":"1.1.1.1"},{"SPF":"v=spf1 a -all"}],"e3.example.com":[{"SPF":"v=spf1 a:foo.example.com\u0000"}],"e4.example.com":[{"SPF":"v=spf1 a:111.222.33.44"}],"e5.example.com":[{"SPF":"v=spf1 a:abc.123"}],"e5a.example.com":[{"SPF":"v=spf1 a:museum"}],"e5b.example.com":[{"SPF":"v=spf1 a:museum."}],"e6.example.com":[{"SPF":"v=spf1 a//33 -all"}],"e6a.example.com":[{"SPF":"v=spf1 a/33 -all"}],"e7.example.com":[{"SPF":"v=spf1 a//129 -all"}],"e8.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24//64 -all"}],"e8e.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24/64 -all"}],"e8a.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24 -all"}],"e8b.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a//64 -all"}],"e9.example.com":[{"SPF":"v=spf1 a:example.com:8080"}],"e10.example.com":[{"SPF":"v=spf1 a:foo.example.com/24"}],"foo.example.com":[{"A":"1.1.1.1"},{"A":"1.2.3.5"}],"e11.example.com":[{"SPF":"v=spf1 a:foo:bar/baz.example.com"}],"foo:bar/baz.example.com":[{"A":"1.2.3.4"}],"e12.example.com":[{"SPF":"v=spf1 a:example.-com"}],"e13.example.com":[{"SPF":"v=spf1 a:"}],"e14.example.com":[{"SPF":"v=spf1 a:foo.example.xn--zckzah -all"}],"foo.example.xn--zckzah":[{"A":"1.2.3.4"}]}, failOnNoFake: true, helo: "mail.example.com"}
        let promise = spf.check_host('1.2.3.4', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'PASS');
        });
      });
      it('a-colon-domain-ip4mapped', function(){
        let email = 'foo@e11.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 a/0 -all"}],"e2.example.com":[{"A":"1.1.1.1"},{"AAAA":"1234::2"},{"SPF":"v=spf1 a/0 -all"}],"e2a.example.com":[{"AAAA":"1234::1"},{"SPF":"v=spf1 a//0 -all"}],"e2b.example.com":[{"A":"1.1.1.1"},{"SPF":"v=spf1 a//0 -all"}],"ipv6.example.com":[{"AAAA":"1234::1"},{"A":"1.1.1.1"},{"SPF":"v=spf1 a -all"}],"e3.example.com":[{"SPF":"v=spf1 a:foo.example.com\u0000"}],"e4.example.com":[{"SPF":"v=spf1 a:111.222.33.44"}],"e5.example.com":[{"SPF":"v=spf1 a:abc.123"}],"e5a.example.com":[{"SPF":"v=spf1 a:museum"}],"e5b.example.com":[{"SPF":"v=spf1 a:museum."}],"e6.example.com":[{"SPF":"v=spf1 a//33 -all"}],"e6a.example.com":[{"SPF":"v=spf1 a/33 -all"}],"e7.example.com":[{"SPF":"v=spf1 a//129 -all"}],"e8.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24//64 -all"}],"e8e.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24/64 -all"}],"e8a.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24 -all"}],"e8b.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a//64 -all"}],"e9.example.com":[{"SPF":"v=spf1 a:example.com:8080"}],"e10.example.com":[{"SPF":"v=spf1 a:foo.example.com/24"}],"foo.example.com":[{"A":"1.1.1.1"},{"A":"1.2.3.5"}],"e11.example.com":[{"SPF":"v=spf1 a:foo:bar/baz.example.com"}],"foo:bar/baz.example.com":[{"A":"1.2.3.4"}],"e12.example.com":[{"SPF":"v=spf1 a:example.-com"}],"e13.example.com":[{"SPF":"v=spf1 a:"}],"e14.example.com":[{"SPF":"v=spf1 a:foo.example.xn--zckzah -all"}],"foo.example.xn--zckzah":[{"A":"1.2.3.4"}]}, failOnNoFake: true, helo: "mail.example.com"}
        let promise = spf.check_host('::FFFF:1.2.3.4', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'PASS');
        });
      });
      it('a-empty-domain', function(){
        let email = 'foo@e13.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 a/0 -all"}],"e2.example.com":[{"A":"1.1.1.1"},{"AAAA":"1234::2"},{"SPF":"v=spf1 a/0 -all"}],"e2a.example.com":[{"AAAA":"1234::1"},{"SPF":"v=spf1 a//0 -all"}],"e2b.example.com":[{"A":"1.1.1.1"},{"SPF":"v=spf1 a//0 -all"}],"ipv6.example.com":[{"AAAA":"1234::1"},{"A":"1.1.1.1"},{"SPF":"v=spf1 a -all"}],"e3.example.com":[{"SPF":"v=spf1 a:foo.example.com\u0000"}],"e4.example.com":[{"SPF":"v=spf1 a:111.222.33.44"}],"e5.example.com":[{"SPF":"v=spf1 a:abc.123"}],"e5a.example.com":[{"SPF":"v=spf1 a:museum"}],"e5b.example.com":[{"SPF":"v=spf1 a:museum."}],"e6.example.com":[{"SPF":"v=spf1 a//33 -all"}],"e6a.example.com":[{"SPF":"v=spf1 a/33 -all"}],"e7.example.com":[{"SPF":"v=spf1 a//129 -all"}],"e8.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24//64 -all"}],"e8e.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24/64 -all"}],"e8a.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a/24 -all"}],"e8b.example.com":[{"A":"1.2.3.5"},{"AAAA":"2001:db8:1234::dead:beef"},{"SPF":"v=spf1 a//64 -all"}],"e9.example.com":[{"SPF":"v=spf1 a:example.com:8080"}],"e10.example.com":[{"SPF":"v=spf1 a:foo.example.com/24"}],"foo.example.com":[{"A":"1.1.1.1"},{"A":"1.2.3.5"}],"e11.example.com":[{"SPF":"v=spf1 a:foo:bar/baz.example.com"}],"foo:bar/baz.example.com":[{"A":"1.2.3.4"}],"e12.example.com":[{"SPF":"v=spf1 a:example.-com"}],"e13.example.com":[{"SPF":"v=spf1 a:"}],"e14.example.com":[{"SPF":"v=spf1 a:foo.example.xn--zckzah -all"}],"foo.example.xn--zckzah":[{"A":"1.2.3.4"}]}, failOnNoFake: true, helo: "mail.example.com"}
        let promise = spf.check_host('1.2.3.4', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'PERMERROR');
        });
      });
    });
    describe('Include mechanism semantics and syntax', function(){
      it('include-fail', function(){
        let email = 'foo@e1.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"ip5.example.com":[{"SPF":"v=spf1 ip4:1.2.3.5 -all"}],"ip6.example.com":[{"SPF":"v=spf1 ip4:1.2.3.6 ~all"}],"ip7.example.com":[{"SPF":"v=spf1 ip4:1.2.3.7 ?all"}],"ip8.example.com":["TIMEOUT"],"erehwon.example.com":[{"TXT":"v=spfl am not an SPF record"}],"e1.example.com":[{"SPF":"v=spf1 include:ip5.example.com ~all"}],"e2.example.com":[{"SPF":"v=spf1 include:ip6.example.com all"}],"e3.example.com":[{"SPF":"v=spf1 include:ip7.example.com -all"}],"e4.example.com":[{"SPF":"v=spf1 include:ip8.example.com -all"}],"e5.example.com":[{"SPF":"v=spf1 include:e6.example.com -all"}],"e6.example.com":[{"SPF":"v=spf1 include +all"}],"e7.example.com":[{"SPF":"v=spf1 include:erehwon.example.com -all"}],"e8.example.com":[{"SPF":"v=spf1 include: -all"}],"e9.example.com":[{"SPF":"v=spf1 include:ip5.example.com/24 -all"}]}, failOnNoFake: true, helo: "mail.example.com"}
        let promise = spf.check_host('1.2.3.4', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'SOFTFAIL');
        });
      });
      it('include-softfail', function(){
        let email = 'foo@e2.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"ip5.example.com":[{"SPF":"v=spf1 ip4:1.2.3.5 -all"}],"ip6.example.com":[{"SPF":"v=spf1 ip4:1.2.3.6 ~all"}],"ip7.example.com":[{"SPF":"v=spf1 ip4:1.2.3.7 ?all"}],"ip8.example.com":["TIMEOUT"],"erehwon.example.com":[{"TXT":"v=spfl am not an SPF record"}],"e1.example.com":[{"SPF":"v=spf1 include:ip5.example.com ~all"}],"e2.example.com":[{"SPF":"v=spf1 include:ip6.example.com all"}],"e3.example.com":[{"SPF":"v=spf1 include:ip7.example.com -all"}],"e4.example.com":[{"SPF":"v=spf1 include:ip8.example.com -all"}],"e5.example.com":[{"SPF":"v=spf1 include:e6.example.com -all"}],"e6.example.com":[{"SPF":"v=spf1 include +all"}],"e7.example.com":[{"SPF":"v=spf1 include:erehwon.example.com -all"}],"e8.example.com":[{"SPF":"v=spf1 include: -all"}],"e9.example.com":[{"SPF":"v=spf1 include:ip5.example.com/24 -all"}]}, failOnNoFake: true, helo: "mail.example.com"}
        let promise = spf.check_host('1.2.3.4', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'PASS');
        });
      });
      it('include-neutral', function(){
        let email = 'foo@e3.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"ip5.example.com":[{"SPF":"v=spf1 ip4:1.2.3.5 -all"}],"ip6.example.com":[{"SPF":"v=spf1 ip4:1.2.3.6 ~all"}],"ip7.example.com":[{"SPF":"v=spf1 ip4:1.2.3.7 ?all"}],"ip8.example.com":["TIMEOUT"],"erehwon.example.com":[{"TXT":"v=spfl am not an SPF record"}],"e1.example.com":[{"SPF":"v=spf1 include:ip5.example.com ~all"}],"e2.example.com":[{"SPF":"v=spf1 include:ip6.example.com all"}],"e3.example.com":[{"SPF":"v=spf1 include:ip7.example.com -all"}],"e4.example.com":[{"SPF":"v=spf1 include:ip8.example.com -all"}],"e5.example.com":[{"SPF":"v=spf1 include:e6.example.com -all"}],"e6.example.com":[{"SPF":"v=spf1 include +all"}],"e7.example.com":[{"SPF":"v=spf1 include:erehwon.example.com -all"}],"e8.example.com":[{"SPF":"v=spf1 include: -all"}],"e9.example.com":[{"SPF":"v=spf1 include:ip5.example.com/24 -all"}]}, failOnNoFake: true, helo: "mail.example.com"}
        let promise = spf.check_host('1.2.3.4', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'FAIL');
        });
      });
      it('include-temperror', function(){
        let email = 'foo@e4.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"ip5.example.com":[{"SPF":"v=spf1 ip4:1.2.3.5 -all"}],"ip6.example.com":[{"SPF":"v=spf1 ip4:1.2.3.6 ~all"}],"ip7.example.com":[{"SPF":"v=spf1 ip4:1.2.3.7 ?all"}],"ip8.example.com":["TIMEOUT"],"erehwon.example.com":[{"TXT":"v=spfl am not an SPF record"}],"e1.example.com":[{"SPF":"v=spf1 include:ip5.example.com ~all"}],"e2.example.com":[{"SPF":"v=spf1 include:ip6.example.com all"}],"e3.example.com":[{"SPF":"v=spf1 include:ip7.example.com -all"}],"e4.example.com":[{"SPF":"v=spf1 include:ip8.example.com -all"}],"e5.example.com":[{"SPF":"v=spf1 include:e6.example.com -all"}],"e6.example.com":[{"SPF":"v=spf1 include +all"}],"e7.example.com":[{"SPF":"v=spf1 include:erehwon.example.com -all"}],"e8.example.com":[{"SPF":"v=spf1 include: -all"}],"e9.example.com":[{"SPF":"v=spf1 include:ip5.example.com/24 -all"}]}, failOnNoFake: true, helo: "mail.example.com"}
        let promise = spf.check_host('1.2.3.4', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'TEMPERROR');
        });
      });
      it('include-permerror', function(){
        let email = 'foo@e5.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"ip5.example.com":[{"SPF":"v=spf1 ip4:1.2.3.5 -all"}],"ip6.example.com":[{"SPF":"v=spf1 ip4:1.2.3.6 ~all"}],"ip7.example.com":[{"SPF":"v=spf1 ip4:1.2.3.7 ?all"}],"ip8.example.com":["TIMEOUT"],"erehwon.example.com":[{"TXT":"v=spfl am not an SPF record"}],"e1.example.com":[{"SPF":"v=spf1 include:ip5.example.com ~all"}],"e2.example.com":[{"SPF":"v=spf1 include:ip6.example.com all"}],"e3.example.com":[{"SPF":"v=spf1 include:ip7.example.com -all"}],"e4.example.com":[{"SPF":"v=spf1 include:ip8.example.com -all"}],"e5.example.com":[{"SPF":"v=spf1 include:e6.example.com -all"}],"e6.example.com":[{"SPF":"v=spf1 include +all"}],"e7.example.com":[{"SPF":"v=spf1 include:erehwon.example.com -all"}],"e8.example.com":[{"SPF":"v=spf1 include: -all"}],"e9.example.com":[{"SPF":"v=spf1 include:ip5.example.com/24 -all"}]}, failOnNoFake: true, helo: "mail.example.com"}
        let promise = spf.check_host('1.2.3.4', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'PERMERROR');
        });
      });
      it('include-syntax-error', function(){
        let email = 'foo@e6.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"ip5.example.com":[{"SPF":"v=spf1 ip4:1.2.3.5 -all"}],"ip6.example.com":[{"SPF":"v=spf1 ip4:1.2.3.6 ~all"}],"ip7.example.com":[{"SPF":"v=spf1 ip4:1.2.3.7 ?all"}],"ip8.example.com":["TIMEOUT"],"erehwon.example.com":[{"TXT":"v=spfl am not an SPF record"}],"e1.example.com":[{"SPF":"v=spf1 include:ip5.example.com ~all"}],"e2.example.com":[{"SPF":"v=spf1 include:ip6.example.com all"}],"e3.example.com":[{"SPF":"v=spf1 include:ip7.example.com -all"}],"e4.example.com":[{"SPF":"v=spf1 include:ip8.example.com -all"}],"e5.example.com":[{"SPF":"v=spf1 include:e6.example.com -all"}],"e6.example.com":[{"SPF":"v=spf1 include +all"}],"e7.example.com":[{"SPF":"v=spf1 include:erehwon.example.com -all"}],"e8.example.com":[{"SPF":"v=spf1 include: -all"}],"e9.example.com":[{"SPF":"v=spf1 include:ip5.example.com/24 -all"}]}, failOnNoFake: true, helo: "mail.example.com"}
        let promise = spf.check_host('1.2.3.4', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'PERMERROR');
        });
      });
      it('include-cidr', function(){
        let email = 'foo@e9.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"ip5.example.com":[{"SPF":"v=spf1 ip4:1.2.3.5 -all"}],"ip6.example.com":[{"SPF":"v=spf1 ip4:1.2.3.6 ~all"}],"ip7.example.com":[{"SPF":"v=spf1 ip4:1.2.3.7 ?all"}],"ip8.example.com":["TIMEOUT"],"erehwon.example.com":[{"TXT":"v=spfl am not an SPF record"}],"e1.example.com":[{"SPF":"v=spf1 include:ip5.example.com ~all"}],"e2.example.com":[{"SPF":"v=spf1 include:ip6.example.com all"}],"e3.example.com":[{"SPF":"v=spf1 include:ip7.example.com -all"}],"e4.example.com":[{"SPF":"v=spf1 include:ip8.example.com -all"}],"e5.example.com":[{"SPF":"v=spf1 include:e6.example.com -all"}],"e6.example.com":[{"SPF":"v=spf1 include +all"}],"e7.example.com":[{"SPF":"v=spf1 include:erehwon.example.com -all"}],"e8.example.com":[{"SPF":"v=spf1 include: -all"}],"e9.example.com":[{"SPF":"v=spf1 include:ip5.example.com/24 -all"}]}, failOnNoFake: true, helo: "mail.example.com"}
        let promise = spf.check_host('1.2.3.4', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'PERMERROR');
        });
      });
      it('include-none', function(){
        let email = 'foo@e7.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"ip5.example.com":[{"SPF":"v=spf1 ip4:1.2.3.5 -all"}],"ip6.example.com":[{"SPF":"v=spf1 ip4:1.2.3.6 ~all"}],"ip7.example.com":[{"SPF":"v=spf1 ip4:1.2.3.7 ?all"}],"ip8.example.com":["TIMEOUT"],"erehwon.example.com":[{"TXT":"v=spfl am not an SPF record"}],"e1.example.com":[{"SPF":"v=spf1 include:ip5.example.com ~all"}],"e2.example.com":[{"SPF":"v=spf1 include:ip6.example.com all"}],"e3.example.com":[{"SPF":"v=spf1 include:ip7.example.com -all"}],"e4.example.com":[{"SPF":"v=spf1 include:ip8.example.com -all"}],"e5.example.com":[{"SPF":"v=spf1 include:e6.example.com -all"}],"e6.example.com":[{"SPF":"v=spf1 include +all"}],"e7.example.com":[{"SPF":"v=spf1 include:erehwon.example.com -all"}],"e8.example.com":[{"SPF":"v=spf1 include: -all"}],"e9.example.com":[{"SPF":"v=spf1 include:ip5.example.com/24 -all"}]}, failOnNoFake: true, helo: "mail.example.com"}
        let promise = spf.check_host('1.2.3.4', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'PERMERROR');
        });
      });
      it('include-empty-domain', function(){
        let email = 'foo@e8.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"ip5.example.com":[{"SPF":"v=spf1 ip4:1.2.3.5 -all"}],"ip6.example.com":[{"SPF":"v=spf1 ip4:1.2.3.6 ~all"}],"ip7.example.com":[{"SPF":"v=spf1 ip4:1.2.3.7 ?all"}],"ip8.example.com":["TIMEOUT"],"erehwon.example.com":[{"TXT":"v=spfl am not an SPF record"}],"e1.example.com":[{"SPF":"v=spf1 include:ip5.example.com ~all"}],"e2.example.com":[{"SPF":"v=spf1 include:ip6.example.com all"}],"e3.example.com":[{"SPF":"v=spf1 include:ip7.example.com -all"}],"e4.example.com":[{"SPF":"v=spf1 include:ip8.example.com -all"}],"e5.example.com":[{"SPF":"v=spf1 include:e6.example.com -all"}],"e6.example.com":[{"SPF":"v=spf1 include +all"}],"e7.example.com":[{"SPF":"v=spf1 include:erehwon.example.com -all"}],"e8.example.com":[{"SPF":"v=spf1 include: -all"}],"e9.example.com":[{"SPF":"v=spf1 include:ip5.example.com/24 -all"}]}, failOnNoFake: true, helo: "mail.example.com"}
        let promise = spf.check_host('1.2.3.4', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'PERMERROR');
        });
      });
    });
    describe('MX mechanism syntax', function(){
      it('mx-cidr6', function(){
        let email = 'foo@e6.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"},{"MX":[0,""]},{"SPF":"v=spf1 mx"}],"e1.example.com":[{"SPF":"v=spf1 mx/0 -all"},{"MX":[0,"e1.example.com"]}],"e2.example.com":[{"A":"1.1.1.1"},{"AAAA":"1234::2"},{"MX":[0,"e2.example.com"]},{"SPF":"v=spf1 mx/0 -all"}],"e2a.example.com":[{"AAAA":"1234::1"},{"MX":[0,"e2a.example.com"]},{"SPF":"v=spf1 mx//0 -all"}],"e2b.example.com":[{"A":"1.1.1.1"},{"MX":[0,"e2b.example.com"]},{"SPF":"v=spf1 mx//0 -all"}],"e3.example.com":[{"SPF":"v=spf1 mx:foo.example.com\u0000"}],"e4.example.com":[{"SPF":"v=spf1 mx"},{"A":"1.2.3.4"}],"e5.example.com":[{"SPF":"v=spf1 mx:abc.123"}],"e6.example.com":[{"SPF":"v=spf1 mx//33 -all"}],"e6a.example.com":[{"SPF":"v=spf1 mx/33 -all"}],"e7.example.com":[{"SPF":"v=spf1 mx//129 -all"}],"e9.example.com":[{"SPF":"v=spf1 mx:example.com:8080"}],"e10.example.com":[{"SPF":"v=spf1 mx:foo.example.com/24"}],"foo.example.com":[{"MX":[0,"foo1.example.com"]}],"foo1.example.com":[{"A":"1.1.1.1"},{"A":"1.2.3.5"}],"e11.example.com":[{"SPF":"v=spf1 mx:foo:bar/baz.example.com"}],"foo:bar/baz.example.com":[{"MX":[0,"foo:bar/baz.example.com"]},{"A":"1.2.3.4"}],"e12.example.com":[{"SPF":"v=spf1 mx:example.-com"}],"e13.example.com":[{"SPF":"v=spf1 mx: -all"}]}, failOnNoFake: true, helo: "mail.example.com"}
        let promise = spf.check_host('1.2.3.4', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'FAIL');
        });
      });
      it('mx-bad-cidr4', function(){
        let email = 'foo@e6a.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"},{"MX":[0,""]},{"SPF":"v=spf1 mx"}],"e1.example.com":[{"SPF":"v=spf1 mx/0 -all"},{"MX":[0,"e1.example.com"]}],"e2.example.com":[{"A":"1.1.1.1"},{"AAAA":"1234::2"},{"MX":[0,"e2.example.com"]},{"SPF":"v=spf1 mx/0 -all"}],"e2a.example.com":[{"AAAA":"1234::1"},{"MX":[0,"e2a.example.com"]},{"SPF":"v=spf1 mx//0 -all"}],"e2b.example.com":[{"A":"1.1.1.1"},{"MX":[0,"e2b.example.com"]},{"SPF":"v=spf1 mx//0 -all"}],"e3.example.com":[{"SPF":"v=spf1 mx:foo.example.com\u0000"}],"e4.example.com":[{"SPF":"v=spf1 mx"},{"A":"1.2.3.4"}],"e5.example.com":[{"SPF":"v=spf1 mx:abc.123"}],"e6.example.com":[{"SPF":"v=spf1 mx//33 -all"}],"e6a.example.com":[{"SPF":"v=spf1 mx/33 -all"}],"e7.example.com":[{"SPF":"v=spf1 mx//129 -all"}],"e9.example.com":[{"SPF":"v=spf1 mx:example.com:8080"}],"e10.example.com":[{"SPF":"v=spf1 mx:foo.example.com/24"}],"foo.example.com":[{"MX":[0,"foo1.example.com"]}],"foo1.example.com":[{"A":"1.1.1.1"},{"A":"1.2.3.5"}],"e11.example.com":[{"SPF":"v=spf1 mx:foo:bar/baz.example.com"}],"foo:bar/baz.example.com":[{"MX":[0,"foo:bar/baz.example.com"]},{"A":"1.2.3.4"}],"e12.example.com":[{"SPF":"v=spf1 mx:example.-com"}],"e13.example.com":[{"SPF":"v=spf1 mx: -all"}]}, failOnNoFake: true, helo: "mail.example.com"}
        let promise = spf.check_host('1.2.3.4', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'PERMERROR');
        });
      });
      it('mx-bad-cidr6', function(){
        let email = 'foo@e7.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"},{"MX":[0,""]},{"SPF":"v=spf1 mx"}],"e1.example.com":[{"SPF":"v=spf1 mx/0 -all"},{"MX":[0,"e1.example.com"]}],"e2.example.com":[{"A":"1.1.1.1"},{"AAAA":"1234::2"},{"MX":[0,"e2.example.com"]},{"SPF":"v=spf1 mx/0 -all"}],"e2a.example.com":[{"AAAA":"1234::1"},{"MX":[0,"e2a.example.com"]},{"SPF":"v=spf1 mx//0 -all"}],"e2b.example.com":[{"A":"1.1.1.1"},{"MX":[0,"e2b.example.com"]},{"SPF":"v=spf1 mx//0 -all"}],"e3.example.com":[{"SPF":"v=spf1 mx:foo.example.com\u0000"}],"e4.example.com":[{"SPF":"v=spf1 mx"},{"A":"1.2.3.4"}],"e5.example.com":[{"SPF":"v=spf1 mx:abc.123"}],"e6.example.com":[{"SPF":"v=spf1 mx//33 -all"}],"e6a.example.com":[{"SPF":"v=spf1 mx/33 -all"}],"e7.example.com":[{"SPF":"v=spf1 mx//129 -all"}],"e9.example.com":[{"SPF":"v=spf1 mx:example.com:8080"}],"e10.example.com":[{"SPF":"v=spf1 mx:foo.example.com/24"}],"foo.example.com":[{"MX":[0,"foo1.example.com"]}],"foo1.example.com":[{"A":"1.1.1.1"},{"A":"1.2.3.5"}],"e11.example.com":[{"SPF":"v=spf1 mx:foo:bar/baz.example.com"}],"foo:bar/baz.example.com":[{"MX":[0,"foo:bar/baz.example.com"]},{"A":"1.2.3.4"}],"e12.example.com":[{"SPF":"v=spf1 mx:example.-com"}],"e13.example.com":[{"SPF":"v=spf1 mx: -all"}]}, failOnNoFake: true, helo: "mail.example.com"}
        let promise = spf.check_host('1.2.3.4', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'PERMERROR');
        });
      });
      it('mx-multi-ip1', function(){
        let email = 'foo@e10.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"},{"MX":[0,""]},{"SPF":"v=spf1 mx"}],"e1.example.com":[{"SPF":"v=spf1 mx/0 -all"},{"MX":[0,"e1.example.com"]}],"e2.example.com":[{"A":"1.1.1.1"},{"AAAA":"1234::2"},{"MX":[0,"e2.example.com"]},{"SPF":"v=spf1 mx/0 -all"}],"e2a.example.com":[{"AAAA":"1234::1"},{"MX":[0,"e2a.example.com"]},{"SPF":"v=spf1 mx//0 -all"}],"e2b.example.com":[{"A":"1.1.1.1"},{"MX":[0,"e2b.example.com"]},{"SPF":"v=spf1 mx//0 -all"}],"e3.example.com":[{"SPF":"v=spf1 mx:foo.example.com\u0000"}],"e4.example.com":[{"SPF":"v=spf1 mx"},{"A":"1.2.3.4"}],"e5.example.com":[{"SPF":"v=spf1 mx:abc.123"}],"e6.example.com":[{"SPF":"v=spf1 mx//33 -all"}],"e6a.example.com":[{"SPF":"v=spf1 mx/33 -all"}],"e7.example.com":[{"SPF":"v=spf1 mx//129 -all"}],"e9.example.com":[{"SPF":"v=spf1 mx:example.com:8080"}],"e10.example.com":[{"SPF":"v=spf1 mx:foo.example.com/24"}],"foo.example.com":[{"MX":[0,"foo1.example.com"]}],"foo1.example.com":[{"A":"1.1.1.1"},{"A":"1.2.3.5"}],"e11.example.com":[{"SPF":"v=spf1 mx:foo:bar/baz.example.com"}],"foo:bar/baz.example.com":[{"MX":[0,"foo:bar/baz.example.com"]},{"A":"1.2.3.4"}],"e12.example.com":[{"SPF":"v=spf1 mx:example.-com"}],"e13.example.com":[{"SPF":"v=spf1 mx: -all"}]}, failOnNoFake: true, helo: "mail.example.com"}
        let promise = spf.check_host('1.2.3.4', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'PASS');
        });
      });
      it('mx-multi-ip2', function(){
        let email = 'foo@e10.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"},{"MX":[0,""]},{"SPF":"v=spf1 mx"}],"e1.example.com":[{"SPF":"v=spf1 mx/0 -all"},{"MX":[0,"e1.example.com"]}],"e2.example.com":[{"A":"1.1.1.1"},{"AAAA":"1234::2"},{"MX":[0,"e2.example.com"]},{"SPF":"v=spf1 mx/0 -all"}],"e2a.example.com":[{"AAAA":"1234::1"},{"MX":[0,"e2a.example.com"]},{"SPF":"v=spf1 mx//0 -all"}],"e2b.example.com":[{"A":"1.1.1.1"},{"MX":[0,"e2b.example.com"]},{"SPF":"v=spf1 mx//0 -all"}],"e3.example.com":[{"SPF":"v=spf1 mx:foo.example.com\u0000"}],"e4.example.com":[{"SPF":"v=spf1 mx"},{"A":"1.2.3.4"}],"e5.example.com":[{"SPF":"v=spf1 mx:abc.123"}],"e6.example.com":[{"SPF":"v=spf1 mx//33 -all"}],"e6a.example.com":[{"SPF":"v=spf1 mx/33 -all"}],"e7.example.com":[{"SPF":"v=spf1 mx//129 -all"}],"e9.example.com":[{"SPF":"v=spf1 mx:example.com:8080"}],"e10.example.com":[{"SPF":"v=spf1 mx:foo.example.com/24"}],"foo.example.com":[{"MX":[0,"foo1.example.com"]}],"foo1.example.com":[{"A":"1.1.1.1"},{"A":"1.2.3.5"}],"e11.example.com":[{"SPF":"v=spf1 mx:foo:bar/baz.example.com"}],"foo:bar/baz.example.com":[{"MX":[0,"foo:bar/baz.example.com"]},{"A":"1.2.3.4"}],"e12.example.com":[{"SPF":"v=spf1 mx:example.-com"}],"e13.example.com":[{"SPF":"v=spf1 mx: -all"}]}, failOnNoFake: true, helo: "mail.example.com"}
        let promise = spf.check_host('1.2.3.4', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'PASS');
        });
      });
      it('mx-bad-domain', function(){
        let email = 'foo@e9.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"},{"MX":[0,""]},{"SPF":"v=spf1 mx"}],"e1.example.com":[{"SPF":"v=spf1 mx/0 -all"},{"MX":[0,"e1.example.com"]}],"e2.example.com":[{"A":"1.1.1.1"},{"AAAA":"1234::2"},{"MX":[0,"e2.example.com"]},{"SPF":"v=spf1 mx/0 -all"}],"e2a.example.com":[{"AAAA":"1234::1"},{"MX":[0,"e2a.example.com"]},{"SPF":"v=spf1 mx//0 -all"}],"e2b.example.com":[{"A":"1.1.1.1"},{"MX":[0,"e2b.example.com"]},{"SPF":"v=spf1 mx//0 -all"}],"e3.example.com":[{"SPF":"v=spf1 mx:foo.example.com\u0000"}],"e4.example.com":[{"SPF":"v=spf1 mx"},{"A":"1.2.3.4"}],"e5.example.com":[{"SPF":"v=spf1 mx:abc.123"}],"e6.example.com":[{"SPF":"v=spf1 mx//33 -all"}],"e6a.example.com":[{"SPF":"v=spf1 mx/33 -all"}],"e7.example.com":[{"SPF":"v=spf1 mx//129 -all"}],"e9.example.com":[{"SPF":"v=spf1 mx:example.com:8080"}],"e10.example.com":[{"SPF":"v=spf1 mx:foo.example.com/24"}],"foo.example.com":[{"MX":[0,"foo1.example.com"]}],"foo1.example.com":[{"A":"1.1.1.1"},{"A":"1.2.3.5"}],"e11.example.com":[{"SPF":"v=spf1 mx:foo:bar/baz.example.com"}],"foo:bar/baz.example.com":[{"MX":[0,"foo:bar/baz.example.com"]},{"A":"1.2.3.4"}],"e12.example.com":[{"SPF":"v=spf1 mx:example.-com"}],"e13.example.com":[{"SPF":"v=spf1 mx: -all"}]}, failOnNoFake: true, helo: "mail.example.com"}
        let promise = spf.check_host('1.2.3.4', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'PERMERROR');
        });
      });
      it('mx-nxdomain', function(){
        let email = 'foo@e1.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"},{"MX":[0,""]},{"SPF":"v=spf1 mx"}],"e1.example.com":[{"SPF":"v=spf1 mx/0 -all"},{"MX":[0,"e1.example.com"]}],"e2.example.com":[{"A":"1.1.1.1"},{"AAAA":"1234::2"},{"MX":[0,"e2.example.com"]},{"SPF":"v=spf1 mx/0 -all"}],"e2a.example.com":[{"AAAA":"1234::1"},{"MX":[0,"e2a.example.com"]},{"SPF":"v=spf1 mx//0 -all"}],"e2b.example.com":[{"A":"1.1.1.1"},{"MX":[0,"e2b.example.com"]},{"SPF":"v=spf1 mx//0 -all"}],"e3.example.com":[{"SPF":"v=spf1 mx:foo.example.com\u0000"}],"e4.example.com":[{"SPF":"v=spf1 mx"},{"A":"1.2.3.4"}],"e5.example.com":[{"SPF":"v=spf1 mx:abc.123"}],"e6.example.com":[{"SPF":"v=spf1 mx//33 -all"}],"e6a.example.com":[{"SPF":"v=spf1 mx/33 -all"}],"e7.example.com":[{"SPF":"v=spf1 mx//129 -all"}],"e9.example.com":[{"SPF":"v=spf1 mx:example.com:8080"}],"e10.example.com":[{"SPF":"v=spf1 mx:foo.example.com/24"}],"foo.example.com":[{"MX":[0,"foo1.example.com"]}],"foo1.example.com":[{"A":"1.1.1.1"},{"A":"1.2.3.5"}],"e11.example.com":[{"SPF":"v=spf1 mx:foo:bar/baz.example.com"}],"foo:bar/baz.example.com":[{"MX":[0,"foo:bar/baz.example.com"]},{"A":"1.2.3.4"}],"e12.example.com":[{"SPF":"v=spf1 mx:example.-com"}],"e13.example.com":[{"SPF":"v=spf1 mx: -all"}]}, failOnNoFake: true, helo: "mail.example.com"}
        let promise = spf.check_host('1.2.3.4', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'FAIL');
        });
      });
      it('mx-cidr4-0', function(){
        let email = 'foo@e2.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"},{"MX":[0,""]},{"SPF":"v=spf1 mx"}],"e1.example.com":[{"SPF":"v=spf1 mx/0 -all"},{"MX":[0,"e1.example.com"]}],"e2.example.com":[{"A":"1.1.1.1"},{"AAAA":"1234::2"},{"MX":[0,"e2.example.com"]},{"SPF":"v=spf1 mx/0 -all"}],"e2a.example.com":[{"AAAA":"1234::1"},{"MX":[0,"e2a.example.com"]},{"SPF":"v=spf1 mx//0 -all"}],"e2b.example.com":[{"A":"1.1.1.1"},{"MX":[0,"e2b.example.com"]},{"SPF":"v=spf1 mx//0 -all"}],"e3.example.com":[{"SPF":"v=spf1 mx:foo.example.com\u0000"}],"e4.example.com":[{"SPF":"v=spf1 mx"},{"A":"1.2.3.4"}],"e5.example.com":[{"SPF":"v=spf1 mx:abc.123"}],"e6.example.com":[{"SPF":"v=spf1 mx//33 -all"}],"e6a.example.com":[{"SPF":"v=spf1 mx/33 -all"}],"e7.example.com":[{"SPF":"v=spf1 mx//129 -all"}],"e9.example.com":[{"SPF":"v=spf1 mx:example.com:8080"}],"e10.example.com":[{"SPF":"v=spf1 mx:foo.example.com/24"}],"foo.example.com":[{"MX":[0,"foo1.example.com"]}],"foo1.example.com":[{"A":"1.1.1.1"},{"A":"1.2.3.5"}],"e11.example.com":[{"SPF":"v=spf1 mx:foo:bar/baz.example.com"}],"foo:bar/baz.example.com":[{"MX":[0,"foo:bar/baz.example.com"]},{"A":"1.2.3.4"}],"e12.example.com":[{"SPF":"v=spf1 mx:example.-com"}],"e13.example.com":[{"SPF":"v=spf1 mx: -all"}]}, failOnNoFake: true, helo: "mail.example.com"}
        let promise = spf.check_host('1.2.3.4', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'PASS');
        });
      });
      it('mx-cidr4-0-ip6', function(){
        let email = 'foo@e2.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"},{"MX":[0,""]},{"SPF":"v=spf1 mx"}],"e1.example.com":[{"SPF":"v=spf1 mx/0 -all"},{"MX":[0,"e1.example.com"]}],"e2.example.com":[{"A":"1.1.1.1"},{"AAAA":"1234::2"},{"MX":[0,"e2.example.com"]},{"SPF":"v=spf1 mx/0 -all"}],"e2a.example.com":[{"AAAA":"1234::1"},{"MX":[0,"e2a.example.com"]},{"SPF":"v=spf1 mx//0 -all"}],"e2b.example.com":[{"A":"1.1.1.1"},{"MX":[0,"e2b.example.com"]},{"SPF":"v=spf1 mx//0 -all"}],"e3.example.com":[{"SPF":"v=spf1 mx:foo.example.com\u0000"}],"e4.example.com":[{"SPF":"v=spf1 mx"},{"A":"1.2.3.4"}],"e5.example.com":[{"SPF":"v=spf1 mx:abc.123"}],"e6.example.com":[{"SPF":"v=spf1 mx//33 -all"}],"e6a.example.com":[{"SPF":"v=spf1 mx/33 -all"}],"e7.example.com":[{"SPF":"v=spf1 mx//129 -all"}],"e9.example.com":[{"SPF":"v=spf1 mx:example.com:8080"}],"e10.example.com":[{"SPF":"v=spf1 mx:foo.example.com/24"}],"foo.example.com":[{"MX":[0,"foo1.example.com"]}],"foo1.example.com":[{"A":"1.1.1.1"},{"A":"1.2.3.5"}],"e11.example.com":[{"SPF":"v=spf1 mx:foo:bar/baz.example.com"}],"foo:bar/baz.example.com":[{"MX":[0,"foo:bar/baz.example.com"]},{"A":"1.2.3.4"}],"e12.example.com":[{"SPF":"v=spf1 mx:example.-com"}],"e13.example.com":[{"SPF":"v=spf1 mx: -all"}]}, failOnNoFake: true, helo: "mail.example.com"}
        let promise = spf.check_host('1234::1', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'FAIL');
        });
      });
      it('mx-cidr6-0-ip4', function(){
        let email = 'foo@e2a.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"},{"MX":[0,""]},{"SPF":"v=spf1 mx"}],"e1.example.com":[{"SPF":"v=spf1 mx/0 -all"},{"MX":[0,"e1.example.com"]}],"e2.example.com":[{"A":"1.1.1.1"},{"AAAA":"1234::2"},{"MX":[0,"e2.example.com"]},{"SPF":"v=spf1 mx/0 -all"}],"e2a.example.com":[{"AAAA":"1234::1"},{"MX":[0,"e2a.example.com"]},{"SPF":"v=spf1 mx//0 -all"}],"e2b.example.com":[{"A":"1.1.1.1"},{"MX":[0,"e2b.example.com"]},{"SPF":"v=spf1 mx//0 -all"}],"e3.example.com":[{"SPF":"v=spf1 mx:foo.example.com\u0000"}],"e4.example.com":[{"SPF":"v=spf1 mx"},{"A":"1.2.3.4"}],"e5.example.com":[{"SPF":"v=spf1 mx:abc.123"}],"e6.example.com":[{"SPF":"v=spf1 mx//33 -all"}],"e6a.example.com":[{"SPF":"v=spf1 mx/33 -all"}],"e7.example.com":[{"SPF":"v=spf1 mx//129 -all"}],"e9.example.com":[{"SPF":"v=spf1 mx:example.com:8080"}],"e10.example.com":[{"SPF":"v=spf1 mx:foo.example.com/24"}],"foo.example.com":[{"MX":[0,"foo1.example.com"]}],"foo1.example.com":[{"A":"1.1.1.1"},{"A":"1.2.3.5"}],"e11.example.com":[{"SPF":"v=spf1 mx:foo:bar/baz.example.com"}],"foo:bar/baz.example.com":[{"MX":[0,"foo:bar/baz.example.com"]},{"A":"1.2.3.4"}],"e12.example.com":[{"SPF":"v=spf1 mx:example.-com"}],"e13.example.com":[{"SPF":"v=spf1 mx: -all"}]}, failOnNoFake: true, helo: "mail.example.com"}
        let promise = spf.check_host('1.2.3.4', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'FAIL');
        });
      });
      it('mx-cidr6-0-ip4mapped', function(){
        let email = 'foo@e2a.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"},{"MX":[0,""]},{"SPF":"v=spf1 mx"}],"e1.example.com":[{"SPF":"v=spf1 mx/0 -all"},{"MX":[0,"e1.example.com"]}],"e2.example.com":[{"A":"1.1.1.1"},{"AAAA":"1234::2"},{"MX":[0,"e2.example.com"]},{"SPF":"v=spf1 mx/0 -all"}],"e2a.example.com":[{"AAAA":"1234::1"},{"MX":[0,"e2a.example.com"]},{"SPF":"v=spf1 mx//0 -all"}],"e2b.example.com":[{"A":"1.1.1.1"},{"MX":[0,"e2b.example.com"]},{"SPF":"v=spf1 mx//0 -all"}],"e3.example.com":[{"SPF":"v=spf1 mx:foo.example.com\u0000"}],"e4.example.com":[{"SPF":"v=spf1 mx"},{"A":"1.2.3.4"}],"e5.example.com":[{"SPF":"v=spf1 mx:abc.123"}],"e6.example.com":[{"SPF":"v=spf1 mx//33 -all"}],"e6a.example.com":[{"SPF":"v=spf1 mx/33 -all"}],"e7.example.com":[{"SPF":"v=spf1 mx//129 -all"}],"e9.example.com":[{"SPF":"v=spf1 mx:example.com:8080"}],"e10.example.com":[{"SPF":"v=spf1 mx:foo.example.com/24"}],"foo.example.com":[{"MX":[0,"foo1.example.com"]}],"foo1.example.com":[{"A":"1.1.1.1"},{"A":"1.2.3.5"}],"e11.example.com":[{"SPF":"v=spf1 mx:foo:bar/baz.example.com"}],"foo:bar/baz.example.com":[{"MX":[0,"foo:bar/baz.example.com"]},{"A":"1.2.3.4"}],"e12.example.com":[{"SPF":"v=spf1 mx:example.-com"}],"e13.example.com":[{"SPF":"v=spf1 mx: -all"}]}, failOnNoFake: true, helo: "mail.example.com"}
        let promise = spf.check_host('::FFFF:1.2.3.4', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'FAIL');
        });
      });
      it('mx-cidr6-0-ip6', function(){
        let email = 'foo@e2a.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"},{"MX":[0,""]},{"SPF":"v=spf1 mx"}],"e1.example.com":[{"SPF":"v=spf1 mx/0 -all"},{"MX":[0,"e1.example.com"]}],"e2.example.com":[{"A":"1.1.1.1"},{"AAAA":"1234::2"},{"MX":[0,"e2.example.com"]},{"SPF":"v=spf1 mx/0 -all"}],"e2a.example.com":[{"AAAA":"1234::1"},{"MX":[0,"e2a.example.com"]},{"SPF":"v=spf1 mx//0 -all"}],"e2b.example.com":[{"A":"1.1.1.1"},{"MX":[0,"e2b.example.com"]},{"SPF":"v=spf1 mx//0 -all"}],"e3.example.com":[{"SPF":"v=spf1 mx:foo.example.com\u0000"}],"e4.example.com":[{"SPF":"v=spf1 mx"},{"A":"1.2.3.4"}],"e5.example.com":[{"SPF":"v=spf1 mx:abc.123"}],"e6.example.com":[{"SPF":"v=spf1 mx//33 -all"}],"e6a.example.com":[{"SPF":"v=spf1 mx/33 -all"}],"e7.example.com":[{"SPF":"v=spf1 mx//129 -all"}],"e9.example.com":[{"SPF":"v=spf1 mx:example.com:8080"}],"e10.example.com":[{"SPF":"v=spf1 mx:foo.example.com/24"}],"foo.example.com":[{"MX":[0,"foo1.example.com"]}],"foo1.example.com":[{"A":"1.1.1.1"},{"A":"1.2.3.5"}],"e11.example.com":[{"SPF":"v=spf1 mx:foo:bar/baz.example.com"}],"foo:bar/baz.example.com":[{"MX":[0,"foo:bar/baz.example.com"]},{"A":"1.2.3.4"}],"e12.example.com":[{"SPF":"v=spf1 mx:example.-com"}],"e13.example.com":[{"SPF":"v=spf1 mx: -all"}]}, failOnNoFake: true, helo: "mail.example.com"}
        let promise = spf.check_host('1234::1', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'PASS');
        });
      });
      it('mx-cidr6-0-nxdomain', function(){
        let email = 'foo@e2b.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"},{"MX":[0,""]},{"SPF":"v=spf1 mx"}],"e1.example.com":[{"SPF":"v=spf1 mx/0 -all"},{"MX":[0,"e1.example.com"]}],"e2.example.com":[{"A":"1.1.1.1"},{"AAAA":"1234::2"},{"MX":[0,"e2.example.com"]},{"SPF":"v=spf1 mx/0 -all"}],"e2a.example.com":[{"AAAA":"1234::1"},{"MX":[0,"e2a.example.com"]},{"SPF":"v=spf1 mx//0 -all"}],"e2b.example.com":[{"A":"1.1.1.1"},{"MX":[0,"e2b.example.com"]},{"SPF":"v=spf1 mx//0 -all"}],"e3.example.com":[{"SPF":"v=spf1 mx:foo.example.com\u0000"}],"e4.example.com":[{"SPF":"v=spf1 mx"},{"A":"1.2.3.4"}],"e5.example.com":[{"SPF":"v=spf1 mx:abc.123"}],"e6.example.com":[{"SPF":"v=spf1 mx//33 -all"}],"e6a.example.com":[{"SPF":"v=spf1 mx/33 -all"}],"e7.example.com":[{"SPF":"v=spf1 mx//129 -all"}],"e9.example.com":[{"SPF":"v=spf1 mx:example.com:8080"}],"e10.example.com":[{"SPF":"v=spf1 mx:foo.example.com/24"}],"foo.example.com":[{"MX":[0,"foo1.example.com"]}],"foo1.example.com":[{"A":"1.1.1.1"},{"A":"1.2.3.5"}],"e11.example.com":[{"SPF":"v=spf1 mx:foo:bar/baz.example.com"}],"foo:bar/baz.example.com":[{"MX":[0,"foo:bar/baz.example.com"]},{"A":"1.2.3.4"}],"e12.example.com":[{"SPF":"v=spf1 mx:example.-com"}],"e13.example.com":[{"SPF":"v=spf1 mx: -all"}]}, failOnNoFake: true, helo: "mail.example.com"}
        let promise = spf.check_host('1234::1', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'FAIL');
        });
      });
      it('mx-null', function(){
        let email = 'foo@e3.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"},{"MX":[0,""]},{"SPF":"v=spf1 mx"}],"e1.example.com":[{"SPF":"v=spf1 mx/0 -all"},{"MX":[0,"e1.example.com"]}],"e2.example.com":[{"A":"1.1.1.1"},{"AAAA":"1234::2"},{"MX":[0,"e2.example.com"]},{"SPF":"v=spf1 mx/0 -all"}],"e2a.example.com":[{"AAAA":"1234::1"},{"MX":[0,"e2a.example.com"]},{"SPF":"v=spf1 mx//0 -all"}],"e2b.example.com":[{"A":"1.1.1.1"},{"MX":[0,"e2b.example.com"]},{"SPF":"v=spf1 mx//0 -all"}],"e3.example.com":[{"SPF":"v=spf1 mx:foo.example.com\u0000"}],"e4.example.com":[{"SPF":"v=spf1 mx"},{"A":"1.2.3.4"}],"e5.example.com":[{"SPF":"v=spf1 mx:abc.123"}],"e6.example.com":[{"SPF":"v=spf1 mx//33 -all"}],"e6a.example.com":[{"SPF":"v=spf1 mx/33 -all"}],"e7.example.com":[{"SPF":"v=spf1 mx//129 -all"}],"e9.example.com":[{"SPF":"v=spf1 mx:example.com:8080"}],"e10.example.com":[{"SPF":"v=spf1 mx:foo.example.com/24"}],"foo.example.com":[{"MX":[0,"foo1.example.com"]}],"foo1.example.com":[{"A":"1.1.1.1"},{"A":"1.2.3.5"}],"e11.example.com":[{"SPF":"v=spf1 mx:foo:bar/baz.example.com"}],"foo:bar/baz.example.com":[{"MX":[0,"foo:bar/baz.example.com"]},{"A":"1.2.3.4"}],"e12.example.com":[{"SPF":"v=spf1 mx:example.-com"}],"e13.example.com":[{"SPF":"v=spf1 mx: -all"}]}, failOnNoFake: true, helo: "mail.example.com"}
        let promise = spf.check_host('1.2.3.5', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'PERMERROR');
        });
      });
      it('mx-numeric-top-label', function(){
        let email = 'foo@e5.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"},{"MX":[0,""]},{"SPF":"v=spf1 mx"}],"e1.example.com":[{"SPF":"v=spf1 mx/0 -all"},{"MX":[0,"e1.example.com"]}],"e2.example.com":[{"A":"1.1.1.1"},{"AAAA":"1234::2"},{"MX":[0,"e2.example.com"]},{"SPF":"v=spf1 mx/0 -all"}],"e2a.example.com":[{"AAAA":"1234::1"},{"MX":[0,"e2a.example.com"]},{"SPF":"v=spf1 mx//0 -all"}],"e2b.example.com":[{"A":"1.1.1.1"},{"MX":[0,"e2b.example.com"]},{"SPF":"v=spf1 mx//0 -all"}],"e3.example.com":[{"SPF":"v=spf1 mx:foo.example.com\u0000"}],"e4.example.com":[{"SPF":"v=spf1 mx"},{"A":"1.2.3.4"}],"e5.example.com":[{"SPF":"v=spf1 mx:abc.123"}],"e6.example.com":[{"SPF":"v=spf1 mx//33 -all"}],"e6a.example.com":[{"SPF":"v=spf1 mx/33 -all"}],"e7.example.com":[{"SPF":"v=spf1 mx//129 -all"}],"e9.example.com":[{"SPF":"v=spf1 mx:example.com:8080"}],"e10.example.com":[{"SPF":"v=spf1 mx:foo.example.com/24"}],"foo.example.com":[{"MX":[0,"foo1.example.com"]}],"foo1.example.com":[{"A":"1.1.1.1"},{"A":"1.2.3.5"}],"e11.example.com":[{"SPF":"v=spf1 mx:foo:bar/baz.example.com"}],"foo:bar/baz.example.com":[{"MX":[0,"foo:bar/baz.example.com"]},{"A":"1.2.3.4"}],"e12.example.com":[{"SPF":"v=spf1 mx:example.-com"}],"e13.example.com":[{"SPF":"v=spf1 mx: -all"}]}, failOnNoFake: true, helo: "mail.example.com"}
        let promise = spf.check_host('1.2.3.4', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'PERMERROR');
        });
      });
      it('mx-colon-domain', function(){
        let email = 'foo@e11.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"},{"MX":[0,""]},{"SPF":"v=spf1 mx"}],"e1.example.com":[{"SPF":"v=spf1 mx/0 -all"},{"MX":[0,"e1.example.com"]}],"e2.example.com":[{"A":"1.1.1.1"},{"AAAA":"1234::2"},{"MX":[0,"e2.example.com"]},{"SPF":"v=spf1 mx/0 -all"}],"e2a.example.com":[{"AAAA":"1234::1"},{"MX":[0,"e2a.example.com"]},{"SPF":"v=spf1 mx//0 -all"}],"e2b.example.com":[{"A":"1.1.1.1"},{"MX":[0,"e2b.example.com"]},{"SPF":"v=spf1 mx//0 -all"}],"e3.example.com":[{"SPF":"v=spf1 mx:foo.example.com\u0000"}],"e4.example.com":[{"SPF":"v=spf1 mx"},{"A":"1.2.3.4"}],"e5.example.com":[{"SPF":"v=spf1 mx:abc.123"}],"e6.example.com":[{"SPF":"v=spf1 mx//33 -all"}],"e6a.example.com":[{"SPF":"v=spf1 mx/33 -all"}],"e7.example.com":[{"SPF":"v=spf1 mx//129 -all"}],"e9.example.com":[{"SPF":"v=spf1 mx:example.com:8080"}],"e10.example.com":[{"SPF":"v=spf1 mx:foo.example.com/24"}],"foo.example.com":[{"MX":[0,"foo1.example.com"]}],"foo1.example.com":[{"A":"1.1.1.1"},{"A":"1.2.3.5"}],"e11.example.com":[{"SPF":"v=spf1 mx:foo:bar/baz.example.com"}],"foo:bar/baz.example.com":[{"MX":[0,"foo:bar/baz.example.com"]},{"A":"1.2.3.4"}],"e12.example.com":[{"SPF":"v=spf1 mx:example.-com"}],"e13.example.com":[{"SPF":"v=spf1 mx: -all"}]}, failOnNoFake: true, helo: "mail.example.com"}
        let promise = spf.check_host('1.2.3.4', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'PASS');
        });
      });
      it('mx-colon-domain-ip4mapped', function(){
        let email = 'foo@e11.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"},{"MX":[0,""]},{"SPF":"v=spf1 mx"}],"e1.example.com":[{"SPF":"v=spf1 mx/0 -all"},{"MX":[0,"e1.example.com"]}],"e2.example.com":[{"A":"1.1.1.1"},{"AAAA":"1234::2"},{"MX":[0,"e2.example.com"]},{"SPF":"v=spf1 mx/0 -all"}],"e2a.example.com":[{"AAAA":"1234::1"},{"MX":[0,"e2a.example.com"]},{"SPF":"v=spf1 mx//0 -all"}],"e2b.example.com":[{"A":"1.1.1.1"},{"MX":[0,"e2b.example.com"]},{"SPF":"v=spf1 mx//0 -all"}],"e3.example.com":[{"SPF":"v=spf1 mx:foo.example.com\u0000"}],"e4.example.com":[{"SPF":"v=spf1 mx"},{"A":"1.2.3.4"}],"e5.example.com":[{"SPF":"v=spf1 mx:abc.123"}],"e6.example.com":[{"SPF":"v=spf1 mx//33 -all"}],"e6a.example.com":[{"SPF":"v=spf1 mx/33 -all"}],"e7.example.com":[{"SPF":"v=spf1 mx//129 -all"}],"e9.example.com":[{"SPF":"v=spf1 mx:example.com:8080"}],"e10.example.com":[{"SPF":"v=spf1 mx:foo.example.com/24"}],"foo.example.com":[{"MX":[0,"foo1.example.com"]}],"foo1.example.com":[{"A":"1.1.1.1"},{"A":"1.2.3.5"}],"e11.example.com":[{"SPF":"v=spf1 mx:foo:bar/baz.example.com"}],"foo:bar/baz.example.com":[{"MX":[0,"foo:bar/baz.example.com"]},{"A":"1.2.3.4"}],"e12.example.com":[{"SPF":"v=spf1 mx:example.-com"}],"e13.example.com":[{"SPF":"v=spf1 mx: -all"}]}, failOnNoFake: true, helo: "mail.example.com"}
        let promise = spf.check_host('::FFFF:1.2.3.4', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'PASS');
        });
      });
      it('mx-bad-toplab', function(){
        let email = 'foo@e12.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"},{"MX":[0,""]},{"SPF":"v=spf1 mx"}],"e1.example.com":[{"SPF":"v=spf1 mx/0 -all"},{"MX":[0,"e1.example.com"]}],"e2.example.com":[{"A":"1.1.1.1"},{"AAAA":"1234::2"},{"MX":[0,"e2.example.com"]},{"SPF":"v=spf1 mx/0 -all"}],"e2a.example.com":[{"AAAA":"1234::1"},{"MX":[0,"e2a.example.com"]},{"SPF":"v=spf1 mx//0 -all"}],"e2b.example.com":[{"A":"1.1.1.1"},{"MX":[0,"e2b.example.com"]},{"SPF":"v=spf1 mx//0 -all"}],"e3.example.com":[{"SPF":"v=spf1 mx:foo.example.com\u0000"}],"e4.example.com":[{"SPF":"v=spf1 mx"},{"A":"1.2.3.4"}],"e5.example.com":[{"SPF":"v=spf1 mx:abc.123"}],"e6.example.com":[{"SPF":"v=spf1 mx//33 -all"}],"e6a.example.com":[{"SPF":"v=spf1 mx/33 -all"}],"e7.example.com":[{"SPF":"v=spf1 mx//129 -all"}],"e9.example.com":[{"SPF":"v=spf1 mx:example.com:8080"}],"e10.example.com":[{"SPF":"v=spf1 mx:foo.example.com/24"}],"foo.example.com":[{"MX":[0,"foo1.example.com"]}],"foo1.example.com":[{"A":"1.1.1.1"},{"A":"1.2.3.5"}],"e11.example.com":[{"SPF":"v=spf1 mx:foo:bar/baz.example.com"}],"foo:bar/baz.example.com":[{"MX":[0,"foo:bar/baz.example.com"]},{"A":"1.2.3.4"}],"e12.example.com":[{"SPF":"v=spf1 mx:example.-com"}],"e13.example.com":[{"SPF":"v=spf1 mx: -all"}]}, failOnNoFake: true, helo: "mail.example.com"}
        let promise = spf.check_host('1.2.3.4', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'PERMERROR');
        });
      });
      it('mx-empty', function(){
        let email = '';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"},{"MX":[0,""]},{"SPF":"v=spf1 mx"}],"e1.example.com":[{"SPF":"v=spf1 mx/0 -all"},{"MX":[0,"e1.example.com"]}],"e2.example.com":[{"A":"1.1.1.1"},{"AAAA":"1234::2"},{"MX":[0,"e2.example.com"]},{"SPF":"v=spf1 mx/0 -all"}],"e2a.example.com":[{"AAAA":"1234::1"},{"MX":[0,"e2a.example.com"]},{"SPF":"v=spf1 mx//0 -all"}],"e2b.example.com":[{"A":"1.1.1.1"},{"MX":[0,"e2b.example.com"]},{"SPF":"v=spf1 mx//0 -all"}],"e3.example.com":[{"SPF":"v=spf1 mx:foo.example.com\u0000"}],"e4.example.com":[{"SPF":"v=spf1 mx"},{"A":"1.2.3.4"}],"e5.example.com":[{"SPF":"v=spf1 mx:abc.123"}],"e6.example.com":[{"SPF":"v=spf1 mx//33 -all"}],"e6a.example.com":[{"SPF":"v=spf1 mx/33 -all"}],"e7.example.com":[{"SPF":"v=spf1 mx//129 -all"}],"e9.example.com":[{"SPF":"v=spf1 mx:example.com:8080"}],"e10.example.com":[{"SPF":"v=spf1 mx:foo.example.com/24"}],"foo.example.com":[{"MX":[0,"foo1.example.com"]}],"foo1.example.com":[{"A":"1.1.1.1"},{"A":"1.2.3.5"}],"e11.example.com":[{"SPF":"v=spf1 mx:foo:bar/baz.example.com"}],"foo:bar/baz.example.com":[{"MX":[0,"foo:bar/baz.example.com"]},{"A":"1.2.3.4"}],"e12.example.com":[{"SPF":"v=spf1 mx:example.-com"}],"e13.example.com":[{"SPF":"v=spf1 mx: -all"}]}, failOnNoFake: true, helo: "mail.example.com"}
        let promise = spf.check_host('1.2.3.4', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'NEUTRAL');
        });
      });
      it('mx-implicit', function(){
        let email = 'foo@e4.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"},{"MX":[0,""]},{"SPF":"v=spf1 mx"}],"e1.example.com":[{"SPF":"v=spf1 mx/0 -all"},{"MX":[0,"e1.example.com"]}],"e2.example.com":[{"A":"1.1.1.1"},{"AAAA":"1234::2"},{"MX":[0,"e2.example.com"]},{"SPF":"v=spf1 mx/0 -all"}],"e2a.example.com":[{"AAAA":"1234::1"},{"MX":[0,"e2a.example.com"]},{"SPF":"v=spf1 mx//0 -all"}],"e2b.example.com":[{"A":"1.1.1.1"},{"MX":[0,"e2b.example.com"]},{"SPF":"v=spf1 mx//0 -all"}],"e3.example.com":[{"SPF":"v=spf1 mx:foo.example.com\u0000"}],"e4.example.com":[{"SPF":"v=spf1 mx"},{"A":"1.2.3.4"}],"e5.example.com":[{"SPF":"v=spf1 mx:abc.123"}],"e6.example.com":[{"SPF":"v=spf1 mx//33 -all"}],"e6a.example.com":[{"SPF":"v=spf1 mx/33 -all"}],"e7.example.com":[{"SPF":"v=spf1 mx//129 -all"}],"e9.example.com":[{"SPF":"v=spf1 mx:example.com:8080"}],"e10.example.com":[{"SPF":"v=spf1 mx:foo.example.com/24"}],"foo.example.com":[{"MX":[0,"foo1.example.com"]}],"foo1.example.com":[{"A":"1.1.1.1"},{"A":"1.2.3.5"}],"e11.example.com":[{"SPF":"v=spf1 mx:foo:bar/baz.example.com"}],"foo:bar/baz.example.com":[{"MX":[0,"foo:bar/baz.example.com"]},{"A":"1.2.3.4"}],"e12.example.com":[{"SPF":"v=spf1 mx:example.-com"}],"e13.example.com":[{"SPF":"v=spf1 mx: -all"}]}, failOnNoFake: true, helo: "mail.example.com"}
        let promise = spf.check_host('1.2.3.4', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'NEUTRAL');
        });
      });
      it('mx-empty-domain', function(){
        let email = 'foo@e13.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"},{"MX":[0,""]},{"SPF":"v=spf1 mx"}],"e1.example.com":[{"SPF":"v=spf1 mx/0 -all"},{"MX":[0,"e1.example.com"]}],"e2.example.com":[{"A":"1.1.1.1"},{"AAAA":"1234::2"},{"MX":[0,"e2.example.com"]},{"SPF":"v=spf1 mx/0 -all"}],"e2a.example.com":[{"AAAA":"1234::1"},{"MX":[0,"e2a.example.com"]},{"SPF":"v=spf1 mx//0 -all"}],"e2b.example.com":[{"A":"1.1.1.1"},{"MX":[0,"e2b.example.com"]},{"SPF":"v=spf1 mx//0 -all"}],"e3.example.com":[{"SPF":"v=spf1 mx:foo.example.com\u0000"}],"e4.example.com":[{"SPF":"v=spf1 mx"},{"A":"1.2.3.4"}],"e5.example.com":[{"SPF":"v=spf1 mx:abc.123"}],"e6.example.com":[{"SPF":"v=spf1 mx//33 -all"}],"e6a.example.com":[{"SPF":"v=spf1 mx/33 -all"}],"e7.example.com":[{"SPF":"v=spf1 mx//129 -all"}],"e9.example.com":[{"SPF":"v=spf1 mx:example.com:8080"}],"e10.example.com":[{"SPF":"v=spf1 mx:foo.example.com/24"}],"foo.example.com":[{"MX":[0,"foo1.example.com"]}],"foo1.example.com":[{"A":"1.1.1.1"},{"A":"1.2.3.5"}],"e11.example.com":[{"SPF":"v=spf1 mx:foo:bar/baz.example.com"}],"foo:bar/baz.example.com":[{"MX":[0,"foo:bar/baz.example.com"]},{"A":"1.2.3.4"}],"e12.example.com":[{"SPF":"v=spf1 mx:example.-com"}],"e13.example.com":[{"SPF":"v=spf1 mx: -all"}]}, failOnNoFake: true, helo: "mail.example.com"}
        let promise = spf.check_host('1.2.3.4', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'PERMERROR');
        });
      });
    });
    describe('EXISTS mechanism syntax', function(){
      it('exists-empty-domain', function(){
        let email = 'foo@e1.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"mail6.example.com":[{"AAAA":"CAFE:BABE::4"}],"err.example.com":["TIMEOUT"],"e1.example.com":[{"SPF":"v=spf1 exists:"}],"e2.example.com":[{"SPF":"v=spf1 exists"}],"e3.example.com":[{"SPF":"v=spf1 exists:mail.example.com/24"}],"e4.example.com":[{"SPF":"v=spf1 exists:mail.example.com"}],"e5.example.com":[{"SPF":"v=spf1 exists:mail6.example.com -all"}],"e6.example.com":[{"SPF":"v=spf1 exists:err.example.com -all"}]}, failOnNoFake: true, helo: "mail.example.com"}
        let promise = spf.check_host('1.2.3.4', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'PERMERROR');
        });
      });
      it('exists-implicit', function(){
        let email = 'foo@e2.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"mail6.example.com":[{"AAAA":"CAFE:BABE::4"}],"err.example.com":["TIMEOUT"],"e1.example.com":[{"SPF":"v=spf1 exists:"}],"e2.example.com":[{"SPF":"v=spf1 exists"}],"e3.example.com":[{"SPF":"v=spf1 exists:mail.example.com/24"}],"e4.example.com":[{"SPF":"v=spf1 exists:mail.example.com"}],"e5.example.com":[{"SPF":"v=spf1 exists:mail6.example.com -all"}],"e6.example.com":[{"SPF":"v=spf1 exists:err.example.com -all"}]}, failOnNoFake: true, helo: "mail.example.com"}
        let promise = spf.check_host('1.2.3.4', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'PERMERROR');
        });
      });
      it('exists-cidr', function(){
        let email = 'foo@e3.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"mail6.example.com":[{"AAAA":"CAFE:BABE::4"}],"err.example.com":["TIMEOUT"],"e1.example.com":[{"SPF":"v=spf1 exists:"}],"e2.example.com":[{"SPF":"v=spf1 exists"}],"e3.example.com":[{"SPF":"v=spf1 exists:mail.example.com/24"}],"e4.example.com":[{"SPF":"v=spf1 exists:mail.example.com"}],"e5.example.com":[{"SPF":"v=spf1 exists:mail6.example.com -all"}],"e6.example.com":[{"SPF":"v=spf1 exists:err.example.com -all"}]}, failOnNoFake: true, helo: "mail.example.com"}
        let promise = spf.check_host('1.2.3.4', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'PERMERROR');
        });
      });
      it('exists-ip4', function(){
        let email = 'foo@e4.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"mail6.example.com":[{"AAAA":"CAFE:BABE::4"}],"err.example.com":["TIMEOUT"],"e1.example.com":[{"SPF":"v=spf1 exists:"}],"e2.example.com":[{"SPF":"v=spf1 exists"}],"e3.example.com":[{"SPF":"v=spf1 exists:mail.example.com/24"}],"e4.example.com":[{"SPF":"v=spf1 exists:mail.example.com"}],"e5.example.com":[{"SPF":"v=spf1 exists:mail6.example.com -all"}],"e6.example.com":[{"SPF":"v=spf1 exists:err.example.com -all"}]}, failOnNoFake: true, helo: "mail.example.com"}
        let promise = spf.check_host('1.2.3.4', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'PASS');
        });
      });
      it('exists-ip6', function(){
        let email = 'foo@e4.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"mail6.example.com":[{"AAAA":"CAFE:BABE::4"}],"err.example.com":["TIMEOUT"],"e1.example.com":[{"SPF":"v=spf1 exists:"}],"e2.example.com":[{"SPF":"v=spf1 exists"}],"e3.example.com":[{"SPF":"v=spf1 exists:mail.example.com/24"}],"e4.example.com":[{"SPF":"v=spf1 exists:mail.example.com"}],"e5.example.com":[{"SPF":"v=spf1 exists:mail6.example.com -all"}],"e6.example.com":[{"SPF":"v=spf1 exists:err.example.com -all"}]}, failOnNoFake: true, helo: "mail.example.com"}
        let promise = spf.check_host('CAFE:BABE::3', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'PASS');
        });
      });
      it('exists-ip6only', function(){
        let email = 'foo@e5.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"mail6.example.com":[{"AAAA":"CAFE:BABE::4"}],"err.example.com":["TIMEOUT"],"e1.example.com":[{"SPF":"v=spf1 exists:"}],"e2.example.com":[{"SPF":"v=spf1 exists"}],"e3.example.com":[{"SPF":"v=spf1 exists:mail.example.com/24"}],"e4.example.com":[{"SPF":"v=spf1 exists:mail.example.com"}],"e5.example.com":[{"SPF":"v=spf1 exists:mail6.example.com -all"}],"e6.example.com":[{"SPF":"v=spf1 exists:err.example.com -all"}]}, failOnNoFake: true, helo: "mail.example.com"}
        let promise = spf.check_host('CAFE:BABE::3', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'FAIL');
        });
      });
      it('exists-dnserr', function(){
        let email = 'foo@e6.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"mail6.example.com":[{"AAAA":"CAFE:BABE::4"}],"err.example.com":["TIMEOUT"],"e1.example.com":[{"SPF":"v=spf1 exists:"}],"e2.example.com":[{"SPF":"v=spf1 exists"}],"e3.example.com":[{"SPF":"v=spf1 exists:mail.example.com/24"}],"e4.example.com":[{"SPF":"v=spf1 exists:mail.example.com"}],"e5.example.com":[{"SPF":"v=spf1 exists:mail6.example.com -all"}],"e6.example.com":[{"SPF":"v=spf1 exists:err.example.com -all"}]}, failOnNoFake: true, helo: "mail.example.com"}
        let promise = spf.check_host('CAFE:BABE::3', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'TEMPERROR');
        });
      });
    });
    describe('IP4 mechanism syntax', function(){
      it('cidr4-0', function(){
        let email = 'foo@e1.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 ip4:1.1.1.1/0 -all"}],"e2.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4/32 -all"}],"e3.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4/33 -all"}],"e4.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4/032 -all"}],"e5.example.com":[{"SPF":"v=spf1 ip4"}],"e6.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4//32"}],"e7.example.com":[{"SPF":"v=spf1 -ip4:1.2.3.4 ip6:::FFFF:1.2.3.4"}],"e8.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4:8080"}],"e9.example.com":[{"SPF":"v=spf1 ip4:1.2.3"}]}, failOnNoFake: true, helo: "mail.example.com"}
        let promise = spf.check_host('1.2.3.4', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'PASS');
        });
      });
      it('cidr4-32', function(){
        let email = 'foo@e2.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 ip4:1.1.1.1/0 -all"}],"e2.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4/32 -all"}],"e3.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4/33 -all"}],"e4.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4/032 -all"}],"e5.example.com":[{"SPF":"v=spf1 ip4"}],"e6.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4//32"}],"e7.example.com":[{"SPF":"v=spf1 -ip4:1.2.3.4 ip6:::FFFF:1.2.3.4"}],"e8.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4:8080"}],"e9.example.com":[{"SPF":"v=spf1 ip4:1.2.3"}]}, failOnNoFake: true, helo: "mail.example.com"}
        let promise = spf.check_host('1.2.3.4', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'PASS');
        });
      });
      it('cidr4-33', function(){
        let email = 'foo@e3.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 ip4:1.1.1.1/0 -all"}],"e2.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4/32 -all"}],"e3.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4/33 -all"}],"e4.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4/032 -all"}],"e5.example.com":[{"SPF":"v=spf1 ip4"}],"e6.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4//32"}],"e7.example.com":[{"SPF":"v=spf1 -ip4:1.2.3.4 ip6:::FFFF:1.2.3.4"}],"e8.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4:8080"}],"e9.example.com":[{"SPF":"v=spf1 ip4:1.2.3"}]}, failOnNoFake: true, helo: "mail.example.com"}
        let promise = spf.check_host('1.2.3.4', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'PERMERROR');
        });
      });
      it('cidr4-032', function(){
        let email = 'foo@e4.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 ip4:1.1.1.1/0 -all"}],"e2.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4/32 -all"}],"e3.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4/33 -all"}],"e4.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4/032 -all"}],"e5.example.com":[{"SPF":"v=spf1 ip4"}],"e6.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4//32"}],"e7.example.com":[{"SPF":"v=spf1 -ip4:1.2.3.4 ip6:::FFFF:1.2.3.4"}],"e8.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4:8080"}],"e9.example.com":[{"SPF":"v=spf1 ip4:1.2.3"}]}, failOnNoFake: true, helo: "mail.example.com"}
        let promise = spf.check_host('1.2.3.4', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'PERMERROR');
        });
      });
      it('bare-ip4', function(){
        let email = 'foo@e5.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 ip4:1.1.1.1/0 -all"}],"e2.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4/32 -all"}],"e3.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4/33 -all"}],"e4.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4/032 -all"}],"e5.example.com":[{"SPF":"v=spf1 ip4"}],"e6.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4//32"}],"e7.example.com":[{"SPF":"v=spf1 -ip4:1.2.3.4 ip6:::FFFF:1.2.3.4"}],"e8.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4:8080"}],"e9.example.com":[{"SPF":"v=spf1 ip4:1.2.3"}]}, failOnNoFake: true, helo: "mail.example.com"}
        let promise = spf.check_host('1.2.3.4', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'PERMERROR');
        });
      });
      it('bad-ip4-port', function(){
        let email = 'foo@e8.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 ip4:1.1.1.1/0 -all"}],"e2.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4/32 -all"}],"e3.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4/33 -all"}],"e4.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4/032 -all"}],"e5.example.com":[{"SPF":"v=spf1 ip4"}],"e6.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4//32"}],"e7.example.com":[{"SPF":"v=spf1 -ip4:1.2.3.4 ip6:::FFFF:1.2.3.4"}],"e8.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4:8080"}],"e9.example.com":[{"SPF":"v=spf1 ip4:1.2.3"}]}, failOnNoFake: true, helo: "mail.example.com"}
        let promise = spf.check_host('1.2.3.4', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'PERMERROR');
        });
      });
      it('bad-ip4-short', function(){
        let email = 'foo@e9.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 ip4:1.1.1.1/0 -all"}],"e2.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4/32 -all"}],"e3.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4/33 -all"}],"e4.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4/032 -all"}],"e5.example.com":[{"SPF":"v=spf1 ip4"}],"e6.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4//32"}],"e7.example.com":[{"SPF":"v=spf1 -ip4:1.2.3.4 ip6:::FFFF:1.2.3.4"}],"e8.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4:8080"}],"e9.example.com":[{"SPF":"v=spf1 ip4:1.2.3"}]}, failOnNoFake: true, helo: "mail.example.com"}
        let promise = spf.check_host('1.2.3.4', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'PERMERROR');
        });
      });
      it('ip4-dual-cidr', function(){
        let email = 'foo@e6.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 ip4:1.1.1.1/0 -all"}],"e2.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4/32 -all"}],"e3.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4/33 -all"}],"e4.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4/032 -all"}],"e5.example.com":[{"SPF":"v=spf1 ip4"}],"e6.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4//32"}],"e7.example.com":[{"SPF":"v=spf1 -ip4:1.2.3.4 ip6:::FFFF:1.2.3.4"}],"e8.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4:8080"}],"e9.example.com":[{"SPF":"v=spf1 ip4:1.2.3"}]}, failOnNoFake: true, helo: "mail.example.com"}
        let promise = spf.check_host('1.2.3.4', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'PERMERROR');
        });
      });
      it('ip4-mapped-ip6', function(){
        let email = 'foo@e7.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 ip4:1.1.1.1/0 -all"}],"e2.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4/32 -all"}],"e3.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4/33 -all"}],"e4.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4/032 -all"}],"e5.example.com":[{"SPF":"v=spf1 ip4"}],"e6.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4//32"}],"e7.example.com":[{"SPF":"v=spf1 -ip4:1.2.3.4 ip6:::FFFF:1.2.3.4"}],"e8.example.com":[{"SPF":"v=spf1 ip4:1.2.3.4:8080"}],"e9.example.com":[{"SPF":"v=spf1 ip4:1.2.3"}]}, failOnNoFake: true, helo: "mail.example.com"}
        let promise = spf.check_host('::FFFF:1.2.3.4', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'FAIL');
        });
      });
    });
    describe('IP6 mechanism syntax', function(){
      it('bare-ip6', function(){
        let email = 'foo@e1.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 -all ip6"}],"e2.example.com":[{"SPF":"v=spf1 ip6:::1.1.1.1/0"}],"e3.example.com":[{"SPF":"v=spf1 ip6:::1.1.1.1/129"}],"e4.example.com":[{"SPF":"v=spf1 ip6:::1.1.1.1//33"}],"e5.example.com":[{"SPF":"v=spf1 ip6:Cafe:Babe:8000::/33"}],"e6.example.com":[{"SPF":"v=spf1 ip6::CAFE::BABE"}]}, failOnNoFake: true, helo: "mail.example.com"}
        let promise = spf.check_host('1.2.3.4', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'PERMERROR');
        });
      });
      it('cidr6-0-ip4', function(){
        let email = 'foo@e2.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 -all ip6"}],"e2.example.com":[{"SPF":"v=spf1 ip6:::1.1.1.1/0"}],"e3.example.com":[{"SPF":"v=spf1 ip6:::1.1.1.1/129"}],"e4.example.com":[{"SPF":"v=spf1 ip6:::1.1.1.1//33"}],"e5.example.com":[{"SPF":"v=spf1 ip6:Cafe:Babe:8000::/33"}],"e6.example.com":[{"SPF":"v=spf1 ip6::CAFE::BABE"}]}, failOnNoFake: true, helo: "mail.example.com"}
        let promise = spf.check_host('1.2.3.4', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'NEUTRAL');
        });
      });
      it('cidr6-ip4', function(){
        let email = 'foo@e2.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 -all ip6"}],"e2.example.com":[{"SPF":"v=spf1 ip6:::1.1.1.1/0"}],"e3.example.com":[{"SPF":"v=spf1 ip6:::1.1.1.1/129"}],"e4.example.com":[{"SPF":"v=spf1 ip6:::1.1.1.1//33"}],"e5.example.com":[{"SPF":"v=spf1 ip6:Cafe:Babe:8000::/33"}],"e6.example.com":[{"SPF":"v=spf1 ip6::CAFE::BABE"}]}, failOnNoFake: true, helo: "mail.example.com"}
        let promise = spf.check_host('::FFFF:1.2.3.4', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'NEUTRAL');
        });
      });
      it('cidr6-0', function(){
        let email = 'foo@e2.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 -all ip6"}],"e2.example.com":[{"SPF":"v=spf1 ip6:::1.1.1.1/0"}],"e3.example.com":[{"SPF":"v=spf1 ip6:::1.1.1.1/129"}],"e4.example.com":[{"SPF":"v=spf1 ip6:::1.1.1.1//33"}],"e5.example.com":[{"SPF":"v=spf1 ip6:Cafe:Babe:8000::/33"}],"e6.example.com":[{"SPF":"v=spf1 ip6::CAFE::BABE"}]}, failOnNoFake: true, helo: "mail.example.com"}
        let promise = spf.check_host('DEAF:BABE::CAB:FEE', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'PASS');
        });
      });
      it('cidr6-129', function(){
        let email = 'foo@e3.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 -all ip6"}],"e2.example.com":[{"SPF":"v=spf1 ip6:::1.1.1.1/0"}],"e3.example.com":[{"SPF":"v=spf1 ip6:::1.1.1.1/129"}],"e4.example.com":[{"SPF":"v=spf1 ip6:::1.1.1.1//33"}],"e5.example.com":[{"SPF":"v=spf1 ip6:Cafe:Babe:8000::/33"}],"e6.example.com":[{"SPF":"v=spf1 ip6::CAFE::BABE"}]}, failOnNoFake: true, helo: "mail.example.com"}
        let promise = spf.check_host('1.2.3.4', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'PERMERROR');
        });
      });
      it('cidr6-bad', function(){
        let email = 'foo@e4.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 -all ip6"}],"e2.example.com":[{"SPF":"v=spf1 ip6:::1.1.1.1/0"}],"e3.example.com":[{"SPF":"v=spf1 ip6:::1.1.1.1/129"}],"e4.example.com":[{"SPF":"v=spf1 ip6:::1.1.1.1//33"}],"e5.example.com":[{"SPF":"v=spf1 ip6:Cafe:Babe:8000::/33"}],"e6.example.com":[{"SPF":"v=spf1 ip6::CAFE::BABE"}]}, failOnNoFake: true, helo: "mail.example.com"}
        let promise = spf.check_host('1.2.3.4', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'PERMERROR');
        });
      });
      it('cidr6-33', function(){
        let email = 'foo@e5.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 -all ip6"}],"e2.example.com":[{"SPF":"v=spf1 ip6:::1.1.1.1/0"}],"e3.example.com":[{"SPF":"v=spf1 ip6:::1.1.1.1/129"}],"e4.example.com":[{"SPF":"v=spf1 ip6:::1.1.1.1//33"}],"e5.example.com":[{"SPF":"v=spf1 ip6:Cafe:Babe:8000::/33"}],"e6.example.com":[{"SPF":"v=spf1 ip6::CAFE::BABE"}]}, failOnNoFake: true, helo: "mail.example.com"}
        let promise = spf.check_host('CAFE:BABE:8000::', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'PASS');
        });
      });
      it('cidr6-33-ip4', function(){
        let email = 'foo@e5.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 -all ip6"}],"e2.example.com":[{"SPF":"v=spf1 ip6:::1.1.1.1/0"}],"e3.example.com":[{"SPF":"v=spf1 ip6:::1.1.1.1/129"}],"e4.example.com":[{"SPF":"v=spf1 ip6:::1.1.1.1//33"}],"e5.example.com":[{"SPF":"v=spf1 ip6:Cafe:Babe:8000::/33"}],"e6.example.com":[{"SPF":"v=spf1 ip6::CAFE::BABE"}]}, failOnNoFake: true, helo: "mail.example.com"}
        let promise = spf.check_host('1.2.3.4', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'NEUTRAL');
        });
      });
      it('ip6-bad1', function(){
        let email = 'foo@e6.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 -all ip6"}],"e2.example.com":[{"SPF":"v=spf1 ip6:::1.1.1.1/0"}],"e3.example.com":[{"SPF":"v=spf1 ip6:::1.1.1.1/129"}],"e4.example.com":[{"SPF":"v=spf1 ip6:::1.1.1.1//33"}],"e5.example.com":[{"SPF":"v=spf1 ip6:Cafe:Babe:8000::/33"}],"e6.example.com":[{"SPF":"v=spf1 ip6::CAFE::BABE"}]}, failOnNoFake: true, helo: "mail.example.com"}
        let promise = spf.check_host('1.2.3.4', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'PERMERROR');
        });
      });
    });
    describe('Semantics of exp and other modifiers', function(){
      it('redirect-none', function(){
        let email = 'foo@e10.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 exp=exp1.example.com redirect=e2.example.com"}],"e2.example.com":[{"SPF":"v=spf1 -all"}],"e3.example.com":[{"SPF":"v=spf1 exp=exp1.example.com redirect=e4.example.com"}],"e4.example.com":[{"SPF":"v=spf1 -all exp=exp2.example.com"}],"exp1.example.com":[{"TXT":"No-see-um"}],"exp2.example.com":[{"TXT":"See me."}],"exp3.example.com":[{"TXT":"Correct!"}],"exp4.example.com":[{"TXT":"%{l} in implementation"}],"e5.example.com":[{"SPF":"v=spf1 1up=foo"}],"e6.example.com":[{"SPF":"v=spf1 =all"}],"e7.example.com":[{"SPF":"v=spf1 include:e3.example.com -all exp=exp3.example.com"}],"e8.example.com":[{"SPF":"v=spf1 -all exp=exp4.example.com"}],"e9.example.com":[{"SPF":"v=spf1 -all foo=%abc"}],"e10.example.com":[{"SPF":"v=spf1 redirect=erehwon.example.com"}],"e11.example.com":[{"SPF":"v=spf1 -all exp=e11msg.example.com"}],"e11msg.example.com":[{"TXT":"Answer a fool according to his folly."},{"TXT":"Do not answer a fool according to his folly."}],"e12.example.com":[{"SPF":"v=spf1 exp= -all"}],"e13.example.com":[{"SPF":"v=spf1 exp=e13msg.example.com -all"}],"e13msg.example.com":[{"TXT":"The %{x}-files."}],"e14.example.com":[{"SPF":"v=spf1 exp=e13msg.example.com -all exp=e11msg.example.com"}],"e15.example.com":[{"SPF":"v=spf1 redirect=e12.example.com -all redirect=e12.example.com"}],"e16.example.com":[{"SPF":"v=spf1 exp=-all"}],"e17.example.com":[{"SPF":"v=spf1 redirect=-all ?all"}],"e18.example.com":[{"SPF":"v=spf1 ?all redirect="}],"e19.example.com":[{"SPF":"v=spf1 default=pass"}],"e20.example.com":[{"SPF":"v=spf1 default=+"}],"e21.example.com":[{"SPF":"v=spf1 exp=e21msg.example.com -all"}],"e21msg.example.com":["TIMEOUT"],"e22.example.com":[{"SPF":"v=spf1 exp=mail.example.com -all"}],"nonascii.example.com":[{"SPF":"v=spf1 exp=badexp.example.com -all"}],"badexp.example.com":[{"TXT":"ï»¿Explanation"}],"tworecs.example.com":[{"SPF":"v=spf1 exp=twoexp.example.com -all"}],"twoexp.example.com":[{"TXT":"one"},{"TXT":"two"}],"e23.example.com":[{"SPF":"v=spf1 a:erehwon.example.com a:foobar.com exp=nxdomain.com -all"}],"e24.example.com":[{"SPF":"v=spf1 redirect=testimplicit.example.com"},{"A":"192.0.2.1"}],"testimplicit.example.com":[{"SPF":"v=spf1 a -all"},{"A":"192.0.2.2"}]}, failOnNoFake: true, helo: "mail.example.com"}
        let promise = spf.check_host('1.2.3.4', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'PERMERROR');
        });
      });
      it('redirect-cancels-exp', function(){
        let email = 'foo@e1.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 exp=exp1.example.com redirect=e2.example.com"}],"e2.example.com":[{"SPF":"v=spf1 -all"}],"e3.example.com":[{"SPF":"v=spf1 exp=exp1.example.com redirect=e4.example.com"}],"e4.example.com":[{"SPF":"v=spf1 -all exp=exp2.example.com"}],"exp1.example.com":[{"TXT":"No-see-um"}],"exp2.example.com":[{"TXT":"See me."}],"exp3.example.com":[{"TXT":"Correct!"}],"exp4.example.com":[{"TXT":"%{l} in implementation"}],"e5.example.com":[{"SPF":"v=spf1 1up=foo"}],"e6.example.com":[{"SPF":"v=spf1 =all"}],"e7.example.com":[{"SPF":"v=spf1 include:e3.example.com -all exp=exp3.example.com"}],"e8.example.com":[{"SPF":"v=spf1 -all exp=exp4.example.com"}],"e9.example.com":[{"SPF":"v=spf1 -all foo=%abc"}],"e10.example.com":[{"SPF":"v=spf1 redirect=erehwon.example.com"}],"e11.example.com":[{"SPF":"v=spf1 -all exp=e11msg.example.com"}],"e11msg.example.com":[{"TXT":"Answer a fool according to his folly."},{"TXT":"Do not answer a fool according to his folly."}],"e12.example.com":[{"SPF":"v=spf1 exp= -all"}],"e13.example.com":[{"SPF":"v=spf1 exp=e13msg.example.com -all"}],"e13msg.example.com":[{"TXT":"The %{x}-files."}],"e14.example.com":[{"SPF":"v=spf1 exp=e13msg.example.com -all exp=e11msg.example.com"}],"e15.example.com":[{"SPF":"v=spf1 redirect=e12.example.com -all redirect=e12.example.com"}],"e16.example.com":[{"SPF":"v=spf1 exp=-all"}],"e17.example.com":[{"SPF":"v=spf1 redirect=-all ?all"}],"e18.example.com":[{"SPF":"v=spf1 ?all redirect="}],"e19.example.com":[{"SPF":"v=spf1 default=pass"}],"e20.example.com":[{"SPF":"v=spf1 default=+"}],"e21.example.com":[{"SPF":"v=spf1 exp=e21msg.example.com -all"}],"e21msg.example.com":["TIMEOUT"],"e22.example.com":[{"SPF":"v=spf1 exp=mail.example.com -all"}],"nonascii.example.com":[{"SPF":"v=spf1 exp=badexp.example.com -all"}],"badexp.example.com":[{"TXT":"ï»¿Explanation"}],"tworecs.example.com":[{"SPF":"v=spf1 exp=twoexp.example.com -all"}],"twoexp.example.com":[{"TXT":"one"},{"TXT":"two"}],"e23.example.com":[{"SPF":"v=spf1 a:erehwon.example.com a:foobar.com exp=nxdomain.com -all"}],"e24.example.com":[{"SPF":"v=spf1 redirect=testimplicit.example.com"},{"A":"192.0.2.1"}],"testimplicit.example.com":[{"SPF":"v=spf1 a -all"},{"A":"192.0.2.2"}]}, failOnNoFake: true, helo: "mail.example.com"}
        let promise = spf.check_host('1.2.3.4', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'FAIL');
        });
      });
      it('redirect-syntax-error', function(){
        let email = 'foo@e17.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 exp=exp1.example.com redirect=e2.example.com"}],"e2.example.com":[{"SPF":"v=spf1 -all"}],"e3.example.com":[{"SPF":"v=spf1 exp=exp1.example.com redirect=e4.example.com"}],"e4.example.com":[{"SPF":"v=spf1 -all exp=exp2.example.com"}],"exp1.example.com":[{"TXT":"No-see-um"}],"exp2.example.com":[{"TXT":"See me."}],"exp3.example.com":[{"TXT":"Correct!"}],"exp4.example.com":[{"TXT":"%{l} in implementation"}],"e5.example.com":[{"SPF":"v=spf1 1up=foo"}],"e6.example.com":[{"SPF":"v=spf1 =all"}],"e7.example.com":[{"SPF":"v=spf1 include:e3.example.com -all exp=exp3.example.com"}],"e8.example.com":[{"SPF":"v=spf1 -all exp=exp4.example.com"}],"e9.example.com":[{"SPF":"v=spf1 -all foo=%abc"}],"e10.example.com":[{"SPF":"v=spf1 redirect=erehwon.example.com"}],"e11.example.com":[{"SPF":"v=spf1 -all exp=e11msg.example.com"}],"e11msg.example.com":[{"TXT":"Answer a fool according to his folly."},{"TXT":"Do not answer a fool according to his folly."}],"e12.example.com":[{"SPF":"v=spf1 exp= -all"}],"e13.example.com":[{"SPF":"v=spf1 exp=e13msg.example.com -all"}],"e13msg.example.com":[{"TXT":"The %{x}-files."}],"e14.example.com":[{"SPF":"v=spf1 exp=e13msg.example.com -all exp=e11msg.example.com"}],"e15.example.com":[{"SPF":"v=spf1 redirect=e12.example.com -all redirect=e12.example.com"}],"e16.example.com":[{"SPF":"v=spf1 exp=-all"}],"e17.example.com":[{"SPF":"v=spf1 redirect=-all ?all"}],"e18.example.com":[{"SPF":"v=spf1 ?all redirect="}],"e19.example.com":[{"SPF":"v=spf1 default=pass"}],"e20.example.com":[{"SPF":"v=spf1 default=+"}],"e21.example.com":[{"SPF":"v=spf1 exp=e21msg.example.com -all"}],"e21msg.example.com":["TIMEOUT"],"e22.example.com":[{"SPF":"v=spf1 exp=mail.example.com -all"}],"nonascii.example.com":[{"SPF":"v=spf1 exp=badexp.example.com -all"}],"badexp.example.com":[{"TXT":"ï»¿Explanation"}],"tworecs.example.com":[{"SPF":"v=spf1 exp=twoexp.example.com -all"}],"twoexp.example.com":[{"TXT":"one"},{"TXT":"two"}],"e23.example.com":[{"SPF":"v=spf1 a:erehwon.example.com a:foobar.com exp=nxdomain.com -all"}],"e24.example.com":[{"SPF":"v=spf1 redirect=testimplicit.example.com"},{"A":"192.0.2.1"}],"testimplicit.example.com":[{"SPF":"v=spf1 a -all"},{"A":"192.0.2.2"}]}, failOnNoFake: true, helo: "mail.example.com"}
        let promise = spf.check_host('1.2.3.4', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'PERMERROR');
        });
      });
      it('include-ignores-exp', function(){
        let email = 'foo@e7.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 exp=exp1.example.com redirect=e2.example.com"}],"e2.example.com":[{"SPF":"v=spf1 -all"}],"e3.example.com":[{"SPF":"v=spf1 exp=exp1.example.com redirect=e4.example.com"}],"e4.example.com":[{"SPF":"v=spf1 -all exp=exp2.example.com"}],"exp1.example.com":[{"TXT":"No-see-um"}],"exp2.example.com":[{"TXT":"See me."}],"exp3.example.com":[{"TXT":"Correct!"}],"exp4.example.com":[{"TXT":"%{l} in implementation"}],"e5.example.com":[{"SPF":"v=spf1 1up=foo"}],"e6.example.com":[{"SPF":"v=spf1 =all"}],"e7.example.com":[{"SPF":"v=spf1 include:e3.example.com -all exp=exp3.example.com"}],"e8.example.com":[{"SPF":"v=spf1 -all exp=exp4.example.com"}],"e9.example.com":[{"SPF":"v=spf1 -all foo=%abc"}],"e10.example.com":[{"SPF":"v=spf1 redirect=erehwon.example.com"}],"e11.example.com":[{"SPF":"v=spf1 -all exp=e11msg.example.com"}],"e11msg.example.com":[{"TXT":"Answer a fool according to his folly."},{"TXT":"Do not answer a fool according to his folly."}],"e12.example.com":[{"SPF":"v=spf1 exp= -all"}],"e13.example.com":[{"SPF":"v=spf1 exp=e13msg.example.com -all"}],"e13msg.example.com":[{"TXT":"The %{x}-files."}],"e14.example.com":[{"SPF":"v=spf1 exp=e13msg.example.com -all exp=e11msg.example.com"}],"e15.example.com":[{"SPF":"v=spf1 redirect=e12.example.com -all redirect=e12.example.com"}],"e16.example.com":[{"SPF":"v=spf1 exp=-all"}],"e17.example.com":[{"SPF":"v=spf1 redirect=-all ?all"}],"e18.example.com":[{"SPF":"v=spf1 ?all redirect="}],"e19.example.com":[{"SPF":"v=spf1 default=pass"}],"e20.example.com":[{"SPF":"v=spf1 default=+"}],"e21.example.com":[{"SPF":"v=spf1 exp=e21msg.example.com -all"}],"e21msg.example.com":["TIMEOUT"],"e22.example.com":[{"SPF":"v=spf1 exp=mail.example.com -all"}],"nonascii.example.com":[{"SPF":"v=spf1 exp=badexp.example.com -all"}],"badexp.example.com":[{"TXT":"ï»¿Explanation"}],"tworecs.example.com":[{"SPF":"v=spf1 exp=twoexp.example.com -all"}],"twoexp.example.com":[{"TXT":"one"},{"TXT":"two"}],"e23.example.com":[{"SPF":"v=spf1 a:erehwon.example.com a:foobar.com exp=nxdomain.com -all"}],"e24.example.com":[{"SPF":"v=spf1 redirect=testimplicit.example.com"},{"A":"192.0.2.1"}],"testimplicit.example.com":[{"SPF":"v=spf1 a -all"},{"A":"192.0.2.2"}]}, failOnNoFake: true, helo: "mail.example.com"}
        let promise = spf.check_host('1.2.3.4', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'FAIL');
        });
      });
      it('redirect-cancels-prior-exp', function(){
        let email = 'foo@e3.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 exp=exp1.example.com redirect=e2.example.com"}],"e2.example.com":[{"SPF":"v=spf1 -all"}],"e3.example.com":[{"SPF":"v=spf1 exp=exp1.example.com redirect=e4.example.com"}],"e4.example.com":[{"SPF":"v=spf1 -all exp=exp2.example.com"}],"exp1.example.com":[{"TXT":"No-see-um"}],"exp2.example.com":[{"TXT":"See me."}],"exp3.example.com":[{"TXT":"Correct!"}],"exp4.example.com":[{"TXT":"%{l} in implementation"}],"e5.example.com":[{"SPF":"v=spf1 1up=foo"}],"e6.example.com":[{"SPF":"v=spf1 =all"}],"e7.example.com":[{"SPF":"v=spf1 include:e3.example.com -all exp=exp3.example.com"}],"e8.example.com":[{"SPF":"v=spf1 -all exp=exp4.example.com"}],"e9.example.com":[{"SPF":"v=spf1 -all foo=%abc"}],"e10.example.com":[{"SPF":"v=spf1 redirect=erehwon.example.com"}],"e11.example.com":[{"SPF":"v=spf1 -all exp=e11msg.example.com"}],"e11msg.example.com":[{"TXT":"Answer a fool according to his folly."},{"TXT":"Do not answer a fool according to his folly."}],"e12.example.com":[{"SPF":"v=spf1 exp= -all"}],"e13.example.com":[{"SPF":"v=spf1 exp=e13msg.example.com -all"}],"e13msg.example.com":[{"TXT":"The %{x}-files."}],"e14.example.com":[{"SPF":"v=spf1 exp=e13msg.example.com -all exp=e11msg.example.com"}],"e15.example.com":[{"SPF":"v=spf1 redirect=e12.example.com -all redirect=e12.example.com"}],"e16.example.com":[{"SPF":"v=spf1 exp=-all"}],"e17.example.com":[{"SPF":"v=spf1 redirect=-all ?all"}],"e18.example.com":[{"SPF":"v=spf1 ?all redirect="}],"e19.example.com":[{"SPF":"v=spf1 default=pass"}],"e20.example.com":[{"SPF":"v=spf1 default=+"}],"e21.example.com":[{"SPF":"v=spf1 exp=e21msg.example.com -all"}],"e21msg.example.com":["TIMEOUT"],"e22.example.com":[{"SPF":"v=spf1 exp=mail.example.com -all"}],"nonascii.example.com":[{"SPF":"v=spf1 exp=badexp.example.com -all"}],"badexp.example.com":[{"TXT":"ï»¿Explanation"}],"tworecs.example.com":[{"SPF":"v=spf1 exp=twoexp.example.com -all"}],"twoexp.example.com":[{"TXT":"one"},{"TXT":"two"}],"e23.example.com":[{"SPF":"v=spf1 a:erehwon.example.com a:foobar.com exp=nxdomain.com -all"}],"e24.example.com":[{"SPF":"v=spf1 redirect=testimplicit.example.com"},{"A":"192.0.2.1"}],"testimplicit.example.com":[{"SPF":"v=spf1 a -all"},{"A":"192.0.2.2"}]}, failOnNoFake: true, helo: "mail.example.com"}
        let promise = spf.check_host('1.2.3.4', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'FAIL');
        });
      });
      it('invalid-modifier', function(){
        let email = 'foo@e5.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 exp=exp1.example.com redirect=e2.example.com"}],"e2.example.com":[{"SPF":"v=spf1 -all"}],"e3.example.com":[{"SPF":"v=spf1 exp=exp1.example.com redirect=e4.example.com"}],"e4.example.com":[{"SPF":"v=spf1 -all exp=exp2.example.com"}],"exp1.example.com":[{"TXT":"No-see-um"}],"exp2.example.com":[{"TXT":"See me."}],"exp3.example.com":[{"TXT":"Correct!"}],"exp4.example.com":[{"TXT":"%{l} in implementation"}],"e5.example.com":[{"SPF":"v=spf1 1up=foo"}],"e6.example.com":[{"SPF":"v=spf1 =all"}],"e7.example.com":[{"SPF":"v=spf1 include:e3.example.com -all exp=exp3.example.com"}],"e8.example.com":[{"SPF":"v=spf1 -all exp=exp4.example.com"}],"e9.example.com":[{"SPF":"v=spf1 -all foo=%abc"}],"e10.example.com":[{"SPF":"v=spf1 redirect=erehwon.example.com"}],"e11.example.com":[{"SPF":"v=spf1 -all exp=e11msg.example.com"}],"e11msg.example.com":[{"TXT":"Answer a fool according to his folly."},{"TXT":"Do not answer a fool according to his folly."}],"e12.example.com":[{"SPF":"v=spf1 exp= -all"}],"e13.example.com":[{"SPF":"v=spf1 exp=e13msg.example.com -all"}],"e13msg.example.com":[{"TXT":"The %{x}-files."}],"e14.example.com":[{"SPF":"v=spf1 exp=e13msg.example.com -all exp=e11msg.example.com"}],"e15.example.com":[{"SPF":"v=spf1 redirect=e12.example.com -all redirect=e12.example.com"}],"e16.example.com":[{"SPF":"v=spf1 exp=-all"}],"e17.example.com":[{"SPF":"v=spf1 redirect=-all ?all"}],"e18.example.com":[{"SPF":"v=spf1 ?all redirect="}],"e19.example.com":[{"SPF":"v=spf1 default=pass"}],"e20.example.com":[{"SPF":"v=spf1 default=+"}],"e21.example.com":[{"SPF":"v=spf1 exp=e21msg.example.com -all"}],"e21msg.example.com":["TIMEOUT"],"e22.example.com":[{"SPF":"v=spf1 exp=mail.example.com -all"}],"nonascii.example.com":[{"SPF":"v=spf1 exp=badexp.example.com -all"}],"badexp.example.com":[{"TXT":"ï»¿Explanation"}],"tworecs.example.com":[{"SPF":"v=spf1 exp=twoexp.example.com -all"}],"twoexp.example.com":[{"TXT":"one"},{"TXT":"two"}],"e23.example.com":[{"SPF":"v=spf1 a:erehwon.example.com a:foobar.com exp=nxdomain.com -all"}],"e24.example.com":[{"SPF":"v=spf1 redirect=testimplicit.example.com"},{"A":"192.0.2.1"}],"testimplicit.example.com":[{"SPF":"v=spf1 a -all"},{"A":"192.0.2.2"}]}, failOnNoFake: true, helo: "mail.example.com"}
        let promise = spf.check_host('1.2.3.4', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'PERMERROR');
        });
      });
      it('empty-modifier-name', function(){
        let email = 'foo@e6.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 exp=exp1.example.com redirect=e2.example.com"}],"e2.example.com":[{"SPF":"v=spf1 -all"}],"e3.example.com":[{"SPF":"v=spf1 exp=exp1.example.com redirect=e4.example.com"}],"e4.example.com":[{"SPF":"v=spf1 -all exp=exp2.example.com"}],"exp1.example.com":[{"TXT":"No-see-um"}],"exp2.example.com":[{"TXT":"See me."}],"exp3.example.com":[{"TXT":"Correct!"}],"exp4.example.com":[{"TXT":"%{l} in implementation"}],"e5.example.com":[{"SPF":"v=spf1 1up=foo"}],"e6.example.com":[{"SPF":"v=spf1 =all"}],"e7.example.com":[{"SPF":"v=spf1 include:e3.example.com -all exp=exp3.example.com"}],"e8.example.com":[{"SPF":"v=spf1 -all exp=exp4.example.com"}],"e9.example.com":[{"SPF":"v=spf1 -all foo=%abc"}],"e10.example.com":[{"SPF":"v=spf1 redirect=erehwon.example.com"}],"e11.example.com":[{"SPF":"v=spf1 -all exp=e11msg.example.com"}],"e11msg.example.com":[{"TXT":"Answer a fool according to his folly."},{"TXT":"Do not answer a fool according to his folly."}],"e12.example.com":[{"SPF":"v=spf1 exp= -all"}],"e13.example.com":[{"SPF":"v=spf1 exp=e13msg.example.com -all"}],"e13msg.example.com":[{"TXT":"The %{x}-files."}],"e14.example.com":[{"SPF":"v=spf1 exp=e13msg.example.com -all exp=e11msg.example.com"}],"e15.example.com":[{"SPF":"v=spf1 redirect=e12.example.com -all redirect=e12.example.com"}],"e16.example.com":[{"SPF":"v=spf1 exp=-all"}],"e17.example.com":[{"SPF":"v=spf1 redirect=-all ?all"}],"e18.example.com":[{"SPF":"v=spf1 ?all redirect="}],"e19.example.com":[{"SPF":"v=spf1 default=pass"}],"e20.example.com":[{"SPF":"v=spf1 default=+"}],"e21.example.com":[{"SPF":"v=spf1 exp=e21msg.example.com -all"}],"e21msg.example.com":["TIMEOUT"],"e22.example.com":[{"SPF":"v=spf1 exp=mail.example.com -all"}],"nonascii.example.com":[{"SPF":"v=spf1 exp=badexp.example.com -all"}],"badexp.example.com":[{"TXT":"ï»¿Explanation"}],"tworecs.example.com":[{"SPF":"v=spf1 exp=twoexp.example.com -all"}],"twoexp.example.com":[{"TXT":"one"},{"TXT":"two"}],"e23.example.com":[{"SPF":"v=spf1 a:erehwon.example.com a:foobar.com exp=nxdomain.com -all"}],"e24.example.com":[{"SPF":"v=spf1 redirect=testimplicit.example.com"},{"A":"192.0.2.1"}],"testimplicit.example.com":[{"SPF":"v=spf1 a -all"},{"A":"192.0.2.2"}]}, failOnNoFake: true, helo: "mail.example.com"}
        let promise = spf.check_host('1.2.3.4', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'PERMERROR');
        });
      });
      it('dorky-sentinel', function(){
        let email = 'Macro Error@e8.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 exp=exp1.example.com redirect=e2.example.com"}],"e2.example.com":[{"SPF":"v=spf1 -all"}],"e3.example.com":[{"SPF":"v=spf1 exp=exp1.example.com redirect=e4.example.com"}],"e4.example.com":[{"SPF":"v=spf1 -all exp=exp2.example.com"}],"exp1.example.com":[{"TXT":"No-see-um"}],"exp2.example.com":[{"TXT":"See me."}],"exp3.example.com":[{"TXT":"Correct!"}],"exp4.example.com":[{"TXT":"%{l} in implementation"}],"e5.example.com":[{"SPF":"v=spf1 1up=foo"}],"e6.example.com":[{"SPF":"v=spf1 =all"}],"e7.example.com":[{"SPF":"v=spf1 include:e3.example.com -all exp=exp3.example.com"}],"e8.example.com":[{"SPF":"v=spf1 -all exp=exp4.example.com"}],"e9.example.com":[{"SPF":"v=spf1 -all foo=%abc"}],"e10.example.com":[{"SPF":"v=spf1 redirect=erehwon.example.com"}],"e11.example.com":[{"SPF":"v=spf1 -all exp=e11msg.example.com"}],"e11msg.example.com":[{"TXT":"Answer a fool according to his folly."},{"TXT":"Do not answer a fool according to his folly."}],"e12.example.com":[{"SPF":"v=spf1 exp= -all"}],"e13.example.com":[{"SPF":"v=spf1 exp=e13msg.example.com -all"}],"e13msg.example.com":[{"TXT":"The %{x}-files."}],"e14.example.com":[{"SPF":"v=spf1 exp=e13msg.example.com -all exp=e11msg.example.com"}],"e15.example.com":[{"SPF":"v=spf1 redirect=e12.example.com -all redirect=e12.example.com"}],"e16.example.com":[{"SPF":"v=spf1 exp=-all"}],"e17.example.com":[{"SPF":"v=spf1 redirect=-all ?all"}],"e18.example.com":[{"SPF":"v=spf1 ?all redirect="}],"e19.example.com":[{"SPF":"v=spf1 default=pass"}],"e20.example.com":[{"SPF":"v=spf1 default=+"}],"e21.example.com":[{"SPF":"v=spf1 exp=e21msg.example.com -all"}],"e21msg.example.com":["TIMEOUT"],"e22.example.com":[{"SPF":"v=spf1 exp=mail.example.com -all"}],"nonascii.example.com":[{"SPF":"v=spf1 exp=badexp.example.com -all"}],"badexp.example.com":[{"TXT":"ï»¿Explanation"}],"tworecs.example.com":[{"SPF":"v=spf1 exp=twoexp.example.com -all"}],"twoexp.example.com":[{"TXT":"one"},{"TXT":"two"}],"e23.example.com":[{"SPF":"v=spf1 a:erehwon.example.com a:foobar.com exp=nxdomain.com -all"}],"e24.example.com":[{"SPF":"v=spf1 redirect=testimplicit.example.com"},{"A":"192.0.2.1"}],"testimplicit.example.com":[{"SPF":"v=spf1 a -all"},{"A":"192.0.2.2"}]}, failOnNoFake: true, helo: "mail.example.com"}
        let promise = spf.check_host('1.2.3.4', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'FAIL');
        });
      });
      it('exp-multiple-txt', function(){
        let email = 'foo@e11.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 exp=exp1.example.com redirect=e2.example.com"}],"e2.example.com":[{"SPF":"v=spf1 -all"}],"e3.example.com":[{"SPF":"v=spf1 exp=exp1.example.com redirect=e4.example.com"}],"e4.example.com":[{"SPF":"v=spf1 -all exp=exp2.example.com"}],"exp1.example.com":[{"TXT":"No-see-um"}],"exp2.example.com":[{"TXT":"See me."}],"exp3.example.com":[{"TXT":"Correct!"}],"exp4.example.com":[{"TXT":"%{l} in implementation"}],"e5.example.com":[{"SPF":"v=spf1 1up=foo"}],"e6.example.com":[{"SPF":"v=spf1 =all"}],"e7.example.com":[{"SPF":"v=spf1 include:e3.example.com -all exp=exp3.example.com"}],"e8.example.com":[{"SPF":"v=spf1 -all exp=exp4.example.com"}],"e9.example.com":[{"SPF":"v=spf1 -all foo=%abc"}],"e10.example.com":[{"SPF":"v=spf1 redirect=erehwon.example.com"}],"e11.example.com":[{"SPF":"v=spf1 -all exp=e11msg.example.com"}],"e11msg.example.com":[{"TXT":"Answer a fool according to his folly."},{"TXT":"Do not answer a fool according to his folly."}],"e12.example.com":[{"SPF":"v=spf1 exp= -all"}],"e13.example.com":[{"SPF":"v=spf1 exp=e13msg.example.com -all"}],"e13msg.example.com":[{"TXT":"The %{x}-files."}],"e14.example.com":[{"SPF":"v=spf1 exp=e13msg.example.com -all exp=e11msg.example.com"}],"e15.example.com":[{"SPF":"v=spf1 redirect=e12.example.com -all redirect=e12.example.com"}],"e16.example.com":[{"SPF":"v=spf1 exp=-all"}],"e17.example.com":[{"SPF":"v=spf1 redirect=-all ?all"}],"e18.example.com":[{"SPF":"v=spf1 ?all redirect="}],"e19.example.com":[{"SPF":"v=spf1 default=pass"}],"e20.example.com":[{"SPF":"v=spf1 default=+"}],"e21.example.com":[{"SPF":"v=spf1 exp=e21msg.example.com -all"}],"e21msg.example.com":["TIMEOUT"],"e22.example.com":[{"SPF":"v=spf1 exp=mail.example.com -all"}],"nonascii.example.com":[{"SPF":"v=spf1 exp=badexp.example.com -all"}],"badexp.example.com":[{"TXT":"ï»¿Explanation"}],"tworecs.example.com":[{"SPF":"v=spf1 exp=twoexp.example.com -all"}],"twoexp.example.com":[{"TXT":"one"},{"TXT":"two"}],"e23.example.com":[{"SPF":"v=spf1 a:erehwon.example.com a:foobar.com exp=nxdomain.com -all"}],"e24.example.com":[{"SPF":"v=spf1 redirect=testimplicit.example.com"},{"A":"192.0.2.1"}],"testimplicit.example.com":[{"SPF":"v=spf1 a -all"},{"A":"192.0.2.2"}]}, failOnNoFake: true, helo: "mail.example.com"}
        let promise = spf.check_host('1.2.3.4', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'FAIL');
        });
      });
      it('exp-no-txt', function(){
        let email = 'foo@e22.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 exp=exp1.example.com redirect=e2.example.com"}],"e2.example.com":[{"SPF":"v=spf1 -all"}],"e3.example.com":[{"SPF":"v=spf1 exp=exp1.example.com redirect=e4.example.com"}],"e4.example.com":[{"SPF":"v=spf1 -all exp=exp2.example.com"}],"exp1.example.com":[{"TXT":"No-see-um"}],"exp2.example.com":[{"TXT":"See me."}],"exp3.example.com":[{"TXT":"Correct!"}],"exp4.example.com":[{"TXT":"%{l} in implementation"}],"e5.example.com":[{"SPF":"v=spf1 1up=foo"}],"e6.example.com":[{"SPF":"v=spf1 =all"}],"e7.example.com":[{"SPF":"v=spf1 include:e3.example.com -all exp=exp3.example.com"}],"e8.example.com":[{"SPF":"v=spf1 -all exp=exp4.example.com"}],"e9.example.com":[{"SPF":"v=spf1 -all foo=%abc"}],"e10.example.com":[{"SPF":"v=spf1 redirect=erehwon.example.com"}],"e11.example.com":[{"SPF":"v=spf1 -all exp=e11msg.example.com"}],"e11msg.example.com":[{"TXT":"Answer a fool according to his folly."},{"TXT":"Do not answer a fool according to his folly."}],"e12.example.com":[{"SPF":"v=spf1 exp= -all"}],"e13.example.com":[{"SPF":"v=spf1 exp=e13msg.example.com -all"}],"e13msg.example.com":[{"TXT":"The %{x}-files."}],"e14.example.com":[{"SPF":"v=spf1 exp=e13msg.example.com -all exp=e11msg.example.com"}],"e15.example.com":[{"SPF":"v=spf1 redirect=e12.example.com -all redirect=e12.example.com"}],"e16.example.com":[{"SPF":"v=spf1 exp=-all"}],"e17.example.com":[{"SPF":"v=spf1 redirect=-all ?all"}],"e18.example.com":[{"SPF":"v=spf1 ?all redirect="}],"e19.example.com":[{"SPF":"v=spf1 default=pass"}],"e20.example.com":[{"SPF":"v=spf1 default=+"}],"e21.example.com":[{"SPF":"v=spf1 exp=e21msg.example.com -all"}],"e21msg.example.com":["TIMEOUT"],"e22.example.com":[{"SPF":"v=spf1 exp=mail.example.com -all"}],"nonascii.example.com":[{"SPF":"v=spf1 exp=badexp.example.com -all"}],"badexp.example.com":[{"TXT":"ï»¿Explanation"}],"tworecs.example.com":[{"SPF":"v=spf1 exp=twoexp.example.com -all"}],"twoexp.example.com":[{"TXT":"one"},{"TXT":"two"}],"e23.example.com":[{"SPF":"v=spf1 a:erehwon.example.com a:foobar.com exp=nxdomain.com -all"}],"e24.example.com":[{"SPF":"v=spf1 redirect=testimplicit.example.com"},{"A":"192.0.2.1"}],"testimplicit.example.com":[{"SPF":"v=spf1 a -all"},{"A":"192.0.2.2"}]}, failOnNoFake: true, helo: "mail.example.com"}
        let promise = spf.check_host('1.2.3.4', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'FAIL');
        });
      });
      it('exp-dns-error', function(){
        let email = 'foo@e21.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 exp=exp1.example.com redirect=e2.example.com"}],"e2.example.com":[{"SPF":"v=spf1 -all"}],"e3.example.com":[{"SPF":"v=spf1 exp=exp1.example.com redirect=e4.example.com"}],"e4.example.com":[{"SPF":"v=spf1 -all exp=exp2.example.com"}],"exp1.example.com":[{"TXT":"No-see-um"}],"exp2.example.com":[{"TXT":"See me."}],"exp3.example.com":[{"TXT":"Correct!"}],"exp4.example.com":[{"TXT":"%{l} in implementation"}],"e5.example.com":[{"SPF":"v=spf1 1up=foo"}],"e6.example.com":[{"SPF":"v=spf1 =all"}],"e7.example.com":[{"SPF":"v=spf1 include:e3.example.com -all exp=exp3.example.com"}],"e8.example.com":[{"SPF":"v=spf1 -all exp=exp4.example.com"}],"e9.example.com":[{"SPF":"v=spf1 -all foo=%abc"}],"e10.example.com":[{"SPF":"v=spf1 redirect=erehwon.example.com"}],"e11.example.com":[{"SPF":"v=spf1 -all exp=e11msg.example.com"}],"e11msg.example.com":[{"TXT":"Answer a fool according to his folly."},{"TXT":"Do not answer a fool according to his folly."}],"e12.example.com":[{"SPF":"v=spf1 exp= -all"}],"e13.example.com":[{"SPF":"v=spf1 exp=e13msg.example.com -all"}],"e13msg.example.com":[{"TXT":"The %{x}-files."}],"e14.example.com":[{"SPF":"v=spf1 exp=e13msg.example.com -all exp=e11msg.example.com"}],"e15.example.com":[{"SPF":"v=spf1 redirect=e12.example.com -all redirect=e12.example.com"}],"e16.example.com":[{"SPF":"v=spf1 exp=-all"}],"e17.example.com":[{"SPF":"v=spf1 redirect=-all ?all"}],"e18.example.com":[{"SPF":"v=spf1 ?all redirect="}],"e19.example.com":[{"SPF":"v=spf1 default=pass"}],"e20.example.com":[{"SPF":"v=spf1 default=+"}],"e21.example.com":[{"SPF":"v=spf1 exp=e21msg.example.com -all"}],"e21msg.example.com":["TIMEOUT"],"e22.example.com":[{"SPF":"v=spf1 exp=mail.example.com -all"}],"nonascii.example.com":[{"SPF":"v=spf1 exp=badexp.example.com -all"}],"badexp.example.com":[{"TXT":"ï»¿Explanation"}],"tworecs.example.com":[{"SPF":"v=spf1 exp=twoexp.example.com -all"}],"twoexp.example.com":[{"TXT":"one"},{"TXT":"two"}],"e23.example.com":[{"SPF":"v=spf1 a:erehwon.example.com a:foobar.com exp=nxdomain.com -all"}],"e24.example.com":[{"SPF":"v=spf1 redirect=testimplicit.example.com"},{"A":"192.0.2.1"}],"testimplicit.example.com":[{"SPF":"v=spf1 a -all"},{"A":"192.0.2.2"}]}, failOnNoFake: true, helo: "mail.example.com"}
        let promise = spf.check_host('1.2.3.4', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'FAIL');
        });
      });
      it('exp-empty-domain', function(){
        let email = 'foo@e12.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 exp=exp1.example.com redirect=e2.example.com"}],"e2.example.com":[{"SPF":"v=spf1 -all"}],"e3.example.com":[{"SPF":"v=spf1 exp=exp1.example.com redirect=e4.example.com"}],"e4.example.com":[{"SPF":"v=spf1 -all exp=exp2.example.com"}],"exp1.example.com":[{"TXT":"No-see-um"}],"exp2.example.com":[{"TXT":"See me."}],"exp3.example.com":[{"TXT":"Correct!"}],"exp4.example.com":[{"TXT":"%{l} in implementation"}],"e5.example.com":[{"SPF":"v=spf1 1up=foo"}],"e6.example.com":[{"SPF":"v=spf1 =all"}],"e7.example.com":[{"SPF":"v=spf1 include:e3.example.com -all exp=exp3.example.com"}],"e8.example.com":[{"SPF":"v=spf1 -all exp=exp4.example.com"}],"e9.example.com":[{"SPF":"v=spf1 -all foo=%abc"}],"e10.example.com":[{"SPF":"v=spf1 redirect=erehwon.example.com"}],"e11.example.com":[{"SPF":"v=spf1 -all exp=e11msg.example.com"}],"e11msg.example.com":[{"TXT":"Answer a fool according to his folly."},{"TXT":"Do not answer a fool according to his folly."}],"e12.example.com":[{"SPF":"v=spf1 exp= -all"}],"e13.example.com":[{"SPF":"v=spf1 exp=e13msg.example.com -all"}],"e13msg.example.com":[{"TXT":"The %{x}-files."}],"e14.example.com":[{"SPF":"v=spf1 exp=e13msg.example.com -all exp=e11msg.example.com"}],"e15.example.com":[{"SPF":"v=spf1 redirect=e12.example.com -all redirect=e12.example.com"}],"e16.example.com":[{"SPF":"v=spf1 exp=-all"}],"e17.example.com":[{"SPF":"v=spf1 redirect=-all ?all"}],"e18.example.com":[{"SPF":"v=spf1 ?all redirect="}],"e19.example.com":[{"SPF":"v=spf1 default=pass"}],"e20.example.com":[{"SPF":"v=spf1 default=+"}],"e21.example.com":[{"SPF":"v=spf1 exp=e21msg.example.com -all"}],"e21msg.example.com":["TIMEOUT"],"e22.example.com":[{"SPF":"v=spf1 exp=mail.example.com -all"}],"nonascii.example.com":[{"SPF":"v=spf1 exp=badexp.example.com -all"}],"badexp.example.com":[{"TXT":"ï»¿Explanation"}],"tworecs.example.com":[{"SPF":"v=spf1 exp=twoexp.example.com -all"}],"twoexp.example.com":[{"TXT":"one"},{"TXT":"two"}],"e23.example.com":[{"SPF":"v=spf1 a:erehwon.example.com a:foobar.com exp=nxdomain.com -all"}],"e24.example.com":[{"SPF":"v=spf1 redirect=testimplicit.example.com"},{"A":"192.0.2.1"}],"testimplicit.example.com":[{"SPF":"v=spf1 a -all"},{"A":"192.0.2.2"}]}, failOnNoFake: true, helo: "mail.example.com"}
        let promise = spf.check_host('1.2.3.4', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'PERMERROR');
        });
      });
      it('explanation-syntax-error', function(){
        let email = 'foo@e13.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 exp=exp1.example.com redirect=e2.example.com"}],"e2.example.com":[{"SPF":"v=spf1 -all"}],"e3.example.com":[{"SPF":"v=spf1 exp=exp1.example.com redirect=e4.example.com"}],"e4.example.com":[{"SPF":"v=spf1 -all exp=exp2.example.com"}],"exp1.example.com":[{"TXT":"No-see-um"}],"exp2.example.com":[{"TXT":"See me."}],"exp3.example.com":[{"TXT":"Correct!"}],"exp4.example.com":[{"TXT":"%{l} in implementation"}],"e5.example.com":[{"SPF":"v=spf1 1up=foo"}],"e6.example.com":[{"SPF":"v=spf1 =all"}],"e7.example.com":[{"SPF":"v=spf1 include:e3.example.com -all exp=exp3.example.com"}],"e8.example.com":[{"SPF":"v=spf1 -all exp=exp4.example.com"}],"e9.example.com":[{"SPF":"v=spf1 -all foo=%abc"}],"e10.example.com":[{"SPF":"v=spf1 redirect=erehwon.example.com"}],"e11.example.com":[{"SPF":"v=spf1 -all exp=e11msg.example.com"}],"e11msg.example.com":[{"TXT":"Answer a fool according to his folly."},{"TXT":"Do not answer a fool according to his folly."}],"e12.example.com":[{"SPF":"v=spf1 exp= -all"}],"e13.example.com":[{"SPF":"v=spf1 exp=e13msg.example.com -all"}],"e13msg.example.com":[{"TXT":"The %{x}-files."}],"e14.example.com":[{"SPF":"v=spf1 exp=e13msg.example.com -all exp=e11msg.example.com"}],"e15.example.com":[{"SPF":"v=spf1 redirect=e12.example.com -all redirect=e12.example.com"}],"e16.example.com":[{"SPF":"v=spf1 exp=-all"}],"e17.example.com":[{"SPF":"v=spf1 redirect=-all ?all"}],"e18.example.com":[{"SPF":"v=spf1 ?all redirect="}],"e19.example.com":[{"SPF":"v=spf1 default=pass"}],"e20.example.com":[{"SPF":"v=spf1 default=+"}],"e21.example.com":[{"SPF":"v=spf1 exp=e21msg.example.com -all"}],"e21msg.example.com":["TIMEOUT"],"e22.example.com":[{"SPF":"v=spf1 exp=mail.example.com -all"}],"nonascii.example.com":[{"SPF":"v=spf1 exp=badexp.example.com -all"}],"badexp.example.com":[{"TXT":"ï»¿Explanation"}],"tworecs.example.com":[{"SPF":"v=spf1 exp=twoexp.example.com -all"}],"twoexp.example.com":[{"TXT":"one"},{"TXT":"two"}],"e23.example.com":[{"SPF":"v=spf1 a:erehwon.example.com a:foobar.com exp=nxdomain.com -all"}],"e24.example.com":[{"SPF":"v=spf1 redirect=testimplicit.example.com"},{"A":"192.0.2.1"}],"testimplicit.example.com":[{"SPF":"v=spf1 a -all"},{"A":"192.0.2.2"}]}, failOnNoFake: true, helo: "mail.example.com"}
        let promise = spf.check_host('1.2.3.4', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'FAIL');
        });
      });
      it('exp-syntax-error', function(){
        let email = 'foo@e16.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 exp=exp1.example.com redirect=e2.example.com"}],"e2.example.com":[{"SPF":"v=spf1 -all"}],"e3.example.com":[{"SPF":"v=spf1 exp=exp1.example.com redirect=e4.example.com"}],"e4.example.com":[{"SPF":"v=spf1 -all exp=exp2.example.com"}],"exp1.example.com":[{"TXT":"No-see-um"}],"exp2.example.com":[{"TXT":"See me."}],"exp3.example.com":[{"TXT":"Correct!"}],"exp4.example.com":[{"TXT":"%{l} in implementation"}],"e5.example.com":[{"SPF":"v=spf1 1up=foo"}],"e6.example.com":[{"SPF":"v=spf1 =all"}],"e7.example.com":[{"SPF":"v=spf1 include:e3.example.com -all exp=exp3.example.com"}],"e8.example.com":[{"SPF":"v=spf1 -all exp=exp4.example.com"}],"e9.example.com":[{"SPF":"v=spf1 -all foo=%abc"}],"e10.example.com":[{"SPF":"v=spf1 redirect=erehwon.example.com"}],"e11.example.com":[{"SPF":"v=spf1 -all exp=e11msg.example.com"}],"e11msg.example.com":[{"TXT":"Answer a fool according to his folly."},{"TXT":"Do not answer a fool according to his folly."}],"e12.example.com":[{"SPF":"v=spf1 exp= -all"}],"e13.example.com":[{"SPF":"v=spf1 exp=e13msg.example.com -all"}],"e13msg.example.com":[{"TXT":"The %{x}-files."}],"e14.example.com":[{"SPF":"v=spf1 exp=e13msg.example.com -all exp=e11msg.example.com"}],"e15.example.com":[{"SPF":"v=spf1 redirect=e12.example.com -all redirect=e12.example.com"}],"e16.example.com":[{"SPF":"v=spf1 exp=-all"}],"e17.example.com":[{"SPF":"v=spf1 redirect=-all ?all"}],"e18.example.com":[{"SPF":"v=spf1 ?all redirect="}],"e19.example.com":[{"SPF":"v=spf1 default=pass"}],"e20.example.com":[{"SPF":"v=spf1 default=+"}],"e21.example.com":[{"SPF":"v=spf1 exp=e21msg.example.com -all"}],"e21msg.example.com":["TIMEOUT"],"e22.example.com":[{"SPF":"v=spf1 exp=mail.example.com -all"}],"nonascii.example.com":[{"SPF":"v=spf1 exp=badexp.example.com -all"}],"badexp.example.com":[{"TXT":"ï»¿Explanation"}],"tworecs.example.com":[{"SPF":"v=spf1 exp=twoexp.example.com -all"}],"twoexp.example.com":[{"TXT":"one"},{"TXT":"two"}],"e23.example.com":[{"SPF":"v=spf1 a:erehwon.example.com a:foobar.com exp=nxdomain.com -all"}],"e24.example.com":[{"SPF":"v=spf1 redirect=testimplicit.example.com"},{"A":"192.0.2.1"}],"testimplicit.example.com":[{"SPF":"v=spf1 a -all"},{"A":"192.0.2.2"}]}, failOnNoFake: true, helo: "mail.example.com"}
        let promise = spf.check_host('1.2.3.4', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'PERMERROR');
        });
      });
      it('exp-twice', function(){
        let email = 'foo@e14.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 exp=exp1.example.com redirect=e2.example.com"}],"e2.example.com":[{"SPF":"v=spf1 -all"}],"e3.example.com":[{"SPF":"v=spf1 exp=exp1.example.com redirect=e4.example.com"}],"e4.example.com":[{"SPF":"v=spf1 -all exp=exp2.example.com"}],"exp1.example.com":[{"TXT":"No-see-um"}],"exp2.example.com":[{"TXT":"See me."}],"exp3.example.com":[{"TXT":"Correct!"}],"exp4.example.com":[{"TXT":"%{l} in implementation"}],"e5.example.com":[{"SPF":"v=spf1 1up=foo"}],"e6.example.com":[{"SPF":"v=spf1 =all"}],"e7.example.com":[{"SPF":"v=spf1 include:e3.example.com -all exp=exp3.example.com"}],"e8.example.com":[{"SPF":"v=spf1 -all exp=exp4.example.com"}],"e9.example.com":[{"SPF":"v=spf1 -all foo=%abc"}],"e10.example.com":[{"SPF":"v=spf1 redirect=erehwon.example.com"}],"e11.example.com":[{"SPF":"v=spf1 -all exp=e11msg.example.com"}],"e11msg.example.com":[{"TXT":"Answer a fool according to his folly."},{"TXT":"Do not answer a fool according to his folly."}],"e12.example.com":[{"SPF":"v=spf1 exp= -all"}],"e13.example.com":[{"SPF":"v=spf1 exp=e13msg.example.com -all"}],"e13msg.example.com":[{"TXT":"The %{x}-files."}],"e14.example.com":[{"SPF":"v=spf1 exp=e13msg.example.com -all exp=e11msg.example.com"}],"e15.example.com":[{"SPF":"v=spf1 redirect=e12.example.com -all redirect=e12.example.com"}],"e16.example.com":[{"SPF":"v=spf1 exp=-all"}],"e17.example.com":[{"SPF":"v=spf1 redirect=-all ?all"}],"e18.example.com":[{"SPF":"v=spf1 ?all redirect="}],"e19.example.com":[{"SPF":"v=spf1 default=pass"}],"e20.example.com":[{"SPF":"v=spf1 default=+"}],"e21.example.com":[{"SPF":"v=spf1 exp=e21msg.example.com -all"}],"e21msg.example.com":["TIMEOUT"],"e22.example.com":[{"SPF":"v=spf1 exp=mail.example.com -all"}],"nonascii.example.com":[{"SPF":"v=spf1 exp=badexp.example.com -all"}],"badexp.example.com":[{"TXT":"ï»¿Explanation"}],"tworecs.example.com":[{"SPF":"v=spf1 exp=twoexp.example.com -all"}],"twoexp.example.com":[{"TXT":"one"},{"TXT":"two"}],"e23.example.com":[{"SPF":"v=spf1 a:erehwon.example.com a:foobar.com exp=nxdomain.com -all"}],"e24.example.com":[{"SPF":"v=spf1 redirect=testimplicit.example.com"},{"A":"192.0.2.1"}],"testimplicit.example.com":[{"SPF":"v=spf1 a -all"},{"A":"192.0.2.2"}]}, failOnNoFake: true, helo: "mail.example.com"}
        let promise = spf.check_host('1.2.3.4', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'PERMERROR');
        });
      });
      it('redirect-empty-domain', function(){
        let email = 'foo@e18.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 exp=exp1.example.com redirect=e2.example.com"}],"e2.example.com":[{"SPF":"v=spf1 -all"}],"e3.example.com":[{"SPF":"v=spf1 exp=exp1.example.com redirect=e4.example.com"}],"e4.example.com":[{"SPF":"v=spf1 -all exp=exp2.example.com"}],"exp1.example.com":[{"TXT":"No-see-um"}],"exp2.example.com":[{"TXT":"See me."}],"exp3.example.com":[{"TXT":"Correct!"}],"exp4.example.com":[{"TXT":"%{l} in implementation"}],"e5.example.com":[{"SPF":"v=spf1 1up=foo"}],"e6.example.com":[{"SPF":"v=spf1 =all"}],"e7.example.com":[{"SPF":"v=spf1 include:e3.example.com -all exp=exp3.example.com"}],"e8.example.com":[{"SPF":"v=spf1 -all exp=exp4.example.com"}],"e9.example.com":[{"SPF":"v=spf1 -all foo=%abc"}],"e10.example.com":[{"SPF":"v=spf1 redirect=erehwon.example.com"}],"e11.example.com":[{"SPF":"v=spf1 -all exp=e11msg.example.com"}],"e11msg.example.com":[{"TXT":"Answer a fool according to his folly."},{"TXT":"Do not answer a fool according to his folly."}],"e12.example.com":[{"SPF":"v=spf1 exp= -all"}],"e13.example.com":[{"SPF":"v=spf1 exp=e13msg.example.com -all"}],"e13msg.example.com":[{"TXT":"The %{x}-files."}],"e14.example.com":[{"SPF":"v=spf1 exp=e13msg.example.com -all exp=e11msg.example.com"}],"e15.example.com":[{"SPF":"v=spf1 redirect=e12.example.com -all redirect=e12.example.com"}],"e16.example.com":[{"SPF":"v=spf1 exp=-all"}],"e17.example.com":[{"SPF":"v=spf1 redirect=-all ?all"}],"e18.example.com":[{"SPF":"v=spf1 ?all redirect="}],"e19.example.com":[{"SPF":"v=spf1 default=pass"}],"e20.example.com":[{"SPF":"v=spf1 default=+"}],"e21.example.com":[{"SPF":"v=spf1 exp=e21msg.example.com -all"}],"e21msg.example.com":["TIMEOUT"],"e22.example.com":[{"SPF":"v=spf1 exp=mail.example.com -all"}],"nonascii.example.com":[{"SPF":"v=spf1 exp=badexp.example.com -all"}],"badexp.example.com":[{"TXT":"ï»¿Explanation"}],"tworecs.example.com":[{"SPF":"v=spf1 exp=twoexp.example.com -all"}],"twoexp.example.com":[{"TXT":"one"},{"TXT":"two"}],"e23.example.com":[{"SPF":"v=spf1 a:erehwon.example.com a:foobar.com exp=nxdomain.com -all"}],"e24.example.com":[{"SPF":"v=spf1 redirect=testimplicit.example.com"},{"A":"192.0.2.1"}],"testimplicit.example.com":[{"SPF":"v=spf1 a -all"},{"A":"192.0.2.2"}]}, failOnNoFake: true, helo: "mail.example.com"}
        let promise = spf.check_host('1.2.3.4', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'PERMERROR');
        });
      });
      it('redirect-twice', function(){
        let email = 'foo@e15.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 exp=exp1.example.com redirect=e2.example.com"}],"e2.example.com":[{"SPF":"v=spf1 -all"}],"e3.example.com":[{"SPF":"v=spf1 exp=exp1.example.com redirect=e4.example.com"}],"e4.example.com":[{"SPF":"v=spf1 -all exp=exp2.example.com"}],"exp1.example.com":[{"TXT":"No-see-um"}],"exp2.example.com":[{"TXT":"See me."}],"exp3.example.com":[{"TXT":"Correct!"}],"exp4.example.com":[{"TXT":"%{l} in implementation"}],"e5.example.com":[{"SPF":"v=spf1 1up=foo"}],"e6.example.com":[{"SPF":"v=spf1 =all"}],"e7.example.com":[{"SPF":"v=spf1 include:e3.example.com -all exp=exp3.example.com"}],"e8.example.com":[{"SPF":"v=spf1 -all exp=exp4.example.com"}],"e9.example.com":[{"SPF":"v=spf1 -all foo=%abc"}],"e10.example.com":[{"SPF":"v=spf1 redirect=erehwon.example.com"}],"e11.example.com":[{"SPF":"v=spf1 -all exp=e11msg.example.com"}],"e11msg.example.com":[{"TXT":"Answer a fool according to his folly."},{"TXT":"Do not answer a fool according to his folly."}],"e12.example.com":[{"SPF":"v=spf1 exp= -all"}],"e13.example.com":[{"SPF":"v=spf1 exp=e13msg.example.com -all"}],"e13msg.example.com":[{"TXT":"The %{x}-files."}],"e14.example.com":[{"SPF":"v=spf1 exp=e13msg.example.com -all exp=e11msg.example.com"}],"e15.example.com":[{"SPF":"v=spf1 redirect=e12.example.com -all redirect=e12.example.com"}],"e16.example.com":[{"SPF":"v=spf1 exp=-all"}],"e17.example.com":[{"SPF":"v=spf1 redirect=-all ?all"}],"e18.example.com":[{"SPF":"v=spf1 ?all redirect="}],"e19.example.com":[{"SPF":"v=spf1 default=pass"}],"e20.example.com":[{"SPF":"v=spf1 default=+"}],"e21.example.com":[{"SPF":"v=spf1 exp=e21msg.example.com -all"}],"e21msg.example.com":["TIMEOUT"],"e22.example.com":[{"SPF":"v=spf1 exp=mail.example.com -all"}],"nonascii.example.com":[{"SPF":"v=spf1 exp=badexp.example.com -all"}],"badexp.example.com":[{"TXT":"ï»¿Explanation"}],"tworecs.example.com":[{"SPF":"v=spf1 exp=twoexp.example.com -all"}],"twoexp.example.com":[{"TXT":"one"},{"TXT":"two"}],"e23.example.com":[{"SPF":"v=spf1 a:erehwon.example.com a:foobar.com exp=nxdomain.com -all"}],"e24.example.com":[{"SPF":"v=spf1 redirect=testimplicit.example.com"},{"A":"192.0.2.1"}],"testimplicit.example.com":[{"SPF":"v=spf1 a -all"},{"A":"192.0.2.2"}]}, failOnNoFake: true, helo: "mail.example.com"}
        let promise = spf.check_host('1.2.3.4', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'PERMERROR');
        });
      });
      it('unknown-modifier-syntax', function(){
        let email = 'foo@e9.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 exp=exp1.example.com redirect=e2.example.com"}],"e2.example.com":[{"SPF":"v=spf1 -all"}],"e3.example.com":[{"SPF":"v=spf1 exp=exp1.example.com redirect=e4.example.com"}],"e4.example.com":[{"SPF":"v=spf1 -all exp=exp2.example.com"}],"exp1.example.com":[{"TXT":"No-see-um"}],"exp2.example.com":[{"TXT":"See me."}],"exp3.example.com":[{"TXT":"Correct!"}],"exp4.example.com":[{"TXT":"%{l} in implementation"}],"e5.example.com":[{"SPF":"v=spf1 1up=foo"}],"e6.example.com":[{"SPF":"v=spf1 =all"}],"e7.example.com":[{"SPF":"v=spf1 include:e3.example.com -all exp=exp3.example.com"}],"e8.example.com":[{"SPF":"v=spf1 -all exp=exp4.example.com"}],"e9.example.com":[{"SPF":"v=spf1 -all foo=%abc"}],"e10.example.com":[{"SPF":"v=spf1 redirect=erehwon.example.com"}],"e11.example.com":[{"SPF":"v=spf1 -all exp=e11msg.example.com"}],"e11msg.example.com":[{"TXT":"Answer a fool according to his folly."},{"TXT":"Do not answer a fool according to his folly."}],"e12.example.com":[{"SPF":"v=spf1 exp= -all"}],"e13.example.com":[{"SPF":"v=spf1 exp=e13msg.example.com -all"}],"e13msg.example.com":[{"TXT":"The %{x}-files."}],"e14.example.com":[{"SPF":"v=spf1 exp=e13msg.example.com -all exp=e11msg.example.com"}],"e15.example.com":[{"SPF":"v=spf1 redirect=e12.example.com -all redirect=e12.example.com"}],"e16.example.com":[{"SPF":"v=spf1 exp=-all"}],"e17.example.com":[{"SPF":"v=spf1 redirect=-all ?all"}],"e18.example.com":[{"SPF":"v=spf1 ?all redirect="}],"e19.example.com":[{"SPF":"v=spf1 default=pass"}],"e20.example.com":[{"SPF":"v=spf1 default=+"}],"e21.example.com":[{"SPF":"v=spf1 exp=e21msg.example.com -all"}],"e21msg.example.com":["TIMEOUT"],"e22.example.com":[{"SPF":"v=spf1 exp=mail.example.com -all"}],"nonascii.example.com":[{"SPF":"v=spf1 exp=badexp.example.com -all"}],"badexp.example.com":[{"TXT":"ï»¿Explanation"}],"tworecs.example.com":[{"SPF":"v=spf1 exp=twoexp.example.com -all"}],"twoexp.example.com":[{"TXT":"one"},{"TXT":"two"}],"e23.example.com":[{"SPF":"v=spf1 a:erehwon.example.com a:foobar.com exp=nxdomain.com -all"}],"e24.example.com":[{"SPF":"v=spf1 redirect=testimplicit.example.com"},{"A":"192.0.2.1"}],"testimplicit.example.com":[{"SPF":"v=spf1 a -all"},{"A":"192.0.2.2"}]}, failOnNoFake: true, helo: "mail.example.com"}
        let promise = spf.check_host('1.2.3.4', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'PERMERROR');
        });
      });
      it('default-modifier-obsolete', function(){
        let email = 'foo@e19.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 exp=exp1.example.com redirect=e2.example.com"}],"e2.example.com":[{"SPF":"v=spf1 -all"}],"e3.example.com":[{"SPF":"v=spf1 exp=exp1.example.com redirect=e4.example.com"}],"e4.example.com":[{"SPF":"v=spf1 -all exp=exp2.example.com"}],"exp1.example.com":[{"TXT":"No-see-um"}],"exp2.example.com":[{"TXT":"See me."}],"exp3.example.com":[{"TXT":"Correct!"}],"exp4.example.com":[{"TXT":"%{l} in implementation"}],"e5.example.com":[{"SPF":"v=spf1 1up=foo"}],"e6.example.com":[{"SPF":"v=spf1 =all"}],"e7.example.com":[{"SPF":"v=spf1 include:e3.example.com -all exp=exp3.example.com"}],"e8.example.com":[{"SPF":"v=spf1 -all exp=exp4.example.com"}],"e9.example.com":[{"SPF":"v=spf1 -all foo=%abc"}],"e10.example.com":[{"SPF":"v=spf1 redirect=erehwon.example.com"}],"e11.example.com":[{"SPF":"v=spf1 -all exp=e11msg.example.com"}],"e11msg.example.com":[{"TXT":"Answer a fool according to his folly."},{"TXT":"Do not answer a fool according to his folly."}],"e12.example.com":[{"SPF":"v=spf1 exp= -all"}],"e13.example.com":[{"SPF":"v=spf1 exp=e13msg.example.com -all"}],"e13msg.example.com":[{"TXT":"The %{x}-files."}],"e14.example.com":[{"SPF":"v=spf1 exp=e13msg.example.com -all exp=e11msg.example.com"}],"e15.example.com":[{"SPF":"v=spf1 redirect=e12.example.com -all redirect=e12.example.com"}],"e16.example.com":[{"SPF":"v=spf1 exp=-all"}],"e17.example.com":[{"SPF":"v=spf1 redirect=-all ?all"}],"e18.example.com":[{"SPF":"v=spf1 ?all redirect="}],"e19.example.com":[{"SPF":"v=spf1 default=pass"}],"e20.example.com":[{"SPF":"v=spf1 default=+"}],"e21.example.com":[{"SPF":"v=spf1 exp=e21msg.example.com -all"}],"e21msg.example.com":["TIMEOUT"],"e22.example.com":[{"SPF":"v=spf1 exp=mail.example.com -all"}],"nonascii.example.com":[{"SPF":"v=spf1 exp=badexp.example.com -all"}],"badexp.example.com":[{"TXT":"ï»¿Explanation"}],"tworecs.example.com":[{"SPF":"v=spf1 exp=twoexp.example.com -all"}],"twoexp.example.com":[{"TXT":"one"},{"TXT":"two"}],"e23.example.com":[{"SPF":"v=spf1 a:erehwon.example.com a:foobar.com exp=nxdomain.com -all"}],"e24.example.com":[{"SPF":"v=spf1 redirect=testimplicit.example.com"},{"A":"192.0.2.1"}],"testimplicit.example.com":[{"SPF":"v=spf1 a -all"},{"A":"192.0.2.2"}]}, failOnNoFake: true, helo: "mail.example.com"}
        let promise = spf.check_host('1.2.3.4', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'NEUTRAL');
        });
      });
      it('default-modifier-obsolete2', function(){
        let email = 'foo@e20.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 exp=exp1.example.com redirect=e2.example.com"}],"e2.example.com":[{"SPF":"v=spf1 -all"}],"e3.example.com":[{"SPF":"v=spf1 exp=exp1.example.com redirect=e4.example.com"}],"e4.example.com":[{"SPF":"v=spf1 -all exp=exp2.example.com"}],"exp1.example.com":[{"TXT":"No-see-um"}],"exp2.example.com":[{"TXT":"See me."}],"exp3.example.com":[{"TXT":"Correct!"}],"exp4.example.com":[{"TXT":"%{l} in implementation"}],"e5.example.com":[{"SPF":"v=spf1 1up=foo"}],"e6.example.com":[{"SPF":"v=spf1 =all"}],"e7.example.com":[{"SPF":"v=spf1 include:e3.example.com -all exp=exp3.example.com"}],"e8.example.com":[{"SPF":"v=spf1 -all exp=exp4.example.com"}],"e9.example.com":[{"SPF":"v=spf1 -all foo=%abc"}],"e10.example.com":[{"SPF":"v=spf1 redirect=erehwon.example.com"}],"e11.example.com":[{"SPF":"v=spf1 -all exp=e11msg.example.com"}],"e11msg.example.com":[{"TXT":"Answer a fool according to his folly."},{"TXT":"Do not answer a fool according to his folly."}],"e12.example.com":[{"SPF":"v=spf1 exp= -all"}],"e13.example.com":[{"SPF":"v=spf1 exp=e13msg.example.com -all"}],"e13msg.example.com":[{"TXT":"The %{x}-files."}],"e14.example.com":[{"SPF":"v=spf1 exp=e13msg.example.com -all exp=e11msg.example.com"}],"e15.example.com":[{"SPF":"v=spf1 redirect=e12.example.com -all redirect=e12.example.com"}],"e16.example.com":[{"SPF":"v=spf1 exp=-all"}],"e17.example.com":[{"SPF":"v=spf1 redirect=-all ?all"}],"e18.example.com":[{"SPF":"v=spf1 ?all redirect="}],"e19.example.com":[{"SPF":"v=spf1 default=pass"}],"e20.example.com":[{"SPF":"v=spf1 default=+"}],"e21.example.com":[{"SPF":"v=spf1 exp=e21msg.example.com -all"}],"e21msg.example.com":["TIMEOUT"],"e22.example.com":[{"SPF":"v=spf1 exp=mail.example.com -all"}],"nonascii.example.com":[{"SPF":"v=spf1 exp=badexp.example.com -all"}],"badexp.example.com":[{"TXT":"ï»¿Explanation"}],"tworecs.example.com":[{"SPF":"v=spf1 exp=twoexp.example.com -all"}],"twoexp.example.com":[{"TXT":"one"},{"TXT":"two"}],"e23.example.com":[{"SPF":"v=spf1 a:erehwon.example.com a:foobar.com exp=nxdomain.com -all"}],"e24.example.com":[{"SPF":"v=spf1 redirect=testimplicit.example.com"},{"A":"192.0.2.1"}],"testimplicit.example.com":[{"SPF":"v=spf1 a -all"},{"A":"192.0.2.2"}]}, failOnNoFake: true, helo: "mail.example.com"}
        let promise = spf.check_host('1.2.3.4', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'NEUTRAL');
        });
      });
      it('non-ascii-exp', function(){
        let email = 'foobar@nonascii.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 exp=exp1.example.com redirect=e2.example.com"}],"e2.example.com":[{"SPF":"v=spf1 -all"}],"e3.example.com":[{"SPF":"v=spf1 exp=exp1.example.com redirect=e4.example.com"}],"e4.example.com":[{"SPF":"v=spf1 -all exp=exp2.example.com"}],"exp1.example.com":[{"TXT":"No-see-um"}],"exp2.example.com":[{"TXT":"See me."}],"exp3.example.com":[{"TXT":"Correct!"}],"exp4.example.com":[{"TXT":"%{l} in implementation"}],"e5.example.com":[{"SPF":"v=spf1 1up=foo"}],"e6.example.com":[{"SPF":"v=spf1 =all"}],"e7.example.com":[{"SPF":"v=spf1 include:e3.example.com -all exp=exp3.example.com"}],"e8.example.com":[{"SPF":"v=spf1 -all exp=exp4.example.com"}],"e9.example.com":[{"SPF":"v=spf1 -all foo=%abc"}],"e10.example.com":[{"SPF":"v=spf1 redirect=erehwon.example.com"}],"e11.example.com":[{"SPF":"v=spf1 -all exp=e11msg.example.com"}],"e11msg.example.com":[{"TXT":"Answer a fool according to his folly."},{"TXT":"Do not answer a fool according to his folly."}],"e12.example.com":[{"SPF":"v=spf1 exp= -all"}],"e13.example.com":[{"SPF":"v=spf1 exp=e13msg.example.com -all"}],"e13msg.example.com":[{"TXT":"The %{x}-files."}],"e14.example.com":[{"SPF":"v=spf1 exp=e13msg.example.com -all exp=e11msg.example.com"}],"e15.example.com":[{"SPF":"v=spf1 redirect=e12.example.com -all redirect=e12.example.com"}],"e16.example.com":[{"SPF":"v=spf1 exp=-all"}],"e17.example.com":[{"SPF":"v=spf1 redirect=-all ?all"}],"e18.example.com":[{"SPF":"v=spf1 ?all redirect="}],"e19.example.com":[{"SPF":"v=spf1 default=pass"}],"e20.example.com":[{"SPF":"v=spf1 default=+"}],"e21.example.com":[{"SPF":"v=spf1 exp=e21msg.example.com -all"}],"e21msg.example.com":["TIMEOUT"],"e22.example.com":[{"SPF":"v=spf1 exp=mail.example.com -all"}],"nonascii.example.com":[{"SPF":"v=spf1 exp=badexp.example.com -all"}],"badexp.example.com":[{"TXT":"ï»¿Explanation"}],"tworecs.example.com":[{"SPF":"v=spf1 exp=twoexp.example.com -all"}],"twoexp.example.com":[{"TXT":"one"},{"TXT":"two"}],"e23.example.com":[{"SPF":"v=spf1 a:erehwon.example.com a:foobar.com exp=nxdomain.com -all"}],"e24.example.com":[{"SPF":"v=spf1 redirect=testimplicit.example.com"},{"A":"192.0.2.1"}],"testimplicit.example.com":[{"SPF":"v=spf1 a -all"},{"A":"192.0.2.2"}]}, failOnNoFake: true, helo: "hosed"}
        let promise = spf.check_host('1.2.3.4', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'FAIL');
        });
      });
      it('two-exp-records', function(){
        let email = 'foobar@tworecs.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 exp=exp1.example.com redirect=e2.example.com"}],"e2.example.com":[{"SPF":"v=spf1 -all"}],"e3.example.com":[{"SPF":"v=spf1 exp=exp1.example.com redirect=e4.example.com"}],"e4.example.com":[{"SPF":"v=spf1 -all exp=exp2.example.com"}],"exp1.example.com":[{"TXT":"No-see-um"}],"exp2.example.com":[{"TXT":"See me."}],"exp3.example.com":[{"TXT":"Correct!"}],"exp4.example.com":[{"TXT":"%{l} in implementation"}],"e5.example.com":[{"SPF":"v=spf1 1up=foo"}],"e6.example.com":[{"SPF":"v=spf1 =all"}],"e7.example.com":[{"SPF":"v=spf1 include:e3.example.com -all exp=exp3.example.com"}],"e8.example.com":[{"SPF":"v=spf1 -all exp=exp4.example.com"}],"e9.example.com":[{"SPF":"v=spf1 -all foo=%abc"}],"e10.example.com":[{"SPF":"v=spf1 redirect=erehwon.example.com"}],"e11.example.com":[{"SPF":"v=spf1 -all exp=e11msg.example.com"}],"e11msg.example.com":[{"TXT":"Answer a fool according to his folly."},{"TXT":"Do not answer a fool according to his folly."}],"e12.example.com":[{"SPF":"v=spf1 exp= -all"}],"e13.example.com":[{"SPF":"v=spf1 exp=e13msg.example.com -all"}],"e13msg.example.com":[{"TXT":"The %{x}-files."}],"e14.example.com":[{"SPF":"v=spf1 exp=e13msg.example.com -all exp=e11msg.example.com"}],"e15.example.com":[{"SPF":"v=spf1 redirect=e12.example.com -all redirect=e12.example.com"}],"e16.example.com":[{"SPF":"v=spf1 exp=-all"}],"e17.example.com":[{"SPF":"v=spf1 redirect=-all ?all"}],"e18.example.com":[{"SPF":"v=spf1 ?all redirect="}],"e19.example.com":[{"SPF":"v=spf1 default=pass"}],"e20.example.com":[{"SPF":"v=spf1 default=+"}],"e21.example.com":[{"SPF":"v=spf1 exp=e21msg.example.com -all"}],"e21msg.example.com":["TIMEOUT"],"e22.example.com":[{"SPF":"v=spf1 exp=mail.example.com -all"}],"nonascii.example.com":[{"SPF":"v=spf1 exp=badexp.example.com -all"}],"badexp.example.com":[{"TXT":"ï»¿Explanation"}],"tworecs.example.com":[{"SPF":"v=spf1 exp=twoexp.example.com -all"}],"twoexp.example.com":[{"TXT":"one"},{"TXT":"two"}],"e23.example.com":[{"SPF":"v=spf1 a:erehwon.example.com a:foobar.com exp=nxdomain.com -all"}],"e24.example.com":[{"SPF":"v=spf1 redirect=testimplicit.example.com"},{"A":"192.0.2.1"}],"testimplicit.example.com":[{"SPF":"v=spf1 a -all"},{"A":"192.0.2.2"}]}, failOnNoFake: true, helo: "hosed"}
        let promise = spf.check_host('1.2.3.4', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'FAIL');
        });
      });
      it('exp-void', function(){
        let email = 'foo@e23.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 exp=exp1.example.com redirect=e2.example.com"}],"e2.example.com":[{"SPF":"v=spf1 -all"}],"e3.example.com":[{"SPF":"v=spf1 exp=exp1.example.com redirect=e4.example.com"}],"e4.example.com":[{"SPF":"v=spf1 -all exp=exp2.example.com"}],"exp1.example.com":[{"TXT":"No-see-um"}],"exp2.example.com":[{"TXT":"See me."}],"exp3.example.com":[{"TXT":"Correct!"}],"exp4.example.com":[{"TXT":"%{l} in implementation"}],"e5.example.com":[{"SPF":"v=spf1 1up=foo"}],"e6.example.com":[{"SPF":"v=spf1 =all"}],"e7.example.com":[{"SPF":"v=spf1 include:e3.example.com -all exp=exp3.example.com"}],"e8.example.com":[{"SPF":"v=spf1 -all exp=exp4.example.com"}],"e9.example.com":[{"SPF":"v=spf1 -all foo=%abc"}],"e10.example.com":[{"SPF":"v=spf1 redirect=erehwon.example.com"}],"e11.example.com":[{"SPF":"v=spf1 -all exp=e11msg.example.com"}],"e11msg.example.com":[{"TXT":"Answer a fool according to his folly."},{"TXT":"Do not answer a fool according to his folly."}],"e12.example.com":[{"SPF":"v=spf1 exp= -all"}],"e13.example.com":[{"SPF":"v=spf1 exp=e13msg.example.com -all"}],"e13msg.example.com":[{"TXT":"The %{x}-files."}],"e14.example.com":[{"SPF":"v=spf1 exp=e13msg.example.com -all exp=e11msg.example.com"}],"e15.example.com":[{"SPF":"v=spf1 redirect=e12.example.com -all redirect=e12.example.com"}],"e16.example.com":[{"SPF":"v=spf1 exp=-all"}],"e17.example.com":[{"SPF":"v=spf1 redirect=-all ?all"}],"e18.example.com":[{"SPF":"v=spf1 ?all redirect="}],"e19.example.com":[{"SPF":"v=spf1 default=pass"}],"e20.example.com":[{"SPF":"v=spf1 default=+"}],"e21.example.com":[{"SPF":"v=spf1 exp=e21msg.example.com -all"}],"e21msg.example.com":["TIMEOUT"],"e22.example.com":[{"SPF":"v=spf1 exp=mail.example.com -all"}],"nonascii.example.com":[{"SPF":"v=spf1 exp=badexp.example.com -all"}],"badexp.example.com":[{"TXT":"ï»¿Explanation"}],"tworecs.example.com":[{"SPF":"v=spf1 exp=twoexp.example.com -all"}],"twoexp.example.com":[{"TXT":"one"},{"TXT":"two"}],"e23.example.com":[{"SPF":"v=spf1 a:erehwon.example.com a:foobar.com exp=nxdomain.com -all"}],"e24.example.com":[{"SPF":"v=spf1 redirect=testimplicit.example.com"},{"A":"192.0.2.1"}],"testimplicit.example.com":[{"SPF":"v=spf1 a -all"},{"A":"192.0.2.2"}]}, failOnNoFake: true, helo: "mail.example.com"}
        let promise = spf.check_host('1.2.3.4', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'FAIL');
        });
      });
      it('redirect-implicit', function(){
        let email = 'bar@e24.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 exp=exp1.example.com redirect=e2.example.com"}],"e2.example.com":[{"SPF":"v=spf1 -all"}],"e3.example.com":[{"SPF":"v=spf1 exp=exp1.example.com redirect=e4.example.com"}],"e4.example.com":[{"SPF":"v=spf1 -all exp=exp2.example.com"}],"exp1.example.com":[{"TXT":"No-see-um"}],"exp2.example.com":[{"TXT":"See me."}],"exp3.example.com":[{"TXT":"Correct!"}],"exp4.example.com":[{"TXT":"%{l} in implementation"}],"e5.example.com":[{"SPF":"v=spf1 1up=foo"}],"e6.example.com":[{"SPF":"v=spf1 =all"}],"e7.example.com":[{"SPF":"v=spf1 include:e3.example.com -all exp=exp3.example.com"}],"e8.example.com":[{"SPF":"v=spf1 -all exp=exp4.example.com"}],"e9.example.com":[{"SPF":"v=spf1 -all foo=%abc"}],"e10.example.com":[{"SPF":"v=spf1 redirect=erehwon.example.com"}],"e11.example.com":[{"SPF":"v=spf1 -all exp=e11msg.example.com"}],"e11msg.example.com":[{"TXT":"Answer a fool according to his folly."},{"TXT":"Do not answer a fool according to his folly."}],"e12.example.com":[{"SPF":"v=spf1 exp= -all"}],"e13.example.com":[{"SPF":"v=spf1 exp=e13msg.example.com -all"}],"e13msg.example.com":[{"TXT":"The %{x}-files."}],"e14.example.com":[{"SPF":"v=spf1 exp=e13msg.example.com -all exp=e11msg.example.com"}],"e15.example.com":[{"SPF":"v=spf1 redirect=e12.example.com -all redirect=e12.example.com"}],"e16.example.com":[{"SPF":"v=spf1 exp=-all"}],"e17.example.com":[{"SPF":"v=spf1 redirect=-all ?all"}],"e18.example.com":[{"SPF":"v=spf1 ?all redirect="}],"e19.example.com":[{"SPF":"v=spf1 default=pass"}],"e20.example.com":[{"SPF":"v=spf1 default=+"}],"e21.example.com":[{"SPF":"v=spf1 exp=e21msg.example.com -all"}],"e21msg.example.com":["TIMEOUT"],"e22.example.com":[{"SPF":"v=spf1 exp=mail.example.com -all"}],"nonascii.example.com":[{"SPF":"v=spf1 exp=badexp.example.com -all"}],"badexp.example.com":[{"TXT":"ï»¿Explanation"}],"tworecs.example.com":[{"SPF":"v=spf1 exp=twoexp.example.com -all"}],"twoexp.example.com":[{"TXT":"one"},{"TXT":"two"}],"e23.example.com":[{"SPF":"v=spf1 a:erehwon.example.com a:foobar.com exp=nxdomain.com -all"}],"e24.example.com":[{"SPF":"v=spf1 redirect=testimplicit.example.com"},{"A":"192.0.2.1"}],"testimplicit.example.com":[{"SPF":"v=spf1 a -all"},{"A":"192.0.2.2"}]}, failOnNoFake: true, helo: "e24.example.com"}
        let promise = spf.check_host('192.0.2.2', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'PASS');
        });
      });
    });
    describe('Macro expansion rules', function(){
      it('trailing-dot-domain', function(){
        let email = 'test@example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"example.com.d.spf.example.com":[{"SPF":"v=spf1 redirect=a.spf.example.com"}],"a.spf.example.com":[{"SPF":"v=spf1 include:o.spf.example.com. ~all"}],"o.spf.example.com":[{"SPF":"v=spf1 ip4:192.168.218.40"}],"msgbas2x.cos.example.com":[{"A":"192.168.218.40"}],"example.com":[{"A":"192.168.90.76"},{"SPF":"v=spf1 redirect=%{d}.d.spf.example.com."}],"exp.example.com":[{"SPF":"v=spf1 exp=msg.example.com. -all"}],"msg.example.com":[{"TXT":"This is a test."}],"e1.example.com":[{"SPF":"v=spf1 -exists:%(ir).sbl.example.com ?all"}],"e1e.example.com":[{"SPF":"v=spf1 exists:foo%(ir).sbl.example.com ?all"}],"e1t.example.com":[{"SPF":"v=spf1 exists:foo%.sbl.example.com ?all"}],"e1a.example.com":[{"SPF":"v=spf1 a:macro%%percent%_%_space%-url-space.example.com -all"}],"macro%percent  space%20url-space.example.com":[{"A":"1.2.3.4"}],"e2.example.com":[{"SPF":"v=spf1 -all exp=%{r}.example.com"}],"e3.example.com":[{"SPF":"v=spf1 -all exp=%{ir}.example.com"}],"40.218.168.192.example.com":[{"TXT":"Connections from %{c} not authorized."}],"somewhat.long.exp.example.com":[{"SPF":"v=spf1 -all exp=foobar.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.example.com"}],"somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.example.com":[{"TXT":"Congratulations!  That was tricky."}],"e4.example.com":[{"SPF":"v=spf1 -all exp=e4msg.example.com"}],"e4msg.example.com":[{"TXT":"%{c} is queried as %{ir}.%{v}.arpa"}],"e5.example.com":[{"SPF":"v=spf1 a:%{a}.example.com -all"}],"e6.example.com":[{"SPF":"v=spf1 -all exp=e6msg.example.com"}],"e6msg.example.com":[{"TXT":"connect from %{p}"}],"mx.example.com":[{"A":"192.168.218.41"},{"A":"192.168.218.42"},{"AAAA":"CAFE:BABE::2"},{"AAAA":"CAFE:BABE::3"}],"40.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"}],"41.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"}],"42.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"},{"PTR":"mx.e7.example.com"}],"1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.E.B.A.B.E.F.A.C.ip6.arpa":[{"PTR":"mx.example.com"}],"3.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.E.B.A.B.E.F.A.C.ip6.arpa":[{"PTR":"mx.example.com"}],"mx.e7.example.com":[{"A":"192.168.218.42"}],"mx.e7.example.com.should.example.com":[{"A":"127.0.0.2"}],"mx.example.com.ok.example.com":[{"A":"127.0.0.2"}],"e7.example.com":[{"SPF":"v=spf1 exists:%{p}.should.example.com ~exists:%{p}.ok.example.com"}],"e8.example.com":[{"SPF":"v=spf1 -all exp=msg8.%{D2}"}],"msg8.example.com":[{"TXT":"http://example.com/why.html?l=%{L}"}],"e9.example.com":[{"SPF":"v=spf1 a:%{H} -all"}],"e10.example.com":[{"SPF":"v=spf1 -include:_spfh.%{d2} ip4:1.2.3.0/24 -all"}],"_spfh.example.com":[{"SPF":"v=spf1 -a:%{h} +all"}],"e11.example.com":[{"SPF":"v=spf1 exists:%{i}.%{l2r-}.user.%{d2}"}],"1.2.3.4.gladstone.philip.user.example.com":[{"A":"127.0.0.2"}],"e12.example.com":[{"SPF":"v=spf1 exists:%{l2r+-}.user.%{d2}"}],"bar.foo.user.example.com":[{"A":"127.0.0.2"}]}, failOnNoFake: true, helo: "msgbas2x.cos.example.com"}
        let promise = spf.check_host('192.168.218.40', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'PASS');
        });
      });
      it('trailing-dot-exp', function(){
        let email = 'test@exp.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"example.com.d.spf.example.com":[{"SPF":"v=spf1 redirect=a.spf.example.com"}],"a.spf.example.com":[{"SPF":"v=spf1 include:o.spf.example.com. ~all"}],"o.spf.example.com":[{"SPF":"v=spf1 ip4:192.168.218.40"}],"msgbas2x.cos.example.com":[{"A":"192.168.218.40"}],"example.com":[{"A":"192.168.90.76"},{"SPF":"v=spf1 redirect=%{d}.d.spf.example.com."}],"exp.example.com":[{"SPF":"v=spf1 exp=msg.example.com. -all"}],"msg.example.com":[{"TXT":"This is a test."}],"e1.example.com":[{"SPF":"v=spf1 -exists:%(ir).sbl.example.com ?all"}],"e1e.example.com":[{"SPF":"v=spf1 exists:foo%(ir).sbl.example.com ?all"}],"e1t.example.com":[{"SPF":"v=spf1 exists:foo%.sbl.example.com ?all"}],"e1a.example.com":[{"SPF":"v=spf1 a:macro%%percent%_%_space%-url-space.example.com -all"}],"macro%percent  space%20url-space.example.com":[{"A":"1.2.3.4"}],"e2.example.com":[{"SPF":"v=spf1 -all exp=%{r}.example.com"}],"e3.example.com":[{"SPF":"v=spf1 -all exp=%{ir}.example.com"}],"40.218.168.192.example.com":[{"TXT":"Connections from %{c} not authorized."}],"somewhat.long.exp.example.com":[{"SPF":"v=spf1 -all exp=foobar.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.example.com"}],"somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.example.com":[{"TXT":"Congratulations!  That was tricky."}],"e4.example.com":[{"SPF":"v=spf1 -all exp=e4msg.example.com"}],"e4msg.example.com":[{"TXT":"%{c} is queried as %{ir}.%{v}.arpa"}],"e5.example.com":[{"SPF":"v=spf1 a:%{a}.example.com -all"}],"e6.example.com":[{"SPF":"v=spf1 -all exp=e6msg.example.com"}],"e6msg.example.com":[{"TXT":"connect from %{p}"}],"mx.example.com":[{"A":"192.168.218.41"},{"A":"192.168.218.42"},{"AAAA":"CAFE:BABE::2"},{"AAAA":"CAFE:BABE::3"}],"40.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"}],"41.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"}],"42.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"},{"PTR":"mx.e7.example.com"}],"1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.E.B.A.B.E.F.A.C.ip6.arpa":[{"PTR":"mx.example.com"}],"3.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.E.B.A.B.E.F.A.C.ip6.arpa":[{"PTR":"mx.example.com"}],"mx.e7.example.com":[{"A":"192.168.218.42"}],"mx.e7.example.com.should.example.com":[{"A":"127.0.0.2"}],"mx.example.com.ok.example.com":[{"A":"127.0.0.2"}],"e7.example.com":[{"SPF":"v=spf1 exists:%{p}.should.example.com ~exists:%{p}.ok.example.com"}],"e8.example.com":[{"SPF":"v=spf1 -all exp=msg8.%{D2}"}],"msg8.example.com":[{"TXT":"http://example.com/why.html?l=%{L}"}],"e9.example.com":[{"SPF":"v=spf1 a:%{H} -all"}],"e10.example.com":[{"SPF":"v=spf1 -include:_spfh.%{d2} ip4:1.2.3.0/24 -all"}],"_spfh.example.com":[{"SPF":"v=spf1 -a:%{h} +all"}],"e11.example.com":[{"SPF":"v=spf1 exists:%{i}.%{l2r-}.user.%{d2}"}],"1.2.3.4.gladstone.philip.user.example.com":[{"A":"127.0.0.2"}],"e12.example.com":[{"SPF":"v=spf1 exists:%{l2r+-}.user.%{d2}"}],"bar.foo.user.example.com":[{"A":"127.0.0.2"}]}, failOnNoFake: true, helo: "msgbas2x.cos.example.com"}
        let promise = spf.check_host('192.168.218.40', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'FAIL');
        });
      });
      it('exp-only-macro-char', function(){
        let email = 'test@e2.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"example.com.d.spf.example.com":[{"SPF":"v=spf1 redirect=a.spf.example.com"}],"a.spf.example.com":[{"SPF":"v=spf1 include:o.spf.example.com. ~all"}],"o.spf.example.com":[{"SPF":"v=spf1 ip4:192.168.218.40"}],"msgbas2x.cos.example.com":[{"A":"192.168.218.40"}],"example.com":[{"A":"192.168.90.76"},{"SPF":"v=spf1 redirect=%{d}.d.spf.example.com."}],"exp.example.com":[{"SPF":"v=spf1 exp=msg.example.com. -all"}],"msg.example.com":[{"TXT":"This is a test."}],"e1.example.com":[{"SPF":"v=spf1 -exists:%(ir).sbl.example.com ?all"}],"e1e.example.com":[{"SPF":"v=spf1 exists:foo%(ir).sbl.example.com ?all"}],"e1t.example.com":[{"SPF":"v=spf1 exists:foo%.sbl.example.com ?all"}],"e1a.example.com":[{"SPF":"v=spf1 a:macro%%percent%_%_space%-url-space.example.com -all"}],"macro%percent  space%20url-space.example.com":[{"A":"1.2.3.4"}],"e2.example.com":[{"SPF":"v=spf1 -all exp=%{r}.example.com"}],"e3.example.com":[{"SPF":"v=spf1 -all exp=%{ir}.example.com"}],"40.218.168.192.example.com":[{"TXT":"Connections from %{c} not authorized."}],"somewhat.long.exp.example.com":[{"SPF":"v=spf1 -all exp=foobar.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.example.com"}],"somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.example.com":[{"TXT":"Congratulations!  That was tricky."}],"e4.example.com":[{"SPF":"v=spf1 -all exp=e4msg.example.com"}],"e4msg.example.com":[{"TXT":"%{c} is queried as %{ir}.%{v}.arpa"}],"e5.example.com":[{"SPF":"v=spf1 a:%{a}.example.com -all"}],"e6.example.com":[{"SPF":"v=spf1 -all exp=e6msg.example.com"}],"e6msg.example.com":[{"TXT":"connect from %{p}"}],"mx.example.com":[{"A":"192.168.218.41"},{"A":"192.168.218.42"},{"AAAA":"CAFE:BABE::2"},{"AAAA":"CAFE:BABE::3"}],"40.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"}],"41.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"}],"42.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"},{"PTR":"mx.e7.example.com"}],"1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.E.B.A.B.E.F.A.C.ip6.arpa":[{"PTR":"mx.example.com"}],"3.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.E.B.A.B.E.F.A.C.ip6.arpa":[{"PTR":"mx.example.com"}],"mx.e7.example.com":[{"A":"192.168.218.42"}],"mx.e7.example.com.should.example.com":[{"A":"127.0.0.2"}],"mx.example.com.ok.example.com":[{"A":"127.0.0.2"}],"e7.example.com":[{"SPF":"v=spf1 exists:%{p}.should.example.com ~exists:%{p}.ok.example.com"}],"e8.example.com":[{"SPF":"v=spf1 -all exp=msg8.%{D2}"}],"msg8.example.com":[{"TXT":"http://example.com/why.html?l=%{L}"}],"e9.example.com":[{"SPF":"v=spf1 a:%{H} -all"}],"e10.example.com":[{"SPF":"v=spf1 -include:_spfh.%{d2} ip4:1.2.3.0/24 -all"}],"_spfh.example.com":[{"SPF":"v=spf1 -a:%{h} +all"}],"e11.example.com":[{"SPF":"v=spf1 exists:%{i}.%{l2r-}.user.%{d2}"}],"1.2.3.4.gladstone.philip.user.example.com":[{"A":"127.0.0.2"}],"e12.example.com":[{"SPF":"v=spf1 exists:%{l2r+-}.user.%{d2}"}],"bar.foo.user.example.com":[{"A":"127.0.0.2"}]}, failOnNoFake: true, helo: "msgbas2x.cos.example.com"}
        let promise = spf.check_host('192.168.218.40', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'PERMERROR');
        });
      });
      it('invalid-macro-char', function(){
        let email = 'test@e1.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"example.com.d.spf.example.com":[{"SPF":"v=spf1 redirect=a.spf.example.com"}],"a.spf.example.com":[{"SPF":"v=spf1 include:o.spf.example.com. ~all"}],"o.spf.example.com":[{"SPF":"v=spf1 ip4:192.168.218.40"}],"msgbas2x.cos.example.com":[{"A":"192.168.218.40"}],"example.com":[{"A":"192.168.90.76"},{"SPF":"v=spf1 redirect=%{d}.d.spf.example.com."}],"exp.example.com":[{"SPF":"v=spf1 exp=msg.example.com. -all"}],"msg.example.com":[{"TXT":"This is a test."}],"e1.example.com":[{"SPF":"v=spf1 -exists:%(ir).sbl.example.com ?all"}],"e1e.example.com":[{"SPF":"v=spf1 exists:foo%(ir).sbl.example.com ?all"}],"e1t.example.com":[{"SPF":"v=spf1 exists:foo%.sbl.example.com ?all"}],"e1a.example.com":[{"SPF":"v=spf1 a:macro%%percent%_%_space%-url-space.example.com -all"}],"macro%percent  space%20url-space.example.com":[{"A":"1.2.3.4"}],"e2.example.com":[{"SPF":"v=spf1 -all exp=%{r}.example.com"}],"e3.example.com":[{"SPF":"v=spf1 -all exp=%{ir}.example.com"}],"40.218.168.192.example.com":[{"TXT":"Connections from %{c} not authorized."}],"somewhat.long.exp.example.com":[{"SPF":"v=spf1 -all exp=foobar.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.example.com"}],"somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.example.com":[{"TXT":"Congratulations!  That was tricky."}],"e4.example.com":[{"SPF":"v=spf1 -all exp=e4msg.example.com"}],"e4msg.example.com":[{"TXT":"%{c} is queried as %{ir}.%{v}.arpa"}],"e5.example.com":[{"SPF":"v=spf1 a:%{a}.example.com -all"}],"e6.example.com":[{"SPF":"v=spf1 -all exp=e6msg.example.com"}],"e6msg.example.com":[{"TXT":"connect from %{p}"}],"mx.example.com":[{"A":"192.168.218.41"},{"A":"192.168.218.42"},{"AAAA":"CAFE:BABE::2"},{"AAAA":"CAFE:BABE::3"}],"40.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"}],"41.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"}],"42.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"},{"PTR":"mx.e7.example.com"}],"1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.E.B.A.B.E.F.A.C.ip6.arpa":[{"PTR":"mx.example.com"}],"3.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.E.B.A.B.E.F.A.C.ip6.arpa":[{"PTR":"mx.example.com"}],"mx.e7.example.com":[{"A":"192.168.218.42"}],"mx.e7.example.com.should.example.com":[{"A":"127.0.0.2"}],"mx.example.com.ok.example.com":[{"A":"127.0.0.2"}],"e7.example.com":[{"SPF":"v=spf1 exists:%{p}.should.example.com ~exists:%{p}.ok.example.com"}],"e8.example.com":[{"SPF":"v=spf1 -all exp=msg8.%{D2}"}],"msg8.example.com":[{"TXT":"http://example.com/why.html?l=%{L}"}],"e9.example.com":[{"SPF":"v=spf1 a:%{H} -all"}],"e10.example.com":[{"SPF":"v=spf1 -include:_spfh.%{d2} ip4:1.2.3.0/24 -all"}],"_spfh.example.com":[{"SPF":"v=spf1 -a:%{h} +all"}],"e11.example.com":[{"SPF":"v=spf1 exists:%{i}.%{l2r-}.user.%{d2}"}],"1.2.3.4.gladstone.philip.user.example.com":[{"A":"127.0.0.2"}],"e12.example.com":[{"SPF":"v=spf1 exists:%{l2r+-}.user.%{d2}"}],"bar.foo.user.example.com":[{"A":"127.0.0.2"}]}, failOnNoFake: true, helo: "msgbas2x.cos.example.com"}
        let promise = spf.check_host('192.168.218.40', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'PERMERROR');
        });
      });
      it('invalid-embedded-macro-char', function(){
        let email = 'test@e1e.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"example.com.d.spf.example.com":[{"SPF":"v=spf1 redirect=a.spf.example.com"}],"a.spf.example.com":[{"SPF":"v=spf1 include:o.spf.example.com. ~all"}],"o.spf.example.com":[{"SPF":"v=spf1 ip4:192.168.218.40"}],"msgbas2x.cos.example.com":[{"A":"192.168.218.40"}],"example.com":[{"A":"192.168.90.76"},{"SPF":"v=spf1 redirect=%{d}.d.spf.example.com."}],"exp.example.com":[{"SPF":"v=spf1 exp=msg.example.com. -all"}],"msg.example.com":[{"TXT":"This is a test."}],"e1.example.com":[{"SPF":"v=spf1 -exists:%(ir).sbl.example.com ?all"}],"e1e.example.com":[{"SPF":"v=spf1 exists:foo%(ir).sbl.example.com ?all"}],"e1t.example.com":[{"SPF":"v=spf1 exists:foo%.sbl.example.com ?all"}],"e1a.example.com":[{"SPF":"v=spf1 a:macro%%percent%_%_space%-url-space.example.com -all"}],"macro%percent  space%20url-space.example.com":[{"A":"1.2.3.4"}],"e2.example.com":[{"SPF":"v=spf1 -all exp=%{r}.example.com"}],"e3.example.com":[{"SPF":"v=spf1 -all exp=%{ir}.example.com"}],"40.218.168.192.example.com":[{"TXT":"Connections from %{c} not authorized."}],"somewhat.long.exp.example.com":[{"SPF":"v=spf1 -all exp=foobar.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.example.com"}],"somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.example.com":[{"TXT":"Congratulations!  That was tricky."}],"e4.example.com":[{"SPF":"v=spf1 -all exp=e4msg.example.com"}],"e4msg.example.com":[{"TXT":"%{c} is queried as %{ir}.%{v}.arpa"}],"e5.example.com":[{"SPF":"v=spf1 a:%{a}.example.com -all"}],"e6.example.com":[{"SPF":"v=spf1 -all exp=e6msg.example.com"}],"e6msg.example.com":[{"TXT":"connect from %{p}"}],"mx.example.com":[{"A":"192.168.218.41"},{"A":"192.168.218.42"},{"AAAA":"CAFE:BABE::2"},{"AAAA":"CAFE:BABE::3"}],"40.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"}],"41.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"}],"42.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"},{"PTR":"mx.e7.example.com"}],"1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.E.B.A.B.E.F.A.C.ip6.arpa":[{"PTR":"mx.example.com"}],"3.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.E.B.A.B.E.F.A.C.ip6.arpa":[{"PTR":"mx.example.com"}],"mx.e7.example.com":[{"A":"192.168.218.42"}],"mx.e7.example.com.should.example.com":[{"A":"127.0.0.2"}],"mx.example.com.ok.example.com":[{"A":"127.0.0.2"}],"e7.example.com":[{"SPF":"v=spf1 exists:%{p}.should.example.com ~exists:%{p}.ok.example.com"}],"e8.example.com":[{"SPF":"v=spf1 -all exp=msg8.%{D2}"}],"msg8.example.com":[{"TXT":"http://example.com/why.html?l=%{L}"}],"e9.example.com":[{"SPF":"v=spf1 a:%{H} -all"}],"e10.example.com":[{"SPF":"v=spf1 -include:_spfh.%{d2} ip4:1.2.3.0/24 -all"}],"_spfh.example.com":[{"SPF":"v=spf1 -a:%{h} +all"}],"e11.example.com":[{"SPF":"v=spf1 exists:%{i}.%{l2r-}.user.%{d2}"}],"1.2.3.4.gladstone.philip.user.example.com":[{"A":"127.0.0.2"}],"e12.example.com":[{"SPF":"v=spf1 exists:%{l2r+-}.user.%{d2}"}],"bar.foo.user.example.com":[{"A":"127.0.0.2"}]}, failOnNoFake: true, helo: "msgbas2x.cos.example.com"}
        let promise = spf.check_host('192.168.218.40', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'PERMERROR');
        });
      });
      it('invalid-trailing-macro-char', function(){
        let email = 'test@e1t.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"example.com.d.spf.example.com":[{"SPF":"v=spf1 redirect=a.spf.example.com"}],"a.spf.example.com":[{"SPF":"v=spf1 include:o.spf.example.com. ~all"}],"o.spf.example.com":[{"SPF":"v=spf1 ip4:192.168.218.40"}],"msgbas2x.cos.example.com":[{"A":"192.168.218.40"}],"example.com":[{"A":"192.168.90.76"},{"SPF":"v=spf1 redirect=%{d}.d.spf.example.com."}],"exp.example.com":[{"SPF":"v=spf1 exp=msg.example.com. -all"}],"msg.example.com":[{"TXT":"This is a test."}],"e1.example.com":[{"SPF":"v=spf1 -exists:%(ir).sbl.example.com ?all"}],"e1e.example.com":[{"SPF":"v=spf1 exists:foo%(ir).sbl.example.com ?all"}],"e1t.example.com":[{"SPF":"v=spf1 exists:foo%.sbl.example.com ?all"}],"e1a.example.com":[{"SPF":"v=spf1 a:macro%%percent%_%_space%-url-space.example.com -all"}],"macro%percent  space%20url-space.example.com":[{"A":"1.2.3.4"}],"e2.example.com":[{"SPF":"v=spf1 -all exp=%{r}.example.com"}],"e3.example.com":[{"SPF":"v=spf1 -all exp=%{ir}.example.com"}],"40.218.168.192.example.com":[{"TXT":"Connections from %{c} not authorized."}],"somewhat.long.exp.example.com":[{"SPF":"v=spf1 -all exp=foobar.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.example.com"}],"somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.example.com":[{"TXT":"Congratulations!  That was tricky."}],"e4.example.com":[{"SPF":"v=spf1 -all exp=e4msg.example.com"}],"e4msg.example.com":[{"TXT":"%{c} is queried as %{ir}.%{v}.arpa"}],"e5.example.com":[{"SPF":"v=spf1 a:%{a}.example.com -all"}],"e6.example.com":[{"SPF":"v=spf1 -all exp=e6msg.example.com"}],"e6msg.example.com":[{"TXT":"connect from %{p}"}],"mx.example.com":[{"A":"192.168.218.41"},{"A":"192.168.218.42"},{"AAAA":"CAFE:BABE::2"},{"AAAA":"CAFE:BABE::3"}],"40.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"}],"41.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"}],"42.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"},{"PTR":"mx.e7.example.com"}],"1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.E.B.A.B.E.F.A.C.ip6.arpa":[{"PTR":"mx.example.com"}],"3.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.E.B.A.B.E.F.A.C.ip6.arpa":[{"PTR":"mx.example.com"}],"mx.e7.example.com":[{"A":"192.168.218.42"}],"mx.e7.example.com.should.example.com":[{"A":"127.0.0.2"}],"mx.example.com.ok.example.com":[{"A":"127.0.0.2"}],"e7.example.com":[{"SPF":"v=spf1 exists:%{p}.should.example.com ~exists:%{p}.ok.example.com"}],"e8.example.com":[{"SPF":"v=spf1 -all exp=msg8.%{D2}"}],"msg8.example.com":[{"TXT":"http://example.com/why.html?l=%{L}"}],"e9.example.com":[{"SPF":"v=spf1 a:%{H} -all"}],"e10.example.com":[{"SPF":"v=spf1 -include:_spfh.%{d2} ip4:1.2.3.0/24 -all"}],"_spfh.example.com":[{"SPF":"v=spf1 -a:%{h} +all"}],"e11.example.com":[{"SPF":"v=spf1 exists:%{i}.%{l2r-}.user.%{d2}"}],"1.2.3.4.gladstone.philip.user.example.com":[{"A":"127.0.0.2"}],"e12.example.com":[{"SPF":"v=spf1 exists:%{l2r+-}.user.%{d2}"}],"bar.foo.user.example.com":[{"A":"127.0.0.2"}]}, failOnNoFake: true, helo: "msgbas2x.cos.example.com"}
        let promise = spf.check_host('192.168.218.40', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'PERMERROR');
        });
      });
      it('macro-mania-in-domain', function(){
        let email = 'test@e1a.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"example.com.d.spf.example.com":[{"SPF":"v=spf1 redirect=a.spf.example.com"}],"a.spf.example.com":[{"SPF":"v=spf1 include:o.spf.example.com. ~all"}],"o.spf.example.com":[{"SPF":"v=spf1 ip4:192.168.218.40"}],"msgbas2x.cos.example.com":[{"A":"192.168.218.40"}],"example.com":[{"A":"192.168.90.76"},{"SPF":"v=spf1 redirect=%{d}.d.spf.example.com."}],"exp.example.com":[{"SPF":"v=spf1 exp=msg.example.com. -all"}],"msg.example.com":[{"TXT":"This is a test."}],"e1.example.com":[{"SPF":"v=spf1 -exists:%(ir).sbl.example.com ?all"}],"e1e.example.com":[{"SPF":"v=spf1 exists:foo%(ir).sbl.example.com ?all"}],"e1t.example.com":[{"SPF":"v=spf1 exists:foo%.sbl.example.com ?all"}],"e1a.example.com":[{"SPF":"v=spf1 a:macro%%percent%_%_space%-url-space.example.com -all"}],"macro%percent  space%20url-space.example.com":[{"A":"1.2.3.4"}],"e2.example.com":[{"SPF":"v=spf1 -all exp=%{r}.example.com"}],"e3.example.com":[{"SPF":"v=spf1 -all exp=%{ir}.example.com"}],"40.218.168.192.example.com":[{"TXT":"Connections from %{c} not authorized."}],"somewhat.long.exp.example.com":[{"SPF":"v=spf1 -all exp=foobar.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.example.com"}],"somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.example.com":[{"TXT":"Congratulations!  That was tricky."}],"e4.example.com":[{"SPF":"v=spf1 -all exp=e4msg.example.com"}],"e4msg.example.com":[{"TXT":"%{c} is queried as %{ir}.%{v}.arpa"}],"e5.example.com":[{"SPF":"v=spf1 a:%{a}.example.com -all"}],"e6.example.com":[{"SPF":"v=spf1 -all exp=e6msg.example.com"}],"e6msg.example.com":[{"TXT":"connect from %{p}"}],"mx.example.com":[{"A":"192.168.218.41"},{"A":"192.168.218.42"},{"AAAA":"CAFE:BABE::2"},{"AAAA":"CAFE:BABE::3"}],"40.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"}],"41.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"}],"42.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"},{"PTR":"mx.e7.example.com"}],"1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.E.B.A.B.E.F.A.C.ip6.arpa":[{"PTR":"mx.example.com"}],"3.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.E.B.A.B.E.F.A.C.ip6.arpa":[{"PTR":"mx.example.com"}],"mx.e7.example.com":[{"A":"192.168.218.42"}],"mx.e7.example.com.should.example.com":[{"A":"127.0.0.2"}],"mx.example.com.ok.example.com":[{"A":"127.0.0.2"}],"e7.example.com":[{"SPF":"v=spf1 exists:%{p}.should.example.com ~exists:%{p}.ok.example.com"}],"e8.example.com":[{"SPF":"v=spf1 -all exp=msg8.%{D2}"}],"msg8.example.com":[{"TXT":"http://example.com/why.html?l=%{L}"}],"e9.example.com":[{"SPF":"v=spf1 a:%{H} -all"}],"e10.example.com":[{"SPF":"v=spf1 -include:_spfh.%{d2} ip4:1.2.3.0/24 -all"}],"_spfh.example.com":[{"SPF":"v=spf1 -a:%{h} +all"}],"e11.example.com":[{"SPF":"v=spf1 exists:%{i}.%{l2r-}.user.%{d2}"}],"1.2.3.4.gladstone.philip.user.example.com":[{"A":"127.0.0.2"}],"e12.example.com":[{"SPF":"v=spf1 exists:%{l2r+-}.user.%{d2}"}],"bar.foo.user.example.com":[{"A":"127.0.0.2"}]}, failOnNoFake: true, helo: "mail.example.com"}
        let promise = spf.check_host('1.2.3.4', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'PASS');
        });
      });
      it('exp-txt-macro-char', function(){
        let email = 'test@e3.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"example.com.d.spf.example.com":[{"SPF":"v=spf1 redirect=a.spf.example.com"}],"a.spf.example.com":[{"SPF":"v=spf1 include:o.spf.example.com. ~all"}],"o.spf.example.com":[{"SPF":"v=spf1 ip4:192.168.218.40"}],"msgbas2x.cos.example.com":[{"A":"192.168.218.40"}],"example.com":[{"A":"192.168.90.76"},{"SPF":"v=spf1 redirect=%{d}.d.spf.example.com."}],"exp.example.com":[{"SPF":"v=spf1 exp=msg.example.com. -all"}],"msg.example.com":[{"TXT":"This is a test."}],"e1.example.com":[{"SPF":"v=spf1 -exists:%(ir).sbl.example.com ?all"}],"e1e.example.com":[{"SPF":"v=spf1 exists:foo%(ir).sbl.example.com ?all"}],"e1t.example.com":[{"SPF":"v=spf1 exists:foo%.sbl.example.com ?all"}],"e1a.example.com":[{"SPF":"v=spf1 a:macro%%percent%_%_space%-url-space.example.com -all"}],"macro%percent  space%20url-space.example.com":[{"A":"1.2.3.4"}],"e2.example.com":[{"SPF":"v=spf1 -all exp=%{r}.example.com"}],"e3.example.com":[{"SPF":"v=spf1 -all exp=%{ir}.example.com"}],"40.218.168.192.example.com":[{"TXT":"Connections from %{c} not authorized."}],"somewhat.long.exp.example.com":[{"SPF":"v=spf1 -all exp=foobar.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.example.com"}],"somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.example.com":[{"TXT":"Congratulations!  That was tricky."}],"e4.example.com":[{"SPF":"v=spf1 -all exp=e4msg.example.com"}],"e4msg.example.com":[{"TXT":"%{c} is queried as %{ir}.%{v}.arpa"}],"e5.example.com":[{"SPF":"v=spf1 a:%{a}.example.com -all"}],"e6.example.com":[{"SPF":"v=spf1 -all exp=e6msg.example.com"}],"e6msg.example.com":[{"TXT":"connect from %{p}"}],"mx.example.com":[{"A":"192.168.218.41"},{"A":"192.168.218.42"},{"AAAA":"CAFE:BABE::2"},{"AAAA":"CAFE:BABE::3"}],"40.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"}],"41.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"}],"42.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"},{"PTR":"mx.e7.example.com"}],"1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.E.B.A.B.E.F.A.C.ip6.arpa":[{"PTR":"mx.example.com"}],"3.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.E.B.A.B.E.F.A.C.ip6.arpa":[{"PTR":"mx.example.com"}],"mx.e7.example.com":[{"A":"192.168.218.42"}],"mx.e7.example.com.should.example.com":[{"A":"127.0.0.2"}],"mx.example.com.ok.example.com":[{"A":"127.0.0.2"}],"e7.example.com":[{"SPF":"v=spf1 exists:%{p}.should.example.com ~exists:%{p}.ok.example.com"}],"e8.example.com":[{"SPF":"v=spf1 -all exp=msg8.%{D2}"}],"msg8.example.com":[{"TXT":"http://example.com/why.html?l=%{L}"}],"e9.example.com":[{"SPF":"v=spf1 a:%{H} -all"}],"e10.example.com":[{"SPF":"v=spf1 -include:_spfh.%{d2} ip4:1.2.3.0/24 -all"}],"_spfh.example.com":[{"SPF":"v=spf1 -a:%{h} +all"}],"e11.example.com":[{"SPF":"v=spf1 exists:%{i}.%{l2r-}.user.%{d2}"}],"1.2.3.4.gladstone.philip.user.example.com":[{"A":"127.0.0.2"}],"e12.example.com":[{"SPF":"v=spf1 exists:%{l2r+-}.user.%{d2}"}],"bar.foo.user.example.com":[{"A":"127.0.0.2"}]}, failOnNoFake: true, helo: "msgbas2x.cos.example.com"}
        let promise = spf.check_host('192.168.218.40', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'FAIL');
        });
      });
      it('domain-name-truncation', function(){
        let email = 'test@somewhat.long.exp.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"example.com.d.spf.example.com":[{"SPF":"v=spf1 redirect=a.spf.example.com"}],"a.spf.example.com":[{"SPF":"v=spf1 include:o.spf.example.com. ~all"}],"o.spf.example.com":[{"SPF":"v=spf1 ip4:192.168.218.40"}],"msgbas2x.cos.example.com":[{"A":"192.168.218.40"}],"example.com":[{"A":"192.168.90.76"},{"SPF":"v=spf1 redirect=%{d}.d.spf.example.com."}],"exp.example.com":[{"SPF":"v=spf1 exp=msg.example.com. -all"}],"msg.example.com":[{"TXT":"This is a test."}],"e1.example.com":[{"SPF":"v=spf1 -exists:%(ir).sbl.example.com ?all"}],"e1e.example.com":[{"SPF":"v=spf1 exists:foo%(ir).sbl.example.com ?all"}],"e1t.example.com":[{"SPF":"v=spf1 exists:foo%.sbl.example.com ?all"}],"e1a.example.com":[{"SPF":"v=spf1 a:macro%%percent%_%_space%-url-space.example.com -all"}],"macro%percent  space%20url-space.example.com":[{"A":"1.2.3.4"}],"e2.example.com":[{"SPF":"v=spf1 -all exp=%{r}.example.com"}],"e3.example.com":[{"SPF":"v=spf1 -all exp=%{ir}.example.com"}],"40.218.168.192.example.com":[{"TXT":"Connections from %{c} not authorized."}],"somewhat.long.exp.example.com":[{"SPF":"v=spf1 -all exp=foobar.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.example.com"}],"somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.example.com":[{"TXT":"Congratulations!  That was tricky."}],"e4.example.com":[{"SPF":"v=spf1 -all exp=e4msg.example.com"}],"e4msg.example.com":[{"TXT":"%{c} is queried as %{ir}.%{v}.arpa"}],"e5.example.com":[{"SPF":"v=spf1 a:%{a}.example.com -all"}],"e6.example.com":[{"SPF":"v=spf1 -all exp=e6msg.example.com"}],"e6msg.example.com":[{"TXT":"connect from %{p}"}],"mx.example.com":[{"A":"192.168.218.41"},{"A":"192.168.218.42"},{"AAAA":"CAFE:BABE::2"},{"AAAA":"CAFE:BABE::3"}],"40.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"}],"41.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"}],"42.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"},{"PTR":"mx.e7.example.com"}],"1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.E.B.A.B.E.F.A.C.ip6.arpa":[{"PTR":"mx.example.com"}],"3.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.E.B.A.B.E.F.A.C.ip6.arpa":[{"PTR":"mx.example.com"}],"mx.e7.example.com":[{"A":"192.168.218.42"}],"mx.e7.example.com.should.example.com":[{"A":"127.0.0.2"}],"mx.example.com.ok.example.com":[{"A":"127.0.0.2"}],"e7.example.com":[{"SPF":"v=spf1 exists:%{p}.should.example.com ~exists:%{p}.ok.example.com"}],"e8.example.com":[{"SPF":"v=spf1 -all exp=msg8.%{D2}"}],"msg8.example.com":[{"TXT":"http://example.com/why.html?l=%{L}"}],"e9.example.com":[{"SPF":"v=spf1 a:%{H} -all"}],"e10.example.com":[{"SPF":"v=spf1 -include:_spfh.%{d2} ip4:1.2.3.0/24 -all"}],"_spfh.example.com":[{"SPF":"v=spf1 -a:%{h} +all"}],"e11.example.com":[{"SPF":"v=spf1 exists:%{i}.%{l2r-}.user.%{d2}"}],"1.2.3.4.gladstone.philip.user.example.com":[{"A":"127.0.0.2"}],"e12.example.com":[{"SPF":"v=spf1 exists:%{l2r+-}.user.%{d2}"}],"bar.foo.user.example.com":[{"A":"127.0.0.2"}]}, failOnNoFake: true, helo: "msgbas2x.cos.example.com"}
        let promise = spf.check_host('192.168.218.40', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'FAIL');
        });
      });
      it('v-macro-ip4', function(){
        let email = 'test@e4.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"example.com.d.spf.example.com":[{"SPF":"v=spf1 redirect=a.spf.example.com"}],"a.spf.example.com":[{"SPF":"v=spf1 include:o.spf.example.com. ~all"}],"o.spf.example.com":[{"SPF":"v=spf1 ip4:192.168.218.40"}],"msgbas2x.cos.example.com":[{"A":"192.168.218.40"}],"example.com":[{"A":"192.168.90.76"},{"SPF":"v=spf1 redirect=%{d}.d.spf.example.com."}],"exp.example.com":[{"SPF":"v=spf1 exp=msg.example.com. -all"}],"msg.example.com":[{"TXT":"This is a test."}],"e1.example.com":[{"SPF":"v=spf1 -exists:%(ir).sbl.example.com ?all"}],"e1e.example.com":[{"SPF":"v=spf1 exists:foo%(ir).sbl.example.com ?all"}],"e1t.example.com":[{"SPF":"v=spf1 exists:foo%.sbl.example.com ?all"}],"e1a.example.com":[{"SPF":"v=spf1 a:macro%%percent%_%_space%-url-space.example.com -all"}],"macro%percent  space%20url-space.example.com":[{"A":"1.2.3.4"}],"e2.example.com":[{"SPF":"v=spf1 -all exp=%{r}.example.com"}],"e3.example.com":[{"SPF":"v=spf1 -all exp=%{ir}.example.com"}],"40.218.168.192.example.com":[{"TXT":"Connections from %{c} not authorized."}],"somewhat.long.exp.example.com":[{"SPF":"v=spf1 -all exp=foobar.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.example.com"}],"somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.example.com":[{"TXT":"Congratulations!  That was tricky."}],"e4.example.com":[{"SPF":"v=spf1 -all exp=e4msg.example.com"}],"e4msg.example.com":[{"TXT":"%{c} is queried as %{ir}.%{v}.arpa"}],"e5.example.com":[{"SPF":"v=spf1 a:%{a}.example.com -all"}],"e6.example.com":[{"SPF":"v=spf1 -all exp=e6msg.example.com"}],"e6msg.example.com":[{"TXT":"connect from %{p}"}],"mx.example.com":[{"A":"192.168.218.41"},{"A":"192.168.218.42"},{"AAAA":"CAFE:BABE::2"},{"AAAA":"CAFE:BABE::3"}],"40.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"}],"41.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"}],"42.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"},{"PTR":"mx.e7.example.com"}],"1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.E.B.A.B.E.F.A.C.ip6.arpa":[{"PTR":"mx.example.com"}],"3.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.E.B.A.B.E.F.A.C.ip6.arpa":[{"PTR":"mx.example.com"}],"mx.e7.example.com":[{"A":"192.168.218.42"}],"mx.e7.example.com.should.example.com":[{"A":"127.0.0.2"}],"mx.example.com.ok.example.com":[{"A":"127.0.0.2"}],"e7.example.com":[{"SPF":"v=spf1 exists:%{p}.should.example.com ~exists:%{p}.ok.example.com"}],"e8.example.com":[{"SPF":"v=spf1 -all exp=msg8.%{D2}"}],"msg8.example.com":[{"TXT":"http://example.com/why.html?l=%{L}"}],"e9.example.com":[{"SPF":"v=spf1 a:%{H} -all"}],"e10.example.com":[{"SPF":"v=spf1 -include:_spfh.%{d2} ip4:1.2.3.0/24 -all"}],"_spfh.example.com":[{"SPF":"v=spf1 -a:%{h} +all"}],"e11.example.com":[{"SPF":"v=spf1 exists:%{i}.%{l2r-}.user.%{d2}"}],"1.2.3.4.gladstone.philip.user.example.com":[{"A":"127.0.0.2"}],"e12.example.com":[{"SPF":"v=spf1 exists:%{l2r+-}.user.%{d2}"}],"bar.foo.user.example.com":[{"A":"127.0.0.2"}]}, failOnNoFake: true, helo: "msgbas2x.cos.example.com"}
        let promise = spf.check_host('192.168.218.40', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'FAIL');
        });
      });
      it('v-macro-ip6', function(){
        let email = 'test@e4.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"example.com.d.spf.example.com":[{"SPF":"v=spf1 redirect=a.spf.example.com"}],"a.spf.example.com":[{"SPF":"v=spf1 include:o.spf.example.com. ~all"}],"o.spf.example.com":[{"SPF":"v=spf1 ip4:192.168.218.40"}],"msgbas2x.cos.example.com":[{"A":"192.168.218.40"}],"example.com":[{"A":"192.168.90.76"},{"SPF":"v=spf1 redirect=%{d}.d.spf.example.com."}],"exp.example.com":[{"SPF":"v=spf1 exp=msg.example.com. -all"}],"msg.example.com":[{"TXT":"This is a test."}],"e1.example.com":[{"SPF":"v=spf1 -exists:%(ir).sbl.example.com ?all"}],"e1e.example.com":[{"SPF":"v=spf1 exists:foo%(ir).sbl.example.com ?all"}],"e1t.example.com":[{"SPF":"v=spf1 exists:foo%.sbl.example.com ?all"}],"e1a.example.com":[{"SPF":"v=spf1 a:macro%%percent%_%_space%-url-space.example.com -all"}],"macro%percent  space%20url-space.example.com":[{"A":"1.2.3.4"}],"e2.example.com":[{"SPF":"v=spf1 -all exp=%{r}.example.com"}],"e3.example.com":[{"SPF":"v=spf1 -all exp=%{ir}.example.com"}],"40.218.168.192.example.com":[{"TXT":"Connections from %{c} not authorized."}],"somewhat.long.exp.example.com":[{"SPF":"v=spf1 -all exp=foobar.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.example.com"}],"somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.example.com":[{"TXT":"Congratulations!  That was tricky."}],"e4.example.com":[{"SPF":"v=spf1 -all exp=e4msg.example.com"}],"e4msg.example.com":[{"TXT":"%{c} is queried as %{ir}.%{v}.arpa"}],"e5.example.com":[{"SPF":"v=spf1 a:%{a}.example.com -all"}],"e6.example.com":[{"SPF":"v=spf1 -all exp=e6msg.example.com"}],"e6msg.example.com":[{"TXT":"connect from %{p}"}],"mx.example.com":[{"A":"192.168.218.41"},{"A":"192.168.218.42"},{"AAAA":"CAFE:BABE::2"},{"AAAA":"CAFE:BABE::3"}],"40.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"}],"41.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"}],"42.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"},{"PTR":"mx.e7.example.com"}],"1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.E.B.A.B.E.F.A.C.ip6.arpa":[{"PTR":"mx.example.com"}],"3.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.E.B.A.B.E.F.A.C.ip6.arpa":[{"PTR":"mx.example.com"}],"mx.e7.example.com":[{"A":"192.168.218.42"}],"mx.e7.example.com.should.example.com":[{"A":"127.0.0.2"}],"mx.example.com.ok.example.com":[{"A":"127.0.0.2"}],"e7.example.com":[{"SPF":"v=spf1 exists:%{p}.should.example.com ~exists:%{p}.ok.example.com"}],"e8.example.com":[{"SPF":"v=spf1 -all exp=msg8.%{D2}"}],"msg8.example.com":[{"TXT":"http://example.com/why.html?l=%{L}"}],"e9.example.com":[{"SPF":"v=spf1 a:%{H} -all"}],"e10.example.com":[{"SPF":"v=spf1 -include:_spfh.%{d2} ip4:1.2.3.0/24 -all"}],"_spfh.example.com":[{"SPF":"v=spf1 -a:%{h} +all"}],"e11.example.com":[{"SPF":"v=spf1 exists:%{i}.%{l2r-}.user.%{d2}"}],"1.2.3.4.gladstone.philip.user.example.com":[{"A":"127.0.0.2"}],"e12.example.com":[{"SPF":"v=spf1 exists:%{l2r+-}.user.%{d2}"}],"bar.foo.user.example.com":[{"A":"127.0.0.2"}]}, failOnNoFake: true, helo: "msgbas2x.cos.example.com"}
        let promise = spf.check_host('CAFE:BABE::1', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'FAIL');
        });
      });
      it('undef-macro', function(){
        let email = 'test@e5.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"example.com.d.spf.example.com":[{"SPF":"v=spf1 redirect=a.spf.example.com"}],"a.spf.example.com":[{"SPF":"v=spf1 include:o.spf.example.com. ~all"}],"o.spf.example.com":[{"SPF":"v=spf1 ip4:192.168.218.40"}],"msgbas2x.cos.example.com":[{"A":"192.168.218.40"}],"example.com":[{"A":"192.168.90.76"},{"SPF":"v=spf1 redirect=%{d}.d.spf.example.com."}],"exp.example.com":[{"SPF":"v=spf1 exp=msg.example.com. -all"}],"msg.example.com":[{"TXT":"This is a test."}],"e1.example.com":[{"SPF":"v=spf1 -exists:%(ir).sbl.example.com ?all"}],"e1e.example.com":[{"SPF":"v=spf1 exists:foo%(ir).sbl.example.com ?all"}],"e1t.example.com":[{"SPF":"v=spf1 exists:foo%.sbl.example.com ?all"}],"e1a.example.com":[{"SPF":"v=spf1 a:macro%%percent%_%_space%-url-space.example.com -all"}],"macro%percent  space%20url-space.example.com":[{"A":"1.2.3.4"}],"e2.example.com":[{"SPF":"v=spf1 -all exp=%{r}.example.com"}],"e3.example.com":[{"SPF":"v=spf1 -all exp=%{ir}.example.com"}],"40.218.168.192.example.com":[{"TXT":"Connections from %{c} not authorized."}],"somewhat.long.exp.example.com":[{"SPF":"v=spf1 -all exp=foobar.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.example.com"}],"somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.example.com":[{"TXT":"Congratulations!  That was tricky."}],"e4.example.com":[{"SPF":"v=spf1 -all exp=e4msg.example.com"}],"e4msg.example.com":[{"TXT":"%{c} is queried as %{ir}.%{v}.arpa"}],"e5.example.com":[{"SPF":"v=spf1 a:%{a}.example.com -all"}],"e6.example.com":[{"SPF":"v=spf1 -all exp=e6msg.example.com"}],"e6msg.example.com":[{"TXT":"connect from %{p}"}],"mx.example.com":[{"A":"192.168.218.41"},{"A":"192.168.218.42"},{"AAAA":"CAFE:BABE::2"},{"AAAA":"CAFE:BABE::3"}],"40.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"}],"41.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"}],"42.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"},{"PTR":"mx.e7.example.com"}],"1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.E.B.A.B.E.F.A.C.ip6.arpa":[{"PTR":"mx.example.com"}],"3.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.E.B.A.B.E.F.A.C.ip6.arpa":[{"PTR":"mx.example.com"}],"mx.e7.example.com":[{"A":"192.168.218.42"}],"mx.e7.example.com.should.example.com":[{"A":"127.0.0.2"}],"mx.example.com.ok.example.com":[{"A":"127.0.0.2"}],"e7.example.com":[{"SPF":"v=spf1 exists:%{p}.should.example.com ~exists:%{p}.ok.example.com"}],"e8.example.com":[{"SPF":"v=spf1 -all exp=msg8.%{D2}"}],"msg8.example.com":[{"TXT":"http://example.com/why.html?l=%{L}"}],"e9.example.com":[{"SPF":"v=spf1 a:%{H} -all"}],"e10.example.com":[{"SPF":"v=spf1 -include:_spfh.%{d2} ip4:1.2.3.0/24 -all"}],"_spfh.example.com":[{"SPF":"v=spf1 -a:%{h} +all"}],"e11.example.com":[{"SPF":"v=spf1 exists:%{i}.%{l2r-}.user.%{d2}"}],"1.2.3.4.gladstone.philip.user.example.com":[{"A":"127.0.0.2"}],"e12.example.com":[{"SPF":"v=spf1 exists:%{l2r+-}.user.%{d2}"}],"bar.foo.user.example.com":[{"A":"127.0.0.2"}]}, failOnNoFake: true, helo: "msgbas2x.cos.example.com"}
        let promise = spf.check_host('CAFE:BABE::192.168.218.40', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'PERMERROR');
        });
      });
      it('p-macro-ip4-novalid', function(){
        let email = 'test@e6.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"example.com.d.spf.example.com":[{"SPF":"v=spf1 redirect=a.spf.example.com"}],"a.spf.example.com":[{"SPF":"v=spf1 include:o.spf.example.com. ~all"}],"o.spf.example.com":[{"SPF":"v=spf1 ip4:192.168.218.40"}],"msgbas2x.cos.example.com":[{"A":"192.168.218.40"}],"example.com":[{"A":"192.168.90.76"},{"SPF":"v=spf1 redirect=%{d}.d.spf.example.com."}],"exp.example.com":[{"SPF":"v=spf1 exp=msg.example.com. -all"}],"msg.example.com":[{"TXT":"This is a test."}],"e1.example.com":[{"SPF":"v=spf1 -exists:%(ir).sbl.example.com ?all"}],"e1e.example.com":[{"SPF":"v=spf1 exists:foo%(ir).sbl.example.com ?all"}],"e1t.example.com":[{"SPF":"v=spf1 exists:foo%.sbl.example.com ?all"}],"e1a.example.com":[{"SPF":"v=spf1 a:macro%%percent%_%_space%-url-space.example.com -all"}],"macro%percent  space%20url-space.example.com":[{"A":"1.2.3.4"}],"e2.example.com":[{"SPF":"v=spf1 -all exp=%{r}.example.com"}],"e3.example.com":[{"SPF":"v=spf1 -all exp=%{ir}.example.com"}],"40.218.168.192.example.com":[{"TXT":"Connections from %{c} not authorized."}],"somewhat.long.exp.example.com":[{"SPF":"v=spf1 -all exp=foobar.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.example.com"}],"somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.example.com":[{"TXT":"Congratulations!  That was tricky."}],"e4.example.com":[{"SPF":"v=spf1 -all exp=e4msg.example.com"}],"e4msg.example.com":[{"TXT":"%{c} is queried as %{ir}.%{v}.arpa"}],"e5.example.com":[{"SPF":"v=spf1 a:%{a}.example.com -all"}],"e6.example.com":[{"SPF":"v=spf1 -all exp=e6msg.example.com"}],"e6msg.example.com":[{"TXT":"connect from %{p}"}],"mx.example.com":[{"A":"192.168.218.41"},{"A":"192.168.218.42"},{"AAAA":"CAFE:BABE::2"},{"AAAA":"CAFE:BABE::3"}],"40.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"}],"41.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"}],"42.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"},{"PTR":"mx.e7.example.com"}],"1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.E.B.A.B.E.F.A.C.ip6.arpa":[{"PTR":"mx.example.com"}],"3.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.E.B.A.B.E.F.A.C.ip6.arpa":[{"PTR":"mx.example.com"}],"mx.e7.example.com":[{"A":"192.168.218.42"}],"mx.e7.example.com.should.example.com":[{"A":"127.0.0.2"}],"mx.example.com.ok.example.com":[{"A":"127.0.0.2"}],"e7.example.com":[{"SPF":"v=spf1 exists:%{p}.should.example.com ~exists:%{p}.ok.example.com"}],"e8.example.com":[{"SPF":"v=spf1 -all exp=msg8.%{D2}"}],"msg8.example.com":[{"TXT":"http://example.com/why.html?l=%{L}"}],"e9.example.com":[{"SPF":"v=spf1 a:%{H} -all"}],"e10.example.com":[{"SPF":"v=spf1 -include:_spfh.%{d2} ip4:1.2.3.0/24 -all"}],"_spfh.example.com":[{"SPF":"v=spf1 -a:%{h} +all"}],"e11.example.com":[{"SPF":"v=spf1 exists:%{i}.%{l2r-}.user.%{d2}"}],"1.2.3.4.gladstone.philip.user.example.com":[{"A":"127.0.0.2"}],"e12.example.com":[{"SPF":"v=spf1 exists:%{l2r+-}.user.%{d2}"}],"bar.foo.user.example.com":[{"A":"127.0.0.2"}]}, failOnNoFake: true, helo: "msgbas2x.cos.example.com"}
        let promise = spf.check_host('192.168.218.40', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'FAIL');
        });
      });
      it('p-macro-ip4-valid', function(){
        let email = 'test@e6.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"example.com.d.spf.example.com":[{"SPF":"v=spf1 redirect=a.spf.example.com"}],"a.spf.example.com":[{"SPF":"v=spf1 include:o.spf.example.com. ~all"}],"o.spf.example.com":[{"SPF":"v=spf1 ip4:192.168.218.40"}],"msgbas2x.cos.example.com":[{"A":"192.168.218.40"}],"example.com":[{"A":"192.168.90.76"},{"SPF":"v=spf1 redirect=%{d}.d.spf.example.com."}],"exp.example.com":[{"SPF":"v=spf1 exp=msg.example.com. -all"}],"msg.example.com":[{"TXT":"This is a test."}],"e1.example.com":[{"SPF":"v=spf1 -exists:%(ir).sbl.example.com ?all"}],"e1e.example.com":[{"SPF":"v=spf1 exists:foo%(ir).sbl.example.com ?all"}],"e1t.example.com":[{"SPF":"v=spf1 exists:foo%.sbl.example.com ?all"}],"e1a.example.com":[{"SPF":"v=spf1 a:macro%%percent%_%_space%-url-space.example.com -all"}],"macro%percent  space%20url-space.example.com":[{"A":"1.2.3.4"}],"e2.example.com":[{"SPF":"v=spf1 -all exp=%{r}.example.com"}],"e3.example.com":[{"SPF":"v=spf1 -all exp=%{ir}.example.com"}],"40.218.168.192.example.com":[{"TXT":"Connections from %{c} not authorized."}],"somewhat.long.exp.example.com":[{"SPF":"v=spf1 -all exp=foobar.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.example.com"}],"somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.example.com":[{"TXT":"Congratulations!  That was tricky."}],"e4.example.com":[{"SPF":"v=spf1 -all exp=e4msg.example.com"}],"e4msg.example.com":[{"TXT":"%{c} is queried as %{ir}.%{v}.arpa"}],"e5.example.com":[{"SPF":"v=spf1 a:%{a}.example.com -all"}],"e6.example.com":[{"SPF":"v=spf1 -all exp=e6msg.example.com"}],"e6msg.example.com":[{"TXT":"connect from %{p}"}],"mx.example.com":[{"A":"192.168.218.41"},{"A":"192.168.218.42"},{"AAAA":"CAFE:BABE::2"},{"AAAA":"CAFE:BABE::3"}],"40.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"}],"41.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"}],"42.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"},{"PTR":"mx.e7.example.com"}],"1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.E.B.A.B.E.F.A.C.ip6.arpa":[{"PTR":"mx.example.com"}],"3.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.E.B.A.B.E.F.A.C.ip6.arpa":[{"PTR":"mx.example.com"}],"mx.e7.example.com":[{"A":"192.168.218.42"}],"mx.e7.example.com.should.example.com":[{"A":"127.0.0.2"}],"mx.example.com.ok.example.com":[{"A":"127.0.0.2"}],"e7.example.com":[{"SPF":"v=spf1 exists:%{p}.should.example.com ~exists:%{p}.ok.example.com"}],"e8.example.com":[{"SPF":"v=spf1 -all exp=msg8.%{D2}"}],"msg8.example.com":[{"TXT":"http://example.com/why.html?l=%{L}"}],"e9.example.com":[{"SPF":"v=spf1 a:%{H} -all"}],"e10.example.com":[{"SPF":"v=spf1 -include:_spfh.%{d2} ip4:1.2.3.0/24 -all"}],"_spfh.example.com":[{"SPF":"v=spf1 -a:%{h} +all"}],"e11.example.com":[{"SPF":"v=spf1 exists:%{i}.%{l2r-}.user.%{d2}"}],"1.2.3.4.gladstone.philip.user.example.com":[{"A":"127.0.0.2"}],"e12.example.com":[{"SPF":"v=spf1 exists:%{l2r+-}.user.%{d2}"}],"bar.foo.user.example.com":[{"A":"127.0.0.2"}]}, failOnNoFake: true, helo: "msgbas2x.cos.example.com"}
        let promise = spf.check_host('192.168.218.41', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'FAIL');
        });
      });
      it('p-macro-ip6-novalid', function(){
        let email = 'test@e6.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"example.com.d.spf.example.com":[{"SPF":"v=spf1 redirect=a.spf.example.com"}],"a.spf.example.com":[{"SPF":"v=spf1 include:o.spf.example.com. ~all"}],"o.spf.example.com":[{"SPF":"v=spf1 ip4:192.168.218.40"}],"msgbas2x.cos.example.com":[{"A":"192.168.218.40"}],"example.com":[{"A":"192.168.90.76"},{"SPF":"v=spf1 redirect=%{d}.d.spf.example.com."}],"exp.example.com":[{"SPF":"v=spf1 exp=msg.example.com. -all"}],"msg.example.com":[{"TXT":"This is a test."}],"e1.example.com":[{"SPF":"v=spf1 -exists:%(ir).sbl.example.com ?all"}],"e1e.example.com":[{"SPF":"v=spf1 exists:foo%(ir).sbl.example.com ?all"}],"e1t.example.com":[{"SPF":"v=spf1 exists:foo%.sbl.example.com ?all"}],"e1a.example.com":[{"SPF":"v=spf1 a:macro%%percent%_%_space%-url-space.example.com -all"}],"macro%percent  space%20url-space.example.com":[{"A":"1.2.3.4"}],"e2.example.com":[{"SPF":"v=spf1 -all exp=%{r}.example.com"}],"e3.example.com":[{"SPF":"v=spf1 -all exp=%{ir}.example.com"}],"40.218.168.192.example.com":[{"TXT":"Connections from %{c} not authorized."}],"somewhat.long.exp.example.com":[{"SPF":"v=spf1 -all exp=foobar.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.example.com"}],"somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.example.com":[{"TXT":"Congratulations!  That was tricky."}],"e4.example.com":[{"SPF":"v=spf1 -all exp=e4msg.example.com"}],"e4msg.example.com":[{"TXT":"%{c} is queried as %{ir}.%{v}.arpa"}],"e5.example.com":[{"SPF":"v=spf1 a:%{a}.example.com -all"}],"e6.example.com":[{"SPF":"v=spf1 -all exp=e6msg.example.com"}],"e6msg.example.com":[{"TXT":"connect from %{p}"}],"mx.example.com":[{"A":"192.168.218.41"},{"A":"192.168.218.42"},{"AAAA":"CAFE:BABE::2"},{"AAAA":"CAFE:BABE::3"}],"40.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"}],"41.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"}],"42.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"},{"PTR":"mx.e7.example.com"}],"1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.E.B.A.B.E.F.A.C.ip6.arpa":[{"PTR":"mx.example.com"}],"3.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.E.B.A.B.E.F.A.C.ip6.arpa":[{"PTR":"mx.example.com"}],"mx.e7.example.com":[{"A":"192.168.218.42"}],"mx.e7.example.com.should.example.com":[{"A":"127.0.0.2"}],"mx.example.com.ok.example.com":[{"A":"127.0.0.2"}],"e7.example.com":[{"SPF":"v=spf1 exists:%{p}.should.example.com ~exists:%{p}.ok.example.com"}],"e8.example.com":[{"SPF":"v=spf1 -all exp=msg8.%{D2}"}],"msg8.example.com":[{"TXT":"http://example.com/why.html?l=%{L}"}],"e9.example.com":[{"SPF":"v=spf1 a:%{H} -all"}],"e10.example.com":[{"SPF":"v=spf1 -include:_spfh.%{d2} ip4:1.2.3.0/24 -all"}],"_spfh.example.com":[{"SPF":"v=spf1 -a:%{h} +all"}],"e11.example.com":[{"SPF":"v=spf1 exists:%{i}.%{l2r-}.user.%{d2}"}],"1.2.3.4.gladstone.philip.user.example.com":[{"A":"127.0.0.2"}],"e12.example.com":[{"SPF":"v=spf1 exists:%{l2r+-}.user.%{d2}"}],"bar.foo.user.example.com":[{"A":"127.0.0.2"}]}, failOnNoFake: true, helo: "msgbas2x.cos.example.com"}
        let promise = spf.check_host('CAFE:BABE::1', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'FAIL');
        });
      });
      it('p-macro-ip6-valid', function(){
        let email = 'test@e6.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"example.com.d.spf.example.com":[{"SPF":"v=spf1 redirect=a.spf.example.com"}],"a.spf.example.com":[{"SPF":"v=spf1 include:o.spf.example.com. ~all"}],"o.spf.example.com":[{"SPF":"v=spf1 ip4:192.168.218.40"}],"msgbas2x.cos.example.com":[{"A":"192.168.218.40"}],"example.com":[{"A":"192.168.90.76"},{"SPF":"v=spf1 redirect=%{d}.d.spf.example.com."}],"exp.example.com":[{"SPF":"v=spf1 exp=msg.example.com. -all"}],"msg.example.com":[{"TXT":"This is a test."}],"e1.example.com":[{"SPF":"v=spf1 -exists:%(ir).sbl.example.com ?all"}],"e1e.example.com":[{"SPF":"v=spf1 exists:foo%(ir).sbl.example.com ?all"}],"e1t.example.com":[{"SPF":"v=spf1 exists:foo%.sbl.example.com ?all"}],"e1a.example.com":[{"SPF":"v=spf1 a:macro%%percent%_%_space%-url-space.example.com -all"}],"macro%percent  space%20url-space.example.com":[{"A":"1.2.3.4"}],"e2.example.com":[{"SPF":"v=spf1 -all exp=%{r}.example.com"}],"e3.example.com":[{"SPF":"v=spf1 -all exp=%{ir}.example.com"}],"40.218.168.192.example.com":[{"TXT":"Connections from %{c} not authorized."}],"somewhat.long.exp.example.com":[{"SPF":"v=spf1 -all exp=foobar.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.example.com"}],"somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.example.com":[{"TXT":"Congratulations!  That was tricky."}],"e4.example.com":[{"SPF":"v=spf1 -all exp=e4msg.example.com"}],"e4msg.example.com":[{"TXT":"%{c} is queried as %{ir}.%{v}.arpa"}],"e5.example.com":[{"SPF":"v=spf1 a:%{a}.example.com -all"}],"e6.example.com":[{"SPF":"v=spf1 -all exp=e6msg.example.com"}],"e6msg.example.com":[{"TXT":"connect from %{p}"}],"mx.example.com":[{"A":"192.168.218.41"},{"A":"192.168.218.42"},{"AAAA":"CAFE:BABE::2"},{"AAAA":"CAFE:BABE::3"}],"40.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"}],"41.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"}],"42.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"},{"PTR":"mx.e7.example.com"}],"1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.E.B.A.B.E.F.A.C.ip6.arpa":[{"PTR":"mx.example.com"}],"3.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.E.B.A.B.E.F.A.C.ip6.arpa":[{"PTR":"mx.example.com"}],"mx.e7.example.com":[{"A":"192.168.218.42"}],"mx.e7.example.com.should.example.com":[{"A":"127.0.0.2"}],"mx.example.com.ok.example.com":[{"A":"127.0.0.2"}],"e7.example.com":[{"SPF":"v=spf1 exists:%{p}.should.example.com ~exists:%{p}.ok.example.com"}],"e8.example.com":[{"SPF":"v=spf1 -all exp=msg8.%{D2}"}],"msg8.example.com":[{"TXT":"http://example.com/why.html?l=%{L}"}],"e9.example.com":[{"SPF":"v=spf1 a:%{H} -all"}],"e10.example.com":[{"SPF":"v=spf1 -include:_spfh.%{d2} ip4:1.2.3.0/24 -all"}],"_spfh.example.com":[{"SPF":"v=spf1 -a:%{h} +all"}],"e11.example.com":[{"SPF":"v=spf1 exists:%{i}.%{l2r-}.user.%{d2}"}],"1.2.3.4.gladstone.philip.user.example.com":[{"A":"127.0.0.2"}],"e12.example.com":[{"SPF":"v=spf1 exists:%{l2r+-}.user.%{d2}"}],"bar.foo.user.example.com":[{"A":"127.0.0.2"}]}, failOnNoFake: true, helo: "msgbas2x.cos.example.com"}
        let promise = spf.check_host('CAFE:BABE::3', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'FAIL');
        });
      });
      it('p-macro-multiple', function(){
        let email = 'test@e7.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"example.com.d.spf.example.com":[{"SPF":"v=spf1 redirect=a.spf.example.com"}],"a.spf.example.com":[{"SPF":"v=spf1 include:o.spf.example.com. ~all"}],"o.spf.example.com":[{"SPF":"v=spf1 ip4:192.168.218.40"}],"msgbas2x.cos.example.com":[{"A":"192.168.218.40"}],"example.com":[{"A":"192.168.90.76"},{"SPF":"v=spf1 redirect=%{d}.d.spf.example.com."}],"exp.example.com":[{"SPF":"v=spf1 exp=msg.example.com. -all"}],"msg.example.com":[{"TXT":"This is a test."}],"e1.example.com":[{"SPF":"v=spf1 -exists:%(ir).sbl.example.com ?all"}],"e1e.example.com":[{"SPF":"v=spf1 exists:foo%(ir).sbl.example.com ?all"}],"e1t.example.com":[{"SPF":"v=spf1 exists:foo%.sbl.example.com ?all"}],"e1a.example.com":[{"SPF":"v=spf1 a:macro%%percent%_%_space%-url-space.example.com -all"}],"macro%percent  space%20url-space.example.com":[{"A":"1.2.3.4"}],"e2.example.com":[{"SPF":"v=spf1 -all exp=%{r}.example.com"}],"e3.example.com":[{"SPF":"v=spf1 -all exp=%{ir}.example.com"}],"40.218.168.192.example.com":[{"TXT":"Connections from %{c} not authorized."}],"somewhat.long.exp.example.com":[{"SPF":"v=spf1 -all exp=foobar.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.example.com"}],"somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.example.com":[{"TXT":"Congratulations!  That was tricky."}],"e4.example.com":[{"SPF":"v=spf1 -all exp=e4msg.example.com"}],"e4msg.example.com":[{"TXT":"%{c} is queried as %{ir}.%{v}.arpa"}],"e5.example.com":[{"SPF":"v=spf1 a:%{a}.example.com -all"}],"e6.example.com":[{"SPF":"v=spf1 -all exp=e6msg.example.com"}],"e6msg.example.com":[{"TXT":"connect from %{p}"}],"mx.example.com":[{"A":"192.168.218.41"},{"A":"192.168.218.42"},{"AAAA":"CAFE:BABE::2"},{"AAAA":"CAFE:BABE::3"}],"40.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"}],"41.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"}],"42.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"},{"PTR":"mx.e7.example.com"}],"1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.E.B.A.B.E.F.A.C.ip6.arpa":[{"PTR":"mx.example.com"}],"3.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.E.B.A.B.E.F.A.C.ip6.arpa":[{"PTR":"mx.example.com"}],"mx.e7.example.com":[{"A":"192.168.218.42"}],"mx.e7.example.com.should.example.com":[{"A":"127.0.0.2"}],"mx.example.com.ok.example.com":[{"A":"127.0.0.2"}],"e7.example.com":[{"SPF":"v=spf1 exists:%{p}.should.example.com ~exists:%{p}.ok.example.com"}],"e8.example.com":[{"SPF":"v=spf1 -all exp=msg8.%{D2}"}],"msg8.example.com":[{"TXT":"http://example.com/why.html?l=%{L}"}],"e9.example.com":[{"SPF":"v=spf1 a:%{H} -all"}],"e10.example.com":[{"SPF":"v=spf1 -include:_spfh.%{d2} ip4:1.2.3.0/24 -all"}],"_spfh.example.com":[{"SPF":"v=spf1 -a:%{h} +all"}],"e11.example.com":[{"SPF":"v=spf1 exists:%{i}.%{l2r-}.user.%{d2}"}],"1.2.3.4.gladstone.philip.user.example.com":[{"A":"127.0.0.2"}],"e12.example.com":[{"SPF":"v=spf1 exists:%{l2r+-}.user.%{d2}"}],"bar.foo.user.example.com":[{"A":"127.0.0.2"}]}, failOnNoFake: true, helo: "msgbas2x.cos.example.com"}
        let promise = spf.check_host('192.168.218.42', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.include(["pass","softfail"], result.toLowerCase());
        });
      });
      it('upper-macro', function(){
        let email = '~jack&jill=up-a_b3.c@e8.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"example.com.d.spf.example.com":[{"SPF":"v=spf1 redirect=a.spf.example.com"}],"a.spf.example.com":[{"SPF":"v=spf1 include:o.spf.example.com. ~all"}],"o.spf.example.com":[{"SPF":"v=spf1 ip4:192.168.218.40"}],"msgbas2x.cos.example.com":[{"A":"192.168.218.40"}],"example.com":[{"A":"192.168.90.76"},{"SPF":"v=spf1 redirect=%{d}.d.spf.example.com."}],"exp.example.com":[{"SPF":"v=spf1 exp=msg.example.com. -all"}],"msg.example.com":[{"TXT":"This is a test."}],"e1.example.com":[{"SPF":"v=spf1 -exists:%(ir).sbl.example.com ?all"}],"e1e.example.com":[{"SPF":"v=spf1 exists:foo%(ir).sbl.example.com ?all"}],"e1t.example.com":[{"SPF":"v=spf1 exists:foo%.sbl.example.com ?all"}],"e1a.example.com":[{"SPF":"v=spf1 a:macro%%percent%_%_space%-url-space.example.com -all"}],"macro%percent  space%20url-space.example.com":[{"A":"1.2.3.4"}],"e2.example.com":[{"SPF":"v=spf1 -all exp=%{r}.example.com"}],"e3.example.com":[{"SPF":"v=spf1 -all exp=%{ir}.example.com"}],"40.218.168.192.example.com":[{"TXT":"Connections from %{c} not authorized."}],"somewhat.long.exp.example.com":[{"SPF":"v=spf1 -all exp=foobar.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.example.com"}],"somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.example.com":[{"TXT":"Congratulations!  That was tricky."}],"e4.example.com":[{"SPF":"v=spf1 -all exp=e4msg.example.com"}],"e4msg.example.com":[{"TXT":"%{c} is queried as %{ir}.%{v}.arpa"}],"e5.example.com":[{"SPF":"v=spf1 a:%{a}.example.com -all"}],"e6.example.com":[{"SPF":"v=spf1 -all exp=e6msg.example.com"}],"e6msg.example.com":[{"TXT":"connect from %{p}"}],"mx.example.com":[{"A":"192.168.218.41"},{"A":"192.168.218.42"},{"AAAA":"CAFE:BABE::2"},{"AAAA":"CAFE:BABE::3"}],"40.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"}],"41.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"}],"42.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"},{"PTR":"mx.e7.example.com"}],"1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.E.B.A.B.E.F.A.C.ip6.arpa":[{"PTR":"mx.example.com"}],"3.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.E.B.A.B.E.F.A.C.ip6.arpa":[{"PTR":"mx.example.com"}],"mx.e7.example.com":[{"A":"192.168.218.42"}],"mx.e7.example.com.should.example.com":[{"A":"127.0.0.2"}],"mx.example.com.ok.example.com":[{"A":"127.0.0.2"}],"e7.example.com":[{"SPF":"v=spf1 exists:%{p}.should.example.com ~exists:%{p}.ok.example.com"}],"e8.example.com":[{"SPF":"v=spf1 -all exp=msg8.%{D2}"}],"msg8.example.com":[{"TXT":"http://example.com/why.html?l=%{L}"}],"e9.example.com":[{"SPF":"v=spf1 a:%{H} -all"}],"e10.example.com":[{"SPF":"v=spf1 -include:_spfh.%{d2} ip4:1.2.3.0/24 -all"}],"_spfh.example.com":[{"SPF":"v=spf1 -a:%{h} +all"}],"e11.example.com":[{"SPF":"v=spf1 exists:%{i}.%{l2r-}.user.%{d2}"}],"1.2.3.4.gladstone.philip.user.example.com":[{"A":"127.0.0.2"}],"e12.example.com":[{"SPF":"v=spf1 exists:%{l2r+-}.user.%{d2}"}],"bar.foo.user.example.com":[{"A":"127.0.0.2"}]}, failOnNoFake: true, helo: "msgbas2x.cos.example.com"}
        let promise = spf.check_host('192.168.218.42', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'FAIL');
        });
      });
      it('hello-macro', function(){
        let email = 'test@e9.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"example.com.d.spf.example.com":[{"SPF":"v=spf1 redirect=a.spf.example.com"}],"a.spf.example.com":[{"SPF":"v=spf1 include:o.spf.example.com. ~all"}],"o.spf.example.com":[{"SPF":"v=spf1 ip4:192.168.218.40"}],"msgbas2x.cos.example.com":[{"A":"192.168.218.40"}],"example.com":[{"A":"192.168.90.76"},{"SPF":"v=spf1 redirect=%{d}.d.spf.example.com."}],"exp.example.com":[{"SPF":"v=spf1 exp=msg.example.com. -all"}],"msg.example.com":[{"TXT":"This is a test."}],"e1.example.com":[{"SPF":"v=spf1 -exists:%(ir).sbl.example.com ?all"}],"e1e.example.com":[{"SPF":"v=spf1 exists:foo%(ir).sbl.example.com ?all"}],"e1t.example.com":[{"SPF":"v=spf1 exists:foo%.sbl.example.com ?all"}],"e1a.example.com":[{"SPF":"v=spf1 a:macro%%percent%_%_space%-url-space.example.com -all"}],"macro%percent  space%20url-space.example.com":[{"A":"1.2.3.4"}],"e2.example.com":[{"SPF":"v=spf1 -all exp=%{r}.example.com"}],"e3.example.com":[{"SPF":"v=spf1 -all exp=%{ir}.example.com"}],"40.218.168.192.example.com":[{"TXT":"Connections from %{c} not authorized."}],"somewhat.long.exp.example.com":[{"SPF":"v=spf1 -all exp=foobar.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.example.com"}],"somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.example.com":[{"TXT":"Congratulations!  That was tricky."}],"e4.example.com":[{"SPF":"v=spf1 -all exp=e4msg.example.com"}],"e4msg.example.com":[{"TXT":"%{c} is queried as %{ir}.%{v}.arpa"}],"e5.example.com":[{"SPF":"v=spf1 a:%{a}.example.com -all"}],"e6.example.com":[{"SPF":"v=spf1 -all exp=e6msg.example.com"}],"e6msg.example.com":[{"TXT":"connect from %{p}"}],"mx.example.com":[{"A":"192.168.218.41"},{"A":"192.168.218.42"},{"AAAA":"CAFE:BABE::2"},{"AAAA":"CAFE:BABE::3"}],"40.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"}],"41.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"}],"42.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"},{"PTR":"mx.e7.example.com"}],"1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.E.B.A.B.E.F.A.C.ip6.arpa":[{"PTR":"mx.example.com"}],"3.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.E.B.A.B.E.F.A.C.ip6.arpa":[{"PTR":"mx.example.com"}],"mx.e7.example.com":[{"A":"192.168.218.42"}],"mx.e7.example.com.should.example.com":[{"A":"127.0.0.2"}],"mx.example.com.ok.example.com":[{"A":"127.0.0.2"}],"e7.example.com":[{"SPF":"v=spf1 exists:%{p}.should.example.com ~exists:%{p}.ok.example.com"}],"e8.example.com":[{"SPF":"v=spf1 -all exp=msg8.%{D2}"}],"msg8.example.com":[{"TXT":"http://example.com/why.html?l=%{L}"}],"e9.example.com":[{"SPF":"v=spf1 a:%{H} -all"}],"e10.example.com":[{"SPF":"v=spf1 -include:_spfh.%{d2} ip4:1.2.3.0/24 -all"}],"_spfh.example.com":[{"SPF":"v=spf1 -a:%{h} +all"}],"e11.example.com":[{"SPF":"v=spf1 exists:%{i}.%{l2r-}.user.%{d2}"}],"1.2.3.4.gladstone.philip.user.example.com":[{"A":"127.0.0.2"}],"e12.example.com":[{"SPF":"v=spf1 exists:%{l2r+-}.user.%{d2}"}],"bar.foo.user.example.com":[{"A":"127.0.0.2"}]}, failOnNoFake: true, helo: "msgbas2x.cos.example.com"}
        let promise = spf.check_host('192.168.218.40', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'PASS');
        });
      });
      it('invalid-hello-macro', function(){
        let email = 'test@e9.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"example.com.d.spf.example.com":[{"SPF":"v=spf1 redirect=a.spf.example.com"}],"a.spf.example.com":[{"SPF":"v=spf1 include:o.spf.example.com. ~all"}],"o.spf.example.com":[{"SPF":"v=spf1 ip4:192.168.218.40"}],"msgbas2x.cos.example.com":[{"A":"192.168.218.40"}],"example.com":[{"A":"192.168.90.76"},{"SPF":"v=spf1 redirect=%{d}.d.spf.example.com."}],"exp.example.com":[{"SPF":"v=spf1 exp=msg.example.com. -all"}],"msg.example.com":[{"TXT":"This is a test."}],"e1.example.com":[{"SPF":"v=spf1 -exists:%(ir).sbl.example.com ?all"}],"e1e.example.com":[{"SPF":"v=spf1 exists:foo%(ir).sbl.example.com ?all"}],"e1t.example.com":[{"SPF":"v=spf1 exists:foo%.sbl.example.com ?all"}],"e1a.example.com":[{"SPF":"v=spf1 a:macro%%percent%_%_space%-url-space.example.com -all"}],"macro%percent  space%20url-space.example.com":[{"A":"1.2.3.4"}],"e2.example.com":[{"SPF":"v=spf1 -all exp=%{r}.example.com"}],"e3.example.com":[{"SPF":"v=spf1 -all exp=%{ir}.example.com"}],"40.218.168.192.example.com":[{"TXT":"Connections from %{c} not authorized."}],"somewhat.long.exp.example.com":[{"SPF":"v=spf1 -all exp=foobar.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.example.com"}],"somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.example.com":[{"TXT":"Congratulations!  That was tricky."}],"e4.example.com":[{"SPF":"v=spf1 -all exp=e4msg.example.com"}],"e4msg.example.com":[{"TXT":"%{c} is queried as %{ir}.%{v}.arpa"}],"e5.example.com":[{"SPF":"v=spf1 a:%{a}.example.com -all"}],"e6.example.com":[{"SPF":"v=spf1 -all exp=e6msg.example.com"}],"e6msg.example.com":[{"TXT":"connect from %{p}"}],"mx.example.com":[{"A":"192.168.218.41"},{"A":"192.168.218.42"},{"AAAA":"CAFE:BABE::2"},{"AAAA":"CAFE:BABE::3"}],"40.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"}],"41.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"}],"42.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"},{"PTR":"mx.e7.example.com"}],"1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.E.B.A.B.E.F.A.C.ip6.arpa":[{"PTR":"mx.example.com"}],"3.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.E.B.A.B.E.F.A.C.ip6.arpa":[{"PTR":"mx.example.com"}],"mx.e7.example.com":[{"A":"192.168.218.42"}],"mx.e7.example.com.should.example.com":[{"A":"127.0.0.2"}],"mx.example.com.ok.example.com":[{"A":"127.0.0.2"}],"e7.example.com":[{"SPF":"v=spf1 exists:%{p}.should.example.com ~exists:%{p}.ok.example.com"}],"e8.example.com":[{"SPF":"v=spf1 -all exp=msg8.%{D2}"}],"msg8.example.com":[{"TXT":"http://example.com/why.html?l=%{L}"}],"e9.example.com":[{"SPF":"v=spf1 a:%{H} -all"}],"e10.example.com":[{"SPF":"v=spf1 -include:_spfh.%{d2} ip4:1.2.3.0/24 -all"}],"_spfh.example.com":[{"SPF":"v=spf1 -a:%{h} +all"}],"e11.example.com":[{"SPF":"v=spf1 exists:%{i}.%{l2r-}.user.%{d2}"}],"1.2.3.4.gladstone.philip.user.example.com":[{"A":"127.0.0.2"}],"e12.example.com":[{"SPF":"v=spf1 exists:%{l2r+-}.user.%{d2}"}],"bar.foo.user.example.com":[{"A":"127.0.0.2"}]}, failOnNoFake: true, helo: "JUMPIN' JUPITER"}
        let promise = spf.check_host('192.168.218.40', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'FAIL');
        });
      });
      it('hello-domain-literal', function(){
        let email = 'test@e9.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"example.com.d.spf.example.com":[{"SPF":"v=spf1 redirect=a.spf.example.com"}],"a.spf.example.com":[{"SPF":"v=spf1 include:o.spf.example.com. ~all"}],"o.spf.example.com":[{"SPF":"v=spf1 ip4:192.168.218.40"}],"msgbas2x.cos.example.com":[{"A":"192.168.218.40"}],"example.com":[{"A":"192.168.90.76"},{"SPF":"v=spf1 redirect=%{d}.d.spf.example.com."}],"exp.example.com":[{"SPF":"v=spf1 exp=msg.example.com. -all"}],"msg.example.com":[{"TXT":"This is a test."}],"e1.example.com":[{"SPF":"v=spf1 -exists:%(ir).sbl.example.com ?all"}],"e1e.example.com":[{"SPF":"v=spf1 exists:foo%(ir).sbl.example.com ?all"}],"e1t.example.com":[{"SPF":"v=spf1 exists:foo%.sbl.example.com ?all"}],"e1a.example.com":[{"SPF":"v=spf1 a:macro%%percent%_%_space%-url-space.example.com -all"}],"macro%percent  space%20url-space.example.com":[{"A":"1.2.3.4"}],"e2.example.com":[{"SPF":"v=spf1 -all exp=%{r}.example.com"}],"e3.example.com":[{"SPF":"v=spf1 -all exp=%{ir}.example.com"}],"40.218.168.192.example.com":[{"TXT":"Connections from %{c} not authorized."}],"somewhat.long.exp.example.com":[{"SPF":"v=spf1 -all exp=foobar.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.example.com"}],"somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.example.com":[{"TXT":"Congratulations!  That was tricky."}],"e4.example.com":[{"SPF":"v=spf1 -all exp=e4msg.example.com"}],"e4msg.example.com":[{"TXT":"%{c} is queried as %{ir}.%{v}.arpa"}],"e5.example.com":[{"SPF":"v=spf1 a:%{a}.example.com -all"}],"e6.example.com":[{"SPF":"v=spf1 -all exp=e6msg.example.com"}],"e6msg.example.com":[{"TXT":"connect from %{p}"}],"mx.example.com":[{"A":"192.168.218.41"},{"A":"192.168.218.42"},{"AAAA":"CAFE:BABE::2"},{"AAAA":"CAFE:BABE::3"}],"40.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"}],"41.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"}],"42.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"},{"PTR":"mx.e7.example.com"}],"1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.E.B.A.B.E.F.A.C.ip6.arpa":[{"PTR":"mx.example.com"}],"3.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.E.B.A.B.E.F.A.C.ip6.arpa":[{"PTR":"mx.example.com"}],"mx.e7.example.com":[{"A":"192.168.218.42"}],"mx.e7.example.com.should.example.com":[{"A":"127.0.0.2"}],"mx.example.com.ok.example.com":[{"A":"127.0.0.2"}],"e7.example.com":[{"SPF":"v=spf1 exists:%{p}.should.example.com ~exists:%{p}.ok.example.com"}],"e8.example.com":[{"SPF":"v=spf1 -all exp=msg8.%{D2}"}],"msg8.example.com":[{"TXT":"http://example.com/why.html?l=%{L}"}],"e9.example.com":[{"SPF":"v=spf1 a:%{H} -all"}],"e10.example.com":[{"SPF":"v=spf1 -include:_spfh.%{d2} ip4:1.2.3.0/24 -all"}],"_spfh.example.com":[{"SPF":"v=spf1 -a:%{h} +all"}],"e11.example.com":[{"SPF":"v=spf1 exists:%{i}.%{l2r-}.user.%{d2}"}],"1.2.3.4.gladstone.philip.user.example.com":[{"A":"127.0.0.2"}],"e12.example.com":[{"SPF":"v=spf1 exists:%{l2r+-}.user.%{d2}"}],"bar.foo.user.example.com":[{"A":"127.0.0.2"}]}, failOnNoFake: true, helo: "[192.168.218.40]"}
        let promise = spf.check_host('192.168.218.40', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'FAIL');
        });
      });
      it('require-valid-helo', function(){
        let email = 'test@e10.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"example.com.d.spf.example.com":[{"SPF":"v=spf1 redirect=a.spf.example.com"}],"a.spf.example.com":[{"SPF":"v=spf1 include:o.spf.example.com. ~all"}],"o.spf.example.com":[{"SPF":"v=spf1 ip4:192.168.218.40"}],"msgbas2x.cos.example.com":[{"A":"192.168.218.40"}],"example.com":[{"A":"192.168.90.76"},{"SPF":"v=spf1 redirect=%{d}.d.spf.example.com."}],"exp.example.com":[{"SPF":"v=spf1 exp=msg.example.com. -all"}],"msg.example.com":[{"TXT":"This is a test."}],"e1.example.com":[{"SPF":"v=spf1 -exists:%(ir).sbl.example.com ?all"}],"e1e.example.com":[{"SPF":"v=spf1 exists:foo%(ir).sbl.example.com ?all"}],"e1t.example.com":[{"SPF":"v=spf1 exists:foo%.sbl.example.com ?all"}],"e1a.example.com":[{"SPF":"v=spf1 a:macro%%percent%_%_space%-url-space.example.com -all"}],"macro%percent  space%20url-space.example.com":[{"A":"1.2.3.4"}],"e2.example.com":[{"SPF":"v=spf1 -all exp=%{r}.example.com"}],"e3.example.com":[{"SPF":"v=spf1 -all exp=%{ir}.example.com"}],"40.218.168.192.example.com":[{"TXT":"Connections from %{c} not authorized."}],"somewhat.long.exp.example.com":[{"SPF":"v=spf1 -all exp=foobar.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.example.com"}],"somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.example.com":[{"TXT":"Congratulations!  That was tricky."}],"e4.example.com":[{"SPF":"v=spf1 -all exp=e4msg.example.com"}],"e4msg.example.com":[{"TXT":"%{c} is queried as %{ir}.%{v}.arpa"}],"e5.example.com":[{"SPF":"v=spf1 a:%{a}.example.com -all"}],"e6.example.com":[{"SPF":"v=spf1 -all exp=e6msg.example.com"}],"e6msg.example.com":[{"TXT":"connect from %{p}"}],"mx.example.com":[{"A":"192.168.218.41"},{"A":"192.168.218.42"},{"AAAA":"CAFE:BABE::2"},{"AAAA":"CAFE:BABE::3"}],"40.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"}],"41.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"}],"42.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"},{"PTR":"mx.e7.example.com"}],"1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.E.B.A.B.E.F.A.C.ip6.arpa":[{"PTR":"mx.example.com"}],"3.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.E.B.A.B.E.F.A.C.ip6.arpa":[{"PTR":"mx.example.com"}],"mx.e7.example.com":[{"A":"192.168.218.42"}],"mx.e7.example.com.should.example.com":[{"A":"127.0.0.2"}],"mx.example.com.ok.example.com":[{"A":"127.0.0.2"}],"e7.example.com":[{"SPF":"v=spf1 exists:%{p}.should.example.com ~exists:%{p}.ok.example.com"}],"e8.example.com":[{"SPF":"v=spf1 -all exp=msg8.%{D2}"}],"msg8.example.com":[{"TXT":"http://example.com/why.html?l=%{L}"}],"e9.example.com":[{"SPF":"v=spf1 a:%{H} -all"}],"e10.example.com":[{"SPF":"v=spf1 -include:_spfh.%{d2} ip4:1.2.3.0/24 -all"}],"_spfh.example.com":[{"SPF":"v=spf1 -a:%{h} +all"}],"e11.example.com":[{"SPF":"v=spf1 exists:%{i}.%{l2r-}.user.%{d2}"}],"1.2.3.4.gladstone.philip.user.example.com":[{"A":"127.0.0.2"}],"e12.example.com":[{"SPF":"v=spf1 exists:%{l2r+-}.user.%{d2}"}],"bar.foo.user.example.com":[{"A":"127.0.0.2"}]}, failOnNoFake: true, helo: "OEMCOMPUTER"}
        let promise = spf.check_host('1.2.3.4', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'FAIL');
        });
      });
      it('macro-reverse-split-on-dash', function(){
        let email = 'philip-gladstone-test@e11.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"example.com.d.spf.example.com":[{"SPF":"v=spf1 redirect=a.spf.example.com"}],"a.spf.example.com":[{"SPF":"v=spf1 include:o.spf.example.com. ~all"}],"o.spf.example.com":[{"SPF":"v=spf1 ip4:192.168.218.40"}],"msgbas2x.cos.example.com":[{"A":"192.168.218.40"}],"example.com":[{"A":"192.168.90.76"},{"SPF":"v=spf1 redirect=%{d}.d.spf.example.com."}],"exp.example.com":[{"SPF":"v=spf1 exp=msg.example.com. -all"}],"msg.example.com":[{"TXT":"This is a test."}],"e1.example.com":[{"SPF":"v=spf1 -exists:%(ir).sbl.example.com ?all"}],"e1e.example.com":[{"SPF":"v=spf1 exists:foo%(ir).sbl.example.com ?all"}],"e1t.example.com":[{"SPF":"v=spf1 exists:foo%.sbl.example.com ?all"}],"e1a.example.com":[{"SPF":"v=spf1 a:macro%%percent%_%_space%-url-space.example.com -all"}],"macro%percent  space%20url-space.example.com":[{"A":"1.2.3.4"}],"e2.example.com":[{"SPF":"v=spf1 -all exp=%{r}.example.com"}],"e3.example.com":[{"SPF":"v=spf1 -all exp=%{ir}.example.com"}],"40.218.168.192.example.com":[{"TXT":"Connections from %{c} not authorized."}],"somewhat.long.exp.example.com":[{"SPF":"v=spf1 -all exp=foobar.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.example.com"}],"somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.example.com":[{"TXT":"Congratulations!  That was tricky."}],"e4.example.com":[{"SPF":"v=spf1 -all exp=e4msg.example.com"}],"e4msg.example.com":[{"TXT":"%{c} is queried as %{ir}.%{v}.arpa"}],"e5.example.com":[{"SPF":"v=spf1 a:%{a}.example.com -all"}],"e6.example.com":[{"SPF":"v=spf1 -all exp=e6msg.example.com"}],"e6msg.example.com":[{"TXT":"connect from %{p}"}],"mx.example.com":[{"A":"192.168.218.41"},{"A":"192.168.218.42"},{"AAAA":"CAFE:BABE::2"},{"AAAA":"CAFE:BABE::3"}],"40.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"}],"41.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"}],"42.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"},{"PTR":"mx.e7.example.com"}],"1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.E.B.A.B.E.F.A.C.ip6.arpa":[{"PTR":"mx.example.com"}],"3.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.E.B.A.B.E.F.A.C.ip6.arpa":[{"PTR":"mx.example.com"}],"mx.e7.example.com":[{"A":"192.168.218.42"}],"mx.e7.example.com.should.example.com":[{"A":"127.0.0.2"}],"mx.example.com.ok.example.com":[{"A":"127.0.0.2"}],"e7.example.com":[{"SPF":"v=spf1 exists:%{p}.should.example.com ~exists:%{p}.ok.example.com"}],"e8.example.com":[{"SPF":"v=spf1 -all exp=msg8.%{D2}"}],"msg8.example.com":[{"TXT":"http://example.com/why.html?l=%{L}"}],"e9.example.com":[{"SPF":"v=spf1 a:%{H} -all"}],"e10.example.com":[{"SPF":"v=spf1 -include:_spfh.%{d2} ip4:1.2.3.0/24 -all"}],"_spfh.example.com":[{"SPF":"v=spf1 -a:%{h} +all"}],"e11.example.com":[{"SPF":"v=spf1 exists:%{i}.%{l2r-}.user.%{d2}"}],"1.2.3.4.gladstone.philip.user.example.com":[{"A":"127.0.0.2"}],"e12.example.com":[{"SPF":"v=spf1 exists:%{l2r+-}.user.%{d2}"}],"bar.foo.user.example.com":[{"A":"127.0.0.2"}]}, failOnNoFake: true, helo: "mail.example.com"}
        let promise = spf.check_host('1.2.3.4', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'PASS');
        });
      });
      it('macro-multiple-delimiters', function(){
        let email = 'foo-bar+zip+quux@e12.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"example.com.d.spf.example.com":[{"SPF":"v=spf1 redirect=a.spf.example.com"}],"a.spf.example.com":[{"SPF":"v=spf1 include:o.spf.example.com. ~all"}],"o.spf.example.com":[{"SPF":"v=spf1 ip4:192.168.218.40"}],"msgbas2x.cos.example.com":[{"A":"192.168.218.40"}],"example.com":[{"A":"192.168.90.76"},{"SPF":"v=spf1 redirect=%{d}.d.spf.example.com."}],"exp.example.com":[{"SPF":"v=spf1 exp=msg.example.com. -all"}],"msg.example.com":[{"TXT":"This is a test."}],"e1.example.com":[{"SPF":"v=spf1 -exists:%(ir).sbl.example.com ?all"}],"e1e.example.com":[{"SPF":"v=spf1 exists:foo%(ir).sbl.example.com ?all"}],"e1t.example.com":[{"SPF":"v=spf1 exists:foo%.sbl.example.com ?all"}],"e1a.example.com":[{"SPF":"v=spf1 a:macro%%percent%_%_space%-url-space.example.com -all"}],"macro%percent  space%20url-space.example.com":[{"A":"1.2.3.4"}],"e2.example.com":[{"SPF":"v=spf1 -all exp=%{r}.example.com"}],"e3.example.com":[{"SPF":"v=spf1 -all exp=%{ir}.example.com"}],"40.218.168.192.example.com":[{"TXT":"Connections from %{c} not authorized."}],"somewhat.long.exp.example.com":[{"SPF":"v=spf1 -all exp=foobar.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.%{o}.example.com"}],"somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.somewhat.long.exp.example.com.example.com":[{"TXT":"Congratulations!  That was tricky."}],"e4.example.com":[{"SPF":"v=spf1 -all exp=e4msg.example.com"}],"e4msg.example.com":[{"TXT":"%{c} is queried as %{ir}.%{v}.arpa"}],"e5.example.com":[{"SPF":"v=spf1 a:%{a}.example.com -all"}],"e6.example.com":[{"SPF":"v=spf1 -all exp=e6msg.example.com"}],"e6msg.example.com":[{"TXT":"connect from %{p}"}],"mx.example.com":[{"A":"192.168.218.41"},{"A":"192.168.218.42"},{"AAAA":"CAFE:BABE::2"},{"AAAA":"CAFE:BABE::3"}],"40.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"}],"41.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"}],"42.218.168.192.in-addr.arpa":[{"PTR":"mx.example.com"},{"PTR":"mx.e7.example.com"}],"1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.E.B.A.B.E.F.A.C.ip6.arpa":[{"PTR":"mx.example.com"}],"3.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.E.B.A.B.E.F.A.C.ip6.arpa":[{"PTR":"mx.example.com"}],"mx.e7.example.com":[{"A":"192.168.218.42"}],"mx.e7.example.com.should.example.com":[{"A":"127.0.0.2"}],"mx.example.com.ok.example.com":[{"A":"127.0.0.2"}],"e7.example.com":[{"SPF":"v=spf1 exists:%{p}.should.example.com ~exists:%{p}.ok.example.com"}],"e8.example.com":[{"SPF":"v=spf1 -all exp=msg8.%{D2}"}],"msg8.example.com":[{"TXT":"http://example.com/why.html?l=%{L}"}],"e9.example.com":[{"SPF":"v=spf1 a:%{H} -all"}],"e10.example.com":[{"SPF":"v=spf1 -include:_spfh.%{d2} ip4:1.2.3.0/24 -all"}],"_spfh.example.com":[{"SPF":"v=spf1 -a:%{h} +all"}],"e11.example.com":[{"SPF":"v=spf1 exists:%{i}.%{l2r-}.user.%{d2}"}],"1.2.3.4.gladstone.philip.user.example.com":[{"A":"127.0.0.2"}],"e12.example.com":[{"SPF":"v=spf1 exists:%{l2r+-}.user.%{d2}"}],"bar.foo.user.example.com":[{"A":"127.0.0.2"}]}, failOnNoFake: true, helo: "mail.example.com"}
        let promise = spf.check_host('1.2.3.4', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'PASS');
        });
      });
    });
    describe('Processing limits', function(){
      it('redirect-loop', function(){
        let email = 'foo@e1.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 ip4:1.1.1.1 redirect=e1.example.com"},{"A":"1.2.3.6"}],"e2.example.com":[{"SPF":"v=spf1 include:e3.example.com"},{"A":"1.2.3.7"}],"e3.example.com":[{"SPF":"v=spf1 include:e2.example.com"},{"A":"1.2.3.8"}],"e4.example.com":[{"SPF":"v=spf1 mx"},{"MX":[0,"mail.example.com"]},{"MX":[1,"mail.example.com"]},{"MX":[2,"mail.example.com"]},{"MX":[3,"mail.example.com"]},{"MX":[4,"mail.example.com"]},{"MX":[5,"mail.example.com"]},{"MX":[6,"mail.example.com"]},{"MX":[7,"mail.example.com"]},{"MX":[8,"mail.example.com"]},{"MX":[9,"mail.example.com"]},{"MX":[10,"e4.example.com"]},{"A":"1.2.3.5"}],"e5.example.com":[{"SPF":"v=spf1 ptr"},{"A":"1.2.3.5"}],"5.3.2.1.in-addr.arpa":[{"PTR":"e1.example.com."},{"PTR":"e2.example.com."},{"PTR":"e3.example.com."},{"PTR":"e4.example.com."},{"PTR":"example.com."},{"PTR":"e6.example.com."},{"PTR":"e7.example.com."},{"PTR":"e8.example.com."},{"PTR":"e9.example.com."},{"PTR":"e10.example.com."},{"PTR":"e5.example.com."}],"e6.example.com":[{"SPF":"v=spf1 a mx a mx a mx a mx a ptr ip4:1.2.3.4 -all"},{"A":"1.2.3.8"},{"MX":[10,"e6.example.com"]}],"e7.example.com":[{"SPF":"v=spf1 a mx a mx a mx a mx a ptr a ip4:1.2.3.4 -all"},{"A":"1.2.3.20"}],"e8.example.com":[{"SPF":"v=spf1 a include:inc.example.com ip4:1.2.3.4 mx -all"},{"A":"1.2.3.4"}],"inc.example.com":[{"SPF":"v=spf1 a a a a a a a a"},{"A":"1.2.3.10"}],"e9.example.com":[{"SPF":"v=spf1 a include:inc.example.com a ip4:1.2.3.4 -all"},{"A":"1.2.3.21"}],"e10.example.com":[{"SPF":"v=spf1 a -all"},{"A":"1.2.3.1"},{"A":"1.2.3.2"},{"A":"1.2.3.3"},{"A":"1.2.3.4"},{"A":"1.2.3.5"},{"A":"1.2.3.6"},{"A":"1.2.3.7"},{"A":"1.2.3.8"},{"A":"1.2.3.9"},{"A":"1.2.3.10"},{"A":"1.2.3.11"},{"A":"1.2.3.12"}],"e11.example.com":[{"TXT":"v=spf1 a:err.example.com a:err1.example.com a:err2.example.com ?all"}],"e12.example.com":[{"TXT":"v=spf1 a:err.example.com a:err1.example.com ?all"}]}, failOnNoFake: true, helo: "mail.example.com"}
        let promise = spf.check_host('1.2.3.4', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'PERMERROR');
        });
      });
      it('include-loop', function(){
        let email = 'foo@e2.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 ip4:1.1.1.1 redirect=e1.example.com"},{"A":"1.2.3.6"}],"e2.example.com":[{"SPF":"v=spf1 include:e3.example.com"},{"A":"1.2.3.7"}],"e3.example.com":[{"SPF":"v=spf1 include:e2.example.com"},{"A":"1.2.3.8"}],"e4.example.com":[{"SPF":"v=spf1 mx"},{"MX":[0,"mail.example.com"]},{"MX":[1,"mail.example.com"]},{"MX":[2,"mail.example.com"]},{"MX":[3,"mail.example.com"]},{"MX":[4,"mail.example.com"]},{"MX":[5,"mail.example.com"]},{"MX":[6,"mail.example.com"]},{"MX":[7,"mail.example.com"]},{"MX":[8,"mail.example.com"]},{"MX":[9,"mail.example.com"]},{"MX":[10,"e4.example.com"]},{"A":"1.2.3.5"}],"e5.example.com":[{"SPF":"v=spf1 ptr"},{"A":"1.2.3.5"}],"5.3.2.1.in-addr.arpa":[{"PTR":"e1.example.com."},{"PTR":"e2.example.com."},{"PTR":"e3.example.com."},{"PTR":"e4.example.com."},{"PTR":"example.com."},{"PTR":"e6.example.com."},{"PTR":"e7.example.com."},{"PTR":"e8.example.com."},{"PTR":"e9.example.com."},{"PTR":"e10.example.com."},{"PTR":"e5.example.com."}],"e6.example.com":[{"SPF":"v=spf1 a mx a mx a mx a mx a ptr ip4:1.2.3.4 -all"},{"A":"1.2.3.8"},{"MX":[10,"e6.example.com"]}],"e7.example.com":[{"SPF":"v=spf1 a mx a mx a mx a mx a ptr a ip4:1.2.3.4 -all"},{"A":"1.2.3.20"}],"e8.example.com":[{"SPF":"v=spf1 a include:inc.example.com ip4:1.2.3.4 mx -all"},{"A":"1.2.3.4"}],"inc.example.com":[{"SPF":"v=spf1 a a a a a a a a"},{"A":"1.2.3.10"}],"e9.example.com":[{"SPF":"v=spf1 a include:inc.example.com a ip4:1.2.3.4 -all"},{"A":"1.2.3.21"}],"e10.example.com":[{"SPF":"v=spf1 a -all"},{"A":"1.2.3.1"},{"A":"1.2.3.2"},{"A":"1.2.3.3"},{"A":"1.2.3.4"},{"A":"1.2.3.5"},{"A":"1.2.3.6"},{"A":"1.2.3.7"},{"A":"1.2.3.8"},{"A":"1.2.3.9"},{"A":"1.2.3.10"},{"A":"1.2.3.11"},{"A":"1.2.3.12"}],"e11.example.com":[{"TXT":"v=spf1 a:err.example.com a:err1.example.com a:err2.example.com ?all"}],"e12.example.com":[{"TXT":"v=spf1 a:err.example.com a:err1.example.com ?all"}]}, failOnNoFake: true, helo: "mail.example.com"}
        let promise = spf.check_host('1.2.3.4', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'PERMERROR');
        });
      });
      it('mx-limit', function(){
        let email = 'foo@e4.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 ip4:1.1.1.1 redirect=e1.example.com"},{"A":"1.2.3.6"}],"e2.example.com":[{"SPF":"v=spf1 include:e3.example.com"},{"A":"1.2.3.7"}],"e3.example.com":[{"SPF":"v=spf1 include:e2.example.com"},{"A":"1.2.3.8"}],"e4.example.com":[{"SPF":"v=spf1 mx"},{"MX":[0,"mail.example.com"]},{"MX":[1,"mail.example.com"]},{"MX":[2,"mail.example.com"]},{"MX":[3,"mail.example.com"]},{"MX":[4,"mail.example.com"]},{"MX":[5,"mail.example.com"]},{"MX":[6,"mail.example.com"]},{"MX":[7,"mail.example.com"]},{"MX":[8,"mail.example.com"]},{"MX":[9,"mail.example.com"]},{"MX":[10,"e4.example.com"]},{"A":"1.2.3.5"}],"e5.example.com":[{"SPF":"v=spf1 ptr"},{"A":"1.2.3.5"}],"5.3.2.1.in-addr.arpa":[{"PTR":"e1.example.com."},{"PTR":"e2.example.com."},{"PTR":"e3.example.com."},{"PTR":"e4.example.com."},{"PTR":"example.com."},{"PTR":"e6.example.com."},{"PTR":"e7.example.com."},{"PTR":"e8.example.com."},{"PTR":"e9.example.com."},{"PTR":"e10.example.com."},{"PTR":"e5.example.com."}],"e6.example.com":[{"SPF":"v=spf1 a mx a mx a mx a mx a ptr ip4:1.2.3.4 -all"},{"A":"1.2.3.8"},{"MX":[10,"e6.example.com"]}],"e7.example.com":[{"SPF":"v=spf1 a mx a mx a mx a mx a ptr a ip4:1.2.3.4 -all"},{"A":"1.2.3.20"}],"e8.example.com":[{"SPF":"v=spf1 a include:inc.example.com ip4:1.2.3.4 mx -all"},{"A":"1.2.3.4"}],"inc.example.com":[{"SPF":"v=spf1 a a a a a a a a"},{"A":"1.2.3.10"}],"e9.example.com":[{"SPF":"v=spf1 a include:inc.example.com a ip4:1.2.3.4 -all"},{"A":"1.2.3.21"}],"e10.example.com":[{"SPF":"v=spf1 a -all"},{"A":"1.2.3.1"},{"A":"1.2.3.2"},{"A":"1.2.3.3"},{"A":"1.2.3.4"},{"A":"1.2.3.5"},{"A":"1.2.3.6"},{"A":"1.2.3.7"},{"A":"1.2.3.8"},{"A":"1.2.3.9"},{"A":"1.2.3.10"},{"A":"1.2.3.11"},{"A":"1.2.3.12"}],"e11.example.com":[{"TXT":"v=spf1 a:err.example.com a:err1.example.com a:err2.example.com ?all"}],"e12.example.com":[{"TXT":"v=spf1 a:err.example.com a:err1.example.com ?all"}]}, failOnNoFake: true, helo: "mail.example.com"}
        let promise = spf.check_host('1.2.3.5', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'PERMERROR');
        });
      });
      it('ptr-limit', function(){
        let email = 'foo@e5.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 ip4:1.1.1.1 redirect=e1.example.com"},{"A":"1.2.3.6"}],"e2.example.com":[{"SPF":"v=spf1 include:e3.example.com"},{"A":"1.2.3.7"}],"e3.example.com":[{"SPF":"v=spf1 include:e2.example.com"},{"A":"1.2.3.8"}],"e4.example.com":[{"SPF":"v=spf1 mx"},{"MX":[0,"mail.example.com"]},{"MX":[1,"mail.example.com"]},{"MX":[2,"mail.example.com"]},{"MX":[3,"mail.example.com"]},{"MX":[4,"mail.example.com"]},{"MX":[5,"mail.example.com"]},{"MX":[6,"mail.example.com"]},{"MX":[7,"mail.example.com"]},{"MX":[8,"mail.example.com"]},{"MX":[9,"mail.example.com"]},{"MX":[10,"e4.example.com"]},{"A":"1.2.3.5"}],"e5.example.com":[{"SPF":"v=spf1 ptr"},{"A":"1.2.3.5"}],"5.3.2.1.in-addr.arpa":[{"PTR":"e1.example.com."},{"PTR":"e2.example.com."},{"PTR":"e3.example.com."},{"PTR":"e4.example.com."},{"PTR":"example.com."},{"PTR":"e6.example.com."},{"PTR":"e7.example.com."},{"PTR":"e8.example.com."},{"PTR":"e9.example.com."},{"PTR":"e10.example.com."},{"PTR":"e5.example.com."}],"e6.example.com":[{"SPF":"v=spf1 a mx a mx a mx a mx a ptr ip4:1.2.3.4 -all"},{"A":"1.2.3.8"},{"MX":[10,"e6.example.com"]}],"e7.example.com":[{"SPF":"v=spf1 a mx a mx a mx a mx a ptr a ip4:1.2.3.4 -all"},{"A":"1.2.3.20"}],"e8.example.com":[{"SPF":"v=spf1 a include:inc.example.com ip4:1.2.3.4 mx -all"},{"A":"1.2.3.4"}],"inc.example.com":[{"SPF":"v=spf1 a a a a a a a a"},{"A":"1.2.3.10"}],"e9.example.com":[{"SPF":"v=spf1 a include:inc.example.com a ip4:1.2.3.4 -all"},{"A":"1.2.3.21"}],"e10.example.com":[{"SPF":"v=spf1 a -all"},{"A":"1.2.3.1"},{"A":"1.2.3.2"},{"A":"1.2.3.3"},{"A":"1.2.3.4"},{"A":"1.2.3.5"},{"A":"1.2.3.6"},{"A":"1.2.3.7"},{"A":"1.2.3.8"},{"A":"1.2.3.9"},{"A":"1.2.3.10"},{"A":"1.2.3.11"},{"A":"1.2.3.12"}],"e11.example.com":[{"TXT":"v=spf1 a:err.example.com a:err1.example.com a:err2.example.com ?all"}],"e12.example.com":[{"TXT":"v=spf1 a:err.example.com a:err1.example.com ?all"}]}, failOnNoFake: true, helo: "mail.example.com"}
        let promise = spf.check_host('1.2.3.5', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.include(["neutral","pass"], result.toLowerCase());
        });
      });
      it('false-a-limit', function(){
        let email = 'foo@e10.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 ip4:1.1.1.1 redirect=e1.example.com"},{"A":"1.2.3.6"}],"e2.example.com":[{"SPF":"v=spf1 include:e3.example.com"},{"A":"1.2.3.7"}],"e3.example.com":[{"SPF":"v=spf1 include:e2.example.com"},{"A":"1.2.3.8"}],"e4.example.com":[{"SPF":"v=spf1 mx"},{"MX":[0,"mail.example.com"]},{"MX":[1,"mail.example.com"]},{"MX":[2,"mail.example.com"]},{"MX":[3,"mail.example.com"]},{"MX":[4,"mail.example.com"]},{"MX":[5,"mail.example.com"]},{"MX":[6,"mail.example.com"]},{"MX":[7,"mail.example.com"]},{"MX":[8,"mail.example.com"]},{"MX":[9,"mail.example.com"]},{"MX":[10,"e4.example.com"]},{"A":"1.2.3.5"}],"e5.example.com":[{"SPF":"v=spf1 ptr"},{"A":"1.2.3.5"}],"5.3.2.1.in-addr.arpa":[{"PTR":"e1.example.com."},{"PTR":"e2.example.com."},{"PTR":"e3.example.com."},{"PTR":"e4.example.com."},{"PTR":"example.com."},{"PTR":"e6.example.com."},{"PTR":"e7.example.com."},{"PTR":"e8.example.com."},{"PTR":"e9.example.com."},{"PTR":"e10.example.com."},{"PTR":"e5.example.com."}],"e6.example.com":[{"SPF":"v=spf1 a mx a mx a mx a mx a ptr ip4:1.2.3.4 -all"},{"A":"1.2.3.8"},{"MX":[10,"e6.example.com"]}],"e7.example.com":[{"SPF":"v=spf1 a mx a mx a mx a mx a ptr a ip4:1.2.3.4 -all"},{"A":"1.2.3.20"}],"e8.example.com":[{"SPF":"v=spf1 a include:inc.example.com ip4:1.2.3.4 mx -all"},{"A":"1.2.3.4"}],"inc.example.com":[{"SPF":"v=spf1 a a a a a a a a"},{"A":"1.2.3.10"}],"e9.example.com":[{"SPF":"v=spf1 a include:inc.example.com a ip4:1.2.3.4 -all"},{"A":"1.2.3.21"}],"e10.example.com":[{"SPF":"v=spf1 a -all"},{"A":"1.2.3.1"},{"A":"1.2.3.2"},{"A":"1.2.3.3"},{"A":"1.2.3.4"},{"A":"1.2.3.5"},{"A":"1.2.3.6"},{"A":"1.2.3.7"},{"A":"1.2.3.8"},{"A":"1.2.3.9"},{"A":"1.2.3.10"},{"A":"1.2.3.11"},{"A":"1.2.3.12"}],"e11.example.com":[{"TXT":"v=spf1 a:err.example.com a:err1.example.com a:err2.example.com ?all"}],"e12.example.com":[{"TXT":"v=spf1 a:err.example.com a:err1.example.com ?all"}]}, failOnNoFake: true, helo: "mail.example.com"}
        let promise = spf.check_host('1.2.3.12', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'PASS');
        });
      });
      it('mech-at-limit', function(){
        let email = 'foo@e6.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 ip4:1.1.1.1 redirect=e1.example.com"},{"A":"1.2.3.6"}],"e2.example.com":[{"SPF":"v=spf1 include:e3.example.com"},{"A":"1.2.3.7"}],"e3.example.com":[{"SPF":"v=spf1 include:e2.example.com"},{"A":"1.2.3.8"}],"e4.example.com":[{"SPF":"v=spf1 mx"},{"MX":[0,"mail.example.com"]},{"MX":[1,"mail.example.com"]},{"MX":[2,"mail.example.com"]},{"MX":[3,"mail.example.com"]},{"MX":[4,"mail.example.com"]},{"MX":[5,"mail.example.com"]},{"MX":[6,"mail.example.com"]},{"MX":[7,"mail.example.com"]},{"MX":[8,"mail.example.com"]},{"MX":[9,"mail.example.com"]},{"MX":[10,"e4.example.com"]},{"A":"1.2.3.5"}],"e5.example.com":[{"SPF":"v=spf1 ptr"},{"A":"1.2.3.5"}],"5.3.2.1.in-addr.arpa":[{"PTR":"e1.example.com."},{"PTR":"e2.example.com."},{"PTR":"e3.example.com."},{"PTR":"e4.example.com."},{"PTR":"example.com."},{"PTR":"e6.example.com."},{"PTR":"e7.example.com."},{"PTR":"e8.example.com."},{"PTR":"e9.example.com."},{"PTR":"e10.example.com."},{"PTR":"e5.example.com."}],"e6.example.com":[{"SPF":"v=spf1 a mx a mx a mx a mx a ptr ip4:1.2.3.4 -all"},{"A":"1.2.3.8"},{"MX":[10,"e6.example.com"]}],"e7.example.com":[{"SPF":"v=spf1 a mx a mx a mx a mx a ptr a ip4:1.2.3.4 -all"},{"A":"1.2.3.20"}],"e8.example.com":[{"SPF":"v=spf1 a include:inc.example.com ip4:1.2.3.4 mx -all"},{"A":"1.2.3.4"}],"inc.example.com":[{"SPF":"v=spf1 a a a a a a a a"},{"A":"1.2.3.10"}],"e9.example.com":[{"SPF":"v=spf1 a include:inc.example.com a ip4:1.2.3.4 -all"},{"A":"1.2.3.21"}],"e10.example.com":[{"SPF":"v=spf1 a -all"},{"A":"1.2.3.1"},{"A":"1.2.3.2"},{"A":"1.2.3.3"},{"A":"1.2.3.4"},{"A":"1.2.3.5"},{"A":"1.2.3.6"},{"A":"1.2.3.7"},{"A":"1.2.3.8"},{"A":"1.2.3.9"},{"A":"1.2.3.10"},{"A":"1.2.3.11"},{"A":"1.2.3.12"}],"e11.example.com":[{"TXT":"v=spf1 a:err.example.com a:err1.example.com a:err2.example.com ?all"}],"e12.example.com":[{"TXT":"v=spf1 a:err.example.com a:err1.example.com ?all"}]}, failOnNoFake: true, helo: "mail.example.com"}
        let promise = spf.check_host('1.2.3.4', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'PASS');
        });
      });
      it('mech-over-limit', function(){
        let email = 'foo@e7.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 ip4:1.1.1.1 redirect=e1.example.com"},{"A":"1.2.3.6"}],"e2.example.com":[{"SPF":"v=spf1 include:e3.example.com"},{"A":"1.2.3.7"}],"e3.example.com":[{"SPF":"v=spf1 include:e2.example.com"},{"A":"1.2.3.8"}],"e4.example.com":[{"SPF":"v=spf1 mx"},{"MX":[0,"mail.example.com"]},{"MX":[1,"mail.example.com"]},{"MX":[2,"mail.example.com"]},{"MX":[3,"mail.example.com"]},{"MX":[4,"mail.example.com"]},{"MX":[5,"mail.example.com"]},{"MX":[6,"mail.example.com"]},{"MX":[7,"mail.example.com"]},{"MX":[8,"mail.example.com"]},{"MX":[9,"mail.example.com"]},{"MX":[10,"e4.example.com"]},{"A":"1.2.3.5"}],"e5.example.com":[{"SPF":"v=spf1 ptr"},{"A":"1.2.3.5"}],"5.3.2.1.in-addr.arpa":[{"PTR":"e1.example.com."},{"PTR":"e2.example.com."},{"PTR":"e3.example.com."},{"PTR":"e4.example.com."},{"PTR":"example.com."},{"PTR":"e6.example.com."},{"PTR":"e7.example.com."},{"PTR":"e8.example.com."},{"PTR":"e9.example.com."},{"PTR":"e10.example.com."},{"PTR":"e5.example.com."}],"e6.example.com":[{"SPF":"v=spf1 a mx a mx a mx a mx a ptr ip4:1.2.3.4 -all"},{"A":"1.2.3.8"},{"MX":[10,"e6.example.com"]}],"e7.example.com":[{"SPF":"v=spf1 a mx a mx a mx a mx a ptr a ip4:1.2.3.4 -all"},{"A":"1.2.3.20"}],"e8.example.com":[{"SPF":"v=spf1 a include:inc.example.com ip4:1.2.3.4 mx -all"},{"A":"1.2.3.4"}],"inc.example.com":[{"SPF":"v=spf1 a a a a a a a a"},{"A":"1.2.3.10"}],"e9.example.com":[{"SPF":"v=spf1 a include:inc.example.com a ip4:1.2.3.4 -all"},{"A":"1.2.3.21"}],"e10.example.com":[{"SPF":"v=spf1 a -all"},{"A":"1.2.3.1"},{"A":"1.2.3.2"},{"A":"1.2.3.3"},{"A":"1.2.3.4"},{"A":"1.2.3.5"},{"A":"1.2.3.6"},{"A":"1.2.3.7"},{"A":"1.2.3.8"},{"A":"1.2.3.9"},{"A":"1.2.3.10"},{"A":"1.2.3.11"},{"A":"1.2.3.12"}],"e11.example.com":[{"TXT":"v=spf1 a:err.example.com a:err1.example.com a:err2.example.com ?all"}],"e12.example.com":[{"TXT":"v=spf1 a:err.example.com a:err1.example.com ?all"}]}, failOnNoFake: true, helo: "mail.example.com"}
        let promise = spf.check_host('1.2.3.4', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'PERMERROR');
        });
      });
      it('include-at-limit', function(){
        let email = 'foo@e8.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 ip4:1.1.1.1 redirect=e1.example.com"},{"A":"1.2.3.6"}],"e2.example.com":[{"SPF":"v=spf1 include:e3.example.com"},{"A":"1.2.3.7"}],"e3.example.com":[{"SPF":"v=spf1 include:e2.example.com"},{"A":"1.2.3.8"}],"e4.example.com":[{"SPF":"v=spf1 mx"},{"MX":[0,"mail.example.com"]},{"MX":[1,"mail.example.com"]},{"MX":[2,"mail.example.com"]},{"MX":[3,"mail.example.com"]},{"MX":[4,"mail.example.com"]},{"MX":[5,"mail.example.com"]},{"MX":[6,"mail.example.com"]},{"MX":[7,"mail.example.com"]},{"MX":[8,"mail.example.com"]},{"MX":[9,"mail.example.com"]},{"MX":[10,"e4.example.com"]},{"A":"1.2.3.5"}],"e5.example.com":[{"SPF":"v=spf1 ptr"},{"A":"1.2.3.5"}],"5.3.2.1.in-addr.arpa":[{"PTR":"e1.example.com."},{"PTR":"e2.example.com."},{"PTR":"e3.example.com."},{"PTR":"e4.example.com."},{"PTR":"example.com."},{"PTR":"e6.example.com."},{"PTR":"e7.example.com."},{"PTR":"e8.example.com."},{"PTR":"e9.example.com."},{"PTR":"e10.example.com."},{"PTR":"e5.example.com."}],"e6.example.com":[{"SPF":"v=spf1 a mx a mx a mx a mx a ptr ip4:1.2.3.4 -all"},{"A":"1.2.3.8"},{"MX":[10,"e6.example.com"]}],"e7.example.com":[{"SPF":"v=spf1 a mx a mx a mx a mx a ptr a ip4:1.2.3.4 -all"},{"A":"1.2.3.20"}],"e8.example.com":[{"SPF":"v=spf1 a include:inc.example.com ip4:1.2.3.4 mx -all"},{"A":"1.2.3.4"}],"inc.example.com":[{"SPF":"v=spf1 a a a a a a a a"},{"A":"1.2.3.10"}],"e9.example.com":[{"SPF":"v=spf1 a include:inc.example.com a ip4:1.2.3.4 -all"},{"A":"1.2.3.21"}],"e10.example.com":[{"SPF":"v=spf1 a -all"},{"A":"1.2.3.1"},{"A":"1.2.3.2"},{"A":"1.2.3.3"},{"A":"1.2.3.4"},{"A":"1.2.3.5"},{"A":"1.2.3.6"},{"A":"1.2.3.7"},{"A":"1.2.3.8"},{"A":"1.2.3.9"},{"A":"1.2.3.10"},{"A":"1.2.3.11"},{"A":"1.2.3.12"}],"e11.example.com":[{"TXT":"v=spf1 a:err.example.com a:err1.example.com a:err2.example.com ?all"}],"e12.example.com":[{"TXT":"v=spf1 a:err.example.com a:err1.example.com ?all"}]}, failOnNoFake: true, helo: "mail.example.com"}
        let promise = spf.check_host('1.2.3.4', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'PASS');
        });
      });
      it('include-over-limit', function(){
        let email = 'foo@e9.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 ip4:1.1.1.1 redirect=e1.example.com"},{"A":"1.2.3.6"}],"e2.example.com":[{"SPF":"v=spf1 include:e3.example.com"},{"A":"1.2.3.7"}],"e3.example.com":[{"SPF":"v=spf1 include:e2.example.com"},{"A":"1.2.3.8"}],"e4.example.com":[{"SPF":"v=spf1 mx"},{"MX":[0,"mail.example.com"]},{"MX":[1,"mail.example.com"]},{"MX":[2,"mail.example.com"]},{"MX":[3,"mail.example.com"]},{"MX":[4,"mail.example.com"]},{"MX":[5,"mail.example.com"]},{"MX":[6,"mail.example.com"]},{"MX":[7,"mail.example.com"]},{"MX":[8,"mail.example.com"]},{"MX":[9,"mail.example.com"]},{"MX":[10,"e4.example.com"]},{"A":"1.2.3.5"}],"e5.example.com":[{"SPF":"v=spf1 ptr"},{"A":"1.2.3.5"}],"5.3.2.1.in-addr.arpa":[{"PTR":"e1.example.com."},{"PTR":"e2.example.com."},{"PTR":"e3.example.com."},{"PTR":"e4.example.com."},{"PTR":"example.com."},{"PTR":"e6.example.com."},{"PTR":"e7.example.com."},{"PTR":"e8.example.com."},{"PTR":"e9.example.com."},{"PTR":"e10.example.com."},{"PTR":"e5.example.com."}],"e6.example.com":[{"SPF":"v=spf1 a mx a mx a mx a mx a ptr ip4:1.2.3.4 -all"},{"A":"1.2.3.8"},{"MX":[10,"e6.example.com"]}],"e7.example.com":[{"SPF":"v=spf1 a mx a mx a mx a mx a ptr a ip4:1.2.3.4 -all"},{"A":"1.2.3.20"}],"e8.example.com":[{"SPF":"v=spf1 a include:inc.example.com ip4:1.2.3.4 mx -all"},{"A":"1.2.3.4"}],"inc.example.com":[{"SPF":"v=spf1 a a a a a a a a"},{"A":"1.2.3.10"}],"e9.example.com":[{"SPF":"v=spf1 a include:inc.example.com a ip4:1.2.3.4 -all"},{"A":"1.2.3.21"}],"e10.example.com":[{"SPF":"v=spf1 a -all"},{"A":"1.2.3.1"},{"A":"1.2.3.2"},{"A":"1.2.3.3"},{"A":"1.2.3.4"},{"A":"1.2.3.5"},{"A":"1.2.3.6"},{"A":"1.2.3.7"},{"A":"1.2.3.8"},{"A":"1.2.3.9"},{"A":"1.2.3.10"},{"A":"1.2.3.11"},{"A":"1.2.3.12"}],"e11.example.com":[{"TXT":"v=spf1 a:err.example.com a:err1.example.com a:err2.example.com ?all"}],"e12.example.com":[{"TXT":"v=spf1 a:err.example.com a:err1.example.com ?all"}]}, failOnNoFake: true, helo: "mail.example.com"}
        let promise = spf.check_host('1.2.3.4', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'PERMERROR');
        });
      });
      it('void-at-limit', function(){
        let email = 'foo@e12.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 ip4:1.1.1.1 redirect=e1.example.com"},{"A":"1.2.3.6"}],"e2.example.com":[{"SPF":"v=spf1 include:e3.example.com"},{"A":"1.2.3.7"}],"e3.example.com":[{"SPF":"v=spf1 include:e2.example.com"},{"A":"1.2.3.8"}],"e4.example.com":[{"SPF":"v=spf1 mx"},{"MX":[0,"mail.example.com"]},{"MX":[1,"mail.example.com"]},{"MX":[2,"mail.example.com"]},{"MX":[3,"mail.example.com"]},{"MX":[4,"mail.example.com"]},{"MX":[5,"mail.example.com"]},{"MX":[6,"mail.example.com"]},{"MX":[7,"mail.example.com"]},{"MX":[8,"mail.example.com"]},{"MX":[9,"mail.example.com"]},{"MX":[10,"e4.example.com"]},{"A":"1.2.3.5"}],"e5.example.com":[{"SPF":"v=spf1 ptr"},{"A":"1.2.3.5"}],"5.3.2.1.in-addr.arpa":[{"PTR":"e1.example.com."},{"PTR":"e2.example.com."},{"PTR":"e3.example.com."},{"PTR":"e4.example.com."},{"PTR":"example.com."},{"PTR":"e6.example.com."},{"PTR":"e7.example.com."},{"PTR":"e8.example.com."},{"PTR":"e9.example.com."},{"PTR":"e10.example.com."},{"PTR":"e5.example.com."}],"e6.example.com":[{"SPF":"v=spf1 a mx a mx a mx a mx a ptr ip4:1.2.3.4 -all"},{"A":"1.2.3.8"},{"MX":[10,"e6.example.com"]}],"e7.example.com":[{"SPF":"v=spf1 a mx a mx a mx a mx a ptr a ip4:1.2.3.4 -all"},{"A":"1.2.3.20"}],"e8.example.com":[{"SPF":"v=spf1 a include:inc.example.com ip4:1.2.3.4 mx -all"},{"A":"1.2.3.4"}],"inc.example.com":[{"SPF":"v=spf1 a a a a a a a a"},{"A":"1.2.3.10"}],"e9.example.com":[{"SPF":"v=spf1 a include:inc.example.com a ip4:1.2.3.4 -all"},{"A":"1.2.3.21"}],"e10.example.com":[{"SPF":"v=spf1 a -all"},{"A":"1.2.3.1"},{"A":"1.2.3.2"},{"A":"1.2.3.3"},{"A":"1.2.3.4"},{"A":"1.2.3.5"},{"A":"1.2.3.6"},{"A":"1.2.3.7"},{"A":"1.2.3.8"},{"A":"1.2.3.9"},{"A":"1.2.3.10"},{"A":"1.2.3.11"},{"A":"1.2.3.12"}],"e11.example.com":[{"TXT":"v=spf1 a:err.example.com a:err1.example.com a:err2.example.com ?all"}],"e12.example.com":[{"TXT":"v=spf1 a:err.example.com a:err1.example.com ?all"}]}, failOnNoFake: true, helo: "mail.example.com"}
        let promise = spf.check_host('1.2.3.4', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'NEUTRAL');
        });
      });
      it('void-over-limit', function(){
        let email = 'foo@e11.example.com';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"mail.example.com":[{"A":"1.2.3.4"}],"e1.example.com":[{"SPF":"v=spf1 ip4:1.1.1.1 redirect=e1.example.com"},{"A":"1.2.3.6"}],"e2.example.com":[{"SPF":"v=spf1 include:e3.example.com"},{"A":"1.2.3.7"}],"e3.example.com":[{"SPF":"v=spf1 include:e2.example.com"},{"A":"1.2.3.8"}],"e4.example.com":[{"SPF":"v=spf1 mx"},{"MX":[0,"mail.example.com"]},{"MX":[1,"mail.example.com"]},{"MX":[2,"mail.example.com"]},{"MX":[3,"mail.example.com"]},{"MX":[4,"mail.example.com"]},{"MX":[5,"mail.example.com"]},{"MX":[6,"mail.example.com"]},{"MX":[7,"mail.example.com"]},{"MX":[8,"mail.example.com"]},{"MX":[9,"mail.example.com"]},{"MX":[10,"e4.example.com"]},{"A":"1.2.3.5"}],"e5.example.com":[{"SPF":"v=spf1 ptr"},{"A":"1.2.3.5"}],"5.3.2.1.in-addr.arpa":[{"PTR":"e1.example.com."},{"PTR":"e2.example.com."},{"PTR":"e3.example.com."},{"PTR":"e4.example.com."},{"PTR":"example.com."},{"PTR":"e6.example.com."},{"PTR":"e7.example.com."},{"PTR":"e8.example.com."},{"PTR":"e9.example.com."},{"PTR":"e10.example.com."},{"PTR":"e5.example.com."}],"e6.example.com":[{"SPF":"v=spf1 a mx a mx a mx a mx a ptr ip4:1.2.3.4 -all"},{"A":"1.2.3.8"},{"MX":[10,"e6.example.com"]}],"e7.example.com":[{"SPF":"v=spf1 a mx a mx a mx a mx a ptr a ip4:1.2.3.4 -all"},{"A":"1.2.3.20"}],"e8.example.com":[{"SPF":"v=spf1 a include:inc.example.com ip4:1.2.3.4 mx -all"},{"A":"1.2.3.4"}],"inc.example.com":[{"SPF":"v=spf1 a a a a a a a a"},{"A":"1.2.3.10"}],"e9.example.com":[{"SPF":"v=spf1 a include:inc.example.com a ip4:1.2.3.4 -all"},{"A":"1.2.3.21"}],"e10.example.com":[{"SPF":"v=spf1 a -all"},{"A":"1.2.3.1"},{"A":"1.2.3.2"},{"A":"1.2.3.3"},{"A":"1.2.3.4"},{"A":"1.2.3.5"},{"A":"1.2.3.6"},{"A":"1.2.3.7"},{"A":"1.2.3.8"},{"A":"1.2.3.9"},{"A":"1.2.3.10"},{"A":"1.2.3.11"},{"A":"1.2.3.12"}],"e11.example.com":[{"TXT":"v=spf1 a:err.example.com a:err1.example.com a:err2.example.com ?all"}],"e12.example.com":[{"TXT":"v=spf1 a:err.example.com a:err1.example.com ?all"}]}, failOnNoFake: true, helo: "mail.example.com"}
        let promise = spf.check_host('1.2.3.4', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'PERMERROR');
        });
      });
    });
    describe('Test cases from implementation bugs', function(){
      it('bytes-bug', function(){
        let email = 'test@example.org';
        let emailSplit = email.split('@');
        if(emailSplit.length < 2) {
          return Promise.resolve();
        }
        let opts = {fakeDNSData: {"example.org":[{"SPF":"v=spf1 mx redirect=_spf.example.com"},{"MX":[10,"smtp.example.org"]},{"MX":[10,"smtp1.example.com"]}],"smtp.example.org":[{"A":"198.51.100.2"},{"AAAA":"2001:db8:ff0:100::3"}],"smtp1.example.com":[{"A":"192.0.2.26"},{"AAAA":"2001:db8:ff0:200::2"}],"2.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.1.0.0.F.F.0.8.B.D.0.1.0.0.2.ip6.arpa":[{"PTR":"smtp6-v.fe.example.org"}],"smtp6-v.fe.example.org":[{"AAAA":"2001:db8:ff0:100::2"}],"_spf.example.com":[{"SPF":"v=spf1 ptr:fe.example.org ptr:sgp.example.com exp=_expspf.example.org -all"}],"_expspf.example.org":[{"TXT":"Sender domain not allowed from this host. Please see http://www.openspf.org/Why?s=mfrom&id=%{S}&ip=%{C}&r=%{R}"}]}, failOnNoFake: true, helo: "example.org"}
        let promise = spf.check_host('2001:db8:ff0:100::2', emailSplit[1], email, opts);
        return promise.then((result) => {
          assert.equal(result, 'PASS');
        });
      });
    });
  });
});
