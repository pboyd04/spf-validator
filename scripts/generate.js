var request = require('request');
var yaml = require('js-yaml');

let testFile = "var spf = require('../index');\nvar assert = require('chai').assert;\n\n";
testFile+= "describe('OpenSPF', function(){\n";

function addTestSuite(suiteName, url) {
  return new Promise((resolve, reject) => {
    request(url, function(err, resp, body) {
      let doc = "  describe('"+suiteName+"', function(){\n";
      if(err) {
        reject(err);
        return;
      }
      let docs = yaml.safeLoadAll(body);
      for(let i = 0; i < docs.length; i++) {
        doc+= "    describe('"+docs[i].description+"', function(){\n";
        for(let testName in docs[i].tests) {
          let test = docs[i].tests[testName];
          testName = testName.replace(/'/g, '"');
          testName = testName.replace(/\n/g, ' ');
          doc+= "      it('"+testName.trim()+"', function(){\n";
          doc+= "        let email = '"+test.mailfrom+"';\n";
          doc+= "        let emailSplit = email.split('@');\n";
          doc+= "        if(emailSplit.length < 2) {\n";
          doc+= "          return Promise.resolve();\n";
          doc+= "        }\n";
          doc+= "        let opts = {fakeDNSData: "+JSON.stringify(docs[i].zonedata)+", failOnNoFake: true, helo: \""+test.helo+"\"}\n";
          doc+= "        let promise = spf.check_host('"+test.host+"', emailSplit[1], email, opts);\n";
          doc+= "        return promise.then((result) => {\n";
          if(Array.isArray(test.result)) {
            doc+= "          assert.include("+JSON.stringify(test.result)+", result.toLowerCase());\n";
          }
          else {
            doc+= "          assert.equal(result, '"+test.result.toUpperCase()+"');\n";
          }
          doc+= "        });\n";
          doc+= "      });\n";
        }
        doc+= "    });\n";
      }
      doc += "  });\n";
      resolve(doc);
    });
  });
}

let suite1Promise = addTestSuite('RFC4408', 'http://www.openspf.org/svn/project/test-suite/rfc4408-tests.yml');
let suite2Promise = addTestSuite('RFC7208', 'http://www.openspf.org/svn/project/test-suite/rfc7208-tests.yml');

Promise.all([suite1Promise, suite2Promise]).then(values => {
  for(let i = 0; i < values.length; i++) {
    testFile+=values[i];
  }
  testFile += "});";
  console.log(testFile);
});
/* vim: set tabstop=2 shiftwidth=2 expandtab: */
