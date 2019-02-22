'use strict'
const dns = require('dns');
const resolver = require('./resolver');
const spfParser = require('spf-parse');
const ip = require('ip-utils');

const FAIL = 0;
const SOFTFAIL = 1;
const NEUTRAL = 2;
const PASS = 3;
const TEMPERROR = 4;
const PERMERROR = 5;
const NONE = 6;

class SPFValidator {
  constructor(options) {
    if(typeof options === 'string' || options instanceof String) {
      options = { 'domain': options };
    }

    this.options = options || {};
    this.DNS = new resolver.DNSResolver(options);
  }

  haveIncludes(records) {
    for(let j = 0; j < records.mechanisms.length; j++) {
      if(records.mechanisms[j].type === 'include') {
        return true;
      }
    }
    return false;
  }

  isAscii(str) {
    return /^[\x00-\x7F]*$/.test(str);
  }

  getRecords(domain) {
    domain = domain || this.options.domain;
    let dnsPromise = this.DNS.getDNSTxt(domain);
    let myInstance = this;
    return new Promise((resolve, reject) => {
      dnsPromise.then(function(entries) {
        if(entries === null) {
          resolve(this.intRetToString(TEMPERROR));
          return;
        }
        let arr = [];
        for(let i = 0; i < entries.length; i++) {
          let string = entries[i].join(' ');
          if(myInstance.isAscii(string) === false) {
            arr.push(Promise.resolve(myInstance.intRetToString(PERMERROR)));
          }
          let records = spfParser(string);
          if(records.valid) {
            let haveIncludes = myInstance.haveIncludes(records);
            if(haveIncludes && myInstance.options.expandIncludes) {
              let expandPromise = myInstance.expandIncludes(records);
              arr.push(expandPromise);
            }
            else {
              arr.push(Promise.resolve(records));
            }
          }
        }
        Promise.all(arr).then((values) => {
          if(values.length === 1) {
            resolve(values[0]);
          }
          else {
            console.log(values);
            resolve(values[0]);
          }
        }).catch(reject);
      }).catch(function(e) {
        reject(NONE);
      });
    });
  }

  expandInclude(mechanisms, i) {
    let recordPromise = this.getRecords(mechanisms[i].value);
    return new Promise(function(resolve, reject){
      recordPromise.then(function(records){
        mechanisms[i].expanded = records;
        resolve(null);
      }).catch(function(e){
        reject(e);
      });
    });
  }

  expandIncludes(records) {
    let dnsPromises = [];
    for(let i = 0; i < records.mechanisms.length; i++) {
      if(records.mechanisms[i].type === 'include') {
        dnsPromises.push(this.expandInclude(records.mechanisms, i));
      }
    }
    let metaPromise = Promise.all(dnsPromises);
    return new Promise(function(resolve, reject) {
      metaPromise.then(function() {
        resolve(records);
      }).catch(function(e) {
        reject(e);
      });
    });
  }

  getIPForHostname(hostname) {
    if(this.options.fakeDNSData !== undefined) {
      if(this.options.fakeDNSData[hostname] !== undefined)
      {
        let dnsData = this.options.fakeDNSData[hostname];
        console.log(dnsData);
        return Promise.reject();
      }
    }
    return new Promise(function(resolve, reject) {
      dns.resolve4(hostname, function(err, addresses) {
        if(err != null) {
          dns.resolve6(hostname, function(err, addresses) {
            if(err != null) {
              reject(err);
            }
            else {
              resolve(addresses[0]);
            }
          });
        }
        else {
          resolve(addresses[0]);
        }
      });
    });
  }

  intRetToString(result) {
    switch(result) {
      default:
      case FAIL:
        result = 'FAIL';
        break;
      case SOFTFAIL:
        result = 'SOFTFAIL';
        break;
      case NEUTRAL:
        result = 'NEUTRAL';
        break;
      case PASS:
        result = 'PASS';
        break;
      case SOFTFAIL:
        result = 'SOFTFAIL';
        break;
      case TEMPERROR:
        result = 'TEMPERROR';
        break;
      case PERMERROR:
        result = 'PERMERROR';
        break;
      case NONE:
        result = 'NONE';
        break;
    }
    return result;
  }

  validateSender(sender) {
    let myInstance = this;
    if(ip.isValidIp(sender) !== true) {
      return new Promise(function(resolve, reject) {
        let dnsPromise = myInstance.getIPForHostname(sender);
        dnsPromise.then(function(address) {
          let childPromise = myInstance.validateSender(address);
          childPromise.then(resolve).catch(reject);
        }).catch(function(e) {
          reject(e);
        });
      });
    }
    let recordsPromise = this.getRecords();
    return new Promise(function(resolve, reject) {
      recordsPromise.then(function(records) {
        if(typeof records === 'number') {
          resolve(records);
        }
        let validatePromise = myInstance.validateSenderFromRecord(sender, records);
        validatePromise.then(resolve).catch(reject);
      }).catch(function(e){
        if(typeof e === 'number') {
          resolve(myInstance.intRetToString(e));
        }
        else {
          resolve('NONE');
        }
      });
    });
  }

  validateSenderFromRecord(sender, records) {
     let myInstance = this;
     return new Promise(function(resolve, reject) {
       if(records === null || records === undefined) {
         resolve('NONE');
         return;
       }
       if(records.mechanisms === undefined) {
         resolve('PERMERROR');
         return;
       }
       let result = NEUTRAL;
       for(let i = 0; i < records.mechanisms.length; i++) {
         let tmp = myInstance.validateMechanism(records.mechanisms[i], sender);
         if(tmp === NONE) {
           resolve(myInstance.intRetToString(NONE));
           return;
         }
         else if(tmp === PASS) {
           resolve(myInstance.intRetToString(PASS));
           return;
         }
         if(tmp < result) {
           result = tmp;
         }
       }
       resolve(myInstance.intRetToString(result));
     });
  }

  validateSenderFromText(sender, spfTxt) {
    let myInstance = this;
    let records = spfParser(spfTxt);
    return new Promise(function(resolve, reject) {
      if(records.valid === false) {
        reject(new Error('Provided record not valid!'));
      }
      else {
        let validatePromise = myInstance.validateSenderFromRecord(sender, records);
        validatePromise.then(resolve).catch(reject);
      }
    });
  }

  prefixToCode(prefix) {
    switch(prefix) {
      case 'Pass':
        return PASS;
      case 'Fail':
        return FAIL;
      case 'SoftFail':
        return SOFTFAIL;
      default:
      case 'Neutral':
        return NEUTRAL;
    }
  }

  validateMechanism(mechanism, sender) {
    switch(mechanism.type) {
      case 'version':
        if(mechanism.value === 'spf1') {
          return NEUTRAL;
        }
        else {
          return NONE;
        }
      case 'all':
        return this.prefixToCode(mechanism.prefixdesc);
      case 'include':
        return this.validateInclude(mechanism, sender);
      case 'ip4':
      case 'ip6':
        return this.validateIp(mechanism, sender);
      default:
        //console.log(mechanism);
        return NEUTRAL;
    }
  }

  validateInclude(mechanism, sender) {
    if(mechanism.expanded === undefined) {
      return SOFTFAIL;
    }
    let res = NEUTRAL;
    for(let i = 0; i < mechanism.expanded.mechanisms.length; i++) {
      let tmp = this.validateMechanism(mechanism.expanded.mechanisms[i], sender);
      if(tmp === NONE) {
        return NONE;
      }
      else if(tmp === PASS) {
        return this.prefixToCode(mechanism.prefixdesc);
      }
      else if(tmp < res) {
        res = tmp;
      }
    }
    return NEUTRAL;
  }

  validateIp(mechanism, sender) {
    let subnet = ip.subnet(mechanism.value);
    if(subnet.sub === undefined) {
      return PERMERROR;
    }
    try{
    if(subnet.contains(sender)) {
      return this.prefixToCode(mechanism.prefixdesc);
    }
    } catch(e) {
      console.log(subnet);
      console.log(sender);
      console.log(mechanism);
      console.log(e);
    }
    return NEUTRAL;
  }
}

module.exports.SPFValidator = SPFValidator;
/* vim: set tabstop=2 shiftwidth=2 expandtab: */
