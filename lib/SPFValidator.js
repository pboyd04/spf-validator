'use strict'
const dns = require('dns');
const spfParser = require('spf-parse');
const ip = require('ip-utils');

const FAIL = 0;
const SOFTFAIL = 1;
const NEUTRAL = 2;
const PASS = 3;

class SPFValidator {
  constructor(options) {
    if(typeof options === 'string' || options instanceof String) {
      options = { 'domain': options };
    }

    this.options = options || {};
  }

  getDNSTxt(domain) {
    return new Promise(function(resolve, reject) {
      dns.resolveTxt(domain, function(err, entries) {
        if(err != null) {
          reject(err);
          return;
        }
        resolve(entries);
      });
    });
  }

  getRecords(domain) {
    if(domain === undefined) {
      domain = this.options.domain;
    }
    let dnsPromise = this.getDNSTxt(domain);
    let myInstance = this;
    return new Promise(function(resolve, reject) {
      dnsPromise.then(function(entries){
        for(let i = 0; i < entries.length; i++) {
          let records = spfParser(entries[i].join(' '));
          if(records.valid) {
            let haveIncludes = false;
            for(let j = 0; j < records.mechanisms.length; j++) {
              if(records.mechanisms[j].type === 'include') {
                haveIncludes = true;
                break;
              }
            }
            if(haveIncludes && myInstance.options.expandIncludes) {
              let expandPromise = myInstance.expandIncludes(records);
              expandPromise.then(resolve).catch(reject);
              return;
            }
            else {
              resolve(records);
              return;
            }
          }
        }
        console.log('No records found!');
        resolve(null);
      }).catch(function(e) {
        reject(e);
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

  validateSender(sender) {
    let myInstance = this;
    if(ip.isValidIp(sender) != true) {
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
      recordsPromise.then(function(records){
        let result = NEUTRAL;
        for(let i = 0; i < records.mechanisms.length; i++) {
          let tmp = myInstance.validateMechanism(records.mechanisms[i], sender);
          if(tmp === PASS) {
            result = PASS;
            break;
          }
          if(tmp < result) {
            result = tmp;
          }
        }
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
        }
        resolve(result);
      }).catch(function(e){
        reject(e);
      });
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
        return NEUTRAL;
      case 'all':
        return this.prefixToCode(mechanism.prefixdesc);
      case 'include':
        return this.validateInclude(mechanism, sender);
      case 'ip4':
      case 'ip6':
        return this.validateIp(mechanism, sender);
      default:
        console.log(mechanism);
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
      if(tmp === PASS) {
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
    if(subnet.contains(sender)) {
      return this.prefixToCode(mechanism.prefixdesc);
    }
    return NEUTRAL;
  }
}

module.exports.SPFValidator = SPFValidator;
/* vim: set tabstop=2 shiftwidth=2 expandtab: */
