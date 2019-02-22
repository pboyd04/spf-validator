'use strict'
const dns = require('dns');

class DNSResolver {
  constructor(options) {
    this.options = options || {};
  }

  isRawIP(str) {
    return /\[([0-9]{1,3}\.)([0-9]{1,3}\.)([0-9]{1,3}\.)([0-9]{1,3})\]/.test(str);
  }

  /** 
   * This returns a Promise. It will be rejected on fatal DNS error and resolved
   * null on non-fatal (temp) error.
   */
	getDNSTxt(hostname) {
    if(this.isRawIP(hostname)) {
      return Promise.reject(new Error('Hostname '+hostname+' is raw IP!'));
    }
    let labels = hostname.split('.');
    for(let i = 0; i < labels.length; i++) {
      if(labels[i].length === 0 || labels[i].length > 63) {
        //DNS Labels must be between 1 and 63
        return Promise.reject(new Error('Label length invalid!'));
      }
    }
    if(this.options.fakeDNSData !== undefined) {
      //Use fake data to override real DNS lookup...
      if(this.options.fakeDNSData[hostname] === undefined) {
        if(this.options.fakeDNSData[hostname.toLowerCase()] !== undefined) {
          hostname = hostname.toLowerCase();
        }
      }
      if(this.options.fakeDNSData[hostname] !== undefined) {
        let dnsData = this.options.fakeDNSData[hostname];
        let arr = [];
        for(let i = 0; i < dnsData.length; i++) {
          if(dnsData[i].SPF !== undefined) {
            if(Array.isArray(dnsData[i].SPF) === true) {
              dnsData[i].SPF = dnsData[i].SPF.join('');
            }
            arr.push(dnsData[i].SPF.split(' '));
          }
        }
        if(arr.length > 0) {
          return Promise.resolve(arr);
        }
        for(let i = 0; i < dnsData.length; i++) {
          if(dnsData[i].TXT !== undefined) {
            arr.push(dnsData[i].TXT.split(' '));
          }
        }
        if(arr.length > 0) {
          return Promise.resolve(arr);
        }
        for(let i = 0; i < dnsData.length; i++) {
          console.log(dnsData[i]);
          if(dnsData[i] === 'TIMEOUT') {
            return Promise.resolve(null);
          }
        }
      }
      if(this.options.failOnNoFake) {
        return Promise.resolve(null);
      }
    }
    return new Promise(function(resolve, reject) {
      dns.resolveTxt(hostname, function(err, entries) {
        if(err != null) {
          reject(err);
          return;
        }
        resolve(entries);
      });
    });
  }
}

module.exports.DNSResolver = DNSResolver;
/* vim: set tabstop=2 shiftwidth=2 expandtab: */
