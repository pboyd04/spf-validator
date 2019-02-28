'use strict'
const dns = require('dns');
const iputils = require('ip-utils');
const SPFValidatorError = require('./SPFValidatorError');

class DNSResolver {
  constructor(options, dnsCount) {
    this.options = options || {};
    this.dns = dns;
    if(this.options.fakeDNSData !== undefined) {
      this.dns = new FakeDNS(this.options.fakeDNSData, this.options.failOnNoFake);
    }
    this.count = 0;
    if(dnsCount) {
      this.count = dnsCount;
    }
  }

  isRawIP(str) {
    return /\[([0-9]{1,3}\.)([0-9]{1,3}\.)([0-9]{1,3}\.)([0-9]{1,3})\]/.test(str);
  }

  /** 
   * This returns a Promise. It will be rejected on fatal DNS error and resolved
   * null on non-fatal (temp) error.
   */
	getDNSTxt(hostname) {
    this.count++;
    if(this.count === 10) {
      return Promise.reject(new SPFValidatorError('Too many lookups', 'PERMERROR'));
    }
    if(this.isRawIP(hostname)) {
      return Promise.reject(new Error('Hostname '+hostname+' is raw IP!'));
    }
    if(hostname[hostname.length-1] === '.') {
      hostname = hostname.substr(0, hostname.length-1);
    }
    let labels = hostname.split('.');
    for(let i = 0; i < labels.length; i++) {
      if(labels[i].length === 0 || labels[i].length > 63) {
        //DNS Labels must be between 1 and 63
        return Promise.reject(new Error('Label length invalid!'));
      }
    }
    let me = this;
    return new Promise(function(resolve, reject) {
      me.dns.resolveTxt(hostname, function(err, entries) {
        if(err != null) {
          reject(err);
          return;
        }
        resolve(entries);
      });
    });
  }

  getDNSA(hostname, resolveOnly) {
    this.count++;
    if(this.count === 10) {
      return Promise.reject(new SPFValidatorError('Too many lookups', 'PERMERROR'));
    }
    if(this.isRawIP(hostname)) {
      if(resolveOnly) {
        return Promsie.resolve(null);
      }
      else {
        return Promise.reject(new Error('Hostname '+hostname+' is raw IP!'));
      }
    }
    let me = this;
    return new Promise((resolve, reject) => {
      me.dns.resolve4(hostname, false, (err, entries) => {
        if(err != null) {
          if(resolveOnly) {
            resolve(null);
          }
          else {
            reject(err);
          }
          return;
        }
        resolve(entries);
      });
    });
  }

  getDNSAAAA(hostname, resolveOnly) {
    this.count++;
    if(this.count === 10) {
      return Promise.reject(new SPFValidatorError('Too many lookups', 'PERMERROR'));
    }
    if(this.isRawIP(hostname)) {
      if(resolveOnly) {
        return Promsie.resolve(null);
      }
      else {
        return Promise.reject(new Error('Hostname '+hostname+' is raw IP!'));
      }
    }
    let me = this;
    return new Promise((resolve, reject) => {
      me.dns.resolve6(hostname, false, (err, entries) => {
        if(err != null) {
          if(resolveOnly) {
            resolve(null);
          }
          else {
            reject(err);
          }
          return;
        }
        resolve(entries);
      });
    });
  }

  sortMx(a, b) {
    if(a.priority < b.priority) {
      return -1;
    }
    if(a.priority > b.priorit) {
      return 1;
    }
    return 0;
  }

  getDNSMx(hostname) {
    this.count++;
    if(this.count === 10) {
      return Promise.reject(new SPFValidatorError('Too many lookups', 'PERMERROR'));
    }
    if(this.isRawIP(hostname)) {
      return Promise.reject(new Error('Hostname '+hostname+' is raw IP!'));
    }
    let me = this;
    return new Promise((resolve, reject) => {
      me.dns.resolveMx(hostname, (err, entries) => {
        if(err != null) {
          reject(err);
          return;
        }
        let sorted = entries.sort(me.sortMx);
        resolve(sorted);
      });
    });
  }

  getDNSReverse(ip) {
    this.count++;
    if(this.count === 10) {
      return Promise.reject(new SPFValidatorError('Too many lookups', 'PERMERROR'));
    }
    let me = this;
    return new Promise((resolve, reject) => {
      me.dns.reverse(ip, (err, entries) => {
        if(err != null) {
          reject(err);
          return;
        }
        resolve(entries);
      });
    });
  }
}

class FakeDNS {
  constructor(data, failOnError) {
    this.data = data;
    this.failOnError = failOnError || false;
  }

  getDataByHostName(hostname) {
    if(hostname[hostname.length-1] === '.') {
      hostname = hostname.substr(0, hostname.length-1);
    }
    if(this.data[hostname] !== undefined) {
      return this.data[hostname];
    }
    if(this.data[hostname.toLowerCase()] !== undefined) {
      return this.data[hostname.toLowerCase()];
    }
    for(let key in this.data) {
      if(key.toLowerCase() === hostname.toLowerCase()) {
        return this.data[key];
      }
    }
    return undefined;
  }

  resolveTxt(hostname, callback) {
    let hostData = this.getDataByHostName(hostname);
    if(hostData) {
      for(let i = 0; i < hostData.length; i++) {
        let arr = [];
        for(let i = 0; i < hostData.length; i++) {
          if(hostData[i].SPF !== undefined) {
            if(Array.isArray(hostData[i].SPF) === true) {
              hostData[i].SPF = hostData[i].SPF.join('');
            }
            arr.push([hostData[i].SPF]);
          }
        }
        if(arr.length > 0) {
          callback(null, arr);
          return;
        }
        for(let i = 0; i < hostData.length; i++) {
          if(hostData[i].TXT !== undefined) {
            arr.push([hostData[i].TXT]);
          }
        }
        if(arr.length > 0) {
          callback(null, arr);
          return;
        }
        if(hostData[i] === 'TIMEOUT') {
          callback(null, null);
          return;
        }
      }
    }
    if(this.failOnError) {
      callback(new Error('No Fake DNS Data!'), null);
    }
    else {
      dns.resolveTxt(hostname, callback);
    }
  }

  resolve4(hostname, options, callback) {
    let hostData = this.getDataByHostName(hostname);
    if(hostData === undefined) {
      callback(new Error('Unable to locate host '+hostname), null);
    }
    let arr = [];
    for(let i = 0; i < hostData.length; i++) {
      if(hostData[i].A !== undefined) {
        arr.push(hostData[i].A);
      }
    }
    if(arr.length > 0) {
      callback(null, arr);
      return;
    }
    if(this.failOnError) {
      callback(new Error('No Fake DNS Data!'), null);
    }
    else {
      dns.resolve4(hostname, options, callback);
    }
  }

  resolve6(hostname, options, callback) {
    let hostData = this.getDataByHostName(hostname);
    let arr = [];
    for(let i = 0; i < hostData.length; i++) {
      if(hostData[i].AAAA !== undefined) {
        arr.push(hostData[i].AAAA);
      }
    }
    if(arr.length > 0) {
      callback(null, arr);
      return;
    }
    if(this.failOnError) {
      callback(new Error('No Fake DNS Data!'), null);
    }
    else {
      dns.resolve6(hostname, options, callback);
    }
  }

  resolveMx(hostname, callback) {
    let hostData = this.getDataByHostName(hostname);
    let arr = [];
    for(let i = 0; i < hostData.length; i++) {
      if(hostData[i].MX !== undefined) {
        let obj = {priority: hostData[i].MX[0], exchange: hostData[i].MX[1]};
        arr.push(obj);
      }
    }
    if(arr.length > 0) {
      callback(null, arr);
      return;
    }
    if(this.failOnError) {
      callback(new Error('No Fake DNS Data!'), null);
    }
    else {
      dns.resolveMx(hostname, callback);
    }
  }

  getIPHostForReverse(ip) {
    if(iputils.isValidIpv4(ip)) {
      let split = ip.split('.');
      let revIp = split.reverse().join('.');
      return revIp+'.in-addr.arpa';
    }
    else {
      let split = ip.split(':');
      let str = Buffer.alloc(63, '.');
      for(let i = 0; i < 63; i+=2) {
        str.write('0', i);
      }
      let j = 62;
      for(let i = 0; i < split.length; i++) {
        if(split[i].length === 0) {
          let count = split.length - (i+1);
          if(count === 0) {
            break;
          }
          let index = (count - 1)*7 + 6;
          j = index;
          continue;
        }
        let k = 0;
        if(split[i].length > 3) {
          str.write(split[i][k], j);
          k++;
        }
        j-=2;
        if(split[i].length > 2) {
          str.write(split[i][k], j);
          k++;
        }
        j-=2;
        if(split[i].length > 1) {
          str.write(split[i][k], j);
          k++;
        }
        j-=2;
        if(split[i].length >= 1) {
          str.write(split[i][k], j);
          k++;
        }
        j-=2;
      }
      return str.toString('ascii')+'.ip6.arpa';
    }
  }

  reverse(ip, callback) {
    let hostname = this.getIPHostForReverse(ip);
    let hostData = this.getDataByHostName(hostname);
    let arr = [];
    for(let i = 0; i < hostData.length; i++) {
      if(hostData[i].PTR !== undefined) {
        arr.push(hostData[i].PTR);
      }
    }
    if(arr.length > 0) {
      callback(null, arr);
      return;
    }
    if(this.failOnError) {
      callback(new Error('No Fake DNS Data!'), null);
    }
    else {
      dns.reverse(ip, callback);
    }
  }
}

module.exports.DNSResolver = DNSResolver;
/* vim: set tabstop=2 shiftwidth=2 expandtab: */
