'use strict'
const dns = require('dns');
const resolver = require('./resolver');
const spfParser = require('spf-parse');
const ipaddr = require('ipaddr.js');
const SPFValidatorError = require('./SPFValidatorError');
const SPFMacroParser = require('./SPFMacroParser');

const NONE = 0;
const NEUTRAL = 1;
const PASS = 2;
const FAIL = 3;
const SOFTFAIL = 4;
const TEMPERROR = 5;
const PERMERROR = 6;

class SPFValidator {
  constructor(options, dns) {
    if(typeof options === 'string' || options instanceof String) {
      options = { 'domain': options };
    }

    this.options = options || {};
    if(dns) {
      this.DNS = dns;
    }
    else {
      this.DNS = new resolver.DNSResolver(options);
    }
    this.txtRecords = this.DNS.getDNSTxt(this.options.domain);
    this.spf = this.getSPF(this.txtRecords);
    this.exp = null;
  }

  validateSender(sender) {
    if(ipaddr.isValid(sender)) {
      return this.check_host(sender, null);
    }
    let me = this;
    let dnsPromise = this.DNS.getDNSA(sender);
    return new Promise(function(resolve, reject) {
      dnsPromise.then(function(addresses) {
        let arr = [];
        for(let i = 0; i < addresses.length; i++) {
          arr.push(me.check_host(addresses[i], null));
        }
        Promise.all(arr).then((values) => {
          if(values.length === 1) {
            resolve(values[0]);
            return;
          }
          //console.log(values);
        }).catch(reject);
      }).catch(function(e) {
        reject(e);
      });
    });
  }

  check_host(hostip, sender) {
    let me = this;
    return new Promise((resolve, reject) => {
      me.spf.then((spf) => {
        me.validate(hostip, sender, spf, resolve, reject);
      }).catch(e => {
        //console.log(e);
        if(e.name === 'SPFValidatorError') {
          resolve(e.resolveAs);
        }
        else {
          resolve(me.resultToString(NONE));
        }
        //reject(e);
      });
    });
  }

  isAscii(str) {
    return /^[\x00-\x7F]*$/.test(str);
  }

  getSPF(txtPromise) {
    let me = this;
    return new Promise((resolve, reject) => {
      txtPromise.then((records) => {
        if(records === null) {
          reject(new SPFValidatorError('No records', 'TEMPERROR'));
          return;
        }
        let record = null;
        for(let i = 0; i < records.length; i++) {
          let recordStr = records[i].join('');
          if(recordStr.toLowerCase().startsWith('v=spf1 ') || recordStr.toLowerCase() === 'v=spf1') {
            if(me.isAscii(recordStr) === false) {
              throw new SPFValidatorError('Non-ASCII SPF', 'PERMERROR');
            }
            else if(recordStr.toLowerCase().includes('ptr: ') || recordStr.toLowerCase().endsWith('ptr:')) {
              throw new SPFValidatorError('Empty PTR domain-spec', 'PERMERROR');
            }
            if(record === null) {
              record = recordStr;
            }
            else {
              reject(new SPFValidatorError('Multiple SPF records!', 'PERMERROR'));
              return;
            }
          }
        }
        if(record !== null) {
          resolve(spfParser(record));
          return;
        }
        if(me.options.isInclude) {
          reject(new SPFValidatorError('No records in include', 'PERMERROR'));
        }
        else {
          reject(new SPFValidatorError('No records', 'NONE'));
        }
      }).catch((e) => {
        if(me.options.isInclude) {
          reject(new SPFValidatorError('No records in include', 'PERMERROR'));
        }
        else {
          reject(e);
        }
      });
    });
  }

  stringToResult(string) {
    switch(string) {
      case 'NONE':
        return NONE;
      case 'NEUTRAL':
        return NEUTRAL;
      case 'PASS':
        return PASS;
      case 'FAIL':
        return FAIL;
      case 'SOFTFAIL':
        return SOFTFAIL;
      case 'TEMPERROR':
        return TEMPERROR;
      case 'PERMERROR':
        return PERMERROR;
    }
  }

  resultToString(result) {
    switch(result) {
      case NONE:
        return "NONE";
      case NEUTRAL:
        return "NEUTRAL";
      case PASS:
        return "PASS";
      case FAIL:
        return "FAIL";
      case SOFTFAIL:
        return "SOFTFAIL";
      case TEMPERROR:
        return "TEMPERROR";
      case PERMERROR:
        return "PERMERROR";
    }
  }

  validate(hostip, sender, spf, pResolve, pReject) {
    let me = this;
    let arr = [];
    if(/^::FFFF:\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(hostip.toUpperCase())) {
      hostip = hostip.substring(7);
    }
    //console.log(spf);
    if(spf.messages !== undefined) {
      for(let i = 0; i < spf.messages.length; i++) {
        if(spf.messages[i].message.startsWith('One or more mechanisms were found after')) {
          //If it's exp after all or all after all, that's fine... otherwise fail...
          for(let j = 0; j < spf.mechanisms.length - 1; j++) {
            if(spf.mechanisms[j].type === 'all') {
              if(spf.mechanisms[j+1].type !== 'exp' && spf.mechanisms[j+1].type !== 'all') {
                pResolve('PERMERROR');
                return;
              }
            }
          }
        }
        else if(spf.messages[i].message.startsWith("Unknown standalone term 'redirect:")) {
          pResolve('PERMERROR');
          return;
        }
        else if(spf.messages[i].message.startsWith("Unknown standalone term 'all")) {
          pResolve('PERMERROR');
          return;
        }
        else if(spf.messages[i].message.startsWith("Unknown standalone term 'a")) {
          pResolve('PERMERROR');
          return;
        }
        else if(spf.messages[i].message.startsWith("Unknown standalone term 'ptr")) {
          pResolve('PERMERROR');
          return;
        }
        else if(spf.messages[i].message.startsWith("Unknown standalone term 'ip4")) {
          pResolve('PERMERROR');
          return;
        }
        else if(spf.messages[i].message.startsWith('Unknown standalone term')) {
          let term = spf.messages[i].message.substring(25);
          term = term.substring(0, term.length-1);
          if(Number.isNaN(term[0]*1) === false || term[0] === '=') {
            pResolve('PERMERROR');
            return;
          }
          let i1 = term.indexOf('/');
          let i2 = term.indexOf('=');
          let i3 = term.indexOf(':');
          //As per the spec you can have macros but they can't be formed like this...
          if(i1 !== -1 && i2 !== -1) {
            if(i1 < i2) {
              pResolve('PERMERROR');
              return;
            }
          }
          if(i3 !== -1 && i2 !== -1) {
            if(i3 < i2) {
              pResolve('PERMERROR');
              return;
            }
          }
        }
        else if(spf.messages[i].message.startsWith("Invalid domain for the \'a\' mechanism")) {
          pResolve('PERMERROR');
          return;
        }
        else if(spf.messages[i].message === "Blank argument for the 'a' mechanism") {
          pResolve('PERMERROR');
          return;
        }
        else if(spf.messages[i].message === "Blank argument for the 'mx' mechanism") {
          pResolve('PERMERROR');
          return;
        }
        else if(spf.messages[i].message === "Blank argument for the 'exists' mechanism") {
          pResolve('PERMERROR');
          return;
        }
        else if(spf.messages[i].message === "Blank argument for the 'exp' mechanism") {
          pResolve('PERMERROR');
          return;
        }
        else if(spf.messages[i].message.includes('may appear only once in an SPF string')) {
          pResolve('PERMERROR');
          return;
        }
      }
    }
    for(let i = 0; i < spf.mechanisms.length; i++) {
      arr.push(this.validateMechanism(hostip, sender, spf.mechanisms[i]));
    }
    Promise.all(arr).then((values) => {
      //console.log(values);
      if(values.length === 1) {
        pResolve(me.resultToString(values[0]));
        return;
      }
      //Look from PERMERROR first...
      for(let i = 0; i < values.length; i++) {
        //Return first non neutral or none value...
        if(values[i] === PERMERROR) {
          pResolve(me.resultToString(values[i]));
          return;
        }
      }
      for(let i = 0; i < values.length; i++) {
        //Return first non neutral or none value...
        if(values[i] !== NONE && values[i] !== NEUTRAL) {
          pResolve(me.resultToString(values[i]));
          return;
        }
      }
      if(me.redirect) {
        let childOpts = me.options;
        childOpts.domain = me.redirect;
        childOpts.isInclude = true;
        let child = new SPFValidator(childOpts, me.DNS);
        let childPromise = child.check_host(hostip, sender);
        childPromise.then(pResolve).catch(pReject);
      }
      else {
        //If there are no non-neutural or non-none values then return NEUTRAL
        pResolve("NEUTRAL");
      }
    }).catch((e) => {
      //console.log(e);
      if(e.name === 'SPFValidatorError') {
        pResolve(e.resolveAs);
      }
      else {
        pReject(e);
      }
    });
  }

  validateMechanism(hostip, sender, mechanism) {
    let me = this;
    switch(mechanism.type) {
      case undefined:
        //This really shouldn't happen in the wild. I'm only handling this to let the OpenSPF tests pass...
        return Promise.resolve(NEUTRAL);
      default:
        throw new Error('Unknown mechanism type '+mechanism.type);
      case 'version':
        return Promise.resolve(NEUTRAL);
      case 'all':
        return this.promiseFromPrefix(mechanism.prefix);
      case 'ip4':
        return this.validateIP4(hostip, sender, mechanism);
      case 'ip6':
        return this.validateIP6(hostip, sender, mechanism);
      case 'a':
        return this.validateA(hostip, sender, mechanism);
      case 'mx':
        return this.validateMx(hostip, sender, mechanism);
      case 'ptr':
        return this.validatePtr(hostip, sender, mechanism);
      case 'exists':
        return this.validateExists(hostip, sender, mechanism);
      case 'include':
        return this.validateInclude(hostip, sender, mechanism);
      case 'exp':
        return this.validateExp(hostip, sender, mechanism);
      case 'redirect':
        try {
          //Save this in case we need it later...
          if(mechanism.value === undefined) {
            return Promise.resolve(PERMERROR);
          }
          else {
            this.exp = null;
            this.redirect = mechanism.value;
            this.redirect = this.redirect.replace(/%{d}/, this.options.domain);
            return Promise.resolve(NEUTRAL);
          }
        }
        catch(e) {
          if(e.name === 'SPFValidatorError') {
            return Promise.resolve(me.stringToResult(e.resolveAs));
          }
          else {
            return Promise.reject(e);
          }
        }
    }
  }

  resultFromPrefix(prefix) {
    let res = FAIL;
    switch(prefix) {
      case '+':
        res = PASS;
        break;
      case '~':
        res = SOFTFAIL;
        break;
      case '?':
        res = NEUTRAL;
        break;
    }
    return res;
  }

  promiseFromPrefix(prefix) {
    return Promise.resolve(this.resultFromPrefix(prefix));
  }

  domainIsValid(domain) {
    const domainRegEx = /[\w\d\.:/-]+/;
    if(/\0/.test(domain)) {
      throw new SPFValidatorError('Has a null character', 'PERMERROR');
    }
    if((domainRegEx.test(domain)) === false) {
      throw new SPFValidatorError('Invalid Domain Name', 'PERMERROR');
    }
    if(domain[domain.length - 1] === '.') {
      domain = domain.substring(0, domain.length - 1);
    }
    let dSplit = domain.split('.');
    if(dSplit.length === 1) {
      throw new SPFValidatorError('Only TLD', 'PERMERROR');
    }
    let tld = dSplit[dSplit.length-1];
    if(/\d+/.test(tld) || tld.includes(':')) { 
      throw new SPFValidatorError('Invalid Domain TLD', 'PERMERROR');
    }
    for(let i = 0; i < dSplit.length; i++) {
      let part = dSplit[i];
      if(part[0] === '-' || part[part.length-1] === '-') {
        throw new SPFValidatorError('Invalid Domain Label', 'PERMERROR');
      }
      if(part.length === 0) {
        throw new SPFValidatorError('Empty Domain Label', 'PERMERROR');
      }
    }
  }

  macroIsValid(macro, isExp, hostip, sender) {
    let parser = new SPFMacroParser(macro, isExp, hostip, sender, this);
    if(!parser.isMacro()) {
      return macro;
    }
    return parser.parse();
  }

  getSubnets(value, hostip, sender, dontValidateMacro) {
    if(value === undefined) {
      return [null, null, null];
    }
    if(value[0] === '/') {
      value = value.substring(1);
      let split = value.split('/');
      let res = [null, null, null];
      if(split.length >= 1) {
        res[1] = parseInt(split[0]);
        if(res[1] > 32) {
          throw new SPFValidatorError('IPv4 can only fix 32 bytes', 'PERMERROR');
        }
      }
      if(split.length === 2) {
        res[2] = parseInt(split[1]);
        if(res[2] > 128) {
          throw new SPFValidatorError('IPv6 can only fix 128 bytes', 'PERMERROR');
        }
      }
      else if(split.length === 3) {
        res[2] = parseInt(split[2]);
        if(res[2] > 128) {
          throw new SPFValidatorError('IPv6 can only fix 128 bytes', 'PERMERROR');
        }
      }
      return res;
    } 
    if(/\/\d{0,3}(\/)?\d/.test(value)) {
      let split = value.split('/'); 
      if(!dontValidateMacro) {
        split[0] = this.macroIsValid(split[0], false, hostip, sender);
      }
      if(split.length === 2) {
        return [split[0], split[1], null];
      }
      //console.log(split);
      return [value, null, null];
    }
    if(!dontValidateMacro) {
      value = this.macroIsValid(value, false, hostip, sender);
    }
    return [value, null, null];
  }

  validateIP4(hostip, sender, mechanism) {
    if(hostip === mechanism.value) {
      return this.promiseFromPrefix(mechanism.prefix);
    }
    if(mechanism.value === undefined) {
      return Promise.resolve(PERMERROR);
    };
    if(mechanism.value.includes('/') === false) {
      return Promise.resolve(NEUTRAL);
    }
    if(/\/0\d/.test(mechanism.value) === true) {
      //This is a pretty dumb case, but the OpenSPF tests say this should fail...
      return Promise.resolve(PERMERROR);
    }
    let addr = ipaddr.parse(hostip);
    try {
      let cidr = ipaddr.parseCIDR(mechanism.value);
      if(addr.match(cidr)) {
        return this.promiseFromPrefix(mechanism.prefix);
      }
    } catch(e) {
      return Promise.resolve(PERMERROR);
    }
    return Promise.resolve(NEUTRAL);
  }

  validateIP6(hostip, sender, mechanism) {
    let addr = ipaddr.parse(hostip); 
    if(/^:[A-Z1-9]/i.test(mechanism.value)) {
      return Promise.resolve(PERMERROR);
    }
    if(hostip === mechanism.value) {
      return this.promiseFromPrefix(mechanism.prefix);
    }
    if(mechanism.value === undefined) {
      return Promise.resolve(PERMERROR);
    };
    if(mechanism.value.includes('/') === false) {
      return Promise.resolve(NEUTRAL);
    } 
    try {
      let cidr = ipaddr.parseCIDR(mechanism.value);
      if(addr.match(cidr)) {
        return this.promiseFromPrefix(mechanism.prefix);
      }
    } catch(e) {
      //There are some really odd CIDRs in the test suite... work around the library parsing for them...
      mechanism.value = mechanism.value.replace(/\./g, ':');
      try {
        let cidr = ipaddr.parseCIDR(mechanism.value);
        if(addr.match(cidr)) {
          return this.promiseFromPrefix(mechanism.prefix);
        }
      } catch(e) {
        if(e.message === 'ipaddr: cannot match ipv4 address with non-ipv4 one') {
          return Promise.resolve(NEUTRAL);
        }
        else {
          return Promise.resolve(PERMERROR);
        }
      }
    }
    return Promise.resolve(NEUTRAL);
  }

  validateADelayed(hostip, sender, mechanism, promise) {
    let me = this;
    return new Promise((resolve, reject) => {
      promise.then((macro) => {
        mechanism.value = macro;
        let child = me.validateA(hostip, sender, mechanism, true);
        child.then(resolve).catch(reject);
      }).catch(reject);
    });
  }

  validateA(hostip, sender, mechanism, dontValidateMacro) {
    let domain = this.options.domain;
    let subnets = this.getSubnets(mechanism.value, hostip, sender, dontValidateMacro);
    let domainValue = subnets.shift();
    if(domainValue !== null) {
      domain = domainValue;
    }
    let me = this;
    let dnsPromise;
    let ipv6 = false;
    let addr;
    try {
      addr = ipaddr.parse(hostip);
    } catch(e) {
      let index = hostip.lastIndexOf(':');
      if(index !== -1) {
        let ipv4 = hostip.substring(index+1);
        let ipv6 = hostip.substring(0, index+1);
        let tmp = ipaddr.parse(ipv4);
        let tmp1 = ipaddr.parse(ipv6);
        let bytes = tmp1.toByteArray();
        bytes.length = 12;
        bytes = bytes.concat(tmp.toByteArray());
        addr = ipaddr.fromByteArray(bytes);
      }
    }
    if(typeof domain !== 'string') {
      return this.validateADelayed(hostip, sender, mechanism, domain);
    }
    try {
      this.domainIsValid(domain);
    } catch(e) {
      if(dontValidateMacro) {
        return Promise.resolve(FAIL);
      }
      else {
        throw e;
      }
    }
    if(addr.kind() === 'ipv6') {
      ipv6 = true;
      dnsPromise = this.DNS.getDNSAAAA(domain);
    }
    else {
      dnsPromise = this.DNS.getDNSA(domain);
    }
    return new Promise((resolve, reject) => {
      dnsPromise.then((records) => {
        if(records.includes(hostip)) {
          resolve(me.resultFromPrefix(mechanism.prefix));
          return;
        }
        for(let i = 0; i < records.length; i++) {
          let net = subnets[0];
          if(ipv6) {
            net = subnets[1];
          }
          if(net === null) {
            resolve(NEUTRAL);
            return;
          }
          let ipText = records[i]+'/'+net;
          let cidr = ipaddr.parseCIDR(ipText);
          if(addr.match(cidr)) {
            resolve(me.resultFromPrefix(mechanism.prefix));
            return;
          }
        }
        resolve(NEUTRAL);
      }).catch((e) => {
        if(e.name === 'SPFValidatorError') {
          resolve(me.stringToResult(e.resolveAs));
        }
        else {
          resolve(NEUTRAL);
        }
      });
    });
  }

  validateMxDelayed(hostip, sender, mechanism, promise) {
    let me = this;
    return new Promise((resolve, reject) => {
      promise.then((macro) => {
        mechanism.value = macro;
        let child = me.validateMx(hostip, sender, mechanism, true);
        child.then(resolve).catch(reject);
      }).catch(reject);
    });
  }

  validateMx(hostip, sender, mechanism, dontValidateMacro) {
    let domain = this.options.domain;
    let subnets = this.getSubnets(mechanism.value, hostip, sender, dontValidateMacro);
    let domainValue = subnets.shift();
    if(domainValue !== null) {
      domain = domainValue;
    }
    let me = this;
    let ipv6 = false;
    let addr = ipaddr.parse(hostip);
    if(addr.kind() === 'ipv6') {
      ipv6 = true;
    }
    if(typeof domain !== 'string') {
      return this.validateMxDelayed(hostip, sender, mechanism, domain);
    }
    this.domainIsValid(domain);
    let dnsPromise = this.DNS.getDNSMx(domain);
    return new Promise((resolve, reject) => {
      dnsPromise.then((records) => {
        let resolved = false;
        for(let i = 0; i < records.length; i++) {
          let mxAPromise;
          if(ipv6) {
            mxAPromise = me.DNS.getDNSAAAA(records[i].exchange);
          }
          else {
            mxAPromise = me.DNS.getDNSA(records[i].exchange);
          }
          mxAPromise.then((ips) => {
            if(ips.includes(hostip)) {
              resolve(me.resultFromPrefix(mechanism.prefix));
              resolved = true;
              return;
            }
            for(let j = 0; j < ips.length; j++) {
              let ipText = ips[j]+'/'+subnets[0];
              if(ipv6) {
                ipText = ips[j]+'/'+subnets[1];
              }
              let cidr = ipaddr.parseCIDR(ipText);
              if(addr.match(cidr)) {
                resolve(me.resultFromPrefix(mechanism.prefix));
                resolved = true;
                return;
              }
            }
            //console.log(ips);
          }).catch((e) => {
            resolve(NEUTRAL);
          });
          if(resolved === true) {
            return;
          }
        }
      }).catch((e) => {
        if(e.name === 'SPFValidatorError') {
          resolve(me.stringToResult(e.resolveAs));
        }
        else {
          resolve(NEUTRAL);
        }
      });
    });
  }

  validatePtr(hostip, sender, mechanism) {
    let domain = mechanism.value || this.options.domain;
    let me = this;
    let ip6 = ipaddr.parse(hostip).kind() === 'ipv6';
    let dnsPromise = this.DNS.getDNSReverse(hostip);
    return new Promise((resolve, reject) => {
      dnsPromise.then((ptrs) => {
        let length = ptrs.length;
        if(length >= 10) {
          length = 10;
        }
        let arr = [];
        let res = [];
        for(let i = 0; i < length; i++) {
          if(ip6) {
            arr.push(this.DNS.getDNSAAAA(ptrs[i], true));
          }
          else {
            arr.push(this.DNS.getDNSA(ptrs[i], true));
          }
          res.push({name: ptrs[i], ips: null, valid: false});
        }
        Promise.all(arr).then((values) => {
          for(let i = 0; i < values.length; i++) {
            res[i].ips = values[i];
            if(values[i] !== null && values[i].includes(hostip)) {
              res[i].valid = true;
            }
          }
          for(let i = 0; i < res.length; i++) {
            if(res[i].valid && res[i].name.toLowerCase().endsWith(domain.toLowerCase())) {
              resolve(me.resultFromPrefix(mechanism.prefix));
              return;
            }
          }
          resolve(NEUTRAL);
        }).catch((e) => {
          resolve(NEUTRAL);
        });
      }).catch((e) => {
        resolve(NEUTRAL);
      });
    });
  }

  validateExistDelayed(hostip, sender, mechanism, promise) {
    let me = this;
    return new Promise((resolve, reject) => {
      promise.then((macro) => {
        mechanism.value = macro;
        let child = me.validateExists(hostip, sender, mechanism, true);
        child.then(resolve).catch(reject);
      }).catch(reject);
    });
  }

  validateExists(hostip, sender, mechanism, dontValidateMacro) {
    if(mechanism.value === undefined) {
      return Promise.resolve(PERMERROR);
    }
    let domain = mechanism.value;
    if(!dontValidateMacro) {
      domain = this.macroIsValid(mechanism.value, false, hostip, sender);
    }
    if(typeof domain !== 'string') {
      return this.validateExistDelayed(hostip, sender, mechanism, domain);
    }
    this.domainIsValid(domain);
    let dnsPromise = this.DNS.getDNSA(domain);
    let me = this;
    return new Promise((resolve, reject) => {
      dnsPromise.then((records) => {
        resolve(me.resultFromPrefix(mechanism.prefix));
      }).catch((e) => {
        resolve(NEUTRAL);
      });
    });
  }

  validateIncludeDelayed(hostip, sender, mechanism, promise) {
    let me = this;
    return new Promise((resolve, reject) => {
      promise.then((macro) => {
        mechanism.value = macro;
        let child = me.validateInclude(hostip, sender, mechanism, true);
        child.then(resolve).catch(reject);
      }).catch(reject);
    });
  }

  validateInclude(hostip, sender, mechanism, dontValidateMacro) {
    if(mechanism.value === undefined) {
      return Promise.resolve(PERMERROR);
    }
    let domain = mechanism.value;
    if(!dontValidateMacro) {
      domain = this.macroIsValid(domain, false, hostip, sender);
    }
    if(typeof domain !== 'string') {
      return this.validateIncludeDelayed(hostip, sender, mechanism, domain);
    }
    this.domainIsValid(domain);
    let opts = this.options;
    opts.isInclude = true;
    opts.domain = domain;
    let child = new SPFValidator(opts, this.DNS);
    let childRes = child.check_host(hostip, sender);
    let me = this;
    return new Promise((resolve, reject) => {
      childRes.then((res) => {
        let intRes = me.stringToResult(res);
        if(intRes < TEMPERROR) {
          let tmp = me.resultFromPrefix(mechanism.prefix);
          if(tmp === intRes) {
            resolve(intRes);
          }
          else {
            resolve(NEUTRAL);
          }
        }
        else {
          resolve(intRes);
        }
      }).catch(reject);
    });
  }

  validateExpDelayed(hostip, sender, mechanism, promise) {
    let me = this;
    return new Promise((resolve, reject) => {
      promise.then((macro) => {
        mechanism.value = macro;
        let child = me.validateExp(hostip, sender, mechanism, true);
        child.then(resolve).catch(reject);
      }).catch(reject);
    });
  }

  validateExp(hostip, sender, mechanism, dontValidateMacro) {
    //Save this in case we need it later...
    if(this.exp !== null) {
      return Promise.resolve(PERMERROR);
    }
    if(mechanism.value === undefined) {
      return Promise.resolve(PERMERROR);
    }
    let exp = mechanism.value;
    if(!dontValidateMacro) {
      exp = this.macroIsValid(mechanism.value, true, hostip, sender);
    }
    if(typeof exp !== 'string') {
      return this.validateExpDelayed(hostip, sender, mechanism, exp);
    }
    this.domainIsValid(exp);
    this.exp = exp;
    return Promise.resolve(NEUTRAL);
  }
}

module.exports.SPFValidator = SPFValidator;
/* vim: set tabstop=2 shiftwidth=2 expandtab: */
