'use strict'
const SPFValidatorError = require('./SPFValidatorError');

class SPFMacroParser {
  constructor(macro, isExp, hostip, sender, validator) {
    this.macro = macro;
    this.exp = isExp;
    this.ip = hostip;
    this.sender = sender;
    if(sender === undefined || sender === null) {
      this.sender = 'nobody@nowhere.org';
    }
    this.validator = validator;
    let sp = this.sender.split('@');
    this.local = sp[0];
    if(this.local.length === 0) {
      this.local = 'postmaster';
    }
    this.domain = sp[1];
    this.vstring = 'in-addr';
    if(hostip.includes(':')) {
      this.vstring = 'ip6';
    }
    this.helo = validator.options.helo;
  }

  isMacro() {
    if(this.macro === undefined || !this.macro.includes('%')) {
      return false;
    }
    return true;
  }

  parse() {
    let me = this;
    if(this.macro === undefined) {
      return Promise.reject(new SPFValidatorError('No Macro', 'PERMERROR'));
    }
    if(this.exp && this.macro.match(/%{[crt]}/)) {
      return Promise.reject(new SPFValidatorError('Letters crt not valid in exp', 'PERMERROR'));
    }
    if(this.macro.includes('%')) {
      let split = this.macro.split('%');
      if(split.length > 1) {
        for(let i = 1; i < split.length; i++) {
          if(split[i].length === 0) {
            i++;
            continue;
          }
          if(split[i][0] !== '{' && split[i][0] !== '-' && split[i][0] !== '_') {
            throw new SPFValidatorError('Invalid Macro Chars', 'PERMERROR');
          }
        }
      }
      if(this.macro.match(/%{[^slodipvh]}/i)) {
        throw new SPFValidatorError('Invalid Macro Chars', 'PERMERROR');
      }
      let macro = this.macro;
      macro = macro.replace(/%{s}/g, this.sender);
      macro = macro.replace(/%{S}/g, encodeURIComponent(this.sender));
      let match = macro.match(/%{(l)(\d)?(r)?([+-]+)?}/i);
      while(match) {
        macro = this.replaceLocal(macro, match);
        match = macro.match(/%{(l)(\d)?(r)?([+-]+)?}/i);
      }
      macro = macro.replace(/%{o}/g, this.domain);
      macro = macro.replace(/%{O}/g, encodeURIComponent(this.domain));
      macro = macro.replace(/%{h}/g, this.helo);
      macro = macro.replace(/%{H}/g, encodeURIComponent(this.helo));
      match = macro.match(/%{(d)(\d+)?}/i);
      while(match) {
        macro = this.replaceDomain(macro, match);
        match = macro.match(/%{(d)(\d+)?}/i);
      }
      macro = macro.replace(/%{i}/g, this.ip);
      macro = macro.replace(/%{v}/g, this.vstring);
      if(macro.match(/%{p}/)) {
        this.macro = macro;
        let dnspromise = this.validator.DNS.getDNSReverse(this.ip);
        return new Promise((resolve, reject) => {
          dnspromise.then((hosts) => {
            for(let i = 0; i < hosts.length; i++) {
              if(hosts[i].includes(this.validator.options.domain)) {
                me.macro = me.macro.replace(/%{p}/g, hosts[i]);
                me.macro = me.finisheMacroReplace(me.macro);
                resolve(me.macro);
                return;
              }
            }
          }).catch(reject);
        });
      }
      this.macro = this.finisheMacroReplace(macro);
    }
    return Promise.resolve(this.macro);
  }

  replaceLocal(macro, match) {
    let repString;
    if(match[1] === 'l') {
      repString = this.local;
    }
    else {
      repString = encodeURIComponent(this.local);
    }
    let delim = '.';
    let rev = false;
    if(match[4]) {
      delim = match[4];
      if(delim.length === 2) {
        delim = new RegExp('['+delim+']');
      }
    }
    if(match[3]) {
      rev = true;
    }
    if(match[2]) {
      let split = repString.split(delim);
      let count = match[2]*1;
      if(rev) {
        split = split.reverse();
      } 
      repString = split.splice(-1*count, count).join('.');
    }
    return macro.replace(match[0], repString);
  }

  replaceDomain(macro, match) {
    let repString;
    if(match[1] === 'd') {
      repString = this.validator.options.domain;
    }
    else {
      repString = encodeURIComponent(this.validator.options.domain);
    }
    if(match[2]) {
      let split = repString.split('.');
      let count = match[2]*1;
      repString = split.splice(-1*count, count).join('.');
    }
    return macro.replace(match[0], repString);
  }

  finisheMacroReplace(macro) {
    macro = macro.replace(/%_/g, ' ');
    macro = macro.replace(/%-/g, '%20');
    return macro.replace(/%%/g, '%'); 
  }
}

module.exports = SPFMacroParser;
/* vim: set tabstop=2 shiftwidth=2 expandtab: */
