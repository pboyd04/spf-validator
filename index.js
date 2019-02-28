module.exports.version = require('./package.json').version;
module.exports.SPFValidator = require('./lib/SPFValidator').SPFValidator;

module.exports.check_host = function(ip, domain, sender, _options) {
  let opts = _options || {};
  opts.domain = domain;
  let validator = new module.exports.SPFValidator(opts);
  return validator.check_host(ip, sender);
};
/* vim: set tabstop=2 shiftwidth=2 expandtab: */
