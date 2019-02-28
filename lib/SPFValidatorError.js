'use strict';

module.exports = function SPFValidatorError(message, resolveAs) {
  Error.captureStackTrace(this, this.constructor);
  this.name = this.constructor.name;
  this.message = message;
  this.resolveAs = resolveAs;
};

require('util').inherits(module.exports, Error);
