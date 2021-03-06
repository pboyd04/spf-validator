# spf-validator

[![Build Status](https://travis-ci.org/pboyd04/spf-validator.svg?branch=master)](https://travis-ci.org/pboyd04/spf-validator)
[![Dependency Status](https://david-dm.org/pboyd04/spf-validator.svg)](https://david-dm.org/pboyd04/spf-validator)
[![Maintainability](https://api.codeclimate.com/v1/badges/a6afa67eca417f6fb7aa/maintainability)](https://codeclimate.com/github/pboyd04/spf-validator/maintainability)

---

## Installation

This module is installed via npm:

```
npm install --save spf-validator-dns
```

## Description

This module provides a simple interface to validate if an IP address is a valid sender for a given email domain.

## Usage

```javascript
const SPFValidator = require('spf-validator-dns').SPFValidator;

let validator = new SPFValidator({'domain': 'google.com', 'expandIncludes': true);
validator.validateSender('172.217.9.142').then(function(result){
  console.log(result); //Should be "PASS"
});
```
