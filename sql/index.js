'use strict'

const rsql = require('easy-postgres/require-sql')

const dir = __dirname

module.exports = {
  deserialize: rsql('./deserialize.sql', dir),
  getAuthenticationDetails: rsql('./getAuthenticationDetails.sql', dir),
  // login: rsql('./login.sql', dir),
}
