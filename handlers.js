'use strict'

// modules > 3rd party
const _ = require('lodash')

// modules > midwest
// const { where } = require('easy-postgres/sql-helpers')
// const { many } = require('easy-postgres/result')
const oki = require('oki')
const resolver = require('deep-equal-resolver')({
  moduleName: 'midwest-membership-auth/handlers',
  validate: oki({
    generateToken: _.isFunction,
  }),
})

module.exports = _.memoize((state) => {
  const { generateToken } = state

  function checkPasswordToken (json, client = state.db) {
    client.query(state.queries.checkPasswordToken, [ json.email, json.token ])
      .then((result) => {
        if (result.rowCount) {
          return true
        }
      })
  }

  function createEmailToken (json, client = state.db) {
    const token = generateToken()

    return client.query('INSERT INTO email_tokens (user_id, email, token) VALUES ($1, $2, $3) RETURNING token;',
      [json.userId, json.email, token]).then((result) => result.rows[0].token)
  }

  function createPasswordToken (json, client = state.db) {
    const token = generateToken()

    return client.query('INSERT INTO password_tokens (user_id, token) VALUES ($1, $2, $3) RETURNING token;',
      [json.userId, json.email, token]).then((result) => result.rows[0].token)
  }

  return {
    checkPasswordToken,
    createEmailToken,
    createPasswordToken,
  }
}, resolver)
