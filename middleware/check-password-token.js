'use strict'

const _ = require('lodash')
const oki = require('oki')

const createError = require('midwest/util/create-error')
const resolver = require('deep-equal-resolver')({
  validate: oki({
    'handlers.users.findOne': _.isFunction,
  }),
})

module.exports = _.memoize((state) => {
  // middleware that checks if an email and token are valid
  return function checkPasswordToken (req, res, next) {
    state.handlers.users.findOne({ email: req.query.email, 'passwordToken.token': req.find.token }).then((user) => {
      if (!user) {
        throw createError('Token not found', 404)
      }

      if (user.passwordToken.date.getTime() + (24 * 60 * 60 * 1000) < Date.now()) {
        throw createError('Token has expired', 410)
      }

      next()
    }).catch(next)
  }
}, resolver)
