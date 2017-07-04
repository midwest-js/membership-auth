'use strict'

const _ = require('lodash')
const express = require('express')
const resolver = require('deep-equal-resolver')()

const middleware = {
  authenticate: require('./middleware/authenticate'),
  changePasswordWithToken: require('./middleware/change-password-with-token'),
  checkPasswordToken: require('./middleware/check-password-token'),
  register: require('./middleware/register'),
  sendResetPasswordLink: require('./middleware/send-reset-password-link'),
  verifyEmail: require('./middleware/verify-email'),
}

const authentication = {
  local: require('./authentication/local'),
  social: require('./authentication/social'),
}

const redirect = require('midwest/factories/redirect')

module.exports = exports = _.memoize((state) => {
  const flash = require('connect-flash')()
  const router = new express.Router()

  router
    .post('/login', exports.local({
      errors: state.config.errors,
      hook: state.hooks.login,
      checkPassword: state.hooks.checkPassword,
      getAuthenticationDetails: state.handlers.users.getAuthenticationDetails,
    }))
    .post('/register', flash, exports.register({
      generateToken: state.hooks.generateToken,
      db: state.db,
      handlers: {
        createUser: state.handlers.users.create,
        findUser: state.handlers.users.findOne,
        findMatchingAdmissions: state.handlers.admissions.findMatches,
        findInviteByEmail: state.handlers.invites.findByEmail,
      },
      errors: state.config.errors,
    }))
    // .post('/send-reset-password-link', exports.sendResetPasswordLink(state))
    // .post('/reset-password', exports.changePasswordWithToken(state))
    .post('/verify', exports.verifyEmail(state))

  if (state.providers && state.providers.length) {
    state.providers.forEach((provider) => {
      router.get('/' + provider.name, flash, exports.social({
        errors: state.config.errors,
        hooks: state.hooks.login,
        findUserByToken: state.handlers.users.findByToken,
        provider,
      }))
    })
  }

  return router
}, resolver)

exports.register = middleware.register

exports.local = (state) => {
  return middleware.authenticate({
    errors: state.errors,
    hook: state.hook,
    authenticate: authentication.local(state),
  })
}

exports.social = (state) => {
  return middleware.authenticate({
    errors: state.config.errors,
    hook: state.hooks,
    authenticate: authentication.social({
      provider: state.provider,
      findUserByToken: state.findByTokenUser,
    }),
  })
}

exports.checkPasswordToken = (...args) => {
  return middleware.checkPasswordToken(...args)
}

exports.changePasswordWithToken = (...args) => {
  return middleware.changePasswordWithToken(...args)
}

exports.sendResetPasswordLink = (...args) => {
  return middleware.sendResetPasswordLink(...args)
}

exports.verifyEmail = (...args) => {
  return middleware.verifyEmail(...args)
}
