'use strict'

const _ = require('lodash')
const oki = require('oki')
const resolver = require('deep-equal-resolver')({
  moduleName: 'midwest-membership-auth/middleware/authenticate',
  validate: oki({
    'authenticate': _.isFunction,
    'errors.emailNotVerified': _.isPlainObject,
    'errors.isBlocked': _.isPlainObject,
    'errors.isBanned': _.isPlainObject,
  }),
})

const createError = require('midwest/util/create-error')

// TODO should this be handled by the responder instead?
// would require the user to create his own responder middleware if he isn't
// using a global responder
const responses = {
  json (req, res, user) {
    if (req.session.previousUrl) res.set('Location', req.session.previousUrl)

    res.json(user)
  },

  html (req, res) {
    res.redirect(req.session.previousUrl || '/')
  },
}

module.exports = _.memoize((state) => (req, res, next) => {
  return state.authenticate(req, res, next).then((user) => {
    let error

    if (state.requireVerification && !user.emailVerifiedAt) {
      error = state.errors.emailNotVerified
    } else if (user.blockedAt) {
      error = state.errors.blocked
    } else if (user.bannedAt) {
      error = state.errors.banned
    }

    if (error) {
      throw createError(...error)
    }

    if (req.body.remember && _.has(state, 'config.remember')) {
      if (state.config.remember.expires) {
        req.session.cookie.expires = state.config.remember.expires
      } else {
        req.session.cookie.maxAge = state.config.remember.maxAge
      }
    }

    if (state.hook) {
      return state.hook(user, req, res).then(() => user)
    }

    return user
  }).then((user) => {
    delete user.password

    res.status(200)

    responses[req.accepts(['json', 'html'])](req, res, user)
  }).catch((err) => {
    if (req.body.password) {
      req.body.password = 'DELETED'
    }

    // TODO this should probably not even be sent to the server
    // or maybe it should, especially if non-js login is required
    if (req.body.confirmPassword) {
      req.body.confirmPassword = 'DELETED'
    }

    next(err)
  })
}, resolver)
