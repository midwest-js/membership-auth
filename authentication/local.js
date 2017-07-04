'use strict'

const _ = require('lodash')
const oki = require('oki')
const createError = require('midwest/util/create-error')
const resolver = require('deep-equal-resolver')({
  moduleName: 'midwest-membership-auth/authentication/local',
  validate: oki({
    'getAuthenticationDetails': _.isFunction,
    'checkPassword': _.isFunction,
    'errors.wrongPassword': _.isPlainObject,
    'errors.noUserFound': _.isPlainObject,
    'errors.notLocal': _.isPlainObject,
  }),
})

module.exports = _.memoize((state) => (req, res, next) => {
  const { email, password } = req.body

  return state.getAuthenticationDetails(email.toLowerCase()).then((user) => {
    if (!user) {
      throw createError(state.errors.noUserFound)
    } else if (!user.password) {
      throw createError(state.errors.notLocal)
    }

    return state.checkPassword(password, user.password).then((result) => {
      if (!result) {
        throw createError(state.errors.wrongPassword)
      }

      return user
    })
  })
}, resolver)
