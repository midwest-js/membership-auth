'use strict'

// modules > 3rd party
const _ = require('lodash')
const oki = require('oki')

const resolver = require('deep-equal-resolver')({
  moduleName: 'midwest-membership-auth/middleware/register',
  validate: oki({
    db: (value) => {
      const keys = ['query', 'connect', 'begin']

      return keys.every((key) => _.has(value, key))
    },
    generateToken: _.isFunction,
    'errors.duplicateEmail': _.isPlainObject,
    'errors.notAuthorized': _.isPlainObject,
    'handlers.users.create': _.isFunction,
    'handlers.users.findOne': _.isFunction,
    'handlers.admissions.findMatches': _.isFunction,
    'handlers.invites.findByEmail': _.isFunction,
  }),
})

module.exports = _.memoize((state) => {
  const { config } = state
  const { generatePasswordToken } = require('../handlers')(state)
  const template = state.config.templates.resetPassword

  return (req, res, next) => {
    const { email } = req.body

    state.handlers.getUserByEmail(email).then((result) => {
      return Promise.all([
        result,
        generatePasswordToken(),
      ]).then(([ user, token ]) => {
        state.sendEmail({
          to: user.email,
          from: `${config.site.title} <${config.site.emails.robot}>`,
          subject: `Welcome to ${config.site.title}!`,
          html: template({ site: config.site, user: user }),
        })
      })
    })
  }
}, resolver)
