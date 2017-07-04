'use strict'

const createError = require('midwest/util/create-error')

module.exports = (state) => {
  const { config, handlers } = state

  return function verifyEmail (req, res, next) {
    handlers.users.findOne({ email: req.find.email, 'emailToken.token': req.find.token }).then((user) => {
      if (!user) {
        throw createError('Incorrect token and/or email', 404)
      }

      if (Date.now() > user.emailToken.date + config.timeouts.verifyEmail) {
        throw createError('Token has expired', 410)
      }

      user.isEmailVerified = true

      if (user.emailToken.email) {
        user.email = user.emailToken.email
      }

      user.emailToken = undefined

      const promise = handlers.update()

      if (config.hooks && config.hooks.verifyEmail) {
        return promise.then(config.hooks.verifyEmail)
      } else {
        return promise
      }
    }).catch(next)
  }
}
