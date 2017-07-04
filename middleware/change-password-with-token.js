'use strict'

const createError = require('midwest/util/create-error')

module.exports = (state) => {
  const { handlers } = state

  return function resetPasswordWithToken (req, res, next) {
    // hide password in body
    function sendError (...args) {
      if (req.body.password) {
        req.body.password = 'DELETED'
      }

      if (req.body.confirmPassword) {
        req.body.confirmPassword = 'DELETED'
      }

      next(createError(...args))
    }

    // if (!req.body.email || !req.body.password || !req.body.token) {
    if (!req.body.password) {
      return sendError(state.config.errors.general.missingParameters)
    }

    // handlers.users.findOne({ email: req.body.email, 'passwordToken.token': req.body.token }, (err, user) => {
    handlers.users.findOne({ email: req.body.email }, (err, user) => {
      if (err) return next(err)

      if (!user) {
        return sendError(state.config.errors.incorrect)
      }

      if (Date.now() > user.passwordToken.date + state.config.timeouts.changePassword) {
        return sendError(state.config.errors.expired)
      }

      handlers.users.update(user.id, { password: req.body.password }).then(() => {
        res.sendStatus(204)
      }).catch(next)
    })
  }
}
