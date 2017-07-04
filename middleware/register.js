'use strict'

// modules > 3rd party
const _ = require('lodash')

// modules > midwest
const createError = require('midwest/util/create-error')
// const { where } = require('easy-postgres/sql-helpers')
// const { many } = require('easy-postgres/result')
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
    'handlers.createUser': _.isFunction,
    'handlers.findUser': _.isFunction,
    'handlers.findMatchingAdmissions': _.isFunction,
    'handlers.findInviteByEmail': _.isFunction,
  }),
})

module.exports = _.memoize((state) => {
  const { db, handlers, config } = state

  const { createEmailToken } = require('../handlers')(_.pick(state, 'db', 'generateToken'))

  function getRoles (req, email) {
    return handlers.invites.findByEmail(email).then((invite) => {
      let roles = invite ? invite.roles : []

      return handlers.admissions.findMatches(email).then((admissions) => {
        if (admissions) {
          roles = _.union(roles, ...admissions.map((admission) => admission.roles))
        }

        return { roles, invite }
      })
    })
  }

  return function register (req, res, next) {
    const social = req.flash('social')[0]

    if (social) {
      Object.assign(req.body, _.pick(social.profile, 'givenName', 'familyName', 'email', 'gender'), {
        [social.provider + 'Id']: social.profile.id,
        [social.provider + 'Token']: social.token.value,
      })
    } else {
      // TODO remove any provider id's or tokens from req.body
    }

    // TODO validate!
    req.body.email = req.body.email.trim().toLowerCase()

    handlers.users.findOne({ email: req.body.email }).then((user) => {
      if (user) {
        throw createError(state.errors.duplicateEmail)
      }

      return getRoles(req.body.email)
    }).then(async ({ roles, invite }) => {
      if (!roles) throw createError(config.errors.notAuthorized)

      const newUser = _.merge({}, req.body, { roles })

      // TEMP
      if (invite) newUser.emailVerifiedAt = new Date()

      const t = await db.begin()
      const user = await handlers.users.create(newUser, t)

      if (!user.emailVerifiedAt) {
        const token = await createEmailToken({ userId: user.id, email: user.email }, t)

        user.emailToken = token
      }

      await t.commit()

      if (state.hook) {
        await state.hook(user, req, res)
      }

      if (req.accepts(['json', '*/*'] === 'json')) {
        return res.status(201).json(_.omit(user, 'password'))
      }

      res.redirect(config.redirects.register)
    }).catch((err) => {
      if (req.body.password) {
        req.body.password = 'DELETED'
      }

      if (req.body.confirmPassword) {
        req.body.confirmPassword = 'DELETED'
      }

      next(err)
    })
  }
}, resolver)
