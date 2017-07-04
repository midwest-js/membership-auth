'use strict'

const { get } = require('rek')
const _ = require('lodash')
const isURL = require('validator/lib/isURL')
const oki = require('oki')
const Promise = require('bluebird')

const resolver = require('deep-equal-resolver')({
  moduleName: 'midwest-membership-auth/middleware/login',
  validate: oki({
    'provider.mapToken': _.isFunction,
    'provider.mapProfile': _.isFunction,
    'provider.name': _.isString,
    'provider.urls.profile': isURL,
    'provider.urls.token': isURL,
    'findUserByToken': _.isFunction,
  }),
})

module.exports = _.memoize((state) => {
  return (req, res, next) => {
    const { code } = req.query

    get(`${state.provider.urls.token}${code}`).then((json) => Promise.all([
      json,
      state.findByUserByToken({ token: json.access_token, provider: state.provider.name }),
    ])).then(([ token, user ]) => {
      if (user) {
        return user
      }

      return Promise.all([
        token,
        get(`${state.provider.urls.profile}&access_token=${token.access_token}`),
      ])
    }).then(([ token, profile ]) => {
      // TODO validate profile
      if (!profile) {
        throw new Error('No profile found! Unable to begin social registration')
      }

      req.flash('social', {
        provider: state.provider.name,
        token: state.provider.mapToken(token),
        createdAt: new Date(),
        profile: state.provider.mapProfile(profile),
      })

      res.redirect('/register')
    }).catch(next)
  }
}, resolver)
