'use strict';

const _ = require('lodash');

const createError = require('midwest/util/create-error');

// TODO should this be handled by the responder instead?
// would require the user to create his own responder middleware if he isn't
// using a global responder
const responses = {
  json(req, res, user) {
    if (req.session.previousUrl) res.set('Location', req.session.previousUrl);

    res.json(user);
  },

  html(req, res) {
    res.redirect(req.session.previousUrl || '/');
  },
};

module.exports = _.memoize((config) => (req, res, next) => {
  const { email, password, remember } = req.body;

  config.getAuthenticationDetails(email.toLowerCase()).then((user) => {
    let error;

    if (user) {
      if (!user.password) {
        error = config.errors.login.notLocal;
      } else if (!user.emailVerifiedAt) {
        error = config.errors.login.emailNotVerified;
      } else if (user.blockedAt) {
        error = config.errors.login.blocked;
      } else if (user.bannedAt) {
        error = config.errors.login.banned;
      } else {
        return config.checkPassword(password, user.password).then(() => {
          if (remember) {
            if (config.remember.expires) {
              req.session.cookie.expires = config.remember.expires;
            } else {
              req.session.cookie.maxAge = config.remember && config.remember.maxAge;
            }
          }

          let promise = config.login(req, user);

          if (config.hooks && config.hooks.login) {
            promise = promise.then(config.hooks.login);
          }

          return promise.then(() => {
            delete user.password;

            res.status(200);

            responses[req.accepts(['json', 'html'])](req, res, user);
          });
        });
      }
    } else {
      error = config.errors.login.noUserFound;
    }

    throw createError(...error);
  }).catch((err) => {
    if (req.body.password) {
      req.body.password = 'DELETED';
    }

    // TODO this should probably not even be sent to the server
    // or maybe it should, especially if non-js login is required
    if (req.body.confirmPassword) {
      req.body.confirmPassword = 'DELETED';
    }

    next(err);
  });
});
