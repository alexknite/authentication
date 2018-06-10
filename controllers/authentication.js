const jwt = require('jwt-simple');
const User = require('../models/user');
const config = require('../config');

function tokenForUser(user) {
  const timestamp = new Date().getTime();
  // sub = subject
  return jwt.encode({ sub: user.id, iat: timestamp }, config.secret);
}

exports.signin = function(req, res, next) {
  // User has already validated credentials
  // Now they just need a token
  res.send({ token: tokenForUser(req.user) });
}

exports.signup = function(req, res, next) {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(422).send({ error: 'You must provide an email and password' });
  }

  // Check if user email already exist
  User.findOne({ email }, function(err, existingUser) {
    if (err) { return next(err); }

    // If it does already exist, return an error
    if (existingUser) {
      return res.status(422).send({ error: 'Email is in use' });
    }

    // If not... create and save record
    const user = new User({
      email,
      password
    });

    user.save(function() {
      if (err) { return next(err); }

      // Respond to request indicating that the user was created
      res.json({ token: tokenForUser(user) });
    });
  });
}
