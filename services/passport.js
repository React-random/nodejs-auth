const passport = require('passport');
const User = require('../models/user');
const config = require('../config');
const JwtStrategy = require('passport-jwt').Strategy;
const ExtractJwt = require('passport-jwt').ExtractJwt;
const LocalStrategy = require('passport-local');

const localLogin = new LocalStrategy({
    usernameField: 'email'
}, function (email, password, done) {
    User.findOne({ email: email }, function (err, user) {
        if (err) return done(err, false);
        if (!user) return done(err, false);

        user.comparePassword(password, function (err, isMatch) {
            if (err) return done(err);
            if (!isMatch) return done(null, false);

            return done(null, user);
        });
    })
});

const jwtLogin = new JwtStrategy({
    jwtFromRequest: ExtractJwt.fromHeader('authorization'),
    secretOrKey: config.secret
}, function (payload, done) {
    User.findById(payload.sub, function (err, user) {
        if (err) return done(err, false);

        if (user) {
            done(null, user);
        } else {
            done(null, false);
        }
    });
});

passport.use(jwtLogin);
passport.use(localLogin);

