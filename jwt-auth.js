'use strict';

const ExtractJwt = require('passport-jwt').ExtractJwt;
const JwtStrategy = require('passport-jwt').Strategy;

module.exports = function (options) {

    const service = 'jwt';

    const params = {};
    params.jwtFromRequest = ExtractJwt.fromAuthHeader();
    params.audience = options.audience;
    params.issuer = options.issuer;
    params.secretOrKey = options.secretOrKey;

    const authPlugin = new JwtStrategy(params, function (payload, done) {

        this.act({ role: 'auth', prepare: 'jwt_login_data', payload }, done);
    });

    this.add({ role: 'auth', prepare: 'jwt_login_data' }, (msg, done) => {

        this.act({ role: 'user', cmd: 'login', nick: msg.payload.sub, auto: true }, (err, out) => {

            if (!out.ok) {
                return done(out.why);
            }
            done(err, out);
        });
    });

    this.act({ role: 'auth', cmd: 'register_service', service, plugin: authPlugin, conf: options });

    return {
        name: 'jwt-auth'
    };
};
