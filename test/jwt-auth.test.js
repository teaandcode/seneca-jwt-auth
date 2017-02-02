'use strict';

const Lab = require('lab');
const lab = exports.lab = Lab.script();
const suite = lab.suite;
const test = lab.test;

const Code = require('code');
const expect = Code.expect;

const Jwt = require('jsonwebtoken');
const Request = require('./mock_request');

suite('jwt strategy suite tests', () => {

    const si = require('seneca')();

    test('call auth register service', (done) => {

        si.add('role: auth, cmd: register_service', (msg, next) => {

            expect(msg).to.exist();
            expect(msg).to.be.an.object();
            expect(msg.service).to.exist();
            expect(msg.service).to.be.equal('jwt');
            expect(msg.plugin).to.exist();
            expect(msg.conf).to.exist();

            const req = new Request();
            req.headers.authorization = 'JWT ' + Jwt.sign({ foo: 'bar' }, 'secret');

            msg.plugin.error = () => { };
            msg.plugin.authenticate(req);

            next();
            done();
        });

        si.use(require('..'), { secretOrKey: 'secret' });
    });

    test('call auth jwt login data successful', (done) => {

        si.add('role: user, cmd: login', (msg, next) => {

            expect(msg).to.exist();
            expect(msg).to.be.an.object();
            expect(msg.nick).to.exist();
            expect(msg.nick).to.be.equal('abc');

            next(null, { ok: true });
        });

        si.act({ role: 'auth', prepare: 'jwt_login_data', payload: { sub: 'abc' } }, (ignore, result) => {

            expect(result).to.exist();
            expect(result).to.be.an.object();
            expect(result.ok).to.exist();
            expect(result.ok).to.be.equal(true);

            done();
        });
    });

    test('call auth jwt login data unsuccessful', (done) => {

        si.add('role: user, cmd: login', (msg, next) => {

            expect(msg).to.exist();
            expect(msg).to.be.an.object();
            expect(msg.nick).to.exist();
            expect(msg.nick).to.be.equal('abc');

            next(null, { ok: false, why: 'xyz' });
        });

        si.act({ role: 'auth', prepare: 'jwt_login_data', payload: { sub: 'abc' } }, (error) => {

            expect(error).to.exist();
            expect(error).to.be.an.instanceof(Error);
            expect(error.code).to.be.equal('xyz');

            done();
        });
    });
});
