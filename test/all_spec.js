/*jshint expr: true*/
/* global describe, before, beforeEach, it */

var Sequelize = require('sequelize'),
    should = require('should'),
    passportLocalSequelize = require('../lib/passport-local-sequelize');

var db = new Sequelize('test-db', 'user', 'pass', {
    dialect: 'sqlite',
    storage: 'test/test-db.sqlite',
    logging: false
});

var User;

var initDb = function (done) {
    User = passportLocalSequelize.defineUser(db, {
        email: {
            type: Sequelize.STRING,
            allowNull: false,
            unique: true
        }
    }, {
        usernameQueryFields: ['email'],
        iterations: 50
    });

    // Authenticate the db
    return db.authenticate().then(function () {
        // Synchronize the db
        return db.sync({ force: true });
    }).then(function () {
        done();
    }).catch(done);
};

describe('Passport Local Sequelize', function () {
    before(function (done) {
        initDb(done);
    });

    beforeEach(function (done) {
        // Delete all users
        User.destroy({truncate: true})
            .then(function () {
                done();
            })
            .catch(done);
    });

    it('can define a User schema for you', function () {
        should.exist(User);
    });

    it('can find user by email', function (done) {
        should.exist(User.findByUsername);
        User.register({username: 'someuser', email: 'test@example.com'}, 'somepass').then(function () {
            return User.findByUsername('test@example.com');
        }).then(function (user) {
            should(user).be.instanceof(User.Instance).and.have.property('email', 'test@example.com');
            done();
        }).catch(function (error) {
            done(error);
        });
    });

    it('can register and authenticate a user', function (done) {
        should.exist(User.register);

        User.register({username: 'someuser', email: 'test@example.com'}, 'somepass').then(function (registeredUser) {
            registeredUser.get('username').should.equal('someuser');
            registeredUser.get('email').should.equal('test@example.com');
            registeredUser.get('id').should.be.above(0);

            registeredUser.authenticate('badpass', function (err, authenticated) {
                if (err) {
                    return done(err);
                }
                authenticated.should.equal(false);

                registeredUser.authenticate('somepass', function (err, authenticatedUser) {
                    if (err) {
                        return done(err);
                    }

                    authenticatedUser.should.not.equal(false);
                    authenticatedUser.get('username').should.equal('someuser');
                    done();
                });
            });
        }).catch(function (error) {
            done(error);
        });
    });

    it('can reset password', function (done) {
        should.exist(User.resetPassword);
        User.register({username: 'someuser', email: 'test@example.com'}, 'somepass').then(function () {
            return User.setResetPasswordKey('someuser');
        }).then(function (user) {
            user.get('username').should.equal('someuser');
            user.get('resetPasswordKey').should.be.ok;
            return User.resetPassword('someuser', 'passsome', user.get('resetPasswordKey'));
        }).then(function (user) {
            user.authenticate('somepass', function (err, authenticated) {
                if (err) {
                    return done(err);
                }
                authenticated.should.equal(false);

                user.authenticate('passsome', function (err, authenticatedUser) {
                    if (err) {
                        return done(err);
                    }
                    authenticatedUser.should.not.equal(false);
                    authenticatedUser.get('username').should.equal('someuser');
                    done();
                });
            });
        }).catch(function (error) {
            done(error);
        });
    });
});
