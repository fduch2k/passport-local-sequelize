var util = require('util');
var Promise = require('bluebird');
var crypto = Promise.promisifyAll(require('crypto'));
var _ = require('lodash');
var Sequelize = require('sequelize');
var LocalStrategy = require('passport-local').Strategy;

// The default option values
var defaultAttachOptions = {
    activationkeylen:  8,
    resetPasswordkeylen:  8,
    saltlen:  32,
    iterations:  10000,
    keylen:  512,
    digest: 'sha512',
    usernameField: 'username',
    usernameLowerCase: false,
    usernameQueryFields: ['username'],
    activationRequired: false,
    hashField: 'hash',
    saltField: 'salt',
    activationKeyField: 'activationKey',
    resetPasswordKeyField: 'resetPasswordKey',
    saveLogins: false,
    lastLoginField: 'lastLogin',
    loginsField: 'logins',

    limitAttempts: false,
    lastLoginAttemptField: 'lastLoginAttempt',
    attemptsField: 'attempts',
    interval: 100,
    maxInterval: 300000,
    maxAttempts: Infinity,

    incorrectPasswordError: 'Incorrect password',
    incorrectUsernameError: 'Incorrect username',
    invalidActivationKeyError: 'Invalid activation key',
    invalidResetPasswordKeyError: 'Invalid reset password key',
    missingUsernameError: 'Field %s is not set',
    missingFieldError: 'Field %s is not set',
    missingPasswordError: 'Password argument not set!',
    userExistsError: 'User already exists with %s',
    activationError: 'Email activation required',
    attemptTooSoonError: 'Account is currently locked. Try again later',
    tooManyAttemptsError: 'Account locked due to too many failed login attempts'
};

// The default schema used when creating the User model
var defaultUserSchema = {
    id: {
        type: Sequelize.INTEGER,
        autoIncrement: true,
        primaryKey: true
    },
    username: {
        type: Sequelize.STRING,
        allowNull: false,
        unique: true
    },
    hash: {
        type: Sequelize.STRING,
        allowNull: false
    },
    salt: {
        type: Sequelize.STRING,
        allowNull: false
    },
    activationKey: {
        type: Sequelize.STRING,
        allowNull: true
    },
    resetPasswordKey: {
        type: Sequelize.STRING,
        allowNull: true
    }
};

var shimPbkdf2 = function (password, salt, iterations, keylen, digest, callback) {
    var params = [password, salt, iterations, keylen];
    var nodeVersion = Number(process.version.match(/^v(\d+\.\d+)/)[1]);
    if (nodeVersion >= 0.12) {
        params.splice(4, 0, digest);
    }
    try {
        return crypto.pbkdf2Async.apply(crypto, params).asCallback(callback);
    } catch (err) {
        return Promise.reject(err).asCallback(err);
    }
};

var shimPbkdf2Async = shimPbkdf2;

var attachToUser = function (UserSchema, options) {
    // Get our options with default values for things not passed in
    options = _.defaults(options || {}, defaultAttachOptions);
    if (_.indexOf(options.usernameQueryFields, options.usernameField) === -1) {
        options.usernameQueryFields.push(options.usernameField);
    }

    UserSchema.options.hooks.beforeCreate = function (user, next) {
        // if specified, convert the username to lowercase
        if (options.usernameLowerCase) {
            user[options.usernameField] = user[options.usernameField].toLowerCase();
        }
        if (typeof(next) === 'function') {
            next();
        }
    };

    UserSchema.Instance.prototype.setPassword = function (password, cb) {
        var self = this;

        if (!password) {
            return Promise.reject(new Error(options.missingPasswordError)).asCallback(cb);
        }

        return crypto.randomBytesAsync(options.saltlen).then(function (buf) {
            var salt = buf.toString('hex');
            self.set(options.saltField, salt);
            return shimPbkdf2Async(password, salt, options.iterations, options.keylen, options.digest);
        }).then(function (hashRaw) {
            self.set(options.hashField, new Buffer(hashRaw, 'binary').toString('hex'));
            return self;
        }).asCallback(cb);
    };

    UserSchema.Instance.prototype.setActivationKey = function (cb) {
        var self = this;

        if (options.activationRequired) {
            return crypto.randomBytesAsync(options.activationkeylen).then(function (buf) {
                var randomHex = buf.toString('hex');
                self.set(options.activationKeyField, randomHex);
                return self;
            }).asCallback(cb);
        }
        return Promise.resolve(self).asCallback(cb);
    };

    UserSchema.Instance.prototype.authenticate = function (password, cb) {
        var self = this;
        if (options.limitAttempts) {
            var attemptsInterval = Math.pow(options.interval, Math.log(self.get(options.attemptsField) + 1));
            var calculatedInterval = Math.min(attemptsInterval, options.maxInterval);
            if (Date.now() - self.get(options.lastLoginAttemptField) < calculatedInterval) {
                self.set(options.lastLoginAttemptField, Date.now());
                self.save();
                return cb(null, false, {message: options.attemptTooSoonError});
            }

            if (self.get(options.attemptsField) >= options.maxAttempts) {
                return cb(null, false, {message: options.tooManyAttemptsError});
            }
        }

        // TODO: Fix callback and behavior to match passport
        shimPbkdf2(password, this.get(options.saltField), options.iterations, options.keylen, options.digest, function (err, hashRaw) {
            if (err) {
                return cb(err);
            }

            var hash = new Buffer(hashRaw, 'binary').toString('hex');

            if (hash === self.get(options.hashField)) {
                if (options.saveLogins) {
                    self.set(options.lastLoginField, Date.now());
                    self.set(options.loginsField, self.get(options.loginsField) + 1);
                }
                if (options.limitAttempts) {
                    self.set(options.lastLoginAttemptField, Date.now());
                    self.set(options.attemptsField, 0);
                }
                if (options.limitAttempts || options.saveLogins) {
                    self.save();
                }
                return cb(null, self);
            } else {
                if (options.limitAttempts) {
                    self.set(options.lastLoginAttemptField, Date.now());
                    self.set(options.attemptsField, self.get(options.attemptsField) + 1);
                    self.save().then(function () {
                        if (self.get(options.attemptsField) >= options.maxAttempts) {
                            return cb(null, false, {message: options.tooManyAttemptsError});
                        } else {
                            return cb(null, false, {message: options.incorrectPasswordError});
                        }
                    }).catch(function (error) {
                        return cb(error);
                    });
                } else {
                    return cb(null, false, {message: options.incorrectPasswordError});
                }
            }
        });
    };

    UserSchema.authenticate = function () {
        var self = this;
        return function (username, password, cb) {
            self.findByUsername(username, function (err, user) {
                if (err) { return cb(err); }

                if (user) {
                    return user.authenticate(password, cb);
                } else {
                    return cb(null, false, {message: options.incorrectUsernameError});
                }
            }).catch(function (error) {
                cb(error);
            });
        };
    };

    UserSchema.serializeUser = function () {
        return function (user, cb) {
            cb(null, user.get(options.usernameField));
        };
    };

    UserSchema.deserializeUser = function () {
        var self = this;
        return function (username, cb) {
            self.findByUsername(username, cb);
            return null;
        };
    };

    UserSchema.register = function (user, password, cb) {
        var self = this;
        if (_.isString(user)) {
            // Create an instance of this in case user is passed as username
            user = _.zipObject([options.usernameField, user]);
        }

        if (_.isObject(user)) {
            // Create an instance if user is passed as fields
            user = self.build(user);
        }

        if (user instanceof UserSchema.Instance) {
            if (!user.get(options.usernameField)) {
                return Promise.reject(new Error(util.format(options.missingUsernameError, options.usernameField))).asCallback(cb);
            }

            return self.findByUsername(user.get(options.usernameField)).then(function (existingUser) {
                if (existingUser) {
                    return new Error(util.format(options.userExistsError, user.get(options.usernameField)));
                }
                var promise = user.setPassword(password, cb);
                return Promise.join(promise, user.setActivationKey(cb));
            }).then(function () {
                return user.save();
            }).asCallback(cb);
        }
    };

    UserSchema.activate = function (email, password, activationKey, cb) {
        var self = this;
        var auth = self.authenticate();
        auth(email, password, function (err, user, info) {

            if (err) { return cb(err); }

            if (!user) { return cb(info); }

            if (user.get(options.activationKeyField) === activationKey) {
                user.updateAttributes({verified: true, activationKey: 'null'}).then(function () {
                    return cb(null, user);
                }).catch(function (error) {
                    return cb(error);
                });
            } else {
                return cb({message: options.invalidActivationKeyError});
            }
        });
    };

    UserSchema.findByUsername = function (username, cb) {
        // if specified, convert the username to lowercase
        if (options.usernameLowerCase) {
            username = username.toLowerCase();
        }

        // queryParameters[options.usernameField] = username;
        // Add each username query field
        var queryOrParameters = [];
        for (var i = 0; i < options.usernameQueryFields.length; i++) {
            var parameter = {};
            parameter[options.usernameQueryFields[i]] = username;
            queryOrParameters.push(parameter);
        }
        return this.findOne({where: {$or: queryOrParameters}}).asCallback(cb);
    };

    UserSchema.setResetPasswordKey = function (username, cb) {
        var self = this;
        return self.findByUsername(username).then(function (user) {
            return [crypto.randomBytesAsync(options.resetPasswordkeylen), user];
        }).spread(function (buf, user) {
            var randomHex = buf.toString('hex');
            user.set(options.resetPasswordKeyField, randomHex);
            return user.save();
        }).asCallback(cb);
    };

    UserSchema.resetPassword = function (username, password, resetPasswordKey, cb) {
        var self = this;
        return self.findByUsername(username).then(function (user) {
            if (user.get(options.resetPasswordKeyField) === resetPasswordKey) {
                return user.setPassword(password).then(function (user) {
                    return user.save();
                });
            } else {
                return new Error(options.invalidResetPasswordKeyError);
            }
        }).asCallback(cb);
    };

    UserSchema.createStrategy = function () {
        return new LocalStrategy(options, this.authenticate());
    };
};

var defineUser = function (sequelize, extraFields, attachOptions) {
    var schema = _.defaults(extraFields || {}, defaultUserSchema);

    var User = sequelize.define('User', schema);

    attachToUser(User, attachOptions);

    return User;
};

module.exports = {
    defaultAttachOptions: defaultAttachOptions,
    defaultUserSchema: defaultUserSchema,
    attachToUser: attachToUser,
    defineUser: defineUser
};
