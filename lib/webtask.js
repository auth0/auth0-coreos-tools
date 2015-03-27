var jws = require('jws')
    , uuid = require('uuid')
    , crypto = require('crypto')
    , async = require('async')
    , request = require('request')
    , LRU = require('lru-cache');

var allowed_request_claims = {
    url: 'string',
    pctx: 'object',
    ectx: 'object',
    ten: 'object',
    exp: 'number',
    nbf: 'number',
    pb: 'number',
    mb: 'number',
    dd: 'number'
};

exports.validate_token_issue_request = function(req, claims) {

    // Check for delegation depth

    if (claims['dd'] === 0) {
        return { code: 400, message: 'The authentication webtask token cannot be used to issue new webtask tokens.' };
    }

    // Parse the ten claim

    if (req.ten) {
        var ten = parse_ten(req.ten);
        if (ten.code) 
            return ten;
        req.ten = ten;
    }

    // Validate claim types from request

    for (var claim in req) {
        if (typeof req[claim] !== allowed_request_claims[claim]) {
            if (!allowed_request_claims[claim])
                return { code: 400, message: 'unsupported claim `' + claim + '`' };
            else
                return { code: 400, message: 'claim `' + claim + '` must be of type `' + allowed_request_claims[claim] + '`' };
        }
    }

    // Validate delegation depth

    if (req['dd'] !== undefined && (req['dd'] < 0 || Math.floor(req['dd']) !== req['dd'])) {
        return { code: 400, message: 'The `dd` claim must be a non-negative integer.' };
    }

    // Validate claim subsetting rules

    var fixed_claims = ['url', 'pctx', 'ectx'];
    for (var i in fixed_claims) {
        var claim = fixed_claims[i];
        if (req[claim] !== undefined && claims[claim] !== undefined)
            return { code: 400, message: 'the `' + claim + '` claim cannot be specified if the authentication token already specifies it' };
    }

    if (claims['url'] && req['pb'] !== undefined && req['pb'] !== claims['pb']) {
        return { code: 400, message: 'the `pb` claim value cannot be changed' };
    }

    if (claims['url'] && req['mb'] !== undefined && req['mb'] !== claims['mb']) {
        return { code: 400, message: 'the `mb` claim value cannot be changed' };
    }

    if (req.ten && claims.ten) {
        if (req.ten.regex) {
            return { code: 400, message: 'the `ten` claim cannot be a regular expression if the `ten` claim of the authentication token is a regular expression' };
        }
        if (claims.ten.whitelist) {
            for (var tenant in req.ten.whitelist) {
                if (!claims.ten.whitelist[tenant]) {
                    return { code: 400, message: 'the `ten` claim must contain a subset of tenants in the `ten` claim of the authentication token' };
                }
            }
        }
        else { // claims.ten.regex 
            for (var tenant in req.ten.whitelist) {
                if (!claims.ten.regex.test(tenant)) {
                    return { code: 400, message: 'the `ten` claim must only contain tenant names that match the `ten` regular expression of the authentication token' };
                }
            }
        }
    }

    if (req.exp !== undefined && claims.exp !== undefined) {
        if (req.exp > claims.exp) {
            return { code: 400, message: 'the `exp` claim cannot extend the expiration of the authentication token' };
        }
    }

    if (req.nbf !== undefined && claims.nbf !== undefined) {
        if (req.nbf < claims.nbf) {
            return { code: 400, message: 'the `nbf` claim cannot extend the expiration of the authentication token' };
        }
    }

    return;
};

exports.issue_token = function (req, claims, kid, keyset) {
    var new_claims = {
        jti: uuid.v4().replace(/-/g,''),
        iat: Math.floor(Date.now() / 1000)
    };

    // Construct issuance chain

    new_claims.ca = claims.ca || [];
    if (claims.jti)
        new_claims.ca.push(claims.jti);

    // Establish new delegation depth

    if (claims['dd'] !== undefined && req['dd'] !== undefined)
        new_claims.dd = Math.min(claims['dd'] - 1, req['dd']);
    else if (claims['dd'] !== undefined)
        new_claims.dd = claims['dd'] - 1;
    else if (req['dd'] !== undefined)
        new_claims.dd = req['dd'];
    else
        new_claims.dd = 1;

    // Create claims of the new token observing inheritance rules

    ['url', 'exp', 'nbf', 'ten', 'pctx', 'ectx'].forEach(function (claim) {
        if (req[claim] !== undefined || claims[claim] !== undefined)
            new_claims[claim] = req[claim] !== undefined ? req[claim] : claims[claim];
    });

    ['mb','pb'].forEach(function (claim) {
        if (claims['url']) {
            if (claims[claim] !== undefined)
                new_claims[claim] = claims[claim];
        }
        else if (req['url']) {
            if (req[claim] !== undefined)
                new_claims[claim] = req[claim];
        }
    });

    // Stringify `ten`

    if (new_claims.ten) {
        if (new_claims.ten.whitelist)
            new_claims.ten = Object.getOwnPropertyNames(new_claims.ten.whitelist).join(',');
        else // new_claims.ten.regex
            new_claims.ten = new_claims.ten.regex.toString();
    }

    // Encrypt context

    if (new_claims.ectx) {
        var plaintext = JSON.stringify(new_claims.ectx);
        var iv = crypto.randomBytes(16);
        var cipher = crypto.createCipheriv(
            'aes-256-cbc', 
            keyset.encryption_key_raw,
            iv);
        var encrypted = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
        new_claims.ectx = encrypted.toString('base64') + '.' + iv.toString('base64');
    }

    // Sign

    var token = jws.sign({
        header: {
            alg: 'HS256',
            kid: kid
        },
        payload: new_claims,
        secret: keyset.signature_key
    });

    return token;
};

exports.ensure_authorized = function (admin, ctx) {
    return function (req, res, next) {
        var msg;
        if (!req.claims) {
            // The are no claims, the user had not been authenticated
            msg = { code: 403, message: 'unauthenticated user is not authorized', req_id: req.req_id };
            ctx.logger.warn({
                req_id: req.req_id,
                path: req.originalUrl,
                method: req.method
            }, msg.message);
        }
        else if (admin) {
            if (req.claims.ten) {
                msg = { code: 403, message: 'insufficient permissions to call administrative API', req_id: req.req_id };
                ctx.logger.warn({
                    req_id: req.req_id,
                    path: req.originalUrl,
                    method: req.method,
                    jwt: req._jwt
                }, msg.message);
            }
            else {
                return next();
            }
        }
        else if (req.claims.ten) {
            var authorized;
            if (req.claims.ten.whitelist) {
                for (var tenant in req.claims.ten.whitelist) {
                    if (req.params.tenant === tenant) {
                        authorized = true;
                        break;
                    }
                }
            }
            else if (req.claims.ten.regex.test(req.params.tenant)) {
                authorized = true;
            }

            if (authorized) {
                return next();
            }

            msg = { code: 403, message: 'not authorized to perform operation on tenant `' + req.params.tenant + '`', req_id: req.req_id };
            ctx.logger.warn({
                req_id: req.req_id,
                path: req.originalUrl,
                method: req.method,
                jwt: req._jwt
            }, msg.message);
        }
        else {
            return next();
        }

        if (msg) {
            res.status(msg.code);
            return res.send(msg);
        }
        else {
            res.status(403);
            return res.end();
        }
    };
};

var lru; // LRU cache of token revocation information

exports.ensure_authenticated = function(ctx) {

    if (!lru) {
        lru = LRU({
            max: +ctx.config.max_revocation_cache_size.current,
            maxAge: 1000 * +ctx.config.max_revocation_cache_age.current
        });
        ctx.config.max_revocation_cache_size.on('modified', function (new_max) {
            lru.max = +new_max;
            ctx.config.info({ max: +new_max }, 'Setting new maximum size of the revocation check LRU cache');
        });
        ctx.config.max_revocation_cache_age.on('modified', function (new_age) {
            lru._maxAge = 1000 * +new_age;
            ctx.config.info({ max_age: +new_age }, 'Setting new maximum age in seconds of the revocation check LRU cache');
        });
    }

    // ctx must have logger and config attached to it
    // Let pass requests with:
    // 1) JWT token signed with one of current signature keys
    // 2) one of the current signature or encryption keys presented as opaque keys
    // If JWT is used:
    // 1) decrypt encrypted claims if present
    // 2) perform revocation check
    // 3) normalize webtask claims by inheriting values from pctx or ectx
    // Store JWT payload in req.claims.
    return function (req, res, next) {
        var msg;
        if (req.headers['authorization']) {
            var ts = req.headers['authorization'].split(' ');
            if (ts.length === 2 && ts[0] === 'Bearer') {
                return parse_credential(ts[1]);
            }
            else {
                msg = { code: 403, message: 'rejecting request with unexpected Authorization header', req_id: req.req_id };
                ctx.logger.warn({
                    req_id: req.req_id,
                    path: req.originalUrl,
                    method: req.method,
                    authorization: req.headers['authorization']
                }, msg.message);
                res.status(msg.code);
                return res.send(msg);
            }
        }
        else if (req.query.key) {
            return parse_credential(req.query.key);
        }
        else {
            msg = { code: 403, message: 'rejecting request without Authorization header or key URL query parameter', req_id: req.req_id };
            ctx.logger.warn({
                req_id: req.req_id,
                path: req.originalUrl,
                method: req.method
            }, msg.message);
            res.status(msg.code);
            return res.send(msg);
        }

        function parse_credential(credential) {
            var jwt = jws.decode(credential);

            async.series([
                function (callback) {
                    // Process if JWT
                    if (!jwt) return callback();

                    if (typeof (jwt.header.kid) !== 'string' || !ctx.config.keysets.set[jwt.header.kid]) {
                        msg = { code: 403, message: 'rejecting request with JWT token signed with untrusted key', req_id: req.req_id };
                        ctx.logger.warn({
                            req_id: req.req_id,
                            path: req.originalUrl,
                            method: req.method,
                            credential: credential
                        }, msg.message);
                        return callback(msg);
                    }

                    if (!jws.verify(credential, ctx.config.keysets.set[jwt.header.kid].signature_key)) {
                        msg = { code: 403, message: 'rejecting request with JWT token that fails signature validation', req_id: req.req_id };
                        ctx.logger.warn({
                            req_id: req.req_id,
                            path: req.originalUrl,
                            method: req.method,
                            keyset: jwt.header.kid,
                            credential: credential
                        }, msg.message);
                        return callback(msg);
                    }

                    try {
                        jwt.payload = JSON.parse(jwt.payload);
                    }
                    catch (e) {
                        msg = { code: 500, message: 'error deserializing JWT token payload', req_id: req.req_id };
                        ctx.logger.error({
                            req_id: req.req_id,
                            path: req.originalUrl,
                            method: req.method,
                            keyset: jwt.header.kid,
                            payload: jwt.payload,
                            credential: credential
                        }, msg.message);
                        return callback(msg);
                    }

                    var now = Math.floor(Date.now() / 1000);
                    if (!isNaN(jwt.payload.nbf) && jwt.payload.nbf > now) {
                        msg = { code: 403, message: 'not yet valid JWT token', req_id: req.req_id };
                        ctx.logger.warn({
                            req_id: req.req_id,
                            path: req.originalUrl,
                            method: req.method,
                            credential: credential
                        }, msg.message);
                        return callback(msg);
                    }

                    if (!isNaN(jwt.payload.exp) && jwt.payload.exp < now) {
                        msg = { code: 403, message: 'expired JWT token', req_id: req.req_id };
                        ctx.logger.warn({
                            req_id: req.req_id,
                            path: req.originalUrl,
                            method: req.method,
                            credential: credential
                        }, msg.message);
                        return callback(msg);
                    }

                    if (!+ctx.config.enable_revocation_check.current) {
                        // Skip revocation check
                        return callback();
                    }

                    check_revocation(jwt, function (error, valid) {
                        if (error) {
                            msg = { code: 502, message: 'Revocation check failed', req_id: req.req_id };
                            ctx.logger.error({
                                req_id: req.req_id,
                                path: req.originalUrl,
                                method: req.method,
                                credential: credential,
                                error: error
                            }, msg.message);
                            if (ctx.config.reject_on_revocation_check_error.current) {
                                return callback(msg);
                            }
                        }
                        else if (!valid) {
                            msg = { code: 403, message: 'Token is revoked', req_id: req.req_id };
                            ctx.logger.warn({
                                req_id: req.req_id,
                                path: req.originalUrl,
                                method: req.method,
                                credential: credential,
                            }, msg.message);
                            return callback(msg);
                        }
                        return callback();
                    });
                },
                function (callback) {
                    // Continue processing if JWT token
                    if (!jwt) return callback();

                    var ectx;
                    if (jwt.payload.ectx) {
                        // decrypt encrypted context
                        try {
                            ectx = jwt.payload.ectx.split('.');
                            ectx[0] = new Buffer(ectx[0], 'base64'); // ciphertext
                            ectx[1] = new Buffer(ectx[1], 'base64'); // iv
                            var cipher = crypto.createDecipheriv(
                                'aes-256-cbc',
                                ctx.config.keysets.set[jwt.header.kid].encryption_key_raw,
                                ectx[1]);
                            var plaintext = cipher.update(ectx[0], 'base64', 'utf8') + cipher.final('utf8');
                            ectx = JSON.parse(plaintext);
                            if (!ectx || typeof ectx !== 'object')
                                throw null;
                            jwt.payload.ectx = true;
                        }
                        catch (e) {
                            msg = { code: 500, message: 'error decrypting JWT token context', req_id: req.req_id };
                            ctx.logger.error({
                                req_id: req.req_id,
                                path: req.originalUrl,
                                method: req.method,
                                keyset: jwt.header.kid,
                                ectx: jwt.payload.ectx,
                                credential: credential
                            }, msg.message);
                            return callback(msg);
                        }
                    }
                    if (jwt.payload.ten)
                        jwt.payload.ten = parse_ten(jwt.payload.ten);
                    ctx.logger.info({
                        req_id: req.req_id,
                        path: req.originalUrl,
                        method: req.method,
                        keyset: jwt.header.kid,
                        claims: jwt.payload
                    }, 'request authenticated with JWT token');
                    if (ectx)
                        jwt.payload.ectx = ectx;
                    req.claims = jwt.payload;
                    req._jwt = credential;

                    // inherit webtask claims from pctx and ectx
                    ['url', 'pb', 'mb'].forEach(function (claim) {
                        if (req.claims.ectx && req.claims.ectx['webtask_' + claim])
                            req.claims[claim] = req.claims.ectx['webtask_' + claim];
                        else if (req.claims.pctx && req.claims.pctx['webtask_' + claim])
                            req.claims[claim] = req.claims.pctx['webtask_' + claim];
                    });
                    
                    return callback();
                },
                function (callback) {
                    // Process if opaque key
                    if (jwt) return callback();

                    // Check for match with signature or encryption keys
                    // of currently accepted keysets
                    for (var id in ctx.config.keysets.set) {
                        var keyset = ctx.config.keysets.set[id];
                        if (keyset.signature_key === credential || keyset.encryption_key === credential) {
                            ctx.logger.info({
                                req_id: req.req_id,
                                path: req.originalUrl,
                                method: req.method,
                                keyset: id
                            }, 'request authenticated with opaque key');
                            req.claims = {}; // unrestricted access
                            req._jwt = false;
                            return callback();
                        }
                    }
                    msg = { code: 403, message: 'rejecting request with untrusted opaque key', req_id: req.req_id };
                    ctx.logger.warn({
                        req_id: req.req_id,
                        path: req.originalUrl,
                        method: req.method,
                        credential: credential
                    }, msg.message);
                    return callback(msg);
                }
            ], function (error) {
                if (error) {
                    res.status(error.code);
                    return res.send(error);
                }
                else {
                    return next();
                }
            });
        }

        function check_revocation(jwt, callback) {
            // Check revocation status of the JWT token and its issuance chain
            var ca = jwt.payload.ca || [];
            if (jwt.payload.jti) {
                ca.push(jwt.payload.jti);
            }
            var valid = true;
            var url = ctx.config.revocation_url.current 
                + (ctx.config.revocation_url.current.indexOf('?') > 0 ? '&jti=' : '?jti=');
            async.each(ca, function (jti, callback) {
                var jti_valid = lru.get(jti);
                if (jti_valid === undefined) {
                    // Revocation info not in cache, call revocation URL
                    request(url + jti, function (error, res, body) {
                        if (error) return callback(error);
                        if (res.statusCode === 200) 
                            valid = jti_valid = false;
                        else if (res.statusCode === 404)
                            jti_valid = true;
                        else
                            return callback(new Error('Error response from revocation URL. HTTP status ' + res.statusCode + '. Body: ' + body));
                        lru.set(jti, jti_valid);
                        return callback();
                    });
                }
                else {
                    // Use revocation info from cache
                    if (!jti_valid)
                        valid = false;
                    return callback();
                }
            }, function (error) {
                callback(error, valid);
            });
        }
    };
};

function parse_ten(ten) {
    if (ten[0] === '/') {
        // Assume regex
        try {
            ten = { regex: new RegExp(ten.substring(1, ten.length - 1)) };
        }
        catch (e) {
            return { code: 400, message: 'the `ten` claim cannot be parsed as a regular expression' };
        }
    }
    else {
        // Assume comma delimied list of tenants
        ten = ten.split(',');
        var result = { whitelist: {}};
        for (var i in ten) {
            ten[i] = ten[i].trim();
            if (ten[i].length === 0)
                return { code: 400, message: 'the `ten` claim cannot contain a list with empty entries' };
            result.whitelist[ten[i]] = 1;
        }
        ten = result;
    }

    return ten;
}
