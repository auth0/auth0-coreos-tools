var jws = require('jws')
    , uuid = require('uuid')
    , crypto = require('crypto');

var allowed_request_claims = {
    url: 'string',
    pctx: 'object',
    ectx: 'object',
    ten: 'object',
    exp: 'number',
    nbf: 'number'
};

exports.validate_token_issue_request = function(req, claims) {
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

    // Validate claim subsetting rules

    var fixed_claims = ['url', 'pctx', 'ectx'];
    for (var i in fixed_claims) {
        var claim = fixed_claims[i];
        if (req[claim] !== undefined && claims[claim] !== undefined)
            return { code: 400, message: 'the `' + claim + '` claim cannot be specified if the authentication token already specifies it' };
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
        iat: Date.now()
    };

    // Create claims of the new token observing inheritance rules

    ['url', 'exp', 'nbf', 'ten', 'pctx', 'ectx'].forEach(function (claim) {
        if (req[claim] !== undefined || claims[claim] !== undefined)
            new_claims[claim] = req[claim] !== undefined ? req[claim] : claims[claim];
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

exports.ensure_authenticated = function(ctx) {
    // ctx must have logger and config attached to it
    // Let pass requests with:
    // 1) JWT token signed with one of current signature keys
    // 2) one of the current signature or encryption keys presented as opaque keys
    // If JWT is used, also decrypt encrypted claims if present. 
    // Store JWT payload in req.claims.
    return function (req, res, next) {
        var msg;
        if (req.headers['authorization']) {
            var ts = req.headers['authorization'].split(' ');
            if (ts.length === 2 && ts[0] === 'Bearer') {
                return parse_credential(ts[1]);
            }
            else {
                msg = { code: 403, message: 'rejecting request with unexpected Authorization header' };
                ctx.logger.warn({
                    path: req.originalUrl,
                    method: req.method,
                    authorization: req.headers['authorization']
                }, msg.message);
                return res.status(msg.code).end(JSON.stringify(msg));
            }
        }
        else if (req.query.key) {
            return parse_credential(req.query.key);
        }
        else {
            msg = { code: 403, message: 'rejecting request without Authorization header or key URL query parameter' };
            ctx.logger.warn({
                path: req.originalUrl,
                method: req.method
            }, msg.message);
            return res.status(msg.code).end(JSON.stringify(msg));
        }

        function parse_credential(credential) {
            var msg;
            var jwt = jws.decode(credential);
            if (jwt) {
                // This is a JWT
                if (typeof (jwt.header.kid) === 'string' && ctx.config.keysets.set[jwt.header.kid]) {
                    if (jws.verify(credential, ctx.config.keysets.set[jwt.header.kid].signature_key)) {
                        try {
                            jwt.payload = JSON.parse(jwt.payload);
                        }
                        catch (e) {
                            msg = { code: 500, message: 'error deserializing JWT token payload' };
                            ctx.logger.error({
                                path: req.originalUrl,
                                method: req.method,
                                keyset: jwt.header.kid,
                                payload: jwt.payload,
                                credential: credential
                            }, msg.message);
                            return res.status(500).end(JSON.stringify(msg));
                        }
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
                                msg = { code: 500, message: 'error decrypting JWT token context' };
                                ctx.logger.error({
                                    path: req.originalUrl,
                                    method: req.method,
                                    keyset: jwt.header.kid,
                                    ectx: jwt.payload.ectx,
                                    credential: credential
                                }, msg.message);
                                return res.status(500).end(JSON.stringify(msg));
                            }
                        }
                        if (jwt.payload.ten)
                            jwt.payload.ten = parse_ten(jwt.payload.ten);
                        ctx.logger.info({
                            path: req.originalUrl,
                            method: req.method,
                            keyset: jwt.header.kid,
                            claims: jwt.payload
                        }, 'request authenticated with JWT token');
                        if (ectx)
                            jwt.payload.ectx = ectx;
                        req.claims = jwt.payload;
                        return next();
                    }
                    else {
                        msg = { code: 403, message: 'rejecting request with JWT token that fails signature validation' };
                        ctx.logger.warn({
                            path: req.originalUrl,
                            method: req.method,
                            keyset: jwt.header.kid,
                            credential: credential
                        }, msg.message);
                    }
                }
                else {
                    msg = { code: 403, message: 'rejecting request with JWT token signed with untrusted key' };
                    ctx.logger.warn({
                        path: req.originalUrl,
                        method: req.method,
                        credential: credential
                    }, msg.message);
                }
            }
            else {
                // Assume opaque key, check for match with signature or encryption keys
                // of currently accepted keysets
                for (var id in ctx.config.keysets.set) {
                    var keyset = ctx.config.keysets.set[id];
                    if (keyset.signature_key === ts[1] || keyset.encryption_key === ts[1]) {
                        ctx.logger.info({
                            path: req.originalUrl,
                            method: req.method,
                            keyset: id
                        }, 'request authenticated with opaque key');
                        req.claims = {}; // unrestricted access
                        return next();
                    }
                }
                msg = { code: 403, message: 'rejecting request with untrusted opaque key' };
                ctx.logger.warn({
                    path: req.originalUrl,
                    method: req.method,
                    credential: credential
                }, msg.message);
            }
            if (msg)
                return res.status(msg.code).end(JSON.stringify(msg));
            else
                return res.status(403).end();
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
