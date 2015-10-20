var assert = require('assert')
    , aws = require('aws-sdk')
    , LRU = require('lru-cache')
    ;

var dynamo;
var lru; // LRU cache of token revocation information

exports.init = function (options) {
    assert.ok(options);
    assert.ok(options.config);
    assert.ok(options.logger);

    if (!lru) {
        lru = LRU({
            max: +options.config.max_revocation_cache_size.current,
            maxAge: 1000 * +options.config.max_revocation_cache_age.current
        });
        options.config.max_revocation_cache_size.on('modified', function (new_max) {
            lru.max = +new_max;
            options.logger.info({ max: +new_max }, 'setting new maximum size of the revocation check LRU cache');
        });
        options.config.max_revocation_cache_age.on('modified', function (new_age) {
            lru._maxAge = 1000 * +new_age;
            options.logger.info({ max_age: +new_age }, 'setting new maximum age in seconds of the revocation check LRU cache');
        });
    }

    if (!dynamo) {
        // Create DynamoDB client 
        aws.config.accessKeyId = options.config.aws_access_key_id.current;
        aws.config.secretAccessKey = options.config.aws_secret_access_key.current;
        aws.config.region = options.config.aws_revocation_region.current;
        aws.config.sslEnabled = true;
        dynamo = new aws.DynamoDB({ params: { TableName: options.config.aws_revocation_table.current }});
    }

    return {

        check_revocation: function (req_id, jwt, callback) {
            // Check revocation status of the JWT token and its issuance chain
            var ca = [];
            if (jwt.payload.ca)
                jwt.payload.ca.forEach(function (jti) { ca.push(jti); });
            if (jwt.payload.jti)
                ca.push(jwt.payload.jti);
            var valid = true;
            async.each(ca, function (jti, callback) {
                if (options.config.revocation_whitelist.list[jti]) {
                    // Whitelisted jti
                    options.logger.info({ 
                        req_id: req_id,
                        jti: jti
                    }, 'revocation check whitelist match');
                    return callback();
                }
                var jti_valid = lru.get(jti);
                if (jti_valid === undefined) {
                    // Revocation info not in cache, check in Dynamo

                    options.logger.info({ 
                        req_id: req_id,
                        jti: jti, 
                    }, 'starting revocation check in DB');

                    var start = Date.now();
                    dynamo.query({
                        KeyConditions: {
                            jti: { 
                                ComparisonOperator: 'EQ',
                                AttributeValueList: [ { S: jti } ]
                            }
                        }
                    }, function (err, data) {
                        if (err) {
                            options.logger.warn({ 
                                req_id: req_id,
                                jti: jti, 
                                dynamo_req_id: this && this.requestId,
                                revocation_check_latency: Date.now() - start,
                                error: err.message
                            }, 'error checking revocation in DB');
                            return callback(err);
                        }

                        if (data.Count > 0)
                            valid = jti_valid = false;
                        else
                            jti_valid = true;

                        lru.set(jti, jti_valid);

                        options.logger.info({ 
                            req_id: req_id,
                            jti: jti, 
                            valid: jti_valid,
                            dynamo_req_id: this && this.requestId,
                            revocation_check_latency: Date.now() - start 
                        }, 'completed revocation check in DB');

                        return callback();
                    });
                }
                else {
                    // Use revocation info from cache
                    options.logger.info({ 
                        req_id: req_id,
                        jti: jti, 
                        valid: jti_valid 
                    }, 'revocation check cache result');
                    if (!jti_valid)
                        valid = false;
                    return callback();
                }
            }, function (error) {
                callback(error, valid);
            });
        },

        revoke_token: function (jti, jwt, callback) {
            lru.del(jti);
            dynamo.putItem({
                Item: {
                    jti: { S: jti },
                    jwt: { S: jwt },
                    t: { S: (new Date()).toString() }
                }
            }, function (error) {
                lru.del(jti);
                callback(error);
            });
        },
    };
};
