var async = require('async')
    , assert = require('assert')
    , host = process.env.COREOS_HOST || '127.0.0.1'
    , etcd = new (require('node-etcd'))(host)
    , bunyan = require('bunyan')
    , Stream = require('stream').Stream
    , util = require('util')
    , EventEmitter = require('events').EventEmitter
    , url = require('url')
    , http = require('http')
    , tripwire = require('tripwire')
    , zmq = require('zmq')
    ;

exports.webtask = require('./webtask.js');

var last_resort_logger = bunyan.createLogger({ name: 'auth0-coreos-tools-last-resort-logging' });

var ZmqStream = exports.ZmqStream = function (options) {
    assert.ok(options, 'options must be specified');
    assert.ok(typeof options === 'object', 'options must be an object');
    assert.ok(Array.isArray(options.topics), 'options.topic must be an array of string topics');
    Stream.call(this);
    this.name = options.name || 'zmq';
    this.writable = true;
    this.options = options;
    this._publisher = options.socket;
    if (!this._publisher) {
        this._publisher = zmq.socket('pub');
        this._publisher.connect('tcp://localhost:8700');
    }
};

util.inherits(ZmqStream, Stream);

ZmqStream.prototype.close = function close() {
    if (this.writable) {
        this.writable = false;
        this._publisher.disconnect();
    }
};

ZmqStream.prototype.destroy = function destroy() {
    this.close();
};

ZmqStream.prototype.end = function end(m) {
    if (m) {
        this.write(m);
    }

    this.close();
};

ZmqStream.prototype.write = function write(m) {
    if (!this.writable) {
        this.emit('error', new Error('Attempt to write to Zmq after stream was closed.'));
    }
    else {
        var message;
        var _topics = m._topics;
        var self = this;
        if (Array.isArray(_topics)) {
            delete m._topics;
            message = JSON.stringify(m);
            _topics.forEach(function (topic) {
                self._publisher.send([ topic, message ]);
            })
        }
        else {
            message = JSON.stringify(m);
        }
        this.options.topics.forEach(function (topic) {
            self._publisher.send([ topic, message ]);
        });
    }
};

var GoogleAnalyticsStream = exports.GoogleAnalyticsStream = function (options) {
    assert.ok(options, 'options must be specified');
    assert.ok(typeof options === 'object', 'options must be an object');
    assert.ok(typeof options.property_id === 'string', 'options.property_id must be specfied');
    Stream.call(this);
    this.name = options.name || 'google_analytics';
    this.writable = true;
    this.options = options;
};

util.inherits(GoogleAnalyticsStream, Stream);

GoogleAnalyticsStream.prototype.close = function close() {
    this.writable = false;
};

GoogleAnalyticsStream.prototype.destroy = function destroy() {
    this.writable = false;
};

GoogleAnalyticsStream.prototype.end = function end() {
    if (arguments.length > 0)
        this.write.apply(this, Array.prototype.slice.call(arguments));

    this.writable = false;
};

GoogleAnalyticsStream.prototype.write = function write(r) {
    if (!this.writable)
        return;
    if (!r)
        return;

    assert.ok(typeof r === 'object', 'GoogleAnalyticsStream can only log raw objects');

    // Create Google Analytics event out of a bunyan record

    var event = {
        v: 1,
        tid: this.options.property_id,
        sc: 'start',
        t: 'event',
        cid: '11111111-1111-1111-1111-111111111111',
        ea: r.msg.substring(0, 512),
        ec: r.level >= 50 ? 'ERROR' : (r.level >= 40 ? 'WARNING' : 'INFO'),
        el: r.name + '/' + r.hostname
    };

    // Form-url-encode the event data.

    var data = url.format({ query: event }).substring(1);

    // Send the Google Analytics request, do not wait for response.

    var greq = http.request({
        hostname: 'www.google-analytics.com',
        port: 80,
        path: '/collect',
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
    }, function (gres) {
        gres.on('data', function () {});
        gres.on('end', function () {});
    });

    greq.write(data);
    greq.end();
};

function create_logger(options) {
    assert.ok(options);
    assert.ok(options.name);
    // options.topics
    // options.google_analytics_id
    // options.socket

    var logger_options = {
        name: options.name,
        streams: [{ level: 'info', stream: process.stdout }]
    };

    var zmq_stream;
    if (Array.isArray(options.topics)) {
        // Enable zmq stream
        zmq_stream = new ZmqStream({
            topics: options.topics,
            socket: options.socket
        });
        zmq_stream.on('error', function (error) {
            last_resort_logger.error(error, 'ZmqStream error');
            // ignore errors
        });
        logger_options.streams.push({ level: 'info', stream: zmq_stream, type: 'raw' });
    }

    var google_stream;
    if (options.google_analytics_id && typeof options.google_analytics_id === 'string' && options.google_analytics_id.length > 0) {
        google_stream = new GoogleAnalyticsStream({ property_id: options.google_analytics_id });
        logger_options.streams.push({ level: 'warn', stream: google_stream, type: 'raw' });
    }

    var result = bunyan.createLogger(logger_options);
    result.on('error', function (error) {
        last_resort_logger.error(error, 'composite logger error');
        // ignore errors
    });

    return result;
};

exports.create_logger = create_logger;

var logger = create_logger({
    name: 'auth0-coreos-tools', 
    topics: ['system']
});

exports.set_logger = function (new_logger) {
    logger = new_logger.child({ 'auth0-coreos-tools' : 1 });
};

// Accepts an array of strings as configuration keys. 
// Each {key1} corresponds to /config/{key1} entry in etcd.
// Returns an object with properties corresponding to input keys. 
// Each property is an EventEmitter. It emits the `modified` event
// when the value of the configuration key. In addition, each EventEmitter
// has a `current` property which returns the current string value stored in etcd. 
exports.etcd_config = function (keys, path, callback) {
    if (typeof path === 'function') {
        callback = path;
        path = '/config/';
    }
    var config = {};
    async.each(
        keys,
        function (key, callback) {
            etcd.get(path + key, function (error, result) {
                if (error) {
                    error.key = path + key;
                    logger.error(error, 'unable to read etcd key');
                    return callback(error);
                }

                var watch = etcd.watcher(path + key, result.node.modifiedIndex + 1);
                watch.current = result.node.value;
                watch.on('change', function (result) {
                    if (watch.current !== result.node.value)
                        this.emit('modified', result.node.value);
                    watch.current = result.node.value;
                });
                watch.on('error', function (error) {
                    error.key = path + key;
                    logger.error(error, 'error watching etcd key');
                    throw error; // TODO (tjanczuk): consider surfacing etcd errors differently?
                });

                config[key] = watch;
                callback();
            });
        },
        function (error) {
            callback && (error ? callback(error) : callback(null, config));
        }
    );

    return config; // for convenience of REPL
};

// Converts response from etcd into a JS object representing only
// the data and its hierarchy. Etcd directories are represented as JS objects.

function etcd2js(node) {
    if (node.value !== undefined)
        return node.value;
    var result = {};
    if (Array.isArray(node.nodes)) {
        node.nodes.forEach(function (child) {
            result[child.key.substring(node.key.length === 1 ? 1 : node.key.length + 1)] 
                = etcd2js(child);
        });
    }
    return result;
}

exports.etcd2js = etcd2js;

// Gets the key from etcd (recursively) and returns a JS representation of
// the hierarchy.
exports.etcd_get = function (key, callback) {
    etcd.get(key, { recursive: true }, function (error, result) {
        error ? callback(error): callback(null, etcd2js(result.node));
    });
};

// Convert object property names to uppercase
exports.upper = function (o) {
    var r = {};
    for (var k in o) 
        r[k.toUpperCase()] = typeof o[k] === 'object' ? upper(o[k]) : o[k];
    return r;
};

// The .lowr async function completes in either of two situations:
//
// 1. If the sync_root is not locked, it obtains an exclusive, distributed lock of the sync_root 
// via etcd and returns a function that can be used to release the lock as a callback parameter. 
//
// 2. If the sync_root is locked, it waits for that lock to be released, and returns without any results.
//
// This logic allows several homogenic, distributed processes to ensure that a certain workload is
// completed by only one of them. 
//
// The lock TTL in etcd is configured with the `/config/lock.ttl` confguration entry. 
// While the lock is held, it is reset to that TTL every `/config/lock.renew` period. 
var lock_id = process.pid + '.' + Math.floor(999999 * Math.random());
exports.lowr = function (sync_root, etcdconfig, callback) {
    logger.info({ sync_root: sync_root }, 'lowr enter');
    // Attempt to take the lock
    var path = '/lock/' + sync_root;
    etcd.set(
        path, 
        lock_id, 
        { prevExist: false, ttl: +etcdconfig.lock_ttl.current },
        function (error, result) {
            if (error) {
                if (error.errorCode === 105) {
                    // Lock is currently held, wait for its release

                    logger.info({ sync_root: sync_root }, 'lowr lock already taken');
                    
                    var watch = etcd.watcher(path, error.error.index + 1);
                    watch.on('change', function (result) {
                        logger.info({ sync_root: sync_root, end_wait: result.node.value === undefined, node: result.node }, 'lowr lock change event')
                        if (result.node.value === undefined)
                            done();
                    });
                    watch.on('error', done);

                    // Set up a poll as a catch-all since etcd watch is not fully reliable

                    var done_called;
                    var poll = setTimeout(poll_one, +etcdconfig.lock_poll_interval.current);
                    function poll_one() {
                        poll = undefined;
                        etcd.get(path, function (error, result) {
                            if (error) {
                                if (error.errorCode === 100) {
                                    logger.info({ sync_root: sync_root }, 'lowr poll indicated lock release');
                                    done(); // key not found - lock released
                                }
                                else {
                                    logger.error(error, 'lowr poll error');
                                    done(error);
                                }
                            }
                            else if (!done_called)
                                poll = setTimeout(poll_one, +etcdconfig.lock_poll_interval.current);
                        });
                    }

                    function done(error) {
                        if (done_called) return;
                        done_called = true;
                        if (error)
                            logger.error(error, 'lowr wait error');
                        else
                            logger.info({ sync_root: sync_root }, 'lowr finished wait');
                        watch.stop();
                        if (poll)
                            clearTimeout(poll);
                        callback(error);
                    }

                    return;
                }

                logger.error({ sync_root: sync_root, error: error }, 'lowr etcd error');

                return callback(error);
            }

            var current_lock = Math.floor(Math.random() * 999999);
            logger.info({ sync_root: sync_root, lock_num: current_lock }, 'lowr obtained lock');

            // Lock was taken, renew it periodically until released

            var renew = setInterval(function () {
                logger.info({ sync_root: sync_root, lock_num: current_lock }, 'lowr renew lock');
                etcd.set(path, lock_id, { ttl: +etcdconfig.lock_ttl.current });
            }, +etcdconfig.lock_renew.current * 1000);

            // Return a function that must be used to release the lock

            callback(null, function (callback) {
                logger.info({ sync_root: sync_root, lock_num: current_lock }, 'lowr delete lock');
                clearInterval(renew);
                etcd.compareAndDelete(path, lock_id, function (error) {
                    return callback && callback(error);
                });
            });
        });
};

exports.setup_tripwire = function (tripwire_timeout_ms) {

    logger.info({ timeout: tripwire_timeout_ms }, 'setting up tripwire to detect blocked event loop');

    var tripwire_context = {};

    process.on('uncaughtException', function (e) {
        var code;        
        if (tripwire_context === tripwire.getContext()) {
            logger.error({ timeout: tripwire_timeout_ms },
                'process blocked the event loop and is terminated');
            code = 66;
        }
        else {
            logger.error(e, 'process generated uncaught exception and is terminated');
            code = 1;
        }
        setTimeout(function () {
            process.exit(code);
        }, 500);
    });        

    // Set up tripwire to terminate the process if the event loop becomes blocked 

    tripwire.resetTripwire(tripwire_timeout_ms, tripwire_context);
    setInterval(function () {
        tripwire.resetTripwire(tripwire_timeout_ms, tripwire_context);
    }, tripwire_timeout_ms / 2);

};