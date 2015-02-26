var async = require('async')
    , assert = require('assert')
    , host = process.env.COREOS_HOST || '127.0.0.1'
    , etcd = new (require('node-etcd'))(host)
    , winston = require('winston')
    , bunyan = require('bunyan')
    , Stream = require('stream').Stream
    , util = require('util')
    , kafka = require('kafka-node')
    , EventEmitter = require('events').EventEmitter
    , url = require('url')
    , http = require('http')
    , tripwire = require('tripwire');

exports.webtask = require('./webtask.js');

var last_resort_logger = bunyan.createLogger({ name: 'auth0-coreos-tools-last-resort-logging' });

var KafkaStream = exports.KafkaStream = function (options) {
    assert.ok(options, 'options must be specified');
    assert.ok(typeof options === 'object', 'options must be an object');
    assert.ok(typeof options.zookeeper === 'string', 'options.zookeeper must be specfied');
    assert.ok(Array.isArray(options.topics), 'options.topic must be an array of string topics');
    Stream.call(this);
    this.name = options.name || 'kafka';
    this.writable = true;
    this.options = options;
    this._pending = [];
    this._client = new kafka.Client(this.options.zookeeper, 'kafka-transport');
    this._producer = new kafka.Producer(this._client);
    var self = this;
    this._producer
        .once('ready', function () {
            self._ready = true;
            KafkaStream.prototype._send_pending.apply(self);
        })
        .on('error', function (error) {
            last_resort_logger.error(error, 'kafka logging error');
            self.emit('error', error);
        });
};

util.inherits(KafkaStream, Stream);

KafkaStream.prototype.close = function close() {
    if (!this._closed) {
        this._closed = true;
        this.writable = false;
        if (this._pending.length > 0)
            this._close_pending = true;
        else {
            try {
                this._client.close();
            }
            catch (e) {
                this.emit('error', e);
            }
        }
    }
};

KafkaStream.prototype.destroy = function destroy() {
    this.writable = false;
    this.close();
};

KafkaStream.prototype.end = function end() {
    if (arguments.length > 0)
        this.write.apply(this, Array.prototype.slice.call(arguments));

    this.writable = false;
    this.close();
};

KafkaStream.prototype.write = function write(r) {
    if (!this.writable)
        this.emit('error', new Error('Attempt to write to Kafka after stream was closed.'));
    else {
        this._pending.push(r);
        this._send_pending();
    }
};

KafkaStream.prototype._send_pending = function () {
    if (this._ready && this._pending.length > 0) {
        var current = this._pending;
        this._pending = [];
        var messages = [];
        var message_topics = {};
        current.forEach(function (entry) {
            var _topics = entry._topics;
            var json_message;
            if (Array.isArray(_topics)) {
                delete entry._topics;
                json_message = JSON.stringify(entry);
                _topics.forEach(function (topic) {
                    if (message_topics[topic])
                        message_topics[topic].push(json_message);
                    else
                        message_topics[topic] = [ json_message ];
                });
            }
            else
                json_message = JSON.stringify(entry);

            messages.push(json_message);
        });
        var payload = [];
        this.options.topics.forEach(function (topic) {
            payload.push({
                topic: topic,
                messages: messages
            });
        });
        for (var topic in message_topics) {
            payload.push({
                topic: topic,
                messages: message_topics[topic]
            });
        }
        var self = this;
        try {
            this._producer.send(payload, function (error) {
                if (error)
                    last_resort_logger.error(error, 'kafka logging error');
                if (self._close_pending) {
                    self.writable = false;
                    self.close();
                }
            });
        }
        catch (e) {
            self.emit('error', e);
        }
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

function create_logger(name, topics, google_analytics_id) {
    var logger_options = {
        name: name,
        streams: [{ level: 'info', stream: process.stdout }]
    };

    var kafka_stream;
    if (Array.isArray(topics) && process.env.KAFKA_ZOOKEEPER) {
        // Enable Kafka stream
        kafka_stream = new KafkaStream({
            zookeeper: process.env.KAFKA_ZOOKEEPER,
            topics: topics
        });
        kafka_stream.on('error', function (error) {
            last_resort_logger.error(error, 'KafkaStream error');
            // ignore errors
        });
        logger_options.streams.push({ level: 'info', stream: kafka_stream, type: 'raw' });
    }

    var google_stream;
    if (google_analytics_id && typeof google_analytics_id === 'string' && google_analytics_id.length > 0) {
        google_stream = new GoogleAnalyticsStream({ property_id: google_analytics_id });
        logger_options.streams.push({ level: 'warn', stream: google_stream, type: 'raw' });
    }

    var result = bunyan.createLogger(logger_options);
    var closed;
    result.close = function () {
        if (!closed) {
            closed = true;
            if (kafka_stream) {
                kafka_stream.close();
                kafka_stream = undefined;
            }
            if (google_stream) {
                google_stream.close();
                google_stream = undefined;
            }
        }
    };
    result.on('error', function (error) {
        last_resort_logger.error(error, 'composite logger error');
        // ignore errors
    });

    return result;
};

exports.create_logger = create_logger;

var logger = create_logger('auth0-coreos-tools', ['system']);

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

var KafkaTransport = exports.KafkaTransport = function (options) {
    assert.ok(options, 'options must be specified');
    assert.ok(typeof options === 'object', 'options must be an object');
    assert.ok(typeof options.zookeeper === 'string', 'options.zookeeper must be specfied');
    assert.ok(Array.isArray(options.topics), 'options.topic must be an array of string topics');
    this.name = options.name || 'kafka';
    this.level = options.level || 'info';
    this.options = options;
    this._pending = [];
    this._client = new kafka.Client(this.options.zookeeper, 'kafka-transport');
    this._producer = new kafka.Producer(this._client);
    var self = this;
    this._producer
        .once('ready', function () {
            self._ready = true;
            self._send_pending();
        })
        .on('error', function (error) {
            self._error = error;
            winston.error('winston-kafka error', error);
        });
};

util.inherits(KafkaTransport, winston.Transport);

KafkaTransport.prototype.log = function (level, msg, meta, callback) {
    if (!this._error) {
        this._pending.push({ time: new Date(), level: level, msg: msg, meta: meta, callback: callback });
        this._send_pending();
    }
    else 
        callback(this._error);
};

KafkaTransport.prototype._send_pending = function () {
    if (this._ready && this._pending.length > 0) {
        var current = this._pending;
        this._pending = [];
        var messages = [];
        current.forEach(function (entry) {
            var meta;
            if (entry.meta && Object.getOwnPropertyNames(entry.meta).length > 0)
                meta = ' ' + util.inspect(entry.meta);
            messages.push(
                entry.time.toISOString() + ' ' 
                + entry.level + ': ' 
                + entry.msg 
                + (meta || '')
            );
        });
        var payload = [];
        this.options.topics.forEach(function (topic) {
            payload.push({
                topic: topic,
                messages: messages
            });
        });
        this._producer.send(payload, function (error) {
            current.forEach(function (entry) {
                entry.callback && entry.callback(error);
            });
        });
    }
};

exports.setup_kafka = function (options, callback) {
    var ev = new EventEmitter();
    var config;
    var zookeeper;

    async.series([
        function (callback) {
            // Get config for enable_kafka_logs
            last_resort_logger.info('checking if kafka logging is enabled');
            exports.etcd_config([
                'enable_kafka_logs',
                'google_analytics_id'
            ], function (error, data) {
                config = data;
                callback(error);
            });
        },
        function (callback) {
            // Get zookeeper config
            last_resort_logger.info({ enable_kafka_logs: +config.enable_kafka_logs.current }, 'kafka logs enabled');
            if (+config.enable_kafka_logs.current)
                setup_zookeeper(callback);
            else
                callback();
        },
        function (callback) {
            // Set up first logger
            setup_logger(+config.enable_kafka_logs.current, zookeeper ? zookeeper.route.current : undefined, config.google_analytics_id.current);

            // Keep track of changes to logging settings
            config.enable_kafka_logs.on('modified', function (kafka_enabled) { 
                last_resort_logger.info({ enable_kafka_logs: +kafka_enabled, zookeeper: zookeeper ? zookeeper.route.current : undefined },
                 'enable_kafka_logs changed');
                if (+kafka_enabled && !zookeeper)
                    setup_zookeeper(function () {
                        setup_logger(+kafka_enabled, zookeeper ? zookeeper.route.current : undefined);
                    });
                else
                    setup_logger(+kafka_enabled, zookeeper ? zookeeper.route.current : undefined);
            });

            config.google_analytics_id.on('modified', function (google_analytics_id) {
                setup_logger(+config.enable_kafka_logs.current, zookeeper ? zookeeper.route.current : undefined, google_analytics_id);
            });

            callback();
        }
    ], function (error) {
        if (!ev.logger)
            setup_logger(false);
        callback(error, ev.logger, zookeeper ? zookeeper.route.current : undefined);
    });

    function setup_zookeeper(callback) {
        last_resort_logger.info('getting zookeeper configuration');
        zookeeper = { route: { current: 'localhost:2181' }};
        callback();
        // exports.etcd_config(['route'], '/services/zookeeper/', function (error, data) {
        //     if (error) {
        //         last_resort_logger.error(error, 'error getting zookeeper configuration');
        //         return callback(error);
        //     }
        //     zookeeper = data;
        //     zookeeper.route.on('modified', function (new_zookeeper) {
        //         last_resort_logger.info({ zookeeper: new_zookeeper }, 'zookeeper address has changed');
        //         setup_logger(+config.enable_kafka_logs.current, new_zookeeper, config.google_analytics_id.current);
        //     });
        //     callback();            
        // });        
    }

    function setup_logger(kafka_enabled, zookeeper_route, google_analytics_id) {
        process.env.KAFKA_ZOOKEEPER = (kafka_enabled && zookeeper_route) ? zookeeper_route : '';
        last_resort_logger.info({ 
            kafka_enabled: kafka_enabled, 
            zookeeper: zookeeper_route, 
            previous_logger: ev.logger !== undefined,
            kafka_zookeper: process.env.KAFKA_ZOOKEEPER,
            options: options
        }, 'setting up new logger');
        if (ev.logger) 
            try { ev.logger.close(); ev.logger = undefined; } catch (e) {}
        ev.logger = exports.create_logger(options.name, options.topics, google_analytics_id);
        ev.logger.info({ kafka_logging: kafka_enabled, zookeeper: zookeeper_route, google_analytics_id: google_analytics_id
            , logging_streams: (ev.logger && Array.isArray(ev.logger.streams)) ? ev.logger.streams.length : 0 }
            ,'updated logger');
        exports.set_logger(ev.logger);
        process.nextTick(function () {
            last_resort_logger.info({ logger: typeof ev.logger, zookeeper: zookeeper_route }, 
                'emitting kafka modified event');
            ev.emit('modified', ev.logger, zookeeper_route);
        });
    }

    return ev;
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