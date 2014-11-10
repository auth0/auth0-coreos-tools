var async = require('async')
    , assert = require('assert')
    , host = process.env.COREOS_HOST || '127.0.0.1'
    , etcd = new (require('node-etcd'))(host)
    , winston = require('winston')
    , bunyan = require('bunyan')
    , Stream = require('stream').Stream
    , util = require('util')
    , kafka = require('kafka-node');

var logger = create_logger('auth0-coreos-tools', ['system']);

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
var lock_id = process.pid + '.' + Date.now();
exports.lowr = function (sync_root, etcdconfig, callback) {
    // Attempt to take the lock
    etcd.set(
        '/lock/' + sync_root, 
        lock_id, 
        { prevExist: false, ttl: +etcdconfig.lock_ttl.current },
        function (error, result) {
            if (error) {
                if (error.errorCode === 105) {
                    // Lock is currently held, wait for its release
                    var watch = etcd.watcher('/lock/' + sync_root, error.error.index + 1);
                    watch.on('change', function (result) {
                        if (result.node.value === undefined)
                            done();
                    });
                    watch.on('error', done);

                    function done(error, result) {
                        watch.stop();
                        callback(error, result);
                    }

                    return;
                }

                return callback(error);
            }

            // Lock was taken, renew it periodically until released

            var renew = setInterval(function () {
                etcd.set('/lock/' + sync_root, lock_id, { ttl: +etcdconfig.lock_ttl.current });
            }, +etcdconfig.lock_renew.current * 1000);

            // Return a function that must be used to release the lock

            callback(null, function (callback) {
                clearInterval(renew);
                etcd.compareAndDelete('/lock/' + sync_root, lock_id, function (error) {
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

function KafkaStream (options) {
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
            self._send_pending();
        })
        .on('error', function (error) {
            self._error = error;
            self.emit('error', error);
        });
};

util.inherits(KafkaStream, Stream);
exports.KafkaStream = KafkaStream;

KafkaStream.prototype.close = function close() {
    this._client.close();
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
    if (!this._error) {
        this._pending.push(r);
        this._send_pending();
    }
    else 
        throw this._error;
};

KafkaStream.prototype._send_pending = function () {
    if (this._ready && this._pending.length > 0) {
        var current = this._pending;
        this._pending = [];
        var messages = [];
        current.forEach(function (entry) {
            messages.push(typeof entry === 'string' ? entry : JSON.stringify(entry));
        });
        var payload = [];
        this.options.topics.forEach(function (topic) {
            payload.push({
                topic: topic,
                messages: messages
            });
        });
        var self = this;
        this._producer.send(payload, function (error) {
            if (error) self.emit('error', error);
        });
    }
};

function create_logger(name, topics) {
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
        logger_options.streams.push({ level: 'info', stream: kafka_stream });
    }

    var result = bunyan.createLogger(logger_options);
    result.close = function () {
        if (kafka_stream) {
            kafka_stream.close();
            kafka_stream = undefined;
        }            
    };

    return result;
};

exports.create_logger = create_logger;
