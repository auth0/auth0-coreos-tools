var async = require('async')
    , assert = require('assert')
    , host = process.env.COREOS_HOST || '127.0.0.1'
    , etcd = new (require('node-etcd'))(host);

// Accepts an array of strings as configuration keys. 
// Each {key1} corresponds to /config/{key1} entry in etcd.
// Returns an object with properties corresponding to input keys. 
// Each property is an EventEmitter. It emits the `modified` event
// when the value of the configuration key. In addition, each EventEmitter
// has a `current` property which returns the current string value stored in etcd. 
exports.etcd_config = function (keys, callback) {
    var config = {};
    async.each(
        keys,
        function (key, callback) {
            etcd.get('/config/' + key, function (error, result) {
                if (error) 
                    return callback(error);

                var watch = etcd.watcher('/config/' + key, result.node.modifiedIndex + 1);
                watch.current = result.node.value;
                watch.on('change', function (result) {
                    if (watch.current !== result.node.value)
                        this.emit('modified', result.node.value);
                    watch.current = result.node.value;
                });
                watch.on('error', function (error) {
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
