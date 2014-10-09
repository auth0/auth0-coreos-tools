var async = require('async')
    , assert = require('assert')
    , host = process.env.COREOS_HOST || '127.0.0.1'
    , etcd = new (require('node-etcd'))(host)
    , docker = new (require('dockerode'))({ host: host, port: 2375 });

// Waits for Docker to map application's port and then registers 
// the application in etcd. Keeps registering the application every
// 45 seconds with a TTL of 60 seconds. Detects SIGTERM and gracefuly recycles the 
// process.
// options.app_name - application name (e.g. 'docs')
// options.app_id - application ID unique within application name (e.g. '1')
// options.coreos_host - IP or hostname of the VM the Docker container is running on
// options.image - the Docker image this container is running
// options.port - the TCP port the application listens on within the container
// options.server - the server to stop on graceful recycling
exports.manage_service = function (options, callback) {
    // Normalize options
    assert.ok(typeof options === 'object');
    ['app_name', 'app_id', 'coreos_host', 'image'].forEach(function (i) {
        options[i] = options[i] || process.env[i.toUpperCase()];
        assert.ok(options[i], 'The options.' + i + ' property or ' + i.toUpperCase() + 
            ' environment variable must be specified.');
    });
    ['server', 'port'].forEach(function (i) {
        assert.ok(options[i], 'The options.' + i + ' property must be specified.');
    });

    // Container name and config path.
    var container_name = options.app_name + '-' + options.app_id;
    var config_path = '/routes/' + options.app_name + '/' + options.app_id;
    var target_port = options.port + '/tcp';
    var container = docker.getContainer(container_name);

    var route;
    var route_timer;
    var config;
    async.series([
        function (callback) {
            // Get etcd config
            exports.etcd_get('/config', function (error, result) {
                config = result;
                callback(error);
            });
        },
        function (callback) {
            // Wait for the docker port mapping
            var attempts = +config.docker_port_registration_retry_count;
            var delay = +config.docker_port_registration_retry_delay;
            var backoff = +config.docker_port_registration_retry_backoff;
            async.doUntil(
                function (callback) {
                    // Check if docker container port had been mapped.
                    container.inspect(function (error, info) {
                        if (error)
                            return callback(error);
                        attempts--;
                        delay *= backoff;
                        if (info.NetworkSettings
                            && typeof info.NetworkSettings.Ports === 'object'
                            && Array.isArray(info.NetworkSettings.Ports[target_port])
                            && info.NetworkSettings.Ports[target_port].length === 1
                            && info.NetworkSettings.Ports[target_port][0].HostPort) 
                                route = info.NetworkSettings.Ports[target_port][0].HostPort;
                        if (route)
                            callback();
                        else if (attempts === 0)
                            callback(new Error('Timeout waiting for the container ' 
                                + container_name + ' to establish a port mapping.'));
                        else 
                            setTimeout(callback, delay);
                    });
                },
                function () {
                    // Stop querying docker for port mapping only when mapped.
                    return route !== undefined;
                },
                callback);
        },
        function (callback) {
            // Register static metadata in etcd
            async.parallel([
                function (callback) {
                    etcd.set(config_path + '/created', Date.now(), callback);
                },
                function (callback) {
                    etcd.set(config_path + '/image', options.image, callback);
                },
                function (callback) {
                    etcd.set(config_path + '/host', options.coreos_host, callback);
                }
            ], callback);
        },
        function (callback) {
            // Keep container route registration in etcd current with a TTL
            var route_config_path = config_path + '/port';
            async.forever(
                function (next) {
                    etcd.set(route_config_path, route, { ttl: 60 }, function (error) {
                        if (error) return next(error);
                        route_timer = setTimeout(next, 45000);
                    });
                }, 
                function () { 
                    recycle(105); 
                });

            // Detect externally initiated graceful termintion of the container
            process
                .once('SIGTERM', function () { recycle(0); })
                .once('SIGINT', function () { recycle(0); });

            function recycle(exitCode) {
                // Remove etcd registration
                if (route_timer)
                    clearTimeout(route_timer);

                etcd.del(config_path, { recursive: true }, function () {
                    // Stop the server after graceful cooldown timeout
                    setTimeout(function () {
                        options.server.close(exit_now);
                    }, +config.cooldown_timeout * 1000);

                    // Let active requests complete up to the graceful shutdown timeout
                    setTimeout(exit_now, +config.graceful_shutdown_timeout * 1000);

                    function exit_now() {
                        process.exit(exitCode);
                    }
                });
            }

            callback();
        }
    ], callback);
}

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
