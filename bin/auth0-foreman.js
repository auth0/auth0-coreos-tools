#!/usr/bin/env node

/////// Required environment variables:

// APP_NAME - application name (e.g. 'docs')
// APP_ID - application ID unique within application name (e.g. '1')
// COREOS_HOST - IP or hostname of the VM the Docker container is running on
// IMAGE - the Docker image this container is running

/////// Optional environment variables:

// APP_HEALTH_URL = URL path that must respond with HTTP 200 for the sevice to be healthy
// APP_PORT - the TCP port the application listens on within the container; if not provided,
//            the foreman will not wait for the Docker port mapping

/////// Required command line parameters: 

// The command and arguments to start the backend, e.g.
// auth0-foreman node server.js
// (This would be typically specifified in Dockerfile)

// Validate environment

var assert = require('assert');

var options = {};
['APP_NAME', 'APP_ID', 'COREOS_HOST', 'IMAGE']
    .forEach(function (v) { 
        assert.ok(process.env[v] !== undefined, v + ' environment variable not set.'); 
        options[v.toLowerCase()] = process.env[v];
    });

// Test URL path is optional

options.app_health_url = process.env.APP_HEALTH_URL;
options.app_port = process.env.APP_PORT;

// Obtain command and arguments to start the backend

process.argv.shift();
process.argv.shift();
options.backend_cmd = process.argv.shift();
options.backend_args = process.argv;
assert.ok(options.backend_cmd, 'The command and optional arguments to start the backend must be specified as command line parameters.');

// Establish the mechanism the foreman will use to activate the service:
// - `exec` means external executable
// - `inproc` means in-process node.js module with child_process.spawn-like API contract

process.env.ACTIVATION_METHOD = options.activation_method = 
    process.env.ACTIVATION_METHOD || (options.backend_cmd.indexOf('.js') > 0 ? 'inproc' : 'exec'); 
assert.ok(options.activation_method === 'exec' || options.activation_method === 'inproc', 
    'ACTIVATION_METHOD environment variable must be either `exec` or `inproc`.');

// Establish signal file name to allow the backend to signal readiness. This is only
// used when ACTIVATION_METHOD === 'exec'

process.env.SIGNAL_FILE = options.signal_file = 
    process.env.SIGNAL_FILE || '/data/backend_signal';

var async = require('async')
    , fs = require('fs')
    , http = require('http')
    , host = process.env.COREOS_HOST || '127.0.0.1'
    , etcd = new (require('node-etcd'))(host)
    , docker = new (require('dockerode'))({ host: host, port: 2375 })
    , coreos_tools = require('../lib/index');

var logger = coreos_tools.create_logger(
    'foreman-' + options.app_name + '-' + options.app_id,
    [ 'app-' + options.app_name, 'system' ]);

logger.info(options, 'starting');

// Container name and config path.
var container_name = options.app_name + '-' + options.app_id;
var foreman_container_name = container_name + '-foreman';
var config_path = '/routes/' + options.app_name + '/' + options.app_id;
var target_port = options.app_port + '/tcp';
var container = docker.getContainer(container_name); 

var route;
var route_timer;
var config;
var config_created;
var backend;

// Register to clean up on process exit
process.on('uncaughtException', function (e) {
    logger.error(e, 'uncaught exception');
    last_resort_cleanup(function () {
        process.exit(1);
    });
});
process.on('exit', function () { 
    last_resort_cleanup(function () {});
});

async.series([
    function (callback) {
        // Get etcd config
        coreos_tools.etcd_get('/config', function (error, result) {
            if (error)
                logger.error(error, 'cannot obtain etcd config');
            config = result;
            callback(error);
        });
    },
    function (callback) {
        // Etablish signal file and watch it, then start the backend
        // and wait for it to signal back, or for the startup timer to expire.

        // Add ETCD config to environment
        process.env.JSON_CONFIG = JSON.stringify(coreos_tools.upper(config));

        var watch, spawn_impl;
        if (options.activation_method === 'exec') {
            // Get the child process spawn command
            spawn_impl = require('child_process').spawn;
            // Wait for changes to the SIGNAL_FILE made by the server
            fs.writeFileSync(options.signal_file, '');
            watch = fs.watch(options.signal_file, { persistent: false });
            watch.once('change', function () { done('signal'); });
        }
        else // 'inproc'
            // Get the inproc activation method that mimics the spawn contract
            spawn_impl = require(options.backend_cmd).spawn;

        backend = spawn_impl(options.backend_cmd, options.backend_args, { 
            env: process.env,
            stdio: 'inherit'
        });

        backend.once('exit', function () { done('exit'); });
        backend.once('error', function () { done('exit'); });
        // The `ready` event is a mechanism used by inproc servers (e.g. sandbox) 
        // to signal readiness
        backend.once('ready', function () { done('signal'); });
        var timeout = setTimeout(function () { 
            done('timeout'); 
        }, +config.container_registration_timeout * 1000);

        var done_reason;
        function done(reason) {
            logger.info({ reason: reason }, 'finished waiting for component to startup');
            if (done_reason) return;
            done_reason = reason;
            backend.removeAllListeners();
            if (done_reason !== 'timeout') 
                clearTimeout(timeout);
            if (reason === 'exit')
                callback(new Error('Backend process terminated unexpectedly during startup.'));
            else { 
                // Timeout may indicate backend that does not know how to signal, 
                // so assume innocence for now.

                // Register to detect backend's exit going forward:
                backend.once('exit', backend_exited);
                backend.once('error', backend_exited);

                callback(); 
            }
        }
    },
    function (callback) {
        // Wait for the docker port mapping if requested
        if (!options.app_port) {
            route = 'default';
            return callback();
        }

        var attempts = +config.docker_port_registration_retry_count;
        var delay = +config.docker_port_registration_retry_delay;
        var backoff = +config.docker_port_registration_retry_backoff;
        async.doUntil(
            function (callback) {
                // Check if docker container port had been mapped.
                container.inspect(function (error, info) {
                    logger.info({ attempts: attempts, error: error }, 'waiting for Docker port mapping');
                    if (error)
                        return callback(error);
                    attempts--;
                    delay *= Math.floor(delay * backoff);
                    if (info.NetworkSettings
                        && typeof info.NetworkSettings.Ports === 'object'
                        && info.NetworkSettings.Ports
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
        logger.info({ port: route }, 'established port mapping');
        // Send the test HTTP GET request to validate the backend
        if (!options.app_health_url)
            return callback();

        var url = 'http://' + options.coreos_host + ':' + route + options.app_health_url;
        logger.info({ url: url }, 'probing health endpoint');
        http.get({
            agent: false, // don't use keep-alive which prevents server from closing down
            host: options.coreos_host,
            port: route,
            path: options.app_health_url
        }, function (res) {
            logger.info({ status: res.statusCode }, 'health endpoint response');
            callback(res.statusCode === 200 
                ? undefined 
                : new Error('Backend did not respond to health check at ' 
                    + url + ' with status code 200: ' + res.statusCode))
        }).on('error', function (error) {
            logger.error(error, 'health endpoint error');
            callback(new Error('Backend failed to respond to health check at ' + url));
        });
    },
    function (callback) {
        // Register static metadata in etcd
        config_created = true;
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
        logger.info({ path: config_path }, 'created routing entry in etcd')
        // Keep container route registration in etcd current with a TTL
        var route_config_path = config_path + '/port';
        async.forever(
            function (next) {
                etcd.set(route_config_path, route, { ttl: 60 }, function (error) {
                    if (error) return next(error);
                    route_timer = setTimeout(next, 45000);
                });
            }, 
            function (error) { 
                logger.error(error, 'error updating route entry in etcd');
                recycle('SIGTERM', 105); 
            });

        // Detect externally initiated graceful termintion of the container
        process
            .once('SIGTERM', function () { recycle('SIGTERM', 0); })
            .once('SIGINT', function () { recycle('SIGINT', 0); });

        function recycle(signal, exitCode) {
            logger.info({ signal: signal, exitCode: exitCode }, 'recycling');
            if (backend)
                backend.graceful_exit_code = exitCode;

            // Remove etcd registration
            if (route_timer) {
                clearTimeout(route_timer);
                route_timer = undefined;
            }

            async.series([
                function (callback) {
                    // Mark the container as recycling in etcd
                    etcd.set(config_path + '/recycling', Date.now(), callback);
                },
                function (callback) {
                    // Remove routing information from etcd
                    etcd.del(config_path + '/port', callback);
                },
                function (callback) {
                    // Gracefully stop the server after cooldown timeout
                    setTimeout(function () {
                        logger.info({ backend_exists: backend !== undefined, signal: signal }, 'cooldown time elapsed, killing backend');
                        if (backend)
                            backend.kill(signal);
                    }, +config.cooldown_timeout * 1000);
                    logger.info({ timeout: +config.cooldown_timeout }, 'initiated cooldown timeout');

                    // Let active requests complete up to the graceful shutdown timeout
                    setTimeout(function () {
                        logger.info('graceful shutdown time elapsed, exiting foreman');
                        last_resort_cleanup(function () {
                            process.exit(exitCode);
                        });
                    }, +config.graceful_shutdown_timeout * 1000);
                    logger.info({ timeout: +config.graceful_shutdown_timeout }, 'initiated graceful shutdown timeout');
                }
            ], callback);
        }
    }
], function (error) {
    logger.error(error, 'foreman error');
    last_resort_cleanup(function () {
        throw error;
    });    
});

function backend_exited(code) {
    logger.info({ code: code }, 'backend exited');
    assert.ok(backend);

    var graceful_exit_code = backend.graceful_exit_code;
    last_resort_cleanup(function () {
        process.exit(graceful_exit_code !== undefined ? graceful_exit_code : code);
    });
}

function last_resort_cleanup(callback) {
    logger.info('last resort cleanup entered');

    if (route_timer) {
        logger.info('last resort cleanup: stopping route update timer');
        clearTimeout(route_timer);
        route_timer = undefined;
    }

    async.series([
        function (callback) {
            // Terminate backed and clean up etcd
            async.parallel([
                function (callback) {
                    // Terminate backend
                    if (backend) {
                        var tmp = backend;
                        backend = undefined;
                        logger.info('last resort cleanup: killing backend');
                        tmp.removeAllListeners();
                        if (tmp.kill.is_async) {
                            // This is the Docker based implementation which is async
                            // because it uses Docker client.
                            tmp.kill('SIGKILL', callback);
                        }
                        else {
                            // This is the child_process based implementation
                            try { tmp.kill('SIGKILL'); } catch(e) {}
                            // Remove the child Docker container
                            container.remove({ force: true }, function () {
                                callback();
                            });
                        }
                    }
                    else 
                        callback();
                },
                function (callback) {
                    // Clean up etcd
                    if (config_created) {
                        config_created = undefined;
                        logger.info('last resort cleanup: removing routing entry in etcd');
                        etcd.del(config_path, { recursive: true }, function () {
                            callback();
                        });
                    }
                    else 
                        callback();
                }
            ], callback);
        },
        function (callback) {
            // Remove own container via Docker
            // TODO: tjanczuk: capture logs before removing foreman
            if (foreman_container_name) {
                logger.info({ container: foreman_container_name }, 'removing own container');
                var tmp = foreman_container_name;
                foreman_container_name = undefined;
                var foreman = docker.getContainer(tmp); 
                foreman.remove({ force: true }, function () {
                    callback();
                });
            }
            else
                callback();
        }
    ], callback);
}
