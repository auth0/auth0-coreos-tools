var async = require('async')
    , etcd = new (require('node-etcd'))();

// Accepts an array of strings as configuration keys. 
// Each {key1} corresponds to /config/{key1} entry in etcd.
// Returns an object with properties corresponding to input keys. 
// Each property is an EventEmitter. It emits the `modified` event
// when the value of the configuration key. In addition, each EventEmitter
// has a `current` property which returns the current string value stored in etcd. 
exports.ectd_config = function (keys, callback) {
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
