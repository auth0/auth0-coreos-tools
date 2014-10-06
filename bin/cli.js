if (typeof process.argv[2] !== 'string') 
    throw new Error('Usage: etcd_get {key}');

require('../lib/index').etcd_get(process.argv[2], function (error, result) {
    if (error)
        throw error;
    console.log(JSON.stringify(result, null, 2));
});
