if (typeof process.argv[2] !== 'string') 
    throw new Error('Usage: etcd_get {key} [--toupper]');
if (process.argv[3] !== undefined && process.argv[3] !== '--toupper')
    throw new Error('Unrecognized option: ' + process.argv[3] + '. Usage: etcd_get {key} [--toupper]');

require('../lib/index').etcd_get(process.argv[2], function (error, result) {
    if (error)
        throw error;

    if (process.argv[3] === '--toupper') 
        result = upper(result);
    console.log(JSON.stringify(result, null, 2));
});

// Convert object property names to uppercase
function upper(o) {
    var r = {};
    for (var k in o) 
        r[k.toUpperCase()] = typeof o[k] === 'object' ? upper(o[k]) : o[k];
    return r;
}
