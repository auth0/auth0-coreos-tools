if (typeof process.argv[2] !== 'string') 
    throw new Error('Usage: etcd_get {key} [--upper]');

var toupper, z = 3;
while (process.argv[z] !== undefined) {
    if (process.argv[z] === '--upper') toupper = true;
    else
        throw new Error('Unrecognized option: ' + process.argv[z] 
            + '. Usage: etcd_get {key} [--upper]');
    z++;
}

require('../lib/index').etcd_get(process.argv[2], function (error, result) {
    if (error)
        throw error;

    if (toupper) 
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
