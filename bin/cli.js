if (typeof process.argv[2] !== 'string') 
    throw new Error('Usage: etcd_get {key} [--upper] [--toml]');

var toml, toupper, z = 3;
while (process.argv[z] !== undefined) {
    if (process.argv[z] === '--upper') toupper = true;
    else if (process.argv[z] === '--toml') toml = true;
    else
        throw new Error('Unrecognized option: ' + process.argv[z] 
            + '. Usage: etcd_get {key} [--upper] [--toml]');
    z++;
}

require('../lib/index').etcd_get(process.argv[2], function (error, result) {
    if (error)
        throw error;

    if (toupper) 
        result = upper(result);
    if (toml) 
        console.log(toml(result));
    else 
        console.log(JSON.stringify(result, null, 2));
});

// Serialize JSON to TOML; up to 1 hierarchy level is supported
function toml(o) {
    var result = '';
    var sections = [];
    for (var k in o) {
        if (typeof o[k] === 'object')
            sections.push(k);
        else
            result += k + ' = ' + o[k] + '\n';
    }
    sections.forEach(function (k) {
        result += '[' + k ']\n' + toml(o[k]);
    });
    return result;
}

// Convert object property names to uppercase
function upper(o) {
    var r = {};
    for (var k in o) 
        r[k.toUpperCase()] = typeof o[k] === 'object' ? upper(o[k]) : o[k];
    return r;
}
