#!/usr/bin/env node

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

var coreos_tools = require('../lib/index');

coreos_tools.etcd_get(process.argv[2], function (error, result) {
    if (error)
        throw error;

    if (toupper) 
        result = coreos_tools.upper(result);
    console.log(JSON.stringify(result, null, 2));
});
