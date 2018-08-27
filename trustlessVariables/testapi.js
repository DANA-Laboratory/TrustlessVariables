'use strict';

const secret = require('./secret.js');
const NodeRSA = require('node-rsa');
const api = require('./app.js').api;
const rsaNode = new NodeRSA(secret.masterkey, 'pkcs8-private-pem');
const masterpub = secret.pemtokey(rsaNode.exportKey('pkcs8-public-pem'));
const assert = require('assert');
const relatedpathvariables = './relatedvalues.js';
var relatedvariables = require(relatedpathvariables); //not a const cuz it could override | reloaded

//admin_api add_address
var m = JSON.stringify({});
var message = JSON.stringify({ m: m, s: rsaNode.sign(m, 'base64', 'utf8'), c: 'add_address', ad: masterpub });
var encpvkey = api(message);
const testNode2 = new NodeRSA(rsaNode.decrypt(encpvkey, 'utf8'), 'pkcs8-private-pem');
assert(testNode2.isPrivate());
let publickey = secret.pemtokey(testNode2.exportKey('pkcs8-public-pem'));

//admin_api add_parameter
message = JSON.stringify({p: 'density'});
assert(api(JSON.stringify({ c: 'add_parameter', ad: publickey, m: message, s: testNode2.sign(message, 'base64', 'utf8') })));

//private_api update_parameter_value
message = JSON.stringify({c: 'update_parameter_value', p: 'density', at: '3M', v: {v: 134.87, t:12345}});
assert(api(message, testNode2.sign(message, 'base64', 'utf8'), publickey));
message = JSON.stringify({c: 'get_parameter', p: 'density', at: '3M'});
assert(api(message) === 134.87);
message = JSON.stringify({c: 'get_parameter_history', p: 'density', at: '3M'});
assert(JSON.stringify(api(message, testNode2.sign(message, 'base64', 'utf8'), publickey)) === JSON.stringify([{v: 134.87, t:12345}]));

//private_api send
message = JSON.stringify({c: 'send', t: testNode2.exportKey('pkcs8-public-pem'), b: 1});
let pKey = secret.pemtokey(rsaNode.exportKey('pkcs8-public-pem'));
assert(api(message, rsaNode.sign(message, 'base64', 'utf8'), pKey));

//admin_api update_require_related
message = JSON.stringify({c: 'update_require_related', v: '$d', f: '{"3M": 2*density["3M"], "2M": density["3M"]}'});
assert(api(message, rsaNode.sign(message, 'base64', 'utf8')));
message = JSON.stringify({c: 'update_parameters'});
assert(api(message, rsaNode.sign(message, 'base64', 'utf8'), pKey));
message = JSON.stringify({c: 'get_parameter', p: '$d', at: '2M'});
assert(api(message) === 134.87);
return 0;
