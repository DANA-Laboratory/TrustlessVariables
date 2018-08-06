const log = (_) => console.log(_);
const crypto = require('crypto');
const db = require('./main.js');
const error = require('./errors.js');
const assert = require('assert');
const ds = db.dataState();
const nu = db.newUser('rza', 'afzalan', 564870);
const nu_ = db.newUser('reza', 'afzalan', 564870);
const dataFilePath = './data';
const either = require('./functional.js');
const zUser = { name: 'reza', family: 'afzalan'};
assert.deepEqual(db.newUser(zUser.name, zUser.family, zUser.id), either.Nothing.of(error.no_id));
const aUser = { name: 'rza', family: 'afzalan', id: 564870 };
const bUser = { name: 'reza', family: 'afzalan', id: 564870 };
db.addUpdateUser(db.newUser(aUser.name, aUser.family, aUser.id), ds);
db.addUpdateUser(db.newUser(bUser.name, bUser.family, bUser.id), ds);
assert.deepEqual(ds, {users: [bUser]});
db.write(dataFilePath, ds);
const newState = db.dataState(db.load(dataFilePath));
assert.deepEqual(ds, newState);

const alice = crypto.createECDH('secp521r1');
const aliceKey = alice.generateKeys();
//log(alice.getPrivateKey());
//log(aliceKey);

// Generate Bob's keys...
const bob = crypto.createECDH('secp521r1');
const bobKey = bob.generateKeys();

//log(bob.getPrivateKey());
//log(bobKey);
// Exchange and generate the secret...
const aliceSecret = alice.computeSecret(bobKey);
const bobSecret = bob.computeSecret(aliceKey);

assert.strictEqual(aliceSecret.toString('hex'), bobSecret.toString('hex'));
