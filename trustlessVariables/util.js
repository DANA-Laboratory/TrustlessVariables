'use strict';

const __test__ = false; //debug use only
//***   Standard libraries
const assert = require('assert');
const crypto = require('crypto');
const fs = require('fs');

//***   RSA (Rivest�Shamir�Adleman) https://en.wikipedia.org/wiki/RSA_(cryptosystem)
//      https://www.npmjs.com/package/node-rsa
const NodeRSA = require('node-rsa');
//      Create a RSA note to validate admin signiture
const MasterKeyAddress = '-----BEGIN PUBLIC KEY-----MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAKeRKdHB7L+LhExYIsPylugeMEiKJ0j15DBlXJC0kW/UoOiZKQwQZebeK6KeNSLEhe2lDix36UXO9i6TIn5pHfUCAwEAAQ==-----END PUBLIC KEY-----'
const MasterNode = new NodeRSA(MasterKeyAddress, 'pkcs8-public-pem');
module.exports.MasterNode = MasterNode;
const isadmin = (address) => { return address === pemtokey(MasterKeyAddress) }; 
//***   Simple Either implementation
const either = require('./functional.js');

//***   Path to custom functions that describe calculation of related variables
const relatedvariablespath = './relatedvalues.js';
//***   Path to path used to simulate function
const relatedvariablessimu = './relatedvaluessim.js';

var relatedvariables = require(relatedvariablespath); //not a const cuz it could override | reloaded

//***   Data structure
const parameters = {};  // Latest state for all parameters and variables `Important :address balance is one parameter here`
const addresses = {};   // Database of addresses with related parameters and their history of changes
const trx = [];         // All transactions
const hashs = [];       // TRX hashes cumulative

module.exports.getparameter = (p, at) => {
    if (at)
        return (parameters[p][at]);
    else
        return (parameters[p]);
};

module.exports.getparameterhistory = (address, p, at) => {
    if (at)
        return addresses[address][p][at];
    else
        return addresses[address][p];
};

const pemtokey = (pem) => { return pem.replace(/(\r\n\t|\n|\r\t)/gm, "").slice(26, -24) };
parameters[pemtokey(MasterKeyAddress)] = 100e6; // Initial balance for admin

//***   Verify a signiture
//      Utility
const verifysigniture = (message/*utf8*/, sig /*'utf8'*/, address /*pkcs8-public-pem*/) => {
    let rsaNode = new NodeRSA(address, 'pkcs8-public-pem');
    let res = rsaNode.verify(message, sig, 'utf8', 'base64');
    return res;
};
module.exports.verifysigniture = verifysigniture;

//***   Return digest of sha256 for str
//      Utility
const gethash = (str) => {
    let hash = crypto.createHash('sha256');
    hash.update(str);
    return hash.digest('base64');
};

//***   Add TRX and update hashes
//      Utility
const addtrx = (tr) => {
    trx.push(tr);
    hashs.push(gethash(hashs.pop + gethash(JSON.stringify(tr))));
    return true;
};
module.exports.addtrx = addtrx;

//***   Verify all trx and update db
//      Utility
const verifytrx = () => { return false };

//***   Move a parameter from an address to another
//      Admin API
const sendparameters = () => { return false };

//***   Create a 512bit-length address return private key
//      Admin API
const createnewaddress = (message) => {
    if (isadmin(message.ad)) {
        let key = new NodeRSA({ b: 512 });
        return MasterNode.encrypt(key.exportKey('pkcs8-private-pem'), 'base64');
    }
    return false;
};
module.exports.createnewaddress = createnewaddress;

//***   Add | Upadte function for a related variable
//      Admin API
const updaterequirerelated = (keytoaddupdate /*Variable to update*/, functionstr /*String function*/) => {
    //Parameters should be updatetd before
    let res = false;
    keytoaddupdate = keytoaddupdate.trim();
    let path = relatedvariablessimu;
    let str_head = "module.exports=(_$p) => { return { \n\t";
    let str_main = keytoaddupdate + ":() => { with(_$p) { return (" + functionstr + ")}},\n"; // Add keytoaddupdate
    let str_tail = "};}";
    let str_old = "";
    let simulate = true;
    [relatedvariablessimu, relatedvariablespath].forEach((path) => {
        if (!simulate) {
            let oldfunc = require(path)();
            for (var k in oldfunc) { // Read all variables exept keytoaddupdate
                if (oldfunc.hasOwnProperty(k) && k !== keytoaddupdate)
                    str_old += k + ":" + oldfunc[k].toString() + ",\n\t";
            }
        }
        fs.writeFileSync(path, str_head + str_old + str_main + str_tail); // Overwrite file
        delete require.cache[require.resolve(path)]; // Delete from require cache
        try {
            relatedvariables = require(path);// check if loading possible
            simulate = false;
        } catch (err) {
            return false;//return cuz simulation failed
        }
    });
    return true;
};
module.exports.updaterequirerelated = updaterequirerelated;

// update relate parameters value
const updateparameters = () => {
    let funcs = relatedvariables(parameters);
    for (let k in funcs) {
        try {
            parameters[k] = funcs[k]();
        } catch(err) {
            return false;
        }
    }
    return true;
}//
module.exports.updateparameters = updateparameters;

//***   Add new parameter to an address in case of new address it adds new one to addresses[] no balance
//      Admin API
const addparameter = (address, parameter) => {
    if (!(addresses.hasOwnProperty(address))) {
        try {
            let key = new NodeRSA(address, 'pkcs8-public-pem');;
            if (key.isPublic()) {
                addresses[address] = {};
            } else
                return false;
        } catch (any) {
            return false;
        }
    }
    addresses[address][parameter] = {};
    parameters[parameter] = {};
    return true;
};
module.exports.addparameter = addparameter;

//**    Update value for a parameter, parameter should be added before using addparameter()
//      value = {v:1.2645, t:2134523523}
//      att   = "1397_3M_measured"
//      Private API
const updateparametervalue = (address, parameter, att /*key*/, value/*json*/) => {
    parameters[parameter][att] = value.v;
    if (att in addresses[address][parameter] ) {
        (addresses[address][parameter][att]).push(value);
    } else {
        addresses[address][parameter][att]=[value];
    }
    return true;
};
module.exports.updateparametervalue = updateparametervalue;

//**    Send balance from one address to another add reciever address if not exists
//      Private API
const send = (from, to, balance) => {
    if (parameters.hasOwnProperty(from) && parameters[from] >= balance) {
        parameters[from] -= balance;
        parameters.hasOwnProperty(to) ? parameters[to] += balance : parameters[to] = balance;
        return true;
    } else
        return false;
}
module.exports.send = send;

// **************************************** __test__ ********************************************
const secret = require('./secret.js');
if (! (__test__))
    return 0;
//verifysigniture
assert.equal(verifysigniture('message', 'sign'), false);

const rsaNode = new NodeRSA(secret.masterkey, 'pkcs8-private-pem');
var message = '{value: {v:3.49873, time:123456}}';
assert.equal(rsaNode.verify(message, rsaNode.sign(message, 'base64', 'utf8'), 'utf8', 'base64'), true);
assert.equal(verifysigniture(message, rsaNode.sign(message, 'base64', 'utf8')), true);
assert.equal(verifysigniture(message, rsaNode.sign(message, 'base64', 'utf8'), secret.pemtokey(MasterKeyAddress)), true);

//createnewaddress
let pk = createnewaddress();
const testNode = new NodeRSA(pk, 'pkcs8-private-pem');
assert(testNode.isPrivate());
assert(testNode.isPublic());
assert(!testNode.isPublic(true));

//addparameter
var _add = {};
assert.equal(JSON.stringify(addresses), JSON.stringify(_add));
assert.equal(addparameter(secret.pemtokey(testNode.exportKey('pkcs8-public-pem')), 'dblVar'), true);
_add[secret.pemtokey(testNode.exportKey('pkcs8-public-pem'))] = {};
_add[secret.pemtokey(testNode.exportKey('pkcs8-public-pem'))]['dblVar'] = {};
assert.equal(JSON.stringify(addresses), JSON.stringify(_add));
assert.equal(addparameter('new address', 'dblVar'), false);

//encrypt decrypt
assert.equal(rsaNode.decrypt(rsaNode.encrypt('test', 'base64'), 'utf8'), 'test');

return 1;
