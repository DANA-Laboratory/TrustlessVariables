'use strict';
const __test__ = true; //debug use only
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

//***   Simple Either implementation
const either = require('./functional.js');

//***   Path to custom functions that describe calculation of related variables
const relatedpathvariables = './relatedvalues.js';
var relatedvariables = require(relatedpathvariables); //not a const cuz it could override | reloaded

//***   Data structure
const parameters = {};  // Latest state for all parameters and variables `Important :address balance is one parameter here`
const addresses = {};   // Database of addresses with related parameters and their history of changes
const trx = [];         // All transactions
const hashs = [];       // TRX hashes cumulative

                                //******    Non Export    ******//
const pemtokey = (pem) => { return pem.replace(/(\r\n\t|\n|\r\t)/gm, "").slice(26, -24) };
parameters[pemtokey(MasterKeyAddress)] = 100e6; // Initial balance for admin

//***   Verify a signiture
//      Utility
const verifysigniturebase = (message/*utf8*/, sig /*'utf8'*/, address /*pkcs8-public-pem*/) => {
    let rsaNode = new NodeRSA(address, 'pkcs8-public-pem');
    let res = rsaNode.verify(message, sig, 'utf8', 'base64');
    return res;
};

//***   Verify a signiture empty address should be signed by admin
//      Utility
const verifysigniture = (message, sig, address) => {
    if (address)
        return verifysigniturebase(message, sig, address);
    else
        return verifysigniturebase(message, sig, MasterKeyAddress);
};

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

//***   Verify all trx and update db
//      Utility
const verifytrx = () => { return false };

//***   Move a parameter from an address to another
//      Admin API
const sendparameters = () => { return false };

//***   Create a 512bit-length address return private key
//      Admin API
const createnewaddress = () => {
    let key = new NodeRSA({ b: 512 });
    return key.exportKey('pkcs8-private-pem');
};

//***   Add | Upadte function for a related variable
//      Admin API
const updaterequirerelated = (pathto /*Path to module for related variables*/, keytoaddupdate /*Variable to update*/, functionstr /*String function*/) => {
    var oldfunc = require(pathto)();
    keytoaddupdate = keytoaddupdate.trim();
    var str = "module.exports=(_$p) => { return { \n\t";
    for (var k in oldfunc) { // Read all variables exept keytoaddupdate
        if (oldfunc.hasOwnProperty(k) && k !== keytoaddupdate)
            str += k + ":" + oldfunc[k].toString() + ",\n\t";
    }
    str += keytoaddupdate + ":() => { with(_$p) { return (" + functionstr + ")}},\n"; // Add keytoaddupdate
    str += "};}";
    fs.writeFileSync(pathto, str); // Overwrite file
    delete require.cache[require.resolve(pathto)]; // Delete from require cache
    relatedvariables = require(pathto);// Load into relatedvariables
    return true;
};

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
                                //******      Export    ******//
//**    API for admin
//add_parameter {ad:address, p:parameter} add new parameter to address the address will become owner
//add_address {} create new address encrypt and send
//update_require_related {v:variablename, f:functionstr} add new related variable with custom function
//change_address
const admin_api = (message, sig) => {
    if (verifysigniture(message, sig)) {
        var messageObj = JSON.parse(message);
        var res = false;
        switch (messageObj.c) {
            case "add_parameter":
                if(messageObj.p[0] !== '$')
                  res = addparameter(messageObj.ad, messageObj.p)
                break;
            case "add_address":
                let newadd = createnewaddress();
                let encnewadd = MasterNode.encrypt(newadd, 'base64');
                res = encnewadd;
                break;
            case "update_require_related":
                if(messageObj.v[0] === '$')
                    res = updaterequirerelated(relatedpathvariables, messageObj.v, messageObj.f);
                break;
            case "change_address":
                break;
        };
        if (res) {
            addtrx({ m: message, s: sig, r: res });
            return res;
        } else
            return false;
    } else
        return false;
};

//**    API for users
//update_parameter_value {p: parameter, at: attribute, v: value} set new value for a parameter
//send {t: to, b: balance} send balance from owner to reciever
//get_parameter_history {p: parameter, at:attribute} returns history of change for a parameter giving address
//update_parameters {} update states for related parameters
//verify {} execute all trx check result validate hashes
const private_api = (message, sig, address) => {
    if (verifysigniture(message, sig, address)) {
        var messageObj = JSON.parse(message);
        var res = false;
        switch (messageObj.c) {
            case "update_parameter_value":
                res = updateparametervalue(address, messageObj.p, messageObj.at, messageObj.v);
                break;
            case "send":
                res = send(address, messageObj.t, messageObj.b);
                break;
            case "get_parameter_history":
                res = addresses[address][messageObj.p][messageObj.at];
                break;
            case "update_parameters":
                let check = true;
                while (check) {
                    check = false;
                    let funcs = relatedvariables(parameters);
                    for (let k in funcs) {
                        try {
                            console.log(k, funcs[k]());
                            check = true;
                        } catch(err) {
                            //console.log(err);
                        }
                    }
                }
                res = true;
                break;
        }
        if (res) {
            addtrx({ m: message, s: sig, a: address, r: res });
            return res;
        } else {
            return false;
        }
    } else
        return false;

};

//** API for public
//get_parameter {p: parameter, at: attribute} returns latest state of a parameter
const public_api = (message) => {
    var messageObj = JSON.parse(message);
    var res = false;
    switch (messageObj.c) {
      case "get_parameter":
          res = parameters[messageObj.p][messageObj.at];
          break;
    }
    return res;
};


module.exports.admin_api = admin_api;
module.exports.private_api = private_api;
module.exports.public_api = public_api;

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

//admin_api update_require_related
let domain = { a: 2, b: 3, c: 1 };
var relatedvalues = updaterequirerelated(relatedpathvariables, 'd', 'a*b+b^2');
assert(relatedvalues);

return 1;
