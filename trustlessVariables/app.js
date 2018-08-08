'use strict';
const MasterKeyAddress = '-----BEGIN PUBLIC KEY-----MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAKeRKdHB7L+LhExYIsPylugeMEiKJ0j15DBlXJC0kW/UoOiZKQwQZebeK6KeNSLEhe2lDix36UXO9i6TIn5pHfUCAwEAAQ==-----END';
const NodeRSA = require('node-rsa');
const MasterNode = new NodeRSA(MasterKeyAddress, 'pkcs8-public-pem');
const assert = require('assert');
const crypto = require('crypto');
const either = require('./functional.js');

const parameters = {};//latest state for all parameters
const addresses = {};//database of addresses with related parameters and their history of changes
const trx = [];//all transactions
const hashs = [];//trx hashes cumulative

const verifysignitureaddress = (message, sig, address) => {
    let rsaNode = new NodeRSA(address, 'pkcs8-public-pem');
    return rsaNode.verify(message, sig, 'utf8', 'base64');
};
const verifysigniture = (message, sig, address) => {
    if (!message || !sig) {
        return false;
    }
    if (address)
        return verifysignitureaddress(message, sig, address);
    else
        return verifysignitureaddress(message, sig, MasterKeyAddress);
};
const createnewaddress = () => {
    let key = new NodeRSA({ b: 512 });
    addresses[key.exportKey('pkcs8-public-pem')] = {b: 0.0};
    return key.exportKey('pkcs8-private-pem');
};
const addparameter = (address, parameter) => {
    if (address in addresses) {
        addresses[address][parameter] = {};
        parameters[parameter] = {};
        return true;
    } else
        return false;
};
const updateparametervalue = (address, parameter, att, value) => {
    parameters[parameter][att] = value.v;
    if (att in addresses[address][parameter] ) {
      (addresses[address][parameter][att]).push(value);
    } else {
      addresses[address][parameter][att]=[value];
    }
    return true;
};
const gethash = (str) => {
    let hash = crypto.createHash('sha256');
    hash.update(str);
    return hash.digest('base64');
};
const addtrx = (tr) => {
    trx.push(tr);
    hashs.push(gethash(hashs.pop + gethash(tr)));
};
const admin_api = (message, sig) => {
    if (verifysigniture(message, sig)) {
        addtrx(JSON.stringify({ m: message, s: sig }));
        var messageObj = JSON.parse(message);
        switch (messageObj.command) {
            case "add_parameter":
                return addparameter(messageObj.address, messageObj.parameter)
                break;
            case "add_address":
                let newadd = createnewaddress();
                let encnewadd = MasterNode.encrypt(newadd, 'base64');
                return encnewadd;
                break;

        }
    } else
        return false;
};
const private_api = (message, sig, address) => {
    if (verifysigniture(message, sig, address)) {
        addtrx(JSON.stringify({ m: message, s: sig, a: address }));
        var messageObj = JSON.parse(message);
        switch (messageObj.command) {
            case "update_parameter_value":
                return updateparametervalue(address, messageObj.parameter, messageObj.attribute, messageObj.value);
                break;

        }
    } else
        return false;

};
module.exports.admin_api = admin_api;
module.exports.private_api = private_api;

//test
const privateKey = '-----BEGIN PRIVATE KEY-----MIIBVAIBADANBgkqhkiG9w0BAQEFAASCAT4wggE6AgEAAkEAp5Ep0cHsv4uETFgiw/KW6B4wSIonSPXkMGVckLSRb9Sg6JkpDBBl5t4rop41IsSF7aUOLHfpRc72LpMifmkd9QIDAQABAkBxHeR+Lgw07ejcZK7rWgsXHLH5dhG5Bg0JwpMvOEXpmCd1HrmMEIvAnb6DM9ZOY2lc7tsTSEKjivcMz2Ezsp8tAiEA0V3KPKhD/5AZhdzbK4V1UcXsIlApDmNxXU/IDdapsysCIQDM4/K1fqE9SeVo7wX2DI/heFUoDQLNvQ0EUiT5RHJjXwIgKyZcXwIC+bH2QKuTFDYuRss27p98xrViEOw3e/qpAP8CIAiTVdpA1ZDSIfb1YiN9PRxrw+ysNrzTt9LBeWixc7QzAiEAgPGBRrxmTPXcwerwyzDdnYJWp9URT/TcqYtW1YVkV8c=-----END PRIVATE KEY-----';
assert.equal(verifysigniture(), false);
assert.equal(verifysigniture('message',), false);
assert.equal(verifysigniture('message', 'sign'), false);

const rsaNode = new NodeRSA(privateKey, 'pkcs8-private-pem');
var message = '{value: {v:3.49873, time:123456}}';
assert.equal(rsaNode.verify(message, rsaNode.sign(message, 'base64', 'utf8'), 'utf8', 'base64'), true);
assert.equal(verifysigniture(message, rsaNode.sign(message, 'base64', 'utf8')), true);
assert.equal(verifysigniture(message, rsaNode.sign(message, 'base64', 'utf8'), MasterKeyAddress), true);
let pk = createnewaddress();
const testNode = new NodeRSA(pk, 'pkcs8-private-pem');
assert(testNode.isPrivate());
assert(testNode.isPublic());
assert(!testNode.isPublic(true));
var _add = {};
_add[testNode.exportKey('pkcs8-public-pem')] = {b : 0.0};
assert.equal(JSON.stringify(addresses), JSON.stringify(_add));
assert.equal(addparameter(testNode.exportKey('pkcs8-public-pem'), 'dblVar'), true);
_add[testNode.exportKey('pkcs8-public-pem')]['dblVar'] = {};
assert.equal(JSON.stringify(addresses), JSON.stringify(_add));
assert.equal(addparameter('new address', 'dblVar'), false);

assert.equal(rsaNode.decrypt(rsaNode.encrypt('test', 'base64'), 'utf8'), 'test');

//admin_api
message = JSON.stringify({ command: 'add_address' });
var encpvkey = admin_api(message, rsaNode.sign(message, 'base64', 'utf8'));
const testNode2 = new NodeRSA(rsaNode.decrypt(encpvkey, 'utf8'), 'pkcs8-private-pem');
assert(testNode2.isPrivate());
let publickey = testNode2.exportKey('pkcs8-public-pem');
message = JSON.stringify({ command: 'add_parameter', address: publickey, parameter: 'density' });
assert(admin_api(message, rsaNode.sign(message, 'base64', 'utf8')));
message = JSON.stringify({ command: 'update_parameter_value', address: publickey, parameter: 'density', attribute: '3M', value: {v: 134.87, t:12345} });
assert(private_api(message, testNode2.sign(message, 'base64', 'utf8'), testNode2.exportKey('pkcs8-public-pem')));

//
let i = {a:2, b:3};
var fun = require('./relatedvalues.js')
console.log(fun(i).c.toString());
console.log(fun(i).c(i));
const fs = require('fs');
fs.writeFileSync("./relatedvalues.js", "module.exports=(_$p) => { return { c:" + fun(i).c.toString() + ",};}");
return 0;
