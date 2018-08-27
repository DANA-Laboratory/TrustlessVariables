'use strict';

const u = require ('./util.js');
                                //******      Export    ******//
//**    API for admin
//
//update_require_related {v:variablename, f:functionstr} add new related variable with custom function
//change_address
const admin_api = (messageObj, sig) => {
    if (u.verifysigniture(message, sig)) {
        var res = false;
        switch (messageObj.c) {
            case "add_parameter":
                if(messageObj.p[0] !== '$')
                  res = u.addparameter(messageObj.ad, messageObj.p)
                break;
            case "add_address":
                break;
            case "update_require_related":
                if(messageObj.v[0] === '$')
                    res = u.updaterequirerelated(messageObj.v, messageObj.f);
                break;
            case "change_address"://TODO
                break;
        };
        if (res) {
            u.addtrx({ m: message, s: sig, r: res });
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
const private_api = (messageObj, sig, address) => {
    if (u.verifysigniture(message, sig, address)) {
        var res = false;
        switch (messageObj.c) {
            case "update_parameter_value":
                res = u.updateparametervalue(address, messageObj.p, messageObj.at, messageObj.v);
                break;
            case "send":
                res = u.send(address, messageObj.t, messageObj.b);
                break;
            case "update_parameters":
                res = u.updateparameters();
                break;
        }
        if (res) {
            u.addtrx({ m: message, s: sig, a: address, r: res });
            return res;
        } else {
            return false;
        }
    } else
        return false;

};

//** API for public
//get_parameter {p: parameter, at: attribute} returns latest state of a parameter
const public_api = (messageObj) => {
    var res = false;
    switch (messageObj.c) {
        case "get_parameter":
            res = u.getparameter(messageObj.p, messageObj.at);
            break;
        case "get_parameter_history":
            res = u.getparameterhistory(address, messageObj.p, messageObj.at);
            break;
    }
    return res;
};
const messagePass = {
    //add_address {} create new address encrypt and send
    add_address: u.createnewaddress,
    //add_parameter { ad: address, p: parameter } add new parameter to address the address will become owner
    add_parameter: u.addparameter,

    get_parameter: public_api,
    get_parameter_history: public_api,
    update_parameter_value: private_api,
    send: private_api,
    update_parameters: private_api,
    update_require_related: admin_api,
    change_address: admin_api,
};

const api = (message) => {
    var messageObj = JSON.parse(message);
    if (messageObj.s) {
        if (u.verifysigniture(messageObj.m, messageObj.s, messageObj.ad)) {
            var messageObjIn = JSON.parse(messageObj.m);
            messageObjIn.ad = messageObj.ad;
            var res = messagePass[messageObj.c](messageObjIn);
            if (res)
                u.addtrx({ tr: messageObj, r: res });
            return res;
        };
    }
};
module.exports.api = api;
