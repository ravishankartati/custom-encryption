var exec = require('cordova/exec');

exports.encrypt = function (secureKey, iv, value, success, error) {
    if(secureKey && iv && value){
        exec(success, error, 'CustomEncryptPlugin', 'ENCRYPT', [secureKey, iv, value]);
    } else {
        success('');
    }
};

exports.decrypt = function (secureKey, iv, value, success, error) {
    if(secureKey && iv && value){
        exec(success, error, 'CustomEncryptPlugin', 'DECRYPT', [secureKey, iv, value]);
    } else {
        success('');
    }
};
