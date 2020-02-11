var exec = require('cordova/exec');

exports.coolMethod = function (secureKey, iv, value, success, error) {
    if(secureKey && iv && value){
        exec(success, error, 'CustomEncryptPlugin', 'ENCRYPT', [secureKey, iv, value]);
    } else {
        success('');
    }
};
