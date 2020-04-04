
const {Pkcs11} = require('./lib/Pkcs11');
const {getPass} = require('./lib/Password');
const path = require('path');

let [processPath, program, apiKey, secret, keyFormat] = process.argv;

if (!keyFormat) {
    keyFormat = 'ascii';
}
if (!apiKey || !secret || ['ascii', "utf8", 'hex', 'base64'].indexOf(keyFormat) == -1){
    console.log(`usage: node ${path.basename(program)} api-key secret-key ascii|hex|base64|utf8`);
    process.exit();
}


(async () => {
    try {
        const password = await getPass();
        const pk11 = new Pkcs11();
        const slots = pk11.getSlots();
        if (slots.length == 0) {
            console.log ("no slot found");
            process.exit();
        }
        pk11.init(slots[0].slotDescription, password);
        pk11.importHmacKey(apiKey, secret, keyFormat);
        console.log("secret key imported");
    } catch (ex){
        console.error(ex);
    }
}) ()