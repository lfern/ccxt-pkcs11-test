
const {Pkcs11} = require('./lib/Pkcs11');
const {getPass} = require('./lib/Password');
const path = require('path');

const [processPath, program, apiKey] = process.argv;

if (!apiKey){
    console.log(`usage: node ${path.basename(program)} api-key `);
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
        pk11.removeHmacKey(apiKey);
        console.log("secret key removed");
    } catch (ex){
        console.error(ex);
    }
}) ()