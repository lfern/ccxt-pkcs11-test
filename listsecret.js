const {Pkcs11} = require('./lib/Pkcs11');
const {getPass} = require('./lib/Password');

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
        console.log(pk11.listHmacKeys());
    } catch (ex){
        console.error(ex);
    }
}) ()
