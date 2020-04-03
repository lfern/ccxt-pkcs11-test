const {Pkcs11} = require('./lib/Pkcs11');
const {getPass} = require('./lib/Password');
const path = require('path');
const ccxt = require('ccxt');

const [processPath, program, exchangeId, apiKey] = process.argv.filter (x => !x.startsWith ('--'));
const verbose = process.argv.includes ('--verbose') || false;
const test = process.argv.includes ('--test') || false;
const futures = process.argv.includes ('--futures') || false;

if (!exchangeId || !apiKey){
    console.log(`usage: node ${path.basename(program)} [--verbose] [--test] [--futures] exchangeId api-key `);
    process.exit();
}

(async () => {
    try {
        
        const options = {
            verbose: verbose,
            apiKey: apiKey,
            secret: apiKey
        };
        if (exchangeId == 'binance' && futures){
            options['defaultType'] = 'futures';
        }
        if (exchangeId == 'binance' && test){
            options ['urls'] = {
                'api': {
                   // 'public': 'https://fapi.binance.com/fapi/v1',
                    'public': 'https://testnet.binancefuture.com/fapi/v1',
                    'private': 'https://testnet.binancefuture.com/fapi/v1'
                }
            } 
        }
        const exchange = new ccxt[exchangeId](options);

        const password = await getPass();
        const pk11 = new Pkcs11();
        const slots = pk11.getSlots();
        if (slots.length == 0) {
            console.log ("no slot found");
            process.exit();
        }
        pk11.init(slots[0].slotDescription, password);
        const oldHmac = exchange.hmac;
        exchange.hmac = (str, apiKey, hash = 'sha256', digest = 'hex') => {
            return pk11.hmac (str, apiKey, hash, digest)
        };

        console.log(await exchange.fetchBalance());

        
    } catch (ex){
        console.error(ex);
    }
}) ()