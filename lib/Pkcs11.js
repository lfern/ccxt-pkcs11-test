var pkcs11js = require("pkcs11js");

/** @typedef {import("pkcs11js").SlotInfo} SlotInfo */
/** @typedef {import("pkcs11js").TokenInfo} TokenInfo */
/** @typedef {import("pkcs11js").handle} Handle */    

class Pkcs11 {
    constructor() {
        this.pkcs11 = new pkcs11js.PKCS11();
        this.pkcs11.load("/usr/lib/softhsm/libsofthsm2.so");
        this.pkcs11.C_Initialize();
        this.module_info = this.pkcs11.C_GetInfo();

        this.slots = this.pkcs11.C_GetSlotList(true);
        /** @type {SlotInfo[]} */
        this.slotsInfo = [];
        /** @type {TokenInfo[]} */
        this.tokenInfo = [];
        this.slots.forEach((slot) => {
            this.slotsInfo.push(this.pkcs11.C_GetSlotInfo(slot));
            this.tokenInfo.push(this.pkcs11.C_GetTokenInfo(slot));
            // Getting info about Mechanism
            //var mechs = pkcs11.C_GetMechanismList(slot);
            //var mech_info = pkcs11.C_GetMechanismInfo(slot, mechs[0]);    
        });
        /** @type {Handle} */
        this.session = null;
    }
    /**
     * @returns {SlotInfo[]}
     */
    getSlots() {
        return this.slotsInfo;
    }
    /**
     * 
     * @param {String} slotDescription 
     * @param {String} password 
     */
    init (slotDescription, password) {
        this.close();
        const slotInfo = this.slotsInfo.find ( slot => slot.slotDescription == slotDescription);
        const index = this.slotsInfo.indexOf (slotInfo);
        if (index < 0) return false;
        const slot = this.slots[index];
        this.session = this.pkcs11.C_OpenSession(slot, pkcs11js.CKF_RW_SESSION | pkcs11js.CKF_SERIAL_SESSION);
        // Getting info about Session
        var info = this.pkcs11.C_GetSessionInfo(this.session);
        this.pkcs11.C_Login(this.session, 1, password);
    }

    close () {
        if (this.session != null){
            this.pkcs11.C_Logout(session);
            this.pkcs11.C_CloseSession(session);
            this.session = null;
        }
    }
    /**
     * list hmac keys
     * 
     * @return {String[]}
     */
    listHmacKeys (label = null) {
        const ret = [];
        this.findKeys((handle, label, keyType) => {
            if ([
                pkcs11js.CKK_SHA224_HMAC,
                pkcs11js.CKK_SHA256_HMAC,
                pkcs11js.CKK_SHA384_HMAC,
                pkcs11js.CKK_SHA512_HMAC
            ].indexOf(keyType) != -1){
                ret.push (label);
            }
        }, label);
        return ret;
    }
    findKeys(cb, label = null, withValue = false){
        const template = [
            { type: pkcs11js.CKA_CLASS, value: pkcs11js.CKO_SECRET_KEY },
            //{ type: pkcs11js.CKA_KEY_TYPE, value: pkcs11js.CKK_SHA224_HMAC },
            //{ type: pkcs11js.CKA_KEY_TYPE, value: pkcs11js.CKK_SHA256_HMAC },
            //{ type: pkcs11js.CKA_KEY_TYPE, value: pkcs11js.CKK_SHA384_HMAC },
            //{ type: pkcs11js.CKA_KEY_TYPE, value: pkcs11js.CKK_SHA512_HMAC }
        ];
        if (label != null){
            template.push({ type: pkcs11js.CKA_LABEL, value: label });
        }
        this.pkcs11.C_FindObjectsInit(this.session, template);
        try {
            var hObject = this.pkcs11.C_FindObjects(this.session);
            while (hObject) {
                const template = [
                    { type: pkcs11js.CKA_CLASS },
                    { type: pkcs11js.CKA_TOKEN },
                    { type: pkcs11js.CKA_LABEL },
                    { type: pkcs11js.CKA_KEY_TYPE},
                ];
                if (withValue){
                    template.push({ type: pkcs11js.CKA_VALUE},);
                }
                var attrs = this.pkcs11.C_GetAttributeValue(this.session, hObject, template);
                // Output info for objects from token only
                if (attrs[1].value[0]){
                    if (withValue){
                        cb (hObject, attrs[2].value.toString(), attrs[3].value[0], attrs[4].value.toString('hex'));
                    } else {
                        cb (hObject, attrs[2].value.toString(), attrs[3].value[0]);
                    }
                }
                
                hObject = this.pkcs11.C_FindObjects(this.session);        
            }
        } finally {
            this.pkcs11.C_FindObjectsFinal(this.session);
        }
    }
    /**
     * remove hmac key
     * 
     * @param {string} label 
     * @return {boolean}
     */
    removeHmacKey(label){
        let removed = false;
        this.findKeys((handle, label, keyType) => {
            if ([
                pkcs11js.CKK_SHA224_HMAC,
                pkcs11js.CKK_SHA256_HMAC,
                pkcs11js.CKK_SHA384_HMAC,
                pkcs11js.CKK_SHA512_HMAC
            ].indexOf(keyType) != -1){
                this.pkcs11.C_DestroyObject(this.session, handle);
                removed = true;
            }
        }, label);
        return removed;
    }
    /**
     * import hmac key
     * 
     * @param {string} label 
     * @param {string} hexkey 
     * @param {'ascii'|'hex'|'base64'} type
     */
    importHmacKey(label, key, type = 'ascii') {
        const buff = Buffer.from(key, type);
        /*
        const bitslength = buff.byteLength * 8;
        let keyType;
        if (bitslength <= 224){
            keyType = pkcs11js.CKK_SHA224_HMAC;
        } else if (bitslength <= 256){
            keyType = pkcs11js.CKK_SHA256_HMAC;
        } else if (bitslength <= 384){
            keyType = pkcs11js.CKK_SHA384_HMAC;
        } else {
            keyType = pkcs11js.CKK_SHA256_HMAC;
        }
        */
        this.pkcs11.C_CreateObject(this.session, [
            { type: pkcs11js.CKA_CLASS, value: pkcs11js.CKO_SECRET_KEY },
            { type: pkcs11js.CKA_TOKEN, value: true },
            { type: pkcs11js.CKA_EXTRACTABLE, value: true },
            { type: pkcs11js.CKA_PRIVATE, value: true },
            { type: pkcs11js.CKA_LABEL, value: label },
            { type: pkcs11js.CKA_KEY_TYPE, value: pkcs11js.CKK_GENERIC_SECRET },
            { type: pkcs11js.CKA_SIGN, value: true},
            { type: pkcs11js.CKA_VERIFY, value: true},
            { type: pkcs11js.CKA_VALUE, value: buff},

            //{ type: pkcs11js.CKA_ALLOWED_MECHANISMS, value: pkcs11js.CKM_SHA256_HMAC_GENERAL}
        ]);
    }

    exportHmacKey(labelKey) {
        let keyValue = null;
        this.findKeys((handle, label, kType, value) => {
            keyValue = value;
        }, labelKey, true);
        return keyValue;
    }
    /**
     * generate hmac 
     * 
     * @param {string} str 
     * @param {string} labelKey 
     * @param {String} hash
     * @param {'hex','base64'} outType 
     */
    hmac (str, labelKey, hash, outType) {
        let keyHandle = null;
        let keyType;
        this.findKeys((handle, label, kType) => {
            keyHandle = handle;
            keyType = kType;
        }, labelKey);
        if (keyHandle == null) throw new Exception("hmac key not found in token");
        let mech;
        switch(hash.toLowerCase()){
            case 'sha224':
                mech = pkcs11js.CKM_SHA224_HMAC;
                break;
            case 'sha256':
                mech = pkcs11js.CKM_SHA256_HMAC;
                break;
            case 'sha384':
                mech = pkcs11js.CKM_SHA348_HMAC;
                break;
            case 'sha512':
                mech = pkcs11js.CKM_SHA512_HMAC;
                break;
            default:
                throw new Exception("invalid hmac key");
        }
        const b = Buffer.from(str);
                
        this.pkcs11.C_SignInit(this.session, { mechanism: mech}, keyHandle);
        this.pkcs11.C_SignUpdate(this.session, b);
        const buffer = this.pkcs11.C_SignFinal(this.session,  Buffer.alloc(256));
        return buffer.toString(outType);
    }
}

module.exports = { Pkcs11 };