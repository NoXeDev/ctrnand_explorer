const crypto = require("crypto")
const aes = require('aes-js')

// Sensible value
const CRYPTO_CONST = BigInt('0x1FF9E9AAC5FE0408024591DC5D52768A')

function rol(val, bits, max){
    const r_bits = BigInt(bits)
    const max_bits = BigInt(max)
    return (val << r_bits % max_bits) & (BigInt(2) ** max_bits - BigInt(1)) | 
        ((val & (BigInt(2) ** max_bits - BigInt(1))) >> (max_bits - (r_bits % max_bits)))
}

module.exports = class boot9 {
    constructor(buffer){
        this.buffer = buffer
        this.keysDataSection = this.buffer.slice(0x0+0xb0e0)
        this.bootrom_dataptr = this.buffer.slice(0xd860, 0xd860+0x400)
        this.otp = undefined
        this.keyslots = {}
    }

    keyScramble(keyX, keyY){
        const formatKeyX = BigInt("0x"+keyX.toString('hex'))
        const formatKeyY = BigInt("0x"+keyY.toString('hex'))
        let rol1 = rol(formatKeyX, 2, 128)
        let xorify = rol1 ^ formatKeyY
        let add = xorify + CRYPTO_CONST
        let ror1 = rol(add, 87, 128)
        return Buffer.from(ror1.toString(16), 'hex')
    }

    extractSlot0x3FNormalKeyAndIV() {
        const otpKeysSection = this.keysDataSection.slice(0x2600/*skip RSA keys section*/)
        const retailKeys = otpKeysSection.slice(0x0, 0x20)
        const normalKey = retailKeys.slice(0x0, 0x10)
        const IV = retailKeys.slice(0x10, 0x20)

        return [normalKey, IV]
    }

    setupNandKeyslots()
    {
        if(!this.otp || this.otp?.encryptedStatus) return console.log("OTP not decrypted, can't setup Nand keyslots")
        // First we need to configure Code BlockX 0 for generate unique keyX
        const conunique_dataptr = this.otp.otpData.slice(0x90, 0x90+0x1C)
        const tmpBuffer = Buffer.concat([conunique_dataptr, this.bootrom_dataptr.slice(0x0, 0x40-0x1C)])
        const hash = crypto.createHash('sha256').update(tmpBuffer).digest()

        const keyX3F = hash.slice(0x0, 0x10)
        const keyY3F = hash.slice(0x10, 0x20)
        const NormalKey3F = this.keyScramble(keyX3F, keyY3F)
        const IVCodeBlockX = this.bootrom_dataptr.slice(0x40-0x1C+0x10, 0x40-0x1C+0x10+0x10)

        const codeBlockX = this.bootrom_dataptr.slice(0x40-0x1C, 0x40-0x1C+0x10)

        const aesCbc = new aes.ModeOfOperation.cbc(NormalKey3F, IVCodeBlockX)
        const KeyX0x04_0x07 = Buffer.from(aesCbc.encrypt(codeBlockX).buffer).slice(0x0, 0x10)

        // Now try to dump KeyY non unique key

        let detailledSkipper = 0

        // Skip bootrom_dataptr sector for calculate hash for get KeyX 3F
        detailledSkipper += 36

        // Skip 3 unique block (our keyY is in the 4th codeblock)
        detailledSkipper += (16 + 64 + 36)*2
        detailledSkipper += (16 + 16 + 36)

        // Skipping AESIV unique block + padding + KeyX2C + KeyX30 + KeyX34 + KeyX38 and 3C keysSlotsX
        detailledSkipper += 16 * 10

        const KeyYBlock = this.bootrom_dataptr.slice(detailledSkipper, detailledSkipper+0x40)

        const KeyY0x04 = KeyYBlock.slice(0x0, 0x10)
        const KeyY0x05 = KeyYBlock.slice(0x10, 0x20)
        const KeyY0x06 = KeyYBlock.slice(0x20, 0x30)
        const KeyY0x07 = KeyYBlock.slice(0x30, 0x40)

        this.keyslots.Key0x04 = this.keyScramble(KeyX0x04_0x07, KeyY0x04)
        this.keyslots.Key0x05 = this.keyScramble(KeyX0x04_0x07, KeyY0x05)
        this.keyslots.Key0x06 = this.keyScramble(KeyX0x04_0x07, KeyY0x06)
        this.keyslots.Key0x07 = this.keyScramble(KeyX0x04_0x07, KeyY0x07)
        return this.keyslots
        
    }

    dumpAndDecryptOTP(otpBuffer) {
        const key = this.extractSlot0x3FNormalKeyAndIV()
        const otp = otpBuffer
        otp.decrypt(key[0], key[1])
        this.otp = otp
    }
}