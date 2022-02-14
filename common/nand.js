const OTP = require("../crypto/otp")
const fs = require('fs')
const crypto = require("crypto")
const boot9 = require("../crypto/boot9")
const aes = require('aes-js')

module.exports = class Nand {
    constructor(buffer)
    {
        this.buffer = buffer
        const tmp = buffer.slice(0x200, 0x200+0xA0)
        // Check for essential infos
        if(tmp == '\0' * 0xA0 || tmp == '\xFF' * 0xA0)
        {
            throw new Error("Essentials can't be find")
        }
    
        this.essentialBuf = tmp

        this.cid = this._parseEssential('nand_cid')
        const nandCidhash = crypto.createHash('sha256').update(this.cid).digest()
        let nandcid = BigInt("0x"+nandCidhash.slice(0x0, 0x10).toString('hex'))
        this.cryptoCid = nandcid

        if(fs.existsSync('./otp.bin')){
            this.otp = new OTP(fs.readFileSync('./otp.bin'))
        } else {
            this.otp = new OTP(this._parseEssential('otp'))
        }
        this.boot9 = new boot9(fs.readFileSync('./boot9.bin'))
        this.boot9.dumpAndDecryptOTP(this.otp)
        this.keySlots = this.boot9.setupNandKeyslots()

        let keys3f = this.boot9.extractSlot0x3FNormalKeyAndIV()
        let NandInfos = `\n
        \   Nand CID    : 0x${this.cid.toString('hex')}
        \   OTP key3F   : 0x${keys3f[0].toString('hex')}
        \   OTP IV 3F   : 0x${keys3f[1].toString('hex')}
        \   KeySlot0x6  : 0x${this.keySlots.Key0x06.toString('hex')}
        `
        console.log(NandInfos)
    }

    _parseEssential(valName)
    {
        for(let i = 0 ; i < this.essentialBuf.length ; i+=0x10)
        {
            if(this.essentialBuf.slice(i, i+0x8).toString('utf-8').includes(valName))
            {
                let header = this.essentialBuf.slice(i, i+0x10)
                let offset = header.slice(0x8, 0x8+0x4).readInt16LE()
                let size = header.slice(0xC, 0xC+0x4).readInt16LE()
                return this.buffer.slice(0x400 + offset, 0x400 + offset+size)
            }
        }
    }

    _dumpAndDecryptPartition(offset, size, keySlot)
    {
        const counter = Buffer.from((this.cryptoCid+BigInt(offset >> 4)).toString(16), 'hex')
        const aesCtr = new aes.ModeOfOperation.ctr(this.keySlots[keySlot], counter)
        return aesCtr.decrypt(this.buffer.slice(offset, offset+size))
    }
}