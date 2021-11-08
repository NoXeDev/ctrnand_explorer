const aes = require('aes-js')
const crypto = require('crypto')
module.exports = class OTP {
    constructor(buffer)
    {
        this.buffer = buffer
        this.otpData = this.buffer.slice(0x0, 0x100)
        this.TWLConsoleID = this.buffer.slice(0x100, 0x100+0x8)
        this.encryptedStatus = (this.otpData.slice(0x0, 0x4).readUInt32LE() == 0xDEADB00F) ? false : true
    }

    decrypt(key, iv){
        if(!this.encryptedStatus) return console.log("Otp already decrypted")
        try{
            const aesCbc = new aes.ModeOfOperation.cbc(key, iv)
            const decrypted = aesCbc.decrypt(this.otpData)
            this.otpData = Buffer.from(decrypted)

            const deadbeef = this.otpData.slice(0x0, 0x4).readUInt32LE()
            
            if(deadbeef != 0xDEADB00F){
                throw "Err otp"
            }

            // checking just in case...
            const hash = this.otpData.slice(0xE0, 0xE0+0x20)
            const calculatedHash = crypto.createHash('sha256').update(this.otpData.slice(0x0, 0xE0))

            if(hash.toString('hex') !== calculatedHash.digest('hex'))
            {
                throw "OTP corrupted"
            }

            this.encryptedStatus = false

        }catch(e){
            console.log("Failed to decrypt... "+e)
        }
    }
}