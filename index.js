const fs = require("fs")
const crypto = require("crypto")
const bootrom = require("./crypto/boot9")
const aes = require('aes-js')
const OTP = require('./crypto/otp')

;
(async () => {
    console.log("Reading NAND.BIN please wait...")
    const nand = await fs.promises.readFile('./nand.bin')

    let hash
    console.log("Reading NAND hash please wait...")
    try {
        hash = await fs.promises.readFile('./nand.bin.sha')
        console.log("Hash readed, checking...")
        const calculatedHash = crypto.createHash('sha256').update(nand).digest('hex')

        if(hash.toString('hex') === calculatedHash) {
            console.log("Hashs match !")
        } else {
            throw new Error("Nand corrupted ...")
        }
        
    } catch {
        console.log("Failed to read nand hash, skipping hash check...")
    }

    let nandCid
    const boot9 = new bootrom(await fs.promises.readFile('./boot9.bin').catch(() => {throw new Error("Can't find boot9.bin (required)")}))
    if(fs.existsSync('./otp.bin'))
    {
        boot9.dumpAndDecryptOTP(new OTP(await fs.promises.readFile('./otp.bin')))
    }
    else {
        const essential = nand.slice(0x200, 0x200+0xA0)
        if(essential == '\0' * 0xA0 || essential == '\xFF' * 0xA0)
        {
            throw new Error("Essentials can't be find")
        }

        for(let i = 0 ; i < essential.length ; i+=0x10)
        {
            if(essential.slice(i, i+0x8).toString('utf-8').includes("otp"))
            {
                let header = essential.slice(i, i+0x10)
                let offset = header.slice(0x8, 0x8+0x4).readInt16LE()
                let size = header.slice(0xC, 0xC+0x4).readInt16LE()
                boot9.dumpAndDecryptOTP(new OTP(nand.slice(0x400 + offset, 0x400 + offset+size)))
            }

            if(essential.slice(i, i+0x8).toString('utf-8').includes("nand_cid"))
            {
                let header = essential.slice(i, i+0x10)
                let offset = header.slice(0x8, 0x8+0x4).readInt16LE()
                let size = header.slice(0xC, 0xC+0x4).readInt16LE()
                nandCid = nand.slice(0x400 + offset, 0x400 + offset+size)
            }
        }
    }

    const keySlots = boot9.setupNandKeyslots()
    
    const firm0Offset = 0x0B130000
    const firm1Offset = 0x0B530000
    const firm0 = nand.slice(firm0Offset, firm0Offset+0x00400000)
    const firm1 = nand.slice(firm1Offset, firm1Offset+0x00400000)

    // get Nand cid
    if(!nandCid){
        if(fs.existsSync('./nand_cid.mem')){
            nandCid = await fs.promises.readFile('./nand_cid.mem')
        } else {
            throw new Error('Failed to open nand cid (needed)')
        }
    }

    let keys3f = boot9.extractSlot0x3FNormalKeyAndIV()

    let NandInfos = `\n
    \   Nand CID    : 0x${nandCid.toString('hex')}
    \   OTP key3F   : 0x${keys3f[0].toString('hex')}
    \   OTP IV 3F   : 0x${keys3f[1].toString('hex')}
    \   KeySlot0x6  : 0x${keySlots.Key0x06.toString('hex')}
    `
    console.log(NandInfos)
    
    const nandCidhash = crypto.createHash('sha256').update(nandCid).digest()
    let nandcid = BigInt("0x"+nandCidhash.slice(0x0, 0x10).toString('hex'))

    const firm0Counter = Buffer.from((nandcid+BigInt(firm0Offset >> 4)).toString(16), 'hex')
    const firm1Counter = Buffer.from((nandcid+BigInt(firm1Offset >> 4)).toString(16), 'hex')

    const aesCtrFirm0 = new aes.ModeOfOperation.ctr(keySlots.Key0x06, firm0Counter)
    const decryptedFirm0 = aesCtrFirm0.decrypt(firm0)

    const aesCtrFirm1 = new aes.ModeOfOperation.ctr(keySlots.Key0x06, firm1Counter)
    const decryptedFirm1 = aesCtrFirm1.decrypt(firm1)

    await fs.promises.writeFile('./firm0.bin', decryptedFirm0)
    await fs.promises.writeFile('./firm1.bin', decryptedFirm1)
})()