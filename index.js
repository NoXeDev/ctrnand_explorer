const fs = require("fs")
const crypto = require("crypto")
const CTRNAND = require('./common/nand')

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

    const NandObj = new CTRNAND(nand)

    await fs.promises.writeFile('./firm0.bin', NandObj._dumpAndDecryptPartition(0x0B130000, 0x00400000, "Key0x06"))
    await fs.promises.writeFile('./firm1.bin', NandObj._dumpAndDecryptPartition(0x0B530000, 0x00400000, "Key0x06"))

    console.log("Decrypt and dump CTRNand Fat filesystem please wait...")
    await fs.promises.writeFile('CTRNandFAT16.img', NandObj._dumpAndDecryptPartition(0x0B95CA00, 0x2F3E3600, "Key0x04"))
})()