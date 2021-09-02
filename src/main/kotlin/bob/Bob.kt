package bob

import HasPublicKey
import encryptMessage

class Bob {
    init {
        println("Bob   : Hello Alice! I am Bob, thanks for your public key!")
    }
    fun sendEncryptedMessage(message: String, recipient: HasPublicKey): ByteArray {
        println("Bob   : I am encrypting my message for you right now.\n")
        val publicKey = recipient.getPublicKey()
        val encryptedMessage =  publicKey.encryptMessage(message)
        println("\nBob   : My (encrypted) message is '${String(encryptedMessage,charset = Charsets.US_ASCII)}'.")
        println("Bob   : I am sending it to you right now.")
        return encryptedMessage
    }
}

