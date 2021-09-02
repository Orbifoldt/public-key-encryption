package alice

import Certificate
import HasPublicKey
import PrivateKey
import PublicKey
import decryptMessage
import gcd
import modularInverse

class Alice(
    private val p: Int = 13, // Random prime number
    private val q: Int = 17, // Other random prime number
    private val exp: Int = 5,  // A fixed integer (with some conditions)
) : HasPublicKey {

    private val n = p * q                         // 13*17 = 221
    private fun lambda() = (p - 1) * (q - 1)      // 12*16 = 192
    private val d = modularInverse(exp, lambda()) // (d * 5) % 192 = 1  => d=77

    public override fun getPublicKey() = PublicKey(exponent = exp, modulus = n)   // (5, 221)
    private fun getPrivateKey() = PrivateKey(decryptionExponent = d, modulus = n) // d=77


    init {
        if (gcd(exp, lambda()) != 1) throw ArithmeticException("exp=$exp and lambda=${lambda()} should have gcd=1")
        if (p * q > 255) throw ArithmeticException("p*q should be less than 255")
        println("\n\nAlice : Hello everyone, I am Alice and my public key is ($exp, ${p * q})!\n")
    }

    public fun receive(encryptedMessage: ByteArray) {
        println("\nAlice : Thanks Bob, I received your encrypted message '${String(encryptedMessage, charset = Charsets.US_ASCII)}'.\n")
        println("   >>> Alice received the message '${String(encryptedMessage, charset = Charsets.US_ASCII)}'")
        println("   >>> Using her private key ${getPrivateKey().decryptionExponent} she can decrypt this:")

        val decryptedMessage = getPrivateKey().decryptMessage(encryptedMessage)

        println("   >>> Decrypted message: '$decryptedMessage'")
        println("\nAlice : I was able to decrypt your message: '$decryptedMessage'\n\n")
    }

    fun getCertificate() = Certificate(
        privateKey = getPrivateKey(),
        publicKey = getPublicKey(),
        subject = "https://www.alice.com",
        signature = null,
        signedBy = null,
    )
}



