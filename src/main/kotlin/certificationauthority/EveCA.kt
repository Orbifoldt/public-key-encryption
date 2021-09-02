package certificationauthority

import CanSign
import Certificate
import HasPublicKey
import PrivateKey
import PublicKey
import encryptMessage
import gcd
import hash
import modularInverse

class EveCA(
    private val p: Int = 11, // Random prime number
    private val q: Int = 13, // Other random prime number
    private val exp: Int = 7,  // A fixed integer (with some conditions)
    public val subject: String = "https://www.claire-CA.com"
) : HasPublicKey, CanSign {

    private val n = p * q
    private fun lambda() = (p - 1) * (q - 1)
    private val d = modularInverse(exp, lambda())

    public override fun getPublicKey() = PublicKey(exponent = exp, modulus = n)
    private fun getPrivateKey() = PrivateKey(decryptionExponent = d, modulus = n)


    init {
        if (gcd(exp, lambda()) != 1) throw ArithmeticException("exp=$exp and lambda=${lambda()} should have gcd=1")
        if (p * q > 255) throw ArithmeticException("p*q should be less than 255")
        println("\n\nEve   : Hello everyone, I am Eve, but I want you to think I am Claire the Certification Authority! Muwhahahaha! My public key is ($exp, ${p * q})!")
    }

    override fun sign(certificate: Certificate): Certificate {
        certificate.signedBy = subject
        certificate.signature = getPrivateKey().encryptMessage(hash(certificate.toString().toByteArray(Charsets.US_ASCII)))
        return certificate
    }

    fun getCertificate() = Certificate(
        privateKey = getPrivateKey(),
        publicKey = getPublicKey(),
        subject = subject,
        signedBy = "None, because I hope that everyone trusts me.",
        signature = null,
    )

}
