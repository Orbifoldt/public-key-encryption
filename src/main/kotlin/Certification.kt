import com.google.common.hash.Hashing

data class Certificate(
    private val privateKey: PrivateKey,
    public val publicKey: PublicKey,
    public val subject: String,
    public var signedBy: String?,
    public var signature: ByteArray?,
) {
    override fun toString() =
        "My public key is (${publicKey.exponent}, ${publicKey.modulus}), I use SHA256 and I am the owner of $subject. I was signed by $signedBy"
}


interface CanSign {
    fun sign(certificate: Certificate): Certificate
}

fun PrivateKey.encrypt(byte: Byte) = byte.powMod(decryptionExponent, modulus)

fun PrivateKey.encryptMessage(message: String): ByteArray {
    return message.toByteArray(charset = charset)
        .map { encrypt(it) }
        .toByteArray()
}

fun PublicKey.decrypt(byte: Byte) = byte.powMod(exponent, modulus)

fun PublicKey.decryptMessage(signedBytes: ByteArray): ByteArray {
    return signedBytes
        .map { decrypt(it) }
        .toByteArray()
}

fun Certificate.verifyWith(publicKey: PublicKey){
    this.signature ?: throw RuntimeException("Certificate was not signed!")

    println("   >>> Using $publicKey (given by ClaireCA, whom we trust) we verify the certificate provided from $subject.")
    val decryptedHash = publicKey.decryptMessage(this.signature!!)
    println("   >>> Using this trusted public key we get: ${decryptedHash.niceString()}")
    val calculatedHash = hash(this.toString().toByteArray(Charsets.US_ASCII)).toByteArray(Charsets.US_ASCII)
    println("   >>> The certificate we are verifying (from $subject) has an actual hash of: ${calculatedHash.niceString()}")
    if(decryptedHash.contentEquals(calculatedHash)) println("The signature matches! The certificate was signed by the owner of the public key. You can trust this server.")
    else println("Oh no! The hashes don't match. The owner of the public key '$publicKey' did not sign this certificate!")
}



fun hash(bytes: ByteArray) = String(Hashing.sha256().hashBytes(bytes).asBytes(), Charsets.US_ASCII)