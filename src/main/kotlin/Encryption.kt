
import java.math.BigInteger
val charset = Charsets.US_ASCII

/** This public key is visible to everyone */
data class PublicKey(
    val exponent: Int,
    val modulus: Int,
)

/** The private key is something you should not share */
data class PrivateKey(
    val decryptionExponent: Int,
    val modulus: Int,
)


interface HasPublicKey {
    fun getPublicKey(): PublicKey
}

/** Encrypt a single block (a byte) using the public key (this is RSA)
 *     > encryptedByte = (byte ^ exp) % modulus                    */
fun PublicKey.encrypt(byte: Byte) = byte.powMod(exponent, modulus)

fun PublicKey.encryptMessage(message: String): ByteArray{
    println("   >>> Bytes to be encrypted: ${message.byteString()}\n   >>> Encrypting...")
    val encryptedBytes = message.toByteArray(charset = charset)
        .map { this.encrypt(it) }
        .toByteArray()
    println("   >>> Encrypted bytes: ${encryptedBytes.niceString()}")
    return encryptedBytes
}


/** Decrypt a single block (a byte) using the private key
 *     > decryptedByte = (encryptedByte ^ decryptionExponent) % modulus
 *     >               = (((byte ^ exp) % modulus) ^ decryptionExponent) % modulus
 *     >               = ((byte ^ exp) ^ decryptionExponent) % modulus
 *     >               = (byte ^ (exp * decryptionExponent)) % modulus
 *     >               = byte ^ (exp * decryptionExponent % lambda)
 *     >               = byte ^ 1
 *     >               = byte                                               */
fun PrivateKey.decrypt(byte: Byte) = byte.powMod(decryptionExponent, modulus)

fun PrivateKey.decryptMessage(encryptedBytes: ByteArray): String{
    println("   >>> Bytes to be decrypted: ${encryptedBytes.niceString()}\n   >>> Decrypting...")
    val decryptedBytes = encryptedBytes
        .map { this.decrypt(it) }
        .toByteArray()
    println("   >>> Decrypted bytes: ${decryptedBytes.niceString()}")
    val decryptedMessage = String(decryptedBytes, charset = charset)
    return decryptedMessage
}





/**  ============================= Helper methods ==================================*/

/** calculates '(this ^ exponent) % modulus' */
fun Byte.powMod(exponent: Int, modulus: Int): Byte {
    val e = BigInteger.valueOf(exponent.toLong())
    val n = BigInteger.valueOf(modulus.toLong())
    val x = BigInteger.valueOf((this).toLong()) + (if(this<0) n else BigInteger.ZERO)
    var result = x.modPow(e, n)
    if(result > BigInteger.valueOf(Byte.MAX_VALUE.toLong())) result -= n
    if(result < BigInteger.valueOf(Byte.MIN_VALUE.toLong())) result += n
    return result.toByte()
}

fun modularInverse(a: Int, n: Int): Int {
    try {
        val x = BigInteger.valueOf(a.toLong()).modInverse(BigInteger.valueOf(n.toLong()))
        return x.intValueExact()
    } catch (e: ArithmeticException){
        println("[ERROR] Could not invert $a mod $n")
        return 0
    }
}

fun gcd(a: Int, b: Int): Int {
    var x = a
    var y = b
    while (x != y) {
        if (x > y) x -= y
        else y -= x
    }
    return x
}

fun String.byteString() = this.toByteArray(charset = charset).niceString()
fun ByteArray.niceString() = this.joinToString(",","[","]")