import alice.Alice
import bob.Bob
import certificationauthority.ClaireCA
import certificationauthority.EveCA

fun main(args: Array<String>) {

    val alice = Alice()
    val bob = Bob()
    val encryptedMessage = bob.sendEncryptedMessage("My password is 1234!", alice)
    alice.receive(encryptedMessage)

    println("=".repeat(160))

    val claireCA = ClaireCA()
    val certificateAlice = alice.getCertificate()
    val signedCertificate = claireCA.sign(certificateAlice)
    println("\nThe website you're visiting says: '$signedCertificate'")
    println("Let's verify this!")
    signedCertificate.verifyWith(claireCA.getPublicKey())


    println("\n\n" + "=".repeat(160))

    val eve = EveCA()
    val evilCertificate = eve.sign(certificateAlice)
    println("\nThe website you're visiting says: '$evilCertificate'")
    println("Let's verify this!")
    evilCertificate.verifyWith(claireCA.getPublicKey())
}

