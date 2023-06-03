package mav

import com.google.gson.Gson
import org.bouncycastle.crypto.agreement.X25519Agreement
import org.bouncycastle.crypto.engines.AESEngine
import org.bouncycastle.crypto.engines.Salsa20Engine
import org.bouncycastle.crypto.generators.Ed25519KeyPairGenerator
import org.bouncycastle.crypto.generators.X25519KeyPairGenerator
import org.bouncycastle.crypto.macs.Poly1305
import org.bouncycastle.crypto.modes.GCMBlockCipher
import org.bouncycastle.crypto.params.*
import org.bouncycastle.crypto.signers.Ed25519Signer
import java.net.HttpURLConnection
import java.net.URL
import java.security.SecureRandom
import java.util.*
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec
import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.security.Security

data class KeyPair(var hex_sign_s_public_key: String, var hex_enc_s_public_key: String,
                   var hex_sign_c_public_key: String, var hex_sign_c_private_key: String,
                   var hex_enc_c_public_key: String, var hex_enc_c_private_key: String,
                   var hex_enc_s_private_key: String)

data class Response(var message: String, var nonce: String)

fun main(args: Array<String>) {
    Security.addProvider(BouncyCastleProvider())

    val keyPair = keyExchange()

    val signedMessage = signMessage(
        Ed25519PrivateKeyParameters(HexFormat.of().parseHex(keyPair.hex_sign_c_private_key)),
        "Hello, World!".toByteArray())

    val resp = send(HexFormat.of().formatHex(signedMessage))

    val decryptedMessage = decrypt(
        HexFormat.of().parseHex(keyPair.hex_enc_c_private_key),
        HexFormat.of().parseHex(keyPair.hex_enc_s_public_key),
        HexFormat.of().parseHex(resp.message))

    val respMessage = verifySignature(
        Ed25519PublicKeyParameters(HexFormat.of().parseHex(keyPair.hex_sign_s_public_key)),
        HexFormat.of().parseHex(decryptedMessage))

}

fun keyExchange(): KeyPair {
    val encKeyPairGenerator = X25519KeyPairGenerator()

    encKeyPairGenerator.init(X25519KeyGenerationParameters(SecureRandom()))

    val encKeyPair = encKeyPairGenerator.generateKeyPair()

    val encPrivateKey = encKeyPair.private as X25519PrivateKeyParameters
    val encPublicKey = encKeyPair.public as X25519PublicKeyParameters

    val byteEncPrivateKey = encPrivateKey.encoded
    val byteEncPublicKey = encPublicKey.encoded

    val hexEncPrivateKey = HexFormat.of().formatHex(byteEncPrivateKey)
    val hexEncPublicKey = HexFormat.of().formatHex(byteEncPublicKey)

    logger.info("Enc Private Key: $hexEncPrivateKey")
    logger.info("Enc Public Key: $hexEncPublicKey")

    val signKeyPairGenerator = Ed25519KeyPairGenerator()

    signKeyPairGenerator.init(Ed25519KeyGenerationParameters(SecureRandom()))

    val signKeyPair = signKeyPairGenerator.generateKeyPair()

    val signPrivateKey = signKeyPair.private as Ed25519PrivateKeyParameters
    val signPublicKey = signKeyPair.public as Ed25519PublicKeyParameters

    val byteSignPrivateKey = signPrivateKey.encoded
    val byteSignPublicKey = signPublicKey.encoded

    val hexSignPrivateKey = HexFormat.of().formatHex(byteSignPrivateKey)
    val hexSignPublicKey = HexFormat.of().formatHex(byteSignPublicKey)

    logger.info("Sign Private Key: $hexSignPrivateKey")
    logger.info("Sign Public Key: $hexSignPublicKey")

    val connection = URL("http://localhost:8080/key-exchange").openConnection() as HttpURLConnection
    connection.requestMethod = "POST"
    connection.addRequestProperty("X-Device-ID", "wasabi-man")
    connection.addRequestProperty("X-Enc-Public-Key", hexEncPublicKey)
    connection.addRequestProperty("X-Sign-Public-Key", hexSignPublicKey)

    val responseCode = connection.responseCode
    if (responseCode == HttpURLConnection.HTTP_OK) {
        val responseBody = connection.inputStream.bufferedReader().use { it.readText() }

        connection.disconnect()

        logger.info("Response body: $responseBody")
        val keyPair = Gson().fromJson(responseBody, KeyPair::class.java)
        keyPair.hex_sign_c_public_key = hexSignPublicKey
        keyPair.hex_sign_c_private_key = hexSignPrivateKey
        keyPair.hex_enc_c_public_key = hexEncPublicKey
        keyPair.hex_enc_c_private_key = hexEncPrivateKey

        return keyPair
    } else {
        connection.disconnect()

        throw Exception("HTTP request failed with response code: $responseCode")
    }
}

fun signMessage(binSignCPrivateKey: Ed25519PrivateKeyParameters, message: ByteArray): ByteArray {
    val signer = Ed25519Signer()

    signer.init(true, binSignCPrivateKey)

    signer.update(message, 0, message.size)

    val signature = signer.generateSignature()

    return signature + message

}

fun verifySignature(binSignSPublicKey: Ed25519PublicKeyParameters, signedMessage: ByteArray): ByteArray {
    val signature = signedMessage.copyOfRange(0, Ed25519PrivateKeyParameters.SIGNATURE_SIZE)
    val message = signedMessage.copyOfRange(Ed25519PrivateKeyParameters.SIGNATURE_SIZE, signedMessage.size)

    val verifier = Ed25519Signer()

    verifier.init(false, binSignSPublicKey)

    verifier.update(message, 0, message.size)

    val isVerified = verifier.verifySignature(signature)

    if (isVerified) {
        val respMessage = String(message)
        logger.info("Response message: $respMessage")
        return message
    } else {
        throw Exception("Signature verification failed.")
    }
}

fun send(signedMessage: String): Response {
    val connection = URL("http://localhost:8080/verify").openConnection() as HttpURLConnection
    connection.requestMethod = "POST"
    connection.addRequestProperty("X-Device-ID", "wasabi-man")
    connection.addRequestProperty("X-Message", signedMessage)

    val responseCode = connection.responseCode
    if (responseCode == HttpURLConnection.HTTP_OK) {
        val responseBody = connection.inputStream.bufferedReader().use { it.readText() }

        connection.disconnect()

        logger.info("Response body: $responseBody")

        return Gson().fromJson(responseBody, Response::class.java)
    } else {
        connection.disconnect()

        throw Exception("HTTP request failed with response code: $responseCode")
    }

}

fun decrypt(binEncCPrivateKey: ByteArray, binEncSPublicKey: ByteArray, ciphertext: ByteArray): String {
    val privateKey = X25519PrivateKeyParameters(binEncCPrivateKey)
    val publicKey = X25519PublicKeyParameters(binEncSPublicKey)

    val agreement = X25519Agreement()
    agreement.init(privateKey)

    val sharedKey = ByteArray(agreement.agreementSize)
    agreement.calculateAgreement(publicKey, sharedKey, 0)

    val res = HexFormat.of().formatHex(sharedKey)

    logger.info("Agreement C: $res")

    val nonce = ciphertext.copyOfRange(0, 96)
    val ciphertext = ciphertext.copyOfRange(96, ciphertext.size - 16)
    val authenticationTag = ciphertext.copyOfRange(ciphertext.size - 16, ciphertext.size)

    val cipher = GCMBlockCipher(AESEngine())
    val params = AEADParameters(KeyParameter(sharedKey), 128, nonce, authenticationTag)
    cipher.init(false, params)

    val plaintext = ByteArray(cipher.getOutputSize(ciphertext.size))
    val len = cipher.processBytes(ciphertext, 0, ciphertext.size, plaintext, 0)
    cipher.doFinal(plaintext, len)

    // Print the decrypted plaintext
    val finres = String(plaintext)
    logger.info("Decrypted plaintext: $plaintext")

    return finres
}
