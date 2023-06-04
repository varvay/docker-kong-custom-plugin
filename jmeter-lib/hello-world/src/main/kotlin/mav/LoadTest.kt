package mav

import com.github.kittinunf.fuel.httpPost
import com.google.gson.Gson
import org.bouncycastle.crypto.agreement.X25519Agreement
import org.bouncycastle.crypto.engines.AESEngine
import org.bouncycastle.crypto.generators.Ed25519KeyPairGenerator
import org.bouncycastle.crypto.generators.X25519KeyPairGenerator
import org.bouncycastle.crypto.modes.GCMBlockCipher
import org.bouncycastle.crypto.params.*
import org.bouncycastle.crypto.signers.Ed25519Signer
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import java.net.HttpURLConnection
import java.net.URL
import java.security.SecureRandom
import java.security.Security
import java.util.*

class LoadTest {

    data class Request(val age: Int, val name: String)

    data class EncWrapper(val nonce: String, val ciphertext: String)

    data class KeyPair(var hex_sign_s_public_key: String, var hex_enc_s_public_key: String,
                       var hex_sign_c_public_key: String, var hex_sign_c_private_key: String,
                       var hex_enc_c_public_key: String, var hex_enc_c_private_key: String,
                       var hex_enc_s_private_key: String)

    val ByteArray.hex: String
        get() = HexFormat.of().formatHex(this)

    val String.byteArray: ByteArray
        get() = HexFormat.of().parseHex(this)

    val ByteArray.string: String
        get() = String(this)

    private val logger: Logger = LoggerFactory.getLogger(LoadTest::class.java)

    fun exec(keyExchangeUrl: String, verifyUrl: String, deviceId: String, jsonRequest: String, isEncDownstream: Boolean, isEncUpstream: Boolean): String {
        Security.addProvider(BouncyCastleProvider())

        val request = Gson().fromJson(jsonRequest, Request::class.java)
        val encodedRequest = Gson().toJson(request)

        val loadTest = LoadTest()

        val keyPair = loadTest.keyExchange(keyExchangeUrl, deviceId)

        val signedMessage = loadTest.signMessage(
            Ed25519PrivateKeyParameters(keyPair.hex_sign_c_private_key.byteArray),
            encodedRequest.toByteArray())

        val (nonce, ciphertext) = loadTest.encrypt(
            keyPair.hex_enc_c_private_key.byteArray,
            keyPair.hex_enc_s_public_key.byteArray,
            signedMessage,
        )

        val encRequest = EncWrapper(nonce.hex, ciphertext.hex)
        val encodedEncRequest = Gson().toJson(encRequest)

        val encResponse = loadTest.sendPost(
            verifyUrl,
            deviceId,
            encodedEncRequest,
            isEncDownstream,
            isEncUpstream)

        val verifiedMessage = loadTest.decrypt(
            keyPair.hex_enc_c_private_key.byteArray,
            keyPair.hex_enc_s_public_key.byteArray,
            encResponse.nonce.byteArray,
            encResponse.ciphertext.byteArray)

        val response = loadTest.verifySignature(
            Ed25519PublicKeyParameters(keyPair.hex_sign_s_public_key.byteArray),
            verifiedMessage.byteArray)

        logger.info("[Completed, message] \t\t\t\t\t${response.string}")

        return response.string

    }

    fun keyExchange(url: String, deviceId: String): KeyPair {

        // Generate encryption key

        val encKeyPairGenerator = X25519KeyPairGenerator()

        encKeyPairGenerator.init(X25519KeyGenerationParameters(SecureRandom()))

        val encKeyPair = encKeyPairGenerator.generateKeyPair()

        val encPrivateKey = encKeyPair.private as X25519PrivateKeyParameters
        val encPublicKey = encKeyPair.public as X25519PublicKeyParameters

        // Generate sign key

        val signKeyPairGenerator = Ed25519KeyPairGenerator()

        signKeyPairGenerator.init(Ed25519KeyGenerationParameters(SecureRandom()))

        val signKeyPair = signKeyPairGenerator.generateKeyPair()

        val signPrivateKey = signKeyPair.private as Ed25519PrivateKeyParameters
        val signPublicKey = signKeyPair.public as Ed25519PublicKeyParameters

        // Perform key-exchange to server

        val connection = URL(url).openConnection() as HttpURLConnection
        connection.requestMethod = "POST"
        connection.addRequestProperty("X-Device-ID", deviceId)
        connection.addRequestProperty("X-Enc-Public-Key", encPublicKey.encoded.hex)
        connection.addRequestProperty("X-Sign-Public-Key", signPublicKey.encoded.hex)

        val responseCode = connection.responseCode
        if (responseCode == HttpURLConnection.HTTP_OK) {

            val responseBody = connection.inputStream.bufferedReader().use { it.readText() }

            connection.disconnect()

            val keyPair = Gson().fromJson(responseBody, KeyPair::class.java)
            keyPair.hex_sign_c_public_key = signPublicKey.encoded.hex
            keyPair.hex_sign_c_private_key = signPrivateKey.encoded.hex
            keyPair.hex_enc_c_public_key = encPublicKey.encoded.hex
            keyPair.hex_enc_c_private_key = encPrivateKey.encoded.hex

            logger.info("[Key Exchange, response-body] \t\t\t$responseBody")
            logger.info("[Key Exchange, enc-private-key] \t\t${encPrivateKey.encoded.hex}")
            logger.info("[Key Exchange, enc-public-key] \t\t\t${encPublicKey.encoded.hex}")
            logger.info("[Key Exchange, sign-private-key] \t\t${signPrivateKey.encoded.hex}")
            logger.info("[Key Exchange, sign-public-key] \t\t${encPublicKey.encoded.hex}")

            return keyPair

        } else {

            connection.disconnect()

            throw Exception("HTTP request failed with response code: $responseCode")

        }

    }

    fun scalarMult(encPrivateKey: ByteArray, encPublicKey: ByteArray): ByteArray {

        // Generate shared key

        val privateKey = X25519PrivateKeyParameters(encPrivateKey)
        val publicKey = X25519PublicKeyParameters(encPublicKey)

        val agreement = X25519Agreement()
        agreement.init(privateKey)

        val sharedKey = ByteArray(agreement.agreementSize)
        agreement.calculateAgreement(publicKey, sharedKey, 0)

        logger.info("[Scalar Multiplication, shared-key] \t${sharedKey.hex}")

        return sharedKey

    }

    fun signMessage(signPrivateKey: Ed25519PrivateKeyParameters, plaintext: ByteArray): ByteArray {

        // Sign message

        val signer = Ed25519Signer()

        signer.init(true, signPrivateKey)

        signer.update(plaintext, 0, plaintext.size)

        val signature = signer.generateSignature()

        logger.info("[Message Signing, signed-message] \t\t${(signature + plaintext).hex}")

        return signature + plaintext

    }

    fun verifySignature(signPublicKey: Ed25519PublicKeyParameters, plaintext: ByteArray): ByteArray {

        // Verify signature

        val signature = plaintext.copyOfRange(0, Ed25519PrivateKeyParameters.SIGNATURE_SIZE)
        val message = plaintext.copyOfRange(Ed25519PrivateKeyParameters.SIGNATURE_SIZE, plaintext.size)

        val verifier = Ed25519Signer()

        verifier.init(false, signPublicKey)

        verifier.update(message, 0, message.size)

        val isVerified = verifier.verifySignature(signature)

        if (isVerified) {

            logger.info("[Signature Verification, message] \t\t${message.string}")

            return message

        } else {

            throw Exception("Signature verification failed")

        }

    }

    fun encrypt(encPrivateKey: ByteArray, publicKey: ByteArray, plaintext: ByteArray): Pair<ByteArray, ByteArray> {

        // Encrypt message

        val sharedKey = scalarMult(encPrivateKey, publicKey)

        val nonce = ByteArray(12)
        SecureRandom().nextBytes(nonce)

        val cipher = GCMBlockCipher(AESEngine())
        val parameters = KeyParameter(sharedKey)
        val aeadParameters = AEADParameters(parameters, 128, nonce, null)

        cipher.init(true, aeadParameters)

        val ciphertext = ByteArray(cipher.getOutputSize(plaintext.size))
        val len = cipher.processBytes(plaintext, 0, plaintext.size, ciphertext, 0)

        cipher.doFinal(ciphertext, len)

        logger.info("[Encrypt, nonce] \t\t\t\t\t\t${nonce.hex}")
        logger.info("[Encrypt, encrypted-message] \t\t\t${ciphertext.hex}")

        return Pair(nonce, ciphertext)
    }

    fun decrypt(privateKey: ByteArray, publicKey: ByteArray, nonce: ByteArray, ciphertext: ByteArray): String {

        // Decrypt message

        val sharedKey = scalarMult(privateKey, publicKey)

        val cipher = GCMBlockCipher(AESEngine())
        val parameters = KeyParameter(sharedKey)
        val aeadParameters = AEADParameters(parameters, 128, nonce, null)

        cipher.init(false, aeadParameters)

        val plaintext = ByteArray(cipher.getOutputSize(ciphertext.size))
        val len = cipher.processBytes(ciphertext, 0, ciphertext.size, plaintext, 0)

        cipher.doFinal(plaintext, len)

        logger.info("[Decrypt, nonce] \t\t\t\t\t\t${nonce.hex}")
        logger.info("[Decrypt, encrypted-message] \t\t\t${plaintext.hex}")

        return plaintext.hex

    }

    fun sendPost(url: String, deviceId: String, message: String,
                         isEncDownstream: Boolean, isEncUpstream: Boolean): EncWrapper {

        // Send message

        val (_, response, result) = url.httpPost()
            .header(
                Pair("Content-Type", "application/json"),
                Pair("X-Device-ID", deviceId),
                Pair("X-Downstream-Enc", isEncDownstream.toString()),
                Pair("X-Upstream-Enc", isEncUpstream.toString()))
            .body(message)
            .responseString()

        if (response.statusCode == 200) {

            logger.info("[Transaction, response-body] \t\t\t${result.get()}")

            return Gson().fromJson(result.get(), EncWrapper::class.java)

        } else {

            throw Exception("HTTP request failed with response code: ${response.statusCode}")

        }

    }

}