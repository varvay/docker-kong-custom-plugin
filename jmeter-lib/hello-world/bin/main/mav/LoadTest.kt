package mav

import org.slf4j.Logger
import org.slf4j.LoggerFactory
import java.io.BufferedReader
import java.io.InputStreamReader
import java.net.HttpURLConnection
import java.net.URL

class LoadTest {

    private val logger: Logger = LoggerFactory.getLogger(LoadTest::class.java)

    fun keyExchange() {
        val url = URL("http://localhost:8080/key-exchange")

        val connection = url.openConnection() as HttpURLConnection

        connection.requestMethod = "POST"
        connection.addRequestProperty("X-Device-ID", "Wasabi-man")
        connection.addRequestProperty("X-Enc-Public-Key", "7083DB6E2E631FDD13276A2DE5FFEFBB50C69378E4AC24A376092D0A153D6A3F")
        connection.addRequestProperty("X-Sign-Public-Key", "EB3940FD20AF314A98F3375F065A2F561621657A56461A2386CB77EF1F76EB17")

        try {

            val responseCode =connection.responseCode
            if (responseCode == HttpURLConnection.HTTP_OK) {
                val inputStream = connection.inputStream
                val reader = BufferedReader(InputStreamReader(inputStream))
                val response = StringBuilder()
                var line: String?
                while (reader.readLine().also { line = it } != null) {
                    response.append(line)
                }
                reader.close()

                logger.info("Response Body: $response")
            }
            else {
                throw Exception("HTTP request failed with response code: $responseCode")
            }

        } finally {
            connection.disconnect()
        }

    }

}