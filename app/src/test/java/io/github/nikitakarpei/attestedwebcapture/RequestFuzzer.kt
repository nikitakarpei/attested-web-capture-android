package io.github.nikitakarpei.attestedwebcapture

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.io.OutputStream
import java.net.Proxy
import java.net.Socket
import java.util.Base64

/**
 * Fuzzes request parsing and the token check (`./gradlew fuzzRequest`). With no signing key, a request that
 * passes every check ends in 503 before any fetch. For any input: one well-formed response, nothing from the
 * input in its headers, and 407 unless the request carries the token (or is too long to read).
 */
object RequestFuzzer {
    const val TOKEN = "0123456789abcdef0123456789abcdef"
    private val client = httpClient(Proxy.NO_PROXY)
    private val stamper = Stamper(client)
    private val drand = Drand(client) { 0L } // never reached: the key fails first
    private val statusLine = Regex("HTTP/1\\.1 (400|405|407|503) Error")
    private val headerLine = Regex("[A-Za-z-]+: [ -~]*")

    private class FakeSocket(private val input: InputStream) : Socket() {
        val written = ByteArrayOutputStream()
        override fun getInputStream() = input
        override fun getOutputStream(): OutputStream = written
        override fun setSoTimeout(timeout: Int) {}
    }

    @JvmStatic
    fun fuzzerTestOneInput(data: ByteArray) {
        val socket = FakeSocket(ByteArrayInputStream(data))
        handle(socket, TOKEN, { error("no signing key while fuzzing") }, client, stamper, drand)

        val out = socket.written.toByteArray().toString(Charsets.ISO_8859_1)
        val head = out.substringBefore("\r\n\r\n", missingDelimiterValue = "")
        check(head.isNotEmpty()) { "no complete response" }
        val lines = head.split("\r\n")
        val status = statusLine.matchEntire(lines[0])?.groupValues?.get(1)?.toInt()
            ?: error("bad status line: ${lines[0]}")
        for (line in lines.drop(1)) check(headerLine.matches(line)) { "bad header line: $line" }
        val length = lines.single { it.startsWith("Content-Length: ") }.substringAfter(": ").toInt()
        check(out.length - head.length - 4 == length) { "Content-Length doesn't match the body" }

        if (status != 407) check(carriesToken(data) || tooLong(data)) { "got $status without the token" }
    }

    /** Written independently of `authorized`, to check it. */
    private fun carriesToken(data: ByteArray): Boolean {
        val header = data.toString(Charsets.ISO_8859_1).split('\n').drop(1).take(100)
            .map { it.removeSuffix("\r").replace("\r", "") }
            .takeWhile { it.isNotEmpty() }
            .firstOrNull { it.lowercase().startsWith("proxy-authorization:") } ?: return false
        val value = header.substringAfter(':').trim()
        if (!value.lowercase().startsWith("basic ")) return false
        val decoded = try {
            Base64.getDecoder().decode(value.substring(6).trim())
        } catch (e: IllegalArgumentException) {
            return false
        }
        return String(decoded).substringAfter(':') == TOKEN
    }

    private fun tooLong(data: ByteArray) = data.toString(Charsets.ISO_8859_1).split('\n').take(101)
        .any { it.replace("\r", "").length > 8192 }
}
