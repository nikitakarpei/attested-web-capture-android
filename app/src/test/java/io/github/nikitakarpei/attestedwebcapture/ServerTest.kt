package io.github.nikitakarpei.attestedwebcapture

import okhttp3.ResponseBody.Companion.toResponseBody
import org.bouncycastle.tsp.TSPAlgorithms
import org.bouncycastle.tsp.TimeStampRequestGenerator
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import java.io.ByteArrayInputStream
import java.io.File
import java.math.BigInteger
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Proxy
import java.net.ServerSocket
import java.net.Socket
import java.security.KeyFactory
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.security.spec.PKCS8EncodedKeySpec
import java.util.Base64
import kotlin.concurrent.thread

/**
 * Runs the real proxy and capture code on the desktop JVM and talks to it with curl. Android Keystore
 * is replaced by tools/test_fake_attestation.py (fake chain, same extension format).
 * Writes build/e2e/example.http and redirect.http, which CI checks with the Hardware-Attested Statements verifier.
 */
class ServerTest {
    private val outDir = File(System.getProperty("e2e.dir")!!).apply { mkdirs() }
    private val tools = File(System.getProperty("tools.dir")!!)

    /** This build machine reaches the internet only through its own proxy; on a phone it's DIRECT. */
    private val client = httpClient(
        System.getProperty("https.proxyHost")?.let { host ->
            Proxy(Proxy.Type.HTTP, InetSocketAddress(host, (System.getProperty("https.proxyPort") ?: "443").toInt()))
        } ?: Proxy.NO_PROXY,
    )

    private fun fakeKey(): SigningKey {
        val p = ProcessBuilder(
            "python3", File(tools, "test_fake_attestation.py").path,
            "--challenge", hex(KEY_CHALLENGE.toByteArray()), "--version-code", "1", "--data-file", "/dev/null", "--state-dir", outDir.path,
        )
            .redirectError(ProcessBuilder.Redirect.INHERIT).start()
        val out = JSONObject(p.inputStream.readBytes().toString(Charsets.UTF_8))
        check(p.waitFor() == 0)
        val cf = CertificateFactory.getInstance("X.509")
        val chain = out.getJSONArray("chain").let { a ->
            (0 until a.length()).map { cf.generateCertificate(ByteArrayInputStream(a.getString(it).toByteArray())) as X509Certificate }
        }
        val priv = KeyFactory.getInstance(
            "EC",
        ).generatePrivate(PKCS8EncodedKeySpec(Base64.getDecoder().decode(out.getString("privateKey"))))
        return SigningKey(priv, chain, "FAKE")
    }

    /** Runs curl through the proxy; returns (HTTP status, raw response file). */
    private fun curl(port: Int, vararg args: String, out: File = File(outDir, "last.http")): Pair<Int, File> {
        val p = ProcessBuilder(listOf("curl", "-s", "-i", "--noproxy", "", "-x", "http://127.0.0.1:$port") + args)
            .redirectOutput(out).redirectError(ProcessBuilder.Redirect.INHERIT).start()
        p.waitFor()
        val statusLine = out.readBytes().toString(Charsets.ISO_8859_1).lineSequence().firstOrNull() ?: ""
        return (statusLine.split(' ').getOrNull(1)?.toIntOrNull() ?: -1) to out
    }

    @Test
    fun addressTable() {
        val blocked = listOf(
            "127.0.0.1", "127.255.0.1", "10.1.2.3", "172.16.0.1", "172.31.255.255", "192.168.1.1",
            "169.254.169.254", "100.64.0.1", "100.127.255.254", "0.0.0.0", "0.1.2.3", "192.0.0.9", "192.0.2.5",
            "198.18.0.1", "198.19.255.1", "198.51.100.7", "203.0.113.9", "224.0.0.1", "239.1.1.1", "240.0.0.1",
            "255.255.255.255", "::", "::1", "::10.0.0.1", "::ffff:127.0.0.1", "::ffff:192.168.0.1", "64:ff9b::7f00:1",
            "64:ff9b::a00:1", "64:ff9b:1::1", "100::1", "2001::1", "2001:db8::1", "2002:c0a8:101::1", "3fff::1",
            "5f00::1", "fc00::1", "fd12:3456::1", "fe80::1", "fec0::1", "ff02::1",
        )
        val allowed = listOf(
            "1.1.1.1", "8.8.8.8", "93.184.215.14", "172.15.255.255", "172.32.0.1", "100.63.255.255",
            "100.128.0.1", "192.0.1.1", "198.17.255.255", "198.20.0.1", "223.255.255.255", "192.31.196.1",
            "2606:4700::6810:84e5", "2a00:1450:4001:80b::200e", "64:ff9b::808:808", "2001:4860:4860::8888",
        )
        for (a in blocked) assertTrue("should block $a", isBlocked(InetAddress.getByName(a)))
        for (a in allowed) assertFalse("should allow $a", isBlocked(InetAddress.getByName(a)))
    }

    @Test
    fun dnsFilterRefusesLocalNames() {
        for (name in listOf("localhost", "127.0.0.1.nip.io")) {
            try {
                client.dns.lookup(name)
                fail("$name should be refused")
            } catch (e: Refused) {
                println("dns $name → ${e.message}")
            } catch (e: java.net.UnknownHostException) {
                println("dns $name → not resolvable here (${e.message})") // no public DNS on this machine is fine
            }
        }
        assertFalse(client.dns.lookup("example.com").isEmpty())
    }

    @Test
    fun timestampChecks() {
        val digest = sha256("a".toByteArray())
        val good = timestamp(client, digest) // checkTimestamp runs inside
        // A genuine response doesn't pass for a different digest (same nonce), or a different nonce.
        val nonce = org.bouncycastle.tsp.TimeStampResponse(good).timeStampToken.timeStampInfo.nonce
        val gen = TimeStampRequestGenerator().apply { setCertReq(true) }
        for ((what, req) in listOf(
            "other digest" to gen.generate(TSPAlgorithms.SHA256, sha256("b".toByteArray()), nonce),
            "other nonce" to gen.generate(TSPAlgorithms.SHA256, digest, nonce + BigInteger.ONE),
        )) {
            try {
                checkTimestamp(req, good)
                fail("$what should be rejected")
            } catch (e: Exception) {
                println("timestamp $what → ${e.message}")
            }
        }
        // A tampered token fails its signature check.
        val tampered = good.copyOf().also { it[it.size - 40] = (it[it.size - 40].toInt() xor 1).toByte() }
        try {
            checkTimestamp(TimeStampRequestGenerator().generate(TSPAlgorithms.SHA256, digest), tampered)
            fail("tampered token should be rejected")
        } catch (e: Exception) {
            println("timestamp tampered → ${e.javaClass.simpleName}: ${e.message}")
        }
    }

    @Test
    fun stamperBatchesAndRateLimits() {
        Stamper(client).use { stamper ->
            val signatures = (1..6).map { "signature $it".toByteArray() }
            val started = System.nanoTime()
            val stamps = signatures.map { sig -> java.util.concurrent.CompletableFuture.supplyAsync { stamper.stamp(sig) } }
                .map { it.get() }
            val secs = (System.nanoTime() - started) / 1e9
            val tokens = stamps.map { it.token.toList() }.distinct()
            println(
                "6 concurrent stamps → ${tokens.size} FreeTSA request(s) in ${"%.1f".format(secs)} s; " +
                    "tree sizes ${stamps.map { it.size }.distinct()}",
            )
            assertTrue(tokens.size <= 2)
            for ((sig, st) in signatures.zip(stamps)) {
                // The path leads from the leaf to the root the token time-stamps (RFC 9162 verification).
                var fn = st.index
                var sn = st.size - 1
                var hash = merkleLeaf(sig)
                for (sibling in st.path) {
                    if (fn % 2 == 1 || fn == sn) {
                        hash = sha256(byteArrayOf(1) + sibling + hash)
                        while (fn % 2 == 0 && fn != 0) {
                            fn = fn shr 1
                            sn = sn shr 1
                        }
                    } else {
                        hash = sha256(byteArrayOf(1) + hash + sibling)
                    }
                    fn = fn shr 1
                    sn = sn shr 1
                }
                val imprint = org.bouncycastle.tsp.TimeStampResponse(st.token).timeStampToken.timeStampInfo.messageImprintDigest
                assertTrue("signature ${st.index} of ${st.size} is in the time-stamped tree", imprint.contentEquals(hash))
                // And the token carries no certificates (certReq FALSE).
                assertEquals(0, org.bouncycastle.tsp.TimeStampResponse(st.token).timeStampToken.certificates.getMatches(null).size)
            }
            // A second batch never follows the first within a second.
            val t2 = System.nanoTime()
            stamper.stamp("x".toByteArray())
            stamper.stamp("y".toByteArray())
            println("2 sequential stamps took ${"%.1f".format((System.nanoTime() - t2) / 1e9)} s")
            assertTrue((System.nanoTime() - t2) / 1e9 >= 1.0)
        }
    }

    /** Signatures come out low-S, whichever form the provider produced, and still verify. */
    @Test
    fun signaturesAreLowS() {
        val gen = java.security.KeyPairGenerator.getInstance("EC").apply { initialize(java.security.spec.ECGenParameterSpec("secp256r1")) }
        val pair = gen.generateKeyPair()
        val key = SigningKey(pair.private, emptyList(), "TEST")
        var high = 0
        repeat(64) {
            val raw = java.security.Signature.getInstance("SHA256withECDSA").run {
                initSign(pair.private)
                update("x".toByteArray())
                sign()
            }
            val s = (org.bouncycastle.asn1.ASN1Sequence.getInstance(raw).getObjectAt(1) as org.bouncycastle.asn1.ASN1Integer).value
            if (s > P256_ORDER.shiftRight(1)) high++
            val low = lowS(raw)
            val ls = (org.bouncycastle.asn1.ASN1Sequence.getInstance(low).getObjectAt(1) as org.bouncycastle.asn1.ASN1Integer).value
            assertTrue(ls <= P256_ORDER.shiftRight(1))
            assertTrue(
                java.security.Signature.getInstance("SHA256withECDSA").run {
                    initVerify(pair.public)
                    update("x".toByteArray())
                    verify(low)
                },
            )
        }
        assertTrue("some raw signatures were high-S", high > 0)
        val sig = key.sign("y".toByteArray())
        assertTrue(
            (org.bouncycastle.asn1.ASN1Sequence.getInstance(sig).getObjectAt(1) as org.bouncycastle.asn1.ASN1Integer).value <=
                P256_ORDER.shiftRight(1),
        )
    }

    /** RFC 6962 test vectors, as computed by the transparency-dev/merkle library the verifier uses. */
    @Test
    fun merkleTreeMatchesRfc6962Vectors() {
        val leaves = listOf("", "00", "10", "2021", "3031", "40414243", "5051525354555657", "606162636465666768696a6b6c6d6e6f")
            .map { merkleLeaf(it.chunked(2).map { b -> b.toInt(16).toByte() }.toByteArray()) }
        assertEquals("5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328", hex(merkleRoot(leaves)))
        assertEquals("aeb6bcfe274b70a14fb067a5e5578264db0fa9b51af5e0ba159158f329e06e77", hex(merkleRoot(leaves.subList(0, 3))))
        assertEquals(
            listOf(
                "96a296d224f285c67bee93c30f8a309157f0daa35dc5b87e410b78630a09cfc7",
                "0298d122906dcfc10892cb53a73992fc5b9f493ea4c9badb27b791b4127a7fe7",
            ),
            merklePath(0, leaves.subList(0, 3)).map { hex(it) },
        )
    }

    @Test
    fun originCannotInjectSignedCaptureHeaders() {
        val origin = listOf(
            "Content-Type" to "text/html",
            "Attested-Statement" to ":forged:",
            "attested-seal" to ":forged:",
            "Connection" to "keep-alive",
            "Set-Cookie" to "a=1",
            "Set-Cookie" to "b=2",
        )
        assertEquals(
            listOf("Content-Type" to "text/html", "Set-Cookie" to "a=1", "Set-Cookie" to "b=2"),
            forwardedHeaders(origin),
        )
    }

    @Test
    fun answersOnlyOnLocalNetworks() {
        val cellular = setOf(InetAddress.getByName("10.123.4.5")) // a carrier's private address
        for (a in listOf(
            "127.0.0.1", "192.168.1.23", "10.0.0.2", "172.20.1.1", "100.101.102.103", "169.254.3.4",
            "::1", "fd7a:115c:a1e0::1", "fe80::1",
        )) {
            assertTrue("should answer on $a", answersOn(InetAddress.getByName(a), cellular))
        }
        for (a in listOf("8.8.8.8", "93.184.215.14", "2a02:6b8::1", "2001:4860:4860::8888", "10.123.4.5")) {
            assertFalse("should not answer on $a", answersOn(InetAddress.getByName(a), cellular))
        }
        // A connection on an address it doesn't answer on is closed without a word.
        val ss = ServerSocket(0, 50, InetAddress.getByName("127.0.0.1"))
        thread(isDaemon = true) { serve(ss, "testtoken", { fakeKey() }, client, { false }) { 0L } }
        try {
            Socket("127.0.0.1", ss.localPort).use { s ->
                s.soTimeout = 5_000
                s.getOutputStream().write("GET http://example.com/ HTTP/1.1\r\n\r\n".toByteArray())
                assertEquals(-1, s.getInputStream().read()) // closed, nothing sent
            }
        } finally {
            ss.close()
        }
    }

    /** The fuzzer's seed requests, run through its checks (see RequestFuzzer; `./gradlew fuzzRequest` fuzzes). */
    @Test
    fun fuzzSeeds() {
        val seeds = File(System.getProperty("fuzz.seeds")!!).listFiles()!!.sorted()
        assertTrue(seeds.size >= 8)
        for (f in seeds) RequestFuzzer.fuzzerTestOneInput(f.readBytes())
    }

    @Test
    fun bodyLimit() {
        val fits = ByteArray(MAX_BODY_BYTES).toResponseBody()
        assertEquals(MAX_BODY_BYTES, readBody(fits).size)
        try {
            readBody(ByteArray(MAX_BODY_BYTES + 1).toResponseBody())
            fail("an over-limit body should be refused")
        } catch (e: IllegalStateException) {
            println("body limit → ${e.message} (status ${statusFor(e)})")
            assertEquals(502, statusFor(e))
        }
    }

    @Test
    fun failureStatuses() {
        assertEquals(400, statusFor(IllegalArgumentException("bad target")))
        assertEquals(400, statusFor(Refused("private address")))
        assertEquals(503, statusFor(Retryable("time-stamp failed")))
        assertEquals(502, statusFor(java.io.IOException("connection reset by target")))
        assertEquals(502, statusFor(IllegalStateException("response larger than 50 MB")))
        // A signing key that can't be created right now → 503 with Retry-After, end to end.
        val ss = ServerSocket(0, 50, InetAddress.getByName("127.0.0.1"))
        thread(isDaemon = true) { serve(ss, "testtoken", { throw IllegalStateException("StrongBox busy") }, client) { 0L } }
        try {
            val (code, file) = curl(ss.localPort, "--proxy-user", ":testtoken", "http://example.com/")
            val text = file.readText(Charsets.ISO_8859_1)
            println("key failure → $code: ${text.lines().filter { it.startsWith("Retry-After") || it.startsWith("capture") }}")
            assertEquals(503, code)
            assertTrue(text.contains("Retry-After: $RETRY_AFTER_SECONDS"))
        } finally {
            ss.close()
        }
    }

    @Test
    fun proxySignsResponses() {
        val key = fakeKey()
        val ss = ServerSocket(0, 50, InetAddress.getByName("127.0.0.1"))
        thread(isDaemon = true) { serve(ss, "testtoken", { key }, client) { System.nanoTime() / 1_000_000 } }
        val port = ss.localPort
        val auth = arrayOf("--proxy-user", ":testtoken")
        try {
            assertEquals(407, curl(port, "http://example.com/").first)
            assertEquals(407, curl(port, "--proxy-user", ":wrong", "http://example.com/").first)
            assertEquals(405, curl(port, *auth, "-X", "POST", "http://example.com/").first)
            assertEquals(400, curl(port, *auth, "http://127.0.0.1/").first)
            assertEquals(400, curl(port, *auth, "http://[::1]/").first)
            assertEquals(400, curl(port, *auth, "http://example.com:8080/").first)
            assertEquals(400, curl(port, *auth, "-H", "User-Agent:", "http://example.com/").first)
            val (connectCode, _) = curl(port, *auth, "https://example.com/")
            println("CONNECT → $connectCode")
            assertTrue(connectCode == 405 || connectCode == -1)
            // A request in origin form (not using the server as a proxy) is refused.
            Socket("127.0.0.1", port).use { s ->
                s.getOutputStream().write("GET / HTTP/1.1\r\nHost: x\r\nProxy-Authorization: Basic OnRlc3R0b2tlbg==\r\n\r\n".toByteArray())
                val line = s.getInputStream().bufferedReader().readLine()
                println("origin-form → $line")
                assertTrue(line.startsWith("HTTP/1.1 400"))
            }
            // A client that sends its request too slowly is cut off (before any token check).
            Socket("127.0.0.1", port).use { s ->
                val t = System.nanoTime()
                s.soTimeout = 30_000
                val w = s.getOutputStream()
                val r = s.getInputStream()
                thread(isDaemon = true) {
                    runCatching {
                        repeat(30) {
                            w.write('G'.code)
                            w.flush()
                            Thread.sleep(1_000)
                        }
                    }
                }
                val reply = r.bufferedReader().readLine()
                val secs = (System.nanoTime() - t) / 1_000_000_000
                println("slow client → '$reply' after ${secs}s")
                assertTrue(secs in 9..16)
            }

            val ua = "Mozilla/5.0 (test) SignedCaptureTest/1"
            val t0 = System.nanoTime()
            val (code, file) = curl(port, *auth, "-A", ua, "http://example.com/", out = File(outDir, "example.http"))
            println("example.com → $code in ${(System.nanoTime() - t0) / 1_000_000} ms")
            assertEquals(200, code)
            val (redirect, _) = curl(port, *auth, "http://grapheneos.org/install", out = File(outDir, "redirect.http"))
            println("grapheneos.org/install → $redirect")
            assertEquals(301, redirect)

            val head = file.readBytes().toString(Charsets.ISO_8859_1).substringBefore("\r\n\r\n")
            val sf = Regex(":[A-Za-z0-9+/]*={0,2}:")
            val signedHeaders = head.lines().filter { it.startsWith("Attested-") }
            assertEquals(6, signedHeaders.size) // version, statement, signature, key, time-stamp, tree
            assertTrue(signedHeaders.contains("Attested-Version: v0.1"))
            for (line in signedHeaders.filter { !it.startsWith("Attested-Timestamp-Tree:") && !it.startsWith("Attested-Version:") }) {
                assertTrue(line, sf.matches(line.substringAfter(": ")))
            }
            val statement =
                JSONObject(
                    String(Base64.getDecoder().decode(Regex("(?m)^Attested-Statement: :([^:\\r\\n]*):").find(head)!!.groupValues[1])),
                )
            assertEquals("https://in-toto.io/Statement/v1", statement.getString("_type"))
            assertEquals(PREDICATE_TYPE, statement.getString("predicateType"))
            val payload = statement.getJSONObject("predicate")
            val drand = payload.getJSONObject("startedAfter").getJSONObject("drand")
            assertEquals(DRAND_CHAIN, drand.getString("chain"))
            println("started after drand round ${drand.getLong("round")}")
            println("signed request: ${payload.getJSONObject("request")}")
            println("signed connection: ${payload.getJSONObject("connection")}")
            val sent = payload.getJSONObject("request").getJSONArray("headers")
                .let { a -> (0 until a.length()).associate { a.getJSONArray(it).getString(0) to a.getJSONArray(it).getString(1) } }
            assertEquals(ua, sent["User-Agent"])
            assertEquals("example.com", sent["Host"]) // recorded as sent on the wire
            assertEquals("identity", sent["Accept-Encoding"])
            println("--- response headers (${head.length} bytes) ---")
            head.lines().forEach { println(if (it.length > 110) it.take(110) + "… (${it.length} chars)" else it) }

            assertTrue(head.lines().any { it.startsWith("Attested-Timestamp-Tree: size=") })
            // Captures in parallel: all signed, sharing few time-stamps (FreeTSA: one request per second).
            val t = System.nanoTime()
            val parallel = (1..8).map { i ->
                java.util.concurrent.CompletableFuture.supplyAsync {
                    curl(port, *auth, "http://example.com/?n=$i", out = File(outDir, "parallel-$i.http"))
                }
            }.map { it.get() }
            val stampsUsed = parallel.map { (_, f) ->
                f.readText(Charsets.ISO_8859_1).lines().first { it.startsWith("Attested-Timestamp:") }
            }.distinct().size
            println(
                "8 parallel captures → ${parallel.map { it.first }} in ${(System.nanoTime() - t) / 1_000_000} ms, " +
                    "$stampsUsed time-stamp request(s)",
            )
            assertTrue(parallel.all { it.first == 200 })
        } finally {
            ss.close()
        }
    }
}
