// Attested Web Capture: a forward HTTP proxy that fetches each target over HTTPS, returns the response
// unchanged, and adds Attested-* headers: an in-toto statement describing the exchange, its signature by a
// hardware-attested key, the key's attestation chain, and an RFC 3161 time-stamp, in the Hardware-Attested
// Statements format (https://github.com/nikitakarpei/hardware-attested-statements), whose verifier checks a saved
// response.
//
// Trust rests on the key: it lives in StrongBox or the TEE, only this app can use it, and its attestation says
// which app (and signing certificate) on which verified OS created it. The rest only needs to be honest, and
// is kept short so it can be checked.
package io.github.nikitakarpei.attestedwebcapture

import android.Manifest
import android.annotation.SuppressLint
import android.app.Activity
import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.ClipData
import android.content.ClipDescription
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.graphics.Typeface
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.os.PersistableBundle
import android.os.PowerManager
import android.os.SystemClock
import android.provider.Settings
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.widget.Button
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import android.widget.Toast
import okhttp3.ConnectionPool
import okhttp3.CookieJar
import okhttp3.Dns
import okhttp3.HttpUrl
import okhttp3.HttpUrl.Companion.toHttpUrlOrNull
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Protocol
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import okhttp3.ResponseBody
import org.bouncycastle.asn1.ASN1Integer
import org.bouncycastle.asn1.ASN1Sequence
import org.bouncycastle.asn1.DERSequence
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.tsp.TSPAlgorithms
import org.bouncycastle.tsp.TSPValidationException
import org.bouncycastle.tsp.TimeStampRequest
import org.bouncycastle.tsp.TimeStampRequestGenerator
import org.bouncycastle.tsp.TimeStampResponse
import org.json.JSONArray
import org.json.JSONObject
import java.io.BufferedInputStream
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.io.InputStream
import java.math.BigInteger
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.NetworkInterface
import java.net.Proxy
import java.net.ServerSocket
import java.net.Socket
import java.net.UnknownHostException
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.MessageDigest
import java.security.PrivateKey
import java.security.SecureRandom
import java.security.Signature
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.security.spec.ECGenParameterSpec
import java.util.Base64
import java.util.concurrent.ArrayBlockingQueue
import java.util.concurrent.CompletableFuture
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.RejectedExecutionException
import java.util.concurrent.ThreadPoolExecutor
import java.util.concurrent.TimeUnit
import kotlin.concurrent.thread

const val PORT = 8787
const val VERSION = "0.6.0"
const val KEY_CHALLENGE = "hardware-attested-statement/v0.1/android/key"
const val PROFILE = "android"
const val SIGNED_ID_PREFIX = "hardware-attested-statement/v0.1/signed"
const val ATTESTED_VERSION = "v0.1"
const val PREDICATE_TYPE = "https://github.com/nikitakarpei/hardware-attested-statements/blob/main/spec/predicates/http-response/v1.md"
const val DSSE_PAYLOAD_TYPE = "application/vnd.in-toto+json"
const val DAY_MS = 24 * 3600 * 1000L
const val TIMESTAMP_WAIT_MS = 60_000L
const val MAX_BODY_BYTES = 10 * 1024 * 1024
const val REQUEST_READ_DEADLINE_MS = 10_000L
const val TSA_URL = "https://freetsa.org/tsr"
const val DRAND_CHAIN = "52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971" // quicknet: a round every 3 s
val DRAND_MIRRORS = listOf("https://api.drand.sh", "https://api2.drand.sh", "https://drand.cloudflare.com")
const val MAX_SIGNATURES_PER_TIMESTAMP = 32
const val MAX_CONCURRENT_CAPTURES = 8
const val MAX_QUEUED_CONNECTIONS = 64

/** FreeTSA's signing certificate (https://freetsa.org/files/tsa.crt, valid 2026–2040), SHA-256
 *  32:E8:41:A9:5C:C1:16:41:01:FF:DE:41:29:8E:F2:FC:75:C1:C4:37:2E:F0:95:E8:8A:6B:BD:47:DF:B1:91:FC.
 *  Pinned rather than requested with each token, which saves ~3.7 KB per capture. */
const val TSA_CERT_PEM = """-----BEGIN CERTIFICATE-----
MIIGYDCCBEigAwIBAgIJAMLphhYNqOnNMA0GCSqGSIb3DQEBDQUAMIGVMREwDwYD
VQQKEwhGcmVlIFRTQTEQMA4GA1UECxMHUm9vdCBDQTEYMBYGA1UEAxMPd3d3LmZy
ZWV0c2Eub3JnMSIwIAYJKoZIhvcNAQkBFhNidXNpbGV6YXNAZ21haWwuY29tMRIw
EAYDVQQHEwlXdWVyemJ1cmcxDzANBgNVBAgTBkJheWVybjELMAkGA1UEBhMCREUw
HhcNMjYwMjE1MTk0NDIyWhcNNDAwMjAyMTk0NDIyWjCCAQsxETAPBgNVBAoMCEZy
ZWUgVFNBMQwwCgYDVQQLDANUU0ExdjB0BgNVBA0MbVRoaXMgY2VydGlmaWNhdGUg
ZGlnaXRhbGx5IHNpZ25zIGRvY3VtZW50cyBhbmQgdGltZSBzdGFtcCByZXF1ZXN0
cyBtYWRlIHVzaW5nIHRoZSBmcmVldHNhLm9yZyBvbmxpbmUgc2VydmljZXMxGDAW
BgNVBAMMD3d3dy5mcmVldHNhLm9yZzEkMCIGCSqGSIb3DQEJARYVYnVzaWxlemFz
QG1haWxib3gub3JnMRIwEAYDVQQHDAlXdWVyemJ1cmcxCzAJBgNVBAYTAkRFMQ8w
DQYDVQQIDAZCYXllcm4wdjAQBgcqhkjOPQIBBgUrgQQAIgNiAASiFeGhstbLhxix
0o4UAumNSwHUUlOe3DBvs8fYs580wADW59oqGSCx15bp61TSmXkwLm1JW48XnbLL
izP6ZtjcvshV3H9uz2bS53sgDXhg1wLbIhAtraC+fHCytHeuVaujggHmMIIB4jAJ
BgNVHRMEAjAAMB0GA1UdDgQWBBQVwL0m69RdgtFdkyYxL+9wsotGXjAfBgNVHSME
GDAWgBT6VQ2MNGZRQ0z357OnbJWveuaklzALBgNVHQ8EBAMCBsAwFgYDVR0lAQH/
BAwwCgYIKwYBBQUHAwgwbAYIKwYBBQUHAQEEYDBeMDMGCCsGAQUFBzAChidodHRw
Oi8vd3d3LmZyZWV0c2Eub3JnL2ZpbGVzL2NhY2VydC5wZW0wJwYIKwYBBQUHMAGG
G2h0dHA6Ly93d3cuZnJlZXRzYS5vcmc6MjU2MDA3BgNVHR8EMDAuMCygKqAohiZo
dHRwOi8vd3d3LmZyZWV0c2Eub3JnL2NybC9yb290X2NhLmNybDCByAYDVR0gBIHA
MIG9MIG6BgMrBQgwgbIwMwYIKwYBBQUHAgEWJ2h0dHA6Ly93d3cuZnJlZXRzYS5v
cmcvZnJlZXRzYV9jcHMuaHRtbDAyBggrBgEFBQcCARYmaHR0cDovL3d3dy5mcmVl
dHNhLm9yZy9mcmVldHNhX2Nwcy5wZGYwRwYIKwYBBQUHAgIwOxo5RnJlZVRTQSB0
cnVzdGVkIHRpbWVzdGFtcGluZyBTb2Z0d2FyZSBhcyBhIFNlcnZpY2UgKFNhYVMp
MA0GCSqGSIb3DQEBDQUAA4ICAQBrMVS/YfnfMr0ziZnesBUOrDNRrNNgt3IgMNDw
Nhwl6oKWHVIhlYnM/5boljfbpZTAbqvxHI3ztT0/swxQOqTat5qBJRAY/VH1n/T4
M9uDjSuu3qfh0ZH5PL9ENqoVW44i5NT/znQev2MGXOAHwz9kZwwzz9MFX6hbGhBq
Wa+nlAqb7Y72KFzj33m1OVHxV2Wl4YD9f91bZTFpUEGW4Ktbkmxpf/iGIPaf4WHp
oBW/O6EzofMKYlz4yXyEBh0wRRVyXltLrj+MFHqhe+PsMBllq/dCaO4W/F+AuHEl
u7aUYWMASelphWAJiUsNMr5HAoeCSSgilqf1CSoWC+k6e4334Fym+Iy4csMex+PG
4rSdqXJVQ+AWEdRajSPKh7yDfpNkdnO6yqQJ/tSd11XQ5cL0M9jWuCD1zHlgA+u+
R2cry3yo23jD7qTGLhZqUvXCyWigH30/Q/RXjjDwrc4DJiQ+gRY0FhdTYqlvgMBP
r4LcJKnNksivdj+kbz7bVSbrBAzRiazK9l841/5XMtP9BvD0hKCpQFvP9PSgCC8E
QnKqgSe26FSJBaAQcA5TnK8NF4jkbElBxf/zyh7P3IjHso35jtgUWD1/itg9BJWb
YUwJ4tfILpB2F0wbk1GcZDCDZoyW3Xf3trApz/Zd93gF3joc9Hh9RFveKRzWQ7dd
Ut3egQ==
-----END CERTIFICATE-----"""

// ------------------------------------------------------------------------------------------------
// Signing key: replaced at every service start, so each boot gets a fresh attestation, and before its chain
// expires. Replaced keys are deleted only at the next start, so a capture still holding one can finish.

class SigningKey(val privateKey: PrivateKey, val chain: List<X509Certificate>, val storage: String) {
    fun sign(data: ByteArray): ByteArray = lowS(
        Signature.getInstance("SHA256withECDSA").run {
            initSign(privateKey)
            update(data)
            sign()
        },
    )
}

val P256_ORDER = BigInteger("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16)

/** (r, n − s) is as valid as (r, s); the spec requires the smaller s, so each signing has exactly one ID. */
fun lowS(der: ByteArray): ByteArray {
    val seq = ASN1Sequence.getInstance(der)
    val r = (seq.getObjectAt(0) as ASN1Integer).value
    val s = (seq.getObjectAt(1) as ASN1Integer).value
    val low = if (s > P256_ORDER.shiftRight(1)) P256_ORDER - s else s
    return DERSequence(arrayOf(ASN1Integer(r), ASN1Integer(low))).encoded
}

object Keys {
    private val ks by lazy { KeyStore.getInstance("AndroidKeyStore").apply { load(null) } }

    @Volatile var current: SigningKey? = null
        private set

    @Synchronized fun get(): SigningKey {
        current?.let { k -> if (k.chain.all { it.notAfter.time - System.currentTimeMillis() > DAY_MS }) return k }
        val alias = "signing-" + System.currentTimeMillis()
        val storage = try {
            generate(alias, strongBox = true)
            "StrongBox"
        } catch (e: Exception) {
            runCatching { ks.deleteEntry(alias) }
            generate(alias, strongBox = false)
            "TEE"
        }
        val key = SigningKey(
            ks.getKey(alias, null) as PrivateKey,
            ks.getCertificateChain(alias).map { it as X509Certificate },
            storage,
        )
        current = key
        return key
    }

    @Synchronized fun reset() {
        current = null
        ks.aliases().toList().forEach { ks.deleteEntry(it) }
    }

    private fun generate(alias: String, strongBox: Boolean) {
        val spec = KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN)
            .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
            .setDigests(KeyProperties.DIGEST_SHA256)
            .setAttestationChallenge(KEY_CHALLENGE.toByteArray())
            .setIsStrongBoxBacked(strongBox)
            .build()
        KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore")
            .apply { initialize(spec) }.generateKeyPair()
    }
}

// ------------------------------------------------------------------------------------------------
// Addresses the proxy never connects to.

/** IANA's special-purpose blocks that aren't "globally reachable" (checked 2026-11), plus multicast and the
 *  deprecated ::/96 and fec0::/10: https://www.iana.org/assignments/iana-ipv4-special-registry and
 *  https://www.iana.org/assignments/iana-ipv6-special-registry. ::ffff:0:0/96 needs no entry: Java turns those
 *  addresses into IPv4 ones. */
val BLOCKED = cidrs(
    "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12",
    "192.0.0.0/24", "192.0.2.0/24", "192.88.99.0/24", "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24",
    "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4",
    "::/96", "64:ff9b:1::/48", "100::/64", "100:0:0:1::/64", "2001::/23", "2001:db8::/32", "2002::/16",
    "3fff::/20", "5f00::/16", "fc00::/7", "fe80::/10", "fec0::/10", "ff00::/8",
)

/** On IPv6-only networks DNS answers with 64:ff9b::/96 addresses for IPv4-only sites; judge the IPv4 inside. */
val NAT64_PREFIX = InetAddress.getByName("64:ff9b::").address.copyOf(12)

fun isBlocked(a: InetAddress): Boolean {
    val b = a.address
    if (b.size == 16 && b.copyOf(12).contentEquals(NAT64_PREFIX)) {
        return isBlocked(InetAddress.getByAddress(b.copyOfRange(12, 16)))
    }
    return BLOCKED.matches(a)
}

fun cidrs(vararg blocks: String): List<Pair<ByteArray, Int>> =
    blocks.map { InetAddress.getByName(it.substringBefore('/')).address to it.substringAfter('/').toInt() }

fun List<Pair<ByteArray, Int>>.matches(a: InetAddress): Boolean {
    val b = a.address
    return any { (net, bits) ->
        net.size == b.size && (0 until bits).all { i ->
            val mask = 0x80 ushr (i % 8)
            (b[i / 8].toInt() and mask) == (net[i / 8].toInt() and mask)
        }
    }
}

// ------------------------------------------------------------------------------------------------
// The proxy answers only connections that arrive on a local-network address of the phone: never on mobile data
// or a public address, which can be reachable from the internet.

val LOCAL_NETWORKS = cidrs(
    "127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10",
    "169.254.0.0/16", "::1/128", "fc00::/7", "fe80::/10",
)

/** Carriers often hand out private addresses too. A VPN over mobile data also reports "cellular", but its
 *  addresses are the VPN's own. */
fun cellularAddresses(ctx: Context): Set<InetAddress> {
    val cm = ctx.getSystemService(ConnectivityManager::class.java)
    @Suppress("DEPRECATION") // allNetworks: a snapshot is all that's needed
    return cm.allNetworks
        .filter { network ->
            val caps = cm.getNetworkCapabilities(network)
            caps != null && caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) &&
                !caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)
        }
        .flatMap { network -> cm.getLinkProperties(network)?.linkAddresses.orEmpty().map { it.address } }
        .toSet()
}

fun answersOn(local: InetAddress, cellular: Set<InetAddress>) = LOCAL_NETWORKS.matches(local) && local !in cellular

class Refused(message: String) : UnknownHostException(message)

/** A temporary failure of the proxy itself, not of the target: 503 with Retry-After. */
class Retryable(message: String, cause: Throwable? = null) : Exception(message, cause)

const val RETRY_AFTER_SECONDS = 10

fun statusFor(e: Exception) = when (e) {
    is IllegalArgumentException, is Refused -> 400
    is Retryable -> 503
    else -> 502
}

fun requireAllowed(host: String, addresses: List<InetAddress>) {
    for (a in addresses) if (isBlocked(a)) throw Refused("refusing non-public address ${a.hostAddress} for $host")
}

/** [proxy]: NO_PROXY on the phone, so the system proxy setting can't reroute captures. */
fun httpClient(proxy: Proxy): OkHttpClient = OkHttpClient.Builder()
    .proxy(proxy)
    // OkHttp connects only to the addresses this returns, so a second, different DNS answer can't slip past.
    .dns { host -> Dns.SYSTEM.lookup(host).also { requireAllowed(host, it) } }
    .protocols(listOf(Protocol.HTTP_1_1))
    .cookieJar(CookieJar.NO_COOKIES)
    // Each capture is exactly one request on a fresh connection; redirects go back to the requester.
    .followRedirects(false).followSslRedirects(false)
    .retryOnConnectionFailure(false)
    .connectionPool(ConnectionPool(0, 1, TimeUnit.SECONDS))
    .connectTimeout(15, TimeUnit.SECONDS).readTimeout(30, TimeUnit.SECONDS).callTimeout(50, TimeUnit.SECONDS)
    .build()

// ------------------------------------------------------------------------------------------------
// Capture: fetch, describe the exchange in a statement, sign it, time-stamp the signature.

class Capture(
    val status: Int,
    val reason: String,
    val headers: List<Pair<String, String>>,
    val body: ByteArray,
    val statement: ByteArray,
    val signature: ByteArray,
    val chain: List<X509Certificate>,
    val stamp: Stamper.Stamp,
)

/** [startedAfter] is the latest drand round when the capture starts: the statement includes it, which proves the
 *  capture can't have been made before that round's time. */
fun capture(url: HttpUrl, userAgent: String, key: SigningKey, startedAfter: Beacon, client: OkHttpClient, stamper: Stamper): Capture {
    require(url.isHttps && url.port == 443) { "only HTTPS on port 443 is fetched" }
    // OkHttp doesn't look up IP-address hosts, so the DNS filter never sees them.
    requireAllowed(url.host, InetAddress.getAllByName(url.host).toList())

    var connectedTo: InetSocketAddress? = null
    val recording = client.newBuilder().addNetworkInterceptor { chain ->
        connectedTo = chain.connection()!!.route().socketAddress
        chain.proceed(chain.request())
    }.build()
    val request = Request.Builder().url(url).get()
        .header("User-Agent", userAgent)
        .header("Accept-Encoding", "identity") // so the body hash covers the bytes as served
        .build()
    val response = recording.newCall(request).execute()
    val body = response.use { readBody(it.body) }
    val handshake = checkNotNull(response.handshake) { "no TLS handshake" }
    // As sent, including the headers OkHttp adds itself.
    val wire = checkNotNull(response.networkResponse) { "response didn't come from the network" }.request
    val headers = response.headers.map { it.first to it.second }
    val statusLine = "HTTP/1.1 ${response.code} ${response.message}"
    // The body subject names how to read the body; verifiers reject a response with either header twice.
    val contentType = response.headers.values("Content-Type")
    val contentEncoding = response.headers.values("Content-Encoding")
    if (contentType.size > 1 || contentEncoding.size > 1) throw java.io.IOException("the site sent Content-Type or Content-Encoding twice")
    val bodySubject = JSONObject().put("name", "body").put("digest", JSONObject().put("sha256", hex(sha256(body))))
    contentType.firstOrNull()?.let { bodySubject.put("mediaType", it) }
    contentEncoding.firstOrNull()?.let { bodySubject.put("annotations", JSONObject().put("contentEncoding", it)) }

    val predicate = JSONObject()
        .put(
            "request",
            JSONObject()
                .put("method", wire.method)
                .put("url", wire.url.toString())
                .put("headers", JSONArray(wire.headers.map { JSONArray(listOf(it.first, it.second)) }))
                .put("cookies", "none"),
        )
        .put(
            "connection",
            JSONObject()
                .put("route", if (client.proxy == Proxy.NO_PROXY) "direct" else client.proxy.toString())
                .put("connectedTo", connectedTo?.let { "${it.address.hostAddress}:${it.port}" })
                .put("protocol", response.protocol.toString())
                .put("tlsVersion", handshake.tlsVersion.javaName)
                .put("cipherSuite", handshake.cipherSuite.javaName)
                .put("serverCertificateSha256", hex(sha256(handshake.peerCertificates[0].encoded))),
        )
        .put(
            "response",
            JSONObject()
                .put("statusLine", statusLine)
                .put("status", response.code)
                .put("headers", JSONArray(headers.map { JSONArray(listOf(it.first, it.second)) })),
        )
        .put(
            "startedAfter",
            JSONObject().put(
                "drand",
                JSONObject().put("chain", DRAND_CHAIN).put("round", startedAfter.round).put("signature", startedAfter.signature),
            ),
        )
    val statement = JSONObject()
        .put("_type", "https://in-toto.io/Statement/v1")
        .put("subject", JSONArray().put(bodySubject))
        .put("predicateType", PREDICATE_TYPE)
        .put("predicate", predicate)
        .toString().toByteArray()
    val signature = key.sign(pae(statement))
    val stamp = try {
        stamper.stamp(signedStatementId(statement, key.chain[0].tbsCertificate, signature))
    } catch (e: Exception) {
        val cause = (e as? java.util.concurrent.ExecutionException)?.cause ?: e
        throw Retryable("time-stamp failed: ${cause.message}", cause)
    }
    return Capture(response.code, response.message, headers, body, statement, signature, key.chain, stamp)
}

// ------------------------------------------------------------------------------------------------
// drand: a public random value every 3 seconds (League of Entropy, https://drand.love).

class Beacon(val round: Long, val signature: String)

/** Fetched on demand, at most once per round, so idle phones don't poll. Not verified here: a bad value only
 *  makes the capture fail verification, and the verifier checks it. */
class Drand(private val client: OkHttpClient, private val clock: () -> Long) {
    private var cached: Pair<Long, Beacon>? = null

    @Synchronized fun latest(): Beacon {
        cached?.let { (fetchedAt, beacon) -> if (clock() - fetchedAt < 3_000) return beacon }
        var failure: Exception? = null
        for (mirror in DRAND_MIRRORS) {
            try {
                val beacon = fetch("$mirror/$DRAND_CHAIN/public/latest")
                cached = clock() to beacon
                return beacon
            } catch (e: Exception) {
                failure = e
            }
        }
        throw Retryable("drand unavailable: ${failure?.message}", failure)
    }

    private fun fetch(url: String): Beacon = client.newCall(Request.Builder().url(url).build()).execute().use { r ->
        check(r.code == 200) { "drand returned HTTP ${r.code}" }
        val json = JSONObject(r.body.string())
        val signature = json.getString("signature")
        check(signature.length == 96 && signature.all { it in "0123456789abcdef" }) { "malformed drand signature" }
        Beacon(json.getLong("round"), signature)
    }
}

// ------------------------------------------------------------------------------------------------
// RFC 3161 time-stamps.

val BC by lazy { BouncyCastleProvider() } // not registered system-wide, so it can't replace Android's crypto
val TSA_CERT: X509Certificate by lazy {
    CertificateFactory.getInstance("X.509").generateCertificate(TSA_CERT_PEM.byteInputStream()) as X509Certificate
}

/** Returns the TSA's DER TimeStampResp for SHA-256 [digest]. */
fun timestamp(client: OkHttpClient, digest: ByteArray): ByteArray {
    val request = TimeStampRequestGenerator().generate(TSPAlgorithms.SHA256, digest, BigInteger(64, SecureRandom()))
    val bytes = client.newCall(
        Request.Builder().url(TSA_URL)
            .post(request.encoded.toRequestBody("application/timestamp-query".toMediaType())).build(),
    ).execute()
        .use { r ->
            check(r.code == 200) { "timestamp authority returned HTTP ${r.code}" }
            r.body.bytes()
        }
    checkTimestamp(request, bytes)
    return bytes
}

/** The requester's checks from RFC 3161 section 2.2, except revocation (a SHOULD), which verifiers can do. */
fun checkTimestamp(request: TimeStampRequest, bytes: ByteArray) {
    val response = TimeStampResponse(bytes)
    check(response.status == 0) { "timestamp not granted: ${response.statusString}" }
    response.validate(request) // hash algorithm, imprint, nonce
    val token = checkNotNull(response.timeStampToken) { "no time-stamp token in response" }
    // Also checks the certificate's timeStamping usage and validity.
    try {
        token.validate(JcaSimpleSignerInfoVerifierBuilder().setProvider(BC).build(TSA_CERT))
    } catch (e: TSPValidationException) {
        throw IllegalStateException("${e.message} (if FreeTSA has a new signing certificate, the app needs an update)", e)
    }
}

/** FreeTSA allows one request per second per IP address, so captures waiting at the same time share a
 *  time-stamp over the root of a Merkle tree of their signed-statement IDs; each response carries its path. */
class Stamper(private val client: OkHttpClient) : AutoCloseable {
    /** [path] proves the signed statement is leaf [index] of the [size]-leaf tree whose root [token] time-stamps. */
    class Stamp(val token: ByteArray, val size: Int, val index: Int, val path: List<ByteArray>)
    private class Pending(val signedId: ByteArray, val result: CompletableFuture<Stamp> = CompletableFuture())

    private val queue = LinkedBlockingQueue<Pending>()
    private val worker = thread(isDaemon = true, name = "time-stamps") {
        try {
            while (true) {
                val batch = mutableListOf(queue.take())
                queue.drainTo(batch, MAX_SIGNATURES_PER_TIMESTAMP - 1)
                val leaves = batch.map { merkleLeaf(it.signedId) }
                try {
                    val token = timestamp(client, merkleRoot(leaves))
                    batch.forEachIndexed { i, p -> p.result.complete(Stamp(token, leaves.size, i, merklePath(i, leaves))) }
                } catch (e: Exception) {
                    batch.forEach { it.result.completeExceptionally(e) }
                }
                Thread.sleep(1_000)
            }
        } catch (e: InterruptedException) {
            // closed
        }
    }

    fun stamp(signedId: ByteArray): Stamp = Pending(signedId).also { queue.put(it) }.result.get(TIMESTAMP_WAIT_MS, TimeUnit.MILLISECONDS)

    override fun close() = worker.interrupt()
}

// ------------------------------------------------------------------------------------------------
// Forward proxy: absolute-form GET only, one request per connection. CONNECT is refused: a tunnel would hide
// the response from the proxy.

val HOP_BY_HOP = setOf(
    "connection", "keep-alive", "proxy-connection", "proxy-authenticate",
    "transfer-encoding", "te", "trailer", "upgrade", "content-length",
)

/** Origin's Attested-* headers are dropped (they stay in the statement), so it can't pass off its own. */
fun forwardedHeaders(headers: List<Pair<String, String>>) = headers.filter { (name, _) ->
    val n = name.lowercase()
    n !in HOP_BY_HOP && !n.startsWith("attested-")
}

fun serve(
    server: ServerSocket,
    token: String,
    key: () -> SigningKey,
    client: OkHttpClient,
    acceptOn: (InetAddress) -> Boolean = { LOCAL_NETWORKS.matches(it) },
    clock: () -> Long,
) {
    // Bounds memory (each capture may hold a full body); connections beyond the queue are closed.
    val pool = ThreadPoolExecutor(
        MAX_CONCURRENT_CAPTURES,
        MAX_CONCURRENT_CAPTURES,
        0,
        TimeUnit.MILLISECONDS,
        ArrayBlockingQueue(MAX_QUEUED_CONNECTIONS),
    )
    val stamper = Stamper(client)
    val drand = Drand(client, clock)
    try {
        while (true) {
            val socket = try {
                server.accept()
            } catch (e: IOException) {
                break // closed
            }
            if (!acceptOn(socket.localAddress)) {
                socket.close()
                continue
            }
            try {
                pool.execute { socket.use { handle(it, token, key, client, stamper, drand) } }
            } catch (e: RejectedExecutionException) {
                socket.close()
            }
        }
    } finally {
        pool.shutdownNow()
        stamper.close()
    }
}

fun handle(socket: Socket, token: String, key: () -> SigningKey, client: OkHttpClient, stamper: Stamper, drand: Drand) {
    socket.soTimeout = 5_000
    val out = socket.getOutputStream()
    fun send(status: Int, reason: String, headers: List<Pair<String, String>>, body: ByteArray) {
        val head = StringBuilder("HTTP/1.1 $status $reason\r\n")
        for ((name, value) in headers) head.append(name).append(": ").append(value).append("\r\n")
        head.append("Content-Length: ${body.size}\r\nConnection: close\r\n\r\n")
        out.write(head.toString().toByteArray(Charsets.ISO_8859_1))
        out.write(body)
        out.flush()
    }
    fun error(status: Int, message: String, extra: List<Pair<String, String>> = emptyList()) =
        send(status, "Error", listOf("Content-Type" to "text/plain; charset=utf-8") + extra, "$message\n".toByteArray())
    try {
        // A deadline for the whole request, not just per read, so slow senders can't hold a thread.
        val deadline = System.nanoTime() + REQUEST_READ_DEADLINE_MS * 1_000_000
        val input = BufferedInputStream(socket.getInputStream())
        val request = readLine(input, deadline).split(' ')
        val headers = generateSequence { readLine(input, deadline).takeIf { it.isNotEmpty() } }.take(100).toList()
        fun header(name: String) = headers.firstOrNull { it.startsWith("$name:", ignoreCase = true) }
            ?.substringAfter(':')?.trim() ?: ""
        if (!authorized(header("proxy-authorization"), token)) {
            return error(
                407,
                "proxy authentication required: use the token as the proxy password",
                listOf("Proxy-Authenticate" to "Basic realm=\"attested-web-capture\""),
            )
        }
        if (request.size != 3) return error(400, "malformed request line")
        val (method, target) = request
        if (method == "CONNECT") return error(405, "CONNECT is not supported: request http://… URLs instead; they are fetched over HTTPS")
        if (method != "GET") return error(405, "only GET is supported")
        val url = target.toHttpUrlOrNull()
            ?: return error(400, "send absolute http:// URLs (use this server as an HTTP proxy)")
        if (url.port != 80 && url.port != 443) return error(400, "only the default ports are supported")
        // Required, because it's sent and signed: the record shows which client the page was served to.
        val userAgent = header("user-agent")
        if (userAgent.isEmpty() || userAgent.length > 512 || userAgent.any { it < ' ' || it > '~' }) {
            return error(
                400,
                "a User-Agent header is required (printable ASCII, at most 512 characters); " +
                    "it is sent to the target and recorded in the signed statement",
            )
        }
        val https = url.newBuilder().scheme("https").port(443).build()
        val k = try {
            key()
        } catch (e: Exception) {
            throw Retryable("signing key unavailable: ${e.message}", e)
        }
        val r = capture(https, userAgent, k, drand.latest(), client, stamper)
        send(
            r.status,
            r.reason,
            forwardedHeaders(r.headers) + listOf(
                "Attested-Version" to ATTESTED_VERSION,
                "Attested-Statement" to sfBytes(r.statement),
                "Attested-Signature" to sfBytes(r.signature),
                "Attested-Key" to sfBytes(keyEvidence(r.chain)),
                "Attested-Timestamp" to sfBytes(r.stamp.token),
                "Attested-Timestamp-Tree" to
                    "size=${r.stamp.size}, index=${r.stamp.index}, path=(${r.stamp.path.joinToString(" ") { sfBytes(it) }})",
            ),
            r.body,
        )
    } catch (e: Exception) {
        val retry = if (e is Retryable) listOf("Retry-After" to "$RETRY_AFTER_SECONDS") else emptyList()
        runCatching { error(statusFor(e), "capture failed: ${e.message}", retry) }
    }
}

/** "Proxy-Authorization: Basic base64(anything:token)", as curl -x http://:token@host sends it. */
fun authorized(value: String, token: String): Boolean {
    if (!value.startsWith("Basic ", ignoreCase = true)) return false
    val given = runCatching { String(Base64.getDecoder().decode(value.substring(6).trim())).substringAfter(':') }
        .getOrDefault("")
    return MessageDigest.isEqual(given.toByteArray(), token.toByteArray())
}

/** [deadline]: System.nanoTime(). */
fun readLine(input: InputStream, deadline: Long): String {
    val b = ByteArrayOutputStream()
    while (true) {
        require(System.nanoTime() < deadline) { "request not received in time" }
        val c = input.read()
        if (c < 0 || c == '\n'.code) break
        if (c != '\r'.code) b.write(c)
        require(b.size() <= 8192) { "request line too long" }
    }
    return b.toString("ISO-8859-1")
}

// ------------------------------------------------------------------------------------------------
// Android: a foreground service runs the proxy; the screen shows how to reach it. Opening the app starts it.

fun notification(ctx: Context): Notification {
    ctx.getSystemService(NotificationManager::class.java)
        .createNotificationChannel(NotificationChannel("server", "Capture proxy", NotificationManager.IMPORTANCE_LOW))
    return Notification.Builder(ctx, "server")
        .setContentTitle("Attested Web Capture proxy")
        .setContentText("Listening on port $PORT")
        .setSmallIcon(android.R.drawable.stat_sys_upload_done)
        .setContentIntent(PendingIntent.getActivity(ctx, 0, Intent(ctx, MainActivity::class.java), PendingIntent.FLAG_IMMUTABLE))
        .setOngoing(true)
        .build()
}

class CaptureService : Service() {
    private val server: ServerSocket? = runCatching { ServerSocket(PORT) }.getOrNull()

    override fun onBind(intent: Intent?) = null

    override fun onCreate() {
        super.onCreate()
        startForeground(1, notification(this))
        val ss = server ?: return stopSelf()
        val token = token(this)
        // A debuggable build can be made to sign anything, so it never gets a key (captures answer 503).
        val debuggable = applicationInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE != 0
        val key: () -> SigningKey = if (debuggable) { -> error("debuggable build: refusing to sign") } else Keys::get
        thread {
            runCatching {
                Keys.reset()
                if (!debuggable) Keys.get()
            }
            serve(
                ss,
                token,
                key,
                httpClient(Proxy.NO_PROXY),
                { answersOn(it, cellularAddresses(this)) },
                SystemClock::elapsedRealtime,
            )
        }
    }

    override fun onDestroy() {
        runCatching { server?.close() }
        super.onDestroy()
    }
}

class MainActivity : Activity() {
    private lateinit var content: LinearLayout

    private fun notificationsMissing() = Build.VERSION.SDK_INT >= 33 &&
        checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED
    private fun batteryOptimized() = !getSystemService(PowerManager::class.java).isIgnoringBatteryOptimizations(packageName)

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        content = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(48, 48, 48, 48)
        }
        setContentView(
            ScrollView(this).apply {
                fitsSystemWindows = true
                addView(content)
            },
        )
        startForegroundService(Intent(this, CaptureService::class.java))
        if (notificationsMissing()) {
            requestPermissions(arrayOf(Manifest.permission.POST_NOTIFICATIONS), 1)
        } else {
            askBatteryOnce()
        }
    }

    override fun onRequestPermissionsResult(requestCode: Int, permissions: Array<out String>, results: IntArray) {
        super.onRequestPermissionsResult(requestCode, permissions, results)
        // Re-post, so the service's notification appears now that it's allowed.
        if (!notificationsMissing()) getSystemService(NotificationManager::class.java).notify(1, notification(this))
        askBatteryOnce()
        refresh()
    }

    /** Without the exemption, Doze may cut the proxy's network access while the screen is off. */
    private fun askBatteryOnce() {
        val prefs = getSharedPreferences("server", Context.MODE_PRIVATE)
        if (batteryOptimized() && !prefs.getBoolean("askedBattery", false)) {
            prefs.edit().putBoolean("askedBattery", true).apply()
            requestBatteryExemption()
        }
    }

    // Lint: against Play Store policy. A proxy that must answer with the screen off is the exemption's use case.
    @SuppressLint("BatteryLife")
    private fun requestBatteryExemption() {
        startActivity(Intent(Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS, Uri.parse("package:$packageName")))
    }

    override fun onResume() {
        super.onResume()
        refresh()
        content.postDelayed({ refresh() }, 3_000) // once the signing key exists
    }

    private fun refresh() {
        content.removeAllViews()
        fun text(s: String, size: Float = 15f) = TextView(this).apply {
            text = s
            textSize = size
            setPadding(0, 12, 0, 12)
        }.also { content.addView(it) }
        fun button(label: String, onClick: () -> Unit) = Button(this).apply {
            text = label
            setOnClickListener { onClick() }
        }.also { content.addView(it) }

        text("Attested Web Capture", 20f).setTypeface(null, Typeface.BOLD)
        val cellular = cellularAddresses(this)
        val urls = NetworkInterface.getNetworkInterfaces().toList().flatMap { it.inetAddresses.toList() }
            .filter { !it.isLoopbackAddress && !it.isLinkLocalAddress && answersOn(it, cellular) }
            .map { a ->
                val host = if (a.address.size == 16) "[${a.hostAddress?.substringBefore('%')}]" else a.hostAddress
                "http://:${token(this)}@$host:$PORT"
            }
        if (urls.isEmpty()) {
            text("Not reachable: connect to Wi-Fi, start a hotspot or a VPN.")
        } else {
            text("Proxy (tap to copy)", 13f)
            for (url in urls) {
                text(url, 14f).apply {
                    typeface = Typeface.MONOSPACE
                    setOnClickListener { copy(url) }
                }
            }
        }
        val k = Keys.current
        if (k == null) {
            text("Signing key not ready: captures return 503 until it is.")
        } else if (k.storage != "StrongBox") {
            text(
                "Signing key is in the ${k.storage} (no StrongBox on this phone): " +
                    "strict verifiers may reject its captures.",
            )
        }
        // For when the user dismissed the system prompts.
        if (notificationsMissing()) {
            button("Show notification") {
                startActivity(Intent(Settings.ACTION_APP_NOTIFICATION_SETTINGS).putExtra(Settings.EXTRA_APP_PACKAGE, packageName))
            }
        }
        if (batteryOptimized()) {
            button("Allow running in background (otherwise the proxy may stop answering while the screen is off)") {
                requestBatteryExemption()
            }
        }
        button("Stop proxy and close") {
            stopService(Intent(this, CaptureService::class.java))
            finishAndRemoveTask()
        }
    }

    /** Marked sensitive, so Android 13+ doesn't show the token in its clipboard preview. */
    private fun copy(url: String) {
        val clip = ClipData.newPlainText("Attested Web Capture proxy", url)
        if (Build.VERSION.SDK_INT >= 33) {
            clip.description.extras = PersistableBundle().apply { putBoolean(ClipDescription.EXTRA_IS_SENSITIVE, true) }
        }
        getSystemService(ClipboardManager::class.java).setPrimaryClip(clip)
        if (Build.VERSION.SDK_INT < 33) Toast.makeText(this, "Copied", Toast.LENGTH_SHORT).show()
    }
}

/** The proxy password, 128 random bits. Older, longer tokens are replaced. */
fun token(ctx: Context): String {
    val prefs = ctx.getSharedPreferences("server", Context.MODE_PRIVATE)
    return prefs.getString("token", null)?.takeIf { it.length == 32 }
        ?: hex(ByteArray(16).also { SecureRandom().nextBytes(it) }).also { prefs.edit().putString("token", it).apply() }
}

// ------------------------------------------------------------------------------------------------

fun readBody(body: ResponseBody): ByteArray {
    val source = body.source()
    check(!source.request(MAX_BODY_BYTES + 1L)) { "response larger than ${MAX_BODY_BYTES / 1024 / 1024} MB" }
    return source.buffer.readByteArray()
}

/** The Android profile's key evidence: the attestation chain, without the self-signed root (verifiers pin it). */
fun keyEvidence(chain: List<X509Certificate>): ByteArray = JSONObject()
    .put("profile", PROFILE)
    .put(
        "certificates",
        JSONArray(
            chain.filter {
                it.subjectX500Principal != it.issuerX500Principal
            }.map { Base64.getEncoder().encodeToString(it.encoded) },
        ),
    )
    .toString().toByteArray()

// RFC 9162 Merkle trees, over leaf hashes.
fun merkleLeaf(data: ByteArray) = sha256(byteArrayOf(0) + data)

fun merkleRoot(leaves: List<ByteArray>): ByteArray {
    if (leaves.size == 1) return leaves[0]
    val k = Integer.highestOneBit(leaves.size - 1) // the largest power of two smaller than the size
    return sha256(byteArrayOf(1) + merkleRoot(leaves.subList(0, k)) + merkleRoot(leaves.subList(k, leaves.size)))
}

/** The inclusion proof of leaf [m], nearest sibling first. */
fun merklePath(m: Int, leaves: List<ByteArray>): List<ByteArray> {
    if (leaves.size == 1) return emptyList()
    val k = Integer.highestOneBit(leaves.size - 1)
    return if (m < k) {
        merklePath(m, leaves.subList(0, k)) + listOf(merkleRoot(leaves.subList(k, leaves.size)))
    } else {
        merklePath(m - k, leaves.subList(k, leaves.size)) + listOf(merkleRoot(leaves.subList(0, k)))
    }
}

/** The leaf of a time-stamp tree: binds the statement, the profile, the key's binding (the leaf certificate's
 *  signed part, holding the key and its attestation), and the signature. */
fun signedStatementId(statement: ByteArray, keyBinding: ByteArray, signature: ByteArray): ByteArray = sha256(
    SIGNED_ID_PREFIX.toByteArray() + byteArrayOf(PROFILE.length.toByte()) + PROFILE.toByteArray() + sha256(statement) +
        sha256(keyBinding) +
        signature,
)

/** DSSE's pre-authentication encoding: binds the payload type into what's signed. */
fun pae(statement: ByteArray): ByteArray =
    "DSSEv1 ${DSSE_PAYLOAD_TYPE.length} $DSSE_PAYLOAD_TYPE ${statement.size} ".toByteArray() + statement

fun sha256(b: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(b)
fun hex(b: ByteArray) = b.joinToString("") { "%02x".format(it) }
fun sfBytes(b: ByteArray) = ":" + Base64.getEncoder().encodeToString(b) + ":" // RFC 9651 byte sequence
