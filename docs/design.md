# Design

For auditors: why the app is built as it is. It is one file, `app/src/main/java/io/github/nikitakarpei/attestedwebcapture/Main.kt`.
Its captures are statements in the [Hardware-Attested Statements](https://github.com/nikitakarpei/hardware-attested-statements)
format, with the Android profile and the predicate type `https://github.com/nikitakarpei/hardware-attested-statements/blob/main/spec/predicates/http-response/v1.md`, both specified there.

## Trust

The signing key is an Android Keystore key in StrongBox or the TEE: only this app can use it, and its attestation
states the app and the device's boot state. Everything else only needs to be honest, and is kept small so it can be
checked: two libraries, OkHttp for HTTPS and Bouncy Castle for RFC 3161.

## Signing key

- One key, in StrongBox if the phone has one, otherwise the TEE. It is replaced at every service start, so each boot
  and update gets a fresh attestation, and before any certificate in its chain expires. A replaced key is deleted at
  the next start, so a capture still holding it can finish.
- Signatures are converted to low-S, so each signing has exactly one valid signature.
- A debuggable build never creates a key: its captures fail with 503.

## Time

- Lower bound: when a capture starts, the latest drand quicknet round, fetched at most once per round and only when
  needed, so an idle phone makes no requests.
- Upper bound: FreeTSA, which allows one request per second per address. Signatures waiting meanwhile share the
  next time-stamp, over a Merkle tree of their signed-statement IDs.
- The app checks each token as a verifier would, and pins FreeTSA's signing certificate: when FreeTSA replaces it,
  captures fail with 503 until the app is updated. Tokens carry no certificates.

## Outbound requests

- HTTPS on port 443 only, HTTP/1.1, no cookies, redirects, retries or connection reuse. The system proxy is ignored;
  a VPN still applies.
- Addresses that aren't globally reachable are refused (IANA special-purpose blocks and multicast; NAT64 addresses by
  the IPv4 address inside). The check runs in OkHttp's DNS step, and OkHttp connects only to the addresses it
  returns, which closes the DNS-rebinding gap; IP-address hosts are checked before the request. HTTPS with the
  system's CAs remains the main protection.
- Response size and concurrent captures are limited, so captures can't exhaust memory.

## Proxy server

- A password of 128 random bits, sent as `Proxy-Authorization: Basic` and compared in constant time.
- Only absolute-form GET. CONNECT is refused, since a tunnel would hide the response. One request per connection;
  request size, header count, request time and connections are limited.
- It answers only connections that arrived on a local-network address of the phone, never on mobile data, even
  where the carrier hands out private addresses.
- No app data leaves the phone: backups and device-to-device transfers are off.

## Reproducible builds

Every tool and library is pinned with its SHA-256 (`gradle/verification-metadata.xml`). Build features that differ
between builds are off: AGP's encrypted dependency list, the embedded git commit, APK entry compression and library
startup profiles. CI builds every commit twice and compares the APKs.
