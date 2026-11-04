# Attested Web Capture

An Android app that saves web pages as evidence. You fetch pages through it like through any proxy; each
response comes back unchanged, plus a signature anyone can check later. The signature shows:

- **what** the server sent: the exact status, headers and body;
- **who** captured it: this app, unmodified, on a phone with a locked bootloader and a verified OS
  (stock Android or GrapheneOS);
- **when**: within one minute before an independent time-stamp.

The signing key is created inside the phone's secure hardware, and only this app can use it. The phone's
hardware certifies the key, including which app made it and whether the OS was verified.

## Capture pages

1. Install the app from the releases page and open it. It runs in the background with a notification, and it asks to be exempt
   from battery optimization so it keeps working with the screen off. The screen shows the proxy address
   with its password; tap it to copy.
2. Fetch pages through it, from a computer on the same Wi-Fi, hotspot or VPN:

   ```
   curl -si -x 'http://:<password>@<phone-address>:8787' http://example.com/ > example.http
   ```

   - Write `http://` URLs. The app always fetches them over HTTPS.
   - Send a `User-Agent` header (curl does by default). It's passed to the site and recorded.
   - Redirects come back as they are; request the new URL yourself if you want it.
   - Keep `-i` and save with `>` so the file stays byte-exact.
3. To stop, tap **Stop proxy and close**.

The proxy only answers on local networks (Wi-Fi, hotspot, VPN), never on mobile data. The password travels
unencrypted on that network, so use one you trust, or a VPN.

When something fails, the proxy answers with a short text explanation:

| Status | Meaning |
|---|---|
| 407 | Wrong or missing password |
| 400 | The request isn't allowed: not a public site, missing User-Agent, a non-standard port, … |
| 405 | Only GET requests work |
| 502 | The site couldn't be fetched, or its response is over 10 MB |
| 503 | A temporary problem on the phone; try again after the `Retry-After` delay |

## Verify a capture

Install `attested-verify` from the
[Hardware-Attested Statements releases](https://github.com/nikitakarpei/hardware-attested-statements/releases), and
write a policy saying whose captures you trust, for example `policy.json`:

```json
{ "policy": "hardware-attested-statement/policy/v0.1",
  "timestampAuthorities": ["freetsa"],
  "drandChains": ["quicknet"],
  "predicateTypes": {
    "https://github.com/nikitakarpei/hardware-attested-statements/blob/main/spec/predicates/http-response/v1.md": {
      "trustedSigners": [{ "profile": "android", "package": "io.github.nikitakarpei.attestedwebcapture",
                           "signingCertificates": ["<release signing certificate SHA-256>"] }],
      "requireTimestamp": true, "requireStartedAfter": true } } }
```

`signingCertificates` is the fingerprint published with the releases. Then:

```
attested-verify -policy policy.json http example.http
```

It prints what was captured, from which server, by which app on what kind of device, and the time window. Device
settings (StrongBox, patch levels, which operating systems) are in the
[Android profile's policy](https://github.com/nikitakarpei/hardware-attested-statements/blob/main/spec/profiles/android.md#policy).

### What a capture does not prove

- That the content is true: only that this server sent it to this phone.
- More about the server than TLS does: the phone checked its certificate as a browser would, and the
  capture records the certificate's fingerprint and the server's address, which you can look up (e.g. on crt.sh).
- That the phone was secure beyond what its hardware reports. A phone with an exploited secure area
  could sign anything, which is why `requireStrongBox` exists.

## Release signing

Releases are built and signed by GitHub Actions. The key never enters the repository or the build;
only the signing step of the release job can read it. One-time setup:

1. **Create the key** on your own computer, and back it up offline. Never commit it.
   ```
   keytool -genkeypair -keystore release.jks -alias release -keyalg RSA -keysize 4096 \
     -validity 10000 -dname "CN=Attested Web Capture"
   ```
   If you lose it, users must uninstall to update, and verifiers must trust a new fingerprint.
2. **Create an environment** named `release` (Settings → Environments). Add yourself as a required
   reviewer, and limit it to tags matching `v*`.
3. **Add the environment secrets**:

   | Secret | Value |
   |---|---|
   | `SIGNING_KEYSTORE_B64` | output of `base64 -w0 release.jks` (macOS: `base64 -i release.jks`) |
   | `SIGNING_STORE_PASSWORD` | the keystore password |
   | `SIGNING_KEY_PASSWORD` | the key password (the same, for the default keystore type) |
   | `SIGNING_KEY_ALIAS` | `release` |

4. **Add the variable** `SIGNING_CERT_SHA256`, the certificate's fingerprint. Get it with:
   ```
   keytool -list -v -keystore release.jks -alias release | sed -n 's/.*SHA256: //p' | tr -d ':' | tr 'A-F' 'a-f'
   ```
   Publish it too: it's what verifiers put in `signingCertificates`. The release job fails if the secrets ever hold
   a different key.
5. **Protect the tags** (Settings → Rules → New tag ruleset for `v*`), so only you can start a release.

To release, raise `versionCode` and `versionName` in `app/build.gradle.kts`, add a section
`## <version> (<date>)` to [CHANGELOG.md](CHANGELOG.md), push the tag `v<version>` and approve the run. The release
holds the signed APK, the unsigned APK it was made from, checksums and a build-provenance attestation
(`gh attestation verify <file> --repo nikitakarpei/attested-web-capture-android`).

## Build from source

Needs JDK 21 and the Android SDK (platform 37, build-tools 37.0.0).

```
./gradlew assembleRelease                        # app/build/outputs/apk/release/app-release-unsigned.apk
tools/sign.sh release.jks release                # sign it with your key to install it
./gradlew lintRelease ktlintCheck testReleaseUnitTest koverVerifyRelease fuzzRequest   # what CI checks
```

The build is reproducible: the same source gives a byte-identical unsigned APK on any machine. To check a
release, build the same tag and compare with the release's unsigned APK, or copy the release's signature onto
your build with `apksigcopier` and compare the signed files.

How it works inside, and why: [docs/design.md](docs/design.md).

## More

[Security](SECURITY.md) · [Contributing](CONTRIBUTING.md) · [Governance](GOVERNANCE.md) · [Changes](CHANGELOG.md) ·
License: [Apache-2.0](LICENSE)
