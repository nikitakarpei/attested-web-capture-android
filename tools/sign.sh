#!/bin/sh
# Signs the unsigned release APK, and checks the signed APK has exactly the keystore's certificate. CI's release job
# signs releases with it, and every build checks it with a throwaway key; locally, it signs your own build to install.
#
#   tools/sign.sh <keystore> <key alias> [unsigned apk] [signed apk]
#
# STORE_PASSWORD (asked for if unset) and KEY_PASSWORD (default: the same) come from the environment, never the
# command line. If EXPECTED_CERT is set, the keystore's certificate must have that SHA-256, or nothing is signed.
# Prints the certificate's SHA-256 (what verifiers put in signingCertificates). Needs ANDROID_HOME (build-tools
# 37.0.0 installed) and a JDK's keytool.
set -eu
keystore=$1
alias=$2
unsigned=${3:-app/build/outputs/apk/release/app-release-unsigned.apk}
signed=${4:-app/build/outputs/apk/release/app-release-signed.apk}
apksigner="${ANDROID_HOME:?set ANDROID_HOME to your Android SDK}/build-tools/37.0.0/apksigner"

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
sha256() { if command -v sha256sum >/dev/null; then sha256sum "$1"; else shasum -a 256 "$1"; fi | cut -d' ' -f1; }

if [ -z "${STORE_PASSWORD+set}" ]; then
  printf 'Keystore password: ' >&2
  stty -echo; IFS= read -r STORE_PASSWORD; stty echo
  printf '\n' >&2
fi
KEY_PASSWORD=${KEY_PASSWORD:-$STORE_PASSWORD}
export STORE_PASSWORD KEY_PASSWORD

# A certificate's SHA-256 is that of its DER encoding, which is what keytool exports.
keytool -exportcert -keystore "$keystore" -alias "$alias" -storepass:env STORE_PASSWORD -file "$tmp/key.der" > "$tmp/keytool.txt" 2>&1 ||
  { cat "$tmp/keytool.txt" >&2; echo "Can't read the certificate of \"$alias\" in $keystore." >&2; exit 1; }
cert=$(sha256 "$tmp/key.der")
if [ -n "${EXPECTED_CERT:-}" ] && [ "$cert" != "$EXPECTED_CERT" ]; then
  echo "The keystore's certificate is $cert, not the expected $EXPECTED_CERT: not signing." >&2
  exit 1
fi

# v3 allows rotating to a new key later; v1 (JAR) would add files, and Android 9+ doesn't need it.
"$apksigner" sign --ks "$keystore" --ks-key-alias "$alias" --ks-pass env:STORE_PASSWORD --key-pass env:KEY_PASSWORD \
  --v1-signing-enabled false --v2-signing-enabled true --v3-signing-enabled true --v4-signing-enabled false \
  --out "$signed" "$unsigned"

# apksigner verify fails on a bad signature. Its certificates are compared as PEM (a fixed format), not by its
# human-readable lines: every certificate it reports must be the keystore's.
"$apksigner" verify --print-certs-pem "$signed" > "$tmp/verify.txt"
awk -v dir="$tmp" '/^-----BEGIN CERTIFICATE-----$/ { n++; inside = 1; next }
  /^-----END CERTIFICATE-----$/ { inside = 0; next }
  inside { print > (dir "/apk" n ".b64") }' "$tmp/verify.txt"
found=0
for b64 in "$tmp"/apk*.b64; do
  [ -e "$b64" ] || break
  base64 -d < "$b64" > "$b64.der"
  [ "$(sha256 "$b64.der")" = "$cert" ] || { echo "The APK is signed with another certificate:" >&2; cat "$tmp/verify.txt" >&2; exit 1; }
  found=$((found + 1))
done
[ "$found" -ge 1 ] || { echo "apksigner reported no certificate:" >&2; cat "$tmp/verify.txt" >&2; exit 1; }

echo "signed: $signed"
echo "certificate SHA-256: $cert"
