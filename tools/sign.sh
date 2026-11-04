#!/bin/sh
# Signs the unsigned release APK with your own key, to install your own build on a phone.
# Release APKs are signed by the CI release job instead; this is for local builds.
#
#   tools/sign.sh <keystore> <key alias> [unsigned apk] [signed apk]
#
# apksigner asks for the passwords. Needs ANDROID_HOME (build-tools 36.0.0 installed).
set -eu
keystore=$1
alias=$2
unsigned=${3:-app/build/outputs/apk/release/app-release-unsigned.apk}
signed=${4:-app/build/outputs/apk/release/app-release-signed.apk}
apksigner="${ANDROID_HOME:?set ANDROID_HOME to your Android SDK}/build-tools/36.0.0/apksigner"
# Same scheme choice as the CI release job: v2 + v3, no v1/JAR signature.
"$apksigner" sign --ks "$keystore" --ks-key-alias "$alias" --v1-signing-enabled false --v2-signing-enabled true \
  --v3-signing-enabled true --v4-signing-enabled false --out "$signed" "$unsigned"
"$apksigner" verify --print-certs "$signed"
echo "signed: $signed"
