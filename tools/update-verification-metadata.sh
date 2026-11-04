#!/bin/sh
# Writes gradle/verification-metadata.xml again, listing exactly what the build uses: it runs what CI runs (so every
# configuration is resolved) from an empty Gradle cache (a warm one skips files Gradle only reads when downloading),
# and keeps the file's settings. Every artifact is then trusted as downloaded now: review the diff.
# Needs what the build needs (README, "Build from source"), and Python 3 with cryptography for the tests.
set -eu
cd "$(dirname "$0")/.."
file=gradle/verification-metadata.xml
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

cp "$file" "$tmp/before.xml"
{ sed -n '1,/<components>/p' "$tmp/before.xml"; printf '   </components>\n</verification-metadata>\n'; } > "$file"
# The Gradle distribution itself is checked by the wrapper's distributionSha256Sum, so a downloaded one is reused.
home=${GRADLE_USER_HOME:-$HOME/.gradle}
mkdir -p "$tmp/gradle/wrapper"
[ -d "$home/wrapper/dists" ] && cp -r "$home/wrapper/dists" "$tmp/gradle/wrapper/"

if ! GRADLE_USER_HOME="$tmp/gradle" ./gradlew --write-verification-metadata sha256 --rerun-tasks --console=plain \
    assembleRelease lintRelease ktlintCheck testReleaseUnitTest koverVerifyRelease fuzzRequest -PfuzzSeconds=5; then
    cp "$tmp/before.xml" "$file"
    echo "The build failed: $file is unchanged." >&2
    exit 1
fi
