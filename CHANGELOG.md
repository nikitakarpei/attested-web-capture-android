# Changelog

Each release has a section `## <version> (<date>)`, used as its release notes. Versions follow
[Semantic Versioning](https://semver.org/).

## 0.2.0 (2026-11-07)

- The screen also shows the proxy's `127.0.0.1` address, for apps on the phone or `adb forward`.
- The "not reachable" warning sits below the addresses, and the battery button reads just
  "Allow running in background".

## 0.1.0 (2026-11-05)

First release: an Android app that saves web pages as evidence. Pages fetched through it come back unchanged,
signed with a key in the phone's secure hardware, time-stamped, and verifiable with `attested-verify`.
