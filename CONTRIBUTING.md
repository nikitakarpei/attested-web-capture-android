# Contributing

Report bugs and propose changes in issues; security problems go to [SECURITY.md](SECURITY.md).

Every change goes through a pull request, which CI must pass and a maintainer reviews. Commit messages follow
[Conventional Commits](https://www.conventionalcommits.org/); commits are signed and carry `Signed-off-by`
(`git commit -s`), certifying the [Developer Certificate of Origin](https://developercertificate.org/).
Add a line to [CHANGELOG.md](CHANGELOG.md).

Before a pull request, run what CI runs:

```
./gradlew lintRelease ktlintCheck testReleaseUnitTest koverVerifyRelease fuzzRequest
```

New behaviour needs tests; a new refusal needs a test that fails without it. A change to what a capture contains
needs the predicate type's specification changed with it. A new or updated dependency needs
`gradle/verification-metadata.xml` written again (`make verification-metadata`; on Dependabot's pull requests a
workflow does it), and a reason in the pull request: the app keeps few on purpose.

**Releases**: a maintainer raises `versionCode` and `versionName`, adds `## <version> (<date>)` to the changelog,
pushes the tag `v<version>`, and approves the release job.
